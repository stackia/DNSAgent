using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using DNSAgent;

namespace DnsAgent
{
    internal class DnsAgent
    {
        private Task _forwardingTask;
        private Task _listeningTask;
        private List<KeyValuePair<IPAddress, int>> _networkWhitelist; // Key for address, value for mask
        private Options _options;
        private CancellationTokenSource _stopTokenSource;
        private ConcurrentDictionary<ushort, IPEndPoint> _transactionClients;
        private ConcurrentDictionary<ushort, CancellationTokenSource> _transactionTimeoutCancellationTokenSources;
        private UdpClient _udpForwarder;
        private UdpClient _udpListener;
        private readonly string _listenOn;

        public DnsAgent(Options options, Rules rules, string listenOn, DnsMessageCache cache)
        {
            Options = options ?? new Options();
            Rules = rules ?? new Rules();
            _listenOn = listenOn;
            Cache = cache ?? new DnsMessageCache();
        }

        public Options Options
        {
            get { return _options; }
            set
            {
                _options = value;
                if (_options.NetworkWhitelist == null)
                    _networkWhitelist = null;
                else
                {
                    _networkWhitelist = _options.NetworkWhitelist.Select(s =>
                    {
                        var pieces = s.Split('/');
                        var ip = IPAddress.Parse(pieces[0]);
                        var mask = int.Parse(pieces[1]);
                        return new KeyValuePair<IPAddress, int>(ip, mask);
                    }).ToList();
                }
            }
        }

        public Rules Rules { get; set; }
        public DnsMessageCache Cache { get; set; }
        public event Action Started;
        public event Action Stopped;

        public bool Start()
        {
            var endPoint = Utils.CreateIpEndPoint(_listenOn, 53);
            _stopTokenSource = new CancellationTokenSource();
            _transactionClients = new ConcurrentDictionary<ushort, IPEndPoint>();
            _transactionTimeoutCancellationTokenSources = new ConcurrentDictionary<ushort, CancellationTokenSource>();
            try
            {
                _udpListener = new UdpClient(endPoint);
                _udpForwarder = new UdpClient(0);
            }
            catch (SocketException e)
            {
                Logger.Error("[Listener] Failed to start DNSAgent:\n{0}", e);
                Stop();
                return false;
            }

            _listeningTask = Task.Run(async () =>
            {
                while (!_stopTokenSource.IsCancellationRequested)
                {
                    try
                    {
                        var query = await _udpListener.ReceiveAsync();
                        ProcessMessageAsync(query);
                    }
                    catch (SocketException e)
                    {
                        if (e.SocketErrorCode != SocketError.ConnectionReset)
                            Logger.Error("[Listener.Receive] Unexpected socket error:\n{0}", e);
                    }
                    catch (AggregateException e)
                    {
                        var socketException = e.InnerException as SocketException;
                        if (socketException != null)
                        {
                            if (socketException.SocketErrorCode != SocketError.ConnectionReset)
                                Logger.Error("[Listener.Receive] Unexpected socket error:\n{0}", e);
                        }
                        else
                            Logger.Error("[Listener] Unexpected exception:\n{0}", e);
                    }
                    catch (ObjectDisposedException)
                    {
                    } // Force closing _udpListener will cause this exception
                    catch (Exception e)
                    {
                        Logger.Error("[Listener] Unexpected exception:\n{0}", e);
                    }
                }
            }, _stopTokenSource.Token);

            _forwardingTask = Task.Run(async () =>
            {
                while (!_stopTokenSource.IsCancellationRequested)
                {
                    try
                    {
                        var query = await _udpForwarder.ReceiveAsync();
                        DnsMessage message;
                        try
                        {
                            message = DnsMessage.Parse(query.Buffer);
                        }
                        catch (Exception)
                        {
                            throw new ParsingException();
                        }
                        if (!_transactionClients.ContainsKey(message.TransactionID)) continue;
                        IPEndPoint remoteEndPoint;
                        CancellationTokenSource ignore;
                        _transactionClients.TryRemove(message.TransactionID, out remoteEndPoint);
                        _transactionTimeoutCancellationTokenSources.TryRemove(message.TransactionID, out ignore);
                        await _udpListener.SendAsync(query.Buffer, query.Buffer.Length, remoteEndPoint);

                        // Update cache
                        if (Options.CacheResponse)
                            Cache.Update(message.Questions[0], message, Options.CacheAge);
                    }
                    catch (ParsingException)
                    {
                    }
                    catch (SocketException e)
                    {
                        if (e.SocketErrorCode != SocketError.ConnectionReset)
                            Logger.Error("[Forwarder.Send] Name server unreachable.");
                        else
                            Logger.Error("[Forwarder.Receive] Unexpected socket error:\n{0}", e);
                    }
                    catch (ObjectDisposedException)
                    {
                    } // Force closing _udpListener will cause this exception
                    catch (Exception e)
                    {
                        Logger.Error("[Forwarder] Unexpected exception:\n{0}", e);
                    }
                }
            }, _stopTokenSource.Token);

            Logger.Info("Listening on {0}...", endPoint);
            OnStarted();
            return true;
        }

        public void Stop()
        {
            _stopTokenSource?.Cancel();
            _udpListener?.Close();
            _udpForwarder?.Close();

            try
            {
                _listeningTask?.Wait();
                _forwardingTask?.Wait();
            }
            catch (AggregateException)
            {
            }

            _stopTokenSource = null;
            _udpListener = null;
            _udpForwarder = null;
            _listeningTask = null;
            _forwardingTask = null;
            _transactionClients = null;
            _transactionTimeoutCancellationTokenSources = null;

            OnStopped();
        }

        private async void ProcessMessageAsync(UdpReceiveResult udpMessage)
        {
            await Task.Run(async () =>
            {
                try
                {
                    DnsMessage message;
                    DnsQuestion question;
                    var respondedFromCache = false;

                    try
                    {
                        message = DnsMessage.Parse(udpMessage.Buffer);
                        question = message.Questions[0];
                    }
                    catch (Exception)
                    {
                        throw new ParsingException();
                    }

                    // Check for authorized subnet access
                    if (_networkWhitelist != null)
                    {
                        if (_networkWhitelist.All(pair =>
                            !pair.Key.GetNetworkAddress(pair.Value)
                                .Equals(udpMessage.RemoteEndPoint.Address.GetNetworkAddress(pair.Value))))
                        {
                            Logger.Info("-> {0} is not authorized, who requested {1}.",
                                udpMessage.RemoteEndPoint.Address,
                                question);
                            message.ReturnCode = ReturnCode.Refused;
                            message.IsQuery = false;
                        }
                    }
                    Logger.Info("-> {0} requested {1} (#{2}, {3}).", udpMessage.RemoteEndPoint.Address, question.Name,
                        message.TransactionID, question.RecordType);

                    // Query cache
                    if (Options.CacheResponse)
                    {
                        if (Cache.ContainsKey(question.Name) && Cache[question.Name].ContainsKey(question.RecordType))
                        {
                            var entry = Cache[question.Name][question.RecordType];
                            if (!entry.IsExpired)
                            {
                                var cachedMessage = entry.Message;
                                Logger.Info("-> #{0} served from cache.", message.TransactionID,
                                    cachedMessage.TransactionID);
                                cachedMessage.TransactionID = message.TransactionID; // Update transaction ID
                                cachedMessage.TSigOptions = message.TSigOptions; // Update TSig options
                                message = cachedMessage;
                                respondedFromCache = true;
                            }
                        }
                    }

                    var targetNameServer = Options.DefaultNameServer;
                    var useHttpQuery = Options.UseHttpQuery;
                    var queryTimeout = Options.QueryTimeout;
                    var useCompressionMutation = Options.CompressionMutation;

                    // Match rules
                    if (message.IsQuery &&
                        (question.RecordType == RecordType.A || question.RecordType == RecordType.Aaaa))
                    {
                        for (var i = Rules.Count - 1; i >= 0; i--)
                        {
                            var match = Regex.Match(question.Name, Rules[i].Pattern);
                            if (!match.Success) continue;

                            // Domain name matched

                            var recordType = question.RecordType;
                            if (Rules[i].ForceAAAA != null && Rules[i].ForceAAAA.Value) // RecordType override
                                recordType = RecordType.Aaaa;

                            if (Rules[i].NameServer != null) // Name server override
                                targetNameServer = Rules[i].NameServer;

                            if (Rules[i].UseHttpQuery != null) // HTTP query override
                                useHttpQuery = Rules[i].UseHttpQuery.Value;

                            if (Rules[i].QueryTimeout != null) // Query timeout override
                                queryTimeout = Rules[i].QueryTimeout.Value;

                            if (Rules[i].CompressionMutation != null) // Compression pointer mutation override
                                useCompressionMutation = Rules[i].CompressionMutation.Value;

                            if (Rules[i].Address != null)
                            {
                                IPAddress ip;
                                IPAddress.TryParse(Rules[i].Address, out ip);
                                if (ip == null) // Invalid IP, may be a domain name
                                {
                                    var address = string.Format(Rules[i].Address, match.Groups.Cast<object>().ToArray());
                                    if (recordType == RecordType.A && useHttpQuery)
                                    {
                                        await ResolveWithHttp(targetNameServer, address, queryTimeout, message);
                                    }
                                    else
                                    {
                                        var serverEndpoint = Utils.CreateIpEndPoint(targetNameServer, 53);
                                        var dnsClient = new DnsClient(serverEndpoint.Address, queryTimeout,
                                            serverEndpoint.Port);
                                        var response =
                                            await
                                                Task<DnsMessage>.Factory.FromAsync(dnsClient.BeginResolve,
                                                    dnsClient.EndResolve,
                                                    address, recordType, question.RecordClass, null);
                                        if (response == null)
                                        {
                                            Logger.Warning($"Remote resolve failed for {address}.");
                                            return;
                                        }
                                        foreach (var answerRecord in response.AnswerRecords)
                                        {
                                            answerRecord.Name = question.Name;
                                            message.AnswerRecords.Add(answerRecord);
                                        }
                                        message.ReturnCode = response.ReturnCode;
                                        message.IsQuery = false;
                                    }
                                }
                                else
                                {
                                    if (recordType == RecordType.A &&
                                        ip.AddressFamily == AddressFamily.InterNetwork)
                                        message.AnswerRecords.Add(new ARecord(question.Name, 600, ip));
                                    else if (recordType == RecordType.Aaaa &&
                                             ip.AddressFamily == AddressFamily.InterNetworkV6)
                                        message.AnswerRecords.Add(new AaaaRecord(question.Name, 600, ip));
                                    else // Type mismatch
                                        continue;

                                    message.ReturnCode = ReturnCode.NoError;
                                    message.IsQuery = false;
                                }
                            }

                            break;
                        }
                    }

                    // TODO: Consider how to integrate System.Net.Dns with this project.
                    // Using System.Net.Dns to forward query if compression mutation is disabled
                    //if (message.IsQuery && !useCompressionMutation &&
                    //    (question.RecordType == RecordType.A || question.RecordType == RecordType.Aaaa))
                    //{
                    //    var dnsResponse = await Dns.GetHostAddressesAsync(question.Name);

                    //    if (question.RecordType == RecordType.A)
                    //    {
                    //        message.AnswerRecords.AddRange(dnsResponse.Where(
                    //            ip => ip.AddressFamily == AddressFamily.InterNetwork).Select(
                    //                ip => new ARecord(question.Name, 0, ip)));
                    //    else if (question.RecordType == RecordType.Aaaa)
                    //    {
                    //        message.AnswerRecords.AddRange(dnsResponse.Where(
                    //            ip => ip.AddressFamily == AddressFamily.InterNetworkV6).Select(
                    //                ip => new AaaaRecord(question.Name, 0, ip)));
                    //    }
                    //    message.ReturnCode = ReturnCode.NoError;
                    //    message.IsQuery = false;
                    //}

                    if (message.IsQuery && question.RecordType == RecordType.A && useHttpQuery)
                    {
                        await ResolveWithHttp(targetNameServer, question.Name, queryTimeout, message);
                    }

                    if (message.IsQuery)
                    {
                        // Use internal forwarder to forward query to another name server
                        await ForwardMessage(message, udpMessage, Utils.CreateIpEndPoint(targetNameServer, 53),
                            queryTimeout, useCompressionMutation);
                    }
                    else
                    {
                        // Already answered, directly return to the client
                        byte[] responseBuffer;
                        message.Encode(false, out responseBuffer);
                        if (responseBuffer != null)
                        {
                            await
                                _udpListener.SendAsync(responseBuffer, responseBuffer.Length, udpMessage.RemoteEndPoint);

                            // Update cache
                            if (Options.CacheResponse && !respondedFromCache)
                                Cache.Update(question, message, Options.CacheAge);
                        }
                    }
                }
                catch (ParsingException)
                {
                }
                catch (SocketException e)
                {
                    Logger.Error("[Listener.Send] Unexpected socket error:\n{0}", e);
                }
                catch (Exception e)
                {
                    Logger.Error("[Processor] Unexpected exception:\n{0}", e);
                }
            });
        }

        private async Task ForwardMessage(DnsMessage message, UdpReceiveResult originalUdpMessage,
            IPEndPoint targetNameServer, int queryTimeout,
            bool useCompressionMutation)
        {
            DnsQuestion question = null;
            if (message.Questions.Count > 0)
                question = message.Questions[0];

            byte[] responseBuffer = null;
            try
            {
                if ((Equals(targetNameServer.Address, IPAddress.Loopback) ||
                     Equals(targetNameServer.Address, IPAddress.IPv6Loopback)) &&
                    targetNameServer.Port == ((IPEndPoint) _udpListener.Client.LocalEndPoint).Port)
                    throw new InfiniteForwardingException(question);

                byte[] sendBuffer;
                if (useCompressionMutation)
                    message.Encode(false, out sendBuffer, true);
                else
                    sendBuffer = originalUdpMessage.Buffer;

                _transactionClients[message.TransactionID] = originalUdpMessage.RemoteEndPoint;

                // Send to Forwarder
                await _udpForwarder.SendAsync(sendBuffer, sendBuffer.Length, targetNameServer);

                if (_transactionTimeoutCancellationTokenSources.ContainsKey(message.TransactionID))
                    _transactionTimeoutCancellationTokenSources[message.TransactionID].Cancel();
                var cancellationTokenSource = new CancellationTokenSource();
                _transactionTimeoutCancellationTokenSources[message.TransactionID] = cancellationTokenSource;

                // Timeout task to cancel the request
                try
                {
                    await Task.Delay(queryTimeout, cancellationTokenSource.Token);
                    if (!_transactionClients.ContainsKey(message.TransactionID)) return;
                    IPEndPoint ignoreEndPoint;
                    CancellationTokenSource ignoreTokenSource;
                    _transactionClients.TryRemove(message.TransactionID, out ignoreEndPoint);
                    _transactionTimeoutCancellationTokenSources.TryRemove(message.TransactionID,
                        out ignoreTokenSource);

                    var warningText = message.Questions.Count > 0
                        ? $"{message.Questions[0].Name} (Type {message.Questions[0].RecordType})"
                        : $"Transaction #{message.TransactionID}";
                    Logger.Warning("Query timeout for: {0}", warningText);
                }
                catch (TaskCanceledException)
                {
                }
            }
            catch (InfiniteForwardingException e)
            {
                Logger.Warning("[Forwarder.Send] Infinite forwarding detected for: {0} (Type {1})", e.Question.Name,
                    e.Question.RecordType);
                Utils.ReturnDnsMessageServerFailure(message, out responseBuffer);
            }
            catch (SocketException e)
            {
                if (e.SocketErrorCode == SocketError.ConnectionReset) // Target name server port unreachable
                    Logger.Warning("[Forwarder.Send] Name server port unreachable: {0}", targetNameServer);
                else
                    Logger.Error("[Forwarder.Send] Unhandled socket error: {0}", e.Message);
                Utils.ReturnDnsMessageServerFailure(message, out responseBuffer);
            }
            catch (Exception e)
            {
                Logger.Error("[Forwarder] Unexpected exception:\n{0}", e);
                Utils.ReturnDnsMessageServerFailure(message, out responseBuffer);
            }

            // If we got some errors
            if (responseBuffer != null)
                await _udpListener.SendAsync(responseBuffer, responseBuffer.Length, originalUdpMessage.RemoteEndPoint);
        }

        private static async Task ResolveWithHttp(string targetNameServer, string domainName, int timeout, DnsMessage message)
        {
            var request = WebRequest.Create($"http://{targetNameServer}/d?dn={domainName}&ttl=1");
            request.Timeout = timeout;
            var stream = (await request.GetResponseAsync()).GetResponseStream();
            if (stream == null)
                throw new Exception("Invalid HTTP response stream.");
            using (var reader = new StreamReader(stream))
            {
                var result = await reader.ReadToEndAsync();
                if (string.IsNullOrEmpty(result))
                {
                    message.ReturnCode = ReturnCode.NxDomain;
                    message.IsQuery = false;
                }
                else
                {
                    var parts = result.Split(',');
                    var ips = parts[0].Split(';');
                    foreach (var ip in ips)
                    {
                        message.AnswerRecords.Add(new ARecord(domainName, int.Parse(parts[1]), IPAddress.Parse(ip)));
                    }
                    message.ReturnCode = ReturnCode.NoError;
                    message.IsQuery = false;
                }
            }
        }

        #region Event Invokers

        protected virtual void OnStarted()
        {
            var handler = Started;
            handler?.Invoke();
        }

        protected virtual void OnStopped()
        {
            var handler = Stopped;
            handler?.Invoke();
        }

        #endregion
    }
}