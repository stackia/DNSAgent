using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using ARSoft.Tools.Net.Dns;
using ARSoft.Tools.Net;
using DNSAgent;

namespace DnsAgent
{
    internal class DnsAgent
    {
        private Task _forwardingTask;
        private Task _listeningTask;
        private CancellationTokenSource _stopTokenSource;
        private ConcurrentDictionary<ushort, IPEndPoint> _transactionClients;
        private ConcurrentDictionary<ushort, CancellationTokenSource> _transactionTimeoutCancellationTokenSources;
        private UdpClient _udpForwarder;
        private UdpClient _udpListener;
        private System.Object lockThis = new System.Object();

        public DnsAgent(Options options, Rules rules)
        {
            Options = options ?? new Options();
            Rules = rules ?? new Rules();
            Cache = new Cache();
        }

        public Options Options { get; set; }
        public Rules Rules { get; set; }
        public Cache Cache { get; set; }
        public event Action Started;
        public event Action Stopped;

        public void Start()
        {
            var endPoint = Utils.CreateIpEndPoint(Options.ListenOn, 53);
            _udpListener = new UdpClient(endPoint);
            _udpForwarder = new UdpClient(0);
            _stopTokenSource = new CancellationTokenSource();
            _transactionClients = new ConcurrentDictionary<ushort, IPEndPoint>();
            _transactionTimeoutCancellationTokenSources = new ConcurrentDictionary<ushort, CancellationTokenSource>();

            _listeningTask = Task.Run(async () =>
            {
                while (!_stopTokenSource.IsCancellationRequested)
                {
                    try
                    {
                        var query = await _udpListener.ReceiveAsync();
                        await Task.Run(() => ProcessMessage(query));
                    }
                    catch (SocketException e)
                    {
                        if (e.SocketErrorCode != SocketError.ConnectionReset)
                            Logger.Error("[Listener.Receive] Unexpected socket error:\n{0}", e);
                    }
                    catch (ObjectDisposedException) { } // Force closing _udpListener will cause this exception
                    catch (Exception e)
                    {
                        Logger.Error("[Listener] Unexpected exception:\n{0}", e);
                    }
                }
                _stopTokenSource.Token.ThrowIfCancellationRequested();
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
                        lock (lockThis)
                        {
                            if (Options.CacheResponse == true && !Cache.ContainsKey(message.Questions[0].Name))
                            {
                                Cache.Add(message.Questions[0].Name, new CacheItem() { ResponseMessage = message });
                            }
                        }
                    }
                    catch (ParsingException) { }
                    catch (SocketException e)
                    {
                        if (e.SocketErrorCode != SocketError.ConnectionReset)
                            Logger.Error("[Forwarder.Send] Name server unreachable.");
                        else
                            Logger.Error("[Forwarder.Receive] Unexpected socket error:\n{0}", e);
                    }
                    catch (ObjectDisposedException) { } // Force closing _udpListener will cause this exception
                    catch (Exception e)
                    {
                        Logger.Error("[Forwarder] Unexpected exception:\n{0}", e);
                    }
                }
                _stopTokenSource.Token.ThrowIfCancellationRequested();
            });

            Logger.Info("DNSAgent has been started.");
            Logger.Info("Listening on {0}...", endPoint);
            Logger.Title = "DNSAgent - Listening ...";
            OnStarted();
        }

        public void Stop()
        {
            if (_stopTokenSource != null)
                _stopTokenSource.Cancel();

            if (_udpListener != null)
                _udpListener.Close();

            if (_udpForwarder != null)
                _udpForwarder.Close();

            try
            {
                if (_listeningTask != null)
                    _listeningTask.Wait();

                if (_forwardingTask != null)
                    _forwardingTask.Wait();
            }
            catch (AggregateException) { }

            _stopTokenSource = null;
            _udpListener = null;
            _udpForwarder = null;
            _listeningTask = null;
            _forwardingTask = null;
            _transactionClients = null;
            _transactionTimeoutCancellationTokenSources = null;

            Logger.Info("DNSAgent has been stopped.");
            OnStopped();
        }

        private async Task ProcessMessage(UdpReceiveResult udpMessage)
        {
            try
            {
                bool handled = false;
                DnsMessage message;                
                DnsQuestion question;

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
                if (Options.FilterSourceIP == true)
                {
                    var _srcIP = udpMessage.RemoteEndPoint.Address;
                    var _validIP = false;

                    Options.ValidSourceNetworkMasks.ForEach(x =>
                        {
                            var _network = IPAddressExtension.GetNetworkAddress(_srcIP, x);
                            if (Options.ValidSourceNetworks.Contains(_network))
                            {
                                _validIP = true;
                            }
                        }
                    );
                    if (!_validIP)
                    {
                        Logger.Info("-> {0} Is not Authorized. They requested {1}", udpMessage.RemoteEndPoint.Address, question);
                        return;
                    }
                }

                var targetNameServer = Options.DefaultNameServer;
                if (Options.QueryTimeout == null)
                    throw new NullReferenceException();
                if (Options.CompressionMutation == null)
                    throw new NullReferenceException();
                var queryTimeout = Options.QueryTimeout.Value;
                var useCompressionMutation = Options.CompressionMutation.Value;


               
                Logger.Info("-> {0} has requested {1}", udpMessage.RemoteEndPoint.Address, question.Name);
                if (Options.CacheResponse == true)
                {
                    if (Cache.ContainsKey(question.Name))
                    {
                        var responseItem = Cache[question.Name];
                        if (responseItem.Age < Options.CacheAge)
                        {
                            var _newTransID = message.TransactionID;
                            var _newTsig = message.TSigOptions;
                            Logger.Info("-> Served from Cache, reusing transaction id: {0}", responseItem.ResponseMessage.TransactionID);
                            handled = true;
                            message = responseItem.ResponseMessage;
                            message.TransactionID = _newTransID;
                            message.TSigOptions = _newTsig;
                        }
                        else
                        {
                            Cache.Remove(question.Name);
                        }
                    }
                }
                // Match rules
                if (!handled && (question.RecordType == RecordType.A || question.RecordType == RecordType.Aaaa))
                {
                    for (var i = Rules.Count - 1; i >= 0; i--)
                    {
                        if (!Regex.IsMatch(question.Name, Rules[i].Pattern)) continue;

                        // Domain name matched
                        if (Rules[i].Address != null)
                        {
                            IPAddress ip;
                            IPAddress.TryParse(Rules[i].Address, out ip);
                            if (ip == null) continue; // Invalid rule

                            if (question.RecordType == RecordType.A &&
                                ip.AddressFamily == AddressFamily.InterNetwork)
                                message.AnswerRecords.Add(new ARecord(question.Name, 0, ip));
                            else if (question.RecordType == RecordType.Aaaa &&
                                     ip.AddressFamily == AddressFamily.InterNetworkV6)
                                message.AnswerRecords.Add(new AaaaRecord(question.Name, 0, ip));
                            else // Type mismatch
                                continue;

                            message.ReturnCode = ReturnCode.NoError;
                            message.IsQuery = false;
                        }
                        else
                        {
                            if (Rules[i].NameServer != null) // Name server override
                            {
                                targetNameServer = Rules[i].NameServer;
                                if (Rules[i].CompressionMutation != null)
                                    useCompressionMutation = Rules[i].CompressionMutation.Value;
                            }

                            if (Rules[i].QueryTimeout != null) // Query timeout override
                                queryTimeout = Rules[i].QueryTimeout.Value;
                        }
                    }
                }

                if (message.IsQuery && !handled)
                {
                    if (Options.UseSystemDNS == true && (question.RecordType == RecordType.A || question.RecordType == RecordType.Aaaa))
                    {
                        var dnsResponse = Dns.GetHostAddresses(question.Name);
                        foreach (var ip in dnsResponse)
                        {
                            if (question.RecordType == RecordType.A &&
                               ip.AddressFamily == AddressFamily.InterNetwork)
                            {
                                var answer = new ARecord(question.Name, 0, ip);
                                if (!message.AnswerRecords.Contains(answer))
                                {
                                    message.AnswerRecords.Add(answer);
                                }

                            }
                            else if (question.RecordType == RecordType.Aaaa &&
                                     ip.AddressFamily == AddressFamily.InterNetworkV6)
                            {
                                var answer = new AaaaRecord(question.Name, 0, ip);
                                if (!message.AnswerRecords.Contains(answer))
                                {
                                    message.AnswerRecords.Add(answer);
                                }
                            }
                            else
                            { // Type mismatch
                                continue;
                            }
                        }
                        handled = true;
                    }
                    else
                    {
                        // Forward query to another name server
                        await ForwardMessage(message, udpMessage, Utils.CreateIpEndPoint(targetNameServer, 53), queryTimeout, useCompressionMutation);
                    }
                }

                if (handled)
                {
                    // Already answered, directly return to the client
                    byte[] responseBuffer;
                    message.Encode(false, out responseBuffer);
                    if (responseBuffer != null)
                    {
                        await _udpListener.SendAsync(responseBuffer, responseBuffer.Length, udpMessage.RemoteEndPoint);
                        lock (lockThis)
                        {
                            if (Options.CacheResponse == true && !Cache.ContainsKey(message.Questions[0].Name))
                            {
                                Cache.Add(message.Questions[0].Name, new CacheItem() { ResponseMessage = message });
                            }
                        }
                    }

                }

            }
            catch (ParsingException) { }
            catch (SocketException e)
            {
                Logger.Error("[Listener.Send] Unexpected socket error:\n{0}", e);
            }
            catch (Exception e)
            {
                Logger.Error("[Processor] Unexpected exception:\n{0}", e);
            }
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
                    targetNameServer.Port == ((IPEndPoint)_udpListener.Client.LocalEndPoint).Port)
                    throw new InfiniteForwardingException(question);

                byte[] sendBuffer;
                if (useCompressionMutation)
                {
                    message.Encode(false, out sendBuffer, true);
                }
                else
                {
                    sendBuffer = originalUdpMessage.Buffer;
                }

                _transactionClients[message.TransactionID] = originalUdpMessage.RemoteEndPoint;

                // Send to Forwarder
                await _udpForwarder.SendAsync(sendBuffer, sendBuffer.Length, targetNameServer);

                if (_transactionTimeoutCancellationTokenSources.ContainsKey(message.TransactionID))
                    _transactionTimeoutCancellationTokenSources[message.TransactionID].Cancel();
                var cancellationTokenSource = new CancellationTokenSource();
                _transactionTimeoutCancellationTokenSources[message.TransactionID] = cancellationTokenSource;

                // Timeout task to cancel the request
                await Task.Delay(queryTimeout, cancellationTokenSource.Token).ContinueWith(t =>
                  {
                      if (!_transactionClients.ContainsKey(message.TransactionID)) return;
                      IPEndPoint ignoreEndPoint;
                      CancellationTokenSource ignoreTokenSource;
                      _transactionClients.TryRemove(message.TransactionID, out ignoreEndPoint);
                      _transactionTimeoutCancellationTokenSources.TryRemove(message.TransactionID, out ignoreTokenSource);

                      var warningText = message.Questions.Count > 0
                          ? string.Format("{0} (Type {1})", message.Questions[0].Name,
                              message.Questions[0].RecordType)
                          : string.Format("Transaction #{0}", message.TransactionID);
                      Logger.Warning("Query timeout for: {0}", warningText);
                  }, cancellationTokenSource.Token);

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

            if (responseBuffer != null)
            {
                // Respond to user - don't need to await this one
                await _udpListener.SendAsync(responseBuffer, responseBuffer.Length, originalUdpMessage.RemoteEndPoint);
                lock (lockThis)
                {
                    if (Options.CacheResponse == true && !Cache.ContainsKey(message.Questions[0].Name))
                    {
                        Cache.Add(message.Questions[0].Name, new CacheItem() { ResponseMessage = message });
                    }
                }
            }
        }

        #region Event Invokers

        protected virtual void OnStarted()
        {
            var handler = Started;
            if (handler != null) handler();
        }

        protected virtual void OnStopped()
        {
            var handler = Stopped;
            if (handler != null) handler();
        }

        #endregion
    }
}