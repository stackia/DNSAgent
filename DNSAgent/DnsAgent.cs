using System;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using ARSoft.Tools.Net.Dns;
using DNSAgent;

namespace DnsAgent
{
    internal class DnsAgent
    {
        public DnsAgent(Options options, Rules rules)
        {
            Options = options ?? new Options();
            Rules = rules ?? new Rules();
        }

        public Options Options { get; set; }
        public Rules Rules { get; set; }
        private UdpClient UdpListener { get; set; }
        public event Action Started;

        public void Start()
        {
            var endPoint = Utils.CreateIpEndPoint(Options.ListenOn, 53);
            UdpListener = new UdpClient(endPoint);
            var connectionPool = new Semaphore(25, 25);

            Logger.Info("DNSAgent has been started.");
            Logger.Info("Listening on {0}...", endPoint);
            Console.Title = "DNSAgent - Listening ...";
            OnStarted();

            while (connectionPool.WaitOne())
                ReceiveMessage(connectionPool);
        }

        public async void ReceiveMessage(Semaphore connectionPool)
        {
            try
            {
                var query = await UdpListener.ReceiveAsync();
                var message = DnsMessage.Parse(query.Buffer);
                var targetNameServer = Options.DefaultNameServer;
                if (Options.QueryTimeout == null)
                    throw new NullReferenceException();
                if (Options.CompressionMutation == null)
                    throw new NullReferenceException();
                var queryTimeout = Options.QueryTimeout.Value;
                var useCompressionMutation = Options.CompressionMutation.Value;
                byte[] responseBuffer;

                // Match rules
                var question = message.Questions[0];
                if (question.RecordType == RecordType.A || question.RecordType == RecordType.Aaaa)
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

                            if (question.RecordType == RecordType.A && ip.AddressFamily == AddressFamily.InterNetwork)
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

                if (message.IsQuery)
                {
                    // Forward query to another name server
                    responseBuffer =
                        await
                            ForwardMessage(message, query.Buffer, Utils.CreateIpEndPoint(targetNameServer, 53),
                                queryTimeout, useCompressionMutation);
                }
                else
                {
                    // Already answered, directly return to the client
                    message.Encode(false, out responseBuffer);
                }
                await UdpListener.SendAsync(responseBuffer, responseBuffer.Length, query.RemoteEndPoint);
            }
            catch (SocketException e)
            {
                if (e.SocketErrorCode != SocketError.ConnectionReset)
                    Logger.Error("Unexpected socket error:\n{0}", e);
            }
            catch (Exception e)
            {
                Logger.Error("Unexpected exception:\n{0}", e);
            }
            finally
            {
                connectionPool.Release();
            }
        }

        public void Stop()
        {
            UdpListener.Close();
        }

        private async Task<byte[]> ForwardMessage(DnsMessage message, byte[] originalMessage,
            IPEndPoint targetNameServer, int queryTimeout, bool useCompressionMutation)
        {
            DnsQuestion question = null;
            if (message.Questions.Count > 0)
                question = message.Questions[0];

            byte[] responseBuffer;
            using (var forwarder = new UdpClient())
            {
                try
                {
                    if ((Equals(targetNameServer.Address, IPAddress.Loopback) ||
                         Equals(targetNameServer.Address, IPAddress.IPv6Loopback)) &&
                        targetNameServer.Port == ((IPEndPoint) UdpListener.Client.LocalEndPoint).Port)
                        throw new InfiniteForwardingException(question);
                    forwarder.Connect(targetNameServer);

                    byte[] sendBuffer;
                    if (useCompressionMutation)
                        message.Encode(false, out sendBuffer, true);
                    else
                        sendBuffer = originalMessage;

                    await forwarder.SendAsync(sendBuffer, sendBuffer.Length);
                    var receiveTask = forwarder.ReceiveAsync();
                    if (await Task.WhenAny(receiveTask, Task.Delay(queryTimeout)) == receiveTask)
                    {
                        var response = await receiveTask;
                        responseBuffer = response.Buffer;
                    }
                    else
                    {
                        // Timeout
                        throw new NameServerTimeoutException();
                    }
                }
                catch (NameServerTimeoutException)
                {
                    var warningText = message.Questions.Count > 0
                        ? string.Format("{0} (Type {1})", message.Questions[0].Name,
                            message.Questions[0].RecordType)
                        : string.Format("Transaction #{0}", message.TransactionID);
                    Logger.Warning("Query timeout for: {0}", warningText);
                    Utils.ReturnDnsMessageServerFailure(message, out responseBuffer);
                }
                catch (InfiniteForwardingException e)
                {
                    Logger.Warning("Infinite forwarding detected for: {0} (Type {1})", e.Question.Name,
                        e.Question.RecordType);
                    Utils.ReturnDnsMessageServerFailure(message, out responseBuffer);
                }
                catch (SocketException e)
                {
                    if (e.SocketErrorCode == SocketError.ConnectionReset) // Target name server port unreachable
                        Logger.Warning("Name server port unreachable: {0}", targetNameServer);
                    else
                        Logger.Error("Unhandled socket error: {0}", e.Message);
                    Utils.ReturnDnsMessageServerFailure(message, out responseBuffer);
                }
                catch (Exception e)
                {
                    Logger.Error("Unexpected exception:\n{0}", e);
                    Utils.ReturnDnsMessageServerFailure(message, out responseBuffer);
                }
            }
            return responseBuffer;
        }

        protected virtual void OnStarted()
        {
            var handler = Started;
            if (handler != null) handler();
        }
    }
}