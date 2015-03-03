using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using ARSoft.Tools.Net.Dns;
using Newtonsoft.Json;

namespace DnsAgent
{
    internal class DnsAgent
    {
        private const int QueryTimeout = 3000;

        public DnsAgent()
        {
            DnsServer = new DnsServer(50, 50, ProcessQuery);
            DnsClient = new DnsClient(IPAddress.Parse("8.8.8.8"), QueryTimeout);
        }

        public List<Rule> Rules { get; set; }
        public DnsServer DnsServer { get; set; }
        public DnsClient DnsClient { get; set; }

        public void Start()
        {
            LoadRules();
            DnsServer.Start();
        }

        public void Stop()
        {
            DnsServer.Stop();
        }

        public void LoadRules()
        {
            using (var file = File.Open(Path.Combine(Environment.CurrentDirectory, "rules.cfg"), FileMode.OpenOrCreate))
            using (var reader = new StreamReader(file))
            using (var jsonTextReader = new JsonTextReader(reader))
            {
                var serializer = JsonSerializer.CreateDefault();
                Rules = serializer.Deserialize<List<Rule>>(jsonTextReader) ?? new List<Rule>();
            }
        }

        private DnsMessageBase ProcessQuery(DnsMessageBase query, IPAddress clientAddress, ProtocolType protocolType)
        {
            var message = query as DnsMessage;
            if (message != null && message.Questions.Count > 0)
            {
                var question = message.Questions[0];
                if (question.RecordType == RecordType.A || question.RecordType == RecordType.Aaaa)
                {
                    for (var i = Rules.Count - 1; i >= 0; i--)
                    {
                        if (!Regex.IsMatch(question.Name, Rules[i].Pattern)) continue;
                        IPAddress ip;
                        if (Rules[i].Address != null)
                        {
                            IPAddress.TryParse(Rules[i].Address, out ip);
                            if (ip == null) continue;
                            if (question.RecordType == RecordType.Aaaa)
                            {
                                message.AnswerRecords.Add(ip.AddressFamily == AddressFamily.InterNetworkV6
                                    ? new AaaaRecord(question.Name, 0, ip)
                                    : new AaaaRecord(question.Name, 0, ip.MapToIPv6()));
                            }
                            else if (question.RecordType == RecordType.A)
                            {
                                if (ip.AddressFamily == AddressFamily.InterNetworkV6) continue;
                                message.AnswerRecords.Add(new ARecord(question.Name, 0, ip));
                            }
                            query.ReturnCode = ReturnCode.NoError;
                            query.IsQuery = false;
                            return query;
                        }
                        if (Rules[i].NameServer != null)
                        {
                            IPAddress.TryParse(Rules[i].NameServer, out ip);
                            if (ip == null) continue;
                            var dnsClient = new DnsClient(ip, QueryTimeout);
                            return dnsClient.SendMessage(message);
                        }
                    }
                }
            }
            return DnsClient.SendMessage(message);
        }
    }
}