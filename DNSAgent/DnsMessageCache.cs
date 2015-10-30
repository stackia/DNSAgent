using System;
using System.Collections.Concurrent;
using System.Linq;
using ARSoft.Tools.Net.Dns;

namespace DNSAgent
{
    internal class DnsCacheMessageEntry
    {
        public DnsCacheMessageEntry(DnsMessage message, int timeToLive)
        {
            Message = message;
            var records = message.AnswerRecords.Concat(message.AuthorityRecords).ToList();
            if (records.Any())
                timeToLive = Math.Max(records.Min(record => record.TimeToLive), timeToLive);
            ExpireTime = DateTime.Now.AddSeconds(timeToLive);
        }

        public DnsMessage Message { get; set; }
        public DateTime ExpireTime { get; set; }

        public bool IsExpired => DateTime.Now > ExpireTime;
    }

    internal class DnsMessageCache :
        ConcurrentDictionary<string, ConcurrentDictionary<RecordType, DnsCacheMessageEntry>>
    {
        public void Update(DnsQuestion question, DnsMessage message, int timeToLive)
        {
            if (!ContainsKey(question.Name))
                this[question.Name] = new ConcurrentDictionary<RecordType, DnsCacheMessageEntry>();

            this[question.Name][question.RecordType] = new DnsCacheMessageEntry(message, timeToLive);
        }
    }
}