using System;
using ARSoft.Tools.Net.Dns;

namespace DNSAgent
{
    ///// <summary>
    /////     Timeout reached when query a remote name server.
    ///// </summary>
    //internal class NameServerTimeoutException : Exception {}

    /// <summary>
    ///     When a query is redirected to this name server itself, causing infinite loop.
    /// </summary>
    internal class InfiniteForwardingException : Exception
    {
        public InfiniteForwardingException(DnsQuestion question)
        {
            Question = question;
        }

        public DnsQuestion Question { get; set; }
    }

    internal class ParsingException : Exception {}
}