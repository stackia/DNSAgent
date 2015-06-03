using System.Collections.Generic;

namespace DNSAgent
{
    internal class Options
    {
        public Options()
        {
            HideOnStart = false;
            ListenOn = "127.0.0.1";
            DefaultNameServer = "8.8.8.8";
            QueryTimeout = 4000;
            CompressionMutation = false;
            CacheResponse = true;
            CacheAge = 0;
            NetworkWhitelist = null;
        }

        /// <summary>
        ///     Set to true to automatically hide the window on start.
        /// </summary>
        public bool HideOnStart { get; set; }

        /// <summary>
        ///     IP and port that DNSAgent will listen on. 0.0.0.0:53 for all interfaces and 127.0.0.1:53 for localhost. Of course
        ///     you can use other ports.
        /// </summary>
        public string ListenOn { get; set; }

        /// <summary>
        ///     Querys that don't match any rules will be send to this server.
        /// </summary>
        public string DefaultNameServer { get; set; }

        /// <summary>
        ///     Timeout for a query, in milliseconds. This may be overridden by rules.cfg for a specific domain name.
        /// </summary>
        public int QueryTimeout { get; set; }

        /// <summary>
        ///     Whether to enable compression pointer mutation to query the default name servers. This may avoid MITM attack in
        ///     some network environments.
        /// </summary>
        public bool CompressionMutation { get; set; }

        /// <summary>
        ///     Whether to enable caching of responses.
        /// </summary>
        public bool CacheResponse { get; set; }

        /// <summary>
        ///     How long will the cached response live. If a DNS record's TTL is longer than this value, it will be used instead of
        ///     this. Set to 0 to use the original TTL.
        /// </summary>
        public int CacheAge { get; set; }

        /// <summary>
        ///     Source network whitelist. Only IPs from these network are accepted. Set to null to accept all IP (disable
        ///     whitelist), empty to deny all IP.
        /// </summary>
        public List<string> NetworkWhitelist { get; set; }
    }
}