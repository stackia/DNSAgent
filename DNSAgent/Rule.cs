using System.Collections.Generic;
using Newtonsoft.Json;

namespace DnsAgent
{
    internal class Rules : List<Rule> {}

    internal class Rule
    {
        /// <summary>
        ///     Regex pattern to match the domain name.
        /// </summary>
        [JsonProperty(Required = Required.Always)]
        public string Pattern { get; set; } = "$^";

        /// <summary>
        ///     IP Address for this domain name. IPv4 address will be returned as A record and IPv6 address as AAAA record.
        /// </summary>
        public string Address { get; set; } = null;

        /// <summary>
        ///     The name server used to query about this domain name. If "Address" is set, this will be ignored.
        /// </summary>
        public string NameServer { get; set; } = null;

        /// <summary>
        ///     Whether to use DNSPod HttpDNS protocol to query the name server for this domain name.
        /// </summary>
        public bool? UseHttpQuery { get; set; } = null;

        /// <summary>
        ///     Timeout for the query, in milliseconds. This overrides options.cfg. If "Address" is set, this will be ignored.
        /// </summary>
        public int? QueryTimeout { get; set; } = null;

        /// <summary>
        ///     Whether to transform request to AAAA type.
        /// </summary>
        public bool? ForceAAAA { get; set; } = null;

        /// <summary>
        ///     Whether to enable compression pointer mutation to query this name server. If "Address" is set, this will be
        ///     ignored.
        /// </summary>
        public bool? CompressionMutation { get; set; } = null;
    }
}