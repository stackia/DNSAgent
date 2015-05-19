using System.Collections.Generic;
using System.Net;
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
        }

        /// <summary>
        ///     Set to true to automatically hide the window on start.
        /// </summary>
        public bool? HideOnStart { get; set; }

        /// <summary>
        ///     IP and port that DNSAgent will listen on. 0.0.0.0:53 for all interfaces and 127.0.0.1:53 for localhost. Of course
        ///     you can use other ports.
        /// </summary>
        public string ListenOn { get; set; }

        /// <summary>
        ///     Querys that don't match any rules will be send to this server.
        /// </summary>
        public string DefaultNameServer { get; set; }

        public bool? UseSystemDNS { get; set; }

        /// <summary>
        ///     Timeout for a query, in milliseconds. This may be overridden by rules.cfg for a specific domain name.
        /// </summary>
        public int? QueryTimeout { get; set; }

        /// <summary>
        ///     Whether to enable compression pointer mutation to query the default name servers. This may avoid MITM attack in
        ///     some network environments.
        /// </summary>
        public bool? CompressionMutation { get; set; }

        /// <summary>
        ///     Whether to enable caching of responses.
        /// </summary>
        public bool? CacheResponse { get; set; }

        /// <summary>
        ///     How long, in minutes, to cache a repsonse.
        /// </summary>
        public int? CacheAge { get; set; }

        /// <summary>
        ///     Whether or not to filter based on source IP
        /// </summary>
        public bool? FilterSourceIP { get; set; }

        /// <summary>
        ///     List of valid source networks
        /// </summary>
        private List<string> _validnetworks;
        private List<int> _validsourcenetworkmasks = new List<int>();
        private List<IPAddress> _validsourcenetworks = new List<IPAddress>();

        public List<string> ValidNetworks
        {
            get { return _validnetworks; }
            set
            {
                _validnetworks = value;
                _validsourcenetworks = new List<IPAddress>();
                _validsourcenetworkmasks = new List<int>();
                _validnetworks.ForEach(x =>
                   {
                       var _pieces = x.Split('/');
                       var _ip = IPAddress.Parse(_pieces[0]);
                       var _mask = int.Parse(_pieces[1]);
                       if (!_validsourcenetworks.Contains(_ip))
                       {
                           _validsourcenetworks.Add(_ip);
                       }
                       if (!_validsourcenetworkmasks.Contains(_mask))
                       {
                           _validsourcenetworkmasks.Add(_mask);
                       }
                   });

            }
        }

       
        /// <summary>
        ///     List of valid source networks
        /// </summary>
        public List<IPAddress> ValidSourceNetworks
        {
            get
            {
                return _validsourcenetworks;
            }
        }


       
        /// <summary>
        ///     List of valid source network mask
        /// </summary>
        public List<int> ValidSourceNetworkMasks
        {
            get
            {
                return _validsourcenetworkmasks;
            }
        }
    }
}