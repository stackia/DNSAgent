using System;
using System.Globalization;
using System.Net;
using ARSoft.Tools.Net.Dns;

namespace DNSAgent
{
    internal class Utils
    {
        /// <summary>
        ///     Parse a "IP:Port" string to IPEndPoint. If no port is specified in that string, using defaultPort instead.
        /// </summary>
        /// <param name="endPoint">An "IP:Port" string to parse.</param>
        /// <param name="defaultPort">A default port to use when no port is specified in "IP:Port" string.</param>
        /// <returns>Corresponding IPEndPoint for this "IP:Port" string.</returns>
        public static IPEndPoint CreateIpEndPoint(string endPoint, int defaultPort)
        {
            var ep = endPoint.Split(':');
            IPAddress ip;
            if (ep.Length < 2 || (ep.Length > 2 && !ep[ep.Length - 2].EndsWith("]"))) // IP without port
            {
                if (!IPAddress.TryParse(endPoint, out ip))
                    throw new FormatException("Invalid ip-address");
                return new IPEndPoint(ip, defaultPort);
            }

            if (ep.Length > 2) // IPv6 with port
            {
                if (!IPAddress.TryParse(string.Join(":", ep, 0, ep.Length - 1), out ip))
                    throw new FormatException("Invalid ip-address");
            }
            else // IPv4 with port
            {
                if (!IPAddress.TryParse(ep[0], out ip))
                    throw new FormatException("Invalid ip-address");
            }
            int port;
            if (!int.TryParse(ep[ep.Length - 1], NumberStyles.None, NumberFormatInfo.CurrentInfo, out port))
                throw new FormatException("Invalid port");
            return new IPEndPoint(ip, port);
        }

        public static void ReturnDnsMessageServerFailure(DnsMessage message, out byte[] buffer)
        {
            message.ReturnCode = ReturnCode.ServerFailure;
            message.IsQuery = false;
            message.Encode(false, out buffer);
        }
    }
}