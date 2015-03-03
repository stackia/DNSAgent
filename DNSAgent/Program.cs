using System;
using System.Globalization;
using System.IO;
using System.Reflection;

namespace DnsAgent
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var version = Assembly.GetExecutingAssembly().GetName().Version;
            var buildTime = RetrieveLinkerTimestamp(Assembly.GetExecutingAssembly().Location);
            Console.WriteLine("DNSAgent {0}.{1}.{2} (build at {3})\n", version.Major, version.Minor,
                version.Build, buildTime.ToString(CultureInfo.CurrentCulture));
            Console.Title = string.Format("DNSAgent - Starting ...");
            Console.WriteLine("Starting...");
            var dnsAgent = new DnsAgent();
            dnsAgent.Start();
            Console.WriteLine("DNSAgent has been started.");
            Console.WriteLine("Listening on 0.0.0.0:53...");
            Console.Title = "DNSAgent - Running ...";
            while (true)
                Console.ReadKey(true);
        }

        /// <summary>
        ///     Retrieves the linker timestamp.
        /// </summary>
        /// <param name="filePath">The file path.</param>
        /// <returns></returns>
        /// <remarks>http://www.codinghorror.com/blog/2005/04/determining-build-date-the-hard-way.html</remarks>
        private static DateTime RetrieveLinkerTimestamp(string filePath)
        {
            const int peHeaderOffset = 60;
            const int linkerTimestampOffset = 8;
            var b = new byte[2048];
            FileStream s = null;
            try
            {
                s = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                s.Read(b, 0, 2048);
            }
            finally
            {
                if (s != null)
                    s.Close();
            }
            var dt =
                new DateTime(1970, 1, 1, 0, 0, 0).AddSeconds(BitConverter.ToInt32(b,
                    BitConverter.ToInt32(b, peHeaderOffset) + linkerTimestampOffset));
            return dt.AddHours(TimeZone.CurrentTimeZone.GetUtcOffset(dt).Hours);
        }
    }
}