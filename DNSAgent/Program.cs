using System;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using DNSAgent;
using Newtonsoft.Json;

namespace DnsAgent
{
    internal class Program
    {
        private const string OptionsFileName = "options.cfg";
        private const string RulesFileName = "rules.cfg";

        private static void Main(string[] args)
        {
            var version = Assembly.GetExecutingAssembly().GetName().Version;
            var buildTime = RetrieveLinkerTimestamp(Assembly.GetExecutingAssembly().Location);
            Console.Title = string.Format("DNSAgent - Starting ...");

            Logger.Info("DNSAgent {0}.{1}.{2} (build at {3})\n", version.Major, version.Minor,
                version.Build, buildTime.ToString(CultureInfo.CurrentCulture));
            Logger.Info("Starting...");

            var dnsAgent = new DnsAgent(ReadOptions(), ReadRules());
            var startedWaitHandler = new ManualResetEvent(false);
            dnsAgent.Started += () => { startedWaitHandler.Set(); };
            Task.Run(() => dnsAgent.Start());
            startedWaitHandler.WaitOne();
            Logger.Info("Press R to reload options.cfg and rules.cfg.");

            while (true) // Reload options.cfg and rules.cfg
            {
                var keyInfo = Console.ReadKey(true);
                if (keyInfo.Key != ConsoleKey.R) continue;
                dnsAgent.Options = ReadOptions();
                dnsAgent.Rules = ReadRules();
                Logger.Info("Options and rules reloaded.");
            }
        }

        private static Options ReadOptions()
        {
            Options options;
            if (File.Exists(Path.Combine(Environment.CurrentDirectory, OptionsFileName)))
            {
                options = JsonConvert.DeserializeObject<Options>(
                    File.ReadAllText(Path.Combine(Environment.CurrentDirectory, OptionsFileName)));
            }
            else
            {
                options = new Options();
                File.WriteAllText(Path.Combine(Environment.CurrentDirectory, OptionsFileName),
                    JsonConvert.SerializeObject(options, Formatting.Indented));
            }
            return options;
        }

        private static Rules ReadRules()
        {
            Rules rules;
            using (
                var file = File.Open(Path.Combine(Environment.CurrentDirectory, RulesFileName), FileMode.OpenOrCreate))
            using (var reader = new StreamReader(file))
            using (var jsonTextReader = new JsonTextReader(reader))
            {
                var serializer = JsonSerializer.CreateDefault();
                rules = serializer.Deserialize<Rules>(jsonTextReader) ?? new Rules();
            }
            return rules;
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