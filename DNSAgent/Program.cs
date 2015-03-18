using System;
using System.Configuration.Install;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.ServiceProcess;
using System.Threading;
using DNSAgent;
using Newtonsoft.Json;

namespace DnsAgent
{
    internal class Program
    {
        private const string OptionsFileName = "options.cfg";
        private const string RulesFileName = "rules.cfg";
        private static DnsAgent dnsAgent;

        private static void Main(string[] args)
        {
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

            if (!Environment.UserInteractive) // Running as service
            {
                using (var service = new Service())
                    ServiceBase.Run(service);
            }
            else // Running as console app
            {
                var parameter = string.Concat(args);
                switch (parameter)
                {
                    case "--install":
                        ManagedInstallerClass.InstallHelper(new[] {"/LogFile=", Assembly.GetExecutingAssembly().Location});
                        return;

                    case "--uninstall":
                        ManagedInstallerClass.InstallHelper(new[] { "/LogFile=", "/u", Assembly.GetExecutingAssembly().Location });
                        return;
                }
                Start(args);
            }
        }

        private static void Start(string[] args)
        {
            Logger.Title = string.Format("DNSAgent - Starting ...");

            var version = Assembly.GetExecutingAssembly().GetName().Version;
            var buildTime = Utils.RetrieveLinkerTimestamp(Assembly.GetExecutingAssembly().Location);
            Logger.Info("DNSAgent {0}.{1}.{2} (build at {3})\n", version.Major, version.Minor,
                version.Build, buildTime.ToString(CultureInfo.CurrentCulture));
            Logger.Info("Starting...");

            dnsAgent = new DnsAgent(ReadOptions(), ReadRules());
            if (Environment.UserInteractive)
            {
                var startedWaitHandler = new ManualResetEvent(false);
                dnsAgent.Started += () => { startedWaitHandler.Set(); };
                dnsAgent.Start();
                startedWaitHandler.WaitOne();
                Logger.Info("Press Ctrl-R to reload configurations, Ctrl-Q to stop and quit.");

                var exit = false;
                while (!exit)
                {
                    var keyInfo = Console.ReadKey(true);
                    if (keyInfo.Modifiers != ConsoleModifiers.Control) continue;
                    switch (keyInfo.Key)
                    {
                        case ConsoleKey.R: // Reload options.cfg and rules.cfg
                            dnsAgent.Options = ReadOptions();
                            dnsAgent.Rules = ReadRules();
                            Logger.Info("Options and rules reloaded.");
                            break;

                        case ConsoleKey.Q:
                            Stop();
                            exit = true;
                            break;
                    }
                }
            }
            else
                dnsAgent.Start();
        }

        private static void Stop()
        {
            if (dnsAgent != null)
                dnsAgent.Stop();
        }

        #region Nested class to support running as service

        private class Service : ServiceBase
        {
            public Service()
            {
                ServiceName = "DNSAgent";
            }

            protected override void OnStart(string[] args)
            {
                Start(args);
                base.OnStart(args);
            }

            protected override void OnStop()
            {
                Program.Stop();
                base.OnStop();
            }
        }

        #endregion

        #region Util functions to read rules

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

        #endregion
    }
}