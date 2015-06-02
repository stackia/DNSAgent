using System;
using System.Configuration.Install;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using DNSAgent;
using Newtonsoft.Json;

namespace DnsAgent
{
    internal class Program
    {
        private const string OptionsFileName = "options.cfg";
        private const string RulesFileName = "rules.cfg";
        private static DnsAgent _dnsAgent;
        private static NotifyIcon _notifyIcon;
        private static ContextMenu _contextMenu;

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
                        ManagedInstallerClass.InstallHelper(new[]
                        {"/LogFile=", Assembly.GetExecutingAssembly().Location});
                        return;

                    case "--uninstall":
                        ManagedInstallerClass.InstallHelper(new[]
                        {"/LogFile=", "/u", Assembly.GetExecutingAssembly().Location});
                        return;
                }
                Start(args);
            }
        }

        private static void Start(string[] args)
        {
            Logger.Title = "DNSAgent - Starting ...";

            var version = Assembly.GetExecutingAssembly().GetName().Version;
            var buildTime = Utils.RetrieveLinkerTimestamp(Assembly.GetExecutingAssembly().Location);
            var programName = string.Format("DNSAgent {0}.{1}.{2}", version.Major, version.Minor, version.Build);
            Logger.Info("{0} (build at {1})\n", programName, buildTime.ToString(CultureInfo.CurrentCulture));
            Logger.Info("Starting...");

            _dnsAgent = new DnsAgent(ReadOptions(), ReadRules());
            if (Environment.UserInteractive)
            {
                var startedWaitHandler = new ManualResetEvent(false);
                _dnsAgent.Started += () => { startedWaitHandler.Set(); };
                _dnsAgent.Start();
                startedWaitHandler.WaitOne();
                Logger.Info("Press Ctrl-R to reload configurations, Ctrl-Q to stop and quit.");

                Task.Run(() =>
                {
                    var exit = false;
                    while (!exit)
                    {
                        var keyInfo = Console.ReadKey(true);
                        if (keyInfo.Modifiers != ConsoleModifiers.Control) continue;
                        switch (keyInfo.Key)
                        {
                            case ConsoleKey.R: // Reload options.cfg and rules.cfg
                                Reload();
                                break;

                            case ConsoleKey.Q:
                                exit = true;
                                Stop();
                                break;
                        }
                    }
                });

                var hideOnStart = _dnsAgent.Options.HideOnStart ?? false;
                var hideMenuItem = new MenuItem(hideOnStart ? "Show" : "Hide");
                if (hideOnStart)
                    ShowWindow(GetConsoleWindow(), SwHide);
                hideMenuItem.Click += (sender, eventArgs) =>
                {
                    if (hideMenuItem.Text == "Hide")
                    {
                        ShowWindow(GetConsoleWindow(), SwHide);
                        hideMenuItem.Text = "Show";
                    }
                    else
                    {
                        ShowWindow(GetConsoleWindow(), SwShow);
                        hideMenuItem.Text = "Hide";
                    }
                };
                _contextMenu = new ContextMenu(new[]
                {
                    hideMenuItem,
                    new MenuItem("Reload", (sender, eventArgs) => Reload()),
                    new MenuItem("Exit", (sender, eventArgs) => Stop())
                });
                _notifyIcon = new NotifyIcon
                {
                    Icon = Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location),
                    ContextMenu = _contextMenu,
                    Text = programName,
                    Visible = true
                };
                _notifyIcon.MouseClick += (sender, eventArgs) =>
                {
                    if (eventArgs.Button == MouseButtons.Left)
                        hideMenuItem.PerformClick();
                };
                Application.Run();
            }
            else
                _dnsAgent.Start();
        }

        private static void Stop()
        {
            if (_dnsAgent != null)
                _dnsAgent.Stop();

            if (Environment.UserInteractive)
            {
                _notifyIcon.Dispose();
                _contextMenu.Dispose();
                Application.Exit();
            }
        }

        private static void Reload()
        {
            _dnsAgent.Options = ReadOptions();
            _dnsAgent.Rules = ReadRules();
            //_dnsAgent.Cache.Clear();
            Logger.Info("Options and rules reloaded. Cache cleared.");
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

        #region Win32 API Import

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        private const int SwHide = 0;
        private const int SwShow = 5;

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