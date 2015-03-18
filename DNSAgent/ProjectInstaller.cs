using System.ComponentModel;
using System.Configuration.Install;
using System.ServiceProcess;

namespace DNSAgent
{
    [RunInstaller(true)]
    public class ProjectInstaller : Installer
    {
        public ProjectInstaller()
        {
            var serviceProcessInstaller = new ServiceProcessInstaller
            {
                Account = ServiceAccount.LocalSystem
            };

            var serviceInstaller = new ServiceInstaller
            {
                ServiceName = "DNSAgent",
                StartType = ServiceStartMode.Automatic
            };

            // Automatically start after install
            AfterInstall += (sender, args) =>
            {
                using (var serviceController = new ServiceController(serviceInstaller.ServiceName))
                    serviceController.Start();
            };

            Installers.AddRange(new Installer[]
            {
                serviceProcessInstaller,
                serviceInstaller
            });
        }
    }
}