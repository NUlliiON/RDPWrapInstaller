using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RDPWrapInstaller;
using Serilog;

namespace RDPWrapInstallerConsoleTests
{
    class Program
    {
        private static RDPWrap _rdpWrap;
        
        static async Task Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .Enrich.FromLogContext()
                .WriteTo.Console()
                .CreateLogger();
            
            var host = Host.CreateDefaultBuilder()
                .ConfigureServices((context, services) =>
                {
                    services.AddSingleton<RDPWrap>();
                })
                .UseSerilog()
                .Build();
            
            _rdpWrap = ActivatorUtilities.CreateInstance<RDPWrap>(host.Services);
            
            Console.WriteLine("I - install\n" +
                              "U - uninstall");
            Console.Write("Command: ");
            try
            {
                char cmd = Char.ToLower(Console.ReadKey().KeyChar);
                Console.WriteLine();
                var task = cmd switch
                {
                    'i' => Install(),
                    'u' => Uninstall(),
                    _ => throw new ArgumentOutOfRangeException()
                };
                await task;
                Console.WriteLine("Command completed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex);
            }

            Console.ReadLine();
        }

        private static async Task Install()
        {
            if (!_rdpWrap.IsInstalled())
                await _rdpWrap.Install();
        }

        private static async Task Uninstall()
        {
            if (_rdpWrap.IsInstalled())
                await _rdpWrap.Uninstall();
        }
        
        static void BuildConfig(IConfigurationBuilder builder)
        {
            builder.SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", optional: true)
                .AddEnvironmentVariables();
        }
    }
}