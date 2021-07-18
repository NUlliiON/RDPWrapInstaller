using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using RDPWrapInstaller.Exceptions;
using RDPWrapInstaller.Helpers;

namespace RDPWrapInstaller
{
    internal enum ResourceType
    {
        Rdpw32,
        Rdpw64,
        Rfxvmt32,
        Rfxvmt64,
        Rdpclip6032,
        Rdpclip6132,
        Rdpclip6064,
        Rdpclip6164
    }

    public sealed class RDPWrap
    {
        private readonly Assembly _assembly;
        private readonly ILogger<RDPWrap>? _logger;
    
        private int _procArch;
        private Version _termSvcVersion;
        private bool _online = true;
        private string _initTermSvcPath;

        private const string TermServiceName = "TermService";
        private const string WrapperPath = @"C:\Program Files\RDP Wrapper\rdpwrap.dll";

        public RDPWrap(ILogger<RDPWrap>? logger = null)
        {
            _assembly = Assembly.GetExecutingAssembly();
            _logger = logger;
        }

        private void ServiceConfigStart(string svcName, ServiceStartMode svcStartMode)
        {
            _logger?.LogInformation("Configuring " + svcName);
            var svcCtrl = new ServiceController(svcName);

            _logger?.LogInformation("Change start mode " + svcName);
            ServiceHelper.ChangeStartMode(svcCtrl, svcStartMode);
        }

        private void ServiceStart(string svcName)
        {
            var serviceController = new ServiceController(svcName);

            if (serviceController.Status == ServiceControllerStatus.Stopped)
            {
                _logger?.LogInformation("Starting " + svcName);
                serviceController.Start();
                serviceController.WaitForStatus(ServiceControllerStatus.Running);
            }
            else
            {
                _logger?.LogInformation("Service " + svcName + " is already running");
            }
        }

        private Task ExecuteAndWait(string cmdline)
        {
            var proc = new Process();
            var procInfo = new ProcessStartInfo()
            {
                WindowStyle = ProcessWindowStyle.Hidden,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System),
                RedirectStandardOutput = true,
                FileName = "cmd.exe",
                Arguments = "/C " + cmdline,
                Verb = "runas"
            };
            proc.StartInfo = procInfo;
            proc.Start();
            return proc.WaitForExitAsync();
        }

        private async Task TsConfigFirewall(bool enable)
        {
            if (enable)
            {
                await ExecuteAndWait("netsh advfirewall firewall add rule name=\"Remote Desktop\" dir=in protocol=tcp localport=3389 profile=any action=allow");
                await ExecuteAndWait("netsh advfirewall firewall add rule name=\"Remote Desktop\" dir=in protocol=udp localport=3389 profile=any action=allow");
            }
            else
            {
                await ExecuteAndWait("netsh advfirewall firewall delete rule name=\"Remote Desktop\"");
            }
        }

        private void TsConfigRegistry(bool enable)
        {
            RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections", !enable, RegistryValueKind.DWord);
            if (enable)
            {
                RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Licensing Core\EnableConcurrentSessions", true, RegistryValueKind.String);
                RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AllowMultipleTSSessions", true, RegistryValueKind.String);
                if (!RegistryHelper.HiveExists(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns"))
                {
                    RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\Clip Redirector\Name", "RDPClip", RegistryValueKind.String);
                    RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\Clip Redirector\Type", 3, RegistryValueKind.DWord);

                    RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\DND Redirector\Name", "RDPDND", RegistryValueKind.String);
                    RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\DND Redirector\Type", 3, RegistryValueKind.DWord);

                    RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\Dynamic VC\Type", -1, RegistryValueKind.DWord);
                }
            }
        }

        private async Task<byte[]> GetResource(ResourceType resourceType)
        {
            _logger?.LogInformation("Requesting resource: " + resourceType);

            string resPrefix = "RDPWrapInstaller.Files";

            await using var dataStream = resourceType switch
            {
                ResourceType.Rdpw32 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPW32.dll"),
                ResourceType.Rdpw64 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPW64.dll"),
                ResourceType.Rfxvmt32 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPW32.dll"),
                ResourceType.Rfxvmt64 => _assembly.GetManifestResourceStream($"{resPrefix}.RFXVMT64.dll"),
                ResourceType.Rdpclip6032 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPCLIP6032.dll"),
                ResourceType.Rdpclip6132 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPCLIP6132.dll"),
                ResourceType.Rdpclip6064 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPCLIP6064.dll"),
                ResourceType.Rdpclip6164 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPCLIP6164.dll"),
                _ => throw new ArgumentOutOfRangeException()
            };
            if (dataStream == null)
            {
                throw new ArgumentOutOfRangeException();
            }
            
            _logger?.LogInformation("Resource fetched");

            var memStream = new MemoryStream();
            await dataStream.CopyToAsync(memStream);
            
            _logger?.LogInformation("Resource writed");

            return memStream.ToArray();
        }

        private async Task ExtractFiles()
        {
            string expandedWrapPath = ExpandPath(WrapperPath);
            string? wrapDirPath = Path.GetDirectoryName(expandedWrapPath);

            if (!Directory.Exists(wrapDirPath))
            {
                _logger?.LogInformation("Creating directory: " + wrapDirPath);
                Directory.CreateDirectory(wrapDirPath);
            }

            if (_online)
            {
                _logger?.LogInformation("Downloading latest INI file...");
                byte[] iniData = GitIniFile();
                string initFilePath = Path.Combine(wrapDirPath, "rdpwrap.ini");
                await File.WriteAllBytesAsync(initFilePath, iniData);
                _logger?.LogInformation("Latest INI file: " + initFilePath);
            }

            ResourceType? rdpClipResType = null;
            ResourceType? rfxvmtResType = null;
            if (_procArch == 32)
            {
                byte[] rdpw32Dll = await GetResource(ResourceType.Rdpw32);
                await File.WriteAllBytesAsync(expandedWrapPath, rdpw32Dll);
                
                if (_termSvcVersion.Major == 6 && _termSvcVersion.Minor == 0)
                    rdpClipResType = ResourceType.Rdpclip6032;
                else if (_termSvcVersion.Major == 6 && _termSvcVersion.Minor == 1)
                    rdpClipResType = ResourceType.Rdpclip6132;
                if (_termSvcVersion.Major == 10 && _termSvcVersion.Minor == 0)
                    rfxvmtResType = ResourceType.Rfxvmt32;
            }
            else if (_procArch == 64)
            {
                byte[] rdpw64Dll = await GetResource(ResourceType.Rdpw64);
                await File.WriteAllBytesAsync(expandedWrapPath, rdpw64Dll);
                
                if (_termSvcVersion.Major == 6 && _termSvcVersion.Minor == 0)
                    rdpClipResType = ResourceType.Rdpclip6064;
                else if (_termSvcVersion.Major == 6 && _termSvcVersion.Minor == 1)
                    rdpClipResType = ResourceType.Rdpclip6164;
                if (_termSvcVersion.Major == 10 && _termSvcVersion.Minor == 0)
                    rfxvmtResType = ResourceType.Rfxvmt64;
            }

            if (rdpClipResType != null)
            {
                if (!File.Exists(ExpandPath(@"%SystemRoot%\System32\rdpclip.exe")))
                {
                    var rdpClipExe = await GetResource(rdpClipResType.Value);
                    await File.WriteAllBytesAsync(ExpandPath(@"%SystemRoot%\System32\rdpclip.exe"), rdpClipExe);
                }
            }
            if (rfxvmtResType != null)
            {
                if (!File.Exists(ExpandPath(@"%SystemRoot%\System32\rfxvmt.dll")))
                {
                    var rfxvmtDll = await GetResource(rfxvmtResType.Value);
                    await File.WriteAllBytesAsync(ExpandPath(@"%SystemRoot%\System32\rfxvmt.dll"), rfxvmtDll);
                }
            }
        }

        private (bool supported, int? architecture) GetSupportedArchitecture() =>
            OperatingSystemHelper.GetPlatform() switch
            {
                OperatingSystemHelper.Platform.X86 => (true, 32),
                OperatingSystemHelper.Platform.IA64 => (false, null),
                OperatingSystemHelper.Platform.X64 => (true, 64),
                OperatingSystemHelper.Platform.Unknown => (false, null),
                _ => (false, null)
            };

        private void SetWrapperDll()
        {
            if (RegistryHelper.HiveExists(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\TermService\Parameters"))
            {
                RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService\Parameters\ServiceDll", WrapperPath, RegistryValueKind.ExpandString);

                if (_procArch == 64 && _termSvcVersion.Major == 6 && _termSvcVersion.Minor == 0)
                    ExecuteAndWait(ExpandPath("%SystemRoot%") + 
                                   @"\system32\reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters /v ServiceDll /t REG_EXPAND_SZ /d \""" + WrapperPath + "\" /f");
            }
        }

        private void ResetServiceDll()
        {
            if (RegistryHelper.HiveExists(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\TermService\Parameters"))
            {
                RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService\Parameters\ServiceDll", @"%SystemRoot%\System32\termsrv.dll", RegistryValueKind.ExpandString);
            }
        }

        private void CheckTermsrvDependencies()
        {
            string CertPropSvc = "CertPropSvc";
            string SessionEnv = "SessionEnv";

            var svcCtrl1 = new ServiceController(CertPropSvc);
            if (svcCtrl1.Status == ServiceControllerStatus.Stopped)
            {
                ServiceConfigStart(CertPropSvc, ServiceStartMode.Automatic); // Maybe Bug
                //SvcStart(CertPropSvc, LogType.);
            }

            var svcCtrl2 = new ServiceController(SessionEnv);
            if (svcCtrl2.Status == ServiceControllerStatus.Stopped)
            {
                ServiceConfigStart(SessionEnv, ServiceStartMode.Automatic); // Maybe Bug
                //SvcStart(SessionEnv, LogType.);
            }
        }

        private void DeleteFiles()
        {
            string termSvcDirPath = Path.GetDirectoryName(_initTermSvcPath)!;

            string iniFilePath = Path.Combine(termSvcDirPath, "rdpwrap.ini"); 
            _logger?.LogInformation("Deleting: " + iniFilePath);
            if (File.Exists(iniFilePath)) File.Delete(iniFilePath);

            _logger?.LogInformation("Deleting: " + _initTermSvcPath);
            if (File.Exists(_initTermSvcPath)) File.Delete(_initTermSvcPath);

            _logger?.LogInformation("Deleteting folder: " + termSvcDirPath);
            if (Directory.Exists(termSvcDirPath)) Directory.Delete(termSvcDirPath);
        }

        private void KillProcess(int pid)
        {
            try
            {
                if (Process.GetProcessById(pid) is var proc)
                    proc.Kill();
            }
            catch (Exception ex)
            {
                _logger?.LogInformation("Terminate process, PID: " + pid);
            }
        }

        private int GetServicePid(string svcName)
        {
            var svcCtrl = new ServiceController(svcName);
            return svcCtrl.GetServiceProcessId();
        }

        private void CheckSupported()
        {
            object imagePathValue = RegistryHelper.GetValue("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TermService\\ImagePath");
            string termSvcHost = imagePathValue as string;

            int tshValue1 = termSvcHost.ToLower().IndexOf("svchost.exe", StringComparison.Ordinal);
            int tshValue2 = termSvcHost.ToLower().IndexOf("svchost -k", StringComparison.Ordinal);

            if (tshValue1 == -1 && tshValue2 == -1)
            {
                string message = "TermService is hosted in a custom application (BeTwin, etc.) - unsupported.\n" +
                                 $"ImagePath: {termSvcHost}";
                _logger?.LogError(message);
                throw new NotSupportedException(message);
            }
        }

        private void CheckAnotherLibraryInstalled()
        {
            string termSvcPath = GetTerminalServicePath();

            int tspValue1 = termSvcPath.IndexOf("termsrv.dll", StringComparison.Ordinal);
            int tspValue2 = termSvcPath.IndexOf("rdpwrap.dll", StringComparison.Ordinal);

            if (tspValue1 == -1 && tspValue2 == -1)
            {
                string message = "Another third-party TermService library is installed.\n" +
                                 $"ServiceDll: {termSvcPath}";
                _logger?.LogError(message);
                throw new NotSupportedException(message);
            }
        }

        public bool IsInstalled()
        {
            return GetTerminalServicePath().ToLower().IndexOf("rdpwrap.dll", StringComparison.CurrentCulture) > -1;
        }

        private string GetTerminalServicePath()
        {
            object termSvcParams = RegistryHelper.GetValue("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters\\ServiceDll");
            return (string)termSvcParams;
        }

        private void GetFileVersion(string fileName, out Version ver)
        {
            var fileVer = FileVersionInfo.GetVersionInfo(fileName);
            ver = new Version(
                fileVer.ProductMajorPart,
                fileVer.ProductMinorPart,
                fileVer.ProductBuildPart,
                fileVer.ProductPrivatePart);
        }

        private byte[] GitIniFile()
        {
            var client = new WebClient();
            // TODO: make this link 'customizable'
            return client.DownloadData("https://raw.githubusercontent.com/asmtron/rdpwrap/master/res/rdpwrap.ini");
        }

        /// <summary>
        /// Get all services that use the process occupied by the service <see cref="serviceName"/>
        /// </summary>
        /// <param name="serviceName"></param>
        /// <param name="serviceUsingPid"></param>
        /// <returns></returns>
        private List<ServiceController> GetSharedServices(string serviceName, int serviceUsingPid)
        {
            var services = ServiceController.GetServices();
            var sharedServices = new List<ServiceController>();
            string sharedServiceText = "";
            foreach (var service in services)
            {
                try
                {
                    if (service.ServiceName != serviceName && service.GetServiceProcessId() == serviceUsingPid)
                    {
                        sharedServices.Add(service);
                        sharedServiceText += $"{service.ServiceName}, ";
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning("Something went wrong while getting the process id.");
                }
            }

            if (sharedServices.Count != 0)
            {
                _logger?.LogInformation("Shared services found: " + sharedServiceText);
            }
            else
            {
                _logger?.LogInformation("Shared services not found");
            }

            return sharedServices;
        }

        private void CheckTermsrvProcess()
        {
            int termSvcProcId = GetServicePid(TermServiceName);
            if (termSvcProcId == -1 || termSvcProcId == 0) // if process killed
            {
                ServiceConfigStart(TermServiceName, ServiceStartMode.Automatic);
                ServiceStart(TermServiceName);
            }
        }

        private void CheckTermsrvVersion()
        {
            string expandedTermSvcPath = ExpandPath(GetTerminalServicePath());

            GetFileVersion(expandedTermSvcPath, out _termSvcVersion);
            string verText = string.Format(
                "{0}.{1}.{2}.{3}", 
                _termSvcVersion.Major,
                _termSvcVersion.Minor,
                _termSvcVersion.Build,
                _termSvcVersion.Revision);
            int supportedLvl;

            _logger?.LogInformation("Terminal Services version: " + verText);
            if (_termSvcVersion.Major == 5 && _termSvcVersion.Minor == 1)
            {
                if (_procArch == 32)
                {
                    _logger?.LogWarning(
                        "Windows XP is not supported.\n" +
                        "You may take a look at RDP Realtime Patch by Stas''M for Windows XP\n" +
                        "Link: ");
                }
                if (_procArch == 64)
                {
                    _logger?.LogWarning("Windows XP 64-bit Edition is not supported.");
                }
            }
            if (_termSvcVersion.Major == 5 && _termSvcVersion.Minor == 2)
            {
                if (_procArch == 32)
                {
                    _logger?.LogWarning("Windows Server 2003 is not supported.");
                }
                else if (_procArch == 64)
                {
                    _logger?.LogWarning("Windows Server 2003 or XP 64-bit Edition is not supported.");
                }
            }

            supportedLvl = 0;
            if (_termSvcVersion.Major == 6 && _termSvcVersion.Minor == 0)
            {
                supportedLvl = 1;
                if (_procArch == 32 && _termSvcVersion.Revision == 6000 & _termSvcVersion.Build == 16386)
                {
                    _logger?.LogWarning(
                        "This version of Terminal Services may crash on logon attempt.\n" +
                        "It''s recommended to upgrade to Service Pack 1 or higher.");
                }
            }

            if (_termSvcVersion.Major == 6 && _termSvcVersion.Minor == 1)
            {
                supportedLvl = 1;
            }

            string iniText = Encoding.UTF8.GetString(GitIniFile());
            if (iniText.IndexOf($"[{verText}]", StringComparison.Ordinal) > -1)
            {
                supportedLvl = 2;
            }

            switch (supportedLvl)
            {
                case 0:
                    _logger?.LogError("This version of Terminal Services is not supported.");
                    throw new OperatingSystemNotSupportedException();
                    // LogUpdateMessage();
                    break;
                case 1:
                    _logger?.LogWarning(
                        "This version of Terminal Services is supported partially.\n" +
                        "It means you may have some limitations such as only 2 concurrent sessions.");
                    // LogUpdateMessage();
                    break;
                case 2:
                    _logger?.LogInformation("This version of Terminal Services is fully supported.");
                    break;
            }
        }

        // TODO:
        // private void LogUpdateMessage()
        // {
        //     _logger?.LogInformation(
        //         "Try running \"update.bat\" or \"RDPWInst - w\" to download latest INI file.\n" +
        //         "If it doesn''t help, send your termsrv.dll to project developer for support.");
        // }

        /// <summary>
        /// Check operating system version
        /// </summary>
        /// <param name="minMajorVer">minimum major version</param>
        /// <param name="minMinorVer">minimum major version</param>
        /// <returns></returns>
        private bool CheckWin32Version(int minMajorVer, int minMinorVer)
        {
            var osVersion = Environment.OSVersion.Version;
            return osVersion.Major > minMajorVer || osVersion.Minor > minMinorVer;
        }

        private string ExpandPath(string path)
        {
            if (_procArch == 64)
            {
                path = path.Replace("%ProgramFiles%", "%ProgramW6432%");
            }
            return Environment.ExpandEnvironmentVariables(path);
        }

        /// <summary>
        /// Install RDPWrapper Library
        /// </summary>
        /// <returns></returns>
        /// <exception cref="UnsupportedArchitectureException">When processor architecture not supported</exception>
        /// <exception cref="RdpWrapperAlreadyInstalledException">When RDPWrapper Library installed</exception>
        public async Task Install()
        {
            if (!CheckWin32Version(6, 0))
            {
                _logger?.LogError(
                    "Unsupported Windows version:\n" +
                    "  only >= 6.0 (Vista, Server 2008 and newer) are supported.");
                return;
            }

            var data = GetSupportedArchitecture();
            if (data is {supported: false} or {architecture: null})
            {
                _logger?.LogError("Unsupported processor architecture.");
                throw new UnsupportedArchitectureException();
            }
            _procArch = data.architecture.Value;

            CheckSupported();
            CheckAnotherLibraryInstalled();

            if (IsInstalled())
            {
                _logger?.LogInformation("RDP Wrapper Library is already installed.");
                throw new RdpWrapperAlreadyInstalledException();
            }
            _logger?.LogInformation("Installing...");
            
            CheckTermsrvVersion();
            CheckTermsrvProcess();

            _logger?.LogInformation("Extracting files...");
            await ExtractFiles();

            _logger?.LogInformation("Configuring library...");
            SetWrapperDll();

            _logger?.LogInformation("Checking dependencies...");
            CheckTermsrvDependencies();

            int termServiceId = GetServicePid(TermServiceName);
            
            var sharedSvcs = GetSharedServices(TermServiceName, termServiceId);
            await Task.Delay(1000);
            
            _logger?.LogInformation("Terminating service...");
            KillProcess(termServiceId);
            await Task.Delay(1000);

            if (sharedSvcs.Count != 0)
            {
                foreach (var svcController in sharedSvcs)
                {
                    ServiceStart(svcController.ServiceName);
                }
            }
            
            ServiceStart(TermServiceName);
            await Task.Delay(1000);

            _logger?.LogInformation("Configuring registry...");
            TsConfigRegistry(true);
            
            _logger?.LogInformation("Configuring firewall...");
            await TsConfigFirewall(true);

            _logger?.LogInformation("Successfully installed.");
        }
        
        /// <summary>
        /// Uninstall RDPWrapper Library
        /// </summary>
        /// <returns></returns>
        /// <exception cref="UnsupportedArchitectureException">When processor architecture not supported</exception>
        /// <exception cref="RdpWrapperNotInstalledException">When RDPWrapper Library not installed</exception>
        public async Task Uninstall()
        {
            _initTermSvcPath = ExpandPath(GetTerminalServicePath());
            
            if (!CheckWin32Version(6, 0))
            {
                _logger?.LogError(
                    "Unsupported Windows version:\n" +
                    "   only >= 6.0 (Vista, Server 2008 and newer) are supported.");
                return;
            }
            
            var data = GetSupportedArchitecture();
            if (data is {supported: false} or {architecture: null})
            {
                _logger?.LogError("Unsupported processor architecture.");
                throw new UnsupportedArchitectureException();
            }
            _procArch = data.architecture.Value;

            if (!IsInstalled())
            {
                _logger?.LogInformation("RDP Wrapper Library is not installed.");
                throw new RdpWrapperNotInstalledException();
            }
            _logger?.LogInformation("Uninstalling...");
            
            CheckTermsrvProcess();

            _logger?.LogInformation("Resetting service library...");
            ResetServiceDll();

            int termServiceId = GetServicePid(TermServiceName);
            
            var sharedSvcs = GetSharedServices(TermServiceName, termServiceId);
            await Task.Delay(1000);
            
            _logger?.LogInformation("Terminating service...");
            KillProcess(termServiceId);
            await Task.Delay(1000);
            
            _logger?.LogInformation("Deleting files...");
            DeleteFiles();
            await Task.Delay(1000);
            
            if (sharedSvcs.Count != 0)
            {
                foreach (var svcController in sharedSvcs)
                {
                    ServiceStart(svcController.ServiceName);
                }
            }
            
            ServiceStart(TermServiceName);

            _logger?.LogInformation("Configuring registry...");
            TsConfigRegistry(false);
            
            _logger?.LogInformation("Configuring firewall...");
            await TsConfigFirewall(false);

            _logger?.LogInformation("Successfully uninstalled.");
        }

        public async Task Reload()
        {
            if (!CheckWin32Version(6, 0))
            {
                _logger?.LogError(
                    "Unsupported Windows version:\n" +
                    "   only >= 6.0 (Vista, Server 2008 and newer) are supported.");
                return;
            }
            
            var data = GetSupportedArchitecture();
            if (data is {supported: false} or {architecture: null})
            {
                _logger?.LogError("Unsupported processor architecture.");
                throw new UnsupportedArchitectureException();
            }
            _procArch = data.architecture.Value;
            
            if (!IsInstalled())
            {
                _logger?.LogInformation("RDP Wrapper Library is not installed.");
                throw new RdpWrapperNotInstalledException();
            }
            _logger?.LogInformation("Restarting...");
            
            CheckTermsrvProcess();

            int termServiceId = GetServicePid(TermServiceName);
            
            var sharedSvcs = GetSharedServices(TermServiceName, termServiceId);
            await Task.Delay(1000);
            
            _logger?.LogInformation("Terminating service...");
            KillProcess(termServiceId);
            await Task.Delay(1000);
            
            if (sharedSvcs.Count != 0)
            {
                foreach (var svcController in sharedSvcs)
                {
                    ServiceStart(svcController.ServiceName);
                }
            }
            
            ServiceStart(TermServiceName);

            _logger?.LogInformation("Successfully reloaded...");
        }
    }
}
