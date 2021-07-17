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
using Microsoft.Win32;
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

    public class RDPWrap
    {
        private static readonly Assembly _assembly;
        private static readonly RDPWrapLogger _logger;
    
        private static int _procArch;
        private static bool _installed;
        private static string _termServicePath;
        private static string _wrapPath;
        private static IntPtr _wow64Value = IntPtr.Zero;
        private static string _termService = "TermService";
        private static int _termServicePID;
        private static Version _fv;
        private static bool _online = true;
        private static List<ServiceController> _sharedSvcs;

        public static string Logs => _logger.Logs;

        static RDPWrap()
        {
            _assembly = Assembly.GetExecutingAssembly();
            _logger = new RDPWrapLogger();
        }

        private static void ServiceConfigStart(string svcName, ServiceStartMode svcStartMode)
        {
            _logger.Log(LogType.Information, "Configuring " + svcName);
            var svcCtrl = new ServiceController(svcName);

            ServiceHelper.ChangeStartMode(svcCtrl, svcStartMode);
            _logger.Log(LogType.Information, "Started " + svcName);
        }

        private static void ServiceStart(string svcName)
        {
            var serviceController = new ServiceController(svcName);
            _logger.Log(LogType.Information, "Starting " + svcName);

            if (serviceController.Status == ServiceControllerStatus.Stopped)
            {
                serviceController.Start();
                serviceController.WaitForStatus(ServiceControllerStatus.Running);
                _logger.Log(LogType.Information, "Started " + svcName);
            }
            else
            {
                _logger.Log(LogType.Error, "Service " + svcName + " is already running");
            }
        }

        private static Task ExecuteAndWait(string cmdline)
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

        private static async Task TsConfigFirewall(bool enable)
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

        private static void TsConfigRegistry(bool enable)
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

        private static async Task<byte[]> GetResource(ResourceType resourceType)
        {
            _logger.Log(LogType.Information, "Requesting resource: " + resourceType);

            string resPrefix = "RDPWrapInstaller.Files";

            using var dataStream = resourceType switch
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
            _logger.Log(LogType.Information, "Resource fetched");

            var memStream = new MemoryStream();
            await dataStream.CopyToAsync(memStream);
            
            _logger.Log(LogType.Information, "Resource writed");

            return memStream.ToArray();
        }

        private static async Task ExtractFiles()
        {
            string super = Path.GetDirectoryName(ExpandPath(_wrapPath));
            if (!Directory.Exists(super))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ExpandPath(_wrapPath)));
                string s = Path.GetDirectoryName(ExpandPath(_wrapPath));
                _logger.Log(LogType.Information, "Folder created: " + s);
                //GrantSidFullAccess(s, "S-1-5-18", LogType.);
                //GrantSidFullAccess(s, "S-1-5-6", LogType.);
                //// TODO:
                //GrantSidFullAccess(S, 'S-1-5-18'); // Local System account
                //GrantSidFullAccess(S, 'S-1-5-6'); // Service group
            }

            if (_online)
            {
                _logger.Log(LogType.Information, "Downloading latest INI file...");
                byte[] iniData = GitIniFile();
                string initFilePath = Path.Combine(Path.GetDirectoryName(ExpandPath(_wrapPath)), "rdpwrap.ini");
                File.WriteAllBytes(initFilePath, iniData);
                _logger.Log(LogType.Information, "Latest INI file: " + initFilePath);
            }

            ResourceType? rdpClipResType = null;
            ResourceType? rfxvmtResType = null;
            if (_procArch == 32)
            {
                byte[] rdpw32Dll = await GetResource(ResourceType.Rdpw32);
                await File.WriteAllBytesAsync(ExpandPath(_wrapPath), rdpw32Dll);
                
                if (_fv.Major == 6 && _fv.Minor == 0)
                    rdpClipResType = ResourceType.Rdpclip6032;
                else if (_fv.Major == 6 && _fv.Minor == 1)
                    rdpClipResType = ResourceType.Rdpclip6132;
                if (_fv.Major == 10 && _fv.Minor == 0)
                    rfxvmtResType = ResourceType.Rfxvmt32;
            }
            else if (_procArch == 64)
            {
                byte[] rdpw64Dll = await GetResource(ResourceType.Rdpw64);
                await File.WriteAllBytesAsync(ExpandPath(_wrapPath), rdpw64Dll);
                
                if (_fv.Major == 6 && _fv.Minor == 0)
                    rdpClipResType = ResourceType.Rdpclip6064;
                else if (_fv.Major == 6 && _fv.Minor == 1)
                    rdpClipResType = ResourceType.Rdpclip6164;
                if (_fv.Major == 10 && _fv.Minor == 0)
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

        private static bool SupportedArchitecture()
        {
            var platform = OperatingSystemHelper.GetPlatform();
            bool supported;
            switch (platform)
            {
                case OperatingSystemHelper.Platform.X86: // Intel x86
                    _procArch = 32;
                    supported = false;
                    break;
                case OperatingSystemHelper.Platform.IA64: // Itaniumbased x64
                    supported = false;
                    break;
                case OperatingSystemHelper.Platform.X64: // Intel or AMD x64
                    _procArch = 64;
                    supported = true;
                    break;
                case OperatingSystemHelper.Platform.Unknown: // Unknown
                    supported = false;
                    break;
                default:
                    supported = false;
                    break;
            }
            return supported;
        }

        private static void SetWrapperDll()
        {
            if (RegistryHelper.HiveExists(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\TermService\Parameters"))
            {
                RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService\Parameters\ServiceDll", _wrapPath, RegistryValueKind.ExpandString);

                if (_procArch == 64 && _fv.Major == 6 && _fv.Minor == 0)
                    ExecuteAndWait(ExpandPath("%SystemRoot%") + @"\system32\reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters /v ServiceDll /t REG_EXPAND_SZ /d \""" + _wrapPath + "\" /f");
            }
        }

        private static void ResetServiceDll()
        {
            if (RegistryHelper.HiveExists(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\TermService\Parameters"))
            {
                // Set default value
                RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService\Parameters\ServiceDll", @"%SystemRoot%\System32\termsrv.dll", RegistryValueKind.ExpandString);
            }
        }

        private static void CheckTermsrvDependencies()
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

        private static void DeleteFiles()
        {
            string fullPath = ExpandPath(_termServicePath);
            string path = Path.GetDirectoryName(fullPath);

            // Remove rdpwrap.ini
            File.Delete(Path.Combine(path, "rdpwrap.ini"));
            _logger.Log(LogType.Information, "Removed file: " + Path.Combine(path, "rdpwrap.ini"));

            // Remove rdpwrap.dll
            File.Delete(fullPath);
            _logger.Log(LogType.Information, "Removed file: " + fullPath);

            // Remove RDP folder
            Directory.Delete(Path.GetDirectoryName(ExpandPath(_termServicePath)));
            _logger.Log(LogType.Information, "Removed folder: " + Path.GetDirectoryName(ExpandPath(_termServicePath)));
        }

        private static void KillProcess(int pid)
        {
            try
            {
                if (Process.GetProcessById(pid) is var proc)
                    proc.Kill();
            }
            catch (Exception ex)
            {
                _logger.Log(LogType.Error, "Terminate process, PID: " + pid);
            }
        }

        private static int GetServicePid(string svcName)
        {
            var svcCtrl = new ServiceController(svcName);
            return svcCtrl.GetServiceProcessId();
        }

        private static void CheckInstall()
        {
            object imagePathValue = Helpers.RegistryHelper.GetValue("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TermService\\ImagePath");
            string termServiceHost = imagePathValue as string;
            // Term Service Host values
            int tshValue1 = termServiceHost.ToLower().IndexOf("svchost.exe");
            int tshValue2 = termServiceHost.ToLower().IndexOf("svchost -k");
            // If not found
            if (tshValue1 == -1 && tshValue2 == -1)
            {
                _logger.Log(LogType.Error,
                    "TermService is hosted in a custom application (BeTwin, etc.) - unsupported.\n" +
                    string.Format("ImagePath: {0}", termServiceHost));
                return;
            }

            object termServiceParams = Helpers.RegistryHelper.GetValue("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters\\ServiceDll");
            _termServicePath = (string)termServiceParams;
            // Term Service Path values
            int tspValue1 = _termServicePath.IndexOf("termsrv.dll");
            int tspValue2 = _termServicePath.IndexOf("rdpwrap.dll");
            // If not found
            if (tspValue1 == -1 && tspValue2 == -1)
            {
                _logger.Log(LogType.Error,
                    "Another third-party TermService library is installed.\n" +
                    string.Format("ServiceDll: {0}", _termServicePath));
                return;
            }

            _installed = _termServicePath.ToLower().IndexOf("rdpwrap.dll", StringComparison.CurrentCulture) > -1;
        }

        private static void GetFileVersion(string fileName, out Version ver)
        {
            var fileVer = FileVersionInfo.GetVersionInfo(fileName);
            ver = new Version(
                fileVer.ProductMajorPart,
                fileVer.ProductMinorPart,
                fileVer.ProductBuildPart,
                fileVer.ProductPrivatePart);
        }

        private static byte[] GitIniFile()
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
        private static List<ServiceController> GetSharedServices(string serviceName, int serviceUsingPid)
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
                        sharedServiceText += string.Format("{0}, ", service.ServiceName);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Log(LogType.Warning, "Something went wrong while getting the process id.");
                }
            }

            if (sharedServices.Count != 0)
            {
                _logger.Log(LogType.Information, "Shared services found: " + sharedServiceText);
            }
            else
            {
                _logger.Log(LogType.Information, "Shared services not found");
            }

            return sharedServices;
        }

        private static void CheckTermsrvProcess()
        {
            int termServiceProcId = GetServicePid(_termService);
            if (termServiceProcId == -1 || termServiceProcId == 0) // if process killed
            {
                ServiceConfigStart(_termService, ServiceStartMode.Automatic);
                ServiceStart(_termService);
            }
        }

        private static void CheckTermsrvVersion()
        {
            GetFileVersion(ExpandPath(_termServicePath), out _fv);
            string verText = string.Format("{0}.{1}.{2}.{3}", _fv.Major, _fv.Minor, _fv.Build, _fv.Revision);
            byte supportedLvl;

            _logger.Log(LogType.Information, "Terminal Services version: " + verText);
            if (_fv.Major == 5 && _fv.Minor == 1)
            {
                if (_procArch == 32)
                {
                    _logger.Log(LogType.Warning,
                        "Windows XP is not supported.\n" +
                        "You may take a look at RDP Realtime Patch by Stas''M for Windows XP\n" +
                        "Link: ");
                }
                if (_procArch == 64)
                {
                    _logger.Log(LogType.Warning, "Windows XP 64-bit Edition is not supported.");
                }
                return;
            }
            if (_fv.Major == 5 && _fv.Minor == 2)
            {
                if (_procArch == 32)
                {
                    _logger.Log(LogType.Warning, "Windows Server 2003 is not supported.");
                }
                else if (_procArch == 64)
                {
                    _logger.Log(LogType.Warning, "Windows Server 2003 or XP 64-bit Edition is not supported.");
                }
                return;
            }
            supportedLvl = 0;
            if (_fv.Major == 6 && _fv.Minor == 0)
            {
                supportedLvl = 1;
                if (_procArch == 32 && _fv.Revision == 6000 & _fv.Build == 16386)
                {
                    _logger.Log(LogType.Warning,
                        "This version of Terminal Services may crash on logon attempt.\n" +
                        "It''s recommended to upgrade to Service Pack 1 or higher.");
                }
                return;
            }

            if (_fv.Major == 6 && _fv.Minor == 1)
            {
                supportedLvl = 1;
            }

            string iniText = Encoding.UTF8.GetString(GitIniFile());
            if (iniText.IndexOf($"[{verText}]") > -1)
            {
                supportedLvl = 2;
            }

            switch (supportedLvl)
            {
                case 0:
                    _logger.Log(LogType.Error, "This version of Terminal Services is not supported.");
                    UpdateMsg();
                    break;
                case 1:
                    _logger.Log(LogType.Warning,
                        "This version of Terminal Services is supported partially.\n" +
                        "It means you may have some limitations such as only 2 concurrent sessions.");
                    UpdateMsg();
                    break;
                case 2:
                    _logger.Log(LogType.Information, "This version of Terminal Services is fully supported.");
                    break;
            }
        }

        private static void UpdateMsg()
        {
            _logger.Log(LogType.Information,
                "Try running \"update.bat\" or \"RDPWInst - w\" to download latest INI file.\n" +
                "If it doesn''t help, send your termsrv.dll to project developer for support.");
        }

        /// <summary>
        /// Check operating system version
        /// </summary>
        /// <param name="minMajorVer">minimum major version</param>
        /// <param name="minMinorVer">minimum major version</param>
        /// <returns></returns>
        private static bool CheckWin32Version(int minMajorVer, int minMinorVer)
        {
            var osVersion = Environment.OSVersion.Version;
            return osVersion.Major > minMajorVer || osVersion.Minor > minMinorVer;
        }

        private static string ExpandPath(string path)
        {
            if (_procArch == 64)
            {
                path = path.Replace("%ProgramFiles%", "%ProgramW6432%");
            }
            return Environment.ExpandEnvironmentVariables(path);
        }

        public static async Task Install()
        {
            if (!CheckWin32Version(6, 0))
            {
                _logger.Log(LogType.Error,
                    "Unsupported Windows version:\n" +
                    "  only >= 6.0 (Vista, Server 2008 and newer) are supported.");
                return;
            }
            if (!SupportedArchitecture())
            {
                _logger.Log(LogType.Error, "Unsupported processor architecture.");
                return;
            }
            CheckInstall();

            if (_installed)
            {
                _logger.Log(LogType.Information, "RDP Wrapper Library is already installed.");
                return;
            }
            _logger.Log(LogType.Information, "Installing...");

            _wrapPath = @"C:\Program Files\RDP Wrapper\rdpwrap.dll";

            CheckTermsrvVersion();
            CheckTermsrvProcess();

            _logger.Log(LogType.Information, "Extracting files...");
            _online = true;
            await ExtractFiles();

            _logger.Log(LogType.Information, "Configuring library...");
            SetWrapperDll();

            _logger.Log(LogType.Information, "Checking dependencies...");
            CheckTermsrvDependencies();

            int termServiceId = GetServicePid(_termService);
            
            _sharedSvcs = GetSharedServices(_termService, termServiceId);
            await Task.Delay(1000);
            
            _logger.Log(LogType.Information, "Terminating service...");
            KillProcess(termServiceId);
            await Task.Delay(1000);

            if (_sharedSvcs.Count != 0)
            {
                foreach (ServiceController svc in _sharedSvcs)
                {
                    ServiceStart(svc.ServiceName);
                }
            }
            
            ServiceStart(_termService);
            await Task.Delay(1000);

            _logger.Log(LogType.Information, "Configuring registry...");
            TsConfigRegistry(true);
            
            _logger.Log(LogType.Information, "Configuring firewall...");
            await TsConfigFirewall(true);

            _logger.Log(LogType.Information, "Successfully installed.");
        }

        public static async Task Uninstall()
        {
            if (!CheckWin32Version(6, 0))
            {
                _logger.Log(LogType.Error,
                    "Unsupported Windows version:\n" +
                    "   only >= 6.0 (Vista, Server 2008 and newer) are supported.");
                return;
            }
            if (!SupportedArchitecture())
            {
                _logger.Log(LogType.Error, "Unsupported processor architecture.");
                return;
            }
            CheckInstall();

            if (!_installed)
            {
                _logger.Log(LogType.Information, "RDP Wrapper Library is not installed.");
                return;
            }
            _logger.Log(LogType.Information, "Uninstalling...");
            
            CheckTermsrvProcess();

            _logger.Log(LogType.Information, "Resetting service library...");
            ResetServiceDll();

            int termServiceId = GetServicePid(_termService);
            
            _sharedSvcs = GetSharedServices(_termService, termServiceId);
            await Task.Delay(1000);
            
            _logger.Log(LogType.Information, "Terminating service...");
            KillProcess(termServiceId);
            await Task.Delay(1000);
            
            _logger.Log(LogType.Information, "Removing files...");
            DeleteFiles();
            await Task.Delay(1000);
            
            if (_sharedSvcs.Count != 0)
            {
                foreach (ServiceController svc in _sharedSvcs)
                {
                    ServiceStart(svc.ServiceName);
                }
            }
            
            ServiceStart(_termService);

            _logger.Log(LogType.Information, "Configuring registry...");
            TsConfigRegistry(false);
            
            _logger.Log(LogType.Information, "Configuring firewall...");
            await TsConfigFirewall(false);

            _logger.Log(LogType.Information, "Successfully uninstalled.");
        }

        public static async Task Reload()
        {
            if (!CheckWin32Version(6, 0))
            {
                _logger.Log(LogType.Error,
                    "Unsupported Windows version:\n" +
                    "   only >= 6.0 (Vista, Server 2008 and newer) are supported.");
                return;
            }
            if (!SupportedArchitecture())
            {
                _logger.Log(LogType.Error, "Unsupported processor architecture.");
                return;
            }
            CheckInstall();

            _logger.Log(LogType.Information, "Restarting...");
            
            CheckTermsrvProcess();

            int termServiceId = GetServicePid(_termService);
            
            _sharedSvcs = GetSharedServices(_termService, termServiceId);
            await Task.Delay(1000);
            
            _logger.Log(LogType.Information, "Terminating service...");
            KillProcess(termServiceId);
            await Task.Delay(1000);
            
            if (_sharedSvcs.Count != 0)
            {
                foreach (ServiceController svc in _sharedSvcs)
                {
                    ServiceStart(svc.ServiceName);
                }
            }
            
            ServiceStart(_termService);

            _logger.Log(LogType.Information, "Successfully reloaded...");
        }
    }
}
