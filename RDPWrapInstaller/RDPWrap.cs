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
        RDPW32,
        RDPW64,
        RFXVMT32,
        RFXVMT64,
        RDPCLIP6032,
        RDPCLIP6132,
        RDPCLIP6064,
        RDPCLIP6164
    }

    public class RDPWrap
    {
        private static readonly RDPWrapLogger _logger;
    
        private static int _procArch; // Архитектура процессора
        private static bool _installed; // установлен ли wrapper
        private static string _termServicePath; // путь в реестре
        private static string _wrapPath; // путь до rdp враппера
        private static IntPtr _wow64Value = IntPtr.Zero;
        private static string _termService = "TermService";
        private static int _termServicePID;
        private static Version _fv;
        private static bool _online = true;
        private static List<ServiceController> _sharedSvcs;
        private static Assembly _assembly;

        public static string Logs => _logger.Logs;

        static RDPWrap()
        {
            _logger = new RDPWrapLogger();
            _assembly = Assembly.GetExecutingAssembly();
        }

        private static void SvcConfigStart(string svcName, ServiceStartMode svcStartMode)
        {
            _logger.Log(LogType.Information, "Configuring " + svcName);
            ServiceController svcCtrl = new ServiceController(svcName);

            ServiceHelper.ChangeStartMode(svcCtrl, svcStartMode);
            _logger.Log(LogType.Information, "Started " + svcName);
        }

        private static void SvcStart(string svcName)
        {
            ServiceController svcCtrl = new ServiceController(svcName);
            _logger.Log(LogType.Information, "Starting " + svcName);

            if (svcCtrl.Status == ServiceControllerStatus.Stopped)
            {
                svcCtrl.Start();
                svcCtrl.WaitForStatus(ServiceControllerStatus.Running);
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
            Helpers.RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections", !enable, RegistryValueKind.DWord);
            if (enable)
            {
                Helpers.RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Licensing Core\EnableConcurrentSessions", true, RegistryValueKind.String);
                Helpers.RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AllowMultipleTSSessions", true, RegistryValueKind.String);
                if (!Helpers.RegistryHelper.HiveExists(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns"))
                {
                    Helpers.RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\Clip Redirector\Name", "RDPClip", RegistryValueKind.String);
                    Helpers.RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\Clip Redirector\Type", 3, RegistryValueKind.DWord);

                    Helpers.RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\DND Redirector\Name", "RDPDND", RegistryValueKind.String);
                    Helpers.RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\DND Redirector\Type", 3, RegistryValueKind.DWord);

                    Helpers.RegistryHelper.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\Dynamic VC\Type", -1, RegistryValueKind.DWord);

                }
            }
        }

        private static async Task<byte[]> GetResource(ResourceType resourceType)
        {
            _logger.Log(LogType.Information, "Requesting resource: " + resourceType);

            string resPrefix = "RDPWrapInstaller.Files.";

            using var dataStream = resourceType switch
            {
                ResourceType.RDPW32 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPW32.dll"),
                ResourceType.RDPW64 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPW64.dll"),
                ResourceType.RFXVMT32 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPW32.dll"),
                ResourceType.RFXVMT64 => _assembly.GetManifestResourceStream($"{resPrefix}.RFXVMT64.dll"),
                ResourceType.RDPCLIP6032 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPCLIP6032.dll"),
                ResourceType.RDPCLIP6132 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPCLIP6132.dll"),
                ResourceType.RDPCLIP6064 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPCLIP6064.dll"),
                ResourceType.RDPCLIP6164 => _assembly.GetManifestResourceStream($"{resPrefix}.RDPCLIP6164.dll"),
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
                string s = Path.Combine(Path.GetDirectoryName(ExpandPath(_wrapPath)), "rdpwrap.ini");
                File.WriteAllBytes(s, iniData);
                _logger.Log(LogType.Information, "Latest INI file -> " + s);
            }

            ResourceType? rdpClipResType = null;
            ResourceType? rfxvmtResType = null;
            if (_procArch == 32)
            {
                byte[] rdpw32Dll = await GetResource(ResourceType.RDPW32);
                await File.WriteAllBytesAsync(ExpandPath(_wrapPath), rdpw32Dll);
                
                if (_fv.Major == 6 && _fv.Minor == 0)
                    rdpClipResType = ResourceType.RDPCLIP6032;
                else if (_fv.Major == 6 && _fv.Minor == 1)
                    rdpClipResType = ResourceType.RDPCLIP6132;
                if (_fv.Major == 10 && _fv.Minor == 0)
                    rfxvmtResType = ResourceType.RFXVMT32;
            }
            else if (_procArch == 64)
            {
                byte[] rdpw64Dll = await GetResource(ResourceType.RDPW64);
                await File.WriteAllBytesAsync(ExpandPath(_wrapPath), rdpw64Dll);
                
                if (_fv.Major == 6 && _fv.Minor == 0)
                    rdpClipResType = ResourceType.RDPCLIP6064;
                else if (_fv.Major == 6 && _fv.Minor == 1)
                    rdpClipResType = ResourceType.RDPCLIP6164;
                if (_fv.Major == 10 && _fv.Minor == 0)
                    rfxvmtResType = ResourceType.RFXVMT64;
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
                SvcConfigStart(CertPropSvc, ServiceStartMode.Automatic); // Maybe Bug
                //SvcStart(CertPropSvc, LogType.);
            }

            var svcCtrl2 = new ServiceController(SessionEnv);
            if (svcCtrl2.Status == ServiceControllerStatus.Stopped)
            {
                SvcConfigStart(SessionEnv, ServiceStartMode.Automatic); // Maybe Bug
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
            var svcs = ServiceController.GetServices();
            var sharedSvc = new List<ServiceController>();
            string sharedSvcTxt = "";
            foreach (ServiceController svc in svcs)
            {
                try
                {
                    if (svc.ServiceName != serviceName && svc.GetServiceProcessId() == serviceUsingPid)
                    {
                        sharedSvc.Add(svc);
                        sharedSvcTxt += string.Format("{0}, ", svc.ServiceName);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Log(LogType.Warning, "Something went wrong while getting the process id.");
                }
            }

            if (sharedSvc.Count != 0)
            {
                _logger.Log(LogType.Information, "Shared services found: " + sharedSvcTxt);
            }
            else
            {
                _logger.Log(LogType.Information, "Shared services not found");
            }

            return sharedSvc;
        }

        private static void CheckTermsrvProcess()
        {
            int termServicePID = GetServicePid(_termService);
            if (termServicePID == -1 || termServicePID == 0) // if process killed
            {
                SvcConfigStart(_termService, ServiceStartMode.Automatic);
                SvcStart(_termService);
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
                        "Windows XP is not supported.",
                        "You may take a look at RDP Realtime Patch by Stas''M for Windows XP",
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
                        "This version of Terminal Services may crash on logon attempt.",
                        "It''s recommended to upgrade to Service Pack 1 or higher.");
                }
                return;
            }
            if (_fv.Major == 6 && _fv.Minor == 1)
                supportedLvl = 1;

            string iniTxt = Encoding.UTF8.GetString(GitIniFile());
            if (iniTxt.IndexOf($"[{verText}]") > -1)
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
                        "This version of Terminal Services is supported partially.",
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
                "Try running \"update.bat\" or \"RDPWInst - w\" to download latest INI file.",
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
            var osVer = Environment.OSVersion.Version;
            if (osVer.Major < minMajorVer || osVer.Minor < minMinorVer)
                return false;
            return true;
        }

        private static string ExpandPath(string path)
        {
            if (_procArch == 64)
            {
                path = path.Replace("%ProgramFiles%", "%ProgramW6432%");
            }
            return Environment.ExpandEnvironmentVariables(path);
            //string test = Environment.ExpandEnvironmentVariables(path);
            //if (Environment.GetEnvironmentVariable(path) != null)
            //{
            //    return path;
            //}
            //return path;
        }

        public static async Task Install()
        {
            if (!CheckWin32Version(6, 0))
            {
                _logger.Log(LogType.Error,
                    "Unsupported Windows version:",
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

            // Получение общих сервисов до завершения терминального сервиса
            _sharedSvcs = GetSharedServices(_termService, GetServicePid(_termService));
            Thread.Sleep(1000);

            // Завершение терминального процесса
            _logger.Log(LogType.Information, "Terminating service...");
            KillProcess(GetServicePid(_termService));
            Thread.Sleep(1000);

            if (_sharedSvcs.Count != 0)
            {
                foreach (ServiceController svc in _sharedSvcs)
                {
                    SvcStart(svc.ServiceName);
                }
            }

            // Запуск терминальной службы
            SvcStart(_termService);
            Thread.Sleep(1000);

            _logger.Log(LogType.Information, "Configuring registry...");
            TsConfigRegistry(true);
            _logger.Log(LogType.Information, "Configuring firewall...");
            TsConfigFirewall(true);

            _logger.Log(LogType.Information, "Successfully installed.");

            //if (_procArch == 64)
            //    RevertWowRedirection();
        }

        public static void Uninstall()
        {
            if (!CheckWin32Version(6, 0))
            {
                _logger.Log(LogType.Error,
                    "Unsupported Windows version:",
                    "  only >= 6.0 (Vista, Server 2008 and newer) are supported.");
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

            // Проверка терминального процесса
            CheckTermsrvProcess();

            _logger.Log(LogType.Information, "Resetting service library...");
            ResetServiceDll();

            // Получение общих сервисов до завершения терминального сервиса
            _sharedSvcs = GetSharedServices(_termService, GetServicePid(_termService));
            Thread.Sleep(1000);

            // Завершение терминального процесса
            _logger.Log(LogType.Information, "Terminating service...");
            KillProcess(GetServicePid(_termService));
            Thread.Sleep(1000);

            // Удаление файлов враппера, dll, ini, папка...
            _logger.Log(LogType.Information, "Removing files...");
            DeleteFiles();
            Thread.Sleep(1000);

            // Запуск обших сервисов 
            if (_sharedSvcs.Count != 0)
            {
                foreach (ServiceController svc in _sharedSvcs)
                {
                    SvcStart(svc.ServiceName);
                }
            }

            // Запуск терминальной службы
            SvcStart(_termService);

            _logger.Log(LogType.Information, "Configuring registry...");
            TsConfigRegistry(false);
            _logger.Log(LogType.Information, "Configuring firewall...");
            TsConfigFirewall(false);

            _logger.Log(LogType.Information, "Successfully uninstalled.");
        }

        public static void Reload()
        {
            if (!CheckWin32Version(6, 0))
            {
                _logger.Log(LogType.Error,
                    "Unsupported Windows version:",
                    "  only >= 6.0 (Vista, Server 2008 and newer) are supported.");
                return;
            }
            if (!SupportedArchitecture())
            {
                _logger.Log(LogType.Error, "Unsupported processor architecture.");
                return;
            }
            CheckInstall();

            _logger.Log(LogType.Information, "Restarting...");

            // Проверка терминального процесса
            CheckTermsrvProcess();

            // Получение общих сервисов до завершения терминального сервиса
            _sharedSvcs = GetSharedServices(_termService, GetServicePid(_termService));
            Thread.Sleep(1000);

            // Завершение терминального процесса
            _logger.Log(LogType.Information, "Terminating service...");
            KillProcess(GetServicePid(_termService));
            Thread.Sleep(1000);

            // Запуск обших сервисов 
            if (_sharedSvcs.Count != 0)
            {
                foreach (ServiceController svc in _sharedSvcs)
                {
                    SvcStart(svc.ServiceName);
                }
            }

            // Запуск терминальной службы
            SvcStart(_termService);

            _logger.Log(LogType.Information, "Successfully reloaded...");
        }
    }
}
