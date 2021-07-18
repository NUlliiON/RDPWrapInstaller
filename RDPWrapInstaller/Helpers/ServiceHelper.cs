using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace RDPWrapInstaller.Helpers
{
    public static class ServiceHelper
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern Boolean ChangeServiceConfig(
            IntPtr hService,
            UInt32 nServiceType,
            UInt32 nStartType,
            UInt32 nErrorControl,
            String lpBinaryPathName,
            String lpLoadOrderGroup,
            IntPtr lpdwTagId,
            [In] char[] lpDependencies,
            String lpServiceStartName,
            String lpPassword,
            String lpDisplayName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle")]
        static extern int CloseServiceHandle(IntPtr hSCObject);

        private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        private const uint SERVICE_QUERY_CONFIG = 0x00000001;
        private const uint SERVICE_CHANGE_CONFIG = 0x00002;
        private const uint SC_MANAGER_ALL_ACCESS = 0x000F003F;

        public enum ServiceControlManagerType : uint
        {
            SC_MANAGER_CONNECT = 0x1,
            SC_MANAGER_CREATE_SERVICE = 0x2,
            SC_MANAGER_ENUMERATE_SERVICE = 0x4,
            SC_MANAGER_LOCK = 0x8,
            SC_MANAGER_QUERY_LOCK_STATUS = 0x10,
            SC_MANAGER_MODIFY_BOOT_CONFIG = 0x20,
            //SC_MANAGER_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_LOCK | SC_MANAGER_QUERY_LOCK_STATUS | SC_MANAGER_MODIFY_BOOT_CONFIG }
        }

        public static void ChangeStartMode(ServiceController svc, ServiceStartMode mode)
        {
            var scManagerHandle = OpenSCManager(null, null, (uint)ServiceControlManagerType.SC_MANAGER_CONNECT);
            if (scManagerHandle == IntPtr.Zero)
            {
                throw new ExternalException("Open Service Manager Error");
            }

            var serviceHandle = OpenService(
                scManagerHandle,
                svc.ServiceName, SERVICE_CHANGE_CONFIG);

            if (serviceHandle == IntPtr.Zero)
            {
                throw new ExternalException("Open Service Error");
            }

            var result = ChangeServiceConfig(
                serviceHandle,
                SERVICE_NO_CHANGE,
                (uint)mode,
                SERVICE_NO_CHANGE,
                null,
                null,
                IntPtr.Zero,
                null,
                null,
                null,
                null);

            if (result == false)
            {
                int nError = Marshal.GetLastWin32Error();
                var win32Exception = new Win32Exception(nError);
                throw new ExternalException("Could not change service start type: "
                    + win32Exception.Message);
            }

            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scManagerHandle);
        }


        [StructLayout(LayoutKind.Sequential)]
        internal sealed class SERVICE_STATUS_PROCESS
        {
            [MarshalAs(UnmanagedType.U4)]
            public uint dwServiceType;
            [MarshalAs(UnmanagedType.U4)]
            public uint dwCurrentState;
            [MarshalAs(UnmanagedType.U4)]
            public uint dwControlsAccepted;
            [MarshalAs(UnmanagedType.U4)]
            public uint dwWin32ExitCode;
            [MarshalAs(UnmanagedType.U4)]
            public uint dwServiceSpecificExitCode;
            [MarshalAs(UnmanagedType.U4)]
            public uint dwCheckPoint;
            [MarshalAs(UnmanagedType.U4)]
            public uint dwWaitHint;
            [MarshalAs(UnmanagedType.U4)]
            public uint dwProcessId;
            [MarshalAs(UnmanagedType.U4)]
            public uint dwServiceFlags;
        }
        
        internal const int ERROR_INSUFFICIENT_BUFFER = 0x7a;
        internal const int SC_STATUS_PROCESS_INFO = 0;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern unsafe bool QueryServiceStatusEx(IntPtr serviceHandle, int infoLevel, IntPtr buffer, int bufferSize, out int bytesNeeded);

        public static int GetServiceProcessId(this ServiceController sc)
        {
            if (sc == null)
            {
                throw new ArgumentNullException("sc");
            }

            IntPtr zero = IntPtr.Zero;

            try
            {
                int dwBytesNeeded;
                // Call once to figure the size of the output buffer.
                QueryServiceStatusEx(sc.ServiceHandle.DangerousGetHandle(), SC_STATUS_PROCESS_INFO, zero, 0, out dwBytesNeeded);
                if (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER)
                {
                    // Allocate required buffer and call again.
                    zero = Marshal.AllocHGlobal((int)dwBytesNeeded);

                    if (QueryServiceStatusEx(sc.ServiceHandle.DangerousGetHandle(), SC_STATUS_PROCESS_INFO, zero, dwBytesNeeded, out dwBytesNeeded))
                    {
                        var ssp = new SERVICE_STATUS_PROCESS();
                        Marshal.PtrToStructure(zero, ssp);
                        return (int)ssp.dwProcessId;
                    }
                }
            }
            finally
            {
                if (zero != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(zero);
                }
            }
            return -1;
        }
    }
}
