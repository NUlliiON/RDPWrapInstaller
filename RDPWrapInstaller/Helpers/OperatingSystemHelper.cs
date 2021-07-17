using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static RDPWrapInstaller.Native.Consts;
using static RDPWrapInstaller.Native.Methods;
using static RDPWrapInstaller.Native.Structs;

namespace RDPWrapInstaller.Helpers
{
    internal class OperatingSystemHelper
    {
        static bool is64BitProcess = (IntPtr.Size == 8);
        static bool is64BitOperatingSystem = is64BitProcess || InternalCheckIsWow64();

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process(
            [In] IntPtr hProcess,
            [Out] out bool wow64Process
        );

        public static bool InternalCheckIsWow64()
        {
            if ((Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Minor >= 1) ||
                Environment.OSVersion.Version.Major >= 6)
            {
                using (Process p = Process.GetCurrentProcess())
                {
                    bool retVal;
                    if (!IsWow64Process(p.Handle, out retVal))
                    {
                        return false;
                    }
                    return retVal;
                }
            }
            else
            {
                return false;
            }
        }

        public enum Platform
        {
            X86,
            X64,
            IA64,
            Unknown
        }

        public static Platform GetPlatform()
        {
            SYSTEM_INFO sysInfo = new SYSTEM_INFO();

            if (Environment.OSVersion.Version.Major > 5 ||
                (Environment.OSVersion.Version.Major == 5 &&
                Environment.OSVersion.Version.Minor >= 1))
            {
                GetNativeSystemInfo(ref sysInfo);
            }
            else
            {
                GetSystemInfo(ref sysInfo);
            }

            switch (sysInfo.wProcessorArchitecture)
            {
                case PROCESSOR_ARCHITECTURE_IA64:
                    return Platform.IA64;
                case PROCESSOR_ARCHITECTURE_AMD64:
                    return Platform.X64;
                case PROCESSOR_ARCHITECTURE_INTEL:
                    return Platform.X86;
                default:
                    return Platform.Unknown;
            }
        }
    }
}
