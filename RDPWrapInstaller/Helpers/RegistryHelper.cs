using System.IO;
using Microsoft.Win32;

namespace RDPWrapInstaller.Helpers
{
    class RegistryHelper
    {
        public static object GetValue(string fullPath)
        {
            string keyName = Path.GetDirectoryName(fullPath);
            string valueName = Path.GetFileName(fullPath);
            return Registry.GetValue(keyName, valueName, null);
        }

        public static void SetValue(string fullPath, object value, RegistryValueKind valueKind)
        {
            string keyName = Path.GetDirectoryName(fullPath);
            string valueName = Path.GetFileName(fullPath);
            Registry.SetValue(keyName, valueName, value, valueKind);
        }

        public static bool KeyExists(string fullPath)
        {
            string keyName = Path.GetDirectoryName(fullPath);
            string valueName = Path.GetFileName(fullPath);
            return Registry.GetValue(keyName, valueName, null) != null;
        }

        public static bool HiveExists(RegistryHive registryHive, string path)
        {
            bool is64BitOsSystem = OperatingSystemHelper.InternalCheckIsWow64();
            var regKey = RegistryKey.OpenBaseKey(registryHive, is64BitOsSystem ? RegistryView.Registry64 : RegistryView.Registry32)
                .OpenSubKey(path);
            return regKey != null;
        }
    }
}
