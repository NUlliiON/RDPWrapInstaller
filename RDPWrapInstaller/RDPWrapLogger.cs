using System;

namespace RDPWrapInstaller
{
    internal enum LogType
    {
        Information,
        Warning,
        Error
    }
    
    internal class RDPWrapLogger
    {
        public string Logs { get; private set; } = "";

        public void Log(LogType logType, string log)
        {
            string logPrefix = logType switch
            {
                LogType.Information => "[*] ",
                LogType.Warning => "[!] ",
                LogType.Error => "[-] ",
                _ => throw new ArgumentOutOfRangeException()
            };
            Logs += string.Format("{0}{1}\n", logPrefix, log);
        }
    }
}
