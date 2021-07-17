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

        public void Log(LogType logType, params string[] logs)
        {
            foreach (string log in logs)
            {
                string logPrefix = logType switch
                {
                    LogType.Information => "[*] ",
                    LogType.Warning => "[!] ",
                    LogType.Error => "[-] "
                };
                Logs +=  string.Format("{0}{1}\n", logPrefix, log);
            }
        }
    }
}
