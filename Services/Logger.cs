using System;
using System.IO;

namespace ProjekatZI.Services
{
    internal class Logger
    {
        private readonly string logPath; 
        private readonly object lockObject = new object();

        public event EventHandler<string> Logged;
        public Logger(string logFile)
        {
            logPath = logFile;
        }
        public void Log(string message)
        {
            string entry = $"[{DateTime.Now: yyyy-MM-dd HH:mm:ss}] {message}";
            lock(lockObject)
            {
                try
                {
                    File.AppendAllText(logPath, entry + Environment.NewLine);
                    Logged?.Invoke(this, entry);
                }
                catch(Exception e)
                {
                    Console.WriteLine($"Greska prilikom logovanja: {e.Message}");
                }
            }
        }
        public void ClearLogs()
        {
            lock(lockObject)
            {
                try
                {
                    File.WriteAllText(logPath, string.Empty);
                }
                catch
                { 
                }
            }
        }
    }
}
