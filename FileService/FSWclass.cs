using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using ProjekatZI.Services;

namespace ProjekatZI.FileService
{
    internal class FSWclass
    {
        private FileSystemWatcher fsw;
        private string sourcePath;
        private string destPath;

        public event EventHandler<string> fileDetected;

        public Logger logger;

        public FSWclass(string src, string dst, Logger logService)
        {
            logger = logService;
            sourcePath = src;
            destPath = dst;

            if (!Directory.Exists(destPath))
                Directory.CreateDirectory(destPath);

            fsw = new FileSystemWatcher(sourcePath);

            fsw.NotifyFilter = NotifyFilters.FileName
                              | NotifyFilters.DirectoryName
                              | NotifyFilters.CreationTime
                              | NotifyFilters.Attributes
                              | NotifyFilters.LastWrite
                              | NotifyFilters.LastAccess
                              | NotifyFilters.Size;

            fsw.Created += OnCreated;
            fsw.Deleted += OnDelete;
            fsw.Renamed += OnRenamed;
            fsw.Error += OnError;

            fsw.Filter = "*.*";
            fsw.IncludeSubdirectories = true;
        }

        public void Start()
        {
            fsw.EnableRaisingEvents = true;
            logger.Log($"FSW: pokrenut za direktorijum {sourcePath}");
        }
        public void Stop()
        {
            fsw.EnableRaisingEvents = false;
            logger.Log("FSW: prekinut");
        }
        private void OnCreated(object sender, FileSystemEventArgs e)
        {
            try
            {
                Thread.Sleep(500);

                logger.Log($"FSW: kreiran je novi fajl: {e.Name}");
                fileDetected?.Invoke(this, e.FullPath);
            }
            catch (Exception ex)
            {
                logger.Log($"FSW: greska {ex.Message}");
            }
        }
        private void OnDelete(object sender, FileSystemEventArgs e) =>
            logger.Log($"FSW: Izbrisano: {e.FullPath}");
        private void OnRenamed(object sender, RenamedEventArgs e)
        {
            logger.Log($"FSW: Preimenovano:");
            logger.Log($" FSW: Starija verzija: {e.OldFullPath}");
            logger.Log($" FSW: Novija verzija: {e.FullPath}");
        }
        private void PrintException(Exception? err)
        {
            if (err != null)
            {
                logger.Log($"FSW: Poruka greske: {err.Message}");
                logger.Log("FSW: Stacktrace:");
                logger.Log(err.StackTrace);
                PrintException(err.InnerException);
            }
        }
        private void OnError(object sender, ErrorEventArgs e) =>
            PrintException(e.GetException());
    }
}
