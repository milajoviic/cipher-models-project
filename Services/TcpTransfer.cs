using ProjekatZI.FileService;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace ProjekatZI.Services
{
    internal class TcpTransfer
    {
        private TcpListener listener;
        private bool isListening;
        private readonly int port;
        private readonly Logger logger;
        private readonly string directory;
        private string currSecret;

        public event EventHandler<string> FileRecieved;
        public event EventHandler<string> SecretKeyRecieved;

        public TcpTransfer(int portNum, Logger l, string dir)
        {
            port = portNum;
            logger = l;
            directory = dir;

            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }
        }

        public void SetSecret(string secret)
        {
            currSecret = secret;
            logger.Log("TCP: tajna rec je postavljena");
        }

        public void Start()
        {
            if (isListening) return;
            isListening = true;
            try
            {
                listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
                
                logger.Log($"TCP: server pokrenut na portu {port}");

                Task.Run(() => AcceptAsync());
                //_ = AcceptAsync();
            }
            catch(Exception e)
            {
                logger.Log($"TCP: doslo je do greske {e.Message}");
                throw;
            }
        }
        public void Stop()
        {
            isListening = false;
            try { listener?.Stop(); } catch { }
            logger.Log("TCP: server je zaustavljen");
        }

        public async Task AcceptAsync()
        {
            while(isListening)
            {
                try
                {
                    TcpClient client = await listener.AcceptTcpClientAsync();
                    logger.Log("TCP: klijent je povezan");
                    _ = Task.Run(() => HandleClientAsync(client));
                }
                catch(Exception e)
                {
                    if(isListening)
                        logger.Log("TCP: greska prilikom prihvatanja klijenta");
                }
            }
        }
        private async Task HandleClientAsync(TcpClient client)
        {
            string tempPath = Path.Combine(directory, Guid.NewGuid() + ".recieved");

            try
            {
                using (client)
                using (var nStream = client.GetStream())
                using (var tempStream = new FileStream(tempPath, FileMode.Create))
                {
                    await nStream.CopyToAsync(tempStream);
                }

                logger.Log($"TCP: Primljeno {new FileInfo(tempPath).Length} bytes");
                if (string.IsNullOrEmpty(currSecret))
                {
                    logger.Log("TCP UPOZORENJE: Fajl primljen ali NEMA ključa!");
                    logger.Log("TCP: Sacuvaj enkriptovan fajl u folder...");

                    string savedPath = Path.Combine(directory, "encrypted_" + Path.GetFileName(tempPath));
                    File.Move(tempPath, savedPath);

                    logger.Log($"TCP: Enkriptovan fajl sacuvan: {savedPath}");
                    FileRecieved?.Invoke(this, savedPath);

                    return; 
                }
                var fileEncrypt = new FileEncrypt(logger);
                MetadataHeader header = fileEncrypt.DecryptFile(tempPath, directory, currSecret);
                FileRecieved?.Invoke(this, tempPath);
            }
            catch(Exception e)
            {
                logger.Log($"greska: {e.Message}");
            }
            finally
            {
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
            }
        }
        public async Task SendSecretKeyAsync(string ip, string secret)
        {
            try
            {
                using(TcpClient client = new TcpClient())
                {
                    await client.ConnectAsync(ip, port);
                    using(NetworkStream stream = client.GetStream())
                    {
                        byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
                        stream.WriteByte(1);
                        await stream.WriteAsync(BitConverter.GetBytes((long)secretBytes.Length),
                            0, 8);
                        await stream.WriteAsync(secretBytes, 0, secretBytes.Length);
                        logger.Log($"TCP: tajna rec je poslatana {ip}");
                    }
                }
            }
            catch(Exception e)
            {
                logger.Log($"TCP: greska prilikom slanja kljuca {e.Message}");
            }
        }
        public async Task SendFileAsync(string ip, string filePath, string alg, string secret)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                if (!fileInfo.Exists)
                    throw new FileNotFoundException("Sifrovani fajl ne postoji", filePath);

                long fileSize = fileInfo.Length;

                using (TcpClient client = new TcpClient())
                {
                    await client.ConnectAsync(ip, port);
                    using(NetworkStream nStream = client.GetStream())
                    {
                        var crypto = new FileEncrypt(logger);
                        crypto.EncryptFile(filePath, nStream, alg, secret);
                        //using (var fileStream = File.OpenRead(filePath))
                        //{
                        //    await fileStream.CopyToAsync(nStream);
                        //}
                        logger.Log($"TCP: fajl je uspesno poslat na {ip} (Raw mode)");
                    }
                }
            }
            catch(Exception e)
            {
                logger.Log($"TCP: greska prilikom slanja fajla {e.Message}");
            }
        }
        public void HandleKeyData(byte[] data)
        {
            string secret = Encoding.UTF8.GetString(data);
            currSecret = secret;
            logger.Log($"TCP: Primljena tajna rec: {secret}");
            SecretKeyRecieved?.Invoke(this, secret);
        }

    }
}
