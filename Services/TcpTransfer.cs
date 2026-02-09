using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;

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
            try
            {
                listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
                isListening = true;
                logger.Log($"TCP: server pokrenut na portu {port}");

                Task.Run(() => AcceptAsync());
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
            listener.Stop();
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
                    logger.Log("TCP: greska prilikom prihvatanja klijenta");
                }
            }
        }
        private async Task HandleClientAsync(TcpClient client)
        {
            using(NetworkStream stream = client.GetStream())
            {
                try
                {
                    using (client) 
                    using(NetworkStream nStream = client.GetStream())
                    {
                        //citanje tipa podataka (1=rec, 2=fajl sa headerom)
                        byte[] typeBuffer = new byte[1];
                        await stream.ReadAsync(typeBuffer, 0, 1);
                        byte dataType = typeBuffer[0];

                        //citanje duzine podataka:
                        byte[] bufferSize = new byte[8];
                        await stream.ReadAsync(bufferSize, 0, 4);
                        int dataLength = BitConverter.ToInt32(bufferSize, 0);

                        if (dataType == 1)
                        {
                            byte[] data = new byte[dataLength];
                            await TotalReadAsync(nStream, data, (int)dataLength);
                            HandleKeyData(data);
                        }
                        else if (dataType == 2)
                        {
                            HandleFileData(nStream, dataLength);
                        }
                        else
                        {
                            logger.Log($"TCP: nepoznat tip podatka: {dataType}");
                        }
                    }
                }
                catch(Exception e)
                {
                    logger.Log($"TCP: greska prilikom rada sa klijentom {e.Message}");
                }
                finally
                {
                    client?.Close();
                }
            }
        }
        public async Task SendSecretKeyAsync(string ip, string secret)
        {
            try
            {
                using(TcpClient client = new TcpClient(ip, port))
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
        public async Task SendFileAsync(string ip, string filePath)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                if (!fileInfo.Exists)
                    throw new FileNotFoundException("Sifrovani fajl ne postoji", filePath);

                long fileSize = fileInfo.Length;

                using (TcpClient client = new TcpClient(ip, port))
                {
                    await client.ConnectAsync(ip, port);
                    using(NetworkStream nStream = client.GetStream())
                    {
                        nStream.WriteByte(2);
                        await nStream.WriteAsync(BitConverter.GetBytes(fileSize), 0, 8);

                        using(var fileStream = File.OpenRead(filePath))
                        {
                            byte[] buffer = new byte[4096];
                            int bytesRead;
                            long totalSent = 0;

                            while((bytesRead = await fileStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                            {
                                await nStream.WriteAsync(buffer, 0, bytesRead);
                                totalSent += bytesRead;
                            }
                        }
                        logger.Log($"TCP: fajl je uspesno poslat na {ip}");
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
        public async Task HandleFileData(NetworkStream nStream, long length)
        {
            string tempFile = Path.Combine(directory, $"primljeno {DateTime.Now:yyyyMMdd_HHmmss}.enc");
            try
            {
                using (var fileStream = File.Create(tempFile))
                {
                    byte[] buffer = new byte[4096];
                    long remain = length;

                    while(remain > 0)
                    {
                        int notRead = (int)Math.Min(remain, buffer.Length);
                        int read = await nStream.ReadAsync(buffer, 0, notRead);
                        if(read == 0)
                        {
                            logger.Log("TCP: konekcija je prekinuta pre nego sto se procitao fajl");
                            break;
                        }
                        await fileStream.WriteAsync(buffer, 0, read);
                        remain -= read;
                    }
                    logger.Log($"TCP: privremeno sacuvan fajl {tempFile}");
                    MetadataHeader header;
                    using(var readStream = File.OpenRead(tempFile))
                    {
                        header = MetadataHeader.ReadFromStream(readStream);
                    }
                    string decryptedPath = Path.Combine(directory, header.OriginalName);
                    var fileEncrypt = new FileEncrypt(logger);
                    try
                    {
                        MetadataHeader resultH = fileEncrypt.DecryptFile(tempFile, decryptedPath, currSecret);
                        logger.Log($"TCP: fajl {resultH.OriginalName} je primljen, desifrovan i verifikovan uspesno");
                        FileRecieved?.Invoke(this, decryptedPath);
                    }
                    catch(Exception e)
                    {
                        logger.Log($"TCP: neuspesna verifikacija hash koda {tempFile}");
                        FileRecieved?.Invoke(this, tempFile);
                        return;
                    }
                    try { File.Delete(tempFile); } catch { }
                }
            }
            catch(Exception e)
            {
                logger.Log($"TCP: doslo je do greske prilikom obrade fajla {e.Message}");
            }
        }
        private static async Task TotalReadAsync(Stream data, byte[] buffer, int count)
        {
            int totalRead = 0;
            while(totalRead < count)
            {
                int read = await data.ReadAsync(buffer, totalRead, count - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
        }
    }
}
