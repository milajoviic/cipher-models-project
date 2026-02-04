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
                    //citanje tipa podataka (1=rec, 2=fajl sa headerom)
                    byte[] typeBuffer = new byte[1];
                    await stream.ReadAsync(typeBuffer, 0, 1);
                    byte dataType = typeBuffer[0];

                    //citanje duzine podataka:
                    byte[] lengthBuffer = new byte[4];
                    await stream.ReadAsync(lengthBuffer, 0, 4);
                    int dataLength = BitConverter.ToInt32(lengthBuffer, 0);

                    //citanje podataka:
                    byte[] data = new byte[dataLength];
                    int totalRead = 0;
                    while(totalRead < dataLength)
                    {
                        int read = await stream.ReadAsync(data, totalRead, dataLength - totalRead);
                        if (read == 0) break;
                        totalRead += read;
                    }
                    if(dataType == 1)
                    {
                        HandleKeyData(data);
                    }
                    else if(dataType == 2)
                    {
                        HandleFileData(data);
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
                using(NetworkStream stream = client.GetStream())
                {
                    byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
                    stream.WriteByte(1);
                    await stream.WriteAsync(BitConverter.GetBytes(secretBytes.Length), 0, 4);
                    await stream.WriteAsync(secretBytes, 0, secretBytes.Length);

                    logger.Log($"TCP: tajna rec je poslatana {ip}");
                }
            }
            catch(Exception e)
            {
                logger.Log($"TCP: greska prilikom slanja kljuca {e.Message}");
            }
        }
        public async Task SendFileAsync(string ip, byte[] fileData)
        {
            try
            {
                using (TcpClient client = new TcpClient(ip, port))
                using (NetworkStream stream = client.GetStream())
                {
                    stream.WriteByte(2);
                    await stream.WriteAsync(BitConverter.GetBytes(fileData.Length), 0, 4); // Dužina
                    await stream.WriteAsync(fileData, 0, fileData.Length);

                    logger.Log($"TCP: Fajl uspešno poslat na {ip}");
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
            logger.Log($"TCP: Primljena tajna rec: {secret}");
            SecretKeyRecieved?.Invoke(this, secret);
        }
        public void HandleFileData(byte[] data)
        {
            try
            {
                MetadataHeader helper = new MetadataHeader();
                int headerLength;
                MetadataHeader header = helper.FromBytes(data, out headerLength);

                byte[] encryptedBody = new byte[data.Length - headerLength];
                Array.Copy(data, headerLength, encryptedBody, 0, encryptedBody.Length);

                string savePath = Path.Combine(directory, header.OriginalName);
                File.WriteAllBytes(savePath, encryptedBody);

                logger.Log($"TCP: fajl {header.OriginalName} je primljen i verifikovan");

                FileRecieved?.Invoke(this, savePath);
            }
            catch(Exception e)
            {
                logger.Log($"TCP: greska kod primanja fajla {e.Message}");
            }
        }
    }
}
