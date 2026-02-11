using ProjekatZI.Algorithms;
using ProjekatZI.Services;
using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace ProjekatZI.FileService
{
    internal class FileEncrypt
    {
        private readonly Logger logger;
        public FileEncrypt(Logger l)
        {
            this.logger = l;
        }
        public void EncryptFile(string inPath, Stream outStream, string alg, string secret)
        {
            if (!File.Exists(inPath))
                throw new FileNotFoundException("Ulazni fajl ne postoji", inPath);
            var fileInfo = new FileInfo(inPath);

                using (var tempEncryptedStream = new MemoryStream())
                {
                    var header = new MetadataHeader
                    {
                        FileName = fileInfo.Name,
                        FileSize = 0, 
                        Timestamp = DateTime.Now,
                        EncryptingAlgorithm = alg,
                        Nonce = null
                    };

                    using (var inStream = File.OpenRead(inPath))
                    {
                        switch (alg)
                        {
                            case "A5_2":
                                var ctr = new CTR(secret); 
                                header.Nonce = (ushort)ctr.Nonce;
                                ctr.Encrypt(inStream, tempEncryptedStream);
                                break;
                            case "SimpleSubstitution":
                                var ss = new SimpleSubstitution();
                                ss.InitializeTables(secret);
                                ss.Encrypt(inStream, tempEncryptedStream);
                                break;
                            //case "A5_2":
                            //    ulong key = GenerateKeyFromSecret(secret);
                            //    uint frame = 0x134; 
                            //    header.Nonce = (ushort)frame;
                            //    var a52 = new A52();
                            //    a52.Initialize(key, frame);
                            //    a52.KeyStream(out var upKey, out _);
                            //    a52.ProcessData(inStream, tempEncryptedStream, upKey);
                            //    break;
                            default:
                                throw new ArgumentException("Nepoznat algoritam");
                        }
                    }

                    tempEncryptedStream.Seek(0, SeekOrigin.Begin);
                    header.HashValue = MD5.CalculateHash(tempEncryptedStream);
                    header.FileSize = tempEncryptedStream.Length;

                    string jsonHeader = JsonSerializer.Serialize(header);
                    byte[] headerBytes = Encoding.UTF8.GetBytes(jsonHeader);
                    byte[] lengthBytes = BitConverter.GetBytes(headerBytes.Length);

                    outStream.Write(lengthBytes, 0, lengthBytes.Length); 
                    outStream.Write(headerBytes, 0, headerBytes.Length); 

                    tempEncryptedStream.Seek(0, SeekOrigin.Begin);
                    tempEncryptedStream.CopyTo(outStream); 
                }
                logger.Log("Sifrovanje fajla je zavrseno");
        }
        public MetadataHeader DecryptFile(string inPath, string outPath, string secret)
        {
            if (!File.Exists(inPath))
                throw new FileNotFoundException("Sifrovani fajl ne postoji");

            logger.Log($"Desifrovanje fajla.. {inPath}");

            using (Stream inStream = new FileStream(inPath, FileMode.Open, FileAccess.Read)) 
            {
                var header = MetadataHeader.ReadFromStream(inStream);
                long dataStartPosition = inStream.Position;
                string currentEncryptedHash = MD5.CalculateHash(inStream); 

                inStream.Seek(dataStartPosition, SeekOrigin.Begin);

                if (currentEncryptedHash != header.HashValue)
                {
                    logger.Log("UPOZORENJE: Hash sifrovanog fajla se ne poklapa (fajl je možda ostecen ili format hash-a nije isti).");
                }

                string destPath = Path.Combine(outPath, "des_" + header.FileName);
                using (Stream outStream = new FileStream(destPath, FileMode.Create, FileAccess.Write))
                {
                    string algorithm = header.EncryptingAlgorithm;

                    if (string.Equals(algorithm, "A5_2", StringComparison.OrdinalIgnoreCase))
                        DecryptCTR(inStream, outStream, secret, header);
                    else if (string.Equals(algorithm, "SimpleSubstitution", StringComparison.OrdinalIgnoreCase))
                        DecryptSimpleSub(inStream, outStream, secret);
                    //else if (string.Equals(algorithm, "A5_2", StringComparison.OrdinalIgnoreCase))
                    //    DecryptA52(inStream, outStream, secret, header);
                    else
                        throw new InvalidDataException($"Nepoznat algoritam: {algorithm}");
                }
               

                return header;
            }
        }
        private void DecryptCTR(Stream inStream, Stream outStream, string secret, MetadataHeader header)
        {
            if (!header.Nonce.HasValue)
                throw new InvalidDataException("CTR zahteva nonce, koji ne postoji");
            ushort nonce = header.Nonce.Value;
            var ctr = new CTR(secret, nonce);
            ctr.Decrypt(inStream, outStream);
            logger.Log($"Fajl je dekriptovan");
        }
        private void DecryptSimpleSub(Stream inStream, Stream outStream, string secret)
        {
            var ss = new SimpleSubstitution();
            ss.InitializeTables(secret);
            ss.Decrypt(inStream, outStream);
        }
        private void DecryptA52(Stream input, Stream output, string secret, MetadataHeader header)
        {
            ulong key = GenerateKeyFromSecret(secret);
            if (!header.Nonce.HasValue)
                throw new InvalidDataException("A5_2 zahteva frame number (nonce).");

            uint frame = (uint)header.Nonce.Value;
            var a52 = new A52();
            a52.Initialize(key, frame);

            a52.KeyStream(out var upKey, out var downKey);
            a52.ProcessData(input, output, upKey);
        }
        private static ulong GenerateKeyFromSecret(string secret)
        {
            byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
            using (var ms = new MemoryStream(secretBytes))
            {
                string hashHex = MD5.CalculateHash(ms);
                string keyHex = hashHex.Substring(0, 16);
                return Convert.ToUInt64(keyHex, 16);
            }
        }
      
    }
}
