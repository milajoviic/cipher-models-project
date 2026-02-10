using System;
using System.Text;
using System.IO;
using ProjekatZI.Algorithms;
using ProjekatZI.Services;

namespace ProjekatZI.FileService
{
    //servis koji povezuje sve algoritme i radi sa fajlovima.
    // [4 byte] -- duzina json-a
    // [n byte] -- duzina header-a
    // [m byte] -- telo fajla
    internal class FileEncrypt
    {
        private readonly Logger logger;
        public FileEncrypt(Logger l)
        {
            this.logger = l;
        }

        //sifrovanje fajla koriscenjem odgovarajuceg algoritma:
        public void EncryptFile(string inPath, string outPath, string alg, string secret)
        {
            if (!File.Exists(inPath))
                throw new FileNotFoundException("Ulazni fajl ne postoji", inPath);
            var fileInfo = new FileInfo(inPath);

            string hashValue;
            using (var hashStream = File.OpenRead(inPath))
            {
                hashValue = MD5.CalculateHash(hashStream);
            }
            var header = new MetadataHeader
            {
                OriginalName = fileInfo.Name,
                FileSize = fileInfo.Length,
                CreationDate = fileInfo.CreationTime,
                EncryptAlg = alg,
                HashAlg = "MD5",
                HashValue = hashValue,
                Nonce = null
            };
            logger.Log("Otpoceto sifrovanje fajla..");
            using (var output = File.Create(outPath))
            {
                switch(alg.ToUpper())
                {
                    case "CTR":
                        EncryptCTR(inPath, output, secret, header);
                        break;
                    case "SimpleSubstitution":
                        EncryptSimpleSubstitution(inPath, output, secret, header);
                        break;
                    default:
                        throw new ArgumentException("Nepoznat algoritam");
                }
                logger.Log("Sifrovanje fajla je zavrseno");
            }
        }
        private void EncryptCTR(string inPath, Stream output, string secret, MetadataHeader header)
        {
            ulong key = GenerateKeyFromSecret(secret);
            var ctr = new CTR(key);

            header.Nonce = ctr.Nonce.ToString();
            header.WriteToStream(output);

            using(var inStream = File.OpenRead(inPath))
            {
                ctr.Encrypt(inStream, output);
            }
        }
        private void EncryptSimpleSubstitution(string inPath, Stream output, string secret, MetadataHeader header)
        {
            header.Nonce = null;
            header.WriteToStream(output);

            var ss = new SimpleSubstitution();
            ss.InitializeTables(secret);

            using(var inStream = File.OpenRead(inPath))
            {
                ss.Encrypt(inStream, output);
            }

        }

        //desifrovanje fajla i verifikacija integriteta pomocu md5 hash-a
        public MetadataHeader DecryptFile(string inPath, string outPath, string secret)
        {
            if (!File.Exists(inPath))
                throw new FileNotFoundException("Sifrovani fajl ne postoji");

            logger.Log($"Desifrovanje fajla {inPath}");
            MetadataHeader header;
            using (var inStream = File.OpenRead(inPath))
            {
                header = MetadataHeader.ReadFromStream(inStream);
                using(var outStream = File.Create(outPath))
                {
                    string algorithm = header.EncryptAlg.ToUpper();
                    if (algorithm == "CTR")
                        DecryptCTR(inStream, outStream, secret, header);
                    else if (algorithm == "SIMPLESUBSTITUTION")
                        DecryptSimpleSub(inStream, outStream, secret, header);
                    else
                        throw new InvalidDataException("Nepoznat algoritam za desifrovanje");
                }
            }

            string decHash = ComputeHash(outPath);
            logger.Log($"MD5 desifrovano: {decHash}");
            logger.Log($"MD5 ocekivano: {header.HashValue}");
            if(decHash!=header.HashValue)
            {
                logger.Log("Verifikacija je neuspesna");
                throw new InvalidDataException($"Verifikacija je neuspesna. Ocekivano:" +
                    $"{header.HashValue}. Dobijeno: {decHash}");
            }
            logger.Log("Verifikacija je uspesna");
            return header;
        }
        private void DecryptCTR(Stream inStream, Stream outStream, string secret, MetadataHeader header)
        {
            ulong key = GenerateKeyFromSecret(secret);
            if (string.IsNullOrEmpty(header.Nonce))
                throw new InvalidDataException("CTR zahteva nonce, koji ne postoji");
            ulong nonce = ulong.Parse(header.Nonce);
            var ctr = new CTR(key, nonce);
            ctr.Decrypt(inStream, outStream);
        }
        private void DecryptSimpleSub(Stream inStream, Stream outStream, string secret, MetadataHeader header)
        {
            var ss = new SimpleSubstitution();
            ss.InitializeTables(secret);
            ss.Decrypt(inStream, outStream);
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
        private string ComputeHash(string filePath)
        {
            using(var fs = File.OpenRead(filePath))
            {
                return MD5.CalculateHash(fs);
            }
        }
    }
}
