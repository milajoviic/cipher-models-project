using System;
using System.Security.Cryptography;

namespace ProjekatZI.Algorithms
{
    internal class CTR
    {
        private A52 cipher;
        private ulong key;
        private ulong nonce;
        public ulong Nonce => nonce;

        //funkcija kojom generisemo nonce. posle cu da napravim jos jednu da bismo se usaglasili sa timom.
        private ulong GenerateNonce()
        {
            using(var rnd = RandomNumberGenerator.Create())
            {
                byte[] nBytes = new byte[8];
                rnd.GetBytes(nBytes);
                this.nonce = BitConverter.ToUInt64(nBytes, 0);
            }
            return nonce;
        }
        //konstrukor sa poznatim kljucem
        public CTR(ulong k)
        {
            this.cipher = new A52();
            this.key = k;
            GenerateNonce();
        }
        //konstruktor sa poznatim nonce-om koji se koristi za desifrovanje.
        public CTR(ulong k, ulong n)
        {
            this.cipher = new A52();
            this.key = k;
            this.nonce = n;
        }
        public void Encrypt(Stream input, Stream output, int size = 4096) =>
            CTRAlgorithm(input, output, size);
        public void Decrypt(Stream input, Stream output, int size = 4096) =>
            CTRAlgorithm(input, output, size);
       
        public void CTRAlgorithm(Stream input, Stream output, int bufferSize = 4096)
        {
            //ovde ide glavna logika koja se koristi u CTR algoritmu.
            //ci = Ek(nonce || i) xor mi
            //mi = ci xor Ek(nonce || i)
            const int keystreamSize = 15;

            int blockAligmentSize = (bufferSize / keystreamSize) * keystreamSize;
            if (blockAligmentSize == 0) blockAligmentSize = keystreamSize;

            byte[] readBuffer = new byte[blockAligmentSize];
            byte[] writeBuffer = new byte[blockAligmentSize];

            long globalIndex = 0;
            int bytesRead;

            while ((bytesRead = TotalRead(input, readBuffer, blockAligmentSize)) > 0)
            {
                int numBlocks = (int)Math.Ceiling((double)bytesRead / keystreamSize);

                for (int num = 0; num < numBlocks; num++)
                {
                    //pravi se counter:
                    ulong counter = nonce + (ulong)(globalIndex + num);
                    cipher.Initialize(this.key, (uint)(counter & 0xFFFFFFFF));
                    cipher.KeyStream(out byte[] upKey, out byte[] downKey);
                    //koristimo upKey kao keystream.

                    int startInd = num * keystreamSize;
                    int endInd = (int)Math.Min(startInd + keystreamSize, input.Length);

                    for (int i = startInd; i < endInd; i++)
                    {
                        writeBuffer[i] = (byte)(readBuffer[i] ^ upKey[i - startInd]);
                    }

                }

                output.Write(writeBuffer, 0, bytesRead);
                globalIndex += numBlocks;
            }
        }
        //funkcija koja se koristi da procita tacno odredjeni broj bajtova iz strima.
        public static int TotalRead(Stream data, byte[] buffer, int byteNum)
        {
            int totalRead = 0;
            while(totalRead < byteNum)
            {
                int r = data.Read(buffer, totalRead, byteNum - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            return totalRead;
        }
    }
}
