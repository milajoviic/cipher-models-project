using System;
using System.Security.Cryptography;

namespace ProjekatZI.Algorithms
{
    internal class CTR
    {
        private A52 cipher;
        private ulong key;
        private ushort nonce;
        public ushort Nonce => nonce;

        //funkcija kojom generisemo nonce. posle cu da napravim jos jednu da bismo se usaglasili sa timom.
        private ulong GenerateNonce()
        {
            using(var rnd = RandomNumberGenerator.Create())
            {
                byte[] nBytes = new byte[8];
                rnd.GetBytes(nBytes);
                this.nonce = (ushort)(BitConverter.ToUInt16(nBytes, 0) & 0x3FF);
            }
            return nonce;
        }
        //konstrukor sa poznatim kljucem
        public CTR(string secret)
        {
            this.cipher = new A52();
            this.key = GenerateKey(secret);
            GenerateNonce();
        }
        //konstruktor sa poznatim nonce-om koji se koristi za desifrovanje.
        public CTR(string secret, ushort n)
        {
            this.cipher = new A52();
            this.key = GenerateKey(secret);
            this.nonce = n;
        }
        public void Encrypt(Stream input, Stream output) =>
            CTRAlgorithm(input, output);
        public void Decrypt(Stream input, Stream output) =>
            CTRAlgorithm(input, output);

        public void CTRAlgorithm(Stream input, Stream output)
        {
            //ovde ide glavna logika koja se koristi u CTR algoritmu.
            //ci = Ek(nonce || i) xor mi
            //mi = ci xor Ek(nonce || i)
            const int segmentSize = 4096;
            byte[] buffer = new byte[segmentSize];
            int bytesRead;
            long globalIndex = 0;

            while ((bytesRead = TotalRead(input, buffer, segmentSize)) > 0)
            {
                uint counter = (uint)(globalIndex % 4096);
                uint frameNum = ((uint)nonce << 12) | counter;
                cipher.Initialize(this.key, frameNum);
                byte[] keyStream = cipher.GenerateKeyStream(bytesRead);

                for(int i = 0; i < bytesRead; i++)
                {
                    buffer[i] = (byte)(buffer[i] ^ keyStream[i]);
                }

                output.Write(buffer, 0, bytesRead);
                globalIndex++;
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
        private static ulong GenerateKey(string secret)
        {
            ulong key = 0;
            foreach (char c in secret)
                key = (key << 5) ^ (key >> 3) ^ (uint)c;

            key ^= key >> 33;
            key *= 0xFF51AFD7ED558CCD;
            key ^= key >> 33;
            key *= 0xC4CEB9FE1A85EC53;
            key ^= key >> 33;
            return key;
        }

    }
}
