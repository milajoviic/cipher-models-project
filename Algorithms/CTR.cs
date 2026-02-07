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
        public byte[] Encrypt(byte[] pt)
        {
            return CTRAlgorithm(pt);
        }
        public byte[] Decrypt(byte[] ct)
        {
            return CTRAlgorithm(ct);
        }
        public byte[] CTRAlgorithm(byte[] input)
        {
            //ovde ide glavna logika koja se koristi u CTR algoritmu.
            //ci = Ek(nonce || i) xor mi
            //mi = ci xor Ek(nonce || i)
            byte[] output = new byte[input.Length];
            const int keystreamSize = 15;
            int numBlocks = (int)Math.Ceiling((double)input.Length / keystreamSize);
            for(int num = 0; num < numBlocks; num++)
            {
                //pravi se counter:
                ulong counter = nonce + (ulong)num;
                cipher.Initialize(this.key, (uint)(counter & 0xFFFFFFFF));
                cipher.KeyStream(out byte[] upKey, out byte[] downKey);
                //koristimo upKey kao keystream.
                byte[] keystream = upKey;
                int startInd = num * keystreamSize;
                int endInd = Math.Min(startInd + keystreamSize, input.Length);

                for(int i = startInd; i < endInd; i++)
                {
                    int keystreamInd = i - startInd;
                    output[i] = (byte)(input[i] ^ keystream[keystreamInd]);
                }
            }
            return output;
        }

    }
}
