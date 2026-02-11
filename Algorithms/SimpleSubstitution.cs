using System;
using System.Collections;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProjekatZI.Algorithms
{
    internal class SimpleSubstitution
    {
        private readonly Dictionary<byte, byte> encryptTable;
        private readonly Dictionary<byte, byte> decryptTable;

        public SimpleSubstitution()
        {
            encryptTable = new Dictionary<byte, byte>();
            decryptTable = new Dictionary<byte, byte>();
        }
        public byte[] GenerateEncryptKey(string secret)
        {
            byte[] key = new byte[256];
            int sum = secret.Sum(c => (int)c);

            for (int i = 0; i < 256; i++)
                key[i] = (byte)((i + sum) % 256);
            return key;
        }
        public byte[] GenerateDecryptKey(byte[] k)
        {
            byte[] decryptKey = new byte[256];

            for (int i = 0; i < 256; i++)
                decryptKey[k[i]] = (byte)i;
            return decryptKey;
        }
        public void InitializeTables(string secret)
        {
            byte[] encryptKey = GenerateEncryptKey(secret);
            
            encryptTable.Clear();
            decryptTable.Clear();

            for(int i=0;i<256;i++)
            {
                encryptTable.Add((byte)i, encryptKey[i]);
                decryptTable.Add(encryptKey[i], (byte)i);
            }
        }

        public void Encrypt(Stream input, Stream output, int size = 4096) =>
            ProcessData(input, output, encryptTable, size);


        public void Decrypt(Stream input, Stream output, int size = 4096) =>
            ProcessData(input, output, decryptTable, size);
       

        private void ProcessData(Stream input, Stream output, 
            Dictionary<byte, byte> table, int buffSize)
        {
            byte[] buffer = new byte[buffSize];
            int bytesRead;

            while((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                for(int i=0; i < bytesRead; i++)
                {
                    buffer[i] = table[buffer[i]];
                }
                output.Write(buffer, 0, bytesRead);
            }
        }
    }
}
