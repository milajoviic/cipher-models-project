using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProjekatZI.Algorithms
{
    internal class MD5
    {
        private static int[] rValue = new int[64];
        private static uint[] K = new uint[64];
        static MD5()
        {
            int[] r = new int[64]
            {
                 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
            };
            Array.Copy(r, rValue, 64);
            for(int i = 0; i < 64; i++)
            {
                K[i] = (uint)Math.Floor(Math.Abs(Math.Sin(i + 1)) * Math.Pow(2, 32));
            }
        }
        public static uint LeftRotate(uint x, int y)
        {
            return (x << y) | (x >> (32 - y));
        }
        //private static byte[] PadMessage(byte[] message)
        //{
        //    long orgLength = message.Length;
        //    long orgBitsLength = orgLength * 8;

        //    int paddingLength = (int)(56 - (orgLength + 1) % 64);
        //    if (paddingLength < 0)
        //        paddingLength += 64;

        //    byte[] paddedMessage = new byte[orgLength + 1 + paddingLength + 8];

        //    Array.Copy(message, paddedMessage, orgLength);

        //    paddedMessage[orgLength] = 0x80;

        //    byte[] lengthBytes = BitConverter.GetBytes(orgBitsLength);
        //    Array.Copy(lengthBytes, 0, paddedMessage, paddedMessage.Length - 8, 8);

        //    return paddedMessage;
        //}
        public static string CalculateHash(Stream input)
        {
            uint a0 = 0x67452301;
            uint b0 = 0xEFCDAB89;
            uint c0 = 0x98BADCFE;
            uint d0 = 0x10325476;

            byte[] buffer = new byte[64];
            long totalBytes = 0;
            bool finished = false;

            while(!finished)
            {
                int read = TotalRead(input, buffer, 64);
                totalBytes += read;

                if (read < 64)
                {
                    byte[] finalBlock = PadBlock(buffer, read, totalBytes);
                    for (int chunk = 0; chunk < finalBlock.Length; chunk += 64)
                        ProcessChunk(finalBlock, chunk, ref a0, ref b0,
                            ref c0, ref d0);
                    finished = true;
                }
                else
                    ProcessChunk(buffer, 0, ref a0, ref b0, ref c0, ref d0);
            }

            byte[] result = new byte[16];
            Array.Copy(BitConverter.GetBytes(a0), 0, result, 0, 4);
            Array.Copy(BitConverter.GetBytes(b0), 0, result, 4, 4);
            Array.Copy(BitConverter.GetBytes(c0), 0, result, 8, 4);
            Array.Copy(BitConverter.GetBytes(d0), 0, result, 12, 4);


            return BitToHexString(result);
        }
        private static byte[] PadBlock(byte[] lastData, int dataLength, long totalBytes)
        {
            long totalBits = totalBytes * 8;
            int padding = 56 - (dataLength + 1) % 64;
            if (padding < 0)
                padding += 64;

            int totalLength = dataLength + 1 + padding + 8;
            byte[] padded = new byte[totalLength];

            Array.Copy(lastData, 0, padded, 0, dataLength);
            padded[dataLength] = 0x80;

            byte[] lengthBytes = BitConverter.GetBytes(totalBits);
            Array.Copy(lengthBytes, 0, padded, padded.Length - 8, 8);

            return padded;
        }
        private static void ProcessChunk(byte[] data, int offset,
            ref uint a0, ref uint b0, ref uint c0, ref uint d0)
        {
            uint[] w = new uint[16];
            for (int i = 0; i < 16; i++)
                w[i] = BitConverter.ToUInt32(data, offset + i * 4);
            uint a = a0, b = b0, c = c0, d = d0;
            for(int i = 0; i < 64; i++)
            {
                uint f, g;
                if (i <= 15)
                {
                    f = (b & c) | (~b & d);
                    g = (uint)i;
                }
                else if (i <= 31)
                {
                    f = (d & b) | (~d & c);
                    g = (uint)((5 * i + 1) % 16);
                }
                else if (i <= 47)
                {
                    f = b ^ c ^ d;
                    g = (uint)((3 * i + 5) % 16);
                }
                else
                {
                    f = c ^ (b | ~d);
                    g = (uint)((7 * i) % 16);
                }
                uint temp = d;
                d = c;
                c = b;
                b = b + LeftRotate(a + f + K[i] + w[g], rValue[i]);
                a = temp;
            }
            a0 += a;
            b0 += b;
            c0 += c;
            d0 += d;
        }
        private static string BitToHexString(byte[] data)
        {
            StringBuilder sb = new StringBuilder();
            foreach(byte b in data)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }
        public static int TotalRead(Stream data, byte[] buff, int count)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int r = data.Read(buff, totalRead, count - totalRead);
                if (r == 0) break;
                totalRead += r;
            }
            return totalRead;
        }
        //mora da postoji byte->stream ne znam zasto.
    }
}
