using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProjekatZI.Algorithms
{
    internal class MD5
    {
        private static int[] rValue = {
                7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
                5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
                4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
                6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
            };
        private static readonly uint[] K = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };
        
        public static uint LeftRotate(uint x, int y)
        {
            return (x << y) | (x >> (32 - y));
        }
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

            return GetByteString(a0) + GetByteString(b0) + GetByteString(c0) + GetByteString(d0);
        }
        private static byte[] PadBlock(byte[] lastData, int dataLength, long totalBytes)
        {
            long totalBits = totalBytes * 8;
            int padding = (56 + 64 - ((dataLength + 1) % 64)) % 64;
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
        private static string GetByteString(uint x)
        {
            return string.Join("", BitConverter.GetBytes(x).Select(y => y.ToString("x2")));
        }
    }
}
