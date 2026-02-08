using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProjekatZI.Algorithms
{
    internal class A52
    {
        private uint R1;
        private uint R2;
        private uint R3;
        private uint R4;

        private const uint R1_Mask = 0x7FFFF;
        private const uint R2_Mask = 0x3FFFFF;
        private const uint R3_Mask = 0x7FFFFF;
        private const uint R4_Mask = 0x1FFFF;

        private static readonly int[] R1_taps = { 18, 17, 16, 13 };
        private static readonly int[] R2_taps = { 21, 20 };
        private static readonly int[] R3_taps = { 22, 21, 20, 7 };
        private static readonly int[] R4_taps = { 16, 11 };

        public A52()
        {
            R1 = R2 = R3 = R4 = 0;
        }

        public void Initialize(ulong key, uint frameNumber)
        {
            R1 = R2 = R3 = R4 = 0;

            for(int i = 0; i < 64; i++)
            {
                uint keyBit = (uint)((key >> i) & 1);
                ClockAllRegisters();
                R1 ^= keyBit;
                R2 ^= keyBit;
                R3 ^= keyBit;
                R4 ^= keyBit;
            }
            for(int i = 0; i < 22; i++)
            {
                uint frameBit = ((frameNumber >> i) & 1);
                ClockAllRegisters();
                R1 ^= frameBit;
                R2 ^= frameBit;
                R3 ^= frameBit;
                R4 ^= frameBit;
            }
            for(int i = 0; i < 100; i++)
            {
                ClockControl();
                GetOutputBit();
            }
        }
        private void ClockAllRegisters()
        {
            R1 = ClockRegister(R1, R1_taps, R1_Mask);
            R2 = ClockRegister(R2, R2_taps, R2_Mask);
            R3 = ClockRegister(R3, R3_taps, R3_Mask);
            R4 = ClockRegister(R4, R4_taps, R4_Mask);
        }
        private uint ClockRegister(uint register, int[] taps, uint mask)
        {
            uint result = 0;
            foreach(int t in taps)
                result ^= (register >> t) & 1;
            register = ((register << 1) | result) & mask;
            return register;
        }
        private void ClockControl()
        {
            uint c1 = (R4 >> 10) & 1;
            uint c2 = (R4 >> 3) & 1;
            uint c3 = (R4 >> 7) & 1;

            if (c1 == 1) R1 = ClockRegister(R1, R1_taps, R1_Mask);
            if (c2 == 1) R2 = ClockRegister(R2, R2_taps, R2_Mask);
            if (c3 == 1) R3 = ClockRegister(R3, R3_taps, R3_Mask);

            R4 = ClockRegister(R4, R4_taps, R4_Mask);
        }
        private uint GetOutputBit()
        {
            //funkcija parnosti.
            uint p1 = ((R1 >> 12) & 1) ^ ((R1 >> 14) & 1) ^ ((R1 >> 15) & 1);
            uint p2 = ((R2 >> 9) & 1) ^ ((R2 >> 13) & 1) ^ ((R2 >> 16) & 1);
            uint p3 = ((R3 >> 13) & 1) ^ ((R3 >> 16) & 1) ^ ((R3 >> 18) & 1);

            //bitovi najvece tezine;
            uint r1 = (R1 >> 18) & 1;
            uint r2 = (R2 >> 21) & 1;
            uint r3 = (R3 >> 22) & 1;

            uint result = r1 ^ r2 ^ r3 ^ p1 ^ p2 ^ p3;

            return result;
        }
        public void KeyStream(out byte[] upKey, out byte[] downKey)
        {
            const int keystreamBits = 228;
            const int halfKeyStream = 114;

            byte[] keystreamFull = new byte[keystreamBits / 8 + 1];
            int bitIndex = 0;
            for(int i=0; i < keystreamBits; i++)
            {
                ClockControl();
                uint bit = GetOutputBit();

                int byteIndex = i / 8;
                int bitPosition = 7 - (i % 8);
                keystreamFull[byteIndex] |= (byte)(bit << bitPosition);
            }
            upKey = new byte[halfKeyStream / 8 + 1];
            downKey = new byte[halfKeyStream / 8 + 1];

            //kopiraj polovine.
            Array.Copy(keystreamFull, 0, upKey, 0, 15);
            Array.Copy(keystreamFull, 14, downKey, 0, 15);
        }
        public void ProcessData(Stream input, Stream output, byte[] ks, int bufferSize = 4096)
        {
            byte[] buffer = new byte[bufferSize];
            int bytesRead;
            long totalRead = 0;

            while((bytesRead = input.Read(buffer, 0, buffer.Length))>0)
            {
                for(int i=0; i<bytesRead; i++)
                    buffer[i] ^= ks[(int)((totalRead + i) % ks.Length)];
                output.Write(buffer, 0, bytesRead);
                totalRead += bytesRead;
            }
        }
    }
}
