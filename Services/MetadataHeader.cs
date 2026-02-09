using System;
using System.Text;
using System.Text.Json;

namespace ProjekatZI
{
    internal class MetadataHeader
    {
        public string OriginalName { get; set; }
        public long FileSize { get; set; }
        public DateTime CreationDate { get; set; }
        public string EncryptAlg { get; set; } = string.Empty;
        public string? Nonce { get; set; } = string.Empty;
        public string HashValue { get; set; } = string.Empty;
        public string HashAlg { get; set; } = string.Empty;
        public MetadataHeader() { }
        public byte[] ToBytes()
        {
            string json = ToJson();
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
            byte[] lengthPrefix = BitConverter.GetBytes(jsonBytes.Length);

            byte[] result = new byte[4 + jsonBytes.Length];
            Array.Copy(lengthPrefix, 0, result, 0, 4);
            Array.Copy(jsonBytes, 0, result, 4, jsonBytes.Length);
            return result;
        }
        public static MetadataHeader FromBytes(byte[] data, out int hLength)
        {
            if (data.Length < 4)
                throw new ArgumentException("Podaci su prekratki za citanje headera.");

            int jsonLength = BitConverter.ToInt32(data, 0);

            if (data.Length < 4 + jsonLength)
                throw new ArgumentException($"Nedovoljno podataka: ocekivano {4 + jsonLength}, dobijeno {data.Length}.");

            string json = Encoding.UTF8.GetString(data, 4, jsonLength);
            hLength = 4 + jsonLength;
            return FromJson(json);
        }
        public string ToJson()
        {
            return JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        }
        public static MetadataHeader FromJson(string json)
        {
            return JsonSerializer.Deserialize<MetadataHeader>(json)
                ?? throw new InvalidDataException("Deserijalizacija header-a je vratila null");
        }
        private static int TotalRead(Stream data, byte[] buffer, int count)
        {
            int totalRead = 0;
            while(totalRead < count)
            {
                int read = data.Read(buffer, totalRead, count - totalRead);
                if (read == 0) break;
                totalRead += read;
            }
            return totalRead;
        }
        public void WriteToStream(Stream s)
        {
            byte[] headerBytes = ToBytes();
            s.Write(headerBytes, 0, headerBytes.Length);
        }
        public static MetadataHeader ReadFromStream(Stream s)
        {
            byte[] buffSize = new byte[4];
            int read = TotalRead(s, buffSize, 4);
            if (read < 4)
                throw new IOException("Neuspesno citanje duzine header-a");
            int jsonLength = BitConverter.ToInt32(buffSize, 0);

            if (jsonLength <= 0 || jsonLength > 10 * 1024 * 1024)
                throw new InvalidDataException("Nevazeca duzina header-a");

            byte[] buffer = new byte[jsonLength];
            read = TotalRead(s, buffer, jsonLength);
            if (read < jsonLength)
                throw new IOException("Neuspesno citanje header-a");
            string json = Encoding.UTF8.GetString(buffer);
            return FromJson(json);
        }
    }
    
}
