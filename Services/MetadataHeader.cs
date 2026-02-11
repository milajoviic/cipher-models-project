using System;
using System.Text;
using System.Text.Json;

namespace ProjekatZI
{
    internal class MetadataHeader
    {
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public DateTime Timestamp { get; set; }
        public string EncryptingAlgorithm { get; set; } = string.Empty;
        public ushort? Nonce { get; set; }
        public string HashValue { get; set; } = string.Empty;
        public MetadataHeader() { }
        
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
