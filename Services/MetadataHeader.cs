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
        public string EncryptAlg { get; set; }
        public string HashAlg { get; set; }

        public MetadataHeader() { }
        public byte[] ToBytes()
        {
            string json = ToJson();
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
            byte[] jsonLength = BitConverter.GetBytes(jsonBytes.Length);

            using (MemoryStream ms = new MemoryStream())
            {
                ms.Write(jsonLength, 0, jsonLength.Length);
                ms.Write(jsonBytes, 0, jsonBytes.Length);
                return ms.ToArray();
            }
        }
        public MetadataHeader FromBytes(byte[] data, out int hLength)
        {
            int jsonLength = BitConverter.ToInt32(data, 0);
            byte[] jsonBytes = new byte[jsonLength];
            Array.Copy(data, 4, jsonBytes, 0, jsonLength);
            string json = Encoding.UTF8.GetString(jsonBytes);
            hLength = 4 + jsonLength;
            return FromJson(json);
        }
        public string ToJson()
        {
            return JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        }
        public MetadataHeader FromJson(string json)
        {
            return JsonSerializer.Deserialize<MetadataHeader>(json);
        }
    }
}
