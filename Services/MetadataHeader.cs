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
        public MetadataHeader() { }
        public byte[] ToBytes()
        {
            string json = ToJson();
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
            byte[] jsonLength = BitConverter.GetBytes(jsonBytes.Length);
            byte[] res = new byte[jsonLength.Length + jsonBytes.Length];
            Array.Copy(jsonLength, 0, res, 0, jsonLength.Length);
            Array.Copy(jsonBytes, 0, res, jsonLength.Length, jsonBytes.Length);
            return res;
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
