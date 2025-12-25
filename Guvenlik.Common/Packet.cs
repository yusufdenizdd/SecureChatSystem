using System;
using System.Text.Json;

namespace Guvenlik.Common
{
    // Ağ üzerinden gönderilecek veri paketi
    public class Packet
    {
        public string Header { get; set; } // Örn: "CERT_REQ", "MSG", "HANDSHAKE"
        public string SenderID { get; set; } // Gönderen Kim? "Client1", "CA" vs.
        public string Payload { get; set; } // Asıl veri (JSON formatında veya Şifreli String)

        // Paketi JSON string'e çevirir (Göndermeden önce)
        public string ToJson()
        {
            return JsonSerializer.Serialize(this);
        }

        // Gelen JSON string'i Pakete çevirir (Aldıktan sonra)
        public static Packet FromJson(string json)
        {
            return JsonSerializer.Deserialize<Packet>(json);
        }
    }
}