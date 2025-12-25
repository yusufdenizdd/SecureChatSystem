using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Guvenlik.Common;
using System.Text.Json;

namespace Guvenlik.CA
{
    public class CAServer
    {
        private TcpListener _listener;
        private bool _isRunning;
        public string CAPublicKey { get; private set; }
        private string CAPrivateKey;
        private Action<string> _logger;

        public CAServer(Action<string> logger)
        {
            _logger = logger;
            _logger("--- CA BAŞLATILIYOR ---");

            // 1. Anahtar Üretimi Detaylı Log
            _logger("ADIM 1: CA kendi RSA Anahtar Çiftini (2048-bit) üretiyor...");
            CryptoHelper.GenerateRSAKeys(out string pub, out string priv);
            CAPublicKey = pub;
            CAPrivateKey = priv;

            _logger($"-> CA Public Key Oluştu (İlk 30 krktr): {CAPublicKey.Substring(0, 30)}...");
            _logger($"-> CA Private Key Oluştu (Gizli): {CAPrivateKey.Substring(0, 30)}...");
            _logger("------------------------------------------------");
        }

        public void Start(int port)
        {
            _listener = new TcpListener(IPAddress.Any, port);
            _listener.Start();
            _isRunning = true;
            _logger($"ADIM 2: CA Server {port} portunda dinlemeye başladı. İstek bekleniyor...");
            Task.Run(() => AcceptClients());
        }

        private async Task AcceptClients()
        {
            while (_isRunning)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync();
                    _logger("ADIM 3: Yeni bir bağlantı isteği geldi!");
                    _ = Task.Run(() => HandleClient(client));
                }
                catch (Exception ex) { _logger("Hata: " + ex.Message); }
            }
        }

        private void HandleClient(TcpClient client)
        {
            try
            {
                NetworkStream stream = client.GetStream();
                byte[] buffer = new byte[8192];
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                string receivedData = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                Packet receivedPacket = Packet.FromJson(receivedData);

                if (receivedPacket.Header == "CERT_REQ")
                {
                    _logger($"ADIM 4: {receivedPacket.SenderID} kullanıcısından Sertifika İsteği alındı.");
                    _logger($"-> Gelen Veri Boyutu: {receivedData.Length} bytes");

                    Certificate clientCert = JsonSerializer.Deserialize<Certificate>(receivedPacket.Payload);
                    _logger($"-> İstemcinin Public Key'i alındı: {clientCert.PublicKey.Substring(0, 30)}...");

                    // Sertifikayı Doldur
                    clientCert.IssuerID = CAPublicKey; // Doğrulama için CA Public Key'i koyuyoruz
                    clientCert.ValidFrom = DateTime.Now;
                    clientCert.ValidTo = DateTime.Now.AddYears(1);

                    // İmzalama İşlemi Detayı
                    _logger("ADIM 5: Sertifika İmzalanıyor (Signing)...");
                    string dataToSign = clientCert.SubjectID + clientCert.PublicKey;
                    _logger($"-> İmzalanacak Ham Veri (SubjectID+PubKey): {dataToSign.Substring(0, 20)}...");

                    clientCert.Signature = CryptoHelper.SignData(dataToSign, CAPrivateKey);
                    _logger($"-> Dijital İmza Oluşturuldu (İlk 30 krktr): {clientCert.Signature.Substring(0, 30)}...");

                    Packet responsePacket = new Packet
                    {
                        Header = "CERT_RES",
                        SenderID = "CA",
                        Payload = JsonSerializer.Serialize(clientCert)
                    };

                    byte[] responseBytes = Encoding.UTF8.GetBytes(responsePacket.ToJson());
                    stream.Write(responseBytes, 0, responseBytes.Length);
                    _logger($"ADIM 6: İmzalı Sertifika {receivedPacket.SenderID}'ye gönderildi.");
                    _logger("------------------------------------------------");
                }
                client.Close();
            }
            catch (Exception ex) { _logger("İstemci işlem hatası: " + ex.Message); }
        }
    }
}