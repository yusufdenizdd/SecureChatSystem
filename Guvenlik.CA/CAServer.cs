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

        // CA'nın kendi anahtarları
        public string CAPublicKey { get; private set; }
        private string CAPrivateKey;

        // Logları ekrana yazdırmak için bir "Eylem" (Action) tanımlıyoruz
        private Action<string> _logger;

        public CAServer(Action<string> logger)
        {
            _logger = logger;
            // 1. Uygulama açılınca CA kendi anahtarlarını üretir
            CryptoHelper.GenerateRSAKeys(out string pub, out string priv);
            CAPublicKey = pub;
            CAPrivateKey = priv;
            _logger("CA Anahtarları üretildi.");
            _logger("CA Public Key: " + CAPublicKey.Substring(0, 20) + "...");
        }

        public void Start(int port)
        {
            _listener = new TcpListener(IPAddress.Any, port);
            _listener.Start();
            _isRunning = true;
            _logger($"CA Server {port} portunda dinlemeye başladı...");

            // Arka planda sürekli müşteri bekle
            Task.Run(() => AcceptClients());
        }

        private async Task AcceptClients()
        {
            while (_isRunning)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync();
                    _logger("Yeni bir istemci bağlandı.");
                    // Her istemciyi ayrı bir kanalda (Task) işle
                    _ = Task.Run(() => HandleClient(client));
                }
                catch (Exception ex)
                {
                    _logger("Hata: " + ex.Message);
                }
            }
        }

        private void HandleClient(TcpClient client)
        {
            try
            {
                NetworkStream stream = client.GetStream();
                byte[] buffer = new byte[4096];
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                string receivedData = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                // Gelen veriyi Pakete çevir
                Packet receivedPacket = Packet.FromJson(receivedData);

                if (receivedPacket.Header == "CERT_REQ") // Sertifika İsteği Geldiyse
                {
                    _logger($"{receivedPacket.SenderID} sertifika istiyor...");

                    // 1. İstemcinin gönderdiği Ham Sertifika bilgisini al
                    Certificate clientCert = JsonSerializer.Deserialize<Certificate>(receivedPacket.Payload);

                    // 2. Sertifikayı CA Bilgileriyle doldur
                    //clientCert.IssuerID = "IZU_CA_SERVER";
                    // Doğrulama yapabilmek için IssuerID alanına CA'nın Public Key'ini koyuyoruz
                    clientCert.IssuerID = CAPublicKey;
                    clientCert.ValidFrom = DateTime.Now;
                    clientCert.ValidTo = DateTime.Now.AddYears(1);

                    // 3. Sertifikanın özetini çıkar ve CA Private Key ile imzala
                    // İmzalanacak veri: SubjectID + PublicKey
                    string dataToSign = clientCert.SubjectID + clientCert.PublicKey;
                    clientCert.Signature = CryptoHelper.SignData(dataToSign, CAPrivateKey);

                    _logger($"{receivedPacket.SenderID} için sertifika imzalandı.");

                    // 4. İmzalı sertifikayı geri gönder
                    Packet responsePacket = new Packet
                    {
                        Header = "CERT_RES",
                        SenderID = "CA",
                        Payload = JsonSerializer.Serialize(clientCert)
                    };

                    byte[] responseBytes = Encoding.UTF8.GetBytes(responsePacket.ToJson());
                    stream.Write(responseBytes, 0, responseBytes.Length);
                }

                client.Close();
            }
            catch (Exception ex)
            {
                _logger("İstemci işlem hatası: " + ex.Message);
            }
        }
    }
}