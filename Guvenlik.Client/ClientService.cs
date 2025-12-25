using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Guvenlik.Common;

namespace Guvenlik.Client
{
    public class ClientService
    {
        public string MyID { get; set; }
        public string MyPublicKey { get; private set; }
        public string MyPrivateKey { get; private set; }
        public Certificate MyCertificate { get; private set; }
        public Certificate PeerCertificate { get; private set; }

        // CA'nın Public Key'i (Sertifika doğrulama için gerekli)
        public string CAPublicKey { get; private set; }

        private TcpListener _p2pListener;
        private Action<string> _logger;

        // Simetrik Anahtarlar (Master ve Session)
        private string _masterKey;
        private string _sessionKey;

        public ClientService(string myId, Action<string> logger)
        {
            MyID = myId;
            _logger = logger;
            _logger("RSA Anahtarları üretiliyor...");
            CryptoHelper.GenerateRSAKeys(out string pub, out string priv);
            MyPublicKey = pub;
            MyPrivateKey = priv;
        }

        // --- BÖLÜM 1: CA İŞLEMLERİ ---
        public async Task<bool> GetCertificateFromCA(string caIp, int caPort)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    await client.ConnectAsync(caIp, caPort);
                    NetworkStream stream = client.GetStream();

                    Certificate requestCert = new Certificate
                    {
                        SubjectID = MyID,
                        AlgorithmID = "RSA-2048",
                        PublicKey = MyPublicKey
                    };

                    Packet reqPacket = new Packet { Header = "CERT_REQ", SenderID = MyID, Payload = JsonSerializer.Serialize(requestCert) };
                    byte[] data = Encoding.UTF8.GetBytes(reqPacket.ToJson());
                    await stream.WriteAsync(data, 0, data.Length);

                    byte[] buffer = new byte[8192];
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    string responseData = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    Packet resPacket = Packet.FromJson(responseData);

                    if (resPacket.Header == "CERT_RES")
                    {
                        MyCertificate = JsonSerializer.Deserialize<Certificate>(resPacket.Payload);
                        // CA güncellememiz sayesinde IssuerID içinde CA Public Key var!
                        CAPublicKey = MyCertificate.IssuerID;
                        _logger("Sertifika alındı ve CA Public Key kaydedildi.");
                        return true;
                    }
                }
            }
            catch (Exception ex) { _logger("CA Hatası: " + ex.Message); }
            return false;
        }

        // --- BÖLÜM 2: SERVER GİBİ DİNLEME (Arkadaşını Bekle) ---
        public void StartP2PServer(int port)
        {
            try
            {
                _p2pListener = new TcpListener(IPAddress.Any, port);
                _p2pListener.Start();
                _logger($"P2P Sunucusu {port} portunda başlatıldı. Arkadaş bekleniyor...");
                Task.Run(() => AcceptPeerConnection());
            }
            catch (Exception ex) { _logger("P2P Başlatma Hatası: " + ex.Message); }
        }

        private async Task AcceptPeerConnection()
        {
            var client = await _p2pListener.AcceptTcpClientAsync();
            _logger("Bir arkadaş bağlandı! El sıkışma başlıyor...");
            _ = Task.Run(() => HandlePeerConversation(client, false)); // false = Ben başlatan değilim (Responder)
        }

        // --- BÖLÜM 3: ARKADAŞA BAĞLANMA (Initiator) ---
        public async Task ConnectToPeer(string ip, int port)
        {
            try
            {
                TcpClient client = new TcpClient();
                await client.ConnectAsync(ip, port);
                _logger($"Arkadaşa ({ip}:{port}) bağlanıldı.");
                await HandlePeerConversation(client, true); // true = Ben başlatanım (Initiator)
            }
            catch (Exception ex) { _logger("Bağlantı Hatası: " + ex.Message); }
        }

        // --- BÖLÜM 4: PROTOKOL (HANDSHAKE) ---
        private async Task HandlePeerConversation(TcpClient client, bool isInitiator)
        {
            NetworkStream stream = client.GetStream();
            byte[] buffer = new byte[8192];

            try
            {
                // ADIM A: Sertifika Değişimi
                // Önce ben sertifikamı atıyorum
                Packet myCertPacket = new Packet { Header = "EXCHANGE_CERT", SenderID = MyID, Payload = JsonSerializer.Serialize(MyCertificate) };
                byte[] myCertBytes = Encoding.UTF8.GetBytes(myCertPacket.ToJson());
                await stream.WriteAsync(myCertBytes, 0, myCertBytes.Length);

                // Sonra onunkini bekliyorum
                int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                Packet peerPacket = Packet.FromJson(Encoding.UTF8.GetString(buffer, 0, bytesRead));
                PeerCertificate = JsonSerializer.Deserialize<Certificate>(peerPacket.Payload);

                _logger($"Arkadaşın ({PeerCertificate.SubjectID}) sertifikası geldi. Doğrulanıyor...");

                // ADIM B: Doğrulama (CA Public Key ile)
                // PDF [cite: 44, 47] - CA Public Key ile imzayı çöz ve hash'i karşılaştır
                string dataToVerify = PeerCertificate.SubjectID + PeerCertificate.PublicKey;
                bool isVerified = CryptoHelper.VerifyData(dataToVerify, PeerCertificate.Signature, CAPublicKey);

                if (!isVerified)
                {
                    _logger("KIRMIZI ALARM: Sertifika doğrulanamadı! Bağlantı kesiliyor.");
                    client.Close();
                    return;
                }
                _logger("Doğrulama BAŞARILI. Güvenli konuşabiliriz.");

                // ADIM C: Master Key Anlaşması (Basitleştirilmiş)
                // Gerçek senaryoda Nonce (N1, N2) takası yapılır. Biz burada RSA ile MasterKey üretip paylaşacağız.

                if (isInitiator) // Başlatan taraf (Client 1) Master Key'i üretir
                {
                    _logger("Master Key üretiliyor ve şifrelenip gönderiliyor...");
                    CryptoHelper.GenerateAESKeys(out string mk, out string iv);
                    _masterKey = mk; // Basitlik için sadece Key kullanıyoruz

                    // Arkadaşın Public Key'i ile şifrele (Sadece o çözebilir)
                    string encryptedMasterKey = CryptoHelper.EncryptRSA(_masterKey, PeerCertificate.PublicKey);

                    Packet keyPacket = new Packet { Header = "MASTER_KEY", SenderID = MyID, Payload = encryptedMasterKey };
                    byte[] keyBytes = Encoding.UTF8.GetBytes(keyPacket.ToJson());
                    await stream.WriteAsync(keyBytes, 0, keyBytes.Length);
                    _logger("Master Key gönderildi. Güvenli tünel hazır!");
                }
                else // Dinleyen taraf (Client 2) bekler
                {
                    _logger("Master Key bekleniyor...");
                    bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    Packet keyPacket = Packet.FromJson(Encoding.UTF8.GetString(buffer, 0, bytesRead));

                    // Kendi Private Key'im ile çözüyorum
                    _masterKey = CryptoHelper.DecryptRSA(keyPacket.Payload, MyPrivateKey);
                    _logger("Master Key alındı ve çözüldü! Tünel hazır.");
                }

                // BURADAN SONRASI ŞİFRELİ SOHBET...
                // (Şimdilik bağlantıyı açık tutalım)
                while (client.Connected)
                {
                    await Task.Delay(1000);
                }
            }
            catch (Exception ex)
            {
                _logger("İletişim Hatası: " + ex.Message);
            }
        }
    }
}