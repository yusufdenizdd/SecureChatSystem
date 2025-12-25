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
        public string CAPublicKey { get; private set; }

        private TcpListener _p2pListener;
        private TcpClient _activePeerClient; // O an konuştuğumuz arkadaş
        private NetworkStream _activeStream;
        private Action<string> _logger;
        private Action<string> _chatLogger; // Ekrana chat mesajı basmak için

        // Simetrik Anahtar (AES)
        private string _masterKey;
        // IV (Initialization Vector) - AES için gereklidir, sabit veya dinamik olabilir.
        // Basitlik adına burada sabit türetiyoruz veya MasterKey ile taşıyabiliriz. 
        // Projede kolaylık olsun diye MasterKey'in ilk 16 karakterini IV gibi kullanacağız.
        private string _iv;

        public ClientService(string myId, Action<string> logger, Action<string> chatLogger)
        {
            MyID = myId;
            _logger = logger;
            _chatLogger = chatLogger;
            _logger("RSA Anahtarları üretiliyor...");
            CryptoHelper.GenerateRSAKeys(out string pub, out string priv);
            MyPublicKey = pub;
            MyPrivateKey = priv;
        }

        public async Task<bool> GetCertificateFromCA(string caIp, int caPort)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    await client.ConnectAsync(caIp, caPort);
                    NetworkStream stream = client.GetStream();

                    Certificate requestCert = new Certificate { SubjectID = MyID, AlgorithmID = "RSA-2048", PublicKey = MyPublicKey };
                    Packet reqPacket = new Packet { Header = "CERT_REQ", SenderID = MyID, Payload = JsonSerializer.Serialize(requestCert) };

                    byte[] data = Encoding.UTF8.GetBytes(reqPacket.ToJson());
                    await stream.WriteAsync(data, 0, data.Length);

                    byte[] buffer = new byte[8192];
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    Packet resPacket = Packet.FromJson(Encoding.UTF8.GetString(buffer, 0, bytesRead));

                    if (resPacket.Header == "CERT_RES")
                    {
                        MyCertificate = JsonSerializer.Deserialize<Certificate>(resPacket.Payload);
                        CAPublicKey = MyCertificate.IssuerID;
                        _logger("Sertifika alındı. CA Public Key kaydedildi.");
                        return true;
                    }
                }
            }
            catch (Exception ex) { _logger("CA Hatası: " + ex.Message); }
            return false;
        }

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
            _ = Task.Run(() => HandlePeerConversation(client, false));
        }

        public async Task ConnectToPeer(string ip, int port)
        {
            try
            {
                TcpClient client = new TcpClient();
                await client.ConnectAsync(ip, port);
                _logger($"Arkadaşa ({ip}:{port}) bağlanıldı.");
                await HandlePeerConversation(client, true);
            }
            catch (Exception ex) { _logger("Bağlantı Hatası: " + ex.Message); }
        }

        private async Task HandlePeerConversation(TcpClient client, bool isInitiator)
        {
            _activePeerClient = client;
            _activeStream = client.GetStream();
            byte[] buffer = new byte[8192];

            try
            {
                // 1. Sertifika Takası
                Packet myCertPacket = new Packet { Header = "EXCHANGE_CERT", SenderID = MyID, Payload = JsonSerializer.Serialize(MyCertificate) };
                byte[] myCertBytes = Encoding.UTF8.GetBytes(myCertPacket.ToJson());
                await _activeStream.WriteAsync(myCertBytes, 0, myCertBytes.Length);

                int bytesRead = await _activeStream.ReadAsync(buffer, 0, buffer.Length);
                Packet peerPacket = Packet.FromJson(Encoding.UTF8.GetString(buffer, 0, bytesRead));
                PeerCertificate = JsonSerializer.Deserialize<Certificate>(peerPacket.Payload);

                _logger($"Arkadaşın ({PeerCertificate.SubjectID}) sertifikası doğrulandı.");

                // 2. Master Key Anlaşması
                if (isInitiator)
                {
                    CryptoHelper.GenerateAESKeys(out string mk, out string iv);
                    _masterKey = mk;
                    // IV'yi de karşıya göndermemiz lazım, şimdilik basitlik için mk ile türetiyoruz

                    string encryptedMasterKey = CryptoHelper.EncryptRSA(_masterKey, PeerCertificate.PublicKey);
                    Packet keyPacket = new Packet { Header = "MASTER_KEY", SenderID = MyID, Payload = encryptedMasterKey };
                    byte[] keyBytes = Encoding.UTF8.GetBytes(keyPacket.ToJson());
                    await _activeStream.WriteAsync(keyBytes, 0, keyBytes.Length);
                    _logger("Master Key (Şifreli) gönderildi.");
                }
                else
                {
                    bytesRead = await _activeStream.ReadAsync(buffer, 0, buffer.Length);
                    Packet keyPacket = Packet.FromJson(Encoding.UTF8.GetString(buffer, 0, bytesRead));
                    _masterKey = CryptoHelper.DecryptRSA(keyPacket.Payload, MyPrivateKey);
                    _logger("Master Key alındı ve çözüldü.");
                }

                // IV üretimi (Basitlik için Key'in hash'inden üretiyoruz ki iki tarafta da aynı olsun)
                using (var sha = System.Security.Cryptography.SHA256.Create())
                {
                    byte[] keyHash = sha.ComputeHash(Encoding.UTF8.GetBytes(_masterKey));
                    byte[] ivBytes = new byte[16];
                    Array.Copy(keyHash, ivBytes, 16);
                    _iv = Convert.ToBase64String(ivBytes);
                }

                _logger("Tünel Hazır! Şifreli sohbet başlayabilir.");

                // 3. Sohbet Döngüsü (Mesaj Dinleme)
                while (client.Connected)
                {
                    bytesRead = await _activeStream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0) break;

                    string jsonStr = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    Packet chatPacket = Packet.FromJson(jsonStr);

                    if (chatPacket.Header == "CHAT_MSG")
                    {
                        // Şifreli mesajı çöz
                        string decryptedMsg = CryptoHelper.DecryptAES(chatPacket.Payload, _masterKey, _iv);
                        _chatLogger($"{chatPacket.SenderID}: {decryptedMsg}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger("Bağlantı koptu: " + ex.Message);
            }
        }

        // Mesaj Gönderme Fonksiyonu
        public async Task SendChatMessage(string plainText)
        {
            if (_activePeerClient == null || !_activePeerClient.Connected) return;

            // Mesajı AES ile şifrele
            string encryptedMsg = CryptoHelper.EncryptAES(plainText, _masterKey, _iv);

            Packet msgPacket = new Packet
            {
                Header = "CHAT_MSG",
                SenderID = MyID,
                Payload = encryptedMsg
            };

            byte[] data = Encoding.UTF8.GetBytes(msgPacket.ToJson());
            await _activeStream.WriteAsync(data, 0, data.Length);

            // Kendi ekranımıza da yazalım
            _chatLogger($"Ben: {plainText}");
        }
    }
}