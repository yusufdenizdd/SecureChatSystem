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
        private TcpClient _activePeerClient;
        private NetworkStream _activeStream;
        private Action<string> _logger;
        private Action<string> _chatLogger;

        private string _masterKey;
        private string _iv;

        public ClientService(string myId, Action<string> logger, Action<string> chatLogger)
        {
            MyID = myId;
            _logger = logger;
            _chatLogger = chatLogger;

            _logger($"=== {MyID.ToUpper()} BAŞLATILIYOR ===");
            _logger("ADIM 1: RSA Anahtar Çifti Üretiliyor...");
            CryptoHelper.GenerateRSAKeys(out string pub, out string priv);
            MyPublicKey = pub;
            MyPrivateKey = priv;
            _logger($"-> My Public Key: {MyPublicKey.Substring(0, 20)}...");
            _logger($"-> My Private Key: {MyPrivateKey.Substring(0, 20)}...");
            _logger("-------------------------------------------");
        }

        public async Task<bool> GetCertificateFromCA(string caIp, int caPort)
        {
            try
            {
                _logger($"ADIM 2: CA ({caIp}:{caPort}) ile bağlantı kuruluyor...");
                using (TcpClient client = new TcpClient())
                {
                    await client.ConnectAsync(caIp, caPort);
                    NetworkStream stream = client.GetStream();

                    Certificate requestCert = new Certificate { SubjectID = MyID, AlgorithmID = "RSA-2048", PublicKey = MyPublicKey };
                    Packet reqPacket = new Packet { Header = "CERT_REQ", SenderID = MyID, Payload = JsonSerializer.Serialize(requestCert) };

                    byte[] data = Encoding.UTF8.GetBytes(reqPacket.ToJson());
                    await stream.WriteAsync(data, 0, data.Length);
                    _logger("-> Sertifika İsteği gönderildi. Cevap bekleniyor...");

                    byte[] buffer = new byte[8192];
                    int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    Packet resPacket = Packet.FromJson(Encoding.UTF8.GetString(buffer, 0, bytesRead));

                    if (resPacket.Header == "CERT_RES")
                    {
                        MyCertificate = JsonSerializer.Deserialize<Certificate>(resPacket.Payload);
                        CAPublicKey = MyCertificate.IssuerID;
                        _logger($"ADIM 3: CA'dan İmzalı Sertifika Alındı!");
                        _logger($"-> CA İmzası: {MyCertificate.Signature.Substring(0, 20)}...");
                        _logger("-> CA Public Key Kaydedildi (Doğrulama için).");
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
                _logger($"ADIM 4 (Server Modu): {port} portunda dinlemeye başlandı.");
                Task.Run(() => AcceptPeerConnection());
            }
            catch (Exception ex) { _logger("P2P Başlatma Hatası: " + ex.Message); }
        }

        private async Task AcceptPeerConnection()
        {
            var client = await _p2pListener.AcceptTcpClientAsync();
            _logger("ADIM 5: Bir arkadaş bağlandı! Handshake başlıyor...");
            _ = Task.Run(() => HandlePeerConversation(client, false));
        }

        public async Task ConnectToPeer(string ip, int port)
        {
            try
            {
                TcpClient client = new TcpClient();
                await client.ConnectAsync(ip, port);
                _logger($"ADIM 4 (Client Modu): Arkadaşa ({ip}:{port}) bağlanıldı.");
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
                // --- SERTİFİKA TAKASI ---
                _logger("ADIM 6: Sertifika Takası Başlıyor...");
                Packet myCertPacket = new Packet { Header = "EXCHANGE_CERT", SenderID = MyID, Payload = JsonSerializer.Serialize(MyCertificate) };
                byte[] myCertBytes = Encoding.UTF8.GetBytes(myCertPacket.ToJson());
                await _activeStream.WriteAsync(myCertBytes, 0, myCertBytes.Length);
                _logger("-> Benim sertifikam gönderildi.");

                int bytesRead = await _activeStream.ReadAsync(buffer, 0, buffer.Length);
                Packet peerPacket = Packet.FromJson(Encoding.UTF8.GetString(buffer, 0, bytesRead));
                PeerCertificate = JsonSerializer.Deserialize<Certificate>(peerPacket.Payload);
                _logger($"-> Arkadaşın ({PeerCertificate.SubjectID}) sertifikası alındı.");

                // --- DOĞRULAMA ---
                _logger("ADIM 7: Arkadaşın Sertifikası Doğrulanıyor (Verify)...");
                string dataToVerify = PeerCertificate.SubjectID + PeerCertificate.PublicKey;
                bool isVerified = CryptoHelper.VerifyData(dataToVerify, PeerCertificate.Signature, CAPublicKey);

                if (!isVerified)
                {
                    _logger("!!! HATA: İmza Doğrulanamadı! Bağlantı kesiliyor.");
                    return;
                }
                _logger("-> BAŞARILI: İmza CA tarafından onaylanmış. Güvenli.");

                // --- MASTER KEY (AES) OLUŞTURMA VE AKTARMA ---
                if (isInitiator)
                {
                    _logger("ADIM 8: Master Key (AES) Üretiliyor...");
                    CryptoHelper.GenerateAESKeys(out string mk, out string iv);
                    _masterKey = mk;
                    _logger($"-> Oluşan AES Key (Plain): {_masterKey.Substring(0, 20)}...");

                    _logger("-> Master Key, Karşı tarafın RSA Public Key'i ile şifreleniyor...");
                    string encryptedMasterKey = CryptoHelper.EncryptRSA(_masterKey, PeerCertificate.PublicKey);
                    _logger($"-> Şifreli Key (Cipher): {encryptedMasterKey.Substring(0, 20)}...");

                    Packet keyPacket = new Packet { Header = "MASTER_KEY", SenderID = MyID, Payload = encryptedMasterKey };
                    byte[] keyBytes = Encoding.UTF8.GetBytes(keyPacket.ToJson());
                    await _activeStream.WriteAsync(keyBytes, 0, keyBytes.Length);
                    _logger("-> Şifreli Master Key gönderildi.");
                }
                else
                {
                    _logger("ADIM 8: Şifreli Master Key Bekleniyor...");
                    bytesRead = await _activeStream.ReadAsync(buffer, 0, buffer.Length);
                    Packet keyPacket = Packet.FromJson(Encoding.UTF8.GetString(buffer, 0, bytesRead));

                    _logger($"-> Şifreli Paket Alındı: {keyPacket.Payload.Substring(0, 20)}...");
                    _logger("-> Kendi Private Key'im ile şifre çözülüyor (Decrypt)...");
                    _masterKey = CryptoHelper.DecryptRSA(keyPacket.Payload, MyPrivateKey);
                    _logger($"-> Çözülen AES Key (Plain): {_masterKey.Substring(0, 20)}...");
                }

                // IV Türetme
                using (var sha = System.Security.Cryptography.SHA256.Create())
                {
                    byte[] keyHash = sha.ComputeHash(Encoding.UTF8.GetBytes(_masterKey));
                    byte[] ivBytes = new byte[16];
                    Array.Copy(keyHash, ivBytes, 16);
                    _iv = Convert.ToBase64String(ivBytes);
                }
                _logger("-> (Session Derivation) Master Key kullanılarak IV (Session Parametresi) türetildi.");
                _logger("ADIM 9: Güvenli Tünel (AES-256) Hazır! Sohbet Başlayabilir.");
                _logger("------------------------------------------------");

                // --- SOHBET DÖNGÜSÜ ---
                while (client.Connected)
                {
                    bytesRead = await _activeStream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0) break;

                    string jsonStr = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    Packet chatPacket = Packet.FromJson(jsonStr);

                    if (chatPacket.Header == "CHAT_MSG")
                    {
                        _logger($"GELEN MESAJ (Şifreli): {chatPacket.Payload.Substring(0, 15)}...");
                        string decryptedMsg = CryptoHelper.DecryptAES(chatPacket.Payload, _masterKey, _iv);
                        _logger($"-> Çözülen Mesaj: {decryptedMsg}");
                        _chatLogger($"{chatPacket.SenderID}: {decryptedMsg}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger("Bağlantı koptu: " + ex.Message);
            }
        }

        public async Task SendChatMessage(string plainText)
        {
            if (_activePeerClient == null || !_activePeerClient.Connected) return;

            _logger($"GÖNDERİLİYOR: \"{plainText}\"");
            string encryptedMsg = CryptoHelper.EncryptAES(plainText, _masterKey, _iv);
            _logger($"-> AES ile Şifrelendi: {encryptedMsg.Substring(0, 15)}...");

            Packet msgPacket = new Packet
            {
                Header = "CHAT_MSG",
                SenderID = MyID,
                Payload = encryptedMsg
            };

            byte[] data = Encoding.UTF8.GetBytes(msgPacket.ToJson());
            await _activeStream.WriteAsync(data, 0, data.Length);

            _chatLogger($"Ben: {plainText}");
        }
    }
}