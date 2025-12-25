using System;
using System.Security.Cryptography;
using System.Text;

namespace Guvenlik.Common
{
    public static class CryptoHelper
    {
        // --- RSA İŞLEMLERİ (Asimetrik) ---

        // Yeni bir RSA Anahtar Çifti üretir (Public ve Private Key)
        public static void GenerateRSAKeys(out string publicKey, out string privateKey)
        {
            using (var rsa = RSA.Create(2048))
            {
                // Mac/Linux uyumlu olması için standart formatta dışarı alıyoruz
                publicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
                privateKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
            }
        }

        // RSA ile Şifreleme (Karşı tarafın Public Key'i ile)
        public static string EncryptRSA(string plainText, string publicKeyBase64)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
                byte[] data = Encoding.UTF8.GetBytes(plainText);
                byte[] encrypted = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                return Convert.ToBase64String(encrypted);
            }
        }

        // RSA ile Şifre Çözme (Kendi Private Key'imiz ile)
        public static string DecryptRSA(string cipherTextBase64, string privateKeyBase64)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyBase64), out _);
                byte[] data = Convert.FromBase64String(cipherTextBase64);
                byte[] decrypted = rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
                return Encoding.UTF8.GetString(decrypted);
            }
        }

        // Veriyi İmzala (Kendi Private Key'imiz ile)
        public static string SignData(string dataToSign, string privateKeyBase64)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyBase64), out _);
                byte[] data = Encoding.UTF8.GetBytes(dataToSign);
                byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return Convert.ToBase64String(signature);
            }
        }

        // İmzayı Doğrula (Gönderenin Public Key'i ile)
        public static bool VerifyData(string originalData, string signatureBase64, string publicKeyBase64)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
                byte[] data = Encoding.UTF8.GetBytes(originalData);
                byte[] signature = Convert.FromBase64String(signatureBase64);
                return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        // --- AES İŞLEMLERİ (Simetrik) ---

        // AES için rastgele Key ve IV (Initialization Vector) üretir
        public static void GenerateAESKeys(out string key, out string iv)
        {
            using (var aes = Aes.Create())
            {
                aes.GenerateKey();
                aes.GenerateIV();
                key = Convert.ToBase64String(aes.Key);
                iv = Convert.ToBase64String(aes.IV);
            }
        }

        // AES ile Şifreleme (Session Key ile)
        public static string EncryptAES(string plainText, string keyBase64, string ivBase64)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = Convert.FromBase64String(keyBase64);
                aes.IV = Convert.FromBase64String(ivBase64);

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
                    return Convert.ToBase64String(encryptedBytes);
                }
            }
        }

        // AES ile Şifre Çözme
        public static string DecryptAES(string cipherTextBase64, string keyBase64, string ivBase64)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = Convert.FromBase64String(keyBase64);
                aes.IV = Convert.FromBase64String(ivBase64);

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    byte[] inputBytes = Convert.FromBase64String(cipherTextBase64);
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }
    }
}