using System;

namespace Guvenlik.Common
{
    // PDF Sayfa 2'deki tabloya uygun Sertifika Sınıfı
    public class Certificate
    {
        public string SubjectID { get; set; } // Sertifika sahibi (Örn: Client1)
        public string AlgorithmID { get; set; } // Örn: RSA-2048
        public string PublicKey { get; set; } // Base64 formatında Public Key
        public DateTime ValidFrom { get; set; } // Başlangıç tarihi
        public DateTime ValidTo { get; set; } // Bitiş tarihi
        public string IssuerID { get; set; } // İmzalayan (CA)
        public string Signature { get; set; } // CA'nın imzası
    }
}