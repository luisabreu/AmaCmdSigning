using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace LA.CmdSigning {
    /// <summary>
    /// Helper service for performing encryption related operations
    /// </summary>
    public class EncryptionHelper {
        private readonly X509Certificate2 _certificate;

        /// <summary>
        /// Creates a new instance of the encryption helper from a valid X509Certificate2
        /// </summary>
        /// <param name="certificate">Valid certificate used for encryption</param>
        public EncryptionHelper(X509Certificate2 certificate) {
            _certificate = certificate;
        }

        /// <summary>
        /// Creates a new instance of thr encryption helper from an existing X509Certificate2 file
        /// </summary>
        /// <param name="pathToCertificate"></param>
        public EncryptionHelper(string pathToCertificate) : this(new X509Certificate2(pathToCertificate)) {
        }

        private byte[] EncryptRsa(byte[] data) {
            using var rsa = _certificate.GetRSAPublicKey();
            rsa!.ExportParameters(false);

            return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
        }

        private byte[] DecryptRsa(byte[] data) {
            using var rsa = _certificate.GetRSAPublicKey();
            rsa!.ExportParameters(false);
            return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
        }

        /// <summary>
        /// RSA encrypts the passed string
        /// </summary>
        /// <param name="text">String to be encrypted</param>
        /// <returns>An array with the encrypted string</returns>
        public byte[] EncryptString(string text) {
            var textBytes = Encoding.ASCII.GetBytes(text);
            return EncryptRsa(textBytes);
        }

        /// <summary>
        /// RSA decrypts the received byte array
        /// </summary>
        /// <param name="data">Array to be decrypted</param>
        /// <returns>Decrypted string</returns>
        public string DecryptString(byte[] data) {
            var dataDec = DecryptRsa(data);
            return Encoding.UTF8.GetString(dataDec);
        }

        /// <summary>
        /// Parses the string into a certificate chain (simple list)
        /// </summary>
        /// <param name="certificate">string with the certificate to be parser</param>
        /// <returns>A readonly list of <see cref="System.Security.Cryptography.X509Certificates.X509Certificate"/></returns>
        public static IReadOnlyList<X509Certificate> ParseStringIntoCertificateChain(string certificate) {
            var bytes = Encoding.ASCII.GetBytes(certificate);
            var certs = new X509CertificateParser().ReadCertificates(bytes)
                                                   .Cast<X509Certificate>()
                                                   .ToList();
            return certs;
        }
    }
}
