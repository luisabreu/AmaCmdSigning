using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using iText.Bouncycastleconnector;
using iText.Commons.Bouncycastle;
using iText.Commons.Bouncycastle.Cert;
using iText.Commons.Bouncycastle.Openssl;


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
            using RSA? rsa = _certificate.GetRSAPublicKey();
            rsa!.ExportParameters(false);

            return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
        }

        private byte[] DecryptRsa(byte[] data) {
            using RSA? rsa = _certificate.GetRSAPublicKey();
            rsa!.ExportParameters(false);
            return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
        }

        /// <summary>
        /// RSA encrypts the passed string
        /// </summary>
        /// <param name="text">String to be encrypted</param>
        /// <returns>An array with the encrypted string</returns>
        public byte[] EncryptString(string text) {
            byte[] textBytes = Encoding.ASCII.GetBytes(text);
            return EncryptRsa(textBytes);
        }

        /// <summary>
        /// RSA decrypts the received byte array
        /// </summary>
        /// <param name="data">Array to be decrypted</param>
        /// <returns>Decrypted string</returns>
        public string DecryptString(byte[] data) {
            byte[] dataDec = DecryptRsa(data);
            return Encoding.UTF8.GetString(dataDec);
        }

        /// <summary>
        /// Parses the string into a certificate chain (simple list)
        /// </summary>
        /// <param name="certificate">string with the certificate to be parser</param>
        /// <returns>A readonly list of <see cref="System.Security.Cryptography.X509Certificates.X509Certificate"/></returns>
        public static IReadOnlyList<IX509Certificate> ParseStringIntoCertificateChain(string certificate) {
            List<IX509Certificate> certificates = new( );
            IBouncyCastleFactory factory = BouncyCastleFactoryCreator.GetFactory( );

            using TextReader reader = new StringReader(certificate);
            IPemReader parser = factory.CreatePEMParser(reader, null);
            object? cert = null;
            while( ( cert = parser.ReadObject( ) ) is not null ) {
                if( cert is not IX509Certificate parsedCertificate ) {
                    continue;
                }
                certificates.Add(parsedCertificate);
            }

            return certificates.AsReadOnly(  );
            
            
        }
    }
}
