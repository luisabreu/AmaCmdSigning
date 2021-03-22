using System.Collections.Generic;
using System.IO;
using System.Linq;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.X509;

namespace LA.CmdSigning {
    /// <summary>
    /// Container for injecting AMA's calculated signature (and clr and ocsp information if required)
    /// </summary>
    public class InjectAmaSignatureContainer : IExternalSignatureContainer {
        private readonly IEnumerable<X509Certificate> _certificates;
        private readonly IEnumerable<byte[]>? _crlBytesCollection;
        private readonly byte[] _documentHash;
        private readonly IEnumerable<byte[]>? _ocspBytes;
        private readonly byte[] _signature;
        private readonly ITSAClient? _tsaClient;

        /// <summary>
        /// Creates a new instance of the external container
        /// </summary>
        /// <param name="signature">Byte array with AMA's generated signature for specified doc</param>
        /// <param name="certificates">User's certificate chain</param>
        /// <param name="documentHash">Naked document hash used during preparation phase</param>
        /// <param name="crlBytesCollection">CRL information that should be embedded</param>
        /// <param name="ocspBytes">OCSP information that should be embedded</param>
        /// <param name="tsaClient">TSA client that should be used for timestamping the document</param>
        public InjectAmaSignatureContainer(byte[] signature,
                                                   IEnumerable<X509Certificate> certificates,
                                                   byte[] documentHash,
                                                   IEnumerable<byte[]>? crlBytesCollection,
                                                   IEnumerable<byte[]>? ocspBytes,
                                                   ITSAClient? tsaClient = null) {
            _signature = signature;
            _certificates = certificates;
            _documentHash = documentHash;
            _crlBytesCollection = crlBytesCollection;
            _ocspBytes = ocspBytes;
            _tsaClient = tsaClient;
        }

        /// <summary>
        /// Append signature and optional data to the temporary PDF document
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public byte[] Sign(Stream data) {
            /*var sgn = new PdfPKCS7(null, _certificates.ToArray(),DigestAlgorithms.SHA256, false);
             sgn.SetExternalDigest(_signature, null, "RSA");
             return sgn.GetEncodedPKCS7();*/

            var sgn = new PdfPKCS7(null,
                                   _certificates.ToArray(),
                                   DigestAlgorithms.SHA256,
                                   false);
            // set the signature bytes
            sgn.SetExternalDigest(_signature,
                                  null,
                                  "RSA");
            // call GetEncoded with the same parameters as the original GetAuthenticatedAtt...
            var encodedSig = sgn.GetEncodedPKCS7(_documentHash,
                                                 PdfSigner.CryptoStandard.CMS,
                                                 _tsaClient,
                                                 _ocspBytes?.ToList(),
                                                 _crlBytesCollection?.ToList());

            return encodedSig;
        }

        public void ModifySigningDictionary(PdfDictionary signDic) {
        }
    }
}
