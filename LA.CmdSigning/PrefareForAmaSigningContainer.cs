using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.X509;

namespace LA.CmdSigning {
    /// <summary>
    /// Container responsible for preparing hash to be sent for AMA signing
    /// </summary>
    public class PrefareForAmaSigningContainer : ExternalBlankSignatureContainer {
        private static readonly byte[] _sha256SigPrefix = {
                                                              0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
                                                              0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                                                              0x05, 0x00, 0x04, 0x20
                                                          };


        private readonly IEnumerable<X509Certificate> _certificates;
        private readonly IEnumerable<byte[]>? _crlBytesCollection;
        private readonly IEnumerable<byte[]>? _ocspBytes;

        /// <summary>
        /// Creates a new instance of the container
        /// </summary>
        /// <param name="certificates">User certficate chain</param>
        /// <param name="crlBytesCollection">Collection of CRL bytes for revocation check</param>
        /// <param name="ocspBytes">Collection od OCSP bytes for revocation</param>
        public PrefareForAmaSigningContainer(IEnumerable<X509Certificate> certificates,
                                   IEnumerable<byte[]>? crlBytesCollection,
                                   IEnumerable<byte[]>? ocspBytes) : base(PdfName.Adobe_PPKLite, PdfName.Adbe_pkcs7_detached) {
            _certificates = certificates;
            _crlBytesCollection = crlBytesCollection;
            _ocspBytes = ocspBytes;
        }

        /// <summary>
        /// Returns the hash that must be send for signing
        /// </summary>
        public byte[] HashToBeSignedByAma { get; private set; } = new byte[0];

        /// <summary>
        /// Original naked hash of the document (used for injecting the signature when it's retrieved from AMA)
        /// </summary>
        public byte[] NakedHash { get; private set; } = new byte[0];

        /// <summary>
        /// Method that will be called during the signing process
        /// </summary>
        /// <param name="data">Stream with the doc data that should be used in the hasing process</param>
        /// <returns></returns>
        public override byte[] Sign(Stream data) {
            // crea pdf pkcs7 for signing the document
            var sgn = new PdfPKCS7(null,
                                   _certificates.ToArray(),
                                   DigestAlgorithms.SHA256,
                                   false);
            // get hash for document bytes
            NakedHash = DigestAlgorithms.Digest(data, DigestAlgorithms.SHA256);

            // get attributes
            var docBytes = sgn.GetAuthenticatedAttributeBytes(NakedHash,
                                                              PdfSigner.CryptoStandard.CMS,
                                                              _ocspBytes?.ToList(),
                                                              _crlBytesCollection?.ToList());
            // hash it again
            using var hashMemoryStream = new MemoryStream(docBytes, false);
            var docBytesHash = DigestAlgorithms.Digest(hashMemoryStream, DigestAlgorithms.SHA256);


            //prepend sha256 prefix
            var totalHash = new byte[_sha256SigPrefix.Length + docBytesHash.Length];
            _sha256SigPrefix.CopyTo(totalHash, 0);
            docBytesHash.CopyTo(totalHash, _sha256SigPrefix.Length);
            HashToBeSignedByAma = totalHash;
            return Array.Empty<byte>();
        }
    }

}


