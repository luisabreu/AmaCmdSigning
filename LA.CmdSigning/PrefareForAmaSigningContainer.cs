using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using iText.Kernel.Pdf;
using iText.Signatures;

namespace LA.CmdSigning {
    /// <summary>
    /// Container responsible for preparing hash to be sent for AMA signing
    /// </summary>
public class PrepareForAmaSigningContainer : ExternalBlankSignatureContainer {
    private static readonly byte[] _sha256SigPrefix = {
                                                          0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
                                                          0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                                                          0x05, 0x00, 0x04, 0x20
                                                      };

    private readonly IEnumerable<byte[]>? _crlBytesCollection;
    private readonly IEnumerable<byte[]>? _ocspBytes;
    private readonly SignerHelper _sgn;

    /// <summary>
    /// Creates a new instance of the container
    /// </summary>
    /// <param name="certificates">User certficate chain</param>
    /// <param name="crlBytesCollection">Collection of CRL bytes for revocation check</param>
    /// <param name="ocspBytes">Collection od OCSP bytes for revocation</param>
    public PrepareForAmaSigningContainer(SignerHelper sgn,
                                         IEnumerable<byte[]>? crlBytesCollection,
                                         IEnumerable<byte[]>? ocspBytes) : base(PdfName.Adobe_PPKLite, PdfName.Adbe_pkcs7_detached) {
        _crlBytesCollection = crlBytesCollection;
        _ocspBytes = ocspBytes;
        _sgn = sgn;
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
        
        // get hash for document bytes
        NakedHash = DigestAlgorithms.Digest(data, DigestAlgorithms.SHA256);

        // get attributes
        byte[]? docBytes = _sgn.Signer.GetAuthenticatedAttributeBytes(NakedHash,
                                                                      PdfSigner.CryptoStandard.CMS,
                                                                      _ocspBytes?.ToList( ),
                                                                      _crlBytesCollection?.ToList( ));
        // hash it again
        using MemoryStream hashMemoryStream = new(docBytes, false);
        hashMemoryStream.Seek(0, SeekOrigin.Begin);
        byte[]? docBytesHash = DigestAlgorithms.Digest(hashMemoryStream, DigestAlgorithms.SHA256);


        //prepend sha256 prefix
        byte[] totalHash = new byte[_sha256SigPrefix.Length + docBytesHash.Length];
        _sha256SigPrefix.CopyTo(totalHash, 0);
        docBytesHash.CopyTo(totalHash, _sha256SigPrefix.Length);
        HashToBeSignedByAma = totalHash;

        return Array.Empty<byte>();
    }
}

}
