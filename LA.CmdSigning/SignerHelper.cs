using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using iText.Commons.Bouncycastle.Cert;
using iText.Signatures;

namespace LA.CmdSigning;

/// <summary>
/// Helper class for initializing objects that can be shared during the process
/// </summary>
public sealed class SignerHelper {
    
    private const string _signaturePolicyUri = "https://www.autenticacao.gov.pt/documents/20126/0/POL%2316.PolAssQual_signed_signed.pdf";
    
    private readonly PdfPKCS7 _sgn;
    private readonly IList<byte[]>? _crlBytesList;
    private readonly IList<byte[]>? _ocspBytesList;
    
    private readonly IEnumerable<ICrlClient>? _crlClients;
    private readonly IOcspClient? _ocspClient;

    /// <summary>
    /// Constructor that initializes the type
    /// </summary>
    /// <param name="userCertificateChain">Certificates that allow us to build the chain</param>
    /// <param name="crlClients"><see cref="ICrlClient"/> list</param>
    /// <param name="ocspClient"><see cref="IOcspClient"/> object</param>
    public SignerHelper(IEnumerable<IX509Certificate> userCertificateChain,
                        IEnumerable<ICrlClient>? crlClients,
                        IOcspClient? ocspClient) {
        _sgn = new(null,
                   userCertificateChain.ToArray( ),
                   DigestAlgorithms.SHA256,
                   false);
            
        // set signature policy information
        MemoryStream policyIdByteMs = new(Encoding.ASCII.GetBytes("2.16.620.2.1.2.2"), false);
        byte[]? policyIdByte = DigestAlgorithms.Digest(policyIdByteMs, DigestAlgorithms.SHA256);
        SignaturePolicyInfo spi = new("2.16.620.2.1.2.2", policyIdByte, DigestAlgorithms.SHA256, _signaturePolicyUri);
        _sgn.SetSignaturePolicy(spi);

        _crlClients = crlClients;
        _ocspClient = ocspClient;

        IX509Certificate[] certificateChain = userCertificateChain.ToArray();
        
        _crlBytesList = GetCrlByteList(certificateChain);
        _ocspBytesList = GetOcspBytesList(certificateChain);
    }

    public PdfPKCS7 Signer => _sgn;

    public IEnumerable<byte[]> CrlBytesList => _crlBytesList;
    
    public IEnumerable<byte[]> OcspBytesList => _ocspBytesList;
    
    private IList<byte[]>? GetCrlByteList(IX509Certificate[] userCertificateChain) => _crlClients == null
                                                                                          ? null
                                                                                          : userCertificateChain.Select(x509 => GetCrlClientBytesList(x509))
                                                                                                                .SelectMany(crlBytes => crlBytes)
                                                                                                                .ToList();

    private IList<byte[]>? GetCrlClientBytesList(IX509Certificate certificate) {
        List<byte[]>? crls = _crlClients?.Select(crlClient => crlClient.GetEncoded(certificate, null))
                                        .Where(encoded => encoded != null)
                                        .SelectMany(bytes => bytes)
                                        .ToList();
        return crls;
    }

    private IList<byte[]>? GetOcspBytesList(IX509Certificate[] userCertificateChain) {
        if(userCertificateChain.Length <= 1 || _ocspClient is null) {
            return null;
        }

        IX509Certificate userCert = userCertificateChain[0];
        IX509Certificate root = userCertificateChain[1];
        IX509Certificate intermediate = userCertificateChain[2];

        List<byte[]> list = new();
        byte[]? encoded = _ocspClient.GetEncoded(userCert, intermediate, null);
        if(encoded != null) {
            list.Add(encoded);
        }

        encoded = _ocspClient.GetEncoded(intermediate, root, null);
        if(encoded != null) {
            list.Add(encoded);
        }

        return list;
    }
}
