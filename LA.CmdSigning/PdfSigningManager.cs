using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using iText.IO.Image;
using iText.Kernel.Font;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.X509;
using Path = System.IO.Path;

namespace LA.CmdSigning {
    /// <summary>
    /// Coordinates the PDF signing process
    /// </summary>
    public class PdfSigningManager {
        private const string _signatureFieldname = "Signature1";
        
        private readonly IEnumerable<ICrlClient>? _crlClients;
        private readonly IOcspClient? _ocspClient;
        private readonly ITSAClient? _tsaClient;


        private readonly IList<X509Certificate> _userCertificateChain;

        /// <summary>
        /// Creates a new instance from the user certificate chain. Calling this ctor will not add OCSP, CRL or TSA to the document
        /// </summary>
        /// <param name="userCertificateChainChain"></param>
        /// <param name="ocspClient">OSCP client used for certificate revocation lists</param>
        /// <param name="crlClients">CRL client list for certificate revocation lists</param>
        public PdfSigningManager(IEnumerable<X509Certificate> userCertificateChainChain,
                                 IOcspClient? ocspClient = null,
                                 IEnumerable<ICrlClient>? crlClients = null,
                                 ITSAClient? tsaClient = null) {
            _userCertificateChain = userCertificateChainChain.ToList();
            _ocspClient = ocspClient;
            _crlClients = crlClients;
            _tsaClient = tsaClient;
        }

        /// <summary>
        /// Method that creates an intermediary pdf and calculates the hash that must be sent to AMA for signing
        /// </summary>
        /// <param name="signingInformation">Information about the signature and its appearance</param>
        /// <returns>Information with the hashes required for signing and completing the retrieved signature injection</returns>
        public HashesForSigning CreateTemporaryPdfForSigning(SigningInformation signingInformation) {
            var pdfSigner = new PdfSigner(new PdfReader(signingInformation.PathToPdf),
                                          new FileStream(signingInformation.PathToIntermediaryPdf, FileMode.Create),
                                          new StampingProperties());
            pdfSigner.SetFieldName(_signatureFieldname);


            var appearance = pdfSigner.GetSignatureAppearance();

            appearance.SetPageRect(new Rectangle(10,
                                                 750,
                                                 150,
                                                 50))
                      .SetPageNumber(signingInformation.PageNumber)
                      .SetLayer2FontSize(6f)
                      .SetLayer2Text(BuildVisibleInformation(signingInformation.Reason, signingInformation.Location))
                      .SetCertificate(_userCertificateChain[0]);

            if (signingInformation.Logo!= null) {
                appearance.SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION)
                          .SetSignatureGraphic(signingInformation.Logo);
            }


            var crlBytesList = GetCrlByteList();

            var ocspBytesList = GetOcspBytesList();
            
            
            var container = new PrefareForAmaSigningContainer(_userCertificateChain, crlBytesList, ocspBytesList);
            pdfSigner.SignExternalContainer(container, EstimateContainerSize(crlBytesList)); // add size for timestamp in signature

            return new HashesForSigning(container.HashToBeSignedByAma, container.NakedHash);
        }

        /// <summary>
        /// Opens temporary PDF and appends signature and ocsp and crl information (if available)
        /// </summary>
        /// <param name="signatureInformation">Information required for finding the temporary PDF</param>
        public void SignIntermediatePdf(SignatureInformation signatureInformation) {
            var document = new PdfDocument(new PdfReader(signatureInformation.PathToIntermediaryPdf));
            using var writer = new FileStream(signatureInformation.pathToSignedPdf, FileMode.Create);

            
            var crlBytesList = GetCrlByteList();
            var ocspBytesList = GetOcspBytesList();


            var container = new InjectAmaSignatureContainer(signatureInformation.Signature,
                                                                    _userCertificateChain,
                                                                    signatureInformation.NakedHashFromIntermediaryPdf,
                                                                    crlBytesList,
                                                                    ocspBytesList,
                                                                    _tsaClient);
            PdfSigner.SignDeferred(document, _signatureFieldname, writer, container);
        }

        private string BuildVisibleInformation(string? reason = "null", string? location = null) {
            CertificateInfo.X500Name subjectFields = CertificateInfo.GetSubjectFields(_userCertificateChain[0]);

            var stringBuilder = new StringBuilder();
            stringBuilder.AppendLine($"Assinado por {subjectFields?.GetField("CN") ?? subjectFields?.GetField("E") ?? ""}");
            stringBuilder.AppendLine($"BI: {subjectFields?.GetField("SN") ?? ""}");
            stringBuilder.AppendLine($"Date: {DateTime.Now:yyyy.MM.dd HH:mm:ss}");
            if (!string.IsNullOrEmpty(location)) {
                stringBuilder.AppendLine($"Local: {location ?? ""}");
            }
            if (!string.IsNullOrEmpty(reason)) {
                stringBuilder.AppendLine($"Motivo: {reason ?? ""}");
            }
            
            return stringBuilder.ToString();
        }


        private IList<byte[]>? GetCrlByteList() => _crlClients == null
                                                       ? null
                                                       : _userCertificateChain.Select(x509 => GetCrlClientBytesList(x509))
                                                                              .SelectMany(crlBytes => crlBytes)
                                                                              .ToList();

        private IList<byte[]>? GetCrlClientBytesList(X509Certificate certificate) {
            if(_crlClients == null) {
                return null;
            }

            var crls = _crlClients.Select(crlClient => crlClient.GetEncoded(certificate, null))
                                  .Where(encoded => encoded != null)
                                  .SelectMany(bytes => bytes)
                                  .ToList();
            return crls;
        }

        private IList<byte[]>? GetOcspBytesList() {
            if(_userCertificateChain.Count <= 1 ||
               _ocspClient == null) {
                return null;
            }
            
            var list = new List<byte[]>();
            for(var i = 0; i < _userCertificateChain.Count - 1; i++) {
                var encoded = _ocspClient.GetEncoded(_userCertificateChain[i], _userCertificateChain[i + 1], null);
                if(encoded != null) {
                    list.Add(encoded);
                }
            }

            return list;
        }


        private int EstimateContainerSize(IEnumerable<byte[]>? crlBytesList) {
            int estimatedSize = 8192 + //initial base container size
                              ( _ocspClient != null ? 4192 : 0 ) +
                              ( _tsaClient != null  ? 4600 : 0 );
            if(crlBytesList != null) {
                estimatedSize += crlBytesList.Sum(crlBytes => crlBytes.Length + 10);
            }

            return estimatedSize;
        }

    }

    
}
