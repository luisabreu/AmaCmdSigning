using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using iText.Commons.Bouncycastle.Cert;
using iText.Forms.Form.Element;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;

namespace LA.CmdSigning {
    /// <summary>
    /// Coordinates the PDF signing process
    /// </summary>
    public class PdfSigningManager {
        private const string _signatureFieldname = "Signature1";
        
        private readonly IEnumerable<ICrlClient>? _crlClients;
        private readonly IOcspClient? _ocspClient;
        private readonly ITSAClient? _tsaClient;


        private readonly IList<IX509Certificate> _userCertificateChain;
        private readonly SignerHelper _sgn;
        private readonly IEnumerable<byte[]>? _crlBytesList;
        private readonly IEnumerable<byte[]>? _ocspBytesList;
        
        public PdfSigningManager(IEnumerable<IX509Certificate> userCertificateChainChain,
                                 IEnumerable<byte[]> crlBytesList,
                                 IEnumerable<byte[]> ocspBytesList,
                                 SignerHelper sgn, 
                                 IOcspClient? ocspClient = null,
                                 IEnumerable<ICrlClient>? crlClients = null,
                                 ITSAClient? tsaClient = null) {
            _userCertificateChain = userCertificateChainChain.ToList();
            _sgn = sgn;
            _ocspClient = ocspClient;
            _crlClients = crlClients;
            _tsaClient = tsaClient;
            _crlBytesList = crlBytesList;
            _ocspBytesList = ocspBytesList;
        }

        /// <summary>
        /// Method that creates a temporary pdf for calating the hash that must be sent to AMA for signing
        /// </summary>
        /// <param name="signingInformation">Information about the signature and its appearance</param>
        /// <returns>Information with the hashes required for signing and completing the retrieved signature injection</returns>
        public HashesForSigning CreateTemporaryPdfForSigning(SigningInformation signingInformation) {
            StampingProperties properties = new();
            properties.UseAppendMode();
            
            PdfSigner pdfSigner = new(new PdfReader(signingInformation.PathToPdf),
                                      new FileStream(signingInformation.PathToIntermediaryPdf, FileMode.Create),
                                      properties);
            pdfSigner.SetFieldName(_signatureFieldname);

            SignatureFieldAppearance appearance = new(pdfSigner.GetFieldName());
            if(signingInformation.Logo is null) {
                appearance.SetContent(BuildVisibleInformation(signingInformation.Reason,
                                                              signingInformation.Location));
            }
            else {
                appearance.SetContent(BuildVisibleInformation(signingInformation.Reason,
                                                              signingInformation.Location),
                                      signingInformation.Logo);
            }

            appearance.SetFontSize(6f);
            pdfSigner.SetSignatureAppearance(appearance);
            pdfSigner.SetPageNumber(signingInformation.PageNumber)
                     .SetPageRect(new Rectangle(10, 750, 150,50));
            
            

            int estimatedSize = EstimateContainerSize();
            PrepareForAmaSigningContainer container = new(_sgn,
                                                          _crlBytesList, 
                                                          _ocspBytesList);
            pdfSigner.SignExternalContainer(container, estimatedSize); // add size for timestamp in signature

            return new HashesForSigning(container.HashToBeSignedByAma, container.NakedHash);
        }

        /// <summary>
        /// Opens temporary PDF and appends signature and ocsp and crl information (if available)
        /// </summary>
        /// <param name="signatureInformation">Information required for finding the temporary PDF</param>
        public void SignIntermediatePdf(SignatureInformation signatureInformation) {
            PdfDocument document = new(new PdfReader(signatureInformation.PathToIntermediaryPdf));
            using FileStream writer = new(signatureInformation.pathToSignedPdf, FileMode.Create);

            Console.WriteLine($"pdf signing manager najed hash interm: {signatureInformation.NakedHashFromIntermediaryPdf.Length}");

            InjectAmaSignatureContainer container = new(signatureInformation.Signature,
                                                        _sgn.Signer,
                                                        signatureInformation.NakedHashFromIntermediaryPdf,
                                                        _crlBytesList,
                                                        _ocspBytesList,
                                                        _tsaClient);
            PdfSigner.SignDeferred(document, _signatureFieldname, writer, container);
        }

        private string BuildVisibleInformation(string? reason = "null", string? location = null) {
            CertificateInfo.X500Name subjectFields = CertificateInfo.GetSubjectFields(_userCertificateChain[0]);

            StringBuilder stringBuilder = new();
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

        private int EstimateContainerSize() {
            int estimatedSize = 8192 + //initial base container size
                              ( _ocspClient != null ? 4192 : 0 ) +
                              ( _tsaClient != null  ? 4600 : 0 );
            if(_crlBytesList != null) {
                estimatedSize += _crlBytesList.Sum(crlBytes => crlBytes.Length + 10);
            }

            if(_ocspBytesList != null) {
                estimatedSize += _ocspBytesList.Sum(c => c.Length + 10);
            }

            return estimatedSize;
        }

    }

    
}
