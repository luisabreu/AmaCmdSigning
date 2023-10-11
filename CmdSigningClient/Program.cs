using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;
using iText.Commons.Bouncycastle.Cert;
using iText.IO.Image;
using iText.Signatures;
using LA.CmdSigning;

namespace CmdSigningClient {
    internal class Program {
        private static async Task Main(string[] args) {
            Console.WriteLine("CMD Signing Docs Demo...");

            AmaOptions amaOptions = LoadFromJsonFile();
            X509Certificate2 amaCert = LoadAmaCertificate();
            
            

            EncryptionHelper encryptionHelper = new(amaCert);
            AmaSigningService amaService = new(amaOptions, 
                                               encryptionHelper);

            Console.WriteLine("Please introduce your phone number: ");
            string? phoneNumber = Console.ReadLine();

            IEnumerable<IX509Certificate> userCertificatesChain = await amaService.GetUserCertificateChainAsync(phoneNumber!);

            string pdfToBeSigned = "d:\\code\\ama\\doc1.pdf";
            string temporaryPdf = "d:\\code\\ama\\doc1_int.pdf";
            string finalPdf = "d:\\code\\ama\\doc1_signed.pdf";

            // freetsa -> config information: https://www.freetsa.org/guide/demonstration-digitally-signed-PDF-documents.html
            TSAClientBouncyCastle tsaClient = new("https://freetsa.org/tsr");
            // crl list for revocation
            List<ICrlClient> crlClients = new() {new CrlClientOnline(userCertificatesChain.ToArray())};
            // added ocsp client
            OcspClientBouncyCastle ocspClient = new(null);

            PdfSigningManager pdfSigner = new(userCertificatesChain,
                                              crlClients: crlClients,
                                              ocspClient: ocspClient,
                                              tsaClient: tsaClient);
            string pathToLogo = "d:\\code\\ama\\logo.jpg";
            ImageData? logo = ImageDataFactory.CreateJpeg(new Uri(pathToLogo));
            HashesForSigning hashInformation = pdfSigner.CreateTemporaryPdfForSigning(new SigningInformation(pdfToBeSigned,
                                                                                                             temporaryPdf,
                                                                                                             Reason: "Because yes",
                                                                                                             Location: "Funchal",
                                                                                                             Logo: logo));

            Console.WriteLine("Please introduce your CMD signing pin: ");
            string cmdSigningPin = ReadSecretValueFromConsole();
            

            string processId = await amaService.StartDocSigningProcessAsync(hashInformation.HashForSigning,
                                                                            "Doc1.pdf",
                                                                            phoneNumber!,
                                                                            cmdSigningPin!);

            Console.WriteLine($"{Environment.NewLine}Please introduce the PIN you've received on your phone");
            string? otpCode = Console.ReadLine();

            byte[] signature = await amaService.ConfirmDocSigningAsync(otpCode!, processId);

            pdfSigner.SignIntermediatePdf(new SignatureInformation(temporaryPdf,
                                                                   finalPdf,
                                                                   signature,
                                                                   hashInformation.NakedHash,
                                                                   null));

            Console.WriteLine("Document signed");

            Process.Start("cmd.exe ",$"/c {finalPdf}");
        }

        private static string ReadSecretValueFromConsole( ) {
            string pass = string.Empty;
            ConsoleKey key;
            do {
                ConsoleKeyInfo keyInfo = Console.ReadKey(true);
                key = keyInfo.Key;

                if(key == ConsoleKey.Backspace && pass.Length > 0) {
                    Console.Write("\b \b");
                    pass = pass[..^1];
                }
                else if(!char.IsControl(keyInfo.KeyChar)) {
                    Console.Write("*");
                    pass += keyInfo.KeyChar;
                }
            } while(key != ConsoleKey.Enter);

            return pass;
        }

        private static AmaOptions LoadFromJsonFile() {
            JsonSerializerOptions jsonOptions = new() {
                                                          PropertyNameCaseInsensitive = true
                                                      };
            AmaOptions? loadedOptions = JsonSerializer.Deserialize<AmaOptions>(File.ReadAllText("d:\\code\\ama\\credentials.txt"),
                                                                               jsonOptions);
            return loadedOptions;
        }

        private static X509Certificate2 LoadAmaCertificate() {
            return new X509Certificate2("d:\\code\\ama\\ama_assinatura.cer");
        }
    }
}
