using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;
using Ama;
using iText.IO.Image;
using iText.Signatures;
using LA.CmdSigning;

namespace CmdSigningClient {
    internal class Program {
        private static async Task Main(string[] args) {
            Console.WriteLine("CMD Signing Docs Demo...");

            var amaOptions = LoadFromJsonFile();
            var amaCert = LoadAmaCertificate();
            
            

            var encryptionHelper = new EncryptionHelper(amaCert);
            var amaService = new AmaSigningService(amaOptions, 
                                                   encryptionHelper);

            Console.WriteLine("Please introduce your phone number: ");
            var phoneNumber = Console.ReadLine();

            var userCertificatesChain = await amaService.GetUserCertificateChainAsync(phoneNumber!);

            var pdfToBeSigned = "d:\\code\\ama\\doc1.pdf";
            var temporaryPdf = "d:\\code\\ama\\doc1_int.pdf";
            var finalPdf = "d:\\code\\ama\\doc1_signed.pdf";

            // freetsa -> config information: https://www.freetsa.org/guide/demonstration-digitally-signed-PDF-documents.html
            var tsaClient = new TSAClientBouncyCastle("https://freetsa.org/tsr");
            // crl list for revocation
            var crlClients = new List<ICrlClient> {new CrlClientOnline(userCertificatesChain.ToArray())};
            // added ocsp client
            var ocspClient = new OcspClientBouncyCastle(null);

            var pdfSigner = new PdfSigningManager(userCertificatesChain,
                                                  crlClients: crlClients,
                                                  ocspClient: ocspClient,
                                                  tsaClient: tsaClient);
            var pathToLogo = "d:\\code\\ama\\logo.jpg";
            var logo = ImageDataFactory.CreateJpeg(new Uri(pathToLogo));
            var hashInformation = pdfSigner.CreateTemporaryPdfForSigning(new SigningInformation(pdfToBeSigned,
                                                                                                   temporaryPdf,
                                                                                                   Reason: "Because yes",
                                                                                                   Location: "Funchal",
                                                                                                   Logo: logo));

            Console.WriteLine("Please introduce your CMD signing pin: ");
            var cmdSigningPin = ReadSecretValueFromConsole();
            

            var processId = await amaService.StartDocSigningProcessAsync(hashInformation.HashForSigning,
                                                                         "Doc1.pdf",
                                                                         phoneNumber!,
                                                                         cmdSigningPin!);

            Console.WriteLine($"{Environment.NewLine}Please introduce the PIN you've received on your phone");
            var otpCode = Console.ReadLine();

            var signature = await amaService.ConfirmDocSigningAsync(otpCode!, processId);

            pdfSigner.SignIntermediatePdf(new SignatureInformation(temporaryPdf,
                                                                   finalPdf,
                                                                   signature,
                                                                   hashInformation.NakedHash,
                                                                   null));

            Console.WriteLine("Document signed");

            Process.Start("cmd.exe ",$"/c {finalPdf}");
        }

        private static string ReadSecretValueFromConsole( ) {
            var pass = string.Empty;
            ConsoleKey key;
            do {
                var keyInfo = Console.ReadKey(true);
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
            var jsonOptions = new JsonSerializerOptions {
                                                        PropertyNameCaseInsensitive = true
                                                    };
            var loadedOptions = JsonSerializer.Deserialize<AmaOptions>(File.ReadAllText("d:\\code\\ama\\credentials.txt"),
                                                                           jsonOptions);
            return loadedOptions;
        }

        private static X509Certificate2 LoadAmaCertificate() {
            return new X509Certificate2("d:\\code\\ama\\ama_assinatura.cer");
        }
    }
}
