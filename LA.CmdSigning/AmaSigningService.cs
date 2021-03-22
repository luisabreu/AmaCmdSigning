using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using Ama;
using Org.BouncyCastle.X509;
using static System.GC;

namespace LA.CmdSigning {
    public class AmaSigningService : IAsyncDisposable {
        private readonly byte[] _applicationId;
        private readonly SCMDServiceClient _client;
        private readonly EncryptionHelper _encryptionHelper;

        /// <summary>
        /// Creates a new instance of the service
        /// </summary>
        /// <param name="options">Options used for calling the web service</param>
        /// <param name="encryptionHelper">Helper for encpryting/decrypting</param>
        public AmaSigningService(AmaOptions options, 
                                 EncryptionHelper encryptionHelper) {
            if (options == null) {
                throw new ArgumentNullException();
            }

            Ama.SCMDServiceClient.AmaOptions = options;

            _client = new SCMDServiceClient();
            _encryptionHelper = encryptionHelper;
            _applicationId = Encoding.UTF8.GetBytes(options.ApplicationId);
        }

        public async ValueTask DisposeAsync() {
            await _client.CloseAsync();

            SuppressFinalize(this);
        }

        /// <summary>
        /// Get user certificate chain for signing 
        /// </summary>
        /// <param name="userId">User's phone number (+351 XXXXXXXXX)</param>
        /// <returns>List of certificates (ordered from user to root)</returns>
        public async Task<IEnumerable<X509Certificate>> GetUserCertificateChainAsync(string userId) {
            var encryptedUserId = EncryptAndConvertToBase64(AdaptUserId(userId));
            var certificateChainInText = await _client.GetCertificateAsync(_applicationId, encryptedUserId);
            if (certificateChainInText == null) {
                throw new InvalidOperationException("Couldn't retrieve certificate");
            }

            var certificates = EncryptionHelper.ParseStringIntoCertificateChain(certificateChainInText);
            return (IEnumerable<X509Certificate>) certificates;
        }

        /// <summary>
        /// Start remote signing process
        /// </summary>
        /// <param name="documentHash">Hash of the document that should be signed</param>
        /// <param name="documentName">Name of the document that is going to be signed</param>
        /// <param name="userId">User's phone number</param>
        /// <param name="cmdSignPin">User's PIN for signing the doc (tipically, it's the same as the one used for CMD)</param>
        /// <returns>The internal process ID that should be used for getting the </returns>
        public async Task<string> StartDocSigningProcessAsync(byte[] documentHash,
                                                              string documentName,
                                                              string userId,
                                                              string cmdSignPin) {
            var requestInfo = new SignRequest {
                                                  ApplicationId = _applicationId,
                                                  DocName = documentName,
                                                  Hash = documentHash,
                                                  Pin = EncryptAndConvertToBase64(cmdSignPin),
                                                  UserId = EncryptAndConvertToBase64(AdaptUserId(userId))
                                              };
            var status = await _client.SCMDSignAsync(requestInfo);
            if (!string.Equals(status.Code, "200")) {
                throw new InvalidOperationException($"The doc signing couldn't start: {status.Message}");
            }

            return status.ProcessId;
        }

        /// <summary>
        /// Confirms the signing of a document and retrieves its signatures
        /// </summary>
        /// <param name="otpCode">Validation code received on the user's phone</param>
        /// <param name="processId">ID that identifies the document that was signed before</param>
        /// <returns></returns>
        public async Task<byte[]> ConfirmDocSigningAsync(string otpCode, string processId) {
            var code = EncryptAndConvertToBase64(otpCode);

            var status = await _client.ValidateOtpAsync(code,
                                                        processId,
                                                        _applicationId);
            if (!string.Equals(status.Status.Code, "200")) {
                throw new InvalidOperationException($"The doc signing couldn't be concluded: {status.Status.Message}");
            }

            return status.Signature;
        }

        private string EncryptAndConvertToBase64(string value) => Convert.ToBase64String(_encryptionHelper.EncryptString(value));

        private static string AdaptUserId(string userId) => userId.StartsWith("+351 ")
                                                                ? userId
                                                                : $"+351 {userId}";
    }
}
