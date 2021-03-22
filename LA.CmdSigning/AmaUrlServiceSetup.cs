using System.ServiceModel;
using LA.CmdSigning;

namespace Ama {
    partial class SCMDServiceClient {
        public static AmaOptions AmaOptions = new AmaOptions();

        /// <summary>
        /// Implement partial method to specify AMA's Web Service URL
        /// </summary>
        /// <param name="serviceEndpoint">Service's endpoint</param>
        /// <param name="clientCredentials">Client credentials</param>
        static partial void ConfigureEndpoint(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint, System.ServiceModel.Description.ClientCredentials clientCredentials) {
            serviceEndpoint.Address = new EndpointAddress(AmaOptions.WebServiceUrl);
            ((BasicHttpsBinding) serviceEndpoint.Binding).Security.Transport.ClientCredentialType = HttpClientCredentialType.Basic;
            clientCredentials.UserName.UserName = AmaOptions.Username;
            clientCredentials.UserName.Password = AmaOptions.Password;
        }
    }
}
