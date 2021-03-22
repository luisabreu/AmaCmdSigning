using System.ServiceModel;

namespace Ama {
    partial class SCMDServiceClient {
        public static string Url = "";

        static partial void ConfigureEndpoint(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint, System.ServiceModel.Description.ClientCredentials clientCredentials) {
            serviceEndpoint.Address = new EndpointAddress(Url);
        }
    }
}
