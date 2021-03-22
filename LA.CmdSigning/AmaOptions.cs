namespace LA.CmdSigning {
    /// <summary>
    /// Options used for calling AMA's signing web service
    /// </summary>
    public class AmaOptions {
        /// <summary>
        /// Application Id (assigned by ama)
        /// </summary>
        public string ApplicationId { get; set; } = "";

        /// <summary>
        /// Username used for calling AMA web service 
        /// </summary>
        public string Username { get; set; } = "";

        /// <summary>
        /// Password for authenticating AMA web service
        /// </summary>
        public string Password { get; set; } = "";

        /// <summary>
        /// Web service used for calling AMA CMD service
        /// </summary>
        public string WebServiceUrl { get; set; } = "";
    }
}
