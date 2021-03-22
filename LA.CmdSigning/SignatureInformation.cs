using iText.Signatures;

namespace LA.CmdSigning {
    /// <summary>
    /// Helper for passing information for injecting signature on the document
    /// </summary>
    public record SignatureInformation(string PathToIntermediaryPdf,
                                       string pathToSignedPdf,
                                       byte[] Signature,
                                       byte[] NakedHashFromIntermediaryPdf,
                                       ITSAClient? tsaClient = null);
}
