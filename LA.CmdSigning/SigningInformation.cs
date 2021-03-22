using iText.IO.Image;

namespace LA.CmdSigning {
    /// <summary>
    /// Helper class for passing the required signing information
    /// </summary>
    public record SigningInformation(string PathToPdf, string PathToIntermediaryPdf, int PageNumber = 1, string Reason = "", string Location = "", ImageData? Logo = null);

}
