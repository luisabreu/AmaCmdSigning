namespace LA.CmdSigning {
    /// <summary>
    /// Helper class for saving hashes used for completing the signing of the temporary PDF
    /// </summary>
    public record HashesForSigning(byte[] HashForSigning, byte[] NakedHash);
    
    
}
