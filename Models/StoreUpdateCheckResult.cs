namespace LocalCam.Models {
    internal sealed record StoreUpdateCheckResult(
        StoreUpdateCheckState State,
        string StatusMessage,
        string? AvailableVersion);
}
