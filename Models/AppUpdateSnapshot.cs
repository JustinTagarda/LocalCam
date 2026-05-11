namespace LocalCam.Models {
    internal sealed record AppUpdateSnapshot(
        AppUpdateState State,
        string StageText,
        string StatusMessage,
        bool IsMandatoryUpdateAvailable,
        bool IsProgressVisible,
        double ProgressValue,
        string InstalledVersion,
        string? AvailableVersion);
}
