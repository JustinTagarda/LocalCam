namespace LocalCam.Models {
    internal sealed record AppUpdateSnapshot(
        AppUpdateState State,
        string StageText,
        string StatusMessage,
        bool IsMandatoryUpdateAvailable,
        bool IsProgressVisible,
        double ProgressValue,
        bool IsRestartRequired,
        string InstalledVersion,
        string? AvailableVersion);
}
