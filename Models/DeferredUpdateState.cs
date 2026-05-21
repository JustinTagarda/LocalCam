namespace LocalCam.Models {
    internal sealed class DeferredUpdateState {
        public DateTimeOffset LastCheckUtc { get; set; }
        public DateTimeOffset? LastAvailableUtc { get; set; }
        public DateTimeOffset? LastDownloadUtc { get; set; }
        public DateTimeOffset? LastInstallAttemptUtc { get; set; }
        public DateTimeOffset? LastInstallSuccessUtc { get; set; }
        public DateTimeOffset? LastFailureUtc { get; set; }
        public DateTimeOffset? LastSuccessUtc { get; set; }
        public bool InstallDeferred { get; set; }
        public int RetryCount { get; set; }
        public string? LastFailureCategory { get; set; }
        public string? PackageFamilyName { get; set; }
        public string? AvailableVersion { get; set; }
        public string? PackageIdentitySnapshot { get; set; }
    }
}
