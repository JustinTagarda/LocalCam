namespace LocalCam.Models {
    public sealed class LocalCamSettings {
        public string RtspUsername { get; set; } = string.Empty;
        public string RtspPassword { get; set; } = string.Empty;
        public string StreamPath { get; set; } = "stream1";
        public bool AutoStreamVideo { get; set; } = true;
        public bool AutoDetectOnStartup { get; set; } = true;
        public string? SnapshotSaveFolder { get; set; }
        public string? RecordingSaveFolder { get; set; }
        public string? LastSuccessfulDetectionMethod { get; set; }
        public bool HasVerifiedPremiumEntitlementCache { get; set; }
        public bool VerifiedPremiumEntitlementOwned { get; set; }
        public DateTimeOffset? VerifiedPremiumEntitlementCheckedUtc { get; set; }
        public string? BasicRecordingUsageDateLocal { get; set; }
        public double BasicRecordingUsageSeconds { get; set; }
        public double? MainWindowLeft { get; set; }
        public double? MainWindowTop { get; set; }
        public double? MainWindowWidth { get; set; }
        public double? MainWindowHeight { get; set; }
        public List<string> StoreUpdateCheckHistoryUtc { get; set; } = new();
        public bool StoreUpdateLastKnownAvailable { get; set; }
        public string? StoreUpdateLastKnownPhase { get; set; }
        public int StoreUpdateLastKnownProgressPercent { get; set; }
        public string? StoreUpdateLastKnownDetailText { get; set; }
        public string? StoreUpdateLastKnownResultText { get; set; }
        public string? StoreUpdateExpectedSubmissionState { get; set; }
        public string? StoreUpdateExpectedRolloutMode { get; set; }
        public string? StoreUpdateExpectedFlightAudience { get; set; }
    }
}
