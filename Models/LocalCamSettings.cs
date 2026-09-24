using System.Text.Json.Serialization;

namespace LocalCam.Models {
    public sealed class RecentCameraConnection {
        public string IpAddress { get; set; } = string.Empty;
        public string? MacAddress { get; set; }
        public string? HostName { get; set; }
        public string? DetectionMethod { get; set; }
        public DateTimeOffset LastConfirmedPlaybackUtc { get; set; }
        public int ConsecutiveReconnectFailures { get; set; }
    }

    public enum AppThemePreference {
        System,
        Light,
        Dark
    }

    public sealed class LocalCamSettings {
        public string RtspUsername { get; set; } = string.Empty;
        public string RtspPassword { get; set; } = string.Empty;
        public string StreamPath { get; set; } = "stream1";
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public bool AutoStreamVideo { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public bool AutoDetectOnStartup { get; set; }
        public bool? ReconnectRecentCamerasOnStartup { get; set; }
        public List<RecentCameraConnection> RecentCameraConnections { get; set; } = new();
        public AppThemePreference ThemePreference { get; set; } = AppThemePreference.System;
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
    }
}
