using LocalCam;
using LocalCam.Models;
using Xunit;

namespace LocalCam.Tests;

public sealed class SettingsMergeTests {
    [Fact]
    public void CloneSettingsPreservesAllPersistedState() {
        var source = new LocalCamSettings {
            RtspUsername = "user",
            RtspPassword = "password",
            StreamPath = "stream2",
            AutoStreamVideo = true,
            AutoDetectOnStartup = true,
            ReconnectRecentCamerasOnStartup = true,
            RecentCameraConnections = [new RecentCameraConnection {
                IpAddress = "192.168.1.20",
                LastConfirmedPlaybackUtc = DateTimeOffset.UtcNow,
                ConsecutiveReconnectFailures = 1
            }],
            ThemePreference = AppThemePreference.Dark,
            SnapshotSaveFolder = "snapshots",
            RecordingSaveFolder = "recordings",
            LastSuccessfulDetectionMethod = "OnvifWsDiscovery",
            HasVerifiedPremiumEntitlementCache = true,
            VerifiedPremiumEntitlementOwned = true,
            VerifiedPremiumEntitlementCheckedUtc = DateTimeOffset.UtcNow,
            BasicRecordingUsageDateLocal = "2026-09-22",
            BasicRecordingUsageSeconds = 123.5,
            MainWindowLeft = 10,
            MainWindowTop = 20,
            MainWindowWidth = 900,
            MainWindowHeight = 700,
            StoreUpdateCheckHistoryUtc = ["2026-09-21T00:00:00Z"],
            StoreUpdateLastKnownAvailable = true,
            StoreUpdateLastKnownPhase = "Downloading",
            StoreUpdateLastKnownProgressPercent = 42,
            StoreUpdateLastKnownDetailText = "Downloading update",
            StoreUpdateLastKnownResultText = "Update available",
            StoreUpdateExpectedSubmissionState = "InProgress",
            StoreUpdateExpectedRolloutMode = "Staged",
            StoreUpdateExpectedFlightAudience = "Internal"
        };

        var clone = SettingsWindow.CloneSettings(source);

        Assert.NotSame(source, clone);
        Assert.Equal(source.RtspUsername, clone.RtspUsername);
        Assert.Equal(source.RtspPassword, clone.RtspPassword);
        Assert.Equal(source.StreamPath, clone.StreamPath);
        Assert.Equal(source.AutoStreamVideo, clone.AutoStreamVideo);
        Assert.Equal(source.AutoDetectOnStartup, clone.AutoDetectOnStartup);
        Assert.Equal(source.ReconnectRecentCamerasOnStartup, clone.ReconnectRecentCamerasOnStartup);
        Assert.Equal(source.ThemePreference, clone.ThemePreference);
        Assert.Equal(source.SnapshotSaveFolder, clone.SnapshotSaveFolder);
        Assert.Equal(source.RecordingSaveFolder, clone.RecordingSaveFolder);
        Assert.Equal(source.LastSuccessfulDetectionMethod, clone.LastSuccessfulDetectionMethod);
        Assert.Equal(source.HasVerifiedPremiumEntitlementCache, clone.HasVerifiedPremiumEntitlementCache);
        Assert.Equal(source.VerifiedPremiumEntitlementOwned, clone.VerifiedPremiumEntitlementOwned);
        Assert.Equal(source.VerifiedPremiumEntitlementCheckedUtc, clone.VerifiedPremiumEntitlementCheckedUtc);
        Assert.Equal(source.BasicRecordingUsageDateLocal, clone.BasicRecordingUsageDateLocal);
        Assert.Equal(source.BasicRecordingUsageSeconds, clone.BasicRecordingUsageSeconds);
        Assert.Equal(source.MainWindowLeft, clone.MainWindowLeft);
        Assert.Equal(source.MainWindowTop, clone.MainWindowTop);
        Assert.Equal(source.MainWindowWidth, clone.MainWindowWidth);
        Assert.Equal(source.MainWindowHeight, clone.MainWindowHeight);
        Assert.Equal(source.StoreUpdateCheckHistoryUtc, clone.StoreUpdateCheckHistoryUtc);
        Assert.Equal(source.StoreUpdateLastKnownAvailable, clone.StoreUpdateLastKnownAvailable);
        Assert.Equal(source.StoreUpdateLastKnownPhase, clone.StoreUpdateLastKnownPhase);
        Assert.Equal(source.StoreUpdateLastKnownProgressPercent, clone.StoreUpdateLastKnownProgressPercent);
        Assert.Equal(source.StoreUpdateLastKnownDetailText, clone.StoreUpdateLastKnownDetailText);
        Assert.Equal(source.StoreUpdateLastKnownResultText, clone.StoreUpdateLastKnownResultText);
        Assert.Equal(source.StoreUpdateExpectedSubmissionState, clone.StoreUpdateExpectedSubmissionState);
        Assert.Equal(source.StoreUpdateExpectedRolloutMode, clone.StoreUpdateExpectedRolloutMode);
        Assert.Equal(source.StoreUpdateExpectedFlightAudience, clone.StoreUpdateExpectedFlightAudience);
        Assert.NotSame(source.RecentCameraConnections, clone.RecentCameraConnections);
        Assert.Equal(source.RecentCameraConnections[0].IpAddress, clone.RecentCameraConnections[0].IpAddress);
        Assert.Equal(source.RecentCameraConnections[0].ConsecutiveReconnectFailures, clone.RecentCameraConnections[0].ConsecutiveReconnectFailures);
    }

    [Fact]
    public void ApplyEditableSettingsPreservesServiceOwnedState() {
        var target = new LocalCamSettings {
            RtspUsername = "old-user",
            RtspPassword = "old-password",
            StreamPath = "old-stream",
            ReconnectRecentCamerasOnStartup = false,
            ThemePreference = AppThemePreference.Light,
            SnapshotSaveFolder = "old-snapshots",
            RecordingSaveFolder = "old-recordings",
            RecentCameraConnections = [new RecentCameraConnection {
                IpAddress = "192.168.1.20",
                LastConfirmedPlaybackUtc = DateTimeOffset.UtcNow
            }],
            LastSuccessfulDetectionMethod = "OnvifWsDiscovery",
            MainWindowLeft = 10,
            MainWindowTop = 20,
            MainWindowWidth = 900,
            MainWindowHeight = 700,
            HasVerifiedPremiumEntitlementCache = true,
            VerifiedPremiumEntitlementOwned = true,
            VerifiedPremiumEntitlementCheckedUtc = DateTimeOffset.UtcNow,
            BasicRecordingUsageDateLocal = "2026-09-22",
            BasicRecordingUsageSeconds = 123.5,
            StoreUpdateCheckHistoryUtc = ["2026-09-21T00:00:00Z"],
            StoreUpdateLastKnownAvailable = true,
            StoreUpdateLastKnownPhase = "Downloading",
            StoreUpdateLastKnownProgressPercent = 42,
            StoreUpdateLastKnownDetailText = "Downloading update",
            StoreUpdateLastKnownResultText = "Update available",
            StoreUpdateExpectedSubmissionState = "InProgress",
            StoreUpdateExpectedRolloutMode = "Staged",
            StoreUpdateExpectedFlightAudience = "Internal"
        };
        var source = new LocalCamSettings {
            RtspUsername = "new-user",
            RtspPassword = "new-password",
            StreamPath = "/new-stream/",
            ReconnectRecentCamerasOnStartup = true,
            ThemePreference = AppThemePreference.Dark,
            SnapshotSaveFolder = "new-snapshots",
            RecordingSaveFolder = "new-recordings"
        };
        var targetReference = target;

        SettingsWindow.ApplyEditableSettings(target, source);

        Assert.Same(targetReference, target);
        Assert.Equal("new-user", target.RtspUsername);
        Assert.Equal("new-password", target.RtspPassword);
        Assert.Equal("new-stream/", target.StreamPath);
        Assert.True(target.ReconnectRecentCamerasOnStartup);
        Assert.Equal(AppThemePreference.Dark, target.ThemePreference);
        Assert.Equal("new-snapshots", target.SnapshotSaveFolder);
        Assert.Equal("new-recordings", target.RecordingSaveFolder);
        Assert.Single(target.RecentCameraConnections);
        Assert.Equal("192.168.1.20", target.RecentCameraConnections[0].IpAddress);
        Assert.Equal("OnvifWsDiscovery", target.LastSuccessfulDetectionMethod);
        Assert.Equal(10, target.MainWindowLeft);
        Assert.Equal(20, target.MainWindowTop);
        Assert.Equal(900, target.MainWindowWidth);
        Assert.Equal(700, target.MainWindowHeight);
        Assert.True(target.HasVerifiedPremiumEntitlementCache);
        Assert.True(target.VerifiedPremiumEntitlementOwned);
        Assert.NotNull(target.VerifiedPremiumEntitlementCheckedUtc);
        Assert.Equal("2026-09-22", target.BasicRecordingUsageDateLocal);
        Assert.Equal(123.5, target.BasicRecordingUsageSeconds);
        Assert.Equal(["2026-09-21T00:00:00Z"], target.StoreUpdateCheckHistoryUtc);
        Assert.True(target.StoreUpdateLastKnownAvailable);
        Assert.Equal("Downloading", target.StoreUpdateLastKnownPhase);
        Assert.Equal(42, target.StoreUpdateLastKnownProgressPercent);
        Assert.Equal("Downloading update", target.StoreUpdateLastKnownDetailText);
        Assert.Equal("Update available", target.StoreUpdateLastKnownResultText);
        Assert.Equal("InProgress", target.StoreUpdateExpectedSubmissionState);
        Assert.Equal("Staged", target.StoreUpdateExpectedRolloutMode);
        Assert.Equal("Internal", target.StoreUpdateExpectedFlightAudience);
    }

    [Fact]
    public void ApplyEditableSettingsDoesNotMutateSource() {
        var target = new LocalCamSettings();
        var source = new LocalCamSettings {
            RtspUsername = "new-user",
            RtspPassword = "new-password",
            StreamPath = "/stream2"
        };

        SettingsWindow.ApplyEditableSettings(target, source);

        Assert.Equal("new-user", source.RtspUsername);
        Assert.Equal("new-password", source.RtspPassword);
        Assert.Equal("/stream2", source.StreamPath);
    }
}
