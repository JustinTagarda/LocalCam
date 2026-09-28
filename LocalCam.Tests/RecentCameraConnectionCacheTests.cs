using System.Net;
using LocalCam.Models;
using LocalCam.Networking;
using LocalCam.Services;
using Xunit;

namespace LocalCam.Tests;

public sealed class RecentCameraConnectionCacheTests {
    [Fact]
    public void PruneExpired_RemovesOnlyEntriesOlderThanSevenDays() {
        var now = DateTimeOffset.UtcNow;
        var settings = new LocalCamSettings {
            RecentCameraConnections = [
                Entry("192.168.1.10", now - TimeSpan.FromDays(7)),
                Entry("192.168.1.11", now - TimeSpan.FromDays(7) - TimeSpan.FromTicks(1))
            ]
        };

        RecentCameraConnectionCache.PruneExpired(settings, now);

        Assert.Single(settings.RecentCameraConnections);
        Assert.Equal("192.168.1.10", settings.RecentCameraConnections[0].IpAddress);
    }

    [Fact]
    public void RegisterReconnectFailure_EvictsAfterSecondConsecutiveFailure() {
        var settings = new LocalCamSettings { RecentCameraConnections = [Entry("192.168.1.10", DateTimeOffset.UtcNow)] };
        var detection = Detection("192.168.1.10");

        Assert.False(RecentCameraConnectionCache.RegisterReconnectFailure(settings, detection));
        Assert.Single(settings.RecentCameraConnections);
        Assert.True(RecentCameraConnectionCache.RegisterReconnectFailure(settings, detection));
        Assert.Empty(settings.RecentCameraConnections);
    }

    [Fact]
    public void ConfirmPlayback_RefreshesEntryAndResetsFailures() {
        var settings = new LocalCamSettings { RecentCameraConnections = [Entry("192.168.1.10", DateTimeOffset.UtcNow, failures: 1)] };
        var now = DateTimeOffset.UtcNow;

        RecentCameraConnectionCache.ConfirmPlayback(settings, Detection("192.168.1.10"), now);

        Assert.Equal(0, settings.RecentCameraConnections[0].ConsecutiveReconnectFailures);
        Assert.Equal(now, settings.RecentCameraConnections[0].LastConfirmedPlaybackUtc);
    }

    [Fact]
    public void InvalidateAll_ClearsEveryEntryWithoutAnEntryCap() {
        var settings = new LocalCamSettings { RecentCameraConnections = Enumerable.Range(1, 64).Select(i => Entry($"192.168.1.{i}", DateTimeOffset.UtcNow)).ToList() };
        RecentCameraConnectionCache.InvalidateAll(settings);
        Assert.Empty(settings.RecentCameraConnections);
    }

    [Fact]
    public void GetValidDetections_PrunesMalformedEntriesBeforeReturningCachedCameras() {
        var settings = new LocalCamSettings {
            RecentCameraConnections = [
                Entry("not-an-ip", DateTimeOffset.UtcNow),
                new RecentCameraConnection {
                    IpAddress = "192.168.1.10",
                    RtspPort = 8554,
                    LastConfirmedPlaybackUtc = DateTimeOffset.UtcNow
                }
            ]
        };

        var detections = RecentCameraConnectionCache.GetValidDetections(settings, DateTimeOffset.UtcNow);

        var detection = Assert.Single(detections);
        Assert.Equal("192.168.1.10", detection.IpAddress.ToString());
        Assert.Equal(8554, detection.RtspPort);
        Assert.Single(settings.RecentCameraConnections);
    }

    [Fact]
    public void ConfirmPlayback_UsesMacAddressBeforeIpAddressWhenReconcilingAnEntry() {
        var settings = new LocalCamSettings {
            RecentCameraConnections = [new RecentCameraConnection {
                IpAddress = "192.168.1.10",
                RtspPort = 8554,
                MacAddress = "AA:BB:CC:DD:EE:FF",
                LastConfirmedPlaybackUtc = DateTimeOffset.UtcNow
            }]
        };

        var detection = new TapoCameraDetection(
            IPAddress.Parse("192.168.1.25"), null, "AA:BB:CC:DD:EE:FF", Array.Empty<int>(), 0, "test");
        RecentCameraConnectionCache.ConfirmPlayback(
            settings,
            detection,
            DateTimeOffset.UtcNow,
            [detection]);

        var entry = Assert.Single(settings.RecentCameraConnections);
        Assert.Equal("192.168.1.25", entry.IpAddress);
        Assert.Equal(554, entry.RtspPort);
    }

    [Fact]
    public void ConfirmPlayback_KeepsEntriesSeparateWhenCurrentDetectionsShareMac() {
        var settings = new LocalCamSettings {
            RecentCameraConnections = [new RecentCameraConnection {
                IpAddress = "192.168.1.10",
                RtspPort = 8554,
                MacAddress = "AA:BB:CC:DD:EE:FF",
                LastConfirmedPlaybackUtc = DateTimeOffset.UtcNow
            }]
        };
        var detections = new[] {
            Detection("192.168.1.10", "AA:BB:CC:DD:EE:FF"),
            Detection("192.168.1.11", "aa:bb:cc:dd:ee:ff")
        };

        RecentCameraConnectionCache.ConfirmPlayback(settings, detections[1], DateTimeOffset.UtcNow, detections);

        Assert.Equal(2, settings.RecentCameraConnections.Count);
        Assert.Equal("192.168.1.10", settings.RecentCameraConnections[0].IpAddress);
        Assert.Equal("192.168.1.11", settings.RecentCameraConnections[1].IpAddress);
    }

    [Fact]
    public void RegisterReconnectFailure_AmbiguousMacOnlyAffectsMatchingAddress() {
        var settings = new LocalCamSettings {
            RecentCameraConnections = [
                Entry("192.168.1.10", DateTimeOffset.UtcNow),
                Entry("192.168.1.11", DateTimeOffset.UtcNow)
            ]
        };
        settings.RecentCameraConnections[0].MacAddress = "AA:BB:CC:DD:EE:FF";
        settings.RecentCameraConnections[1].MacAddress = "AA:BB:CC:DD:EE:FF";
        var detection = Detection("192.168.1.11", "AA:BB:CC:DD:EE:FF");

        Assert.False(RecentCameraConnectionCache.RegisterReconnectFailure(settings, detection));

        Assert.Equal(0, settings.RecentCameraConnections[0].ConsecutiveReconnectFailures);
        Assert.Equal(1, settings.RecentCameraConnections[1].ConsecutiveReconnectFailures);
    }

    [Fact]
    public void RegisterReconnectFailure_DoesNotChargeDifferentAddressWhenCurrentMacIsAmbiguous() {
        var settings = new LocalCamSettings {
            RecentCameraConnections = [new RecentCameraConnection {
                IpAddress = "192.168.1.10",
                MacAddress = "AA:BB:CC:DD:EE:FF",
                LastConfirmedPlaybackUtc = DateTimeOffset.UtcNow
            }]
        };
        var detections = new[] {
            Detection("192.168.1.10", "AA:BB:CC:DD:EE:FF"),
            Detection("192.168.1.11", "AA:BB:CC:DD:EE:FF")
        };

        Assert.False(RecentCameraConnectionCache.RegisterReconnectFailure(settings, detections[1], detections));

        Assert.Single(settings.RecentCameraConnections);
        Assert.Equal(0, settings.RecentCameraConnections[0].ConsecutiveReconnectFailures);
    }

    private static RecentCameraConnection Entry(string ip, DateTimeOffset at, int failures = 0) => new() { IpAddress = ip, LastConfirmedPlaybackUtc = at, ConsecutiveReconnectFailures = failures };
    private static TapoCameraDetection Detection(string ip, string? mac = null) => new(IPAddress.Parse(ip), null, mac, Array.Empty<int>(), 0, "test");
}
