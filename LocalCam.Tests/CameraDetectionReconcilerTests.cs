using System.Net;
using LocalCam.Networking;
using LocalCam.Services;
using Xunit;

namespace LocalCam.Tests;

public sealed class CameraDetectionReconcilerTests {
    [Fact]
    public void Reconcile_PreservesExistingCameraOrderWhenDiscoveryReordersResults() {
        var previous = new[] {
            Detection("192.0.2.10", "AA:00:00:00:00:01"),
            Detection("192.0.2.20", "AA:00:00:00:00:02"),
            Detection("192.0.2.30", "AA:00:00:00:00:03")
        };
        var discovered = new[] {
            Detection("192.0.2.30", "AA:00:00:00:00:03"),
            Detection("192.0.2.10", "AA:00:00:00:00:01"),
            Detection("192.0.2.20", "AA:00:00:00:00:02")
        };

        var result = CameraDetectionReconciler.Reconcile(previous, discovered);

        Assert.Equal(
            ["192.0.2.10", "192.0.2.20", "192.0.2.30"],
            result.Select(detection => detection.IpAddress.ToString()));
    }

    [Fact]
    public void Reconcile_CollapsesDuplicateMacIdentitiesAndKeepsHighestConfidenceDetection() {
        var discovered = new[] {
            Detection("192.0.2.10", "aa:00:00:00:00:01", confidence: 0.4),
            Detection("192.0.2.11", "AA:00:00:00:00:01", confidence: 0.9),
            Detection("192.0.2.20", null)
        };

        var result = CameraDetectionReconciler.Reconcile([], discovered);

        Assert.Equal(2, result.Count);
        Assert.Equal("192.0.2.11", result[0].IpAddress.ToString());
        Assert.Equal("192.0.2.20", result[1].IpAddress.ToString());
    }

    [Fact]
    public void Reconcile_MatchesByIpWhenMacAvailabilityChangesAndAppendsNewCameras() {
        var previous = new[] {
            Detection("192.0.2.10", null),
            Detection("192.0.2.20", "AA:00:00:00:00:02")
        };
        var discovered = new[] {
            Detection("192.0.2.30", "AA:00:00:00:00:03"),
            Detection("192.0.2.20", "AA:00:00:00:00:02"),
            Detection("192.0.2.10", "AA:00:00:00:00:01")
        };

        var result = CameraDetectionReconciler.Reconcile(previous, discovered);

        Assert.Equal(
            ["192.0.2.10", "192.0.2.20", "192.0.2.30"],
            result.Select(detection => detection.IpAddress.ToString()));
    }

    private static TapoCameraDetection Detection(string ipAddress, string? macAddress, double confidence = 0.5) => new(
        IPAddress.Parse(ipAddress),
        HostName: null,
        MacAddress: macAddress,
        OpenPorts: Array.Empty<int>(),
        ConfidenceScore: confidence,
        DetectionReason: "synthetic test detection");
}
