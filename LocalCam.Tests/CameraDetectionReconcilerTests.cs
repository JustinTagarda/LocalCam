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
    public void Reconcile_PreservesDifferentAddressesThatShareMacAndKeepsUniqueCamera() {
        var discovered = new[] {
            Detection("192.0.2.10", "aa:00:00:00:00:01", confidence: 0.4),
            Detection("192.0.2.11", "AA:00:00:00:00:01", confidence: 0.9),
            Detection("192.0.2.20", "AA:00:00:00:00:03")
        };

        var result = CameraDetectionReconciler.Reconcile([], discovered);

        Assert.Equal(3, result.Count);
        Assert.Equal(discovered.Select(detection => detection.IpAddress.ToString()),
            result.Select(detection => detection.IpAddress.ToString()));
        Assert.Equal("ip:192.0.2.10", CameraDetectionReconciler.GetIdentity(result[0], result));
        Assert.Equal("ip:192.0.2.11", CameraDetectionReconciler.GetIdentity(result[1], result));
        Assert.Equal("mac:AA:00:00:00:00:03", CameraDetectionReconciler.GetIdentity(result[2], result));
    }

    [Fact]
    public void Reconcile_CollapsesRepeatedDetectionForSameAddressAndKeepsHighestConfidence() {
        var discovered = new[] {
            Detection("192.0.2.10", "AA:00:00:00:00:01", confidence: 0.4),
            Detection("192.0.2.10", "aa:00:00:00:00:01", confidence: 0.9)
        };

        var result = CameraDetectionReconciler.Reconcile([], discovered);

        var detection = Assert.Single(result);
        Assert.Equal(0.9, detection.ConfidenceScore);
    }

    [Fact]
    public void Reconcile_PreservesPriorCameraOrderWhenMacBecomesAmbiguous() {
        var previous = new[] {
            Detection("192.0.2.11", "AA:00:00:00:00:01"),
            Detection("192.0.2.20", "AA:00:00:00:00:02")
        };
        var discovered = new[] {
            Detection("192.0.2.10", "AA:00:00:00:00:01"),
            Detection("192.0.2.11", "AA:00:00:00:00:01"),
            Detection("192.0.2.20", "AA:00:00:00:00:02")
        };

        var result = CameraDetectionReconciler.Reconcile(previous, discovered);

        Assert.Equal(
            ["192.0.2.11", "192.0.2.20", "192.0.2.10"],
            result.Select(detection => detection.IpAddress.ToString()));
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
