using System.Net;
using System.Reflection;
using LocalCam.Networking;
using Xunit;

namespace LocalCam.Tests;

public sealed class TapoCameraScannerTests {
    [Fact]
    public void EvaluateCandidate_ReturnsTrue_ForGenericRtspCameraWithoutTapoSignals() {
        var probe = CreateHostProbeResult(
            IPAddress.Parse("192.168.1.50"),
            [554],
            httpFingerprint: null,
            discoveredViaOnvif: false,
            discoveredViaTapoBroadcast: false,
            discoveredViaTapoUnicast: false);

        var evaluation = TapoCameraScanner.EvaluateCandidate(probe, macAddress: null, hostName: null);

        Assert.True(evaluation.IsLikelyTapo);
        Assert.Contains("RTSP service port is open", evaluation.Reason);
    }

    [Fact]
    public void EvaluateCandidate_ReturnsFalse_ForRepeaterLikeHostWithoutCameraSignals() {
        var probe = CreateHostProbeResult(
            IPAddress.Parse("192.168.1.51"),
            [80],
            httpFingerprint: "TP-Link Repeater login",
            discoveredViaOnvif: false,
            discoveredViaTapoBroadcast: false,
            discoveredViaTapoUnicast: false);

        var evaluation = TapoCameraScanner.EvaluateCandidate(probe, macAddress: null, hostName: "tplinkrepeater");

        Assert.False(evaluation.IsLikelyTapo);
    }

    private static TapoCameraScanner.HostProbeResult CreateHostProbeResult(
        IPAddress ipAddress,
        IReadOnlyList<int> openPorts,
        string? httpFingerprint,
        bool discoveredViaOnvif,
        bool discoveredViaTapoBroadcast,
        bool discoveredViaTapoUnicast) {
        var hostProbeResultType = typeof(TapoCameraScanner).GetNestedType("HostProbeResult", BindingFlags.NonPublic);
        Assert.NotNull(hostProbeResultType);

        return (TapoCameraScanner.HostProbeResult)Activator.CreateInstance(
            hostProbeResultType!,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: [
                ipAddress,
                openPorts,
                httpFingerprint,
                discoveredViaOnvif,
                discoveredViaTapoBroadcast,
                discoveredViaTapoUnicast
            ],
            culture: null)!;
    }
}
