using System.Net;
using LocalCam.Networking;
using Xunit;

namespace LocalCam.Tests;

public sealed class AdaptiveRtspVerificationProbeTests {
    [Fact]
    public void BuildRequestsChecksRootAndConfiguredPathWithoutCredentials() {
        var requests = AdaptiveRtspVerificationProbe.BuildRequests(
            IPAddress.Parse("192.0.2.45"), 554, "entry/stream 1");

        Assert.Equal(["OPTIONS", "OPTIONS", "DESCRIBE"], requests.Select(static request => request.Method));
        Assert.Equal("*", requests[0].RequestUri);
        Assert.Contains("/entry/stream%201", requests[1].RequestUri);
        Assert.Contains("/entry/stream%201", requests[2].RequestUri);
        Assert.Contains("Accept: application/sdp", requests[2].Headers);
        Assert.All(requests, request => Assert.DoesNotContain("Authorization:", request.Headers, StringComparison.OrdinalIgnoreCase));
        var alternatePortRequests = AdaptiveRtspVerificationProbe.BuildRequests(
            IPAddress.Parse("192.0.2.45"), 8554, "stream1");
        Assert.Equal(["OPTIONS", "OPTIONS"], alternatePortRequests.Select(static request => request.Method));
        Assert.Empty(AdaptiveRtspVerificationProbe.BuildRequests(IPAddress.Loopback, 8080, "stream1"));
    }

    [Fact]
    public void SelectTargetsPrioritizesOpenRtspPortsThenUsesFallbackAndSkipsDetectedCameras() {
        var candidate = CreateCandidate("192.168.1.50", [554, 8554]);
        var alreadyDetected = CreateCandidate("192.168.1.51", [554]);
        var webOnlyHost = CreateCandidate("192.168.1.52", [80, 443]);
        var detections = new[] {
            new TapoCameraDetection(IPAddress.Parse("192.168.1.51"), null, null, [554], 2, "test")
        };

        var targets = AdaptiveRtspVerificationProbe.SelectTargets([candidate, alreadyDetected, webOnlyHost], detections);

        Assert.Collection(targets,
            target => {
                Assert.Equal(("192.168.1.50", 554), (target.IpAddress.ToString(), target.Port));
                Assert.True(target.PortWasConfirmedOpen);
            },
            target => {
                Assert.Equal(("192.168.1.50", 8554), (target.IpAddress.ToString(), target.Port));
                Assert.True(target.PortWasConfirmedOpen);
            },
            target => {
                Assert.Equal(("192.168.1.52", 554), (target.IpAddress.ToString(), target.Port));
                Assert.False(target.PortWasConfirmedOpen);
            },
            target => {
                Assert.Equal(("192.168.1.52", 8554), (target.IpAddress.ToString(), target.Port));
                Assert.False(target.PortWasConfirmedOpen);
            });
    }

    [Fact]
    public void SelectTargetsUsesFallbackForResponsiveHostsWithoutOpenPorts() {
        var cameraLike = CreateCandidate("192.168.1.60", [], isLikelyCamera: true, confidenceScore: 1.5);
        var genericHost = CreateCandidate("192.168.1.61", []);

        var targets = AdaptiveRtspVerificationProbe.SelectTargets([genericHost, cameraLike, genericHost], []);

        Assert.Equal(["192.168.1.60", "192.168.1.60", "192.168.1.61", "192.168.1.61"],
            targets.Select(static target => target.IpAddress.ToString()));
        Assert.All(targets, target => Assert.False(target.PortWasConfirmedOpen));
        Assert.Equal([554, 8554, 554, 8554], targets.Select(static target => target.Port));
    }

    [Fact]
    public void SelectTargetsHonorsEndpointLimit() {
        var candidates = Enumerable.Range(1, 100)
            .Select(index => CreateCandidate($"10.0.0.{index}", [554]))
            .ToArray();

        var targets = AdaptiveRtspVerificationProbe.SelectTargets(candidates, []);

        Assert.Equal(AdaptiveRtspVerificationProbe.MaxTargets, targets.Count);
    }

    [Fact]
    public void SelectTargetsHonorsRemainingBudgetAcrossStages() {
        var firstStageCandidates = Enumerable.Range(1, 50)
            .Select(index => CreateCandidate($"10.0.0.{index}", [554]))
            .ToArray();
        var secondStageCandidates = Enumerable.Range(1, 50)
            .Select(index => CreateCandidate($"10.0.1.{index}", [554]))
            .ToArray();

        var firstStageTargets = AdaptiveRtspVerificationProbe.SelectTargets(firstStageCandidates, []);
        var secondStageTargets = AdaptiveRtspVerificationProbe.SelectTargets(
            secondStageCandidates,
            [],
            AdaptiveRtspVerificationProbe.MaxTargets - firstStageTargets.Count);

        Assert.Equal(AdaptiveRtspVerificationProbe.MaxTargets, firstStageTargets.Count + secondStageTargets.Count);
    }

    [Fact]
    public void SelectTargetsFallbackHonorsRemainingBudgetAcrossStages() {
        var firstStageCandidates = Enumerable.Range(1, 40)
            .Select(index => CreateCandidate($"10.0.0.{index}", []))
            .ToArray();
        var secondStageCandidates = Enumerable.Range(1, 40)
            .Select(index => CreateCandidate($"10.0.1.{index}", []))
            .ToArray();

        var firstStageTargets = AdaptiveRtspVerificationProbe.SelectTargets(firstStageCandidates, []);
        var secondStageTargets = AdaptiveRtspVerificationProbe.SelectTargets(
            secondStageCandidates,
            [],
            AdaptiveRtspVerificationProbe.MaxTargets - firstStageTargets.Count);

        Assert.Equal(AdaptiveRtspVerificationProbe.MaxTargets, firstStageTargets.Count + secondStageTargets.Count);
        Assert.All(firstStageTargets.Concat(secondStageTargets), target => Assert.False(target.PortWasConfirmedOpen));
    }

    private static TapoCameraCandidateDiagnostics CreateCandidate(
        string address,
        IReadOnlyList<int> ports,
        bool isLikelyCamera = false,
        double confidenceScore = 0.5) =>
        new(
            IPAddress.Parse(address),
            IsLikelyTapo: isLikelyCamera,
            ConfidenceScore: confidenceScore,
            Reason: "RTSP port is open",
            HostName: null,
            MacAddress: null,
            SeenInArpTable: false,
            DiscoveredViaOnvif: false,
            DiscoveredViaSsdp: false,
            DiscoveredViaMdns: false,
            DiscoveredViaRtspOptions: false,
            DiscoveredViaTapoBroadcast: false,
            DiscoveredViaTapoUnicast: false,
            OpenPorts: ports);
}
