using System.Net;
using LocalCam.Networking;
using Xunit;

namespace LocalCam.Tests;

public sealed class AdaptiveCameraNetworkPlannerTests {
    [Fact]
    public void PrefersRecentAndNetworkEvidenceOutsideConnectedSubnet() {
        var interfaces = new[] {
            new CameraNetworkInterfaceSummary("VMware", "virtual", "192.168.194.10", "24", true,
                ["192.168.68.1", "8.8.8.8"], ["192.168.50.1"])
        };

        var candidates = AdaptiveCameraNetworkPlanner.BuildCandidates(interfaces,
            [IPAddress.Parse("192.168.31.20"), IPAddress.Parse("192.168.194.15")]);

        Assert.Equal(["192.168.31.0/24", "192.168.68.0/24", "192.168.50.0/24"],
            candidates.Take(3).Select(candidate => candidate.Range.ToString()));
        Assert.DoesNotContain(candidates, candidate => candidate.Range.ToString() == "192.168.194.0/24");
        Assert.All(candidates.Take(3), candidate => Assert.True(candidate.HasNetworkEvidence));
        Assert.True(candidates.Count <= AdaptiveCameraNetworkPlanner.MaxCandidateRanges);
    }

    [Fact]
    public void SelectsResponsiveRangesAndBoundsUnconfirmedFallback() {
        var interfaces = new[] {
            new CameraNetworkInterfaceSummary("VMware", "virtual", "192.168.194.10", "24", true, [], [])
        };
        var candidates = AdaptiveCameraNetworkPlanner.BuildCandidates(interfaces, []);

        var fallback = AdaptiveCameraNetworkPlanner.SelectRangesForProbe(candidates,
            new HashSet<Ipv4CidrRange>());
        Assert.Equal(AdaptiveCameraNetworkPlanner.MaxUnconfirmedRanges, fallback.Count);
        Assert.All(fallback, candidate => Assert.False(candidate.HasNetworkEvidence));

        var responsiveRanges = new HashSet<Ipv4CidrRange> {
            candidates[1].Range,
            candidates[8].Range
        };
        var responsive = AdaptiveCameraNetworkPlanner.SelectRangesForProbe(candidates,
            responsiveRanges);

        Assert.Equal(AdaptiveCameraNetworkPlanner.MaxExpandedRanges, responsive.Count);
        Assert.Equal([candidates[1].Range, candidates[8].Range, candidates[0].Range, candidates[2].Range],
            responsive.Select(candidate => candidate.Range));
        Assert.Equal(responsive.Count, responsive.Select(candidate => candidate.Range).Distinct().Count());
    }

    [Fact]
    public void SelectsNextStageFromUnattemptedRangesWithoutExceedingTotalRangeBudget() {
        var interfaces = new[] {
            new CameraNetworkInterfaceSummary("VMware", "virtual", "192.168.194.10", "24", true, [], [])
        };
        var candidates = AdaptiveCameraNetworkPlanner.BuildCandidates(interfaces, []);
        var responsiveRanges = new HashSet<Ipv4CidrRange> {
            candidates[1].Range,
            candidates[8].Range
        };
        var firstStage = AdaptiveCameraNetworkPlanner.SelectRangesForProbe(candidates, responsiveRanges);
        var attemptedRanges = firstStage.Select(candidate => candidate.Range).ToHashSet();

        var secondStage = AdaptiveCameraNetworkPlanner.SelectNextStageRangesForProbe(
            candidates,
            responsiveRanges,
            attemptedRanges);

        Assert.Equal(AdaptiveCameraNetworkPlanner.MaxExpandedRanges, firstStage.Count);
        Assert.Equal(AdaptiveCameraNetworkPlanner.MaxExpandedRanges, secondStage.Count);
        Assert.DoesNotContain(secondStage, candidate => attemptedRanges.Contains(candidate.Range));
        Assert.Equal([candidates[3].Range, candidates[4].Range, candidates[5].Range, candidates[6].Range],
            secondStage.Select(candidate => candidate.Range));
        Assert.True(firstStage.Count + secondStage.Count <= AdaptiveCameraNetworkPlanner.MaxTotalExpandedRanges);
    }
}
