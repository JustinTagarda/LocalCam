using System.Net;

namespace LocalCam.Networking;

internal sealed record AdaptiveCameraNetworkCandidate(
    Ipv4CidrRange Range,
    string Source,
    bool HasNetworkEvidence);

internal static class AdaptiveCameraNetworkPlanner {
    public const int MaxCandidateRanges = 16;
    public const int MaxExpandedRanges = 4;
    public const int MaxExpansionStages = 2;
    public const int MaxTotalExpandedRanges = MaxExpandedRanges * MaxExpansionStages;
    public const int MaxUnconfirmedRanges = 3;

    private static readonly string[] CommonHomeNetworkSeeds = [
        "192.168.1.1", "192.168.0.1", "192.168.68.1", "192.168.50.1",
        "192.168.31.1", "192.168.4.1", "192.168.10.1", "192.168.100.1",
        "192.168.254.1", "10.0.0.1", "10.0.1.1", "172.16.0.1"
    ];

    public static IReadOnlyList<AdaptiveCameraNetworkCandidate> BuildCandidates(
        IReadOnlyList<CameraNetworkInterfaceSummary> interfaces,
        IReadOnlyList<IPAddress> recentCameraAddresses) {
        var connectedRanges = interfaces
            .Select(item => IPAddress.TryParse(item.Ipv4Address, out var address)
                && int.TryParse(item.Prefix, out var prefix)
                && Ipv4CidrRange.TryCreate(address, prefix, out var range)
                    ? range
                    : (Ipv4CidrRange?)null)
            .Where(static range => range.HasValue)
            .Select(static range => range!.Value)
            .ToArray();
        var candidates = new List<AdaptiveCameraNetworkCandidate>();
        var seen = new HashSet<Ipv4CidrRange>();

        void AddAddress(IPAddress address, string source, bool hasNetworkEvidence) {
            if (candidates.Count >= MaxCandidateRanges
                || !IsPrivateIpv4(address)
                || connectedRanges.Any(range => range.Contains(address))
                || !Ipv4CidrRange.TryCreate(address, 24, out var candidateRange)
                || !seen.Add(candidateRange)) {
                return;
            }

            candidates.Add(new AdaptiveCameraNetworkCandidate(candidateRange, source, hasNetworkEvidence));
        }

        foreach (var address in recentCameraAddresses) {
            AddAddress(address, "recent-camera", hasNetworkEvidence: true);
        }
        foreach (var networkInterface in interfaces) {
            foreach (var rawAddress in networkInterface.DnsAddresses) {
                if (IPAddress.TryParse(rawAddress, out var address)) {
                    AddAddress(address, "dns-server", hasNetworkEvidence: true);
                }
            }
            foreach (var rawAddress in networkInterface.DhcpAddresses) {
                if (IPAddress.TryParse(rawAddress, out var address)) {
                    AddAddress(address, "dhcp-server", hasNetworkEvidence: true);
                }
            }
        }
        foreach (var rawAddress in CommonHomeNetworkSeeds) {
            AddAddress(IPAddress.Parse(rawAddress), "common-home-network", hasNetworkEvidence: false);
        }

        return candidates;
    }

    public static IReadOnlyList<AdaptiveCameraNetworkCandidate> SelectRangesForProbe(
        IReadOnlyList<AdaptiveCameraNetworkCandidate> candidates,
        IReadOnlySet<Ipv4CidrRange> responsiveGatewayRanges) {
        var selected = new List<AdaptiveCameraNetworkCandidate>(MaxExpandedRanges);
        selected.AddRange(candidates.Where(static candidate => candidate.HasNetworkEvidence).Take(MaxExpandedRanges));
        var selectedRanges = selected.Select(static candidate => candidate.Range).ToHashSet();

        foreach (var candidate in candidates.Where(candidate =>
                     !candidate.HasNetworkEvidence
                     && responsiveGatewayRanges.Contains(candidate.Range)
                     && !selectedRanges.Contains(candidate.Range))) {
            if (selected.Count >= MaxExpandedRanges) {
                break;
            }
            selected.Add(candidate);
            selectedRanges.Add(candidate.Range);
        }

        if (selected.Count < MaxExpandedRanges) {
            var unconfirmedCount = 0;
            foreach (var candidate in candidates.Where(candidate =>
                         !candidate.HasNetworkEvidence
                         && !responsiveGatewayRanges.Contains(candidate.Range)
                         && !selectedRanges.Contains(candidate.Range))) {
                if (selected.Count >= MaxExpandedRanges || unconfirmedCount >= MaxUnconfirmedRanges) {
                    break;
                }

                selected.Add(candidate);
                selectedRanges.Add(candidate.Range);
                unconfirmedCount++;
            }
        }

        return selected;
    }

    public static IReadOnlyList<AdaptiveCameraNetworkCandidate> SelectNextStageRangesForProbe(
        IReadOnlyList<AdaptiveCameraNetworkCandidate> candidates,
        IReadOnlySet<Ipv4CidrRange> responsiveGatewayRanges,
        IReadOnlySet<Ipv4CidrRange> attemptedRanges) {
        var remainingCandidates = candidates
            .Where(candidate => !attemptedRanges.Contains(candidate.Range))
            .ToArray();
        var selected = new List<AdaptiveCameraNetworkCandidate>(MaxExpandedRanges);
        var selectedRanges = new HashSet<Ipv4CidrRange>();

        void AddCandidates(IEnumerable<AdaptiveCameraNetworkCandidate> orderedCandidates) {
            foreach (var candidate in orderedCandidates) {
                if (selected.Count >= MaxExpandedRanges) {
                    break;
                }

                if (selectedRanges.Add(candidate.Range)) {
                    selected.Add(candidate);
                }
            }
        }

        AddCandidates(remainingCandidates.Where(static candidate => candidate.HasNetworkEvidence));
        AddCandidates(remainingCandidates.Where(candidate => responsiveGatewayRanges.Contains(candidate.Range)));
        AddCandidates(remainingCandidates);

        return selected;
    }

    private static bool IsPrivateIpv4(IPAddress address) {
        var bytes = address.GetAddressBytes();
        return bytes.Length == 4
            && (bytes[0] == 10
                || bytes[0] == 172 && bytes[1] is >= 16 and <= 31
                || bytes[0] == 192 && bytes[1] == 168);
    }
}
