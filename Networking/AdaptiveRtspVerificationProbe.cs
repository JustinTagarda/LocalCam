using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LocalCam.Networking;

internal sealed record AdaptiveRtspVerificationTarget(
    IPAddress IpAddress,
    int Port,
    TapoCameraCandidateDiagnostics Candidate);

internal sealed record AdaptiveRtspVerificationOutcome(
    AdaptiveRtspVerificationTarget Target,
    bool Verified,
    string Outcome,
    string? RequestMethod,
    int? StatusCode,
    bool AuthenticationRequired,
    bool AuthenticationChallengeReceived,
    bool OptionsConfirmed,
    bool DescribeConfirmed);

internal sealed record AdaptiveRtspRequest(string Method, string RequestUri, string Headers);

internal static class AdaptiveRtspVerificationProbe {
    public const int MaxTargets = 64;
    private const int MaxParallelism = 8;
    private const int RequestTimeoutMs = 650;
    private const int MaxResponseBytes = 16 * 1024;

    public static IReadOnlyList<AdaptiveRtspVerificationTarget> SelectTargets(
        IReadOnlyList<TapoCameraCandidateDiagnostics> candidates,
        IReadOnlyList<TapoCameraDetection> detections,
        int maximumTargets = MaxTargets) {
        var detectedAddresses = detections
            .Select(static detection => detection.IpAddress)
            .ToHashSet();
        var selected = candidates
            .Where(candidate => !detectedAddresses.Contains(candidate.IpAddress))
            .SelectMany(candidate => new[] { 554, 8554 }
                .Where(candidate.OpenPorts.Contains)
                .Select(port => new AdaptiveRtspVerificationTarget(candidate.IpAddress, port, candidate)))
            .DistinctBy(static target => $"{target.IpAddress}:{target.Port}", StringComparer.Ordinal)
            .OrderByDescending(static target => HasIndependentCameraEvidence(target.Candidate))
            .ThenBy(static target => target.Port == 554 ? 0 : 1)
            .ThenBy(static target => ToUInt32(target.IpAddress))
            .Take(Math.Clamp(maximumTargets, 0, MaxTargets))
            .ToArray();

        return selected;
    }

    public static IReadOnlyList<AdaptiveRtspRequest> BuildRequests(IPAddress address, int port, string? streamPath) {
        if (port is not (554 or 8554)) {
            return Array.Empty<AdaptiveRtspRequest>();
        }

        var normalizedPath = NormalizeStreamPath(streamPath);
        var uri = $"rtsp://{address}:{port}/{EscapePath(normalizedPath)}";
        var requests = new List<AdaptiveRtspRequest> {
            new("OPTIONS", "*", string.Empty),
            new("OPTIONS", uri, string.Empty)
        };
        if (port == 554) {
            requests.Add(new AdaptiveRtspRequest("DESCRIBE", uri, "Accept: application/sdp\r\n"));
        }

        return requests;
    }

    public static async Task<IReadOnlyList<AdaptiveRtspVerificationOutcome>> ProbeAsync(
        IReadOnlyList<AdaptiveRtspVerificationTarget> targets,
        string? streamPath,
        int requestedParallelism,
        CancellationToken cancellationToken) {
        var outcomes = new ConcurrentBag<AdaptiveRtspVerificationOutcome>();
        await Parallel.ForEachAsync(targets,
            new ParallelOptions {
                CancellationToken = cancellationToken,
                MaxDegreeOfParallelism = Math.Clamp(requestedParallelism, 1, MaxParallelism)
            },
            async (target, token) => {
                outcomes.Add(await ProbeTargetAsync(target, streamPath, token).ConfigureAwait(false));
            }).ConfigureAwait(false);

        return outcomes
            .OrderBy(static outcome => ToUInt32(outcome.Target.IpAddress))
            .ThenBy(static outcome => outcome.Target.Port)
            .ToArray();
    }

    private static async Task<AdaptiveRtspVerificationOutcome> ProbeTargetAsync(
        AdaptiveRtspVerificationTarget target,
        string? streamPath,
        CancellationToken cancellationToken) {
        var lastOutcome = "no_rtsp_response";
        var requests = BuildRequests(target.IpAddress, target.Port, streamPath);
        for (var index = 0; index < requests.Count; index++) {
            cancellationToken.ThrowIfCancellationRequested();
            var request = requests[index];
            var result = await SendRequestAsync(target, request, index + 1, cancellationToken).ConfigureAwait(false);
            if (result.Response is not null) {
                return new AdaptiveRtspVerificationOutcome(
                    target,
                    Verified: true,
                    Outcome: result.Response.HasAuthenticationChallenge ? "authentication_challenge" : "rtsp_response",
                    request.Method,
                    result.Response.StatusCode,
                    result.Response.RequiresAuthentication,
                    result.Response.HasAuthenticationChallenge,
                    OptionsConfirmed: request.Method == "OPTIONS",
                    DescribeConfirmed: request.Method == "DESCRIBE");
            }

            lastOutcome = result.Outcome;
        }

        return new AdaptiveRtspVerificationOutcome(
            target,
            Verified: false,
            Outcome: lastOutcome,
            RequestMethod: null,
            StatusCode: null,
            AuthenticationRequired: false,
            AuthenticationChallengeReceived: false,
            OptionsConfirmed: false,
            DescribeConfirmed: false);
    }

    private static async Task<RtspRequestResult> SendRequestAsync(
        AdaptiveRtspVerificationTarget target,
        AdaptiveRtspRequest request,
        int sequence,
        CancellationToken cancellationToken) {
        try {
            using var client = new TcpClient();
            await client.ConnectAsync(target.IpAddress, target.Port)
                .WaitAsync(TimeSpan.FromMilliseconds(RequestTimeoutMs), cancellationToken)
                .ConfigureAwait(false);

            await using var stream = client.GetStream();
            var payload = Encoding.ASCII.GetBytes(
                $"{request.Method} {request.RequestUri} RTSP/1.0\r\nCSeq: {sequence}\r\nUser-Agent: LocalCam/1.0\r\n{request.Headers}\r\n");
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);

            using var response = new MemoryStream();
            var buffer = new byte[1024];
            while (response.Length < MaxResponseBytes) {
                var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                    .AsTask()
                    .WaitAsync(TimeSpan.FromMilliseconds(RequestTimeoutMs), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0) {
                    break;
                }

                response.Write(buffer, 0, read);
                var text = Encoding.ASCII.GetString(response.GetBuffer(), 0, (int)response.Length);
                if (!text.Contains("\r\n\r\n", StringComparison.Ordinal)) {
                    continue;
                }

                return CameraDiscoveryParsers.TryParseRtspResponse(text, sequence, out var parsed)
                    ? new RtspRequestResult(parsed, "rtsp_response")
                    : new RtspRequestResult(null, "invalid_rtsp_response");
            }

            return new RtspRequestResult(null, "empty_response");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
            throw;
        }
        catch (TimeoutException) {
            return new RtspRequestResult(null, "timeout");
        }
        catch (SocketException) {
            return new RtspRequestResult(null, "connection_failed");
        }
        catch (IOException) {
            return new RtspRequestResult(null, "connection_failed");
        }
    }

    private static bool HasIndependentCameraEvidence(TapoCameraCandidateDiagnostics candidate) =>
        candidate.DiscoveredViaOnvif
        || candidate.DiscoveredViaSsdp
        || candidate.DiscoveredViaMdns
        || candidate.DiscoveredViaTapoBroadcast
        || candidate.DiscoveredViaTapoUnicast;

    private static string NormalizeStreamPath(string? streamPath) {
        var normalized = (streamPath ?? string.Empty).Trim().Trim('/');
        return string.IsNullOrWhiteSpace(normalized) ? "stream1" : normalized;
    }

    private static string EscapePath(string path) =>
        string.Join('/', path.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Uri.EscapeDataString));

    private static uint ToUInt32(IPAddress address) {
        var bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    private sealed record RtspRequestResult(CameraDiscoveryParsers.RtspResponse? Response, string Outcome);
}
