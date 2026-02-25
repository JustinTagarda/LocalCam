using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace LocalCam.Networking {
    public sealed record TapoCameraDetection(
        IPAddress IpAddress,
        string? HostName,
        string? MacAddress,
        IReadOnlyList<int> OpenPorts,
        double ConfidenceScore,
        string DetectionReason);

    public static class TapoCameraScanner {
        private static readonly int[] ProbePorts = [80, 443, 554, 8554, 2020, 8080, 8443];

        // Known TP-Link OUIs (Tapo is TP-Link consumer brand).
        private static readonly HashSet<string> TpLinkOuiPrefixes = new(StringComparer.OrdinalIgnoreCase) {
            "0846EA", "14CC20", "1C61B4", "246F28", "2C3AF2", "30B5C2", "488F5A", "50C7BF",
            "60E327", "74DA38", "84D81B", "8C3BA5", "98DA60", "A0F3C1", "AC84C6", "B0487A",
            "B09575", "C04A00", "C05627", "C46E1F", "D067E5", "D85D4C", "DC9FDB", "E894F6",
            "EC086B", "F4F26D", "FCECDA"
        };

        private static readonly Regex ArpEntryPattern = new(
            @"^\s*(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<mac>[0-9a-fA-F\-:]{17})\s+\w+",
            RegexOptions.Multiline | RegexOptions.Compiled);

        private static readonly HttpClient ProbeHttpClient = CreateProbeHttpClient();

        public static async Task<IReadOnlyList<TapoCameraDetection>> ScanLocalNetworkForTapoCamerasAsync(
            int maxParallelism = 48,
            CancellationToken cancellationToken = default) {
            if (maxParallelism < 1) {
                throw new ArgumentOutOfRangeException(nameof(maxParallelism), "Parallelism must be at least 1.");
            }

            var subnets = GetCandidateSubnets();
            var hostAddresses = subnets
                .SelectMany(EnumerateHostAddresses)
                .DistinctBy(static ip => ip.ToString())
                .ToArray();

            if (hostAddresses.Length == 0) {
                return Array.Empty<TapoCameraDetection>();
            }

            var probes = new ConcurrentBag<HostProbeResult>();

            await Parallel.ForEachAsync(
                hostAddresses,
                new ParallelOptions {
                    CancellationToken = cancellationToken,
                    MaxDegreeOfParallelism = maxParallelism
                },
                async (ip, token) => {
                    var result = await ProbeHostAsync(ip, token).ConfigureAwait(false);
                    if (result is not null) {
                        probes.Add(result);
                    }
                }).ConfigureAwait(false);

            var arpTable = await ReadArpTableAsync(cancellationToken).ConfigureAwait(false);
            var detections = new List<TapoCameraDetection>();

            foreach (var probe in probes.OrderBy(static p => IpToUInt32(p.IpAddress))) {
                cancellationToken.ThrowIfCancellationRequested();

                arpTable.TryGetValue(probe.IpAddress, out var macAddress);
                var hostName = await TryResolveHostNameAsync(probe.IpAddress, cancellationToken).ConfigureAwait(false);
                var evaluation = EvaluateCandidate(probe, macAddress, hostName);

                if (!evaluation.IsLikelyTapo) {
                    continue;
                }

                detections.Add(new TapoCameraDetection(
                    probe.IpAddress,
                    hostName,
                    macAddress,
                    probe.OpenPorts,
                    Math.Round(evaluation.Score, 2),
                    evaluation.Reason));
            }

            return detections;
        }

        private static async Task<HostProbeResult?> ProbeHostAsync(IPAddress ipAddress, CancellationToken cancellationToken) {
            var pingTask = PingHostAsync(ipAddress, timeoutMs: 300, cancellationToken);
            var portTasks = ProbePorts.ToDictionary(
                static port => port,
                port => ProbeTcpPortAsync(ipAddress, port, timeoutMs: 350, cancellationToken));

            await Task.WhenAll(portTasks.Values.Prepend(pingTask)).ConfigureAwait(false);

            var openPorts = portTasks
                .Where(static kvp => kvp.Value.Result)
                .Select(static kvp => kvp.Key)
                .Order()
                .ToArray();

            var pingSucceeded = pingTask.Result;
            if (!pingSucceeded && openPorts.Length == 0) {
                return null;
            }

            string? httpFingerprint = null;

            if (openPorts.Contains(80)) {
                httpFingerprint = await TryGetHttpFingerprintAsync(ipAddress, useHttps: false, cancellationToken).ConfigureAwait(false);
            }

            if (string.IsNullOrWhiteSpace(httpFingerprint) && openPorts.Contains(443)) {
                httpFingerprint = await TryGetHttpFingerprintAsync(ipAddress, useHttps: true, cancellationToken).ConfigureAwait(false);
            }

            return new HostProbeResult(ipAddress, openPorts, httpFingerprint);
        }

        private static CandidateEvaluation EvaluateCandidate(HostProbeResult probe, string? macAddress, string? hostName) {
            var reasons = new List<string>();
            var score = 0d;

            var hasRtsp = probe.OpenPorts.Contains(554) || probe.OpenPorts.Contains(8554);
            var hasOnvif = probe.OpenPorts.Contains(2020);
            var hasWebManagement = probe.OpenPorts.Contains(80)
                || probe.OpenPorts.Contains(443)
                || probe.OpenPorts.Contains(8080)
                || probe.OpenPorts.Contains(8443);
            var hasTpLinkMac = !string.IsNullOrWhiteSpace(macAddress) && IsTpLinkMac(macAddress);

            if (hasRtsp) {
                score += 2.0;
                reasons.Add("RTSP service port is open");
            }

            if (hasOnvif) {
                score += 1.5;
                reasons.Add("ONVIF port 2020 is open");
            }

            if (hasWebManagement) {
                score += 0.5;
                reasons.Add("Web management port is open");
            }

            var fingerprint = probe.HttpFingerprint?.ToLowerInvariant() ?? string.Empty;
            if (fingerprint.Contains("tapo") || fingerprint.Contains("tp-link") || fingerprint.Contains("tplink")) {
                score += 3.0;
                reasons.Add("HTTP endpoint reports Tapo/TP-Link markers");
            }

            var hostSuggestsTpLink = false;
            if (!string.IsNullOrWhiteSpace(hostName)) {
                var normalizedHost = hostName.ToLowerInvariant();
                if (normalizedHost.Contains("tapo") || normalizedHost.Contains("tp-link") || normalizedHost.Contains("tplink")) {
                    hostSuggestsTpLink = true;
                    score += 2.0;
                    reasons.Add($"Hostname '{hostName}' matches Tapo/TP-Link pattern");
                }
            }

            if (hasTpLinkMac) {
                score += 1.0;
                reasons.Add("MAC OUI is assigned to TP-Link");
            }

            var fingerprintSuggestsTpLink =
                fingerprint.Contains("tapo") || fingerprint.Contains("tp-link") || fingerprint.Contains("tplink");
            var hasStrongBrandSignal = fingerprint.Contains("tapo") || hostSuggestsTpLink;
            var hasCameraService = hasRtsp || hasOnvif;
            var hasTpLinkSignal = hasTpLinkMac || hostSuggestsTpLink || fingerprintSuggestsTpLink;

            var isLikely =
                hasStrongBrandSignal
                || (hasCameraService && hasTpLinkSignal)
                || (hasRtsp && hasOnvif)
                || (hasRtsp && hasWebManagement && score >= 2.5);

            var reason = reasons.Count == 0
                ? "No Tapo-specific markers were found."
                : string.Join("; ", reasons);

            return new CandidateEvaluation(isLikely, score, reason);
        }

        private static async Task<bool> ProbeTcpPortAsync(
            IPAddress ipAddress,
            int port,
            int timeoutMs,
            CancellationToken cancellationToken) {
            try {
                using var client = new TcpClient();
                await client.ConnectAsync(ipAddress, port)
                    .WaitAsync(TimeSpan.FromMilliseconds(timeoutMs), cancellationToken)
                    .ConfigureAwait(false);
                return client.Connected;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            }
            catch {
                return false;
            }
        }

        private static async Task<bool> PingHostAsync(IPAddress ipAddress, int timeoutMs, CancellationToken cancellationToken) {
            try {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ipAddress, timeoutMs)
                    .WaitAsync(TimeSpan.FromMilliseconds(timeoutMs + 100), cancellationToken)
                    .ConfigureAwait(false);
                return reply.Status == IPStatus.Success;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            }
            catch {
                return false;
            }
        }

        private static async Task<string?> TryGetHttpFingerprintAsync(
            IPAddress ipAddress,
            bool useHttps,
            CancellationToken cancellationToken) {
            var scheme = useHttps ? "https" : "http";

            try {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"{scheme}://{ipAddress}/");
                request.Headers.UserAgent.ParseAdd("LocalCam/1.0");
                using var response = await ProbeHttpClient
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                    .ConfigureAwait(false);

                var serverHeader = response.Headers.Server.ToString();
                var authHeader = response.Headers.WwwAuthenticate.ToString();
                var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

                if (body.Length > 1024) {
                    body = body[..1024];
                }

                var fingerprint = $"{serverHeader} {authHeader} {body}".Trim();
                return string.IsNullOrWhiteSpace(fingerprint) ? null : fingerprint;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            }
            catch {
                return null;
            }
        }

        private static async Task<Dictionary<IPAddress, string>> ReadArpTableAsync(CancellationToken cancellationToken) {
            var map = new Dictionary<IPAddress, string>();

            try {
                var startInfo = new ProcessStartInfo {
                    FileName = "arp",
                    Arguments = "-a",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                if (process is null) {
                    return map;
                }

                var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                var output = await outputTask.ConfigureAwait(false);

                foreach (Match match in ArpEntryPattern.Matches(output)) {
                    if (!IPAddress.TryParse(match.Groups["ip"].Value, out var ipAddress)) {
                        continue;
                    }

                    var normalizedMac = NormalizeMac(match.Groups["mac"].Value);
                    if (normalizedMac is null) {
                        continue;
                    }

                    map[ipAddress] = normalizedMac;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            }
            catch {
                // Best-effort enrichment only.
            }

            return map;
        }

        private static async Task<string?> TryResolveHostNameAsync(IPAddress ipAddress, CancellationToken cancellationToken) {
            try {
                var hostEntry = await Dns.GetHostEntryAsync(ipAddress)
                    .WaitAsync(TimeSpan.FromMilliseconds(700), cancellationToken)
                    .ConfigureAwait(false);

                return string.IsNullOrWhiteSpace(hostEntry.HostName)
                    ? null
                    : hostEntry.HostName;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            }
            catch {
                return null;
            }
        }

        private static bool IsTpLinkMac(string macAddress) {
            var normalized = macAddress.Replace(":", string.Empty, StringComparison.Ordinal);
            if (normalized.Length < 6) {
                return false;
            }

            return TpLinkOuiPrefixes.Contains(normalized[..6]);
        }

        private static string? NormalizeMac(string rawMac) {
            var compact = rawMac
                .Replace("-", string.Empty, StringComparison.Ordinal)
                .Replace(":", string.Empty, StringComparison.Ordinal)
                .ToUpperInvariant();

            if (compact.Length != 12) {
                return null;
            }

            return string.Join(':', Enumerable.Range(0, 6).Select(i => compact.Substring(i * 2, 2)));
        }

        private static IReadOnlyList<Ipv4Subnet> GetCandidateSubnets() {
            var subnets = new List<Ipv4Subnet>();
            var seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()) {
                if (nic.OperationalStatus != OperationalStatus.Up) {
                    continue;
                }

                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) {
                    continue;
                }

                IPInterfaceProperties ipProperties;
                try {
                    ipProperties = nic.GetIPProperties();
                }
                catch {
                    continue;
                }

                var hasIpv4Gateway = ipProperties.GatewayAddresses.Any(static g =>
                    g.Address.AddressFamily == AddressFamily.InterNetwork
                    && !IPAddress.Any.Equals(g.Address));
                if (!hasIpv4Gateway) {
                    continue;
                }

                foreach (var unicast in ipProperties.UnicastAddresses) {
                    var ipAddress = unicast.Address;
                    if (ipAddress.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(ipAddress)) {
                        continue;
                    }

                    if (IsApipaAddress(ipAddress)) {
                        continue;
                    }

                    var prefixLength = unicast.PrefixLength;
                    if (prefixLength <= 0 || prefixLength >= 31) {
                        continue;
                    }

                    // Cap broad networks to /24 to avoid scanning thousands of hosts by default.
                    if (prefixLength < 24) {
                        prefixLength = 24;
                    }

                    var networkAddress = IpToUInt32(ipAddress) & PrefixMask(prefixLength);
                    var key = $"{networkAddress}/{prefixLength}";
                    if (!seen.Add(key)) {
                        continue;
                    }

                    subnets.Add(new Ipv4Subnet(ipAddress, networkAddress, prefixLength));
                }
            }

            return subnets;
        }

        private static IEnumerable<IPAddress> EnumerateHostAddresses(Ipv4Subnet subnet) {
            var hostBits = 32 - subnet.PrefixLength;
            if (hostBits <= 0) {
                yield break;
            }

            var hostCount = (1u << hostBits) - 2u;
            if (hostCount < 1) {
                yield break;
            }

            var localAddressValue = IpToUInt32(subnet.LocalAddress);

            for (var offset = 1u; offset <= hostCount; offset++) {
                var value = subnet.NetworkAddress + offset;
                if (value == localAddressValue) {
                    continue;
                }

                yield return UInt32ToIp(value);
            }
        }

        private static uint PrefixMask(int prefixLength) {
            return prefixLength == 0
                ? 0u
                : uint.MaxValue << (32 - prefixLength);
        }

        private static bool IsApipaAddress(IPAddress ipAddress) {
            var octets = ipAddress.GetAddressBytes();
            return octets[0] == 169 && octets[1] == 254;
        }

        private static uint IpToUInt32(IPAddress address) {
            var bytes = address.GetAddressBytes();
            return ((uint)bytes[0] << 24)
                 | ((uint)bytes[1] << 16)
                 | ((uint)bytes[2] << 8)
                 | bytes[3];
        }

        private static IPAddress UInt32ToIp(uint value) {
            return new IPAddress([
                (byte)(value >> 24),
                (byte)(value >> 16),
                (byte)(value >> 8),
                (byte)value
            ]);
        }

        private static HttpClient CreateProbeHttpClient() {
            var handler = new HttpClientHandler {
                ServerCertificateCustomValidationCallback = static (_, _, _, _) => true
            };

            return new HttpClient(handler) {
                Timeout = TimeSpan.FromMilliseconds(1200)
            };
        }

        private readonly record struct Ipv4Subnet(IPAddress LocalAddress, uint NetworkAddress, int PrefixLength);

        private sealed record HostProbeResult(IPAddress IpAddress, IReadOnlyList<int> OpenPorts, string? HttpFingerprint);

        private readonly record struct CandidateEvaluation(bool IsLikelyTapo, double Score, string Reason);
    }
}
