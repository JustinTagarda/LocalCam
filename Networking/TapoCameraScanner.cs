using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace LocalCam.Networking {
    public sealed record TapoCameraDetection(
        IPAddress IpAddress,
        string? HostName,
        string? MacAddress,
        IReadOnlyList<int> OpenPorts,
        double ConfidenceScore,
        string DetectionReason);

    public sealed record TapoCameraCandidateDiagnostics(
        IPAddress IpAddress,
        bool IsLikelyTapo,
        double ConfidenceScore,
        string Reason,
        string? HostName,
        string? MacAddress,
        bool SeenInArpTable,
        bool DiscoveredViaOnvif,
        bool DiscoveredViaTapoBroadcast,
        bool DiscoveredViaTapoUnicast,
        IReadOnlyList<int> OpenPorts);

    public sealed record TapoScanDiagnostics(
        IReadOnlyList<string> SubnetsScanned,
        int EnumeratedHostCount,
        int ArpSeedCount,
        int OnvifHintCount,
        int TapoBroadcastHintCount,
        int TapoUnicastHintCount,
        int ResponsiveHostCount,
        IReadOnlyList<TapoCameraCandidateDiagnostics> Candidates);

    public sealed record TapoCameraScanResult(
        IReadOnlyList<TapoCameraDetection> Detections,
        TapoScanDiagnostics Diagnostics);

    public static class TapoCameraScanner {
        private const int MaxHostsForFullSubnetScan = 4096;
        private const int LargeSubnetChunkSize = 256;
        private const int MaxLargeSubnetChunks = 16;
        private const int OnvifDiscoveryPort = 3702;
        private const int OnvifReceiveWindowMs = 1800;
        private const int TapoDiscoveryPort = 20002;
        private const int TpLinkLegacyDiscoveryPort = 9999;
        private const int TapoDiscoveryReceiveWindowMs = 2200;
        private const int ProbeTcpTimeoutMsPrimary = 450;
        private const int ProbeTcpTimeoutMsRetry = 1300;
        private const int ProbeTcpMaxAttempts = 2;
        private const int ProbePingTimeoutMs = 450;
        private const int ArpPrimePingTimeoutMs = 170;
        private const int MaxArpPrimeHosts = 2048;
        private const int TapoUnicastProbeTimeoutMs = 260;
        private const int HttpFingerprintBodyLimit = 8192;

        private static readonly int[] ProbePorts = [80, 443, 554, 8554, 2020, 8080, 8443, 20002, 9999];
        private static readonly IPAddress OnvifMulticastAddress = IPAddress.Parse("239.255.255.250");
        private static readonly string[] TapoDiscoveryPayloads = [
            """{"system":{"get_sysinfo":{}}}""",
            """{"method":"getDeviceInfo","params":null}""",
            """{"method":"multipleRequest","params":{"requests":[{"method":"getDeviceInfo","params":null}]}}"""
        ];

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
        private static readonly Regex Ipv4AddressPattern = new(
            @"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b",
            RegexOptions.Compiled);

        private static readonly HttpClient ProbeHttpClient = CreateProbeHttpClient();

        public static async Task<IReadOnlyList<TapoCameraDetection>> ScanLocalNetworkForTapoCamerasAsync(
            int maxParallelism = 64,
            CancellationToken cancellationToken = default) {
            var scanResult = await ScanLocalNetworkForTapoCamerasWithDiagnosticsAsync(
                maxParallelism,
                cancellationToken).ConfigureAwait(false);

            return scanResult.Detections;
        }

        public static async Task<TapoCameraScanResult> ScanLocalNetworkForTapoCamerasWithDiagnosticsAsync(
            int maxParallelism = 64,
            CancellationToken cancellationToken = default) {
            if (maxParallelism < 1) {
                throw new ArgumentOutOfRangeException(nameof(maxParallelism), "Parallelism must be at least 1.");
            }

            var subnets = GetCandidateSubnets();
            var enumeratedSubnetHosts = subnets
                .SelectMany(EnumerateHostAddresses)
                .DistinctBy(static ip => ip.ToString())
                .ToArray();

            await PrimeArpCacheAsync(enumeratedSubnetHosts, cancellationToken).ConfigureAwait(false);

            var onvifHints = await DiscoverOnvifCameraAddressesAsync(
                subnets.Select(static s => s.LocalAddress),
                cancellationToken).ConfigureAwait(false);
            var tapoBroadcastHints = await DiscoverTapoBroadcastAddressesAsync(
                subnets,
                cancellationToken).ConfigureAwait(false);
            var arpSeedTable = await ReadArpTableAsync(cancellationToken).ConfigureAwait(false);

            var hostAddresses = enumeratedSubnetHosts
                .Concat(arpSeedTable.Keys)
                .Concat(onvifHints)
                .Concat(tapoBroadcastHints)
                .DistinctBy(static ip => ip.ToString())
                .ToArray();

            var subnetDiagnostics = subnets
                .OrderBy(static s => s.NetworkAddress)
                .ThenBy(static s => s.PrefixLength)
                .Select(FormatSubnetDiagnostic)
                .ToArray();

            if (hostAddresses.Length == 0) {
                return new TapoCameraScanResult(
                    Array.Empty<TapoCameraDetection>(),
                    new TapoScanDiagnostics(
                        subnetDiagnostics,
                        EnumeratedHostCount: 0,
                        ArpSeedCount: arpSeedTable.Count,
                        OnvifHintCount: onvifHints.Count,
                        TapoBroadcastHintCount: tapoBroadcastHints.Count,
                        TapoUnicastHintCount: 0,
                        ResponsiveHostCount: 0,
                        Candidates: Array.Empty<TapoCameraCandidateDiagnostics>()));
            }

            var onvifHintSet = onvifHints.ToHashSet();
            var tapoBroadcastHintSet = tapoBroadcastHints.ToHashSet();
            var probes = new ConcurrentBag<HostProbeResult>();

            await Parallel.ForEachAsync(
                hostAddresses,
                new ParallelOptions {
                    CancellationToken = cancellationToken,
                    MaxDegreeOfParallelism = maxParallelism
                },
                async (ip, token) => {
                    var result = await ProbeHostAsync(
                        ip,
                        discoveredViaOnvif: onvifHintSet.Contains(ip),
                        discoveredViaTapoBroadcast: tapoBroadcastHintSet.Contains(ip),
                        token).ConfigureAwait(false);
                    if (result is not null) {
                        probes.Add(result);
                    }
                }).ConfigureAwait(false);

            var arpPostProbeTable = await ReadArpTableAsync(cancellationToken).ConfigureAwait(false);
            var arpTable = MergeArpTables(arpSeedTable, arpPostProbeTable);

            var orderedProbes = probes
                .OrderBy(static p => IpToUInt32(p.IpAddress))
                .ToArray();

            var detections = new List<TapoCameraDetection>();
            var candidates = new List<TapoCameraCandidateDiagnostics>(orderedProbes.Length);

            foreach (var probe in orderedProbes) {
                cancellationToken.ThrowIfCancellationRequested();

                var hasArpEntry = arpTable.TryGetValue(probe.IpAddress, out var macAddress);
                var hostName = await TryResolveHostNameAsync(probe.IpAddress, cancellationToken).ConfigureAwait(false);
                var evaluation = EvaluateCandidate(probe, macAddress, hostName);

                candidates.Add(new TapoCameraCandidateDiagnostics(
                    probe.IpAddress,
                    evaluation.IsLikelyTapo,
                    Math.Round(evaluation.Score, 2),
                    evaluation.Reason,
                    hostName,
                    macAddress,
                    hasArpEntry,
                    probe.DiscoveredViaOnvif,
                    probe.DiscoveredViaTapoBroadcast,
                    probe.DiscoveredViaTapoUnicast,
                    probe.OpenPorts));

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

            var diagnostics = new TapoScanDiagnostics(
                subnetDiagnostics,
                EnumeratedHostCount: hostAddresses.Length,
                ArpSeedCount: arpSeedTable.Count,
                OnvifHintCount: onvifHints.Count,
                TapoBroadcastHintCount: tapoBroadcastHints.Count,
                TapoUnicastHintCount: orderedProbes.Count(static p => p.DiscoveredViaTapoUnicast),
                ResponsiveHostCount: orderedProbes.Length,
                Candidates: candidates);

            return new TapoCameraScanResult(detections, diagnostics);
        }

        private static async Task<HostProbeResult?> ProbeHostAsync(
            IPAddress ipAddress,
            bool discoveredViaOnvif,
            bool discoveredViaTapoBroadcast,
            CancellationToken cancellationToken) {
            var pingTask = PingHostAsync(ipAddress, timeoutMs: ProbePingTimeoutMs, cancellationToken);
            var portTasks = ProbePorts.ToDictionary(
                static port => port,
                port => ProbeTcpPortWithRetryAsync(ipAddress, port, cancellationToken));

            await Task.WhenAll(portTasks.Values.Prepend(pingTask)).ConfigureAwait(false);

            var openPorts = portTasks
                .Where(static kvp => kvp.Value.Result)
                .Select(static kvp => kvp.Key)
                .Order()
                .ToArray();

            var pingSucceeded = pingTask.Result;
            var discoveredViaTapoUnicast =
                await TryProbeTapoUnicastAsync(ipAddress, cancellationToken).ConfigureAwait(false);

            if (!pingSucceeded
                && openPorts.Length == 0
                && !discoveredViaOnvif
                && !discoveredViaTapoBroadcast
                && !discoveredViaTapoUnicast) {
                return null;
            }

            string? httpFingerprint = null;

            if (openPorts.Contains(80)) {
                httpFingerprint = await TryGetHttpFingerprintAsync(ipAddress, port: 80, useHttps: false, cancellationToken).ConfigureAwait(false);
            }

            if (string.IsNullOrWhiteSpace(httpFingerprint) && openPorts.Contains(8080)) {
                httpFingerprint = await TryGetHttpFingerprintAsync(ipAddress, port: 8080, useHttps: false, cancellationToken).ConfigureAwait(false);
            }

            if (string.IsNullOrWhiteSpace(httpFingerprint) && openPorts.Contains(443)) {
                httpFingerprint = await TryGetHttpFingerprintAsync(ipAddress, port: 443, useHttps: true, cancellationToken).ConfigureAwait(false);
            }

            if (string.IsNullOrWhiteSpace(httpFingerprint) && openPorts.Contains(8443)) {
                httpFingerprint = await TryGetHttpFingerprintAsync(ipAddress, port: 8443, useHttps: true, cancellationToken).ConfigureAwait(false);
            }

            return new HostProbeResult(
                ipAddress,
                openPorts,
                httpFingerprint,
                discoveredViaOnvif,
                discoveredViaTapoBroadcast,
                discoveredViaTapoUnicast);
        }

        private static CandidateEvaluation EvaluateCandidate(HostProbeResult probe, string? macAddress, string? hostName) {
            var reasons = new List<string>();
            var score = 0d;

            var hasRtsp = probe.OpenPorts.Contains(554) || probe.OpenPorts.Contains(8554);
            var hasOnvif = probe.OpenPorts.Contains(2020);
            var hasTapoControlPort = probe.OpenPorts.Contains(20002) || probe.OpenPorts.Contains(9999);
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

            if (probe.DiscoveredViaOnvif) {
                score += 2.0;
                reasons.Add("Responded to ONVIF WS-Discovery probe");
            }

            if (probe.DiscoveredViaTapoBroadcast) {
                score += 2.0;
                reasons.Add("Responded to TP-Link/Tapo local discovery probe");
            }

            if (probe.DiscoveredViaTapoUnicast) {
                score += 2.5;
                reasons.Add("Responded to direct TP-Link/Tapo UDP probe");
            }

            if (hasTapoControlPort) {
                score += 1.0;
                reasons.Add("TP-Link/Tapo control port is open (20002/9999)");
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

            var looksLikeRepeater =
                fingerprint.Contains("tplinkrepeater")
                || fingerprint.Contains("mwlogin")
                || fingerprint.Contains("repeater");
            if (looksLikeRepeater) {
                score -= 3.0;
                reasons.Add("HTTP endpoint looks like TP-Link repeater/router UI");
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
            var hasCameraService =
                hasRtsp
                || hasOnvif
                || hasTapoControlPort
                || probe.DiscoveredViaOnvif
                || probe.DiscoveredViaTapoBroadcast
                || probe.DiscoveredViaTapoUnicast;
            var hasTpLinkSignal = hasTpLinkMac || hostSuggestsTpLink || fingerprintSuggestsTpLink;

            var isLikely =
                hasStrongBrandSignal
                || (hasCameraService && hasTpLinkSignal)
                || (hasRtsp && hasOnvif)
                || (probe.DiscoveredViaOnvif && hasRtsp)
                || (probe.DiscoveredViaTapoBroadcast && (hasRtsp || hasOnvif || hasWebManagement))
                || (probe.DiscoveredViaTapoUnicast && (hasRtsp || hasOnvif || hasWebManagement || hasTpLinkSignal))
                || (hasTapoControlPort && hasTpLinkSignal && !looksLikeRepeater)
                || (hasRtsp && hasWebManagement && score >= 2.5);

            if (looksLikeRepeater
                && !hasRtsp
                && !hasOnvif
                && !probe.DiscoveredViaOnvif
                && !probe.DiscoveredViaTapoUnicast) {
                isLikely = false;
            }

            var reason = reasons.Count == 0
                ? "No Tapo-specific markers were found."
                : string.Join("; ", reasons);

            return new CandidateEvaluation(isLikely, score, reason);
        }

        private static async Task<bool> ProbeTcpPortWithRetryAsync(
            IPAddress ipAddress,
            int port,
            CancellationToken cancellationToken) {
            for (var attempt = 1; attempt <= ProbeTcpMaxAttempts; attempt++) {
                var timeout = attempt == 1 ? ProbeTcpTimeoutMsPrimary : ProbeTcpTimeoutMsRetry;
                var isOpen = await ProbeTcpPortAsync(ipAddress, port, timeout, cancellationToken).ConfigureAwait(false);
                if (isOpen) {
                    return true;
                }

                if (attempt < ProbeTcpMaxAttempts) {
                    await Task.Delay(40, cancellationToken).ConfigureAwait(false);
                }
            }

            return false;
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

        private static async Task<bool> TryProbeTapoUnicastAsync(IPAddress ipAddress, CancellationToken cancellationToken) {
            foreach (var payload in TapoDiscoveryPayloads) {
                var plainPayload = Encoding.UTF8.GetBytes(payload);
                if (await TryProbeUdpPayloadAsync(ipAddress, TapoDiscoveryPort, plainPayload, cancellationToken).ConfigureAwait(false)) {
                    return true;
                }

                var legacyPayload = EncodeTpLinkLegacyPayload(payload);
                if (await TryProbeUdpPayloadAsync(ipAddress, TpLinkLegacyDiscoveryPort, legacyPayload, cancellationToken).ConfigureAwait(false)) {
                    return true;
                }
            }

            return false;
        }

        private static async Task<bool> TryProbeUdpPayloadAsync(
            IPAddress ipAddress,
            int port,
            byte[] payload,
            CancellationToken cancellationToken) {
            try {
                using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
                await udpClient.SendAsync(payload, payload.Length, new IPEndPoint(ipAddress, port)).ConfigureAwait(false);

                var response = await udpClient.ReceiveAsync()
                    .WaitAsync(TimeSpan.FromMilliseconds(TapoUnicastProbeTimeoutMs), cancellationToken)
                    .ConfigureAwait(false);

                return response.RemoteEndPoint.Address.Equals(ipAddress);
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
            int port,
            bool useHttps,
            CancellationToken cancellationToken) {
            var scheme = useHttps ? "https" : "http";
            var paths = new[] { "/", "/index.html", "/mainFrame.htm", "/error.html" };

            try {
                var fingerprintParts = new List<string>(paths.Length * 2);

                foreach (var path in paths) {
                    cancellationToken.ThrowIfCancellationRequested();

                    using var request = new HttpRequestMessage(HttpMethod.Get, $"{scheme}://{ipAddress}:{port}{path}");
                    request.Headers.UserAgent.ParseAdd("LocalCam/1.0");
                    using var response = await ProbeHttpClient
                        .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                        .ConfigureAwait(false);

                    var serverHeader = response.Headers.Server.ToString();
                    var authHeader = response.Headers.WwwAuthenticate.ToString();
                    var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

                    if (body.Length > HttpFingerprintBodyLimit) {
                        body = body[..HttpFingerprintBodyLimit];
                    }

                    if (!string.IsNullOrWhiteSpace(serverHeader)) {
                        fingerprintParts.Add(serverHeader);
                    }

                    if (!string.IsNullOrWhiteSpace(authHeader)) {
                        fingerprintParts.Add(authHeader);
                    }

                    if (!string.IsNullOrWhiteSpace(body)) {
                        fingerprintParts.Add(body);
                    }
                }

                var fingerprint = string.Join(' ', fingerprintParts).Trim();
                return string.IsNullOrWhiteSpace(fingerprint) ? null : fingerprint;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            }
            catch {
                return null;
            }
        }

        private static async Task<HashSet<IPAddress>> DiscoverOnvifCameraAddressesAsync(
            IEnumerable<IPAddress> localAddresses,
            CancellationToken cancellationToken) {
            var discoveredAddresses = new HashSet<IPAddress>();
            var probeBytes = Encoding.UTF8.GetBytes(BuildOnvifProbePayload());
            var multicastEndpoint = new IPEndPoint(OnvifMulticastAddress, OnvifDiscoveryPort);

            foreach (var localAddress in localAddresses.DistinctBy(static ip => ip.ToString())) {
                cancellationToken.ThrowIfCancellationRequested();

                try {
                    using var udpClient = new UdpClient(new IPEndPoint(localAddress, 0));
                    await udpClient.SendAsync(probeBytes, probeBytes.Length, multicastEndpoint).ConfigureAwait(false);

                    var receiveUntil = DateTime.UtcNow.AddMilliseconds(OnvifReceiveWindowMs);
                    while (DateTime.UtcNow < receiveUntil) {
                        var remaining = receiveUntil - DateTime.UtcNow;
                        if (remaining <= TimeSpan.Zero) {
                            break;
                        }

                        UdpReceiveResult response;
                        try {
                            response = await udpClient.ReceiveAsync()
                                .WaitAsync(remaining, cancellationToken)
                                .ConfigureAwait(false);
                        }
                        catch (TimeoutException) {
                            break;
                        }

                        if (response.RemoteEndPoint.Address.AddressFamily == AddressFamily.InterNetwork
                            && !IPAddress.IsLoopback(response.RemoteEndPoint.Address)
                            && !IsApipaAddress(response.RemoteEndPoint.Address)) {
                            discoveredAddresses.Add(response.RemoteEndPoint.Address);
                        }

                        foreach (var extractedAddress in ExtractIpv4Addresses(Encoding.UTF8.GetString(response.Buffer))) {
                            discoveredAddresses.Add(extractedAddress);
                        }
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                    throw;
                }
                catch {
                    // Best-effort discovery only.
                }
            }

            return discoveredAddresses;
        }

        private static async Task<HashSet<IPAddress>> DiscoverTapoBroadcastAddressesAsync(
            IReadOnlyList<Ipv4Subnet> subnets,
            CancellationToken cancellationToken) {
            var discoveredAddresses = new HashSet<IPAddress>();
            var localAddresses = subnets
                .Select(static s => s.LocalAddress)
                .DistinctBy(static ip => ip.ToString())
                .ToArray();

            var broadcastEndpoints = BuildTapoBroadcastEndpoints(subnets);
            if (localAddresses.Length == 0 || broadcastEndpoints.Length == 0) {
                return discoveredAddresses;
            }

            var plainPayloadBytes = TapoDiscoveryPayloads
                .Select(Encoding.UTF8.GetBytes)
                .ToArray();
            var legacyEncodedPayloadBytes = TapoDiscoveryPayloads
                .Select(EncodeTpLinkLegacyPayload)
                .ToArray();

            foreach (var localAddress in localAddresses) {
                cancellationToken.ThrowIfCancellationRequested();

                try {
                    using var udpClient = new UdpClient(new IPEndPoint(localAddress, 0)) {
                        EnableBroadcast = true
                    };

                    foreach (var endpoint in broadcastEndpoints) {
                        var payloads = endpoint.Port == TpLinkLegacyDiscoveryPort
                            ? legacyEncodedPayloadBytes
                            : plainPayloadBytes;

                        foreach (var payload in payloads) {
                            await udpClient.SendAsync(payload, payload.Length, endpoint).ConfigureAwait(false);
                        }
                    }

                    var receiveUntil = DateTime.UtcNow.AddMilliseconds(TapoDiscoveryReceiveWindowMs);
                    while (DateTime.UtcNow < receiveUntil) {
                        var remaining = receiveUntil - DateTime.UtcNow;
                        if (remaining <= TimeSpan.Zero) {
                            break;
                        }

                        UdpReceiveResult response;
                        try {
                            response = await udpClient.ReceiveAsync()
                                .WaitAsync(remaining, cancellationToken)
                                .ConfigureAwait(false);
                        }
                        catch (TimeoutException) {
                            break;
                        }

                        if (response.RemoteEndPoint.Address.AddressFamily == AddressFamily.InterNetwork
                            && !IPAddress.IsLoopback(response.RemoteEndPoint.Address)
                            && !IsApipaAddress(response.RemoteEndPoint.Address)) {
                            discoveredAddresses.Add(response.RemoteEndPoint.Address);
                        }

                        foreach (var extractedAddress in ExtractIpv4Addresses(Encoding.UTF8.GetString(response.Buffer))) {
                            discoveredAddresses.Add(extractedAddress);
                        }
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                    throw;
                }
                catch {
                    // Best-effort discovery only.
                }
            }

            return discoveredAddresses;
        }

        private static IPEndPoint[] BuildTapoBroadcastEndpoints(IReadOnlyList<Ipv4Subnet> subnets) {
            var endpoints = new Dictionary<string, IPEndPoint>(StringComparer.Ordinal);

            void AddEndpoint(IPAddress address, int port) {
                var key = $"{address}:{port}";
                if (!endpoints.ContainsKey(key)) {
                    endpoints.Add(key, new IPEndPoint(address, port));
                }
            }

            AddEndpoint(IPAddress.Broadcast, TapoDiscoveryPort);
            AddEndpoint(IPAddress.Broadcast, TpLinkLegacyDiscoveryPort);

            foreach (var subnet in subnets) {
                var broadcastAddress = GetBroadcastAddress(subnet.NetworkAddress, subnet.PrefixLength);
                AddEndpoint(broadcastAddress, TapoDiscoveryPort);
                AddEndpoint(broadcastAddress, TpLinkLegacyDiscoveryPort);
            }

            return endpoints.Values.ToArray();
        }

        private static byte[] EncodeTpLinkLegacyPayload(string payload) {
            var source = Encoding.UTF8.GetBytes(payload);
            var encoded = new byte[source.Length];
            byte key = 0xAB;

            for (var i = 0; i < source.Length; i++) {
                var encrypted = (byte)(source[i] ^ key);
                encoded[i] = encrypted;
                key = encrypted;
            }

            return encoded;
        }

        private static string BuildOnvifProbePayload() {
            var messageId = $"uuid:{Guid.NewGuid()}";

            return $"""
<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>{messageId}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>
""";
        }

        private static IEnumerable<IPAddress> ExtractIpv4Addresses(string payload) {
            foreach (Match match in Ipv4AddressPattern.Matches(payload)) {
                if (!IPAddress.TryParse(match.Value, out var parsedAddress)) {
                    continue;
                }

                if (parsedAddress.AddressFamily != AddressFamily.InterNetwork
                    || IPAddress.IsLoopback(parsedAddress)
                    || IsApipaAddress(parsedAddress)) {
                    continue;
                }

                yield return parsedAddress;
            }
        }

        private static async Task PrimeArpCacheAsync(
            IReadOnlyList<IPAddress> hostAddresses,
            CancellationToken cancellationToken) {
            if (hostAddresses.Count == 0) {
                return;
            }

            var targets = hostAddresses
                .Take(MaxArpPrimeHosts)
                .Where(static ip =>
                    ip.AddressFamily == AddressFamily.InterNetwork
                    && !IPAddress.IsLoopback(ip)
                    && !IsApipaAddress(ip))
                .ToArray();

            await Parallel.ForEachAsync(
                targets,
                new ParallelOptions {
                    MaxDegreeOfParallelism = 192,
                    CancellationToken = cancellationToken
                },
                async (ipAddress, token) => {
                    try {
                        using var ping = new Ping();
                        await ping.SendPingAsync(ipAddress, ArpPrimePingTimeoutMs)
                            .WaitAsync(TimeSpan.FromMilliseconds(ArpPrimePingTimeoutMs + 120), token)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (token.IsCancellationRequested) {
                        throw;
                    }
                    catch {
                        // Priming is best-effort only.
                    }
                }).ConfigureAwait(false);
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

        private static Dictionary<IPAddress, string> MergeArpTables(
            Dictionary<IPAddress, string> seedTable,
            Dictionary<IPAddress, string> postProbeTable) {
            var merged = new Dictionary<IPAddress, string>(seedTable);
            foreach (var entry in postProbeTable) {
                merged[entry.Key] = entry.Value;
            }

            return merged;
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

                var gatewayAddresses = ipProperties.GatewayAddresses
                    .Select(static g => g.Address)
                    .Where(static a =>
                        a.AddressFamily == AddressFamily.InterNetwork
                        && !IPAddress.Any.Equals(a))
                    .DistinctBy(static a => a.ToString())
                    .ToArray();

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

                    var networkAddress = IpToUInt32(ipAddress) & PrefixMask(prefixLength);
                    var key = $"{networkAddress}/{prefixLength}";
                    if (!seen.Add(key)) {
                        continue;
                    }

                    subnets.Add(new Ipv4Subnet(ipAddress, networkAddress, prefixLength, gatewayAddresses));
                }
            }

            return subnets;
        }

        private static IEnumerable<IPAddress> EnumerateHostAddresses(Ipv4Subnet subnet) {
            var hostBits = 32 - subnet.PrefixLength;
            if (hostBits <= 0) {
                yield break;
            }

            var hostCount = (1UL << hostBits) - 2UL;
            if (hostCount < 1UL) {
                yield break;
            }

            var localAddressValue = IpToUInt32(subnet.LocalAddress);
            if (hostCount > MaxHostsForFullSubnetScan) {
                foreach (var largeSubnetAddress in EnumerateLargeSubnetHosts(subnet, localAddressValue, hostCount)) {
                    yield return largeSubnetAddress;
                }

                yield break;
            }

            for (var offset = 1UL; offset <= hostCount; offset++) {
                var value = subnet.NetworkAddress + (uint)offset;
                if (value == localAddressValue) {
                    continue;
                }

                yield return UInt32ToIp(value);
            }
        }

        private static IEnumerable<IPAddress> EnumerateLargeSubnetHosts(
            Ipv4Subnet subnet,
            uint localAddressValue,
            ulong hostCount) {
            var networkStart = subnet.NetworkAddress + 1u;
            var networkEnd = subnet.NetworkAddress + (uint)hostCount;
            var chunkStarts = BuildPreferredChunkStarts(subnet, networkStart, networkEnd, localAddressValue);
            var yielded = new HashSet<uint>();

            foreach (var chunkStart in chunkStarts) {
                var chunkHostStart = Math.Max(networkStart, chunkStart + 1u);
                var chunkHostEnd = Math.Min(networkEnd, chunkStart + 254u);
                if (chunkHostStart > chunkHostEnd) {
                    continue;
                }

                for (var value = chunkHostStart; value <= chunkHostEnd; value++) {
                    if (value == localAddressValue) {
                        continue;
                    }

                    if (yielded.Add(value)) {
                        yield return UInt32ToIp(value);
                    }
                }
            }
        }

        private static IReadOnlyList<uint> BuildPreferredChunkStarts(
            Ipv4Subnet subnet,
            uint networkStart,
            uint networkEnd,
            uint localAddressValue) {
            var chunkStarts = new List<uint>(MaxLargeSubnetChunks);
            var seenChunks = new HashSet<uint>();

            void TryAddChunkStart(uint chunkStart) {
                if (chunkStarts.Count >= MaxLargeSubnetChunks) {
                    return;
                }

                var hasAnyHostsInChunk = chunkStart + 1u <= networkEnd && chunkStart + 254u >= networkStart;
                if (!hasAnyHostsInChunk) {
                    return;
                }

                if (seenChunks.Add(chunkStart)) {
                    chunkStarts.Add(chunkStart);
                }
            }

            var localChunk = ToClassCNetwork(localAddressValue);
            TryAddChunkStart(localChunk);

            foreach (var gatewayAddress in subnet.GatewayAddresses) {
                TryAddChunkStart(ToClassCNetwork(IpToUInt32(gatewayAddress)));
            }

            TryAddChunkStart(ToClassCNetwork(networkStart));
            TryAddChunkStart(ToClassCNetwork(networkEnd));

            var seedChunks = chunkStarts.ToArray();
            for (var radius = 1; radius <= 2 && chunkStarts.Count < MaxLargeSubnetChunks; radius++) {
                foreach (var seedChunk in seedChunks) {
                    var lowerNeighbor = ShiftChunkStart(seedChunk, -radius);
                    if (lowerNeighbor is uint lowerChunk) {
                        TryAddChunkStart(lowerChunk);
                    }

                    var upperNeighbor = ShiftChunkStart(seedChunk, radius);
                    if (upperNeighbor is uint upperChunk) {
                        TryAddChunkStart(upperChunk);
                    }

                    if (chunkStarts.Count >= MaxLargeSubnetChunks) {
                        break;
                    }
                }
            }

            if (chunkStarts.Count < MaxLargeSubnetChunks) {
                var firstChunk = ToClassCNetwork(networkStart);
                var lastChunk = ToClassCNetwork(networkEnd);
                var totalChunks = ((ulong)(lastChunk - firstChunk) / LargeSubnetChunkSize) + 1UL;
                var remaining = MaxLargeSubnetChunks - chunkStarts.Count;
                var stride = totalChunks > (ulong)remaining
                    ? Math.Max(1UL, totalChunks / (ulong)remaining)
                    : 1UL;

                for (var chunk = (ulong)firstChunk;
                     chunk <= lastChunk && chunkStarts.Count < MaxLargeSubnetChunks;
                     chunk += stride * LargeSubnetChunkSize) {
                    TryAddChunkStart((uint)chunk);
                }
            }

            return chunkStarts;
        }

        private static uint ToClassCNetwork(uint address) {
            return address & 0xFFFFFF00u;
        }

        private static uint? ShiftChunkStart(uint chunkStart, int chunkOffset) {
            var shifted = (long)chunkStart + (long)chunkOffset * LargeSubnetChunkSize;
            if (shifted < 0 || shifted > uint.MaxValue) {
                return null;
            }

            return (uint)shifted;
        }

        private static string FormatSubnetDiagnostic(Ipv4Subnet subnet) {
            var networkAddress = UInt32ToIp(subnet.NetworkAddress);
            var gateways = subnet.GatewayAddresses
                .Select(static g => g.ToString())
                .ToArray();

            if (gateways.Length == 0) {
                return $"{networkAddress}/{subnet.PrefixLength} (local {subnet.LocalAddress})";
            }

            return $"{networkAddress}/{subnet.PrefixLength} (local {subnet.LocalAddress}, gateway {string.Join(", ", gateways)})";
        }

        private static uint PrefixMask(int prefixLength) {
            return prefixLength == 0
                ? 0u
                : uint.MaxValue << (32 - prefixLength);
        }

        private static IPAddress GetBroadcastAddress(uint networkAddress, int prefixLength) {
            var hostMask = ~PrefixMask(prefixLength);
            return UInt32ToIp(networkAddress | hostMask);
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
                Timeout = TimeSpan.FromMilliseconds(2600)
            };
        }

        private readonly record struct Ipv4Subnet(
            IPAddress LocalAddress,
            uint NetworkAddress,
            int PrefixLength,
            IReadOnlyList<IPAddress> GatewayAddresses);

        private sealed record HostProbeResult(
            IPAddress IpAddress,
            IReadOnlyList<int> OpenPorts,
            string? HttpFingerprint,
            bool DiscoveredViaOnvif,
            bool DiscoveredViaTapoBroadcast,
            bool DiscoveredViaTapoUnicast);

        private readonly record struct CandidateEvaluation(bool IsLikelyTapo, double Score, string Reason);
    }
}
