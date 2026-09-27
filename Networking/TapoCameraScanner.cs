using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using LocalCam.Services;

namespace LocalCam.Networking {
    public sealed record TapoCameraDetection(
        IPAddress IpAddress,
        string? HostName,
        string? MacAddress,
        IReadOnlyList<int> OpenPorts,
        double ConfidenceScore,
        string DetectionReason,
        int RtspPort = 554);

    public sealed record TapoCameraCandidateDiagnostics(
        IPAddress IpAddress,
        bool IsLikelyTapo,
        double ConfidenceScore,
        string Reason,
        string? HostName,
        string? MacAddress,
        bool SeenInArpTable,
        bool DiscoveredViaOnvif,
        bool DiscoveredViaSsdp,
        bool DiscoveredViaMdns,
        bool DiscoveredViaRtspOptions,
        bool DiscoveredViaTapoBroadcast,
        bool DiscoveredViaTapoUnicast,
        IReadOnlyList<int> OpenPorts,
        bool DiscoveredViaRtspDescribe = false,
        bool RtspAuthenticationRequired = false);

    public sealed record TapoScanDiagnostics(
        IReadOnlyList<string> SubnetsScanned,
        int EnumeratedHostCount,
        int ArpSeedCount,
        int OnvifHintCount,
        int SsdpCameraHintCount,
        int MdnsCameraHintCount,
        int RtspOptionsHintCount,
        int TapoBroadcastHintCount,
        int TapoUnicastHintCount,
        int ResponsiveHostCount,
        IReadOnlyList<TapoCameraCandidateDiagnostics> Candidates);

    public enum TapoDetectionMethod {
        OnvifWsDiscovery,
        SsdpUpnpSearch,
        TapoUdpBroadcast,
        MdnsDnsSdSweep,
        ArpSeededTargetProbe,
        SubnetProbeFallback,
        RtspOptionsProbe,
        AdaptiveRtspVerificationProbe
    }

    public sealed record TapoDetectionMethodAttempt(
        TapoDetectionMethod Method,
        bool Succeeded,
        int DetectionCount,
        long DurationMs,
        string StatusMessage);

    public sealed record TapoCameraScanActivity(
        TapoDetectionMethod? Method,
        string StatusMessage,
        IReadOnlyList<TapoCameraDetection>? Detections = null);

    public sealed record TapoCameraScanResult(
        IReadOnlyList<TapoCameraDetection> Detections,
        TapoScanDiagnostics Diagnostics,
        TapoDetectionMethod? SuccessfulMethod,
        IReadOnlyList<TapoDetectionMethodAttempt> AttemptedMethods);

    public static class TapoCameraScanner {
        private const int MaxHostsForFullSubnetScan = 1024;
        private const int LargeSubnetChunkSize = 256;
        private const int MaxLargeSubnetChunks = 4;
        private const int OnvifDiscoveryPort = 3702;
        private const int OnvifReceiveWindowMs = 1800;
        private const int SsdpDiscoveryPort = 1900;
        private const int SsdpReceiveWindowMs = 1800;
        private const int MdnsDiscoveryPort = 5353;
        private const int MdnsReceiveWindowMs = 1500;
        private const int TapoDiscoveryPort = 20002;
        private const int TpLinkLegacyDiscoveryPort = 9999;
        private const int TapoDiscoveryReceiveWindowMs = 2200;
        private const int RtspOptionsTimeoutMs = 650;
        private const int MaxSsdpDescriptionFetches = 128;
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
        private static readonly IPAddress SsdpMulticastAddress = IPAddress.Parse("239.255.255.250");
        private static readonly IPAddress MdnsMulticastAddress = IPAddress.Parse("224.0.0.251");
        private static readonly TapoDetectionMethod[] DetectionMethodOrder = [
            TapoDetectionMethod.TapoUdpBroadcast,
            TapoDetectionMethod.OnvifWsDiscovery,
            TapoDetectionMethod.MdnsDnsSdSweep,
            TapoDetectionMethod.SsdpUpnpSearch,
            TapoDetectionMethod.ArpSeededTargetProbe,
            TapoDetectionMethod.RtspOptionsProbe,
            TapoDetectionMethod.SubnetProbeFallback
        ];
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
            TapoDetectionMethod? preferredFirstMethod = null,
            IProgress<TapoCameraScanActivity>? progress = null,
            CancellationToken cancellationToken = default) {
            var scanResult = await ScanLocalNetworkForTapoCamerasWithDiagnosticsAsync(
                maxParallelism,
                preferredFirstMethod,
                progress,
                cancellationToken).ConfigureAwait(false);

            return scanResult.Detections;
        }

        public static async Task<TapoCameraScanResult> ScanLocalNetworkForTapoCamerasWithDiagnosticsAsync(
            int maxParallelism = 64,
            TapoDetectionMethod? preferredFirstMethod = null,
            IProgress<TapoCameraScanActivity>? progress = null,
            CancellationToken cancellationToken = default,
            IReadOnlyList<IPAddress>? recentCameraAddresses = null,
            string? streamPath = null) {
            if (maxParallelism < 1) {
                throw new ArgumentOutOfRangeException(nameof(maxParallelism), "Parallelism must be at least 1.");
            }

            var startedAtUtc = DateTimeOffset.UtcNow;
            var subnets = GetCandidateSubnets();
            var networkInterfaces = CameraNetworkTopology.GetInterfaces();
            JsonLogStore.Information(
                eventName: "camera_search_started",
                message: "Starting local network scan for likely Tapo cameras.",
                category: "camera_search",
                data: new Dictionary<string, object?> {
                    ["maxParallelism"] = maxParallelism,
                    ["subnetCount"] = subnets.Count,
                    ["subnets"] = subnets.Select(FormatSubnetDiagnostic).ToArray(),
                    ["networkInterfaces"] = networkInterfaces,
                    ["networkKinds"] = networkInterfaces.Select(static item => item.Kind).Distinct().ToArray()
                });

            if (preferredFirstMethod is TapoDetectionMethod preferredMethod) {
                JsonLogStore.Information(
                    eventName: "camera_search_preferred_method_loaded",
                    message: "Prioritizing the last successful camera detection method.",
                    category: "camera_search",
                    data: new Dictionary<string, object?> {
                        ["preferredMethod"] = preferredMethod.ToString()
                    });
            }

            var subnetHosts = subnets
                .SelectMany(EnumerateHostAddresses)
                .DistinctBy(static ip => ip.ToString())
                .ToArray();
            var enumeratedSubnetHosts = subnetHosts;

            JsonLogStore.Information(
                eventName: "camera_search_phase_complete",
                message: "Candidate subnet enumeration completed.",
                category: "camera_search",
                data: new Dictionary<string, object?> {
                    ["phase"] = "enumerate_subnets",
                    ["elapsedMs"] = (long)(DateTimeOffset.UtcNow - startedAtUtc).TotalMilliseconds,
                    ["subnetCount"] = subnets.Count,
                    ["enumeratedHostCount"] = enumeratedSubnetHosts.Length
                });

            JsonLogStore.Information(
                eventName: "camera_search_phase_started",
                message: "Priming ARP cache for candidate hosts.",
                category: "camera_search",
                data: new Dictionary<string, object?> {
                    ["phase"] = "prime_arp",
                    ["hostCount"] = subnetHosts.Length
                });

            try {
                await PrimeArpCacheAsync(subnetHosts, cancellationToken).ConfigureAwait(false);

                JsonLogStore.Information(
                    eventName: "camera_search_phase_complete",
                    message: "ARP cache priming completed.",
                    category: "camera_search",
                    data: new Dictionary<string, object?> {
                        ["phase"] = "prime_arp",
                        ["elapsedMs"] = (long)(DateTimeOffset.UtcNow - startedAtUtc).TotalMilliseconds,
                        ["hostCount"] = subnetHosts.Length
                    });

                JsonLogStore.Information(
                    eventName: "camera_search_phase_started",
                    message: "Reading ARP table before host probing.",
                    category: "camera_search",
                    data: new Dictionary<string, object?> {
                        ["phase"] = "read_arp"
                    });

                var arpSeedTable = await ReadArpTableAsync(cancellationToken).ConfigureAwait(false);

                JsonLogStore.Information(
                    eventName: "camera_search_phase_complete",
                    message: "Initial ARP table read completed.",
                    category: "camera_search",
                    data: new Dictionary<string, object?> {
                        ["phase"] = "read_arp",
                        ["elapsedMs"] = (long)(DateTimeOffset.UtcNow - startedAtUtc).TotalMilliseconds,
                        ["arpSeedCount"] = arpSeedTable.Count
                    });

                var subnetDiagnostics = subnets
                    .OrderBy(static s => s.NetworkAddress)
                    .ThenBy(static s => s.PrefixLength)
                    .Select(FormatSubnetDiagnostic)
                    .ToList();

                if (enumeratedSubnetHosts.Length == 0 && arpSeedTable.Count == 0 && networkInterfaces.Count == 0) {
                    var emptyResult = new TapoCameraScanResult(
                        Array.Empty<TapoCameraDetection>(),
                        new TapoScanDiagnostics(
                            subnetDiagnostics,
                            EnumeratedHostCount: enumeratedSubnetHosts.Length,
                            ArpSeedCount: arpSeedTable.Count,
                            OnvifHintCount: 0,
                            SsdpCameraHintCount: 0,
                            MdnsCameraHintCount: 0,
                            RtspOptionsHintCount: 0,
                            TapoBroadcastHintCount: 0,
                            TapoUnicastHintCount: 0,
                            ResponsiveHostCount: 0,
                            Candidates: Array.Empty<TapoCameraCandidateDiagnostics>()),
                        SuccessfulMethod: null,
                        AttemptedMethods: Array.Empty<TapoDetectionMethodAttempt>());

                    JsonLogStore.Information(
                        eventName: "camera_search_completed",
                        message: "Local network scan completed without candidate hosts.",
                        category: "camera_search",
                        data: new Dictionary<string, object?> {
                            ["elapsedMs"] = (long)(DateTimeOffset.UtcNow - startedAtUtc).TotalMilliseconds,
                            ["detectionCount"] = emptyResult.Detections.Count,
                            ["responsiveHostCount"] = emptyResult.Diagnostics.ResponsiveHostCount,
                            ["subnetCount"] = emptyResult.Diagnostics.SubnetsScanned.Count
                        });

                    return emptyResult;
                }

                var localAddresses = subnets
                    .Select(static s => s.LocalAddress)
                    .DistinctBy(static ip => ip.ToString())
                    .ToArray();
                HashSet<IPAddress>? onvifHints = null;
                HashSet<IPAddress>? ssdpHints = null;
                HashSet<IPAddress>? tapoBroadcastHints = null;
                HashSet<IPAddress>? mdnsHints = null;
                var attemptedMethods = new List<TapoDetectionMethodAttempt>();
                var aggregatedCandidates = new Dictionary<string, TapoCameraCandidateDiagnostics>(StringComparer.Ordinal);
                var aggregatedDetections = new Dictionary<string, TapoCameraDetection>(StringComparer.Ordinal);
                var probedHosts = new ConcurrentDictionary<IPAddress, ProbeCacheEntry>();
                TapoDetectionMethod? successfulMethod = null;
                var adaptiveHostCount = 0;
                var parallelPriorityMethodHints = new Dictionary<TapoDetectionMethod, DiscoveryHintResult>();
                var priorityMethodsStartedTogether = false;
                var preferredMethodIsPriorityMethod = preferredFirstMethod is
                    TapoDetectionMethod.TapoUdpBroadcast or TapoDetectionMethod.OnvifWsDiscovery;
                var priorityMethodsStartedAtUtc = DateTimeOffset.MinValue;

                foreach (var method in BuildAttemptOrder(preferredFirstMethod)) {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (!priorityMethodsStartedTogether &&
                        !preferredMethodIsPriorityMethod &&
                        method == TapoDetectionMethod.TapoUdpBroadcast) {
                        priorityMethodsStartedTogether = true;
                        priorityMethodsStartedAtUtc = DateTimeOffset.UtcNow;
                        var priorityMethods = new[] {
                            TapoDetectionMethod.TapoUdpBroadcast,
                            TapoDetectionMethod.OnvifWsDiscovery
                        };
                        foreach (var priorityMethod in priorityMethods) {
                            progress?.Report(new TapoCameraScanActivity(
                                priorityMethod,
                                BuildMethodStartMessage(priorityMethod, isPreferred: false)));
                            JsonLogStore.Information(
                                eventName: "camera_search_method_started",
                                message: BuildMethodStartMessage(priorityMethod, isPreferred: false),
                                category: "camera_search",
                                data: new Dictionary<string, object?> {
                                    ["method"] = priorityMethod.ToString(),
                                    ["preferred"] = false,
                                    ["parallelPriorityGroup"] = true
                                });
                        }

                        JsonLogStore.Information(
                            eventName: "camera_search_priority_methods_started_together",
                            message: "Starting Tapo local discovery and ONVIF WS-Discovery concurrently.",
                            category: "camera_search");
                        var tapoHintsTask = CaptureDiscoveryHintsAsync(
                            token => DiscoverTapoBroadcastAddressesAsync(subnets, token),
                            cancellationToken);
                        var onvifHintsTask = CaptureDiscoveryHintsAsync(
                            token => DiscoverOnvifCameraAddressesAsync(localAddresses, subnets, token),
                            cancellationToken);
                        await Task.WhenAll(tapoHintsTask, onvifHintsTask).ConfigureAwait(false);
                        parallelPriorityMethodHints[TapoDetectionMethod.TapoUdpBroadcast] = await tapoHintsTask.ConfigureAwait(false);
                        parallelPriorityMethodHints[TapoDetectionMethod.OnvifWsDiscovery] = await onvifHintsTask.ConfigureAwait(false);
                        tapoBroadcastHints = parallelPriorityMethodHints[TapoDetectionMethod.TapoUdpBroadcast].Addresses;
                        onvifHints = parallelPriorityMethodHints[TapoDetectionMethod.OnvifWsDiscovery].Addresses;
                    }

                    var hasParallelPriorityHints = parallelPriorityMethodHints.TryGetValue(method, out var parallelHints);
                    var startMessage = BuildMethodStartMessage(method, preferredFirstMethod == method);
                    if (!hasParallelPriorityHints) {
                        progress?.Report(new TapoCameraScanActivity(method, startMessage));
                        JsonLogStore.Information(
                            eventName: "camera_search_method_started",
                            message: startMessage,
                            category: "camera_search",
                            data: new Dictionary<string, object?> {
                                ["method"] = method.ToString(),
                                ["preferred"] = preferredFirstMethod == method
                            });
                    }

                    var methodStartedAtUtc = hasParallelPriorityHints
                        ? priorityMethodsStartedAtUtc
                        : DateTimeOffset.UtcNow;

                    try {
                        MethodExecutionResult executionResult;
                        switch (method) {
                            case TapoDetectionMethod.AdaptiveRtspVerificationProbe: {
                                var candidates = AdaptiveCameraNetworkPlanner.BuildCandidates(
                                    networkInterfaces,
                                    recentCameraAddresses ?? []);
                                var routedCandidates = candidates
                                    .Where(candidate => CameraNetworkTopology.ClassifyRoute(
                                        candidate.Range.EnumerateHosts().First(), networkInterfaces) != "no-local-route-evidence")
                                    .ToArray();
                                var responsiveGateways = await ProbeAdaptiveGatewayCluesAsync(
                                    routedCandidates, cancellationToken).ConfigureAwait(false);
                                var initialRanges = AdaptiveCameraNetworkPlanner.SelectRangesForProbe(
                                    routedCandidates, responsiveGateways);
                                var attemptedRanges = new HashSet<Ipv4CidrRange>();
                                var allCandidates = new List<TapoCameraCandidateDiagnostics>();
                                var allDetections = new List<TapoCameraDetection>();
                                var rtspEndpointCount = 0;

                                for (var stageIndex = 0;
                                     stageIndex < AdaptiveCameraNetworkPlanner.MaxExpansionStages
                                     && attemptedRanges.Count < AdaptiveCameraNetworkPlanner.MaxTotalExpandedRanges;
                                     stageIndex++) {
                                    cancellationToken.ThrowIfCancellationRequested();
                                    var selectedRanges = stageIndex == 0
                                        ? initialRanges
                                        : AdaptiveCameraNetworkPlanner.SelectNextStageRangesForProbe(
                                            routedCandidates,
                                            responsiveGateways,
                                            attemptedRanges);
                                    if (selectedRanges.Count == 0) {
                                        break;
                                    }

                                    foreach (var selectedRange in selectedRanges) {
                                        attemptedRanges.Add(selectedRange.Range);
                                        subnetDiagnostics.Add($"{selectedRange.Range} (automatic unicast search)");
                                    }

                                    var adaptiveHosts = selectedRanges
                                        .SelectMany(static candidate => candidate.Range.EnumerateHosts())
                                        .DistinctBy(static address => address.ToString())
                                        .ToArray();
                                    adaptiveHostCount += adaptiveHosts.Length;
                                    JsonLogStore.Information(
                                        eventName: "camera_search_adaptive_plan",
                                        message: "Selected bounded additional camera networks from current network evidence.",
                                        category: "camera_search",
                                        data: new Dictionary<string, object?> {
                                            ["stage"] = stageIndex + 1,
                                            ["stageLimit"] = AdaptiveCameraNetworkPlanner.MaxExpansionStages,
                                            ["candidateRangeCount"] = candidates.Count,
                                            ["routedRangeCount"] = routedCandidates.Length,
                                            ["responsiveGatewayCount"] = responsiveGateways.Count,
                                            ["selectedRanges"] = selectedRanges.Select(static candidate => candidate.Range.ToString()).ToArray(),
                                            ["sources"] = selectedRanges.Select(static candidate => candidate.Source).ToArray(),
                                            ["targetRouteClasses"] = selectedRanges.Select(candidate => CameraNetworkTopology.ClassifyRoute(
                                                candidate.Range.EnumerateHosts().First(), networkInterfaces)).ToArray(),
                                            ["stageHostCount"] = adaptiveHosts.Length,
                                            ["cumulativeHostCount"] = adaptiveHostCount
                                        });

                                    var stageResult = await ProbeAndEvaluateCandidatesAsync(
                                        adaptiveHosts,
                                        arpSeedTable,
                                        maxParallelism,
                                        discoveredViaOnvifHints: null,
                                        discoveredViaTapoBroadcastHints: null,
                                        discoveredViaSsdpHints: null,
                                        discoveredViaMdnsHints: null,
                                        "Extended network search did not detect a compatible camera.",
                                        probedHosts,
                                        cancellationToken).ConfigureAwait(false);
                                    allCandidates.AddRange(stageResult.Candidates);
                                    allDetections.AddRange(stageResult.Detections);
                                    MergeDetections(aggregatedDetections, stageResult.Detections);

                                    var remainingRtspTargets = AdaptiveRtspVerificationProbe.MaxTargets - rtspEndpointCount;
                                    var rtspTargets = AdaptiveRtspVerificationProbe.SelectTargets(
                                        stageResult.Candidates,
                                        stageResult.Detections,
                                        remainingRtspTargets);
                                    rtspEndpointCount += rtspTargets.Count;
                                    var rtspOutcomes = await AdaptiveRtspVerificationProbe.ProbeAsync(
                                        rtspTargets,
                                        streamPath,
                                        maxParallelism,
                                        cancellationToken).ConfigureAwait(false);
                                    var verifiedDetections = new List<TapoCameraDetection>();
                                    var verifiedCandidates = new List<TapoCameraCandidateDiagnostics>();
                                    foreach (var outcome in rtspOutcomes.Where(static outcome => outcome.Verified)) {
                                        var requiresAuthentication = outcome.AuthenticationRequired;
                                        var reason = outcome.AuthenticationChallengeReceived
                                            ? $"RTSP endpoint requested authentication after {outcome.RequestMethod}."
                                            : $"RTSP endpoint responded to {outcome.RequestMethod} with status {outcome.StatusCode}.";
                                        var candidate = outcome.Target.Candidate with {
                                            IsLikelyTapo = true,
                                            ConfidenceScore = Math.Max(outcome.Target.Candidate.ConfidenceScore, 2.0),
                                            Reason = reason,
                                            DiscoveredViaRtspOptions = outcome.Target.Candidate.DiscoveredViaRtspOptions || outcome.OptionsConfirmed,
                                            DiscoveredViaRtspDescribe = outcome.Target.Candidate.DiscoveredViaRtspDescribe || outcome.DescribeConfirmed,
                                            RtspAuthenticationRequired = requiresAuthentication
                                        };
                                        verifiedCandidates.Add(candidate);
                                        verifiedDetections.Add(new TapoCameraDetection(
                                            outcome.Target.IpAddress,
                                            candidate.HostName,
                                            candidate.MacAddress,
                                            candidate.OpenPorts,
                                            candidate.ConfidenceScore,
                                            candidate.Reason,
                                            outcome.Target.Port));
                                    }

                                    allCandidates.AddRange(verifiedCandidates);
                                    allDetections.AddRange(verifiedDetections);
                                    MergeDetections(aggregatedDetections, verifiedDetections);
                                    if (aggregatedDetections.Count > 0) {
                                        var stageDetections = aggregatedDetections.Values
                                            .OrderBy(static detection => IpToUInt32(detection.IpAddress))
                                            .ToArray();
                                        progress?.Report(new TapoCameraScanActivity(
                                            method,
                                            $"Found {stageDetections.Length} {Pluralize(stageDetections.Length, "camera")}. Continuing extended search...",
                                            stageDetections));
                                    }
                                    JsonLogStore.Information(
                                        eventName: "camera_search_adaptive_rtsp_verification",
                                        message: "Adaptive RTSP verification completed for reachable RTSP endpoints.",
                                        category: "camera_search",
                                        data: new Dictionary<string, object?> {
                                            ["stage"] = stageIndex + 1,
                                            ["eligibleEndpointCount"] = rtspTargets.Count,
                                            ["cumulativeEndpointCount"] = rtspEndpointCount,
                                            ["verifiedEndpointCount"] = rtspOutcomes.Count(static outcome => outcome.Verified),
                                            ["authenticationChallengeCount"] = rtspOutcomes.Count(static outcome => outcome.AuthenticationChallengeReceived),
                                            ["timeoutCount"] = rtspOutcomes.Count(static outcome => outcome.Outcome == "timeout"),
                                            ["unverifiedEndpointCount"] = rtspOutcomes.Count(static outcome => !outcome.Verified),
                                            ["targetOutcomes"] = rtspOutcomes.Select(static outcome => new {
                                                ipAddress = outcome.Target.IpAddress.ToString(),
                                                port = outcome.Target.Port,
                                                portWasConfirmedOpen = outcome.Target.PortWasConfirmedOpen,
                                                outcome.Outcome,
                                                outcome.RequestMethod,
                                                outcome.StatusCode,
                                                outcome.AuthenticationRequired,
                                                outcome.AuthenticationChallengeReceived
                                            }).ToArray()
                                        });

                                }

                                var statusMessage = allDetections.Count > 0
                                    ? $"Detected {allDetections.Count} {Pluralize(allDetections.Count, "camera")}."
                                    : "Extended network search did not detect a compatible camera.";
                                executionResult = new MethodExecutionResult(allDetections, allCandidates, statusMessage);
                                break;
                            }
                            case TapoDetectionMethod.OnvifWsDiscovery:
                                if (hasParallelPriorityHints) {
                                    if (parallelHints!.Failure is not null) {
                                        throw parallelHints.Failure;
                                    }
                                    onvifHints = parallelHints.Addresses;
                                }
                                else {
                                    onvifHints ??= await DiscoverOnvifCameraAddressesAsync(localAddresses, subnets, cancellationToken).ConfigureAwait(false);
                                }
                                executionResult = await ExecuteHintMethodAsync(
                                    method,
                                    onvifHints,
                                    arpSeedTable,
                                    maxParallelism,
                                    discoveredViaOnvif: true,
                                    discoveredViaTapoBroadcast: false,
                                    discoveredViaSsdp: false,
                                    discoveredViaMdns: false,
                                    probedHosts,
                                    cancellationToken).ConfigureAwait(false);
                                break;
                            case TapoDetectionMethod.SsdpUpnpSearch:
                                ssdpHints ??= await DiscoverSsdpAddressesAsync(localAddresses, subnets, cancellationToken).ConfigureAwait(false);
                                executionResult = await ExecuteHintMethodAsync(
                                    method,
                                    ssdpHints,
                                    arpSeedTable,
                                    maxParallelism,
                                    discoveredViaOnvif: false,
                                    discoveredViaTapoBroadcast: false,
                                    discoveredViaSsdp: true,
                                    discoveredViaMdns: false,
                                    probedHosts,
                                    cancellationToken).ConfigureAwait(false);
                                break;
                            case TapoDetectionMethod.TapoUdpBroadcast:
                                if (hasParallelPriorityHints) {
                                    if (parallelHints!.Failure is not null) {
                                        throw parallelHints.Failure;
                                    }
                                    tapoBroadcastHints = parallelHints.Addresses;
                                }
                                else {
                                    tapoBroadcastHints ??= await DiscoverTapoBroadcastAddressesAsync(subnets, cancellationToken).ConfigureAwait(false);
                                }
                                executionResult = await ExecuteHintMethodAsync(
                                    method,
                                    tapoBroadcastHints,
                                    arpSeedTable,
                                    maxParallelism,
                                    discoveredViaOnvif: false,
                                    discoveredViaTapoBroadcast: true,
                                    discoveredViaSsdp: false,
                                    discoveredViaMdns: false,
                                    probedHosts,
                                    cancellationToken).ConfigureAwait(false);
                                break;
                            case TapoDetectionMethod.MdnsDnsSdSweep:
                                mdnsHints ??= await DiscoverMdnsCandidateAddressesAsync(localAddresses, subnets, cancellationToken).ConfigureAwait(false);
                                executionResult = await ExecuteHintMethodAsync(
                                    method,
                                    mdnsHints,
                                    arpSeedTable,
                                    maxParallelism,
                                    discoveredViaOnvif: false,
                                    discoveredViaTapoBroadcast: false,
                                    discoveredViaSsdp: false,
                                    discoveredViaMdns: true,
                                    probedHosts,
                                    cancellationToken).ConfigureAwait(false);
                                break;
                            case TapoDetectionMethod.ArpSeededTargetProbe:
                                executionResult = await ExecuteArpSeededMethodAsync(
                                    arpSeedTable,
                                    subnets,
                                    maxParallelism,
                                    probedHosts,
                                    cancellationToken).ConfigureAwait(false);
                                break;
                            case TapoDetectionMethod.RtspOptionsProbe: {
                                var rtspCandidates = enumeratedSubnetHosts
                                    .Concat(arpSeedTable.Keys)
                                    .Concat(onvifHints ?? [])
                                    .Concat(ssdpHints ?? [])
                                    .Concat(tapoBroadcastHints ?? [])
                                    .Concat(mdnsHints ?? [])
                                    .DistinctBy(static address => address.ToString())
                                    .ToArray();
                                executionResult = await ProbeAndEvaluateCandidatesAsync(
                                    rtspCandidates,
                                    arpSeedTable,
                                    maxParallelism,
                                    onvifHints,
                                    tapoBroadcastHints,
                                    ssdpHints,
                                    mdnsHints,
                                    "RTSP did not confirm any compatible camera services.",
                                    probedHosts,
                                    cancellationToken).ConfigureAwait(false);
                                break;
                            }
                            case TapoDetectionMethod.SubnetProbeFallback:
                                executionResult = await ExecuteSubnetProbeFallbackAsync(
                                    enumeratedSubnetHosts,
                                    arpSeedTable,
                                    onvifHints,
                                    ssdpHints,
                                    tapoBroadcastHints,
                                    mdnsHints,
                                    maxParallelism,
                                    probedHosts,
                                    cancellationToken).ConfigureAwait(false);
                                break;

                            default:
                                throw new InvalidOperationException($"Unknown camera detection method '{method}'.");
                        }

                        MergeCandidates(aggregatedCandidates, executionResult.Candidates);
                        MergeDetections(aggregatedDetections, executionResult.Detections);
                        var durationMs = (long)(DateTimeOffset.UtcNow - methodStartedAtUtc).TotalMilliseconds;
                        attemptedMethods.Add(new TapoDetectionMethodAttempt(
                            method,
                            executionResult.Detections.Count > 0,
                            executionResult.Detections.Count,
                            durationMs,
                            executionResult.StatusMessage));

                        if (executionResult.Detections.Count > 0) {
                            successfulMethod ??= method;
                        }

                        var currentDetections = aggregatedDetections.Count == 0
                            ? null
                            : aggregatedDetections.Values
                                .OrderBy(static detection => IpToUInt32(detection.IpAddress))
                                .ToArray();
                        progress?.Report(new TapoCameraScanActivity(
                            method,
                            executionResult.StatusMessage,
                            currentDetections));
                        var methodLogData = new Dictionary<string, object?> {
                            ["method"] = method.ToString(),
                            ["durationMs"] = durationMs,
                            ["candidateCount"] = executionResult.Candidates.Count,
                            ["detectionCount"] = executionResult.Detections.Count
                        };
                        if (hasParallelPriorityHints) {
                            methodLogData["protocolDiscoveryDurationMs"] = parallelHints!.DiscoveryDurationMs;
                            methodLogData["parallelPriorityGroup"] = true;
                        }
                        if (executionResult.Detections.Count > 0) {
                            JsonLogStore.Information(
                                eventName: "camera_search_method_completed",
                                message: executionResult.StatusMessage,
                                category: "camera_search",
                                data: methodLogData);
                        } else {
                            JsonLogStore.Warning(
                                eventName: "camera_search_method_no_detections",
                                message: executionResult.StatusMessage,
                                category: "camera_search",
                                data: methodLogData);
                        }
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                        throw;
                    }
                    catch (Exception ex) {
                        var durationMs = (long)(DateTimeOffset.UtcNow - methodStartedAtUtc).TotalMilliseconds;
                        var failureMessage = $"{GetMethodDisplayName(method)} failed. Trying the next method.";
                        attemptedMethods.Add(new TapoDetectionMethodAttempt(
                            method,
                            Succeeded: false,
                            DetectionCount: 0,
                            DurationMs: durationMs,
                            StatusMessage: failureMessage));
                        progress?.Report(new TapoCameraScanActivity(method, failureMessage));
                        JsonLogStore.Error(
                            eventName: "camera_search_method_failed",
                            message: "A camera detection method failed.",
                            category: "camera_search",
                            exception: ex,
                            data: new Dictionary<string, object?> {
                                ["method"] = method.ToString(),
                                ["durationMs"] = durationMs,
                                ["protocolDiscoveryDurationMs"] = hasParallelPriorityHints
                                    ? parallelHints!.DiscoveryDurationMs
                                    : null,
                                ["parallelPriorityGroup"] = hasParallelPriorityHints
                            });
                    }
                }

                var detections = aggregatedDetections.Values
                    .OrderBy(static detection => IpToUInt32(detection.IpAddress))
                    .ToArray();
                var attemptedMethodNames = attemptedMethods
                    .Select(static attempt => GetMethodDisplayName(attempt.Method))
                    .ToArray();
                var finalResult = BuildScanResult(
                    detections,
                    subnetDiagnostics,
                    enumeratedSubnetHosts.Length + adaptiveHostCount,
                    arpSeedTable.Count,
                    onvifHints?.Count ?? 0,
                    ssdpHints?.Count ?? 0,
                    mdnsHints?.Count ?? 0,
                    aggregatedCandidates.Values.Count(static candidate => candidate.DiscoveredViaRtspOptions),
                    tapoBroadcastHints?.Count ?? 0,
                    aggregatedCandidates,
                    successfulMethod,
                    attemptedMethods);

                if (finalResult.Detections.Count > 0) {
                    JsonLogStore.Information(
                        eventName: "camera_search_completed",
                        message: "Local network scan completed.",
                        category: "camera_search",
                        data: new Dictionary<string, object?> {
                            ["elapsedMs"] = (long)(DateTimeOffset.UtcNow - startedAtUtc).TotalMilliseconds,
                            ["detectionCount"] = finalResult.Detections.Count,
                            ["successfulMethod"] = finalResult.SuccessfulMethod?.ToString(),
                            ["attemptedMethods"] = attemptedMethods.Select(static a => a.Method.ToString()).ToArray()
                        });

                    return finalResult;
                }

                var finalFailureMessage = attemptedMethodNames.Length == 0
                    ? "No compatible camera detected."
                    : $"No compatible camera detected. Tried: {string.Join(", ", attemptedMethodNames)}.";
                progress?.Report(new TapoCameraScanActivity(null, finalFailureMessage));

                JsonLogStore.Warning(
                    eventName: "camera_search_no_detections",
                    message: "Local network scan completed without any likely Tapo cameras.",
                    category: "camera_search",
                    data: new Dictionary<string, object?> {
                        ["elapsedMs"] = (long)(DateTimeOffset.UtcNow - startedAtUtc).TotalMilliseconds,
                        ["attemptedMethods"] = attemptedMethods.Select(static a => a.Method.ToString()).ToArray()
                    });

                return finalResult;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                JsonLogStore.Warning(
                    eventName: "camera_search_canceled",
                    message: "Local network scan was canceled.",
                    category: "camera_search",
                    data: new Dictionary<string, object?> {
                        ["elapsedMs"] = (long)(DateTimeOffset.UtcNow - startedAtUtc).TotalMilliseconds
                    });
                throw;
            }
            catch (Exception ex) {
                JsonLogStore.Error(
                    eventName: "camera_search_failed",
                    message: "Local network scan failed.",
                    category: "camera_search",
                    exception: ex,
                    data: new Dictionary<string, object?> {
                        ["elapsedMs"] = (long)(DateTimeOffset.UtcNow - startedAtUtc).TotalMilliseconds
                    });
                throw;
            }
        }

        public static bool TryParseDetectionMethod(string? rawValue, out TapoDetectionMethod method) {
            if (!string.IsNullOrWhiteSpace(rawValue) &&
                Enum.TryParse(rawValue, ignoreCase: true, out method) &&
                DetectionMethodOrder.Contains(method)) {
                return true;
            }

            method = default;
            return false;
        }

        private static IReadOnlyList<TapoDetectionMethod> BuildAttemptOrder(TapoDetectionMethod? preferredFirstMethod) {
            var orderedMethods = new List<TapoDetectionMethod>(DetectionMethodOrder.Length + 1);
            if (preferredFirstMethod is TapoDetectionMethod preferred && DetectionMethodOrder.Contains(preferred)) {
                orderedMethods.Add(preferred);
            }

            foreach (var method in DetectionMethodOrder) {
                if (!orderedMethods.Contains(method)) {
                    orderedMethods.Add(method);
                }
            }

            orderedMethods.Add(TapoDetectionMethod.AdaptiveRtspVerificationProbe);

            return orderedMethods;
        }

        private static async Task<DiscoveryHintResult> CaptureDiscoveryHintsAsync(
            Func<CancellationToken, Task<HashSet<IPAddress>>> discover,
            CancellationToken cancellationToken) {
            var stopwatch = Stopwatch.StartNew();
            try {
                var addresses = await discover(cancellationToken).ConfigureAwait(false);
                return new DiscoveryHintResult(addresses, null, stopwatch.ElapsedMilliseconds);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            }
            catch (Exception ex) {
                return new DiscoveryHintResult([], ex, stopwatch.ElapsedMilliseconds);
            }
        }

        private static string BuildMethodStartMessage(TapoDetectionMethod method, bool isPreferred) {
            var displayName = GetMethodDisplayName(method);
            return isPreferred
                ? $"Trying last successful method: {displayName}..."
                : $"Trying detection method: {displayName}...";
        }

        private static string GetMethodDisplayName(TapoDetectionMethod method) {
            return method switch {
                TapoDetectionMethod.AdaptiveRtspVerificationProbe => "extended network search",
                TapoDetectionMethod.OnvifWsDiscovery => "ONVIF WS-Discovery",
                TapoDetectionMethod.SsdpUpnpSearch => "SSDP/UPnP search",
                TapoDetectionMethod.TapoUdpBroadcast => "local discovery",
                TapoDetectionMethod.MdnsDnsSdSweep => "mDNS/DNS-SD sweep",
                TapoDetectionMethod.ArpSeededTargetProbe => "ARP-seeded target probe",
                TapoDetectionMethod.SubnetProbeFallback => "subnet probe fallback",
                TapoDetectionMethod.RtspOptionsProbe => "RTSP",
                _ => method.ToString()
            };
        }

        private static TapoCameraScanResult BuildScanResult(
            IReadOnlyList<TapoCameraDetection> detections,
            IReadOnlyList<string> subnetDiagnostics,
            int enumeratedHostCount,
            int arpSeedCount,
            int onvifHintCount,
            int ssdpCameraHintCount,
            int mdnsCameraHintCount,
            int rtspOptionsHintCount,
            int tapoBroadcastHintCount,
            Dictionary<string, TapoCameraCandidateDiagnostics> aggregatedCandidates,
            TapoDetectionMethod? successfulMethod,
            List<TapoDetectionMethodAttempt> attemptedMethods) {
            var orderedCandidates = aggregatedCandidates.Values
                .OrderBy(static candidate => IpToUInt32(candidate.IpAddress))
                .ToArray();

            return new TapoCameraScanResult(
                detections,
                new TapoScanDiagnostics(
                    subnetDiagnostics,
                    EnumeratedHostCount: enumeratedHostCount,
                    ArpSeedCount: arpSeedCount,
                    OnvifHintCount: onvifHintCount,
                    SsdpCameraHintCount: ssdpCameraHintCount,
                    MdnsCameraHintCount: mdnsCameraHintCount,
                    RtspOptionsHintCount: rtspOptionsHintCount,
                    TapoBroadcastHintCount: tapoBroadcastHintCount,
                    TapoUnicastHintCount: orderedCandidates.Count(static c => c.DiscoveredViaTapoUnicast),
                    ResponsiveHostCount: orderedCandidates.Length,
                    Candidates: orderedCandidates),
                successfulMethod,
                attemptedMethods.ToArray());
        }

        private static void MergeCandidates(
            Dictionary<string, TapoCameraCandidateDiagnostics> aggregatedCandidates,
            IReadOnlyList<TapoCameraCandidateDiagnostics> candidates) {
            foreach (var candidate in candidates) {
                var key = candidate.IpAddress.ToString();
                if (!aggregatedCandidates.TryGetValue(key, out var existing) ||
                    candidate.IsLikelyTapo && !existing.IsLikelyTapo ||
                    candidate.ConfidenceScore > existing.ConfidenceScore) {
                    if (existing is not null) {
                        var mergedCandidate = candidate with {
                            DiscoveredViaOnvif = candidate.DiscoveredViaOnvif || existing.DiscoveredViaOnvif,
                            DiscoveredViaSsdp = candidate.DiscoveredViaSsdp || existing.DiscoveredViaSsdp,
                            DiscoveredViaMdns = candidate.DiscoveredViaMdns || existing.DiscoveredViaMdns,
                            DiscoveredViaRtspOptions = candidate.DiscoveredViaRtspOptions || existing.DiscoveredViaRtspOptions,
                            DiscoveredViaRtspDescribe = candidate.DiscoveredViaRtspDescribe || existing.DiscoveredViaRtspDescribe,
                            RtspAuthenticationRequired = candidate.RtspAuthenticationRequired || existing.RtspAuthenticationRequired,
                            DiscoveredViaTapoBroadcast = candidate.DiscoveredViaTapoBroadcast || existing.DiscoveredViaTapoBroadcast,
                            DiscoveredViaTapoUnicast = candidate.DiscoveredViaTapoUnicast || existing.DiscoveredViaTapoUnicast,
                            OpenPorts = candidate.OpenPorts.Union(existing.OpenPorts).Order().ToArray()
                        };
                        aggregatedCandidates[key] = mergedCandidate;
                    }
                    else {
                        aggregatedCandidates[key] = candidate;
                    }
                }
                else if (aggregatedCandidates.TryGetValue(key, out existing)) {
                    aggregatedCandidates[key] = existing with {
                        DiscoveredViaOnvif = candidate.DiscoveredViaOnvif || existing.DiscoveredViaOnvif,
                        DiscoveredViaSsdp = candidate.DiscoveredViaSsdp || existing.DiscoveredViaSsdp,
                        DiscoveredViaMdns = candidate.DiscoveredViaMdns || existing.DiscoveredViaMdns,
                        DiscoveredViaRtspOptions = candidate.DiscoveredViaRtspOptions || existing.DiscoveredViaRtspOptions,
                        DiscoveredViaRtspDescribe = candidate.DiscoveredViaRtspDescribe || existing.DiscoveredViaRtspDescribe,
                        RtspAuthenticationRequired = candidate.RtspAuthenticationRequired || existing.RtspAuthenticationRequired,
                        DiscoveredViaTapoBroadcast = candidate.DiscoveredViaTapoBroadcast || existing.DiscoveredViaTapoBroadcast,
                        DiscoveredViaTapoUnicast = candidate.DiscoveredViaTapoUnicast || existing.DiscoveredViaTapoUnicast,
                        OpenPorts = candidate.OpenPorts.Union(existing.OpenPorts).Order().ToArray()
                    };
                }
            }
        }

        private static void MergeDetections(
            Dictionary<string, TapoCameraDetection> aggregatedDetections,
            IReadOnlyList<TapoCameraDetection> detections) {
            foreach (var detection in detections) {
                var key = detection.IpAddress.ToString();
                if (!aggregatedDetections.TryGetValue(key, out var existing) ||
                    detection.ConfidenceScore > existing.ConfidenceScore) {
                    aggregatedDetections[key] = detection;
                }
            }
        }

        private static async Task<HashSet<Ipv4CidrRange>> ProbeAdaptiveGatewayCluesAsync(
            IReadOnlyList<AdaptiveCameraNetworkCandidate> candidates,
            CancellationToken cancellationToken) {
            var responsive = new ConcurrentDictionary<Ipv4CidrRange, byte>();
            await Parallel.ForEachAsync(candidates.Where(static candidate => !candidate.HasNetworkEvidence),
                new ParallelOptions { CancellationToken = cancellationToken, MaxDegreeOfParallelism = 8 },
                async (candidate, token) => {
                    var firstHost = candidate.Range.EnumerateHosts().First();
                    var lastHost = candidate.Range.EnumerateHosts().Last();
                    var probes = new[] {
                        PingHostAsync(firstHost, 350, token),
                        ProbeTcpPortAsync(firstHost, 80, 350, token),
                        ProbeTcpPortAsync(firstHost, 443, 350, token),
                        PingHostAsync(lastHost, 350, token),
                        ProbeTcpPortAsync(lastHost, 80, 350, token),
                        ProbeTcpPortAsync(lastHost, 443, 350, token)
                    };
                    if ((await Task.WhenAll(probes).ConfigureAwait(false)).Any(static answer => answer)) {
                        responsive.TryAdd(candidate.Range, 0);
                    }
                }).ConfigureAwait(false);
            return responsive.Keys.ToHashSet();
        }

        private static async Task<MethodExecutionResult> ExecuteHintMethodAsync(
            TapoDetectionMethod method,
            HashSet<IPAddress> hintAddresses,
            Dictionary<IPAddress, string> arpSeedTable,
            int maxParallelism,
            bool discoveredViaOnvif,
            bool discoveredViaTapoBroadcast,
            bool discoveredViaSsdp,
            bool discoveredViaMdns,
            ConcurrentDictionary<IPAddress, ProbeCacheEntry> probedHosts,
            CancellationToken cancellationToken) {
            if (hintAddresses.Count == 0) {
                return new MethodExecutionResult(
                    Array.Empty<TapoCameraDetection>(),
                    Array.Empty<TapoCameraCandidateDiagnostics>(),
                    $"{GetMethodDisplayName(method)} returned no reachable devices.");
            }

            return await ProbeAndEvaluateCandidatesAsync(
                hintAddresses,
                arpSeedTable,
                maxParallelism,
                discoveredViaOnvif ? hintAddresses : null,
                discoveredViaTapoBroadcast ? hintAddresses : null,
                discoveredViaSsdp ? hintAddresses : null,
                discoveredViaMdns ? hintAddresses : null,
                $"{GetMethodDisplayName(method)} did not detect a compatible camera.",
                probedHosts,
                cancellationToken).ConfigureAwait(false);
        }

        private static async Task<MethodExecutionResult> ExecuteArpSeededMethodAsync(
            Dictionary<IPAddress, string> arpSeedTable,
            IReadOnlyList<Ipv4Subnet> subnets,
            int maxParallelism,
            ConcurrentDictionary<IPAddress, ProbeCacheEntry> probedHosts,
            CancellationToken cancellationToken) {
            var candidates = arpSeedTable.Keys
                .Where(ip => IsInCandidateSubnets(ip, subnets))
                .OrderByDescending(ip => arpSeedTable.TryGetValue(ip, out var mac) && !string.IsNullOrWhiteSpace(mac) && IsTpLinkMac(mac))
                .ThenBy(static ip => IpToUInt32(ip))
                .ToArray();

            if (candidates.Length == 0) {
                return new MethodExecutionResult(
                    Array.Empty<TapoCameraDetection>(),
                    Array.Empty<TapoCameraCandidateDiagnostics>(),
                    $"{GetMethodDisplayName(TapoDetectionMethod.ArpSeededTargetProbe)} returned no reachable devices.");
            }

            return await ProbeAndEvaluateCandidatesAsync(
                candidates,
                arpSeedTable,
                maxParallelism,
                discoveredViaOnvifHints: null,
                discoveredViaTapoBroadcastHints: null,
                discoveredViaSsdpHints: null,
                discoveredViaMdnsHints: null,
                $"{GetMethodDisplayName(TapoDetectionMethod.ArpSeededTargetProbe)} did not detect a compatible camera.",
                probedHosts,
                cancellationToken).ConfigureAwait(false);
        }

        private static async Task<MethodExecutionResult> ExecuteSubnetProbeFallbackAsync(
            IReadOnlyList<IPAddress> enumeratedSubnetHosts,
            Dictionary<IPAddress, string> arpSeedTable,
            HashSet<IPAddress>? onvifHints,
            HashSet<IPAddress>? ssdpHints,
            HashSet<IPAddress>? tapoBroadcastHints,
            HashSet<IPAddress>? mdnsHints,
            int maxParallelism,
            ConcurrentDictionary<IPAddress, ProbeCacheEntry> probedHosts,
            CancellationToken cancellationToken) {
            var hostAddresses = enumeratedSubnetHosts
                .Concat(arpSeedTable.Keys)
                .Concat(onvifHints ?? [])
                .Concat(ssdpHints ?? [])
                .Concat(tapoBroadcastHints ?? [])
                .Concat(mdnsHints ?? [])
                .DistinctBy(static ip => ip.ToString())
                .ToArray();

            if (hostAddresses.Length == 0) {
                return new MethodExecutionResult(
                    Array.Empty<TapoCameraDetection>(),
                    Array.Empty<TapoCameraCandidateDiagnostics>(),
                    $"{GetMethodDisplayName(TapoDetectionMethod.SubnetProbeFallback)} returned no reachable devices.");
            }

            return await ProbeAndEvaluateCandidatesAsync(
                hostAddresses,
                arpSeedTable,
                maxParallelism,
                onvifHints,
                tapoBroadcastHints,
                ssdpHints,
                mdnsHints,
                $"{GetMethodDisplayName(TapoDetectionMethod.SubnetProbeFallback)} did not detect a compatible camera.",
                probedHosts,
                cancellationToken).ConfigureAwait(false);
        }

        private static async Task<MethodExecutionResult> ProbeAndEvaluateCandidatesAsync(
            IReadOnlyCollection<IPAddress> candidateAddresses,
            Dictionary<IPAddress, string> arpSeedTable,
            int maxParallelism,
            HashSet<IPAddress>? discoveredViaOnvifHints,
            HashSet<IPAddress>? discoveredViaTapoBroadcastHints,
            HashSet<IPAddress>? discoveredViaSsdpHints,
            HashSet<IPAddress>? discoveredViaMdnsHints,
            string noDetectionMessage,
            ConcurrentDictionary<IPAddress, ProbeCacheEntry> probedHosts,
            CancellationToken cancellationToken) {
            var normalizedCandidates = candidateAddresses
                .Where(static ip =>
                    ip.AddressFamily == AddressFamily.InterNetwork
                    && !IPAddress.IsLoopback(ip)
                    && !IsApipaAddress(ip))
                .DistinctBy(static ip => ip.ToString())
                .ToArray();

            if (normalizedCandidates.Length == 0) {
                return new MethodExecutionResult(
                    Array.Empty<TapoCameraDetection>(),
                    Array.Empty<TapoCameraCandidateDiagnostics>(),
                    noDetectionMessage);
            }

            var unseenCandidates = normalizedCandidates
                .Where(address => !probedHosts.ContainsKey(address))
                .ToArray();
            var newProbes = await ProbeHostsAsync(
                unseenCandidates,
                discoveredViaOnvifHints,
                discoveredViaTapoBroadcastHints,
                discoveredViaSsdpHints,
                discoveredViaMdnsHints,
                maxParallelism,
                cancellationToken).ConfigureAwait(false);
            foreach (var probe in newProbes) {
                probedHosts.TryAdd(probe.IpAddress, probe);
            }

            if (normalizedCandidates.All(address =>
                    !probedHosts.TryGetValue(address, out var entry) || entry.Probe is null)) {
                return new MethodExecutionResult(
                    Array.Empty<TapoCameraDetection>(),
                    Array.Empty<TapoCameraCandidateDiagnostics>(),
                    noDetectionMessage);
            }

            var arpPostProbeTable = await ReadArpTableAsync(cancellationToken).ConfigureAwait(false);
            var arpTable = MergeArpTables(arpSeedTable, arpPostProbeTable);
            var orderedProbes = normalizedCandidates
                .Where(address => probedHosts.TryGetValue(address, out var entry) && entry.Probe is not null)
                .Select(address => MergeProbeEvidence(
                    probedHosts[address].Probe!,
                    discoveredViaOnvifHints?.Contains(address) == true,
                    discoveredViaSsdpHints?.Contains(address) == true,
                    discoveredViaMdnsHints?.Contains(address) == true,
                    discoveredViaTapoBroadcastHints?.Contains(address) == true))
                .ToArray();
            foreach (var probe in orderedProbes) {
                probedHosts[probe.IpAddress] = new ProbeCacheEntry(probe.IpAddress, probe);
            }

            orderedProbes = orderedProbes
                .OrderBy(static probe => IpToUInt32(probe.IpAddress))
                .ToArray();
            var detections = new List<TapoCameraDetection>();
            var candidates = new List<TapoCameraCandidateDiagnostics>(orderedProbes.Length);

            foreach (var probe in orderedProbes) {
                cancellationToken.ThrowIfCancellationRequested();

                var hasArpEntry = arpTable.TryGetValue(probe.IpAddress, out var macAddress);
                var hostName = await TryResolveHostNameAsync(probe.IpAddress, cancellationToken).ConfigureAwait(false);
                var evaluation = EvaluateCandidate(probe, macAddress, hostName);
                var diagnostic = new TapoCameraCandidateDiagnostics(
                    probe.IpAddress,
                    evaluation.IsLikelyTapo,
                    Math.Round(evaluation.Score, 2),
                    evaluation.Reason,
                    hostName,
                    macAddress,
                    hasArpEntry,
                    probe.DiscoveredViaOnvif,
                    probe.DiscoveredViaSsdp,
                    probe.DiscoveredViaMdns,
                    probe.DiscoveredViaRtspOptions,
                    probe.DiscoveredViaTapoBroadcast,
                    probe.DiscoveredViaTapoUnicast,
                    probe.OpenPorts);
                candidates.Add(diagnostic);

                if (!evaluation.IsLikelyTapo) {
                    continue;
                }

                detections.Add(new TapoCameraDetection(
                    probe.IpAddress,
                    hostName,
                    macAddress,
                    probe.OpenPorts,
                    Math.Round(evaluation.Score, 2),
                    evaluation.Reason,
                    probe.RtspPort));
            }

            var statusMessage = detections.Count > 0
                ? $"Detected {detections.Count} {Pluralize(detections.Count, "camera")}."
                : noDetectionMessage;

            return new MethodExecutionResult(detections, candidates, statusMessage);
        }

        private static async Task<ProbeCacheEntry[]> ProbeHostsAsync(
            IReadOnlyList<IPAddress> hostAddresses,
            HashSet<IPAddress>? discoveredViaOnvifHints,
            HashSet<IPAddress>? discoveredViaTapoBroadcastHints,
            HashSet<IPAddress>? discoveredViaSsdpHints,
            HashSet<IPAddress>? discoveredViaMdnsHints,
            int maxParallelism,
            CancellationToken cancellationToken) {
            var probes = new ConcurrentBag<ProbeCacheEntry>();
            var completedProbeCount = 0;
            var responsiveProbeCount = 0;

            await Parallel.ForEachAsync(
                hostAddresses,
                new ParallelOptions {
                    CancellationToken = cancellationToken,
                    MaxDegreeOfParallelism = maxParallelism
                },
                async (ipAddress, token) => {
                    var result = await ProbeHostAsync(
                        ipAddress,
                        discoveredViaOnvifHints?.Contains(ipAddress) == true,
                        discoveredViaTapoBroadcastHints?.Contains(ipAddress) == true,
                        discoveredViaSsdpHints?.Contains(ipAddress) == true,
                        discoveredViaMdnsHints?.Contains(ipAddress) == true,
                        token).ConfigureAwait(false);
                    probes.Add(new ProbeCacheEntry(ipAddress, result));
                    if (result is not null) {
                        Interlocked.Increment(ref responsiveProbeCount);
                    }

                    var completed = Interlocked.Increment(ref completedProbeCount);
                    if (completed % 128 == 0 || completed == hostAddresses.Count) {
                        JsonLogStore.Information(
                            eventName: "camera_search_probe_progress",
                            message: "Local network probing is still in progress.",
                            category: "camera_search",
                            data: new Dictionary<string, object?> {
                                ["completedProbeCount"] = completed,
                                ["responsiveProbeCount"] = Volatile.Read(ref responsiveProbeCount),
                                ["hostAddressCount"] = hostAddresses.Count
                            });
                    }
                }).ConfigureAwait(false);

            return probes.ToArray();
        }

        private static bool IsInCandidateSubnets(IPAddress ipAddress, IReadOnlyList<Ipv4Subnet> subnets) {
            var value = IpToUInt32(ipAddress);
            foreach (var subnet in subnets) {
                var mask = PrefixMask(subnet.PrefixLength);
                if ((value & mask) == subnet.NetworkAddress) {
                    return true;
                }
            }

            return false;
        }

        private static async Task<HostProbeResult?> ProbeHostAsync(
            IPAddress ipAddress,
            bool discoveredViaOnvif,
            bool discoveredViaTapoBroadcast,
            bool discoveredViaSsdp,
            bool discoveredViaMdns,
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
            var rtspResponseDetected = false;
            var confirmedRtspPort = 554;
            foreach (var rtspPort in new[] { 554, 8554 }.Where(openPorts.Contains)) {
                if (await TryProbeRtspOptionsAsync(ipAddress, rtspPort, cancellationToken).ConfigureAwait(false)) {
                    rtspResponseDetected = true;
                    confirmedRtspPort = rtspPort;
                    break;
                }
            }

            var discoveredViaTapoUnicast =
                await TryProbeTapoUnicastAsync(ipAddress, cancellationToken).ConfigureAwait(false);

            if (!pingSucceeded
                && openPorts.Length == 0
                && !discoveredViaOnvif
                && !discoveredViaSsdp
                && !discoveredViaMdns
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
                confirmedRtspPort,
                discoveredViaOnvif,
                discoveredViaSsdp,
                discoveredViaMdns,
                rtspResponseDetected,
                discoveredViaTapoBroadcast,
                discoveredViaTapoUnicast);
        }

        private static HostProbeResult MergeProbeEvidence(
            HostProbeResult probe,
            bool discoveredViaOnvif,
            bool discoveredViaSsdp,
            bool discoveredViaMdns,
            bool discoveredViaTapoBroadcast) {
            return probe with {
                DiscoveredViaOnvif = probe.DiscoveredViaOnvif || discoveredViaOnvif,
                DiscoveredViaSsdp = probe.DiscoveredViaSsdp || discoveredViaSsdp,
                DiscoveredViaMdns = probe.DiscoveredViaMdns || discoveredViaMdns,
                DiscoveredViaTapoBroadcast = probe.DiscoveredViaTapoBroadcast || discoveredViaTapoBroadcast
            };
        }

        private static async Task<bool> TryProbeRtspOptionsAsync(
            IPAddress ipAddress,
            int port,
            CancellationToken cancellationToken) {
            try {
                using var client = new TcpClient();
                await client.ConnectAsync(ipAddress, port)
                    .WaitAsync(TimeSpan.FromMilliseconds(RtspOptionsTimeoutMs), cancellationToken)
                    .ConfigureAwait(false);

                await using var stream = client.GetStream();
                var request = Encoding.ASCII.GetBytes(
                    $"OPTIONS rtsp://{ipAddress}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: LocalCam/1.0\r\n\r\n");
                await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);

                using var response = new MemoryStream();
                var buffer = new byte[1024];
                while (response.Length < 16 * 1024) {
                    var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                        .AsTask()
                        .WaitAsync(TimeSpan.FromMilliseconds(RtspOptionsTimeoutMs), cancellationToken)
                        .ConfigureAwait(false);
                    if (read == 0) {
                        break;
                    }

                    response.Write(buffer, 0, read);
                    var text = Encoding.ASCII.GetString(response.GetBuffer(), 0, (int)response.Length);
                    if (text.Contains("\r\n\r\n", StringComparison.Ordinal)) {
                        return CameraDiscoveryParsers.TryParseRtspOptionsResponse(text, 1, out _);
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            }
            catch {
                // RTSP capability probing is best-effort.
            }

            return false;
        }

        internal static CandidateEvaluation EvaluateCandidate(HostProbeResult probe, string? macAddress, string? hostName) {
            var reasons = new List<string>();
            var score = 0d;

            var hasRtsp = probe.OpenPorts.Contains(554) || probe.OpenPorts.Contains(8554);
            var hasRtspResponse = probe.DiscoveredViaRtspOptions;
            var hasOnvif = probe.DiscoveredViaOnvif;
            var hasSsdpCameraDescription = probe.DiscoveredViaSsdp;
            var hasMdnsCameraService = probe.DiscoveredViaMdns;
            var hasTapoControlPort = probe.OpenPorts.Contains(20002) || probe.OpenPorts.Contains(9999);
            var hasWebManagement = probe.OpenPorts.Contains(80)
                || probe.OpenPorts.Contains(443)
                || probe.OpenPorts.Contains(8080)
                || probe.OpenPorts.Contains(8443);
            var hasTpLinkMac = !string.IsNullOrWhiteSpace(macAddress) && IsTpLinkMac(macAddress);

            if (hasRtspResponse) {
                score += 2.0;
                reasons.Add("Responded to RTSP OPTIONS");
            }
            else if (hasRtsp) {
                score += 0.5;
                reasons.Add("RTSP service port is open");
            }

            if (hasOnvif) {
                score += 2.0;
                reasons.Add("Matched ONVIF WS-Discovery response");
            }

            if (hasSsdpCameraDescription) {
                score += 2.0;
                reasons.Add("SSDP description identifies a camera or video device");
            }

            if (hasMdnsCameraService) {
                score += 2.0;
                reasons.Add("Advertised a camera-related DNS-SD service");
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
                hasRtspResponse
                || hasOnvif
                || hasSsdpCameraDescription
                || hasMdnsCameraService
                || hasTapoControlPort
                || probe.DiscoveredViaTapoBroadcast
                || probe.DiscoveredViaTapoUnicast;
            var hasGenericCameraService =
                hasRtspResponse
                || hasOnvif
                || hasSsdpCameraDescription
                || hasMdnsCameraService
                || probe.DiscoveredViaTapoBroadcast
                || probe.DiscoveredViaTapoUnicast;
            var hasTpLinkSignal = hasTpLinkMac || hostSuggestsTpLink || fingerprintSuggestsTpLink;

            var isLikely =
                hasStrongBrandSignal
                || (hasCameraService && hasTpLinkSignal)
                || (hasRtspResponse && hasOnvif)
                || (probe.DiscoveredViaTapoBroadcast && (hasRtsp || hasOnvif || hasWebManagement))
                || (probe.DiscoveredViaTapoUnicast && (hasRtsp || hasOnvif || hasWebManagement || hasTpLinkSignal))
                || (hasTapoControlPort && hasTpLinkSignal && !looksLikeRepeater)
                || (hasGenericCameraService && score >= 2.0 && !looksLikeRepeater)
                || (hasRtspResponse && hasWebManagement && score >= 2.5);

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
                    var body = await ReadResponseContentBoundedAsync(
                        response.Content,
                        HttpFingerprintBodyLimit,
                        cancellationToken).ConfigureAwait(false);

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
            IReadOnlyList<Ipv4Subnet> subnets,
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

                        if (!CameraDiscoveryParsers.TryParseOnvifProbeMatches(
                                Encoding.UTF8.GetString(response.Buffer), out var serviceAddresses)) {
                            continue;
                        }

                        if (IsLocalCandidateAddress(response.RemoteEndPoint.Address, subnets)) {
                            discoveredAddresses.Add(response.RemoteEndPoint.Address);
                        }

                        foreach (var serviceAddress in serviceAddresses) {
                            if (IPAddress.TryParse(serviceAddress.Host, out var address)
                                && IsLocalCandidateAddress(address, subnets)) {
                                discoveredAddresses.Add(address);
                            }
                        }
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                    throw;
                }
                catch (Exception ex) {
                    LogDiscoveryTransportFailure("ONVIF WS-Discovery", localAddress, ex);
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

                        if (IsLocalCandidateAddress(response.RemoteEndPoint.Address, subnets)) {
                            discoveredAddresses.Add(response.RemoteEndPoint.Address);
                        }

                        foreach (var extractedAddress in ExtractIpv4Addresses(Encoding.UTF8.GetString(response.Buffer))) {
                            if (IsLocalCandidateAddress(extractedAddress, subnets)) {
                                discoveredAddresses.Add(extractedAddress);
                            }
                        }
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                    throw;
                }
                catch (Exception ex) {
                    LogDiscoveryTransportFailure("TP-Link/Tapo UDP", localAddress, ex);
                }
            }

            return discoveredAddresses;
        }

        private static async Task<HashSet<IPAddress>> DiscoverSsdpAddressesAsync(
            IEnumerable<IPAddress> localAddresses,
            IReadOnlyList<Ipv4Subnet> subnets,
            CancellationToken cancellationToken) {
            var discoveredAddresses = new HashSet<IPAddress>();
            var requestBytes = Encoding.ASCII.GetBytes(BuildSsdpSearchRequest());
            var multicastEndpoint = new IPEndPoint(SsdpMulticastAddress, SsdpDiscoveryPort);
            var descriptionsFetched = 0;

            foreach (var localAddress in localAddresses.DistinctBy(static ip => ip.ToString())) {
                cancellationToken.ThrowIfCancellationRequested();

                try {
                    using var udpClient = new UdpClient(new IPEndPoint(localAddress, 0));
                    await udpClient.SendAsync(requestBytes, requestBytes.Length, multicastEndpoint).ConfigureAwait(false);

                    var receiveUntil = DateTime.UtcNow.AddMilliseconds(SsdpReceiveWindowMs);
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

                        if (!CameraDiscoveryParsers.TryParseSsdpResponse(
                                Encoding.UTF8.GetString(response.Buffer), out var ssdpResponse)
                            || ssdpResponse is null
                            || !IPAddress.TryParse(ssdpResponse.Location.Host, out var locationAddress)
                            || !IsLocalCandidateAddress(locationAddress, subnets)
                            || descriptionsFetched >= MaxSsdpDescriptionFetches) {
                            continue;
                        }

                        descriptionsFetched++;
                        var descriptionIsCamera = await TryFetchCameraDescriptionAsync(
                            ssdpResponse.Location,
                            cancellationToken).ConfigureAwait(false);
                        if (descriptionIsCamera) {
                            discoveredAddresses.Add(locationAddress);
                        }
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                    throw;
                }
                catch (Exception ex) {
                    LogDiscoveryTransportFailure("SSDP/UPnP", localAddress, ex);
                }
            }

            return discoveredAddresses;
        }

        private static async Task<HashSet<IPAddress>> DiscoverMdnsCandidateAddressesAsync(
            IEnumerable<IPAddress> localAddresses,
            IReadOnlyList<Ipv4Subnet> subnets,
            CancellationToken cancellationToken) {
            var discoveredAddresses = new HashSet<IPAddress>();
            var queries = new[] {
                BuildMdnsQuery("_services._dns-sd._udp.local"),
                BuildMdnsQuery("_http._tcp.local"),
                BuildMdnsQuery("_rtsp._tcp.local"),
                BuildMdnsQuery("_onvif._tcp.local")
            };
            var multicastEndpoint = new IPEndPoint(MdnsMulticastAddress, MdnsDiscoveryPort);

            foreach (var localAddress in localAddresses.DistinctBy(static ip => ip.ToString())) {
                cancellationToken.ThrowIfCancellationRequested();

                try {
                    using var udpClient = new UdpClient(AddressFamily.InterNetwork);
                    udpClient.Client.ExclusiveAddressUse = false;
                    udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, MdnsDiscoveryPort));
                    udpClient.Client.SetSocketOption(
                        SocketOptionLevel.IP,
                        SocketOptionName.MulticastInterface,
                        localAddress.GetAddressBytes());
                    udpClient.Client.SetSocketOption(
                        SocketOptionLevel.IP,
                        SocketOptionName.MulticastTimeToLive,
                        255);
                    udpClient.JoinMulticastGroup(MdnsMulticastAddress, localAddress);

                    foreach (var query in queries) {
                        await udpClient.SendAsync(query, query.Length, multicastEndpoint).ConfigureAwait(false);
                    }

                    var receiveUntil = DateTime.UtcNow.AddMilliseconds(MdnsReceiveWindowMs);
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

                        foreach (var service in CameraDiscoveryParsers.ParseDnsSdServices(response.Buffer)) {
                            if (!IsCameraMdnsService(service)) {
                                continue;
                            }

                            var localServiceAddresses = service.Addresses
                                .Where(address => IsLocalCandidateAddress(address, subnets))
                                .ToArray();
                            if (localServiceAddresses.Length == 0
                                && IsLocalCandidateAddress(response.RemoteEndPoint.Address, subnets)) {
                                discoveredAddresses.Add(response.RemoteEndPoint.Address);
                            }
                            else {
                                discoveredAddresses.UnionWith(localServiceAddresses);
                            }
                        }
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                    throw;
                }
                catch (Exception ex) {
                    LogDiscoveryTransportFailure("mDNS/DNS-SD", localAddress, ex);
                }
            }

            return discoveredAddresses;
        }

        private static void LogDiscoveryTransportFailure(string protocol, IPAddress localAddress, Exception exception) {
            JsonLogStore.Warning(
                eventName: "camera_search_protocol_error",
                message: "A local camera discovery protocol probe failed on a network interface.",
                category: "camera_search",
                data: new Dictionary<string, object?> {
                    ["protocol"] = protocol,
                    ["localAddress"] = localAddress.ToString(),
                    ["exceptionType"] = exception.GetType().Name
                });
        }

        private static bool IsCameraMdnsService(CameraDiscoveryParsers.DnsSdService service) {
            var identity = $"{service.ServiceType} {service.InstanceName}";
            return service.ServiceType.Contains("_rtsp._tcp", StringComparison.OrdinalIgnoreCase)
                || identity.Contains("camera", StringComparison.OrdinalIgnoreCase)
                || identity.Contains("video", StringComparison.OrdinalIgnoreCase)
                || identity.Contains("surveillance", StringComparison.OrdinalIgnoreCase)
                || identity.Contains("nvr", StringComparison.OrdinalIgnoreCase)
                || identity.Contains("dvr", StringComparison.OrdinalIgnoreCase);
        }

        private static async Task<bool> TryFetchCameraDescriptionAsync(Uri location, CancellationToken cancellationToken) {
            try {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromMilliseconds(1000));
                using var request = new HttpRequestMessage(HttpMethod.Get, location);
                request.Headers.UserAgent.ParseAdd("LocalCam/1.0");
                using var response = await ProbeHttpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    timeout.Token).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode) {
                    return false;
                }

                var body = await ReadResponseContentBoundedAsync(response.Content, 64 * 1024, timeout.Token).ConfigureAwait(false);
                return body is not null && CameraDiscoveryParsers.IsCameraDescription(body);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            }
            catch {
                return false;
            }
        }

        private static async Task<string?> ReadResponseContentBoundedAsync(
            HttpContent content,
            int maximumBytes,
            CancellationToken cancellationToken) {
            if (content.Headers.ContentLength is long contentLength && contentLength > maximumBytes) {
                return null;
            }

            await using var source = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var destination = new MemoryStream(Math.Min(maximumBytes, 4096));
            var buffer = new byte[4096];
            while (destination.Length <= maximumBytes) {
                var bytesToRead = (int)Math.Min(buffer.Length, maximumBytes + 1L - destination.Length);
                if (bytesToRead <= 0) {
                    return null;
                }

                var read = await source.ReadAsync(buffer.AsMemory(0, bytesToRead), cancellationToken).ConfigureAwait(false);
                if (read == 0) {
                    return Encoding.UTF8.GetString(destination.ToArray());
                }

                destination.Write(buffer, 0, read);
            }

            return null;
        }

        private static bool IsLocalCandidateAddress(IPAddress address, IReadOnlyList<Ipv4Subnet> subnets) {
            return address.AddressFamily == AddressFamily.InterNetwork
                && !IPAddress.IsLoopback(address)
                && !IsApipaAddress(address)
                && IsInCandidateSubnets(address, subnets);
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

        private static string BuildSsdpSearchRequest() {
            return "M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\nUSER-AGENT:LocalCam/1.0\r\n\r\n";
        }

        private static byte[] BuildMdnsQuery(string questionName) {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream, Encoding.ASCII, leaveOpen: true);

            WriteNetworkUInt16(writer, 0);
            WriteNetworkUInt16(writer, 0);
            WriteNetworkUInt16(writer, 1);
            WriteNetworkUInt16(writer, 0);
            WriteNetworkUInt16(writer, 0);
            WriteNetworkUInt16(writer, 0);

            foreach (var label in questionName.Split('.', StringSplitOptions.RemoveEmptyEntries)) {
                var labelBytes = Encoding.ASCII.GetBytes(label);
                writer.Write((byte)labelBytes.Length);
                writer.Write(labelBytes);
            }

            writer.Write((byte)0);
            WriteNetworkUInt16(writer, 12);
            WriteNetworkUInt16(writer, 1);
            writer.Flush();
            return stream.ToArray();
        }

        private static void WriteNetworkUInt16(BinaryWriter writer, ushort value) {
            writer.Write((byte)(value >> 8));
            writer.Write((byte)value);
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
                    var key = $"{ipAddress}/{networkAddress}/{prefixLength}";
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
                AllowAutoRedirect = false
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

        internal sealed record HostProbeResult(
            IPAddress IpAddress,
            IReadOnlyList<int> OpenPorts,
            string? HttpFingerprint,
            int RtspPort,
            bool DiscoveredViaOnvif,
            bool DiscoveredViaSsdp,
            bool DiscoveredViaMdns,
            bool DiscoveredViaRtspOptions,
            bool DiscoveredViaTapoBroadcast,
            bool DiscoveredViaTapoUnicast);

        private sealed record ProbeCacheEntry(IPAddress IpAddress, HostProbeResult? Probe);

        private sealed record MethodExecutionResult(
            IReadOnlyList<TapoCameraDetection> Detections,
            IReadOnlyList<TapoCameraCandidateDiagnostics> Candidates,
            string StatusMessage);

        private sealed record DiscoveryHintResult(
            HashSet<IPAddress> Addresses,
            Exception? Failure,
            long DiscoveryDurationMs);

        internal readonly record struct CandidateEvaluation(bool IsLikelyTapo, double Score, string Reason);

        private static string Pluralize(int count, string singular, string? plural = null) {
            return count == 1
                ? singular
                : plural ?? $"{singular}s";
        }
    }
}
