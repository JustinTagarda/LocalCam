# LocalCam Decisions and Constraints

These records capture durable choices already reflected in the repository. New architectural choices should be added here as dated ADR-style entries.

## DEC-001: Windows WPF desktop application

Status: Accepted

LocalCam uses a single-window WPF UI on .NET 10 for Windows. This matches the current interaction model and LibVLCSharp.WPF integration.

## DEC-002: x64-only runtime and packaging

Status: Accepted

`LocalCam.csproj` and Store packaging are constrained to `win-x64`. ARM64, AnyCPU, and multi-architecture packaging are out of scope unless explicitly approved.

## DEC-003: Tapo-first discovery with brand-neutral UI

Status: Accepted

Internal scanner identifiers and heuristics may remain Tapo/TP-Link-specific. Normal user-facing wording and detection method labels remain generic and compatible-camera oriented.

## DEC-004: Best-effort local discovery

Status: Accepted

Discovery uses multiple bounded probes and confidence signals. It is not an authoritative inventory and must remain cancellable and retryable.

## DEC-005: Fixed RTSP construction boundary

Status: Accepted

The current stream contract uses detected host, port `554`, credentials, and normalized path with default `stream1`. Custom URL/port support is a future product decision, not an implicit refactor.

## DEC-006: One active recording session

Status: Accepted

Recording is manual, `.ts`, non-remuxed/non-transcoded, and limited to one active card with 60-minute rollover.

## DEC-007: Local-first persistence and diagnostics

Status: Accepted

Settings, media output, and diagnostics remain local. Any future cloud or remote service would require a separate privacy, security, and architecture decision.

## DEC-017: Unified application-data diagnostics retention

Status: Accepted

Debug, Release, and installed builds use the same `JsonLogStore` route and JSONL schema. Logs are stored below the Windows application-data local folder rather than beside the executable. For packaged builds, this is package-owned local data and Windows removes it with the package. Unpackaged desktop runs use the same application-data abstraction with a local fallback because an unpackaged executable has no OS uninstall lifecycle.

Diagnostic messages, exception text, stack traces, and structured data are sanitized before serialization. Credentials, complete RTSP URLs, URL values, and secret-bearing fields are replaced with `[REDACTED]`. Logs rotate by UTC day, and files older than seven days are deleted during startup and periodic retention sweeps.

Local IP addresses, hostnames, and stream paths may remain in diagnostics to preserve local troubleshooting context. Diagnostics are local-only and are not an exported support artifact; any future diagnostics export requires a separate privacy review.

## DEC-008: Existing code is the baseline

Status: Accepted

These documents describe the application as implemented. They do not retroactively claim requirements were designed before implementation, and any mismatch is recorded as a gap or recommendation.

## DEC-009: Host-driven Fluent theme resources with safe runtime refresh

## DEC-010: Expiring recent-camera reconnect cache

Status: Accepted

LocalCam retains only locally stored, recently confirmed camera endpoints. Entries expire after seven days, are removed after two consecutive reconnect failures, and are invalidated whenever shared RTSP credentials or stream path change. The cache is uncapped and is an acceleration mechanism, not a permanent camera profile registry; normal local discovery remains the recovery path.

Status: Accepted

LocalCam uses WPF `Application.ThemeMode` and the Windows-provided Fluent resource tokens for System, Light, and Dark appearance. It does not define a custom fixed-color palette. Existing LocalCam brush aliases remain as compatibility seams for XAML and dynamically created controls.

The persisted preference is applied before the first `MainWindow` visual tree is initialized. When the preference changes at runtime, `AppThemeService` refreshes the aliases by cloning the active Fluent brushes and replacing the alias resources. This is required because WPF Fluent brushes can be frozen and direct mutation can crash the process. Camera-card visuals created in code are refreshed in place after the runtime change.

Guardrail: do not replace Fluent resource tokens with fixed colors, mutate frozen brushes, remove the pre-initialization theme application, or change the preference semantics without explicit user authorization and corresponding FR-020 verification updates.

## DEC-010: Native window frames and flattened client roots

Status: Accepted

MainWindow and SettingsWindow use native Windows/WPF window frames. Their client areas begin with flattened root grids rather than decorative outer border wrappers. Settings no longer owns a custom title bar, close button, or manual drag behavior.

Internal borders remain valid for semantic UI surfaces such as status panels, camera cards, separators, control templates, and dropdown popups. This decision does not prohibit those borders.

The Settings Theme ComboBox uses a complete custom template because the default WPF ComboBox template does not maintain the application's Fluent-backed light/dark surface styling. The template must preserve dynamic resources, System/Light/Dark behavior, keyboard/dropdown interaction, and item highlighting.

Guardrail: do not reintroduce custom window chrome, decorative outer frame borders, fixed theme colors, or partial/default Theme ComboBox styling without explicit user authorization and updates to FR-021 and its verification evidence.

## DEC-011: App-wide shared button baseline

Status: Accepted

`App.xaml` owns `GlobalButtonStyle`, whose initial configuration is the regular button style formerly owned by `SettingsWindow`. The application-level implicit `Button` style is based on `GlobalButtonStyle`, so unqualified buttons receive the baseline automatically. Window-local and code-created specialized styles must derive from `GlobalButtonStyle` and may override only presentation-specific properties such as icon dimensions, overlay transparency, compact spacing, or status emphasis.

Strict guardrails:

- Do not create or retain an independent button template in a window, dialog, or code path.
- Do not apply a button style that is not based on `GlobalButtonStyle`.
- Do not replace the Fluent-backed dynamic button brushes with fixed colors or mutate frozen theme resources.
- Do not change the baseline padding, minimum width, height, 4px corner radius, cursor, border, hover, pressed, or disabled behavior without explicit authorization and corresponding verification updates.
- Specialized button behavior (visibility, focusability, commands, icon geometry, overlay placement, and accessibility) remains independent of the shared visual baseline and must not be removed to satisfy style reuse.
- Any future button-style change must include a static inheritance audit and live System/Light/Dark checks across every window and active camera-card button surface.

## DEC-012: Content-sized camera-area action buttons

Status: Accepted

The in-video action buttons hosted in camera areas use `CameraOverlayIconButtonStyle`, which derives from `GlobalButtonStyle` but overrides `MinWidth` to `0`, leaves `Width` and `Height` unset, and sets uniform `Padding` to `6px`. Each action icon uses a `16x16` content canvas while inner glyphs retain their visual proportions. This keeps Expand, Collapse, Play, Stop Stream, Snapshot, and Record buttons content-sized with automatic height while retaining the shared button behavior.

Guardrail: this exception is limited to camera-area in-video action buttons. Do not change the global button width, height, or padding rules, introduce a non-16x16 action icon canvas, or apply these camera-button settings to toolbar, Settings, dialog, update, status, or other buttons without explicit authorization and corresponding UI design and verification updates.

## DEC-013: Pinned .NET SDK 10.0.400

Status: Accepted

LocalCam pins .NET SDK `10.0.400` in `global.json` with roll-forward disabled. The pinned SDK is part of the repository build contract and must be used for Debug builds, tests, packaging, and generated artifacts with the Visual Studio 2026 MSBuild toolchain.

Guardrails:

- Do not silently downgrade to `10.0.300`, roll forward to another SDK, or bypass `global.json`.
- Do not claim FAST-BUILD or test verification for this repository when another SDK version was used.
- Any SDK update requires explicit authorization and synchronized updates to `global.json`, `AGENTS.md`, README build instructions, NFR-009, the architecture baseline, this decision record, and the traceability verification steps.
- If the pinned SDK is not installed, stop and report the gap rather than changing the pin or using a fallback.

## DEC-014: Identity-bound camera playback lifecycle

Status: Accepted

Each tile binds a media-player instance to an immutable camera identity for that playback attempt. Reassigning a tile to a different detection stops and disposes the old player before it can affect the new camera. LibVLC `Playing` is the live-state and recent-cache confirmation boundary; a playback request being accepted is not confirmation. A terminal `EndReached` or `EncounteredError` event receives one bounded restart attempt, while failed recent-cache reconnects continue to use discovery fallback and the two-failure eviction policy. A system suspend or hibernation transition takes precedence over automatic recovery: it uses Stop All, cancels pending automatic recovery, preserves tiles and connection state, and leaves playback stopped after resume.

## DEC-015: Render-first video-engine initialization

Status: Accepted

The dashboard shell is shown before nonessential LibVLC initialization completes. LibVLC initialization runs asynchronously after the first render, while stream-start actions remain gated until the engine is ready. Initialization progress and failures are visible in the main window, and failures provide an in-place retry action. Startup reconnect and discovery begin only after successful engine initialization.

The existing single-instance mutex remains authoritative. Secondary launches signal the primary instance, which restores and activates its existing window instead of silently exiting.

Guardrails: do not change RTSP construction, discovery behavior, recent-camera cache policy, theme startup ordering, recording rules, or the single-window constraint while implementing this decision.

## DEC-016: Per-camera playback health and bounded recovery

Status: Accepted

LibVLC accepting a playback request is not evidence that video output is usable. LocalCam therefore treats LibVLC `Playing` as the confirmation boundary, allows a short per-camera output-initialization grace period, and evaluates health from consecutive samples of playback state and media/output counters. A single early sample or temporary missing video output must not restart a stream.

Health recovery is periodic and isolated to the affected camera. Each camera has an independent cooldown and bounded recovery-attempt window. Recovery exhaustion stops automatic retries for that camera, surfaces a card-local classified error, and does not stop healthy camera streams. Explicit user Play or a new Play all request resets that camera's automatic recovery state.

Repeated LibVLC runtime messages are rate-limited in structured diagnostics. Diagnostics distinguish accepted playback requests from confirmed playback, include per-camera recovery state, and never include credentials or complete RTSP URLs. Direct3D11 and Windows driver failures remain an investigation concern; video-output options must not be changed solely to suppress their log messages.

Guardrails: preserve identity-bound player handling, recent-camera cache confirmation and eviction rules, terminal-event recovery policy, suspend/hibernate Stop All behavior, RTSP construction, and per-card failure isolation.

## DEC-018: Coordinated atomic settings persistence

Status: Accepted

Settings are local application state shared by the WPF UI and asynchronous Store/entitlement services. All service-managed mutations are marshaled through the MainWindow-owned settings path. SettingsStore serializes file access, normalizes nullable persisted collections, writes a flushed temporary file, atomically replaces the primary settings file, and retains the previous valid file as `settings.json.bak`.

If the primary settings file cannot be deserialized, the application attempts the backup before falling back to defaults. The original invalid file is preserved for diagnosis. This decision does not change the settings schema or user-facing Settings controls.

## DEC-019: Store plan controls belong in Settings

Status: Accepted

The MainWindow footer is the consolidated operational/status surface. It is presented as a flat footer row with a Fluent-backed top separator rather than an enclosing panel wrapper. It retains the existing status/activity text, progress indicator, and Retry control. Copyright, the resolved version text at the right edge, and packaged Store plan controls (`Basic`, `Premium`, and `Upgrade`) are presented in one compact, full-width row at the bottom of Settings. Unpackaged runs do not surface Store plan or Upgrade controls.

The existing MainWindow-owned Store entitlement services, entitlement rules, purchase route, and gating behavior remain unchanged; Settings receives presentation state and invokes the purchase route through a callback. Microsoft Store delivers package updates outside the LocalCam process.

## DEC-020: Microsoft Store-managed package updates

Status: Accepted

LocalCam relies on Microsoft Store to deliver updates for its x64 MSIX releases. The app does not check for package updates, render update-specific UI, persist update queue state, or request download, installation, restart, or cancellation through Store APIs.

This removes a fragile application-owned path whose lifecycle depended on Store context availability, UI-thread affinity, update consent, and restart timing. Store-flight validation remains the release-level evidence that a published package update reaches Store-installed clients.

## DEC-021: Validated multi-protocol local discovery

Status: Accepted

Local discovery remains bounded, best-effort, and IPv4-only. Standard-protocol replies contribute camera evidence only after validation: ONVIF requires a matching `NetworkVideoTransmitter` ProbeMatch and service address; SSDP requires a valid search response plus a bounded local UPnP description that identifies a video device; DNS-SD requires linked PTR/SRV records identifying an RTSP or camera-related service; and RTSP requires a parseable OPTIONS response with a matching CSeq. DNS-SD uses UDP 5353, joins mDNS on each eligible interface, and queries common RTSP/ONVIF service types. SSDP description fetches must remain on enumerated local subnets, avoid redirects, and use bounded response sizes and timeouts. HTTP fingerprints use normal TLS certificate validation.

Within a scan, protocol evidence is merged by IPv4 address and responsive or unresponsive host probe results are cached so the later subnet fallback does not repeat host probes. Connected IPv4 interfaces remain eligible even when they have no gateway. Tapo UDP payloads and Tapo-first internal scoring remain supported. Discovery sends no RTSP credentials and does not start media playback.

Guardrails: preserve Detect and Play fallback, detection identity reconciliation, credentials, cache expiry/eviction, user-facing brand-neutral labels, and scan cancellation. IPv6 discovery, proprietary Hikvision/Dahua protocols, arbitrary RTSP ports, and authenticated ONVIF management remain out of scope. RTSP port selection is governed by DEC-022.

## DEC-022: Additive route-aware discovery and validated RTSP port

Status: Partially superseded by DEC-024 (configured CIDR UI and probing only); validated RTSP-port behavior remains accepted

The existing automatic local-interface scan and its method order remain intact. Settings may supply up to 16 additional IPv4 CIDR ranges from /20 through /30, with a total cap of 8,192 additional hosts. Those targets join the existing per-host unicast probing/cache and evidence merge. Invalid values are rejected by Settings and ignored by the scanner if present in legacy or manually edited settings. Protocol multicast remains local-link behavior; the application does not imply that mDNS or multicast crosses routers.

Diagnostics classify observable adapter and route evidence using Windows network interfaces and the OS-selected local source address for each route lookup. The app reports Wi-Fi, virtual-network, wired/other, direct-subnet, or routed paths as available. Mesh, extender, wireless-backhaul, AP, and VMware NAT mode are not asserted unless an authoritative source exposes that fact. A configured CIDR does not create a route or bypass Windows firewall, network ACLs, NAT, or camera-side service restrictions.

Port 554 remains the default playback port. Port 8554 is used only when a validated RTSP OPTIONS exchange confirms RTSP on that port; this validated endpoint is retained in the recent-camera cache and used for playback/reconnect. No credentials are sent during discovery. Existing stream path normalization, credential handling, LibVLC options, and stream lifecycle remain unchanged.

This decision is based on Windows route entries exposing destination prefix, next hop, interface, and metric ([Microsoft route structure](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/mib-ipforward-row2)) and mDNS being link-local multicast ([RFC 6762](https://www.rfc-editor.org/info/rfc6762/)).

## DEC-023: On-demand early probing of configured camera networks

Status: Superseded by DEC-024

When the user configures additional IPv4 camera CIDR ranges, LocalCam probes those targets using the existing bounded unicast host-probe and evidence-merge path before waiting on link-local discovery protocols. When no ranges are configured, the existing local discovery method order is unchanged. ARP cache priming remains limited to connected local subnets because it cannot prime individual hosts across a routed boundary. Configured ranges remain on-demand and bounded by DEC-022; they do not imply that a NAT route, firewall permission, or remote camera service exists. The new early-pass result uses normal detection reconciliation and RTSP playback behavior, but is not persisted as the preferred local discovery method.

## DEC-024: Automatic bounded additional-network discovery

Status: Partially superseded by DEC-030 (adaptive-search trigger)

The technical Additional Camera Networks Settings field and persisted range input are removed. The established local discovery methods and their order remain unchanged. Only after those methods yield zero cameras does LocalCam run an additional unicast search. It derives private /24 candidate networks from valid recent-camera cache addresses, adapter DNS/DHCP addresses, and a bounded list of common home networks. It checks the Windows-selected route for each candidate and tests common gateway addresses. The first stage prioritizes candidates with network evidence and responsive gateways, then fills remaining range slots with the next ranked candidates. When untried candidates remain within the global limits, the second stage selects up to four more ranges regardless of whether stage one found cameras. Detections and evidence from both stages are merged. Across both stages it selects at most eight ranges and inventories at most 2,032 additional hosts from at most 16 candidates per scan. It reuses the existing per-host probe, evidence validation, cache, cancellation, and connection flow. The automatic method is not persisted as the preferred local discovery method.

This is a best-effort search, not network configuration or a guarantee of camera discovery. A VM NAT guest may not expose the host's physical LAN prefix, and a guest route or firewall may still prevent unicast camera access. The app does not change Windows routes, VMware configuration, firewall rules, or camera settings. Diagnostics record candidate and selected-range counts and sources without credentials or complete RTSP URLs. The former DEC-022 range-input portion and DEC-023 early probe are historical behavior superseded by this decision; the validated 8554 behavior of DEC-022 remains.

## DEC-025: Adaptive RTSP verification after local discovery

Status: Partially superseded by DEC-030 (adaptive-search trigger)

After the established discovery methods produce zero detections, the final adaptive pass may verify responsive hosts in its selected networks. It prioritizes hosts whose initial TCP probe confirmed RTSP ports, then uses remaining budget to try ports 554 and 8554 on other responsive candidates. The combined budget is limited to 64 endpoints across both search stages. Verification uses bounded unauthenticated OPTIONS requests for `*` and the configured stream path, plus one DESCRIBE request for port 554, and reads no more than 16 KiB per response under existing cancellation and timeout controls. A syntactically valid RTSP response with the matching CSeq is service evidence; 401/407 with an authentication challenge is recognized as an endpoint requiring authentication. The confirmed playback port remains constrained by DEC-022: 8554 is selected only after a validated OPTIONS response.

The verification pass never transmits saved RTSP credentials. Once a target is detected, the existing playback flow uses shared Settings credentials for that detected address only. Responsive non-camera devices may receive a bounded TCP connection attempt on fallback RTSP ports and, if a connection succeeds, unauthenticated RTSP requests; these probes do not change device configuration. Diagnostics record whether the initial port probe confirmed each target and its bounded outcome, and never store credentials, authorization headers, or complete RTSP URLs. Existing local method order, scoring, identity merge under DEC-031, reconnect-cache policy, and playback behavior remain unchanged.

## DEC-026: Incremental discovery playback and credential-specific scan handling

Status: Accepted

The scanner publishes cumulative detection snapshots after each completed local detection method and each adaptive unicast stage. The MainWindow reconciles each snapshot immediately and submits one playback request per newly discovered camera identity while the scan continues. The progress indicator remains active until discovery completes or is canceled. The established detection method order, probes, evidence scoring, identity reconciliation under DEC-031, and Bridged behavior remain unchanged.

If a camera is found while the shared RTSP username, password, or stream path is incomplete, discovery is canceled and Settings opens after scanner cleanup. If RTSP configuration is present but a discovery-started camera rejects it or otherwise fails playback, the failure remains on that camera's card and discovery continues for other cameras. User-requested playback retains the existing credential-related Settings escalation. Discovery-started identities are tracked so playback retries or subsequent LibVLC error events do not convert a camera-specific auto-play failure into a global Settings interruption.

## DEC-027: Confirm video output separately from LibVLC Playing

Status: Accepted

LibVLC `Playing` remains the established confirmation for a started RTSP playback attempt and for refreshing the recent-camera reconnect cache. It does not by itself prove that video output or frames are available. The per-camera health state therefore records first video evidence separately, using LibVLC video-output presence or decoded/displayed picture counters; media time and read-byte changes alone do not count as frame evidence.

The existing startup grace, health sampling cadence, stale deadline, and bounded recovery policy remain in force. If no video evidence has appeared by that deadline, the affected card reports that the stream connected but no video frames arrived. The existing recovery path remains per-camera; the no-video failure stays visible through recovery attempts and clears when video evidence appears. This change does not alter discovery methods, RTSP URL construction, credentials, stream start/stop, or the cache's `Playing` confirmation semantics.

## DEC-028: Refresh discovery after cache-first reconnect

Status: Accepted

Recent camera connections are a fast reconnect hint, not a complete inventory of currently reachable cameras. Startup reconnect and Detect and Play shall request playback for cached cameras first, then run the existing discovery pipeline even when all cached reconnects succeed. Discovery runs while cached streams play and while their reconnect confirmations remain tracked. Reconciliation preserves existing camera identities and active players; only newly discovered identities receive a new auto-play request. Discovery does not start when shared RTSP settings are incomplete, preserving the existing Settings escalation.

This decision does not change the cache expiry or two-consecutive-failure eviction rules, local discovery method order, adaptive discovery bounds, or the behavior of the established Bridged path.

## DEC-029: Prioritize the last successful method and run early protocol hints concurrently

Status: Accepted

Each discovery process shall place the valid persisted `LastSuccessfulDetectionMethod` first. A successful scan continues to update and persist that method at runtime so later startup or Detect and Play scans use the latest successful local method. If the preferred method is Tapo UDP broadcast or ONVIF WS-Discovery, it runs alone first and the other follows next. If there is no preferred method, or the preferred method is outside that pair, Tapo UDP broadcast and ONVIF WS-Discovery hint collection run concurrently as the first pair after the preferred method. Detection evidence is then processed in deterministic Tapo-before-ONVIF order.

The remaining default local order is mDNS/DNS-SD, SSDP/UPnP, ARP-seeded target probing, RTSP OPTIONS probing, and subnet fallback. Method probes, scoring, identity reconciliation as specified by DEC-031, adaptive-search bounds, and RTSP connection behavior remain unchanged. The adaptive-search trigger is governed by DEC-030. This decision supersedes only the local method-order statement in DEC-026; its incremental publishing, playback, and credential handling decisions remain in force.

## DEC-030: Run adaptive discovery after local results

Status: Accepted

After the existing local discovery methods finish, LocalCam shall run the existing `AdaptiveRtspVerificationProbe` whether or not those methods found cameras. Local detections remain published as they arrive and can start playback while the adaptive search runs. Adaptive detections merge into the same result set; existing identities and active streams are preserved by the current reconciliation path, and only newly discovered identities receive playback requests.

This changes only the adaptive pass trigger. It does not add a discovery method, change local method order or behavior, change candidate selection, or relax the existing bounds: at most eight additional `/24` networks across two stages, 2,032 additional hosts, and 64 unauthenticated RTSP verification endpoints. Connected local ranges remain excluded from the additional-range planner because the local methods already search those ranges. The pass remains best-effort and depends on the app being able to identify and route to candidate networks.

The purpose is to let a scan that finds cameras on one home-network segment continue checking other reachable segments, such as a separately routed mesh or IoT network. It does not claim that the app can identify exact mesh/extender topology or overcome client isolation, firewall rules, or missing routes.

## DEC-031: Preserve distinct camera endpoints when MAC addresses collide

Status: Accepted

When a discovery result contains multiple distinct IPv4 addresses with the same MAC address, LocalCam treats those addresses as separate camera identities for that result and uses each IP address as its identity. When a MAC address is unique in the current result, LocalCam continues to use that MAC address as the stable identity; detections without a MAC continue to use their IP address. Reconciliation preserves an existing tile's order by matching the endpoint IP when a previously unique MAC becomes ambiguous.

The MainWindow preserves an active player when only the identity representation changes for the same IP and MAC endpoint. A real detection change still invalidates the old tile binding and player callbacks. Discovery-start tracking follows the resolved identity so each distinct endpoint receives at most one automatic playback request per route.

When a MAC is ambiguous in the current detections or appears on multiple recent-cache entries, playback confirmation and reconnect-failure accounting match the cache entry by IP. When the MAC is unique, cache matching continues to use MAC first and IP as fallback, preserving the existing address-change behavior. The cache remains seven-day, uncapped, and evicts an entry only after two consecutive reconnect failures; its persisted schema is unchanged.

This decision supersedes earlier statements that duplicate known MAC addresses are always collapsed. Discovery probes and scoring, credentials, RTSP URL construction, playback lifecycle, and network bounds remain unchanged.
