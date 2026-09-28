# LocalCam Traceability and Verification Plan

## Current evidence map

| Requirement area | Primary implementation evidence | Current test evidence | Gap |
|---|---|---|---|
| Startup/settings and theme | `App.xaml.cs`, `SettingsStore.cs`, `LocalCamSettings.cs`, `AppThemeService.cs`, `App.xaml`, `MainWindow.xaml(.cs)`, `SettingsWindow.xaml(.cs)` | `SettingsMergeTests.CloneSettingsPreservesAllPersistedState`; `SettingsStoreTests` obsolete-updater compatibility, backup recovery, concurrent-save, and invalid-file tests; FAST-BUILD and manual startup check | Add persisted-settings integration, pre-initialization theme mapping, persistence, brush-refresh, native-frame, host light/dark Fluent-resource, default Theme ComboBox behavior, accent-foreground UI, dashboard-before-engine-render, initialization retry, readiness gating, and repeated-launch activation checks |
| Discovery | `Networking/TapoCameraScanner.cs`, `Networking/AdaptiveRtspVerificationProbe.cs`, `Networking/CameraDiscoveryParsers.cs`, `Networking/Ipv4CidrRange.cs`, `Networking/CameraNetworkTopology.cs`, `Networking/AdaptiveCameraNetworkPlanner.cs`, `MainWindow.xaml.cs`, `SettingsWindow.xaml(.cs)`, `docs/requirements/08-RUNTIME-PIPELINES-AND-CHANGE-GUARDRAILS.md` | `CameraDiscoveryParserTests`, `CameraDiscoveryPipelineTests`, `TapoCameraScannerTests`, `AdaptiveRtspVerificationProbeTests`, `Ipv4CidrRangeTests`, `AdaptiveCameraNetworkPlannerTests`, `SettingsStoreTests` | Verify persisted last-successful method runs first and is updated after a successful result; verify default Tapo UDP/ONVIF concurrent hint collection and follow-on local order, incremental result delivery/playback, adaptive pass after partial local detections, credential-gated cancellation, route/target outcomes, RTSP-port cache behavior, and controlled network scenarios |
| Recent-camera reconnect | `Services/RecentCameraConnectionCache.cs`, `Services/CameraDetectionReconciler.cs`, `MainWindow.xaml.cs` | Cache-policy and detection-reconciliation tests | Add controlled-network check with fewer cached than reachable cameras; verify playback starts from cache before discovery completes, pending cache confirmations survive discovery, new identities start once, duplicate-MAC cache entries remain IP-scoped, unique-MAC address changes update the existing entry, existing streams remain attached, and timeout/failure accounting remains correct |
| Dashboard/playback and window state | `MainWindow.xaml(.cs)`, `InformationWindow.xaml(.cs)`, `Services/CameraDetectionReconciler.cs`, `Services/StreamHealthEvaluator.cs`, `LocalCam.Tests/CameraDetectionReconcilerTests.cs`, `LocalCam.Tests/StreamFailureClassificationTests.cs`, `LocalCam.Tests/StreamHealthEvaluatorTests.cs` | Camera detection reconciliation, stream-failure classification, and stream-health evaluator tests | Add FR-025 Information view acceptance checks; also add incremental Detect and Play timing, one auto-start per resolved identity, unique and colliding MAC handling, preservation of active playback during a representation-only identity change, missing-settings stop/deferred Settings, credential-rejection card isolation with continued discovery, confirmed-playback state transition, separate video-evidence confirmation and no-video timeout/card error, startup grace, consecutive stale-sample, bounded recovery/cooldown, terminal-event recovery invalidation, suspend/hibernate Stop All, resume-no-autostart, native WPF window, persisted-bounds, direct saved-size restore, close-time save, per-card failure isolation, credential-escalation, and manual live-stream checks |
| Settings UI | `SettingsWindow.xaml(.cs)` | No UI test source found | Add validation, dirty-state, folder, placeholder, credential-border, focus, Update-with-missing-credentials, camera setup guide link/browser-launch, single-row copyright/Store-plan footer, packaged Basic/Premium visibility, Upgrade callback, and theme/DPI checks |
| Snapshots | `MainWindow.xaml.cs`, settings folder logic | No test source found | Add unique-name and unavailable-folder tests |
| Recording | `MainWindow.xaml.cs`, recording policy docs | No test source found | Add single-session, rollover, and failure tests |
| Diagnostics | `Services/JsonLogStore.cs` | `LocalCam.Tests/JsonLogStoreTests.cs` | Redaction helper, exception-message/stack-trace serialization, nested structured-data, and seven-day retention tests; verify packaged application-data cleanup, unpackaged fallback location, release logging, and live seven-day rotation |
| Store packaging and submission | `LocalCam.Package/Package.appxmanifest`, `LocalCam.Package/LocalCam.Package.wapproj`, `docs/STORE-SUBMISSION-GUIDE.md` | Manifest identity/version checks, x64 MSIX build, upload-artifact hash, packaged smoke test, Partner Center submission record, and Store-flight evidence | Record external Partner Center certification and production-publication results for each release; local builds cannot establish those results |

## Shared button-style verification

## Route-aware discovery verification

Automated checks:

1. `Ipv4CidrRangeTests` verifies normalized IPv4 range creation, usable-host enumeration, containment, and invalid prefix/IPv6 rejection.
2. `AdaptiveCameraNetworkPlannerTests` verifies recent-camera and DNS/DHCP priority, connected-subnet exclusion, candidate caps, responsive gateway priority, filling spare range slots with ranked fallbacks, distinct second-stage ranges, and the eight-range total cap.
3. `SettingsStoreTests` confirms obsolete AdditionalCameraRanges input is dropped on save and a validated RTSP 8554 cache entry persists.
4. Existing scanner parser/candidate tests continue to pass; review confirms the seven local methods retain their order and targets and the adaptive pass starts after local methods whether or not local detections exist.
5. `AdaptiveRtspVerificationProbeTests` confirms confirmed-open RTSP endpoints are prioritized, responsive-host fallback is selected within the remaining endpoint budget, already detected addresses are skipped, requests include the configured path, and no Authorization header is generated.
6. `CameraDiscoveryParserTests` confirms an RTSP 401 authentication challenge with a matching CSeq is recognized while malformed, wrong-sequence, and HTTP responses are rejected.

Controlled-network manual checks:

1. With no saved preferred method, confirm Tapo UDP broadcast and ONVIF WS-Discovery start together, detections from each are merged, and later methods run in mDNS, SSDP, ARP, RTSP, subnet order. Confirm the first reported camera begins playback immediately.
2. Set each supported local method in `LastSuccessfulDetectionMethod` in turn. Confirm that method starts before every other method; if it is Tapo UDP or ONVIF, confirm the other early method starts afterward. Confirm a successful scan updates the saved value without restarting the app, and the next discovery starts with that value.
3. Run on a normal camera LAN. Confirm local cameras are published and begin playback before the adaptive pass completes; confirm the pass remains bounded and does not restart or disturb existing streams.
4. Run in a VMware NAT guest with a routed path to a camera network while at least one local camera is also discoverable. Scan without user-entered network data. Confirm the adaptive pass still starts after local methods, logs candidate source/route and selected-range/host counts, and probes each target once. Confirm newly found detections follow the existing connection flow while already playing cameras stay attached. Confirm logs state the attempted scope when NAT/host routing or firewall blocks the camera subnet.
5. Repeat with Wi-Fi, an extender, a mesh node, and an AP/backhaul setup where available. Confirm app reporting stays at observable Wi-Fi/direct/routed classification and does not assert exact mesh/extender/backhaul topology.
6. Confirm ARP priming remains limited to connected local subnets and adaptive routed targets use bounded unicast probes. Confirm mDNS, SSDP, and other link-local multicast behavior remains unchanged and is not reported as cross-router discovery.
7. Confirm port 554 remains preferred when both 554 and 8554 provide valid RTSP OPTIONS responses. When only 8554 validates, confirm playback uses 8554, Information shows 8554, and the recent-camera cache reconnects to 8554. An open 8554 port without a valid RTSP response must not change playback port.
8. Cancel a scan during either adaptive stage and verify prompt cancellation; confirm the first stage is limited to four /24 ranges, the second selects distinct untried ranges when available even after partial first-stage detections, and total expansion is capped at eight /24 ranges and 2,032 hosts. Confirm detections from local methods and both adaptive stages are merged, local playback can start before adaptive completion, total RTSP verification stays capped at 64 endpoints, and measure scan duration on unreachable networks.
9. In NAT, clear recent-camera entries and scan with credentials configured, then repeat with credentials empty. Confirm the adaptive pass tries responsive-host fallback targets when the initial port probe misses an RTSP port, reports whether each port was initially confirmed, reports challenge-required endpoints, and routes any detected camera through the existing playback/settings flow. Confirm the combined confirmed-open and fallback target count stays at or below 64 and no credentials or authorization headers appear in diagnostics or are sent to unverified hosts.

## RTSP credential and per-camera playback verification

For FR-008 and FR-009, perform the following manual checks:

1. Open Settings with empty credentials and confirm the username and password placeholders are visible.
2. Modify a non-credential setting with both credentials empty and save. Confirm the setting and empty credential values persist after reopening Settings, with no credential validation error blocking the save.
3. With detected cameras, trigger Detect and Play, Play all, and per-card Play with missing credentials. Confirm Settings opens, shows the exact required message, highlights only missing fields, and the stream-start flow does not close Settings or attempt RTSP playback.
4. Repeat stream-start validation with only the username missing and then only the password missing. Confirm only the missing field is red, focus moves to the username field, and the valid field retains the normal input border.
5. Open Settings and confirm the camera setup guide link is visible below Stream Path and opens the configured guide in the default browser.
6. With cached cameras and with a fresh discovery result, trigger Detect and Play. Confirm cache-first reconnect/discovery occurs and each detected camera receives one playback request, with no duplicate start request from rendering and route orchestration.
6a. Seed the recent cache with three working cameras while a fourth reachable camera is absent. On startup and separately through Detect and Play, confirm the three cached streams begin immediately, discovery still runs, the fourth camera is appended and starts playback as soon as it is reported, and the original three streams are not restarted. Confirm cached reconnect timeout/failure tracking remains active while discovery runs and duplicate scan reports do not cause duplicate playback.
7. With multiple detected cameras, cause one camera to fail because of credential rejection, network failure, or playback/decode failure. Confirm the failed card alone shows centered red error text, the suggestion is shown only for a classified reason, and other cameras continue streaming.
   - During a failed-camera fallback scan, confirm existing active cards and video surfaces remain visible. Return detections in a different order and with a repeated known MAC identity; verify existing players remain associated with the same camera, endpoints with a shared MAC at distinct IPs remain separate cards, a representation-only identity change does not stop the matching active player, and only stopped/new endpoints receive a playback request. If discovery returns no detections, existing cards remain visible and usable.
8. Confirm a credential-related playback failure opens Settings, while network, device/decode, and unknown failures do not open Settings.
9. Restore playback on the failed card and confirm its error text clears after LibVLC reports `Playing`.
10. Start a fresh discovery with complete RTSP settings and delay later discovery methods/stages. Confirm each camera appears and receives exactly one playback request as soon as its result is reported, while the progress indicator remains visible and scanning continues.
11. Repeat with either the username or password missing. Confirm the first reported camera remains visible, discovery cancels promptly, cleanup completes, and Settings opens with `RTSP credentials are missing or invalid.`
12. With credentials present but rejected by one discovered camera, confirm that camera displays its classified error on its card, Settings does not open, discovery continues, and later cameras with valid credentials start playback immediately. Confirm the existing manual Play credential-escalation behavior remains unchanged.
13. With a stream that raises LibVLC `Playing` before video output appears, confirm the playback event is logged without claiming video confirmation, the existing startup grace is honored, and subsequent vout/displayed/decoded-frame evidence is logged once and treated as confirmation. Confirm media-time/read-byte progress alone does not count as video evidence.
14. With a reachable RTSP endpoint that never exposes video output or decoded/displayed frames, confirm the existing health deadline produces the concise `The stream connected, but no video frames arrived.` card error, bounded per-camera recovery runs without delaying other camera streams, and the card retains the no-video error when recovery is exhausted. Confirm evidence arriving during recovery clears that specific error.
15. Confirm the recent-camera cache is still refreshed on the existing LibVLC `Playing` confirmation. With two cache entries sharing a MAC, confirm success and reconnect failure affect only the entry with the matching IP; with a unique MAC, confirm a changed IP still updates the existing cache entry. Detection probes, RTSP URL construction, credentials, and stream lifecycle behavior remain unchanged.

For Store UI placement and footer behavior, perform the following manual checks:

1. In an unpackaged run, confirm the MainWindow footer retains the status/activity text, progress indicator, and conditional Retry control; confirm the Settings footer shows copyright and the version at the right edge without Basic/Premium or Upgrade controls.
2. In a packaged Basic run, confirm the MainWindow footer retains all status/activity controls while Settings shows `Basic`, an enabled `Upgrade` button, and the version as the rightmost footer item.
3. In a packaged Premium run, confirm Settings shows `Premium`, hides Upgrade, and retains the version at the right edge.
4. Exercise video-engine preparation/failure, discovery progress, stream failure, snapshot/recording feedback, and retry states. Confirm every existing status message remains visible in the relocated MainWindow footer and no status/activity control is removed.
5. Activate Upgrade from Settings and confirm the existing confirmation, purchase, entitlement refresh, and accessibility restoration flow remains functional without changing persisted Settings values.
6. Repeat the MainWindow and Settings footer checks in System, Light, and Dark themes, at the supported DPI/scaling levels, and at the MainWindow minimum width. Confirm the MainWindow footer presents as a flat row with a top separator only, has no enclosing panel wrapper, and has no overlap when progress and Retry are simultaneously visible.

The app-wide button invariant is owned by `App.xaml` and must be checked for every button change:

1. Confirm `GlobalButtonStyle` retains the Settings baseline: Fluent-backed dynamic brushes, 1px border, `12,4` padding, `92` minimum width, `30` height, hand cursor, 4px corner radius, hover/pressed states, and disabled opacity.
2. Confirm the implicit `Button` style is based on `GlobalButtonStyle`.
3. Confirm every XAML button has either the implicit global style or an explicit style based on `GlobalButtonStyle`; no window-local button style may duplicate an independent button template.
4. Confirm every code-created button resolves a style whose inheritance chain reaches `GlobalButtonStyle`.
5. Confirm specialized icon, overlay, and status buttons preserve their required geometry, visibility, accessibility, and command behavior while inheriting the global baseline.
6. Repeat the visual check in System, Light, and Dark modes, including Settings, MainWindow, UnsavedChangesDialog, BasicFeatureGateDialog, and active camera-card overlays.

## Camera-area action-button verification

For the camera-area in-video action buttons, verify that `CameraOverlayIconButtonStyle` derives from `GlobalButtonStyle`, has no fixed `Width` or `Height`, explicitly sets `MinWidth` to `0`, and sets uniform `Padding` to `6px`. Confirm every action icon uses a `16x16` content canvas, the buttons remain content-sized with automatic height, and existing glyph proportions, visibility, command, tooltip, accessibility, and overlay behavior are retained. Repeat in collapsed and expanded cards during active playback, resize, DPI scaling, and System/Light/Dark theme changes. Do not apply this sizing rule to non-camera buttons.

## Camera Information view verification

For FR-025, perform the following manual checks:

1. Confirm a detected camera card shows an icon-only Information button as the first in-video action. Confirm it uses the camera overlay style and size, has the `Information` tooltip and accessible name, and is keyboard reachable.
2. Confirm empty cards do not show Information. Open Information for a detected camera and verify available IP address, hostname, MAC address, brand-neutral detection reason, confidence, and open ports are shown. Missing values must be labeled unavailable; discovery method must be labeled as not retained per camera when it cannot be associated reliably.
3. Confirm connection details show RTSP, host, port `554`, stream path and its configuration status, and whether shared credentials are configured. Verify neither credential value nor any credential-bearing URL appears.
4. Open the view while playback is stopped and playing. Confirm playback lifecycle, position/duration when available, and visible playback error details match the current card. While recording, confirm recording status, elapsed time, and output path are current; after stopping, confirm the view reports not recording.
5. Verify detection reason text does not expose Tapo, TAPO, or TP-Link wording.
6. Click the icon-only Copy action at the left edge of the modal action row. Confirm the clipboard contains every displayed section and label/value in readable text, with credential values and credential-bearing URLs absent. Confirm success feedback appears; exercise clipboard-unavailable behavior and confirm a concise failure message appears.
7. Repeat with persisted System, Light, and Dark themes. While streaming, resize and move the window, use expanded and collapsed cards, and confirm the Information action remains attached to its own video area and the modal stays readable and centered on its owner.

## Theme verification procedure

For FR-020, perform the following manual checks on a Windows host whose current theme is known:

1. Start the Debug executable with persisted `System`, `Light`, and `Dark` preferences separately.
2. Confirm the main window, custom Settings window, inputs, labels, borders, buttons, overlays, and auxiliary update dialog match the selected preference.
3. Change the preference in Settings, click `Update`, and confirm the main window updates without closing the app or stopping active streams.
4. Reopen Settings and confirm the saved preference and visual theme remain aligned.
5. Repeat the change in both directions and verify no process crash occurs.
6. If a crash occurs, collect the latest JSONL diagnostics from the application-data log folder and Windows `Application`, `.NET Runtime`, and `Windows Error Reporting` events.
7. Confirm no decorative outer client border is present on MainWindow or SettingsWindow, and confirm the Settings Theme ComboBox uses the default WPF closed control, focus visual, arrow, popup, and highlighted-item behavior.

The known regression guard is the frozen-brush failure: `AppThemeService` must clone Fluent brushes and replace aliases; it must not assign `Color` or `Opacity` on a frozen brush.

## Recommended verification layers

1. Unit tests for pure normalization, settings comparison, URL construction, folder resolution, detection labeling, and recording state transitions.
2. Component tests using fake network/media/store boundaries.
3. UI acceptance checks for control visibility, accessibility, overlays, settings escalation, and window state.
   - Standard WPF window checks: native minimize/maximize/restore/close, system menu, snap behavior, minimum size, multi-monitor movement, DPI behavior, persisted bounds, direct saved-size restore, and close-time persistence after the final move or resize.
4. Controlled-network integration checks for discovery and RTSP startup.
5. Follow [the Store submission guide](../STORE-SUBMISSION-GUIDE.md) for x64 package creation, manifest/version validation, local packaged smoke testing, Partner Center submission evidence, and Store-flight update delivery.

## Startup responsiveness verification

For FR-001 and FR-024, verify the following on a Debug executable:

1. Start after a cold native-library cache and confirm the main dashboard is visible while `Preparing video engine...` and the indeterminate progress indicator are shown.
2. Confirm Play all and per-card Play are unavailable until LibVLC initialization completes, while Settings remains available.
3. Confirm recent-camera reconnect and local discovery begin only after the video engine is ready.
4. Simulate missing or invalid LibVLC native assets and confirm the dashboard remains open with a concise failure status and a retry control that is focusable only while visible.
5. Use the retry control and confirm successful initialization restores normal stream controls and startup flow.
6. Launch the executable again while the first instance is starting or visible and confirm the existing window is activated without creating a second window.
7. Close during video-engine initialization and confirm the process exits without leaving a live LibVLC engine or activation listener.

## Playback health and recovery verification

For FR-009, FR-018, NFR-006, and NFR-008, perform the following checks:

1. Start one and then four compatible cameras. Confirm playback-request logs precede distinct LibVLC playback-confirmed logs and that no recovery occurs during the startup grace period.
2. Confirm repeated `Playing` events do not interrupt the monitor sampling interval or create a restart storm.
3. Hold one camera without advancing video output. Confirm recovery requires consecutive unhealthy samples, respects cooldown, and stops after the per-camera attempt limit.
4. Confirm recovery exhaustion shows a centered red error only on the failed card and leaves other cameras streaming.
5. Restore the failed camera and use Play. Confirm manual playback clears the exhausted recovery state and the card error after confirmed playback.
6. Trigger credential rejection, network failure, decode/output failure, and an unknown failure. Confirm only credential-related failures open Settings.
7. Verify repeated LibVLC warnings/errors are rate-limited while the latest error remains available for classification.
8. Repeat with one camera and four cameras while checking Windows Application, .NET Runtime, Windows Error Reporting, and relevant graphics-driver events. Record whether Direct3D11 errors or LiveKernel events recur.

## Minimum acceptance suite for future changes

- Verify from the repository directory that `dotnet --version` reports exactly `10.0.400`; stop if the pinned SDK is unavailable.
- Build the affected project with the repository FAST-BUILD command.
- Run all available automated tests.
- Verify the affected happy path and at least one failure path.
- Confirm settings are backward-compatible with existing JSON.
- Verify seven-day cache expiry, two-failure eviction, stable camera/playback-attempt handling, bounded playback confirmation timeout, RTSP-setting invalidation, discovery fallback, detection replacement while an old player emits late events, and one terminal-event recovery attempt.
- With one or more active streams and an active recording, enter both Sleep and Hibernate. Confirm Stop All runs before suspension, detected tiles and connection properties remain, recording is stopped, and automatic/user resume leaves every stream stopped.
- Confirm diagnostics contain no credentials, complete RTSP URLs, URL query secrets, or secret-bearing structured fields.
- Update requirement status and evidence links when behavior changes.

Toolchain guardrail: if the .NET SDK pin changes, verify `global.json`, `AGENTS.md`, README build instructions, NFR-009, the architecture baseline, and the decision record are updated together. Do not accept a build completed with a different SDK as evidence for the pinned-toolchain requirement.

## Definition of done for a requirement

A requirement is done when its wording is testable, implementation exists, the relevant automated or manual verification is recorded, failure behavior is defined, and traceability points to the owning code path.
