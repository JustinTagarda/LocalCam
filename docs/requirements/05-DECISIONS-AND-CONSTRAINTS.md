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
