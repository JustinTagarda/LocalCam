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

MainWindow, SettingsWindow, and StoreUpdateProgressWindow use native Windows/WPF window frames. Their client areas begin with flattened root grids rather than decorative outer border wrappers. Settings no longer owns a custom title bar, close button, or manual drag behavior.

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

Each tile binds a media-player instance to an immutable camera identity for that playback attempt. Reassigning a tile to a different detection stops and disposes the old player before it can affect the new camera. LibVLC `Playing` is the live-state and recent-cache confirmation boundary; a playback request being accepted is not confirmation. A terminal `EndReached` or `EncounteredError` event receives one bounded restart attempt, while failed recent-cache reconnects continue to use discovery fallback and the two-failure eviction policy.
