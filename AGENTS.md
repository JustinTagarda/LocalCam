# LocalCam

## Inheritance Rule

- By default, follow [D:\Projects\AGENTS.md](D:\Projects\AGENTS.md).
- When this repo `AGENTS.md` provides project-specific instructions, those override global instructions.
- If there is no conflict, apply both global and repo-local instructions.

## Project Build Metadata

- `FAST_BUILD_PROJECT`: `LocalCam.csproj`
- `DEBUG_EXE_PATH`: `bin\Debug\net10.0-windows10.0.19041.0\LocalCam.exe`
- INSTANCE_MODE: `single-instance`
- PACKAGE_ARCHITECTURE: `x64-only`

## .NET SDK Toolchain Policy

- The repository pins .NET SDK `10.0.400` in `global.json` with `rollForward` disabled.
- Use exactly .NET SDK `10.0.400` for LocalCam builds, tests, packaging, and generated build artifacts.
- Before any build or test, verify `dotnet --version` reports `10.0.400` from the repository directory.
- Do not silently change `global.json` to another SDK version, use an installed fallback SDK, or bypass the repository SDK pin.
- A toolchain update requires explicit user authorization and synchronized updates to `global.json`, this instruction file, the requirements documentation, and verification evidence.
- If `10.0.400` is unavailable, stop and report the toolchain gap instead of falling back.

## Packaging Architecture Policy

- LocalCam is an x64 desktop app.
- Keep `LocalCam.csproj` runtime identifiers limited to `win-x64`.
- Do not add ARM64, win-arm64, AnyCPU, or multi-architecture packaging targets unless the user explicitly requests a packaging architecture policy change.

## Reusable Rules

- Mandatory enforcement: implement and keep behavior aligned with `D:\Projects\DEBUG-LOGGING.md`.
- Treat the workspace as the source of truth.
- Read local instructions first when they exist.
- Build a quick mental model before changing code.
- Inspect structure, entrypoints, config, core modules, data flow, and dependencies before editing.
- Search for existing patterns before introducing new ones.
- Prefer the existing architecture over idealized refactors.
- Make the smallest change that solves the problem.
- Verify facts in the codebase; do not speculate.
- If something is unclear, state `not found`.
- Preserve style, naming, and architecture.
- Avoid unrelated refactors.
- Do not overwrite user changes unless explicitly asked.
- Keep comments only when they add real clarity.
- Use ASCII by default unless the file already uses non-ASCII.
- Never assume missing files.
- Only modify provided files.
- Preserve existing user-facing controls by default.
- If a control must materially change to complete the task, stop first and explain what would change, why it is necessary, and what behavior would be lost or replaced.
- Keep the app lean.
- Before adding a package or heavy framework, ask whether built-in platform functionality can do the job.
- Add dependencies only when there is a clear project need and long-term maintenance cost is justified.
- Use minimal structured logging where it helps diagnose failures.
- Do not spam logs during normal interaction.
- Prefer a clear logging abstraction over scattered debug output.
- Prefer readability over cleverness.
- Use small focused methods.
- Use `async` and `await` correctly.
- Do not swallow exceptions silently.
- Avoid `async void` except for real event handlers.
- Do not edit, rewrite, regenerate, move, or delete `AGENTS.md` or similar instruction files unless explicitly asked.
- Treat instruction files as human-owned and read-only by default.
- Do not hardcode real runtime business data in code, prompts, defaults, or tests that behave like production data.
- Keep AI-facing prompt text in one owning file or prompt source per prompt.
- Do not duplicate prompt prose across files without a clear ownership reason.
- If the correct runtime store or owning prompt file is missing or unclear, stop and ask instead of inventing one.
- When asked to draw or describe control layouts, use ASCII tree format by default unless another format is requested.
- Prefer targeted tests or checks.
- Validate the affected path when the project has a known build or test command.
- Call out gaps if verification cannot be completed.
- Use the appropriate build mode for routine work rather than defaulting to a full build.
- Prefer the project’s required toolchain when builds are needed.
- A task is not done unless the code builds, fits the project structure, has no obvious dead code, has sensible behavior, handles failures reasonably, and remains maintainable.

## Current Implementation Snapshot

- Runtime/UI:
  - Single-window WPF desktop app (`MainWindow`) using the native Windows frame and a flattened client-area root grid.
  - Startup can reconnect recent cameras when enabled; Detect and Play retries the cache-first reconnect/discovery flow from the same window.
  - Camera tiles are shown based on current detections, with expand/collapse behavior and responsive layout.
  - Settings edits RTSP credentials, stream path, reconnect preference, theme, snapshot folder, and recording folder.
  - Settings uses a native WPF window frame and flattened client-area root grid; it does not use a custom title bar.
  - Detect and Play starts playback for detected cameras; Reconnect recent cameras on startup is the persisted startup preference.

- Discovery:
  - Local-network discovery is heuristic and best-effort.
  - Scanner uses multi-method probing with persisted preferred detection method.
  - Detection and scan lifecycle statuses are surfaced in the main window.
  - After the local method sequence completes, the existing bounded adaptive unicast search runs whether or not local cameras were found; it does not require user-entered CIDR ranges.
  - Windows-observable interface and route clues do not establish exact mesh, extender, access-point, or wireless-backhaul identity.

- Streaming:
  - RTSP playback uses LibVLCSharp.
  - Start/stop controls are state-gated by scan state, stream state, and credentials.
  - Stream resources are cleaned up on stop/close.

- Persistence and diagnostics:
  - App settings persist at `%LocalAppData%\\LocalCam\\settings.json`.
  - Structured JSONL app diagnostics use one `JsonLogStore` route across Debug, Release, and installed builds.
  - Packaged builds write under Windows package-local application data, which is removed with the package; unpackaged builds use `%LocalAppData%\\LocalCam\\LocalState\\logs` and never write beside the launched executable.
  - Diagnostics redact credentials, complete RTSP URLs, and secret-bearing values, and retain log files for seven days.
  - Shared RTSP credentials are stored in the local JSON settings file; diagnostics must never disclose them.

## Pipeline And Route Change Control

- Before changing an entrypoint, pipeline, persistence route, network route, playback path, or shutdown path, read `docs/requirements/08-RUNTIME-PIPELINES-AND-CHANGE-GUARDRAILS.md` and the applicable requirement/decision records.
- Preserve the existing owners, ordering, state transitions, cancellation boundaries, persistence side effects, and UI feedback described there unless the user explicitly authorizes the specific behavior change.
- Do not bypass an existing route by adding a parallel path that has different identity, cache, credential, logging, or cleanup behavior.
- Changes crossing subsystem boundaries require an accepted decision record before implementation; behavior changes update the SRS, architecture baseline, and traceability plan in the same change.
- Keep discovery, camera identity reconciliation, playback, settings escalation, reconnect cache, and per-camera errors as separate but connected stages. Local results stay incremental; adaptive discovery follows all local methods even after local detections and retains its documented bounds.
- Treat the pipeline guardrail document as a map of current behavior, not proof of integration coverage. Record unverified live-network, WPF, LibVLC, or Store behavior as unverified.

## Theme Implementation And Change Guardrails

- LocalCam supports persisted `System`, `Light`, and `Dark` theme preferences through `Application.ThemeMode` in `Services/AppThemeService.cs`.
- The persisted theme must be applied before `MainWindow.InitializeComponent()` so the first visual tree is created under the selected WPF Fluent theme.
- User-facing colors must come from Windows-provided WPF Fluent resources. Do not introduce fixed hex colors, a LocalCam-specific accent palette, or legacy `SystemColors` mappings for theme-dependent application content without explicit user instruction.
- The application-level brush aliases in `App.xaml` are intentionally retained for existing XAML and code-created controls. `AppThemeService.Apply` must refresh those aliases from the active Fluent brush resources after every theme change.
- Fluent brushes may be frozen. Never mutate a resolved Fluent brush or a frozen LocalCam brush in place; use an unfrozen clone/resource replacement and preserve existing control references safely.
- Runtime theme changes must refresh both XAML-bound surfaces and dynamically created camera-card controls, overlays, badges, and icons without rebuilding or stopping active streams.
- Do not change the `System`/`Light`/`Dark` preference meanings, startup ordering, Fluent resource mapping, brush-refresh behavior, or theme persistence without explicit user instruction.
- Any future theme change must include a live check of persisted Light, Dark, and System modes, including changing the preference while Settings is open and reopening the dialog.
- If a theme change causes a crash, inspect the latest JSONL diagnostics from the active application-data log folder and Windows Application/.NET Runtime event logs before modifying the theme code.

## Window Framing And Theme Control Guardrails

- MainWindow and SettingsWindow use native WPF/Windows window frames. Do not reintroduce `WindowStyle="None"`, `AllowsTransparency="True"`, custom title bars, client-area close buttons, or manual `DragMove()` logic without explicit user instruction.
- Keep the client-area root of those windows flattened to a `Grid`; do not add an outer decorative `Border` solely for window framing, border brush, border thickness, corner radius, or clipping.
- Internal layout borders remain allowed when they represent a real panel, status surface, input, card, separator, or popup surface. Do not remove those as part of window-frame cleanup.
- Settings theme selection must use a complete themed ComboBox template for the closed control and dropdown popup. It must use dynamic Fluent-backed aliases, preserve System/Light/Dark semantics, and remain visually consistent with Settings inputs and buttons.
- Do not replace the native window frame with a custom surface, introduce fixed theme colors, or change theme persistence/selection behavior without explicit instruction.
- Any future window-frame or Theme ComboBox modification requires a live check of MainWindow, SettingsWindow, and the Theme dropdown in System, Light, and Dark modes, plus a FAST-BUILD verification.

- Distribution:
  - LocalCam runs as a non-Store desktop app from project build output during development.
  - Microsoft Store distribution uses the x64 packaging project. Microsoft Store delivers MSIX updates; LocalCam does not implement in-app update checks, update UI, queue recovery, or self-installation.
  - Store-specific entitlement and purchase behavior is outside this update-delivery change; do not add new Store monetization workflows unless explicitly authorized.

## Brand-Neutral UI With Tapo-First Implementation Policy

### Intent

LocalCam must present itself in the user interface as a generic local/network camera application, not as a Tapo-only application.

The implementation may remain Tapo-first under the hood. Existing Tapo/TP-Link discovery heuristics, scanner names, detection method names, scoring logic, and RTSP streaming behavior must not be refactored or generalized unless the user explicitly requests that work.

This policy exists to avoid discouraging users with non-Tapo cameras from trying the app while preserving the current tested implementation.

### Core Rule

- User-facing text must be brand-neutral.
- Internal implementation may remain Tapo-specific where that reflects actual behavior.
- Do not infer that brand-neutral UI requires scanner refactoring.
- Do not rename internal Tapo-specific code identifiers unless explicitly requested.
- Do not change detection behavior while performing a UI wording pass.

### User-Facing Wording Requirements

Avoid visible UI wording that mentions:

- `Tapo`
- `TAPO`
- `TP-Link`
- `Tapo camera`
- `likely Tapo camera`

Use neutral wording instead:

- `camera`
- `network camera`
- `local camera`
- `compatible camera`
- `RTSP stream`
- `local discovery`

Examples of required UI wording:

- `Searching local network for TAPO cameras...`
  - Use: `Searching local network for cameras...`

- `No TAPO camera detected. Retry search?`
  - Use: `No compatible camera detected. Retry search?`

- `No TAPO camera detected.`
  - Use: `No compatible camera detected.`

- `No TAPO camera detected. Tried: {methods}.`
  - Use: `No compatible camera detected. Tried: {methods}.`

- `Detected {count} camera(s) using Tapo UDP.`
  - Use: `Detected {count} camera(s) using local discovery.`

- `Local network scan found one or more likely Tapo cameras.`
  - If shown to users, use: `Local network scan found one or more compatible cameras.`

### Detection Method Display Names

Internal enum names may remain unchanged.

When detection method names are shown to users, use this display mapping:

- `OnvifWsDiscovery` -> `ONVIF`
- `SsdpUpnpSearch` -> `SSDP`
- `TapoUdpBroadcast` -> `local discovery`
- `MdnsDnsSdSweep` -> `mDNS`
- `ArpSeededTargetProbe` -> `ARP probe`
- `SubnetProbeFallback` -> `subnet probe`

Do not expose `Tapo UDP` in normal UI text.

### Internal Implementation Guardrails

The following may remain Tapo/TP-Link-specific and must not be renamed during a UI wording-only task:

- `TapoCameraScanner`
- `TapoCameraDetection`
- `TapoDetectionMethod`
- `TapoScanDiagnostics`
- `TapoUdpBroadcast`
- `TapoDiscoveryPayloads`
- `TpLinkOuiPrefixes`
- `TryProbeTapoUnicastAsync`
- Tapo/TP-Link HTTP fingerprint checks
- Tapo/TP-Link hostname checks
- TP-Link MAC OUI scoring
- Diagnostic payload fields that describe Tapo-specific internals

These names are allowed because they describe implementation details, not product positioning.

### Discovery Behavior Requirements

Current discovery behavior must remain functionally unchanged unless explicitly requested.

The app remains Tapo-first and may continue using:

- ONVIF WS-Discovery
- SSDP/UPnP discovery
- Tapo UDP broadcast
- mDNS/DNS-SD probing
- ARP-seeded target probing
- subnet probing
- TP-Link/Tapo UDP payloads
- TP-Link OUI scoring
- Tapo/TP-Link HTTP, hostname, and fingerprint markers

The app may discover non-Tapo cameras when they expose compatible services, especially RTSP and ONVIF.

Route-aware discovery additions:

- Preserve the existing automatic local-network methods, ordering, evidence scoring, identity merge, cancellation, and per-host probe cache.
- Resolve the current `LastSuccessfulDetectionMethod` for every scan, run it before other local methods, and continue updating it after successful local scans; never pin it once at process startup or persist the adaptive verifier as the preferred local method.
- Run the existing bounded `AdaptiveRtspVerificationProbe` after the local method sequence whether or not local methods found cameras. Do not add a second adaptive route or change its selection, request, endpoint, host, or range limits without explicit authorization.
- Automatic private `/24` candidates are inferred from recent confirmed camera addresses, adapter DNS/DHCP clues, and bounded common home-network candidates; the app does not expose manual CIDR entry in Settings.
- Additional ranges add unicast host probes. Do not claim that local-link mDNS or multicast discovery crosses routers; inferred targets do not create a route or bypass NAT/firewall policy.
- Use Windows-observable interface and selected-route data only. Do not infer exact mesh, extender, AP, wireless-backhaul, or VMware NAT mode from an adapter label alone.
- Discovery may select RTSP port 8554 only after a validated RTSP OPTIONS reply confirms the service. Port 554 remains the default. Preserve the confirmed port in recent-camera reconnect data.
- Never send credentials during discovery. Keep stream path normalization, credential handling, LibVLC options, and stream lifecycle unchanged.

Do not claim or imply universal camera compatibility.

Avoid wording such as:

- `works with all cameras`
- `supports every RTSP camera`
- `universal ONVIF camera viewer`

### Settings Requirements

Settings UI must remain generic and RTSP-focused.

Keep wording such as:

- `RTSP Username`
- `RTSP Password`
- `Stream Path`
- `Reconnect recent cameras on startup`
- `Snapshot Save Folder`
- `Recording Save Folder`

Do not add brand selectors, brand presets, model fields, or manufacturer fields unless explicitly requested.

Do not change the default stream path unless explicitly requested.

## Settings Stream Path Policy

- Scope:
- Applies to `Settings` stream path behavior.

- Requirements:
- Default/initial stream path value must be `stream1`.
- User can change stream path in Settings.
- Stream path changes must persist and be loaded on next app start.

- Precedence:
- If any existing instruction in this file overlaps or conflicts with this stream path policy, this section wins.

### Streaming Requirements

RTSP streaming behavior must remain unchanged during brand-neutral UI work, except that the explicitly approved route-aware discovery feature may carry a validated RTSP service port of 8554 from discovery into playback and recent-camera reconnect.

Do not change:

- RTSP URL credential escaping and normalized path behavior
- arbitrary RTSP ports; only validated 554 and 8554 are supported, with 554 default
- credential handling
- stream path normalization
- LibVLC options
- stream start/stop behavior
- snapshot behavior
- recording behavior

Current RTSP URL construction may remain:

`rtsp://{username}:{password}@{host}:{validatedPort}/{streamPath}` where `validatedPort` is `554` by default or `8554` only after a valid RTSP OPTIONS response.

## Stream Start Validation and Settings Escalation Policy

- Scope:
- Applies when starting video stream from:
  - top toolbar `Play all`
  - per-card `Play`
  - Detect and Play

- Trigger condition:
- If stream start fails because RTSP configuration is missing, incomplete, or invalid, including:
  - missing/invalid RTSP credentials
  - missing/invalid stream path

- Required behavior:
- Open `Settings` immediately.
- Show this exact message text in Settings:
  - `RTSP credentials are missing or invalid.`
- Message style and placement:
  - concise
  - red text
  - lower-left of Settings dialog
  - same row as action buttons, left side

- Guardrails:
- For these validation failures, do not rely on generic start-failed messaging alone.
- Keep behavior consistent across all three stream-start entry points.

- Precedence:
- If any existing instruction in this file overlaps or conflicts with this policy for stream-start validation handling, this section wins.

### Diagnostics And Logging

User-visible diagnostics must be brand-neutral.

Internal structured logs may remain Tapo-specific when they describe actual implementation behavior.

Rule:

- User-visible text: brand-neutral.
- Developer/internal diagnostics: technically accurate.

Do not rename diagnostic event names or structured log fields just to remove Tapo wording unless explicitly requested.

### Documentation Positioning

For developer documentation, use accurate wording:

`LocalCam is Tapo-first and optimized for TP-Link/Tapo discovery, while also supporting compatible RTSP/ONVIF cameras when they expose similar network services.`

For user-facing or store-facing wording, use neutral positioning:

`LocalCam discovers compatible cameras on your local network and streams RTSP video in a multi-camera viewer.`

### Acceptance Criteria For Brand-Neutral UI Changes

A brand-neutral UI task is complete only when:

- No normal visible UI text uses `Tapo`, `TAPO`, or `TP-Link`.
- Detection and streaming behavior are unchanged.
- Detection method labels shown to users are brand-neutral.
- Settings remain generic and RTSP-focused.
- Internal identifiers may remain Tapo-specific.
- Internal logs may remain Tapo-specific where technically accurate.
- No new dependencies are introduced.
- No unrelated UI, scanner, streaming, snapshot, recording, persistence, or settings behavior is changed.
- The project builds using the required fast build command.

### Out Of Scope Unless Explicitly Requested

Do not include any of the following in a brand-neutral UI wording task:

- Generic brand scanner architecture
- Manual camera IP entry
- Custom RTSP URL support
- Non-`554` RTSP port support
- Brand presets
- ONVIF profile negotiation
- Authentication discovery
- Camera model display
- Camera manufacturer display
- Internal scanner renaming
- Large documentation rewrites
- Discovery algorithm changes
- Streaming architecture changes

## LibVLCSharp.WPF.VideoView Overlay Policy

- Scope:
- Applies to all UI issues related to `LibVLCSharp.WPF.VideoView`: layering, overlays, click handling, badges, toolbars, and in-video controls.
- Default Rule:
- Implement overlay UI inside `VideoView` content.
- Treat this as mandatory for fixes and new UI behavior around `VideoView`.
- Do not place overlay controls as sibling WPF elements intended to appear above `VideoView`.
- Required Pattern:
- Place overlay controls as children/content of the `VideoView` host.
- Keep overlays local to each camera card and anchored to video bounds.
- Use standard WPF alignment/margins inside `VideoView` content for placement.
- Manage overlay z-order only within `VideoView` content.
- Validate during active streaming, not only when idle.
- Verification Checklist:
- Overlay stays visible while video is playing.
- Overlay moves and resizes with its camera card.
- Overlay interactions (click, hover, focus) work reliably.
- Behavior is correct in normal and expanded/collapsed card states.
- Behavior remains correct after window move, maximize/restore, and DPI scaling changes.
- Exception Handling:
- If in-`VideoView` overlay cannot satisfy a requirement, document:
- exact limitation
- reproducible steps
- expected vs actual behavior
- proposed fallback and tradeoffs
- Require explicit approval before implementing any fallback that uses separate overlay windows/surfaces.
- Guardrails:
- Keep changes minimal and localized to the affected card/video path.
- Do not mix multiple overlay strategies in one feature unless explicitly required.
- Avoid unrelated refactors while fixing `VideoView` UI issues.
- Definition of Done:
- Overlay behavior is stable under live streaming and window/layout changes.
- Controls remain visually attached to their owning camera card.
- No regression in existing camera card interactions.

## Button Accessibility and Visibility Policy

- Global:
- Hidden controls must not be keyboard-focusable or screen-reader actionable.
- Disabled controls that are marked always visible must remain visible but non-interactive.

- Top toolbar buttons:
- Detect and Play:
- always visible
- disable while detection is running
- enable when detection is not running
- Play all:
- always visible
- enable if one or more cards are not playing video
- disable if all cards are playing video
- Stop All:
- always visible
- enable if one or more cards are playing video
- disable if no cards are playing video
- Settings:
- always visible
- always enabled

- Per-card buttons:
- Play:
- visible only when camera is detected and video is not playing
- hidden otherwise
- always enabled when visible
- Stop:
- visible only when camera is detected and video is playing
- hidden otherwise
- always enabled when visible
- Snapshot:
- icon-only button
- place on the card toolbar immediately after Play/Stop
- visible only when video is playing
- hidden otherwise
- disable while snapshot save is processing
- enable when snapshot save completes (success or failure)
- onclick captures a snapshot image from the currently playing video for that card
- Expand:
- visible only when video is playing and card is collapsed
- hidden otherwise
- always enabled when visible
- Collapse:
- visible only when video is playing and card is expanded
- hidden otherwise
- always enabled when visible

- Per-card interaction:
- Card double-click:
- enabled only when that card's video is playing
- disabled when that card's video is not playing
- when enabled, toggles collapsed or expanded state (same behavior as Expand and Collapse)

- State definitions:
- Detected: card has a valid discovered camera target.
- Playing: card has active video stream playback.
- Expanded or collapsed: current visual state of the card layout.
- Expand and Collapse are mutually exclusive and only relevant while playing.

## Snapshot Save Location Policy

- Add a Settings option for snapshot save folder selection using a folder picker (`Snapshot Save Folder`).
- Persist the selected folder path in `%LocalAppData%\\LocalCam\\settings.json` and load it on startup.
- Default effective snapshot save folder is `%UserProfile%\\Pictures\\LocalCam` (shown as `Pictures` in UI when applicable).
- Effective save path rule:
- if the active folder is the user's Pictures folder, save to `%UserProfile%\\Pictures\\LocalCam`
- if the active folder is any other user-selected folder, save directly in that folder (no forced `LocalCam` subfolder)
- Create `%UserProfile%\\Pictures\\LocalCam` if it does not exist when Pictures is the active folder.
- Keep snapshot filenames unique to avoid collisions.
- Show a concise user-facing error and structured diagnostic log if the target folder is unavailable or inaccessible at save time.

## Video Recording Policy (Per Card)

- Scope:
- Applies to per-card manual video recording from active RTSP playback cards.

- Recording mode and concurrency:
- Manual recording only.
- Exactly one active recording session is allowed across all cards at a time.
- If a user starts recording on a different card while another card is recording, the current recording must auto-stop first, then recording starts on the requested card.
- This cross-card switch must be non-blocking and must report activity through the existing status/activity panel (`StreamingStatusText`).

- Recording lifecycle:
- Treat LibVLC recorder events as authoritative for recording state.
- If the recording media player reports stopped, ended, or encountered error unexpectedly, clear the active recording state, hide the recording badge, restore the button to `Record`, and report status through `StreamingStatusText`.
- Do not leave a card in `Recording` UI state after the recorder has stopped or failed.
- Segment rollover must log and present success only when the next segment actually starts.
- Stopping playback on the recording card must also stop recording for that card.

- Format and segmentation:
- Recording output format is `.ts`.
- No remux and no transcoding in this policy scope.
- Maximum segment duration is 60 minutes per file.
- When the 60-minute limit is reached during an active recording, the app should continue recording by rolling to a new segment file for the same card when playback is still active.

- Per-card toolbar button behavior:
- Add a `Record` button to each card toolbar.
- Place the `Record` button immediately after `Snapshot`.
- Visibility and enablement baseline must match `Snapshot` behavior:
- visible only when video is playing
- hidden otherwise
- disable while a recording start/stop operation is processing
- enable when processing completes (success or failure)
- Icon and tooltip states are mandatory:
- `Play`: green triangle icon, tooltip `Play`
- `Stop Stream`: white square icon, tooltip `Stop Stream`
- `Record` (idle): red circle icon, tooltip `Record`
- `Record` (active stop state): red square icon, tooltip `Stop Recording`
- Reject static `Record` meaning during active recording; explicit stop-recording state is mandatory.

- Recording status surface:
- Recording-scope user feedback must use the existing status/activity panel (`StreamingStatusText`).
- Do not use toast messages for recording start/stop/switch/failure/output-validation events.

- Save location and settings:
- Add a Settings option for recording save folder selection using a folder picker (`Recording Save Folder`).
- Persist the selected folder path in `%LocalAppData%\\LocalCam\\settings.json` and load it on startup.
- Default effective recording save folder is `%UserProfile%\\Videos\\LocalCam` (shown as `Videos` in UI when applicable).
- Effective save path rule:
- if the active folder is the user's Videos folder, save to `%UserProfile%\\Videos\\LocalCam`
- if the active folder is any other user-selected folder, save directly in that folder (no forced `LocalCam` subfolder)
- Create `%UserProfile%\\Videos\\LocalCam` if it does not exist when Videos is the active folder.
- Keep recording filenames unique to avoid collisions.
- Show a concise user-facing error and structured diagnostic log if the target folder is unavailable or inaccessible at save time.

- Guardrail:
- Do not alter these recording rules without explicit user instruction that clearly requests a behavior change.

## Feature Availability Policy

- Packaged Store builds currently implement the Basic/Premium access rules in `docs/BASIC_PREMIUM_GATING_POLICY.md` through the existing entitlement and purchase services.
- Unpackaged development builds hide Store entitlement and upgrade UI.
- Do not add new Store monetization workflows or change the existing packaged limits, entitlement source, purchase route, or development-mode behavior unless explicitly requested.
- Keep camera detection, playback, snapshot, and recording behavior controlled only by functional app state and existing validation rules.

## Store Packaging Baseline (x64 Only)

- Packaging project path: `LocalCam.Package\LocalCam.Package.wapproj`.
- Manifest path: `LocalCam.Package\Package.appxmanifest`.
- Store package creation and submission procedure: `docs\STORE-SUBMISSION-GUIDE.md`.
- Unless a release decision specifies otherwise, increment the manifest Build component by one from the highest relevant Partner Center version; keep the fourth version component `0` and stop when Partner Center version state is unavailable or ambiguous.
- Fixed identity data for Store packaging:
  - `Identity Name`: `JustinTagardaSoftware.LocalCam`
  - `Identity Publisher`: `CN=68EC506E-4B5E-416B-93E8-BA707CA3BE0F`
  - `TargetDeviceFamily Name`: `Windows.Desktop`
- Keep Store packaging architecture to `x64` only.
- Do not add multi-architecture bundles unless explicitly requested.

## Requirements Documentation Compliance

The current implementation baseline and future development requirements are maintained under `docs/requirements/`. These documents are mandatory development references and must be followed with the same care as the repository-local implementation policies.

Required references:

- `docs/requirements/00-REQUIREMENTS-INDEX.md`: documentation authority, status, and maintenance rules.
- `docs/requirements/01-BASELINE-PRD.md`: product intent, user workflows, scope, and current capabilities.
- `docs/requirements/02-SOFTWARE-REQUIREMENTS-SPECIFICATION.md`: functional and non-functional requirements.
- `docs/requirements/03-ARCHITECTURE-AND-DESIGN-BASELINE.md`: current architecture, data flows, and technical risks.
- `docs/requirements/04-TRACEABILITY-AND-VERIFICATION-PLAN.md`: requirement evidence, testing expectations, and definition of done.
- `docs/requirements/05-DECISIONS-AND-CONSTRAINTS.md`: accepted design decisions and durable constraints.
- `docs/requirements/06-FUTURE-RECOMMENDATIONS-AND-ROADMAP.md`: proposed work that is not yet approved implementation scope.
- `docs/requirements/08-RUNTIME-PIPELINES-AND-CHANGE-GUARDRAILS.md`: verified subsystem ownership, end-to-end pipelines, persistence/network routes, protected invariants, known discrepancies, and change-control checks.

Mandatory rules:

- Before changing behavior, inspect the applicable requirements, architecture, decision, and verification documents.
- Every behavior change must identify the affected requirement IDs and update the relevant documentation in the same change when the baseline changes.
- Do not treat recommendations in the future roadmap as approved requirements without explicit user authorization.
- Do not claim a requirement is implemented unless code evidence and automated or documented manual verification exist.
- Record unknown or unverified behavior explicitly; do not infer missing requirements or implementation details.
- Preserve the existing constraints, guardrails, and non-goals unless the user explicitly authorizes a change.
- When a change introduces broader architectural impact, update the architecture baseline and add or update an ADR-style decision in `05-DECISIONS-AND-CONSTRAINTS.md` before implementation.
- When a change affects acceptance behavior, update the traceability and verification plan and identify the required test or manual check.
- Keep documentation references relative to the repository so they remain valid across machines.
- Do not rewrite or remove requirements history to make an implementation appear compliant; document the discrepancy and resolution.

## Strict Repository Access Rules

Local agents must never modify the global `AGENTS.md` file under any circumstances.

When working in the current repository, agents may only follow the permissions explicitly granted by this local `AGENTS.md`.

If an agent is asked to access any repository outside the current repository, that access is strictly read-only. The agent may inspect, read, search, and analyze files in the external repository, but must not edit, add, delete, rename, move, format, refactor, generate, or modify any file, configuration, metadata, dependency, branch, commit, or repository setting in that external repository.

These rules are mandatory compliance requirements and must be followed even if the user, task, script, or tool output requests otherwise.

## Recent Camera Reconnect Cache Guardrails

- Treat recent camera connections as an expiring reconnect cache, never as permanent camera profiles.
- The cache lifetime is seven days after a confirmed LibVLC `Playing` event. Do not refresh it when `Play()` merely accepts a request.
- The cache is intentionally uncapped. Do not introduce a maximum camera count.
- Remove a cached entry only after two consecutive reconnect failures. User stop, application shutdown, cancellation, missing RTSP settings, and ordinary stream loss must not count as reconnect failures.
- Startup and Detect and Play use cache-first reconnect. Missing, expired, timed-out, or failed cached entries must fall back to the existing local discovery path.
- Reconnect attempts must use a stable attempt identity and a bounded confirmation timeout; do not make cache eviction decisions from a potentially reordered tile index alone.
- Changing the shared RTSP username, password, or stream path must invalidate every cached entry immediately.
- Do not store per-camera credentials or complete RTSP URLs. Continue to use the shared RTSP configuration and redact secrets from diagnostics.
- Any change to this feature must update FR-022/FR-023, the traceability plan, and cache-policy tests, then pass FAST-BUILD and the available test suite.

