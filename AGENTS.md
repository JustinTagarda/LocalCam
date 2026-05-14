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

## Packaging Architecture Policy

- LocalCam is an x64 package-only app.
- Keep `LocalCam.csproj` runtime identifiers limited to `win-x64`.
- Keep `LocalCam.Package.wapproj` package platforms limited to `x64`.
- Do not add, restore, generate, or publish ARM64, win-arm64, AnyCPU, or multi-architecture Store packages unless the user explicitly requests a packaging architecture policy change.
- If generated ARM64 package artifacts appear under `AppPackages`, treat them as stale outputs and remove them before packaging verification.

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
  - Single-window WPF desktop app (`MainWindow`) with custom window chrome.
  - Camera discovery runs on load and can be retried from the same window.
  - Camera tiles are shown based on current detections, with expand/collapse behavior and responsive layout.
  - Settings dialog is available for RTSP credentials and stream path.
  - Auto-stream toggle is supported and persisted.

- Discovery:
  - Local-network discovery is heuristic and best-effort.
  - Scanner uses multi-method probing with persisted preferred detection method.
  - Detection and scan lifecycle statuses are surfaced in the main window.

- Streaming:
  - RTSP playback uses LibVLCSharp.
  - Start/stop controls are state-gated by scan state, stream state, and credentials.
  - Stream resources are cleaned up on stop/close.

- Persistence and diagnostics:
  - App settings persist at `%LocalAppData%\\LocalCam\\settings.json`.
  - Structured JSONL app diagnostics are written under `%LocalAppData%\\LocalCam\\logs`.

- Microsoft Store readiness:
  - Packaging project exists: `LocalCam.Package.wapproj`.
  - Manifest identity is configured for Store upload.
  - Store updater workflow is implemented in-app using `Windows.Services.Store` through service abstractions.
  - Footer update surface includes update state, progress, and restart affordance after install completion.

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
- `Auto-stream`
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

RTSP streaming behavior must remain unchanged during brand-neutral UI work.

Do not change:

- RTSP URL construction
- RTSP port behavior
- credential handling
- stream path normalization
- LibVLC options
- stream start/stop behavior
- snapshot behavior
- recording behavior

Current RTSP URL construction may remain:

`rtsp://{username}:{password}@{host}:554/{streamPath}`

## Stream Start Validation and Settings Escalation Policy

- Scope:
- Applies when starting video stream from:
  - top toolbar `Start All`
  - per-card `Play`
  - auto-start (persisted auto-stream behavior)

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
- Detect Camera:
- always visible
- disable while detection is running
- enable when detection is not running
- Start All:
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

## Store Tiering Policy (Basic vs Premium)

- Scope:
- Defines feature gating and runtime behavior for Microsoft Store monetization tiers.
- Keep all existing non-tier rules intact unless explicitly superseded by this section.

- Tier definitions:
- Basic (Free):
  - Unlimited camera detection.
  - Maximum 4 simultaneously playing cameras.
  - If a 5th camera is started while 4 are already playing, auto-stop the earliest-played active camera, then start the requested camera.
  - Recording is limited to 30 minutes per recording session.
  - At 30 minutes, recording hard-stops and does not continue to a next segment.
  - User may start recording again manually with no enforced session-count cap.
  - Show a custom modal when recording stops due to the Basic 30-minute limit, including a Premium upsell CTA.
  - All other current features remain available in Basic unless explicitly gated.
- Premium (Paid):
  - Unlimited camera detection.
  - No cap on the number of cameras that can play simultaneously.
  - Recording behavior remains complete as currently implemented (including segment rollover behavior).
  - All existing features remain fully available.

- Entitlement and fallback:
- Resolve tier entitlement at runtime.
- If entitlement cannot be resolved, fail-safe to Basic behavior.
- Tier state must be consumable by playback and recording flows.

- Basic playback cap enforcement:
- Track stream play order using an explicit runtime ordering signal (for example, start sequence/timestamp).
- Eviction candidate for the 5th start must be selected from currently active streams only.
- On 5th start request in Basic:
  - stop earliest-played active stream
  - start requested stream
  - final state must contain exactly 4 active streams

- Basic recording cap enforcement:
- Trigger stop at 30 minutes elapsed for the active Basic recording session.
- Do not start a new recording segment automatically after the 30-minute cap is reached.
- Keep stream playback running unless separately stopped by user/system conditions.
- Limit-stop reason must be explicitly distinguishable from user-stop, stream-stop, and error-stop reasons.

- Upgrade modal requirements (Basic recording limit):
- Modal appears only when recording stops due to Basic 30-minute cap.
- Modal must explain the limit clearly and include:
  - primary action: Premium upgrade CTA
  - secondary action: dismiss/close
- Do not show this monetization modal for non-limit recording failures.

- Recording status surface:
- Recording activity and outcomes continue to use `StreamingStatusText` per existing policy.
- Modal is additive for the Basic-limit stop case and must not replace status text updates.

- Suggested marketing wording (custom modal):
- Title options:
  - `Recording limit reached`
  - `Keep recording without interruptions`
  - `Basic session completed`
- Body guidance:
  - State that Basic recordings stop at 30 minutes.
  - State that Premium removes this 30-minute recording stop and enables continuous recording behavior.
- CTA labels:
  - `Upgrade to Premium`, `See Premium`, or `Upgrade`
- Secondary labels:
  - `Not now`, `Later`, or `Close`

- Logging and diagnostics:
- Log structured events for:
- tier resolution result
  - Basic 4-stream cap enforcement (requested tile, evicted tile, active counts)
  - Basic 30-minute recording-limit stop
  - upgrade modal shown/dismissed/CTA clicked

- Guardrail:
- Do not change Basic/Premium gating behavior defined in this section without explicit user instruction.
