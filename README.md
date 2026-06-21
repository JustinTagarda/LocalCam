# LocalCam

LocalCam is a Windows desktop WPF app for discovering compatible cameras on the local network and viewing RTSP streams in a multi-tile viewer. The implementation is Tapo-first under the hood, but the user-facing app is branded as a generic network camera viewer.

## What It Does

- Discovers local-network cameras with heuristic scanning
- Shows live camera tiles in a single window
- Plays RTSP streams with LibVLCSharp
- Lets you start and stop streams per tile or all at once
- Supports per-tile snapshot capture
- Supports per-tile manual recording with automatic 60-minute segment rollover
- Keeps discovery and streaming status visible in the main window footer

## Current UI

- Main window opens directly to the camera dashboard
- Local camera discovery runs on load and can be retried from the same window
- Per-tile controls include:
  - Play/Stop
  - Snapshot
  - Record / Stop Recording
  - Expand / Collapse while video is playing
- Settings are available from the toolbar

## Settings

The Settings dialog currently covers:

- RTSP username
- RTSP password
- RTSP stream path
- Auto-stream
- Snapshot save folder
- Recording save folder

Defaults and persistence:

- Settings persist to `%LocalAppData%\LocalCam\settings.json`
- Window bounds are persisted
- Preferred detection method is persisted
- Snapshot files default to `%UserProfile%\Pictures\LocalCam`
- Recording files default to `%UserProfile%\Videos\LocalCam`
- The app shows `Pictures` or `Videos` in the UI when the active save folder matches those default locations

## Discovery

Discovery is best-effort and heuristic-based, not authoritative.

Current scan behavior:

- Enumerates active network interfaces
- Ignores loopback and tunnel interfaces
- Requires an IPv4 gateway on the interface
- Caps broad subnets to `/24`
- Probes common ports and reads lightweight fingerprints
- Uses a persisted preferred detection method when available

The scanner remains Tapo-first internally, while the user-facing text stays brand-neutral.

## Streaming

- RTSP playback uses LibVLCSharp.WPF
- RTSP URLs are built from the configured username, password, host IP, and stream path
- Auto-stream can start playback automatically after detections are found
- Streams are stopped and disposed cleanly on close

## Diagnostics

- In Debug local runs, structured JSONL logs are written beside the launched executable
- Logging is disabled for Release and installed distributions
- Discovery, settings, snapshot, recording, and stream events are logged

## Tech Stack

- C# / .NET 10
- WPF (XAML)
- Target framework: `net10.0-windows10.0.19041.0`
- LibVLCSharp.WPF for video playback

## Build And Run

For routine development, use the fast Debug build:

```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" .\LocalCam.csproj /t:Build /p:Configuration=Debug /p:RunAnalyzers=false /m
```

Launch the app from the Debug output:

```powershell
.\bin\Debug\net10.0-windows10.0.19041.0\LocalCam.exe
```

## Project Files

- App startup: [App.xaml.cs](D:/Projects/LocalCam/App.xaml.cs)
- Main UI: [MainWindow.xaml](D:/Projects/LocalCam/MainWindow.xaml)
- Main UI logic: [MainWindow.xaml.cs](D:/Projects/LocalCam/MainWindow.xaml.cs)
- Discovery logic: [Networking/TapoCameraScanner.cs](D:/Projects/LocalCam/Networking/TapoCameraScanner.cs)
- Settings dialog: [SettingsWindow.xaml](D:/Projects/LocalCam/SettingsWindow.xaml)
- Settings persistence: [Services/SettingsStore.cs](D:/Projects/LocalCam/Services/SettingsStore.cs)
- App diagnostics: [Services/JsonLogStore.cs](D:/Projects/LocalCam/Services/JsonLogStore.cs)

## Documentation

- Project rules and operating instructions: [AGENTS.md](D:/Projects/LocalCam/AGENTS.md)
- Product behavior specification: [SPECIFICATION.md](D:/Projects/LocalCam/SPECIFICATION.md)
- Basic/Premium restoration policy: [docs/BASIC_PREMIUM_GATING_POLICY.md](D:/Projects/LocalCam/docs/BASIC_PREMIUM_GATING_POLICY.md)
- Basic/Premium validation checklist: [docs/BASIC_PREMIUM_GATING_TEST_CHECKLIST.md](D:/Projects/LocalCam/docs/BASIC_PREMIUM_GATING_TEST_CHECKLIST.md)

## Policy Guardrails

- For changes touching stream start, recording, entitlement, or purchase flow, treat the Basic/Premium policy doc as the restoration source of truth.
- Re-validate with the Basic/Premium gating checklist before considering such changes complete.

## Distribution

- LocalCam supports Microsoft Store packaging readiness validation for pre-submission workflows.
- Store packaging is maintained with `x64`-only policy and Store upload mode requirements.

## Store App Update Flow

- Microsoft Store app updates use `Windows.Services.Store.StoreContext`.
- Update checks run after first render and do not block startup.
- Update checks are gated to packaged runtime only; unpackaged runs keep updater UI hidden.
- Check throttling is persisted (`>=30` minute cooldown, max `10` checks per rolling 24 hours).
- Footer order is `[Basic/Premium] [Upgrade] [version] [Update]`.
- The compact footer `Update` button is shown only after a fresh positive Store availability result or while an active Store update queue item is in progress.
- If availability/recheck returns zero updates, the `Update` button is hidden immediately and cached availability is cleared.
- Clicking `Update` starts `RequestDownloadAndInstallStorePackageUpdatesAsync`.
- If Store permission UX is pending, the update modal shows `Waiting for permission...` while the request remains active.
- Store update progress is shown in a dedicated modal window (not in the footer) with phase, percent, details, and terminal result (`Completed`, `Canceled`, `Failed` guidance).
- Active Store queue state is recovered on startup via Store queue APIs so progress can continue across restarts.
- Queue recovery now fail-closes to hidden updater UI when no active/relevant queue state remains.
- Store update diagnostics include release-expectation context fields (submission publish state, rollout mode, flight audience status) when recorded.

## Premium Add-On (Store)

- Store model: Basic mode remains usable; Premium is unlocked via Microsoft Store durable add-on ownership.
- Purchase path: all upgrade actions use in-app `Windows.Services.Store` purchase (`RequestPurchaseAsync`) rather than direct PDP links.
- Purchase confirmation: all upgrade entry points show the in-app modal `Upgrade` confirmation dialog before opening Store purchase UI.
- Purchase binding: Store purchase uses per-invocation owner-window binding to the active top-level app window handle when available.
- Startup mode check: Premium entitlement is checked after first render; footer mode text and upgrade control stay hidden until the check completes.
- Entitlement fallback: previously verified Premium cache is used only when Store entitlement checks are unavailable.
- Window recovery: after purchase/cancel/failure, app window accessibility is restored (enabled + activated/focused).
- Footer behavior:
  - owned entitlement: `Premium` text shown, `Upgrade` hidden
  - not owned entitlement: `Basic` text shown, compact `Upgrade` button shown
- Runtime configuration:
  - Premium durable add-on Store ID baseline: `9P9KCJ3NFZFT` (`localcam_premium_lifetime`, Durable).
  - In unpackaged environments, purchase is reported as not supported.

## Store Packaging Baseline

- Packaging project: `LocalCam.Package/LocalCam.Package.wapproj`
- Manifest: `LocalCam.Package/Package.appxmanifest`
- Store identity baseline:
  - `Name`: `JustinTagardaSoftware.LocalCam`
  - `Publisher`: `CN=68EC506E-4B5E-416B-93E8-BA707CA3BE0F`
  - `PublisherDisplayName`: `JustinTagarda`
  - `TargetDeviceFamily`: `Windows.Desktop`
- Packaging target policy is `x64` only.
- Store upload mode is configured for Release packaging validation.

## Store Pre-Submission Readiness

- Follow `D:\Projects\4-MSSTORE-PACKAGE-GENERATION.md` for Store package generation and versioning workflow.
- When generating Store packages, use `FULL-BUILD` and `C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe` after confirming `D:\Projects\global.json` pins the installed SDK root.
- Validate manifest identity and target fields before release packaging:
  - `Identity Name`: `JustinTagardaSoftware.LocalCam`
  - `Identity Publisher`: `CN=68EC506E-4B5E-416B-93E8-BA707CA3BE0F`
  - `TargetDeviceFamily Name`: `Windows.Desktop`
- Validate package version format as `Major.Minor.Build.0` and increment `Identity Version` before each new Store package build.
- Validate output artifacts include Store upload artifact (`.msixupload`) and `x64` architecture package (`.msix`) in Release packaging flow.
- Treat stale artifacts under `LocalCam.Package/AppPackages` and `LocalCam.Package/bin/x64/Release/Upload` as `NOT READY` until cleaned by packaging workflow.

### Current Package Baseline (2026-06-21)

Status: `LATEST STORE BUILD COMPLETED`

Current versioning state:

- `Identity Name`: `JustinTagardaSoftware.LocalCam`
- `Identity Publisher`: `CN=68EC506E-4B5E-416B-93E8-BA707CA3BE0F`
- `TargetDeviceFamily Name`: `Windows.Desktop`
- `Identity Version`: `1.0.32.0`
- Version format: `Major.Minor.Build.0`
- Publisher display name: `JustinTagarda`
- Packaging mode: `StoreUpload`
- Package architecture policy: `x64` only
- SDK pin source for Store builds: `D:\Projects\global.json`

Previous generated package version:

- `1.0.31.0`

Ready-state notes:

- Stale artifact cleanup was completed by the packaging workflow.
- The latest Store package build used manifest version `1.0.32.0`.
- Store upload and `x64` package artifacts were regenerated by the latest FULL-BUILD packaging run.

Artifact paths (required reporting):

- Store upload artifact (`.msixupload`): `D:\Projects\LocalCam\LocalCam.Package\AppPackages\LocalCam.Package_1.0.32.0_x64.msixupload`
- Architecture package (`.msix`, x64): `D:\Projects\LocalCam\LocalCam.Package\AppPackages\LocalCam.Package_1.0.32.0_x64_Test\LocalCam.Package_1.0.32.0_x64.msix`
- Bundle artifact (`.msixbundle`, x64-only when bundle mode is used): `not found`

