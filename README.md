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
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe" .\LocalCam.csproj /t:Build /p:Configuration=Debug /p:RunAnalyzers=false /m
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

## Premium Add-On (Store)

- Store model: Basic mode remains usable; Premium is unlocked via Microsoft Store durable add-on ownership.
- Purchase path: all upgrade actions use in-app `Windows.Services.Store` purchase (`RequestPurchaseAsync`) rather than direct PDP links.
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
  - `TargetDeviceFamily`: `Windows.Desktop`
- Packaging target policy is `x64` only.
- Store upload mode is configured for Release packaging validation.

## Store Pre-Submission Readiness

- Follow `D:\Projects\1-MSSTORE-PACKAGE-PREPARATION.md` for readiness gates and baseline implementation checks.
- Validate manifest identity and target fields before release packaging:
  - `Identity Name`: `JustinTagardaSoftware.LocalCam`
  - `Identity Publisher`: `CN=68EC506E-4B5E-416B-93E8-BA707CA3BE0F`
  - `TargetDeviceFamily Name`: `Windows.Desktop`
- Validate package version format as `Major.Minor.Build.0`.
- Validate output artifacts include Store upload artifact (`.msixupload`) and `x64` architecture package (`.msix`) in Release packaging flow.
- Treat stale artifacts under `LocalCam.Package/AppPackages` and `LocalCam.Package/bin/x64/Release/Upload` as `NOT READY` until cleaned by packaging workflow.

### Current Readiness Audit (2026-05-29)

Status: `NOT READY`

Gate results from `Release|x64` packaging validation:

- `PASS`: Packaging project exists and is wired: `LocalCam.Package/LocalCam.Package.wapproj`.
- `PASS`: Manifest exists and is parseable: `LocalCam.Package/Package.appxmanifest`.
- `PASS`: SDK pin source exists for Store-readiness validation: `D:\Projects\LocalCam\global.json`.
- `PASS`: Fixed identity and target data match:
  - `Identity Name`: `JustinTagardaSoftware.LocalCam`
  - `Identity Publisher`: `CN=68EC506E-4B5E-416B-93E8-BA707CA3BE0F`
  - `TargetDeviceFamily Name`: `Windows.Desktop`
- `PASS`: Manifest/package version format is `Major.Minor.Build.0` (`1.0.0.0`).
- `PASS`: UI footer version text is derived from package version and rendered as `Major.Minor.Build.0`.
- `PASS`: Packaging mode is Store upload mode (`UapAppxPackageBuildMode=StoreUpload`).
- `PASS`: Package architecture policy is `x64` only (`AppxBundle=Never`, `AppxBundlePlatforms=x64`, `Platform/Platforms=x64`).
- `PASS`: Manifest asset files exist and dimensions are valid:
  - `StoreLogo.png` `50x50`
  - `Square44x44Logo.png` `44x44`
  - `Square150x150Logo.png` `150x150`
  - `Wide310x150Logo.png` `310x150`
  - `SplashScreen.png` `620x300`
- `PASS`: Store upload artifact generated (`.msixupload` only).
- `FAIL`: Stale artifact cleanup gate is not satisfied because readiness scope folders contain artifacts and must be treated as `NOT READY` until packaging cleanup workflow handles them.

Build notes:

- `Release|x64` packaging build completed successfully via `LocalCam.Package.wapproj` (Visual Studio 2026 MSBuild).
- Warnings observed and retained for follow-up:
  - `MSB4011` duplicate common props import from DesktopBridge props chain.
  - `NU1702` packaging project framework-resolution compatibility warning for project reference.

Artifact paths (required reporting):

- Store upload artifact (`.msixupload`):
  - `D:\Projects\LocalCam\LocalCam.Package\AppPackages\LocalCam.Package_1.0.0.0_x64.msixupload`
- Architecture package (`.msix`, x64):
  - `D:\Projects\LocalCam\LocalCam.Package\AppPackages\LocalCam.Package_1.0.0.0_x64_Test\LocalCam.Package_1.0.0.0_x64.msix`
  - `D:\Projects\LocalCam\LocalCam.Package\bin\x64\Release\Upload\LocalCam.Package_1.0.0.0_x64\LocalCam.Package_1.0.0.0_x64.msix`
- Bundle artifact (`.msixbundle`, x64-only when bundle mode is used):
  - `D:\Projects\LocalCam\LocalCam.Package\AppPackages\LocalCam.Package_1.0.0.0_x64.msixbundle` -> `not found`

