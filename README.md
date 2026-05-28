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

## Distribution

- LocalCam supports Microsoft Store packaging readiness validation for pre-submission workflows.
- Store packaging is maintained with `x64`-only policy and Store upload mode requirements.

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

