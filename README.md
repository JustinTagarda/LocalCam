# LocalCam

LocalCam is a Windows desktop WPF app for discovering compatible cameras on the local network and viewing RTSP streams in a multi-tile viewer. The implementation is Tapo-first under the hood, but the user-facing app is branded as a generic network camera viewer.

## What It Does

- Discovers local-network cameras with heuristic scanning
- Shows up to 4 live camera tiles in a single window
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
- The footer shows current access tier (`Basic`/`Premium`) and app version
- Clicking version checks for updates and opens the Microsoft Store updates page when an update is available
- When no update is available, the version click flow shows a small `No update available` toast above the version text
- The footer menu also exposes Premium promo-code redemption and purchase restore actions
- Premium promo-code redemption opens the Microsoft Store redeem page; after redeeming, use Restore purchase so LocalCam refreshes entitlement

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
- Discovery, settings, snapshot, recording, stream, and updater events are logged

## Microsoft Store Support

- Packaging project exists for Store submission workflows
- The package project is x64-only and runtime identifiers are limited to `win-x64`
- Store integration uses `Windows.Services.Store`
- Startup runs a hidden, non-blocking Store update check after the first render
- If updates are available, the app prefers silent download and defers install until app exit when supported
- If silent download is unavailable or fails, the app falls back to Microsoft Store / OS-provided update UI
- Deferred update state is persisted to `%LocalAppData%\LocalCam\update-state.json`
- Deferred exit-time installs run with an app-owned modal progress dialog, then resume the user's close
- User-initiated update checks open the Microsoft Store updates page when an update is available
- The app does not force automatic restart after update operations
- Premium is implemented as a durable Microsoft Store add-on with Product ID `localcam_premium_lifetime` and Store ID `9P9KCJ3NFZFT`
- Repository Store association metadata lives in [Package.StoreAssociation.xml](D:/Projects/LocalCam/Package.StoreAssociation.xml) and is included in [LocalCam.Package.wapproj](D:/Projects/LocalCam/LocalCam.Package.wapproj)

## Store Update Validation

Use this checklist to validate the Store update flow after packaging or when testing in a Store/MSIX context:

- App starts with no update available: opens normally, no update UI appears
- App starts with an available update: hidden background check runs after first render
- Silent path is available: update downloads silently and install is deferred until exit
- Silent path is unavailable or fails: fallback Store / OS update UI is used
- Deferred install exists on exit: close is paused, modal progress UI appears, install runs, then exit resumes
- Deferred install fails on exit: failure message appears, deferred state is cleared, exit resumes
- App is unpackaged: Store update flow is skipped safely
- App does not restart itself after update operations

For code-level verification, use the fast Debug build:

```powershell
dotnet msbuild .\LocalCam.csproj /t:Build /p:Configuration=Debug /p:RunAnalyzers=false /m
```

For Store configuration validation, use:

```powershell
.\scripts\Validate-StoreConfiguration.ps1
```

The validation script checks the manifest identity, x64 StoreUpload packaging, durable Premium add-on IDs, the Microsoft Store updates page URI, and the Store association XML.

## Tech Stack

- C# / .NET 10
- WPF (XAML)
- Target framework: `net10.0-windows10.0.19041.0`
- LibVLCSharp.WPF for video playback

## Build And Run

For routine development, use the fast Debug build:

```powershell
dotnet msbuild .\LocalCam.csproj /t:Build /p:Configuration=Debug /p:RunAnalyzers=false /m
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
- Store services: `Services/Store/`, `Services/StoreUpdateClient.cs`, `Services/AppVersionProvider.cs`
- Store update orchestration: `Services/Updates/`
- Store packaging project: [LocalCam.Package.wapproj](D:/Projects/LocalCam/LocalCam.Package.wapproj)
- Store manifest: [Package.appxmanifest](D:/Projects/LocalCam/Package.appxmanifest)
- Store association metadata: [Package.StoreAssociation.xml](D:/Projects/LocalCam/Package.StoreAssociation.xml)

## Documentation

- Project rules and operating instructions: [AGENTS.md](D:/Projects/LocalCam/AGENTS.md)
- Product behavior specification: [SPECIFICATION.md](D:/Projects/LocalCam/SPECIFICATION.md)
