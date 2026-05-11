# LocalCam

LocalCam is a Windows desktop WPF app for discovering likely Tapo cameras on the local network and viewing RTSP streams in a multi-tile viewer.

## Current Implementation

- Main window workflow:
  - App opens directly to `MainWindow`.
  - Local camera discovery runs on load.
  - Discovery can be retried without leaving the window.

- Camera viewer:
  - Displays up to 4 camera tiles.
  - Supports per-tile expand/collapse behavior.
  - Uses LibVLCSharp playback for RTSP streams.

- Streaming controls:
  - Start/Stop stream actions are state-aware.
  - RTSP username/password and stream path are configurable.
  - Auto-stream option is supported.

- Settings and persistence:
  - Settings dialog is available from the toolbar.
  - Settings persist to `%LocalAppData%\\LocalCam\\settings.json`.
  - Window bounds and preferred detection method are persisted.

- Diagnostics:
  - Structured JSONL logs are written to `%LocalAppData%\\LocalCam\\logs`.
  - Discovery, input, stream, and updater events are logged.

- Microsoft Store implementation:
  - Packaging project and manifest are configured for Store upload workflows.
  - In-app Store updater is implemented via service abstractions using `Windows.Services.Store`.
  - Updater UI is shown in the footer with passive status/progress behavior.
  - After update install completion, a footer restart action is provided.

## Tech Stack

- C# / .NET 10
- WPF (XAML)
- Target framework: `net10.0-windows10.0.19041.0`
- LibVLCSharp.WPF for video playback

## Project Files

- App startup: [App.xaml.cs](D:/Projects/LocalCam/App.xaml.cs)
- Main UI: [MainWindow.xaml](D:/Projects/LocalCam/MainWindow.xaml)
- Main UI logic: [MainWindow.xaml.cs](D:/Projects/LocalCam/MainWindow.xaml.cs)
- Discovery logic: [Networking/TapoCameraScanner.cs](D:/Projects/LocalCam/Networking/TapoCameraScanner.cs)
- Settings persistence: [Services/SettingsStore.cs](D:/Projects/LocalCam/Services/SettingsStore.cs)
- App diagnostics: [Services/JsonLogStore.cs](D:/Projects/LocalCam/Services/JsonLogStore.cs)
- Store updater services: `Services/AppUpdateService.cs`, `Services/StoreUpdateClient.cs`, `Services/AppVersionProvider.cs`
- Store packaging project: [LocalCam.Package.wapproj](D:/Projects/LocalCam/LocalCam.Package.wapproj)
- Store manifest: [Package.appxmanifest](D:/Projects/LocalCam/Package.appxmanifest)

## Documentation

- Project rules and operating instructions: [AGENTS.md](D:/Projects/LocalCam/AGENTS.md)
- Product behavior specification: [SPECIFICATION.md](D:/Projects/LocalCam/SPECIFICATION.md)
