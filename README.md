# LocalCam

LocalCam is a Windows desktop WPF application that discovers compatible cameras on a local network and displays their RTSP video in a multi-camera dashboard. Discovery is Tapo-first internally, while the user-facing product is brand-neutral.

## Implemented Features

- Best-effort local-network camera discovery with multiple detection methods.
- Camera tiles showing detected addresses and discovery status.
- RTSP playback through LibVLCSharp, with per-camera and Start All/Stop All controls.
- Auto-detection and optional auto-streaming on startup.
- Snapshot capture for active streams.
- Manual video recording to `.ts` files, with one active recording across the app and 60-minute segment rollover.
- Expand/collapse controls and double-click layout toggling for active camera tiles.
- Settings for RTSP credentials, stream path, auto-detection, auto-streaming, snapshot folder, and recording folder.
- Inline validation that opens Settings when RTSP configuration is missing or invalid.
- Persisted settings and window bounds.
- Structured JSONL diagnostics for discovery, settings, streaming, snapshots, recording, entitlement, and Store update events.
- Packaged Microsoft Store entitlement, Premium purchase, and app-update flows.

## Current Limitations

- Discovery is heuristic and is not an authoritative camera inventory.
- The scanner is optimized for Tapo/TP-Link signals but can find compatible cameras exposing similar RTSP or ONVIF-related services.
- There is no manual IP/camera entry workflow, camera profile management, or device authentication handshake.
- RTSP uses port `554`; arbitrary RTSP ports and custom RTSP URLs are not exposed as settings.
- The repository contains a test project, but no test source files are currently present.

## User Workflow

1. Start the app. The main window discovers cameras when auto-detection is enabled.
2. Review detected camera tiles and retry discovery from the dashboard when needed.
3. Open Settings to provide RTSP username/password and configure the stream path. The default path is `stream1`.
4. Start an individual stream or use Start All. Use Snapshot or Record on active tiles.
5. Stop playback before closing; the app also stops streams and disposes video resources during shutdown.

## Settings and Persistence

Settings are stored at `%LocalAppData%\\LocalCam\\settings.json` and include RTSP options, discovery preferences, save-folder choices, window bounds, Premium entitlement cache, and Store update state.

- Snapshots default to `%UserProfile%\\Pictures\\LocalCam`.
- Recordings default to `%UserProfile%\\Videos\\LocalCam`.
- A user-selected non-default folder is used directly.
- Stream paths are normalized and persisted between launches.

## Discovery

The scanner enumerates active IPv4 interfaces, skips loopback/tunnel interfaces, limits broad subnet probing to `/24`, and uses bounded concurrent probing. Detection combines network reachability, open ports, ARP data, reverse DNS, HTTP/HTTPS fingerprints, ONVIF/SSDP/mDNS hints, and Tapo/TP-Link-specific signals. The last successful detection method is persisted and preferred on the next scan.

User-facing detection labels are mapped to neutral names such as `ONVIF`, `SSDP`, `local discovery`, `mDNS`, `ARP probe`, and `subnet probe`.

## Streaming, Snapshots, and Recording

RTSP URLs are built from the configured credentials, detected host, port `554`, and normalized stream path. LibVLC media players are created per active tile and disposed when playback stops or the window closes.

Snapshots use unique filenames and report save failures through the activity/status area and structured diagnostics. Recordings use `.ts` output, allow only one active recording session across all cards, automatically stop a previous card's recording when switching cards, and roll over to a new segment after 60 minutes while playback remains active.

Packaged Store builds apply the Basic/Premium policy: Basic allows up to two active streams and 30 minutes of recording per local day; Premium removes those limits. Unpackaged development runs hide Store entitlement and upgrade UI.

## Technology Stack

- C# with nullable reference types and implicit usings.
- .NET 10 for Windows: `net10.0-windows10.0.19041.0`.
- WPF and XAML for the desktop UI.
- LibVLCSharp.WPF `3.9.6` and VideoLAN.LibVLC.Windows `3.0.23` for playback and recording.
- Windows Store APIs for packaged entitlement, in-app purchase, and package updates.
- `System.Net`, `System.Net.NetworkInformation`, and `System.Net.Sockets` for discovery.
- JSON serialization and JSONL diagnostics using built-in .NET APIs.
- xUnit/Microsoft.NET.Test.Sdk are referenced by `LocalCam.Tests`, but test cases are not currently present.

## Architecture and Key Files

- `App.xaml.cs`: application startup, logging initialization, and shutdown.
- `MainWindow.xaml` / `MainWindow.xaml.cs`: dashboard, discovery lifecycle, playback, snapshots, recording, gating, and Store UI orchestration.
- `Networking/TapoCameraScanner.cs`: multi-method local-network discovery and diagnostics.
- `Models/LocalCamSettings.cs`: persisted settings model.
- `SettingsWindow.xaml` / `SettingsWindow.xaml.cs`: settings UI, validation, and folder selection.
- `Services/SettingsStore.cs`: JSON settings persistence.
- `Services/JsonLogStore.cs`: structured diagnostic logging.
- `Services/PremiumEntitlementService.cs` and `PremiumPurchaseService.cs`: Store entitlement and purchase handling.
- `Services/StoreAppUpdaterService.cs`: packaged Store update availability, installation, progress, and queue recovery.
- `LocalCam.Package/`: x64-only Store packaging project and manifest.

## Build and Run

Use the Visual Studio 2026 MSBuild toolchain for the routine Debug build:

```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" .\LocalCam.csproj /t:Build /p:Configuration=Debug /p:RunAnalyzers=false /m
```

Launch the generated executable directly:

```powershell
.\bin\Debug\net10.0-windows10.0.19041.0\LocalCam.exe
```

The project is configured for the `win-x64` runtime. Store packaging is x64-only and is separate from the routine Debug build.

## Documentation
- Project rules and operating instructions: [AGENTS.md](D:/Projects/LocalCam/AGENTS.md)
- [SPECIFICATION.md](D:/Projects/LocalCam/SPECIFICATION.md): current product and implementation specification.
- [docs/BASIC_PREMIUM_GATING_POLICY.md](D:/Projects/LocalCam/docs/BASIC_PREMIUM_GATING_POLICY.md): restoration source for Basic/Premium behavior.
- [docs/BASIC_PREMIUM_GATING_TEST_CHECKLIST.md](D:/Projects/LocalCam/docs/BASIC_PREMIUM_GATING_TEST_CHECKLIST.md): regression checklist for gating changes.
- [history.md](D:/Projects/LocalCam/history.md): historical implementation notes.
- [docs/requirements/00-REQUIREMENTS-INDEX.md](D:/Projects/LocalCam/docs/requirements/00-REQUIREMENTS-INDEX.md): requirements documentation index and maintenance rules.
- [docs/requirements/01-BASELINE-PRD.md](D:/Projects/LocalCam/docs/requirements/01-BASELINE-PRD.md): current product baseline.
- [docs/requirements/02-SOFTWARE-REQUIREMENTS-SPECIFICATION.md](D:/Projects/LocalCam/docs/requirements/02-SOFTWARE-REQUIREMENTS-SPECIFICATION.md): functional and non-functional requirements.
- [docs/requirements/03-ARCHITECTURE-AND-DESIGN-BASELINE.md](D:/Projects/LocalCam/docs/requirements/03-ARCHITECTURE-AND-DESIGN-BASELINE.md): architecture and data flows.
- [docs/requirements/04-TRACEABILITY-AND-VERIFICATION-PLAN.md](D:/Projects/LocalCam/docs/requirements/04-TRACEABILITY-AND-VERIFICATION-PLAN.md): verification and traceability.
- [docs/requirements/05-DECISIONS-AND-CONSTRAINTS.md](D:/Projects/LocalCam/docs/requirements/05-DECISIONS-AND-CONSTRAINTS.md): accepted decisions and constraints.
- [docs/requirements/06-FUTURE-RECOMMENDATIONS-AND-ROADMAP.md](D:/Projects/LocalCam/docs/requirements/06-FUTURE-RECOMMENDATIONS-AND-ROADMAP.md): recommended future goals.
