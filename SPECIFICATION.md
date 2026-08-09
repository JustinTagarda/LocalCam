# LocalCam Specification

## 1. Product Summary

LocalCam is a single-window Windows WPF application for discovering compatible cameras on a local network and viewing their RTSP streams in a multi-camera dashboard. Its implementation is Tapo-first and optimized for TP-Link/Tapo discovery, while its normal user-facing wording remains brand-neutral.

The primary workflow is scan, configure RTSP settings, and stream one or more detected cameras.

## 2. Technology and Runtime

- C# and XAML.
- WPF desktop UI.
- .NET 10 target: `net10.0-windows10.0.19041.0`.
- `win-x64` runtime identifier.
- LibVLCSharp.WPF `3.9.6` with VideoLAN.LibVLC.Windows `3.0.23`.
- Windows.Services.Store APIs for packaged entitlement, purchase, and update operations.
- Built-in .NET networking APIs for discovery and JSON serialization/logging.

The application is built from `LocalCam.csproj`; Store packaging is defined separately in `LocalCam.Package/LocalCam.Package.wapproj` and is x64-only.

## 3. Architecture

The application is organized around four responsibilities:

- Bootstrap: `App.xaml.cs` initializes diagnostics and opens the main window.
- Discovery: `Networking/TapoCameraScanner.cs` performs bounded, best-effort local-network detection.
- Dashboard and media: `MainWindow.xaml` and `MainWindow.xaml.cs` manage camera tiles, LibVLC playback, snapshots, recording, status, and shutdown cleanup.
- Persistence and platform services: `Models/LocalCamSettings.cs`, `Services/SettingsStore.cs`, `Services/JsonLogStore.cs`, and the Store service classes manage settings, diagnostics, entitlement, purchases, and updates.

## 4. Startup and Shutdown

1. `App.xaml.cs` initializes JSONL diagnostics.
2. `MainWindow` loads persisted settings and restores window bounds when available.
3. If auto-detection is enabled, the main window scans the local network on load.
4. Detected cameras become dashboard tiles; an empty result remains retryable from the dashboard.
5. Packaged Store builds resolve Premium UI state and initialize Store update checks after first render.
6. On close, active recordings and streams are stopped, cancellation is requested, and LibVLC resources are disposed.

## 5. Discovery

Discovery is heuristic and best-effort. It does not prove camera identity or guarantee that every compatible camera will be found.

The scanner:

- Enumerates active IPv4 interfaces with gateways.
- Skips loopback, tunnel, and APIPA interfaces.
- Limits broad subnet enumeration to `/24`.
- Uses bounded concurrency and short network timeouts.
- Probes reachability and common camera/service ports, including `80`, `443`, `554`, `8554`, `2020`, `8080`, and `8443`.
- Reads ARP data and attempts reverse DNS.
- Uses HTTP/HTTPS fingerprints, ONVIF WS-Discovery, SSDP/UPnP, mDNS/DNS-SD, ARP-seeded probes, subnet probes, and Tapo UDP signals.
- Persists the last successful detection method and prefers it for subsequent scans.

Internal results are represented by Tapo-specific records such as `TapoCameraDetection`, with IP address, hostname, MAC address, open ports, confidence score, and detection reason. Internal names are intentionally not generalized. User-facing method labels are mapped to `ONVIF`, `SSDP`, `local discovery`, `mDNS`, `ARP probe`, and `subnet probe`.

## 6. Dashboard and Playback

The custom-chrome main window provides:

- Detect Camera, Start All, Stop All, and Settings toolbar actions.
- A camera tile for each current detection.
- Per-tile Play/Stop, Snapshot, Record/Stop Recording, and Expand/Collapse actions.
- Double-click collapse/expand behavior while a tile is playing.
- Discovery, stream, snapshot, and recording status in the activity/status area.

RTSP playback uses the configured username, password, detected host, port `554`, and normalized stream path:

`rtsp://{username}:{password}@{host}:554/{streamPath}`

Credentials are URL-escaped before URL construction. The default stream path is `stream1`; blank or slash-prefixed input is normalized. Missing or invalid RTSP configuration opens Settings and displays `RTSP credentials are missing or invalid.`

LibVLC media players are created for active tiles, use low-latency-oriented media options, and are stopped/disposed during stream shutdown and application close.

## 7. Snapshots and Recording

Snapshots are available only while a tile is playing. They use unique filenames and the effective snapshot folder from Settings. Save failures are reported to the user and logged.

Recording is manual and available only while a tile is playing. The implementation enforces:

- One active recording session across all cards.
- Automatic stop of the current recording before switching to another card.
- `.ts` output without remuxing or transcoding.
- Maximum segment duration of 60 minutes.
- Segment rollover while playback remains active.
- Authoritative cleanup when the recorder stops, ends, or errors.
- Automatic recording stop when the owning stream stops.

Packaged Store builds additionally apply Basic/Premium limits defined in `docs/BASIC_PREMIUM_GATING_POLICY.md`: Basic permits two active streams and 30 minutes of recording per local day; Premium removes those limits. Unpackaged development builds hide Basic/Premium UI and do not surface upgrade prompts.

## 8. Settings and Persistence

`SettingsWindow` exposes:

- RTSP username and password.
- Stream Path.
- Auto detect on startup.
- Auto start when connected.
- Snapshot Save Folder.
- Recording Save Folder.

Settings are persisted to `%LocalAppData%\\LocalCam\\settings.json`. Persisted state also includes the last successful discovery method, window bounds, Basic recording usage, Premium entitlement cache, and Store update state.

Effective default folders are `%UserProfile%\\Pictures\\LocalCam` for snapshots and `%UserProfile%\\Videos\\LocalCam` for recordings. A user-selected non-default folder is used directly. Default folders are created when needed.

Optional development defaults can be supplied through `LOCALCAM_RTSP_USERNAME` and `LOCALCAM_RTSP_PASSWORD`.

## 9. Diagnostics and Error Handling

Debug local runs write structured JSONL diagnostics beside the launched executable. Release and installed distributions disable local Debug logging behavior as configured by the application.

Logged areas include startup, discovery attempts and results, settings load/save, stream lifecycle, snapshot saves, recording lifecycle, entitlement, purchase, and Store updates.

The UI reports retryable discovery failure, cancellation, stream initialization failure, missing credentials, individual stream failure, unavailable save folders, recording transitions, and Store update terminal states. Exceptions are not silently discarded in the primary workflows.

## 10. Store Features

Packaged Store builds support:

- Durable Premium add-on entitlement through Store ID `9P9KCJ3NFZFT`.
- In-app Premium purchase confirmation and purchase routing through `RequestPurchaseAsync`.
- Basic/Premium footer state and gated-action upgrade dialog.
- Store package update availability checks after first render.
- Throttled update checks, progress modal, cancellation/failure guidance, and queue-state recovery across restarts.

These features are unavailable or hidden in unpackaged Debug runs.

## 11. Limitations and Non-Goals

The current implementation does not provide:

- Manual camera IP entry or a persistent camera profile inventory.
- A device authentication or ONVIF profile-negotiation handshake.
- Arbitrary RTSP port or custom RTSP URL settings.
- Guaranteed universal camera compatibility.
- Diagnostics export.
- Multi-page navigation.

HTTPS certificate validation is bypassed for discovery fingerprint probing. RTSP credentials are held locally and used to construct stream URLs; the application does not provide a remote credential service.

The `LocalCam.Tests` project references xUnit and the .NET test SDK, but no test source files are currently present.

## 12. Key Files

- `App.xaml.cs`: bootstrap and logging initialization.
- `MainWindow.xaml` / `MainWindow.xaml.cs`: dashboard and runtime feature orchestration.
- `Networking/TapoCameraScanner.cs`: discovery implementation.
- `Models/LocalCamSettings.cs`: persisted settings model.
- `SettingsWindow.xaml` / `SettingsWindow.xaml.cs`: settings UI and validation.
- `Services/SettingsStore.cs`: settings persistence.
- `Services/JsonLogStore.cs`: diagnostics.
- `Services/PremiumEntitlementService.cs`: entitlement resolution.
- `Services/PremiumPurchaseService.cs`: Store purchase handling.
- `Services/StoreAppUpdaterService.cs`: Store update lifecycle.
