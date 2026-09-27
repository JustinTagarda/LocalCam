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
- Windows.Services.Store APIs for packaged entitlement and purchase operations.
- Built-in .NET networking APIs for discovery and JSON serialization/logging.

The application is built from `LocalCam.csproj`; Store packaging is defined separately in `LocalCam.Package/LocalCam.Package.wapproj` and is x64-only.

## 3. Architecture

The application is organized around four responsibilities:

- Bootstrap: `App.xaml.cs` initializes diagnostics and opens the main window.
- Discovery: `Networking/TapoCameraScanner.cs` performs bounded, best-effort local-network detection.
- Dashboard and media: `MainWindow.xaml` and `MainWindow.xaml.cs` manage camera tiles, LibVLC playback, snapshots, recording, status, and shutdown cleanup.
- Persistence and platform services: `Models/LocalCamSettings.cs`, `Services/SettingsStore.cs`, `Services/JsonLogStore.cs`, and the Store service classes manage settings, diagnostics, entitlement, and purchases.

## 4. Startup and Shutdown

1. `App.xaml.cs` initializes JSONL diagnostics.
2. `MainWindow` loads persisted settings and restores window bounds when available.
3. If Reconnect recent cameras on startup is enabled, the main window reconnects recent cameras after the video engine is ready.
4. Detect and Play requests cached-camera playback first, then refreshes discovery even when cached reconnect succeeds. New detections start playback incrementally; the bounded adaptive pass runs after local methods even when local cameras were found.
5. Packaged Store builds resolve Premium UI state after first render; Microsoft Store delivers package updates outside the app.
6. On close, active recordings and streams are stopped, cancellation is requested, and LibVLC resources are disposed.

## 5. Discovery

Discovery is heuristic and best-effort. It does not prove camera identity or guarantee that every compatible camera will be found.

The scanner:

- Enumerates active, eligible IPv4 interfaces and uses connected-prefix and route clues visible to Windows.
- Skips loopback, tunnel, and APIPA interfaces.
- Bounds connected-prefix enumeration, concurrency, protocol receive windows, request counts, response sizes, and timeouts.
- Probes reachability and common camera/service ports, including `80`, `443`, `554`, `8554`, `2020`, `8080`, and `8443`.
- Reads ARP data and attempts reverse DNS.
- Uses ONVIF WS-Discovery, SSDP/UPnP, Tapo UDP, mDNS/DNS-SD, ARP-seeded probes, RTSP OPTIONS probes, subnet probes, and Tapo/TP-Link-specific fingerprints.
- Runs the persisted last successful local method first. When neither Tapo UDP nor ONVIF is preferred, their discovery hints are collected concurrently; remaining local methods continue in their fixed order.
- Successful local detection results update the persisted method preference, which is resolved again on the next scan in the same app session or after restart.
- Runs the existing `AdaptiveRtspVerificationProbe` after all local methods even if local cameras have been found. It selects bounded candidate private `/24` ranges from recent camera and adapter DNS/DHCP clues plus common home-network candidates, then validates responsive RTSP endpoints without credentials.
- Publishes cumulative detections during scanning so newly found cameras can start playback before the full scan completes.
- Does not claim multicast crosses routers or identify exact mesh/extender/backhaul topology. Candidate inference does not create routes or bypass NAT, ACLs, or firewalls.

Internal results are represented by Tapo-specific records such as `TapoCameraDetection`, with IP address, hostname, MAC address, open ports, confidence score, and detection reason. Internal names are intentionally not generalized. User-facing method labels are mapped to `ONVIF`, `SSDP`, `local discovery`, `mDNS`, `ARP probe`, and `subnet probe`.

## 6. Dashboard and Playback

The native-frame main window provides:

- Detect and Play, Play all, Stop All, and Settings toolbar actions.
- A camera tile for each current detection.
- Per-tile Play/Stop, Snapshot, Record/Stop Recording, and Expand/Collapse actions.
- Double-click collapse/expand behavior while a tile is playing.
- Discovery, stream, snapshot, and recording status in the activity/status area.

RTSP playback uses the configured username, password, detected host, a validated service port, and normalized stream path. Port `554` is the default; `8554` is retained for playback/reconnect only after a valid RTSP OPTIONS response confirms that endpoint:

`rtsp://{username}:{password}@{host}:{validatedPort}/{streamPath}`

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
- Reconnect recent cameras on startup.
- Theme preference (System, Light, or Dark).
- Snapshot Save Folder.
- Recording Save Folder.

Settings are persisted to `%LocalAppData%\\LocalCam\\settings.json`. Persisted state also includes the last successful discovery method, window bounds, Basic recording usage, and Premium entitlement cache.

Effective default folders are `%UserProfile%\\Pictures\\LocalCam` for snapshots and `%UserProfile%\\Videos\\LocalCam` for recordings. A user-selected non-default folder is used directly. Default folders are created when needed.

Optional development defaults can be supplied through `LOCALCAM_RTSP_USERNAME` and `LOCALCAM_RTSP_PASSWORD`.

## 9. Diagnostics and Error Handling

Debug, Release, and installed distributions use one structured JSONL diagnostics route under Windows application-data storage; logs are never written beside the launched executable. Packaged local data is removed by Windows when the package is uninstalled. Unpackaged desktop runs use the same application-data abstraction with a local fallback because an unpackaged executable has no OS uninstall lifecycle.

Log files rotate by UTC day and files older than seven days are deleted during startup and periodic retention sweeps. Messages, exception details, stack traces, URLs, and structured data are sanitized before serialization so credentials, complete RTSP URLs, and secret-bearing fields are replaced with `[REDACTED]`.

Logged areas include startup, discovery attempts and results, settings load/save, stream lifecycle, snapshot saves, recording lifecycle, entitlement, and purchase.

The UI reports retryable discovery failure, cancellation, stream initialization failure, missing credentials, individual stream failure, unavailable save folders, and recording transitions. Exceptions are not silently discarded in the primary workflows.

## 10. Store Features

Packaged Store builds support:

- Durable Premium add-on entitlement through Store ID `9P9KCJ3NFZFT`.
- In-app Premium purchase confirmation and purchase routing through `RequestPurchaseAsync`.
- Basic/Premium status and gated-action upgrade entry point in the Settings footer.
- Microsoft Store-managed MSIX package delivery. LocalCam does not check for updates in-app, show update UI, track package queues, or request package installation.

These features are unavailable or hidden in unpackaged Debug runs.

## 11. Limitations and Non-Goals

The current implementation does not provide:

- Manual camera IP entry or a persistent camera profile inventory.
- A device authentication or ONVIF profile-negotiation handshake.
- Arbitrary RTSP ports or custom RTSP URL settings; supported ports are 554 by default and 8554 only after validation.
- Guaranteed universal camera compatibility.
- Diagnostics export.
- Multi-page navigation.

HTTPS certificate validation is bypassed for discovery fingerprint probing. RTSP credentials are held locally and used to construct stream URLs; the application does not provide a remote credential service.

The `LocalCam.Tests` project references xUnit and the .NET test SDK and contains automated unit and persistence tests. Live WPF, LibVLC, multi-camera, and package verification remain separate manual or integration checks.

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
- `docs/STORE-SUBMISSION-GUIDE.md`: Store package versioning, build, validation, submission, and flight procedure.
