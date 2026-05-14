# LocalCam Specification

## 1. Product Summary

LocalCam is a Windows desktop WPF application for discovering compatible local network cameras and viewing their RTSP streams in a custom client. The implementation is Tapo-first and optimized for TP-Link/Tapo discovery, while also supporting compatible RTSP/ONVIF cameras when they expose similar network services.

Primary goal:
- Detect compatible cameras on the LAN
- Present detected cameras to the user
- Connect to RTSP streams using user-provided credentials
- Display live camera feeds in a single window

## 2. Tech Stack

- .NET 10 WPF desktop app
- C# with XAML UI
- LibVLCSharp.WPF for video playback
- `System.Net`, `System.Net.NetworkInformation`, `System.Net.Sockets` for LAN scanning
- Windows desktop-only runtime target: `net10.0-windows`

Source references:
- [LocalCam.csproj](D:\Projects\LocalCam\LocalCam.csproj)
- [App.xaml.cs](D:\Projects\LocalCam\App.xaml.cs)
- [MainWindow.xaml.cs](D:\Projects\LocalCam\MainWindow.xaml.cs)
- [Networking\TapoCameraScanner.cs](D:\Projects\LocalCam\Networking\TapoCameraScanner.cs)

## 3. Application Structure

The app has three main layers:

- Bootstrap layer: application startup and shutdown control
- Discovery layer: local subnet scanning and candidate detection
- Presentation/playback layer: startup dialog and main streaming window

## 4. Startup and Exit Flow

Startup flow:
1. Application starts in [App.xaml.cs](D:\Projects\LocalCam\App.xaml.cs).
2. App initializes JSON logging.
3. App opens `MainWindow` directly.
4. `MainWindow` performs local-network camera discovery on load.
5. If detections are found, the viewer populates camera tiles for the detections.
6. If no detections are found, the user can retry search from the main window.
7. App exits when the main window closes.

Exit flow:
- If the main window closes, the app stops streams, disposes VLC resources, and terminates.

## 5. Camera Discovery Specification

Discovery is best-effort and heuristic-based, not authoritative.

Scan scope:
- Enumerates active network interfaces
- Ignores loopback and tunnel interfaces
- Requires an IPv4 gateway on the interface
- Ignores APIPA addresses
- Caps broad subnets to `/24` to avoid excessive host enumeration
- Skips extremely small or invalid prefixes

Host probing:
- Pings each candidate host
- Probes ports:
  - `80`
  - `443`
  - `554`
  - `8554`
  - `2020`
  - `8080`
  - `8443`
- Reads the ARP table using `arp -a`
- Attempts reverse DNS lookup
- Fetches HTTP/HTTPS headers/body fingerprints from port 80 or 443 when available

Tapo-first compatible camera scoring signals:
- RTSP open on `554` or `8554`
- ONVIF-related open port `2020`
- Web management ports open
- HTTP response contains Tapo/TP-Link markers
- Hostname contains Tapo/TP-Link markers
- MAC OUI matches known TP-Link prefixes

Output:
- A list of `TapoCameraDetection` records containing:
  - IP address
  - Host name
  - MAC address
  - Open ports
  - Confidence score
  - Detection reason

Important constraint:
- Detection is probabilistic. The app shows only hosts that meet the internal compatible-camera threshold.

Implementation reference:
- [Networking\TapoCameraScanner.cs](D:\Projects\LocalCam\Networking\TapoCameraScanner.cs)

## 6. Main Window Specification

The main window is the streaming dashboard.

Behavior:
- Opens only after a successful startup scan with at least one detection
- Shows camera tiles for detected cameras
- Shows detected IP addresses on tiles
- Allows entering RTSP username and password
- Allows editing RTSP stream path
- Starts and stops playback through LibVLC
- Supports minimize, maximize/restore, and close
- Uses a custom chrome-less window style

Stream rules:
- Each detection maps to one video tile/player
- RTSP URLs are built as:
  - `rtsp://{username}:{password}@{ip}:554/{streamPath}`
- Username/password are URL-escaped
- Default stream path is `stream1`
- Empty or slash-prefixed path input is normalized

Playback behavior:
- Initializes LibVLC on window construction
- Creates muted media players per active camera tile
- Applies options for network caching and low jitter
- Starts only if credentials exist and detections are available
- Stops all streams before restarting
- Stops and disposes resources on close

Credential defaults:
- Reads optional environment variables:
  - `LOCALCAM_RTSP_USERNAME`
  - `LOCALCAM_RTSP_PASSWORD`

Implementation reference:
- [MainWindow.xaml](D:\Projects\LocalCam\MainWindow.xaml)
- [MainWindow.xaml.cs](D:\Projects\LocalCam\MainWindow.xaml.cs)

## 7. Configuration Specification

Current configuration surface is minimal and environment-driven.

Supported runtime configuration:
- RTSP username default via `LOCALCAM_RTSP_USERNAME`
- RTSP password default via `LOCALCAM_RTSP_PASSWORD`

Implicit behavior:
- No external config file is required for the current implementation
- No saved user profile or persistent camera list exists yet
- No selectable camera inventory exists beyond the current scan result

## 8. Non-Functional Constraints

Platform:
- Windows desktop only

Performance:
- Scan is concurrent with bounded parallelism
- Default max parallelism is `48`
- Port probe and ping timeouts are short to keep startup responsive

Resource handling:
- Scan cancellation is supported
- VLC resources are disposed on exit
- Media players are stopped before disposal

Security and trust:
- HTTPS certificate validation is intentionally bypassed during fingerprint probing
- This is discovery-only probing, not full authentication
- RTSP credentials are handled locally in memory and used to form stream URLs

## 9. Error Handling Specification

Discovery failures:
- If scan returns no candidates, user gets a retryable “no camera detected” state
- If scan is canceled, the UI reflects cancellation or close behavior
- If scan throws, the user sees a failure message with the exception message

Streaming failures:
- If the video engine fails to initialize, the status text shows the failure
- If no cameras are detected, streaming is disabled by behavior
- If credentials are missing, the user is prompted before stream start
- If individual camera streams fail, the UI reports the failed IPs

Resource cleanup:
- On startup window close, cancellation is issued for active scans
- On main window close, streams are stopped and VLC objects are disposed

## 10. Current Product Scope

Implemented:
- LAN discovery of compatible cameras using Tapo-first heuristics
- RTSP streaming in a multi-tile dashboard
- Basic window chrome and polished WPF styling
- Retry search from the main window

Not implemented:
- Persistent camera profiles
- Manual camera entry or selection workflow
- Device authentication handshake before streaming
- Saved credentials
- Diagnostics export
- A confirmed device identity model beyond heuristics
- Multi-page navigation or settings screen

## 11. Current Design Intent

The current UI is:
- Dark-themed
- Compact and focused
- Custom-chrome WPF
- Split into:
  - a discovery gate
  - a live streaming dashboard

Functional intent:
- Minimize setup friction
- Make scan-to-stream the dominant workflow
- Keep the app simple enough for immediate camera access on a local network
