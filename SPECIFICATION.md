# LocalCam Specification

## 1. Product Summary

LocalCam is a Windows desktop WPF application for discovering Tapo security cameras on the local network and viewing their RTSP streams in a custom client.

Primary goal:
- Detect likely Tapo cameras on the LAN
- Present detected cameras to the user
- Connect to RTSP streams using user-provided credentials
- Display up to 4 live camera feeds in a single window

## 2. Tech Stack

- .NET 10 WPF desktop app
- C# with XAML UI
- LibVLCSharp.WPF for video playback
- `System.Net`, `System.Net.NetworkInformation`, `System.Net.Sockets` for LAN scanning
- Windows desktop-only runtime target: `net10.0-windows`

Source references:
- [LocalCam.csproj](D:\Projects\LocalCam\LocalCam.csproj)
- [App.xaml.cs](D:\Projects\LocalCam\App.xaml.cs)
- [StartupWindow.xaml.cs](D:\Projects\LocalCam\StartupWindow.xaml.cs)
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
2. App sets `ShutdownMode = OnExplicitShutdown`.
3. A modal `StartupWindow` is shown.
4. `StartupWindow` scans the local network on load.
5. If at least one likely Tapo camera is found, the dialog closes with `DialogResult = true`.
6. App opens `MainWindow` with the detected cameras.
7. App switches to `ShutdownMode = OnMainWindowClose`.
8. App exits when the main window closes.

Exit flow:
- User can exit from the startup window directly.
- If no cameras are found, the user can retry or exit.
- If the main window closes, the app stops streams, disposes VLC resources, and terminates.

## 5. Startup Window Specification

The startup window is the discovery gate.

Behavior:
- Shows a scanning status message on load.
- Runs an asynchronous LAN scan automatically.
- Supports `Scan again`.
- Supports `Exit`.
- Supports close-button exit.
- Cancels active scanning on close.

UI states:
- Scanning
- No camera detected
- Scan canceled
- Scan failed
- Success, with detected camera list passed to the main window

Implementation reference:
- [StartupWindow.xaml](D:\Projects\LocalCam\StartupWindow.xaml)
- [StartupWindow.xaml.cs](D:\Projects\LocalCam\StartupWindow.xaml.cs)

## 6. Camera Discovery Specification

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

Likely Tapo scoring signals:
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
- Detection is probabilistic. The app shows only hosts that meet the internal “likely Tapo” threshold.

Implementation reference:
- [Networking\TapoCameraScanner.cs](D:\Projects\LocalCam\Networking\TapoCameraScanner.cs)

## 7. Main Window Specification

The main window is the streaming dashboard.

Behavior:
- Opens only after a successful startup scan with at least one detection
- Shows up to 4 camera tiles
- Shows detected IP addresses on tiles
- Allows entering RTSP username and password
- Allows editing RTSP stream path
- Starts and stops playback through LibVLC
- Supports minimize, maximize/restore, and close
- Uses a custom chrome-less window style

Stream rules:
- Only the first 4 detections are used
- Each detection maps to one video tile/player
- RTSP URLs are built as:
  - `rtsp://{username}:{password}@{ip}:554/{streamPath}`
- Username/password are URL-escaped
- Default stream path is `stream1`
- Empty or slash-prefixed path input is normalized

Playback behavior:
- Initializes LibVLC on window construction
- Creates 4 muted media players
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

## 8. Configuration Specification

Current configuration surface is minimal and environment-driven.

Supported runtime configuration:
- RTSP username default via `LOCALCAM_RTSP_USERNAME`
- RTSP password default via `LOCALCAM_RTSP_PASSWORD`

Implicit behavior:
- No external config file is required for the current implementation
- No saved user profile or persistent camera list exists yet
- No selectable camera inventory exists beyond the current scan result

## 9. Non-Functional Constraints

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

## 10. Error Handling Specification

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

## 11. Current Product Scope

Implemented:
- LAN discovery of likely Tapo cameras
- Startup scan UI
- Retry and exit controls
- RTSP streaming in a 4-tile dashboard
- Basic window chrome and polished WPF styling

Not implemented:
- Persistent camera profiles
- Manual camera entry or selection workflow
- Device authentication handshake before streaming
- Saved credentials
- Diagnostics export
- A confirmed device identity model beyond heuristics
- Multi-page navigation or settings screen

## 12. Current Design Intent

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

## 13. Known Repo Mismatch

The README is behind the implementation in at least one place:
- [README.md](D:\Projects\LocalCam\README.md) says stream playback is planned
- The code already implements streaming, VLC initialization, RTSP URL generation, and stream control
