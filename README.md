# LocalCam

LocalCam is a Windows desktop WPF application for discovering likely Tapo security cameras on the local network and viewing their RTSP streams in a custom viewer.

## Current Status

The app currently implements:
- Local network scanning for likely Tapo camera devices
- A startup scan window with retry and exit actions
- A main viewer window with up to 4 live camera tiles
- RTSP stream playback through LibVLCSharp
- Basic custom chrome and dark-themed UI styling

## Tech Stack

- C# (.NET 10, `net10.0-windows`)
- WPF (XAML) for the desktop UI
- LibVLCSharp.WPF for video playback
- .NET networking APIs for LAN discovery

## Workflow

1. App starts in `App.xaml.cs`.
2. A startup window scans the local network for likely Tapo cameras.
3. If detections are found, the main window opens with those cameras.
4. The main window accepts RTSP credentials and a stream path.
5. Streams start and stop from the viewer window.
6. Closing the main window exits the app.

## Discovery Behavior

The scanner uses a best-effort heuristic approach:
- Enumerates active IPv4-capable network interfaces
- Probes likely camera ports such as `554`, `8554`, and `2020`
- Checks HTTP/HTTPS fingerprints when available
- Uses ARP and reverse DNS enrichment
- Scores candidates using camera-service and TP-Link/Tapo signals

## Streaming Behavior

The viewer:
- Shows up to 4 detected cameras
- Builds RTSP URLs from user-supplied credentials
- Uses a default stream path of `stream1`
- Reads optional defaults from:
  - `LOCALCAM_RTSP_USERNAME`
  - `LOCALCAM_RTSP_PASSWORD`

## Project Docs

- [SPECIFICATION.md](SPECIFICATION.md) contains the implementation-based project specification.
- [AGENTS.md](AGENTS.md) contains repo instructions for Codex and related agents.

## Notes

- Detection is heuristic, not authoritative.
- The app is Windows desktop only.
- The README is kept aligned with the current implementation rather than the original prototype scope.
