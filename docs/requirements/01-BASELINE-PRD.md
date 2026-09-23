# LocalCam Baseline Product Requirements

Status: Implemented baseline

## Product summary

LocalCam is a Windows desktop application that discovers compatible cameras on a local network and presents their RTSP video in a multi-camera dashboard. The implementation is Tapo-first internally, while normal user-facing wording is brand-neutral.

## Users and primary needs

- A local camera owner who wants to find cameras without manually scanning a subnet.
- A desktop operator who wants to view several discovered streams in one window.
- A developer or support operator who needs actionable status and structured diagnostics.

## Product goals

1. Make local camera discovery quick, retryable, and understandable.
2. Make RTSP configuration and stream startup predictable.
3. Provide lightweight snapshot and manual recording workflows.
4. Preserve settings and useful diagnostics across launches.
5. Keep the implementation lean, x64-only, and suitable for continued incremental development.

## Current user journey

1. Launch the single-window application and immediately see the dashboard shell.
2. Load settings and restore window bounds while the video engine prepares in the background.
3. Reconnect recent cameras when enabled, falling back to discovery for unavailable or new cameras after the video engine is ready.
4. Use Detect and Play to reconnect or discover cameras and start playback for the detected cameras.
5. Review detected camera tiles and discovery status.
6. Configure RTSP credentials and stream path in Settings, using the camera setup guide when needed.
7. Play one camera or all cameras manually when needed.
8. Capture snapshots or record one active stream, then stop streams and recording; resources are cleaned up during shutdown.

## Current capabilities

- Multi-method, best-effort local-network discovery.
- Seven-day local recent-camera reconnect cache with discovery fallback and two-failure eviction.
- Brand-neutral display labels for discovery methods.
- Per-camera and Start All/Stop All stream controls.
- System suspend/hibernate uses the normal Stop All path and leaves detected camera tiles and connection state intact; resume does not auto-start playback or recording.
- RTSP playback using LibVLCSharp.WPF and VideoLAN.LibVLC.Windows.
- Stream path persistence with default `stream1`; RTSP port remains `554`.
- Detect and Play for cache-first reconnect, discovery, and playback of detected cameras.
- Settings for credentials, reconnect recent cameras on startup, snapshot folder, recording folder, and a camera setup guide link.
- Validation escalation to Settings for invalid RTSP configuration.
- Snapshot capture with unique filenames.
- Manual `.ts` recording, one active recording across the app, and 60-minute segmentation.
- Expand/collapse and double-click layout toggling while playing.
- Atomic, backup-aware JSON settings persistence and structured JSONL diagnostics.
- Responsive startup with visible video-engine preparation status, readiness-gated stream actions, retryable initialization failure, and existing-instance activation for repeated launches.
- Persisted System, Light, and Dark preferences using the Windows WPF Fluent theme and host-provided theme resources.
- Theme changes apply before the initial visual tree is created and refresh existing LocalCam brush aliases and dynamically created camera-card visuals.
- MainWindow, SettingsWindow, and the update-progress window use native Windows/WPF frames with flattened client-area roots; Settings uses a themed custom ComboBox for the System/Light/Dark preference.
- Separate packaged Store entitlement, purchase, and update services.

## Scope boundaries

Current implementation does not provide manual IP entry, permanent camera profiles, arbitrary RTSP ports, custom RTSP URLs, device authentication handshakes, guaranteed universal compatibility, diagnostics export, or multi-page navigation.

Store Basic/Premium behavior applies to packaged Store builds. Unpackaged development builds hide Store entitlement and upgrade UI.

## Product success measures to establish

The repository does not currently define product telemetry or target thresholds. Future releases should establish measurable targets for discovery completion rate, time to first successful stream, stream-start failure recovery, snapshot/recording success rate, crash-free sessions, and test coverage of critical workflows.
