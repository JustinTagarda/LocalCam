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

1. Launch the single-window application.
2. Load settings and restore window bounds.
3. Discover cameras automatically when enabled, or start discovery manually.
4. Review detected camera tiles and discovery status.
5. Configure RTSP credentials and stream path in Settings.
6. Play one camera, all cameras, or auto-start eligible streams.
7. Capture snapshots or record one active stream.
8. Stop streams and recording; resources are cleaned up during shutdown.

## Current capabilities

- Multi-method, best-effort local-network discovery.
- Brand-neutral display labels for discovery methods.
- Per-camera and Start All/Stop All stream controls.
- RTSP playback using LibVLCSharp.WPF and VideoLAN.LibVLC.Windows.
- Stream path persistence with default `stream1`; RTSP port remains `554`.
- Settings for credentials, auto-detection, auto-streaming, snapshot folder, and recording folder.
- Validation escalation to Settings for invalid RTSP configuration.
- Snapshot capture with unique filenames.
- Manual `.ts` recording, one active recording across the app, and 60-minute segmentation.
- Expand/collapse and double-click layout toggling while playing.
- JSON settings persistence and structured JSONL diagnostics.
- Separate packaged Store entitlement, purchase, and update services.

## Scope boundaries

Current implementation does not provide manual IP entry, persistent camera profiles, arbitrary RTSP ports, custom RTSP URLs, device authentication handshakes, guaranteed universal compatibility, diagnostics export, or multi-page navigation.

Store Basic/Premium behavior applies to packaged Store builds. Unpackaged development builds hide Store entitlement and upgrade UI.

## Product success measures to establish

The repository does not currently define product telemetry or target thresholds. Future releases should establish measurable targets for discovery completion rate, time to first successful stream, stream-start failure recovery, snapshot/recording success rate, crash-free sessions, and test coverage of critical workflows.
