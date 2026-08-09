# LocalCam Traceability and Verification Plan

## Current evidence map

| Requirement area | Primary implementation evidence | Current test evidence | Gap |
|---|---|---|---|
| Startup/settings | `App.xaml.cs`, `SettingsStore.cs`, `LocalCamSettings.cs` | No test source found | Add persistence and recovery tests |
| Discovery | `Networking/TapoCameraScanner.cs` | No test source found | Add deterministic scanner tests with fakes |
| Dashboard/playback | `MainWindow.xaml(.cs)` | No test source found | Add state-transition tests and manual live-stream checklist |
| Settings UI | `SettingsWindow.xaml(.cs)` | No test source found | Add validation, dirty-state, and folder tests |
| Snapshots | `MainWindow.xaml.cs`, settings folder logic | No test source found | Add unique-name and unavailable-folder tests |
| Recording | `MainWindow.xaml.cs`, recording policy docs | No test source found | Add single-session, rollover, and failure tests |
| Diagnostics | `Services/JsonLogStore.cs` | No test source found | Add schema and redaction tests |
| Store packaging | `LocalCam.Package/`, Store services | Existing policy/checklist docs | Add package validation in release workflow |

## Recommended verification layers

1. Unit tests for pure normalization, settings comparison, URL construction, folder resolution, detection labeling, and recording state transitions.
2. Component tests using fake network/media/store boundaries.
3. UI acceptance checks for control visibility, accessibility, overlays, settings escalation, and window state.
4. Controlled-network integration checks for discovery and RTSP startup.
5. Package/release checks for x64 packaging, Store-only behavior, and update flows.

## Minimum acceptance suite for future changes

- Build the affected project with the repository FAST-BUILD command.
- Run all available automated tests.
- Verify the affected happy path and at least one failure path.
- Confirm settings are backward-compatible with existing JSON.
- Confirm diagnostics contain no credentials or complete RTSP URLs.
- Update requirement status and evidence links when behavior changes.

## Definition of done for a requirement

A requirement is done when its wording is testable, implementation exists, the relevant automated or manual verification is recorded, failure behavior is defined, and traceability points to the owning code path.
