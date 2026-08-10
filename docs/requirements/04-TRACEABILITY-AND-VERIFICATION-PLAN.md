# LocalCam Traceability and Verification Plan

## Current evidence map

| Requirement area | Primary implementation evidence | Current test evidence | Gap |
|---|---|---|---|
| Startup/settings and theme | `App.xaml.cs`, `SettingsStore.cs`, `LocalCamSettings.cs`, `AppThemeService.cs`, `App.xaml`, `MainWindow.xaml(.cs)`, `SettingsWindow.xaml(.cs)`, `StoreUpdateProgressWindow.xaml` | No test source found; FAST-BUILD verified | Add settings recovery, pre-initialization theme mapping, persistence, brush-refresh, native-frame, host light/dark Fluent-resource, default Theme ComboBox behavior, and accent-foreground UI checks |
| Discovery | `Networking/TapoCameraScanner.cs` | No test source found | Add deterministic scanner tests with fakes |
| Dashboard/playback and window state | `MainWindow.xaml(.cs)` | No test source found | Add state-transition, native WPF window, persisted-bounds, direct saved-size restore, close-time save, and manual live-stream checks |
| Settings UI | `SettingsWindow.xaml(.cs)` | No test source found | Add validation, dirty-state, and folder tests |
| Snapshots | `MainWindow.xaml.cs`, settings folder logic | No test source found | Add unique-name and unavailable-folder tests |
| Recording | `MainWindow.xaml.cs`, recording policy docs | No test source found | Add single-session, rollover, and failure tests |
| Diagnostics | `Services/JsonLogStore.cs` | No test source found | Add schema and redaction tests |
| Store packaging | `LocalCam.Package/`, Store services | Existing policy/checklist docs | Add package validation in release workflow |

## Theme verification procedure

For FR-020, perform the following manual checks on a Windows host whose current theme is known:

1. Start the Debug executable with persisted `System`, `Light`, and `Dark` preferences separately.
2. Confirm the main window, custom Settings window, inputs, labels, borders, buttons, overlays, and auxiliary update dialog match the selected preference.
3. Change the preference in Settings, click `Update`, and confirm the main window updates without closing the app or stopping active streams.
4. Reopen Settings and confirm the saved preference and visual theme remain aligned.
5. Repeat the change in both directions and verify no process crash occurs.
6. If a crash occurs, collect the latest JSONL diagnostics and Windows `Application`, `.NET Runtime`, and `Windows Error Reporting` events.
7. Confirm no decorative outer client border is present on MainWindow, SettingsWindow, or StoreUpdateProgressWindow, and confirm the Settings Theme ComboBox uses the default WPF closed control, focus visual, arrow, popup, and highlighted-item behavior.

The known regression guard is the frozen-brush failure: `AppThemeService` must clone Fluent brushes and replace aliases; it must not assign `Color` or `Opacity` on a frozen brush.

## Recommended verification layers

1. Unit tests for pure normalization, settings comparison, URL construction, folder resolution, detection labeling, and recording state transitions.
2. Component tests using fake network/media/store boundaries.
3. UI acceptance checks for control visibility, accessibility, overlays, settings escalation, and window state.
   - Standard WPF window checks: native minimize/maximize/restore/close, system menu, snap behavior, minimum size, multi-monitor movement, DPI behavior, persisted bounds, direct saved-size restore, and close-time persistence after the final move or resize.
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
