# LocalCam Traceability and Verification Plan

## Current evidence map

| Requirement area | Primary implementation evidence | Current test evidence | Gap |
|---|---|---|---|
| Startup/settings and theme | `App.xaml.cs`, `SettingsStore.cs`, `LocalCamSettings.cs`, `AppThemeService.cs`, `App.xaml`, `MainWindow.xaml(.cs)`, `SettingsWindow.xaml(.cs)`, `StoreUpdateProgressWindow.xaml` | No test source found; FAST-BUILD verified | Add settings recovery, pre-initialization theme mapping, persistence, brush-refresh, native-frame, host light/dark Fluent-resource, default Theme ComboBox behavior, and accent-foreground UI checks |
| Discovery | `Networking/TapoCameraScanner.cs` | No test source found | Add deterministic scanner tests with fakes |
| Recent-camera reconnect | `Services/RecentCameraConnectionCache.cs`, `MainWindow.xaml.cs` | Cache-policy tests | Add controlled-network reconnect/fallback check |
| Dashboard/playback and window state | `MainWindow.xaml(.cs)` | No test source found | Add state-transition, native WPF window, persisted-bounds, direct saved-size restore, close-time save, and manual live-stream checks |
| Settings UI | `SettingsWindow.xaml(.cs)` | No test source found | Add validation, dirty-state, and folder tests |
| Snapshots | `MainWindow.xaml.cs`, settings folder logic | No test source found | Add unique-name and unavailable-folder tests |
| Recording | `MainWindow.xaml.cs`, recording policy docs | No test source found | Add single-session, rollover, and failure tests |
| Diagnostics | `Services/JsonLogStore.cs` | No test source found | Add schema and redaction tests |
| Store packaging | `LocalCam.Package/`, Store services | Existing policy/checklist docs | Add package validation in release workflow |

## Shared button-style verification

The app-wide button invariant is owned by `App.xaml` and must be checked for every button change:

1. Confirm `GlobalButtonStyle` retains the Settings baseline: Fluent-backed dynamic brushes, 1px border, `12,4` padding, `92` minimum width, `30` height, hand cursor, 4px corner radius, hover/pressed states, and disabled opacity.
2. Confirm the implicit `Button` style is based on `GlobalButtonStyle`.
3. Confirm every XAML button has either the implicit global style or an explicit style based on `GlobalButtonStyle`; no window-local button style may duplicate an independent button template.
4. Confirm every code-created button resolves a style whose inheritance chain reaches `GlobalButtonStyle`.
5. Confirm specialized icon, overlay, and status buttons preserve their required geometry, visibility, accessibility, and command behavior while inheriting the global baseline.
6. Repeat the visual check in System, Light, and Dark modes, including Settings, MainWindow, StoreUpdateProgressWindow, UnsavedChangesDialog, BasicFeatureGateDialog, and active camera-card overlays.

## Camera-area action-button verification

For the camera-area in-video action buttons, verify that `CameraOverlayIconButtonStyle` derives from `GlobalButtonStyle`, has no fixed `Width` or `Height`, explicitly sets `MinWidth` to `0`, and sets uniform `Padding` to `6px`. Confirm every action icon uses a `16x16` content canvas, the buttons remain content-sized with automatic height, and existing glyph proportions, visibility, command, tooltip, accessibility, and overlay behavior are retained. Repeat in collapsed and expanded cards during active playback, resize, DPI scaling, and System/Light/Dark theme changes. Do not apply this sizing rule to non-camera buttons.

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

- Verify from the repository directory that `dotnet --version` reports exactly `10.0.400`; stop if the pinned SDK is unavailable.
- Build the affected project with the repository FAST-BUILD command.
- Run all available automated tests.
- Verify the affected happy path and at least one failure path.
- Confirm settings are backward-compatible with existing JSON.
- Verify seven-day cache expiry, two-failure eviction, stable-attempt handling, bounded playback confirmation timeout, RTSP-setting invalidation, and discovery fallback.
- Confirm diagnostics contain no credentials or complete RTSP URLs.
- Update requirement status and evidence links when behavior changes.

Toolchain guardrail: if the .NET SDK pin changes, verify `global.json`, `AGENTS.md`, README build instructions, NFR-009, the architecture baseline, and the decision record are updated together. Do not accept a build completed with a different SDK as evidence for the pinned-toolchain requirement.

## Definition of done for a requirement

A requirement is done when its wording is testable, implementation exists, the relevant automated or manual verification is recorded, failure behavior is defined, and traceability points to the owning code path.
