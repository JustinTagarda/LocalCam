# LocalCam Traceability and Verification Plan

## Current evidence map

| Requirement area | Primary implementation evidence | Current test evidence | Gap |
|---|---|---|---|
| Startup/settings and theme | `App.xaml.cs`, `SettingsStore.cs`, `LocalCamSettings.cs`, `AppThemeService.cs`, `App.xaml`, `MainWindow.xaml(.cs)`, `SettingsWindow.xaml(.cs)` | `SettingsMergeTests.CloneSettingsPreservesAllPersistedState`; `SettingsStoreTests` obsolete-updater compatibility, backup recovery, concurrent-save, and invalid-file tests; FAST-BUILD and manual startup check | Add persisted-settings integration, pre-initialization theme mapping, persistence, brush-refresh, native-frame, host light/dark Fluent-resource, default Theme ComboBox behavior, accent-foreground UI, dashboard-before-engine-render, initialization retry, readiness gating, and repeated-launch activation checks |
| Discovery | `Networking/TapoCameraScanner.cs` | No test source found | Add deterministic scanner tests with fakes |
| Recent-camera reconnect | `Services/RecentCameraConnectionCache.cs`, `Services/CameraDetectionReconciler.cs`, `MainWindow.xaml.cs` | Cache-policy and detection-reconciliation tests | Add controlled-network reconnect/fallback check, including a delayed `Playing` event after timeout or tile reassignment |
| Dashboard/playback and window state | `MainWindow.xaml(.cs)`, `Services/CameraDetectionReconciler.cs`, `Services/StreamHealthEvaluator.cs`, `LocalCam.Tests/CameraDetectionReconcilerTests.cs`, `LocalCam.Tests/StreamFailureClassificationTests.cs`, `LocalCam.Tests/StreamHealthEvaluatorTests.cs` | Camera detection reconciliation, stream-failure classification, and stream-health evaluator tests | Add Detect and Play single-start verification, confirmed-playback state transition, startup grace, consecutive stale-sample, bounded recovery/cooldown, terminal-event recovery invalidation, suspend/hibernate Stop All, resume-no-autostart, native WPF window, persisted-bounds, direct saved-size restore, close-time save, per-card failure isolation, credential-escalation, and manual live-stream checks |
| Settings UI | `SettingsWindow.xaml(.cs)` | No UI test source found | Add validation, dirty-state, folder, placeholder, credential-border, focus, Update-with-missing-credentials, camera setup guide link/browser-launch, single-row copyright/Store-plan footer, packaged Basic/Premium visibility, Upgrade callback, and theme/DPI checks |
| Snapshots | `MainWindow.xaml.cs`, settings folder logic | No test source found | Add unique-name and unavailable-folder tests |
| Recording | `MainWindow.xaml.cs`, recording policy docs | No test source found | Add single-session, rollover, and failure tests |
| Diagnostics | `Services/JsonLogStore.cs` | `LocalCam.Tests/JsonLogStoreTests.cs` | Redaction helper, exception-message/stack-trace serialization, nested structured-data, and seven-day retention tests; verify packaged application-data cleanup, unpackaged fallback location, release logging, and live seven-day rotation |
| Store packaging and submission | `LocalCam.Package/Package.appxmanifest`, `LocalCam.Package/LocalCam.Package.wapproj`, `docs/STORE-SUBMISSION-GUIDE.md` | Manifest identity/version checks, x64 MSIX build, upload-artifact hash, packaged smoke test, Partner Center submission record, and Store-flight evidence | Record external Partner Center certification and production-publication results for each release; local builds cannot establish those results |

## Shared button-style verification

## RTSP credential and per-camera playback verification

For FR-008 and FR-009, perform the following manual checks:

1. Open Settings with empty credentials and confirm the username and password placeholders are visible without changing persisted values.
2. Modify a non-credential setting and click Update with empty credentials. Confirm Settings remains open, the exact required message is shown, both empty credential fields use the theme-aware critical border, and focus moves to the username field.
3. Repeat with only the username missing and then only the password missing. Confirm only the missing field is red. Enter a valid value and confirm that field returns to the normal input border while the other invalid field remains red.
4. With detected cameras, trigger Detect and Play, Play all, and per-card Play with missing credentials. Confirm Settings opens and only missing fields are highlighted; the stream-start flow does not close Settings or attempt RTSP playback.
5. Open Settings and confirm the camera setup guide link is visible below Stream Path and opens the configured guide in the default browser.
6. With cached cameras and with a fresh discovery result, trigger Detect and Play. Confirm cache-first reconnect/discovery occurs and each detected camera receives one playback request, with no duplicate start request from rendering and route orchestration.
7. With multiple detected cameras, cause one camera to fail because of credential rejection, network failure, or playback/decode failure. Confirm the failed card alone shows centered red error text, the suggestion is shown only for a classified reason, and other cameras continue streaming.
   - During a failed-camera fallback scan, confirm existing active cards and video surfaces remain visible. Return detections in a different order and with a repeated known MAC identity; verify existing players remain associated with the same camera, each known camera identity appears on one card, and only stopped/new detections receive a new playback request. If discovery returns no detections, existing cards remain visible and usable.
8. Confirm a credential-related playback failure opens Settings, while network, device/decode, and unknown failures do not open Settings.
9. Restore playback on the failed card and confirm its error text clears after LibVLC reports `Playing`.

For Store UI placement and footer behavior, perform the following manual checks:

1. In an unpackaged run, confirm the MainWindow footer retains the status/activity text, progress indicator, and conditional Retry control; confirm the Settings footer shows copyright and the version at the right edge without Basic/Premium or Upgrade controls.
2. In a packaged Basic run, confirm the MainWindow footer retains all status/activity controls while Settings shows `Basic`, an enabled `Upgrade` button, and the version as the rightmost footer item.
3. In a packaged Premium run, confirm Settings shows `Premium`, hides Upgrade, and retains the version at the right edge.
4. Exercise video-engine preparation/failure, discovery progress, stream failure, snapshot/recording feedback, and retry states. Confirm every existing status message remains visible in the relocated MainWindow footer and no status/activity control is removed.
5. Activate Upgrade from Settings and confirm the existing confirmation, purchase, entitlement refresh, and accessibility restoration flow remains functional without changing persisted Settings values.
6. Repeat the MainWindow and Settings footer checks in System, Light, and Dark themes, at the supported DPI/scaling levels, and at the MainWindow minimum width. Confirm the MainWindow footer presents as a flat row with a top separator only, has no enclosing panel wrapper, and has no overlap when progress and Retry are simultaneously visible.

The app-wide button invariant is owned by `App.xaml` and must be checked for every button change:

1. Confirm `GlobalButtonStyle` retains the Settings baseline: Fluent-backed dynamic brushes, 1px border, `12,4` padding, `92` minimum width, `30` height, hand cursor, 4px corner radius, hover/pressed states, and disabled opacity.
2. Confirm the implicit `Button` style is based on `GlobalButtonStyle`.
3. Confirm every XAML button has either the implicit global style or an explicit style based on `GlobalButtonStyle`; no window-local button style may duplicate an independent button template.
4. Confirm every code-created button resolves a style whose inheritance chain reaches `GlobalButtonStyle`.
5. Confirm specialized icon, overlay, and status buttons preserve their required geometry, visibility, accessibility, and command behavior while inheriting the global baseline.
6. Repeat the visual check in System, Light, and Dark modes, including Settings, MainWindow, UnsavedChangesDialog, BasicFeatureGateDialog, and active camera-card overlays.

## Camera-area action-button verification

For the camera-area in-video action buttons, verify that `CameraOverlayIconButtonStyle` derives from `GlobalButtonStyle`, has no fixed `Width` or `Height`, explicitly sets `MinWidth` to `0`, and sets uniform `Padding` to `6px`. Confirm every action icon uses a `16x16` content canvas, the buttons remain content-sized with automatic height, and existing glyph proportions, visibility, command, tooltip, accessibility, and overlay behavior are retained. Repeat in collapsed and expanded cards during active playback, resize, DPI scaling, and System/Light/Dark theme changes. Do not apply this sizing rule to non-camera buttons.

## Theme verification procedure

For FR-020, perform the following manual checks on a Windows host whose current theme is known:

1. Start the Debug executable with persisted `System`, `Light`, and `Dark` preferences separately.
2. Confirm the main window, custom Settings window, inputs, labels, borders, buttons, overlays, and auxiliary update dialog match the selected preference.
3. Change the preference in Settings, click `Update`, and confirm the main window updates without closing the app or stopping active streams.
4. Reopen Settings and confirm the saved preference and visual theme remain aligned.
5. Repeat the change in both directions and verify no process crash occurs.
6. If a crash occurs, collect the latest JSONL diagnostics from the application-data log folder and Windows `Application`, `.NET Runtime`, and `Windows Error Reporting` events.
7. Confirm no decorative outer client border is present on MainWindow or SettingsWindow, and confirm the Settings Theme ComboBox uses the default WPF closed control, focus visual, arrow, popup, and highlighted-item behavior.

The known regression guard is the frozen-brush failure: `AppThemeService` must clone Fluent brushes and replace aliases; it must not assign `Color` or `Opacity` on a frozen brush.

## Recommended verification layers

1. Unit tests for pure normalization, settings comparison, URL construction, folder resolution, detection labeling, and recording state transitions.
2. Component tests using fake network/media/store boundaries.
3. UI acceptance checks for control visibility, accessibility, overlays, settings escalation, and window state.
   - Standard WPF window checks: native minimize/maximize/restore/close, system menu, snap behavior, minimum size, multi-monitor movement, DPI behavior, persisted bounds, direct saved-size restore, and close-time persistence after the final move or resize.
4. Controlled-network integration checks for discovery and RTSP startup.
5. Follow [the Store submission guide](../STORE-SUBMISSION-GUIDE.md) for x64 package creation, manifest/version validation, local packaged smoke testing, Partner Center submission evidence, and Store-flight update delivery.

## Startup responsiveness verification

For FR-001 and FR-024, verify the following on a Debug executable:

1. Start after a cold native-library cache and confirm the main dashboard is visible while `Preparing video engine...` and the indeterminate progress indicator are shown.
2. Confirm Play all and per-card Play are unavailable until LibVLC initialization completes, while Settings remains available.
3. Confirm recent-camera reconnect and local discovery begin only after the video engine is ready.
4. Simulate missing or invalid LibVLC native assets and confirm the dashboard remains open with a concise failure status and a retry control that is focusable only while visible.
5. Use the retry control and confirm successful initialization restores normal stream controls and startup flow.
6. Launch the executable again while the first instance is starting or visible and confirm the existing window is activated without creating a second window.
7. Close during video-engine initialization and confirm the process exits without leaving a live LibVLC engine or activation listener.

## Playback health and recovery verification

For FR-009, FR-018, NFR-006, and NFR-008, perform the following checks:

1. Start one and then four compatible cameras. Confirm playback-request logs precede distinct LibVLC playback-confirmed logs and that no recovery occurs during the startup grace period.
2. Confirm repeated `Playing` events do not interrupt the monitor sampling interval or create a restart storm.
3. Hold one camera without advancing video output. Confirm recovery requires consecutive unhealthy samples, respects cooldown, and stops after the per-camera attempt limit.
4. Confirm recovery exhaustion shows a centered red error only on the failed card and leaves other cameras streaming.
5. Restore the failed camera and use Play. Confirm manual playback clears the exhausted recovery state and the card error after confirmed playback.
6. Trigger credential rejection, network failure, decode/output failure, and an unknown failure. Confirm only credential-related failures open Settings.
7. Verify repeated LibVLC warnings/errors are rate-limited while the latest error remains available for classification.
8. Repeat with one camera and four cameras while checking Windows Application, .NET Runtime, Windows Error Reporting, and relevant graphics-driver events. Record whether Direct3D11 errors or LiveKernel events recur.

## Minimum acceptance suite for future changes

- Verify from the repository directory that `dotnet --version` reports exactly `10.0.400`; stop if the pinned SDK is unavailable.
- Build the affected project with the repository FAST-BUILD command.
- Run all available automated tests.
- Verify the affected happy path and at least one failure path.
- Confirm settings are backward-compatible with existing JSON.
- Verify seven-day cache expiry, two-failure eviction, stable camera/playback-attempt handling, bounded playback confirmation timeout, RTSP-setting invalidation, discovery fallback, detection replacement while an old player emits late events, and one terminal-event recovery attempt.
- With one or more active streams and an active recording, enter both Sleep and Hibernate. Confirm Stop All runs before suspension, detected tiles and connection properties remain, recording is stopped, and automatic/user resume leaves every stream stopped.
- Confirm diagnostics contain no credentials, complete RTSP URLs, URL query secrets, or secret-bearing structured fields.
- Update requirement status and evidence links when behavior changes.

Toolchain guardrail: if the .NET SDK pin changes, verify `global.json`, `AGENTS.md`, README build instructions, NFR-009, the architecture baseline, and the decision record are updated together. Do not accept a build completed with a different SDK as evidence for the pinned-toolchain requirement.

## Definition of done for a requirement

A requirement is done when its wording is testable, implementation exists, the relevant automated or manual verification is recorded, failure behavior is defined, and traceability points to the owning code path.
