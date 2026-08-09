# LocalCam Software Requirements Specification

Status: Current implementation baseline

## Functional requirements

| ID | Requirement | Priority | Status | Verification |
|---|---|---|---|---|
| FR-001 | The application shall start as a single-window WPF desktop app. | Must | Implemented | Build and launch |
| FR-002 | The application shall load persisted settings from `%LocalAppData%\\LocalCam\\settings.json`. | Must | Implemented | Settings integration test |
| FR-003 | The application shall restore persisted window bounds when valid. | Should | Implemented | Manual UI check |
| FR-004 | The application shall discover compatible cameras using bounded, best-effort local-network probing. | Must | Implemented | Scanner tests and controlled-network test |
| FR-005 | The application shall expose retryable discovery and status feedback. | Must | Implemented | UI acceptance check |
| FR-006 | The application shall display a camera tile for each current detection. | Must | Implemented | UI acceptance check |
| FR-007 | The application shall build RTSP URLs from credentials, detected host, port `554`, and normalized stream path. | Must | Implemented | Unit tests |
| FR-008 | Invalid or missing RTSP configuration shall open Settings and show `RTSP credentials are missing or invalid.`. | Must | Implemented | UI acceptance check |
| FR-009 | The application shall support per-camera Play/Stop and global Start All/Stop All actions. | Must | Implemented | UI and stream integration checks |
| FR-010 | The application shall clean up stream and LibVLC resources on stop and close. | Must | Implemented | Lifecycle test/manual check |
| FR-011 | The application shall capture snapshots only from active streams and use unique filenames. | Must | Implemented | Snapshot test |
| FR-012 | The application shall support one manual recording session across all cards. | Must | Implemented | Recording state tests |
| FR-013 | Starting recording on another card shall stop the current recording before switching. | Must | Implemented | Recording integration test |
| FR-014 | Recordings shall use `.ts` output and roll over at 60 minutes while playback remains active. | Must | Implemented | Timer/recorder test |
| FR-015 | Recorder stop, end, or error shall clear recording UI state and report activity. | Must | Implemented | Failure-path test |
| FR-016 | Settings shall support RTSP credentials, stream path, auto-detection, auto-streaming, snapshot folder, and recording folder. | Must | Implemented | Settings UI test |
| FR-017 | The application shall persist selected non-default save folders and use default Pictures/Videos LocalCam folders when unset. | Must | Implemented | Persistence test |
| FR-018 | The application shall write structured diagnostics for startup, discovery, settings, streaming, snapshots, recording, entitlement, and updates. | Should | Implemented | Log schema check |
| FR-019 | Packaged builds shall support Store entitlement, Premium purchase, and update flows according to the existing policy documents. | Should | Implemented/packaged-only | Package validation |

## Non-functional requirements

| ID | Requirement | Priority | Status | Verification |
|---|---|---|---|---|
| NFR-001 | The supported runtime and package architecture shall remain x64-only. | Must | Implemented | Project/package inspection |
| NFR-002 | Discovery shall use bounded concurrency and timeouts so a scan remains cancellable. | Must | Implemented | Code review and timeout test |
| NFR-003 | User-facing discovery text shall remain brand-neutral. | Must | Implemented | Text audit |
| NFR-004 | User-visible controls shall follow the documented visibility, enablement, and keyboard-accessibility rules. | Must | Implemented | UI acceptance matrix |
| NFR-005 | Video overlays shall be hosted inside the VideoView content and remain attached during resize and active playback. | Must | Implemented/needs regression evidence | Live UI check |
| NFR-006 | Failures in critical workflows shall be visible to users and not silently swallowed. | Must | Partial | Failure-path review |
| NFR-007 | Settings and diagnostics shall remain local to the device unless future scope explicitly adds remote services. | Must | Implemented | Code/dependency review |
| NFR-008 | Critical behaviors shall have automated tests or a documented manual verification path. | Must | Partial | Traceability review |

## Constraints and non-goals

See [05 Decisions and Constraints](05-DECISIONS-AND-CONSTRAINTS.md). Requirements for manual camera entry, arbitrary RTSP URLs/ports, universal camera support, and architecture generalization are not current requirements.
