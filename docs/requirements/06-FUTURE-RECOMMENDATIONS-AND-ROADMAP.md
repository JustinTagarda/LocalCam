# LocalCam Future Recommendations and Roadmap

The following are recommendations, not current requirements. Priorities should be revalidated before implementation.

## P0: Establish a testable core

Create test source files in `LocalCam.Tests` and extract or isolate pure logic for settings, RTSP URL construction, discovery display mapping, folder resolution, and recording state. This is the highest-leverage improvement because current critical behavior has little automated evidence.

## P0: Protect credentials and diagnostics

Add explicit redaction tests and review every log path to ensure passwords, credentials, and complete RTSP URLs never enter JSONL diagnostics. Consider Windows-protected storage for credentials only after defining migration and recovery behavior.

## P1: Reduce MainWindow coupling

Introduce small application services around discovery orchestration, playback lifecycle, snapshot/recording output, and Store integration while preserving current UI behavior. Do this incrementally behind existing seams; avoid a broad rewrite.

## P1: Improve discovery observability

Add a user-initiated diagnostics export or copy action, scan duration, interface summary, and reason codes that help support failures without exposing sensitive data. Keep internal Tapo-specific diagnostics technically accurate.

## P1: Define measurable quality targets

Set targets for scan completion time, cancellation responsiveness, time to first frame, recovery after stream failure, snapshot/recording success, and crash-free sessions. Store targets in release checklists and verify them on representative networks.

## P2: Expand compatibility deliberately

Before adding manual camera entry or custom RTSP URLs, define a compatibility model: supported protocols, authentication expectations, port behavior, and user-facing limits. Add controlled fixtures for ONVIF, SSDP, mDNS, and RTSP variations.

## P2: Add release automation

Automate FAST-BUILD, tests, x64 package validation, static text audits for brand-neutral UI, and documentation/requirement traceability checks. Keep Store submission workflows separate from routine Debug validation.

## P2: Improve operational resilience

Add settings schema versioning and migration tests, safe recovery for malformed JSON, output-folder preflight checks, and clear handling for camera disappearance during playback.

## Suggested sequencing

1. Add pure-logic tests and log-redaction tests.
2. Add playback/recording state-machine tests.
3. Add deterministic discovery fakes and controlled integration checks.
4. Add small service seams around `MainWindow` responsibilities.
5. Add diagnostics export and release automation.
6. Reassess compatibility expansion using measured failure data.

## Research basis

- [ISO/IEC/IEEE 29148:2018](https://www.iso.org/standard/72089.html) defines requirements-engineering processes and required information items.
- [IEEE overview of requirements engineering](https://standards.ieee.org/ieee/802.1Q/6937/) describes requirement characteristics and traceability.
- [Official C4 model](https://c4model.com/) recommends hierarchical architecture views and explicitly supports retrospective documentation of existing codebases.
- [C4 tooling guidance](https://c4model.com/tooling) discusses keeping long-lived architecture documentation close to the source and choosing lightweight, diffable formats.
- [Atlassian PRD guidance](https://www.atlassian.com/agile/product-management/requirements/) emphasizes purpose, goals, user needs, acceptance criteria, assumptions, and scope boundaries for Agile requirements.
