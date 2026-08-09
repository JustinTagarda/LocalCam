# LocalCam Decisions and Constraints

These records capture durable choices already reflected in the repository. New architectural choices should be added here as dated ADR-style entries.

## DEC-001: Windows WPF desktop application

Status: Accepted

LocalCam uses a single-window WPF UI on .NET 10 for Windows. This matches the current interaction model and LibVLCSharp.WPF integration.

## DEC-002: x64-only runtime and packaging

Status: Accepted

`LocalCam.csproj` and Store packaging are constrained to `win-x64`. ARM64, AnyCPU, and multi-architecture packaging are out of scope unless explicitly approved.

## DEC-003: Tapo-first discovery with brand-neutral UI

Status: Accepted

Internal scanner identifiers and heuristics may remain Tapo/TP-Link-specific. Normal user-facing wording and detection method labels remain generic and compatible-camera oriented.

## DEC-004: Best-effort local discovery

Status: Accepted

Discovery uses multiple bounded probes and confidence signals. It is not an authoritative inventory and must remain cancellable and retryable.

## DEC-005: Fixed RTSP construction boundary

Status: Accepted

The current stream contract uses detected host, port `554`, credentials, and normalized path with default `stream1`. Custom URL/port support is a future product decision, not an implicit refactor.

## DEC-006: One active recording session

Status: Accepted

Recording is manual, `.ts`, non-remuxed/non-transcoded, and limited to one active card with 60-minute rollover.

## DEC-007: Local-first persistence and diagnostics

Status: Accepted

Settings, media output, and diagnostics remain local. Any future cloud or remote service would require a separate privacy, security, and architecture decision.

## DEC-008: Existing code is the baseline

Status: Accepted

These documents describe the application as implemented. They do not retroactively claim requirements were designed before implementation, and any mismatch is recorded as a gap or recommendation.
