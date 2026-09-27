# LocalCam Development Requirements Documentation

Status: Baseline derived from the implemented repository
Date: 2026-09-27

## Purpose

This directory is the maintained requirements and design baseline for LocalCam. It documents what the current implementation does, how it is verified, and what future work is recommended.

The current repository toolchain baseline is .NET SDK `10.0.400`, pinned by `global.json` with roll-forward disabled.

## Document map

| Document | Use |
|---|---|
| [01 Baseline PRD](01-BASELINE-PRD.md) | Product intent, users, workflows, scope, and outcomes |
| [02 SRS](02-SOFTWARE-REQUIREMENTS-SPECIFICATION.md) | Testable functional and quality requirements |
| [03 Architecture baseline](03-ARCHITECTURE-AND-DESIGN-BASELINE.md) | Current structure, runtime flows, deployment, and risks |
| [04 Traceability and verification](04-TRACEABILITY-AND-VERIFICATION-PLAN.md) | Requirement-to-code evidence and test strategy |
| [05 Decisions and constraints](05-DECISIONS-AND-CONSTRAINTS.md) | Durable design decisions and repository rules |
| [06 Future roadmap](06-FUTURE-RECOMMENDATIONS-AND-ROADMAP.md) | Recommended next goals and sequencing |
| [07 UI design requirements](07-UI-DESIGN-REQUIREMENTS.md) | Shared button baseline and scoped camera-area sizing rules |
| [08 Runtime pipelines and change guardrails](08-RUNTIME-PIPELINES-AND-CHANGE-GUARDRAILS.md) | Verified code ownership, end-to-end flows, persistence/network routes, protected invariants, known discrepancies, and change-control checks |
| [Store submission guide](../STORE-SUBMISSION-GUIDE.md) | Operational Store package creation, validation, submission, and flight evidence |

## Authority and maintenance

- The running code is the source of truth for current behavior.
- `README.md` and `SPECIFICATION.md` remain useful summaries; these documents add structure and traceability rather than replacing them.
- `docs/STORE-SUBMISSION-GUIDE.md` is the operational source of truth for Store packaging and submission; it does not replace the SRS or verification requirements.
- A requirement is current only when its status and code/test evidence agree.
- The runtime-pipeline guardrail document maps current routes and invariants; the source code remains the authority when a mismatch is found, and the mismatch must be recorded rather than silently normalized.
- New behavior should update the PRD, SRS, traceability, and relevant architecture/decision documents in the same change.
- Unknown behavior is recorded as `Not found` or `Unverified`; it must not be presented as implemented.
- Toolchain requirements are authoritative: `global.json`, `AGENTS.md`, and the requirements documents must agree on the pinned .NET SDK version. A toolchain change must update all three sources and its verification evidence in the same change.

## Requirement notation

- `BR-*`: business/product requirement
- `FR-*`: functional requirement
- `NFR-*`: non-functional requirement
- `DR-*`: design or deployment constraint
- Priority: `Must`, `Should`, or `Could`
- Status: `Implemented`, `Partial`, `Planned`, or `Unverified`

## External basis

This structure is informed by ISO/IEC/IEEE 29148:2018 requirements-engineering information items, the official C4 model for retrospective architecture documentation, and lightweight Agile PRD practice. See the sources in [06 Future Recommendations](06-FUTURE-RECOMMENDATIONS-AND-ROADMAP.md).
