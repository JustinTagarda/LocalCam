# LocalCam Development Requirements Documentation

Status: Baseline derived from the implemented repository
Date: 2026-08-09

## Purpose

This directory is the maintained requirements and design baseline for LocalCam. It documents what the current implementation does, how it is verified, and what future work is recommended.

## Document map

| Document | Use |
|---|---|
| [01 Baseline PRD](01-BASELINE-PRD.md) | Product intent, users, workflows, scope, and outcomes |
| [02 SRS](02-SOFTWARE-REQUIREMENTS-SPECIFICATION.md) | Testable functional and quality requirements |
| [03 Architecture baseline](03-ARCHITECTURE-AND-DESIGN-BASELINE.md) | Current structure, runtime flows, deployment, and risks |
| [04 Traceability and verification](04-TRACEABILITY-AND-VERIFICATION-PLAN.md) | Requirement-to-code evidence and test strategy |
| [05 Decisions and constraints](05-DECISIONS-AND-CONSTRAINTS.md) | Durable design decisions and repository rules |
| [06 Future roadmap](06-FUTURE-RECOMMENDATIONS-AND-ROADMAP.md) | Recommended next goals and sequencing |

## Authority and maintenance

- The running code is the source of truth for current behavior.
- `README.md` and `SPECIFICATION.md` remain useful summaries; these documents add structure and traceability rather than replacing them.
- A requirement is current only when its status and code/test evidence agree.
- New behavior should update the PRD, SRS, traceability, and relevant architecture/decision documents in the same change.
- Unknown behavior is recorded as `Not found` or `Unverified`; it must not be presented as implemented.

## Requirement notation

- `BR-*`: business/product requirement
- `FR-*`: functional requirement
- `NFR-*`: non-functional requirement
- `DR-*`: design or deployment constraint
- Priority: `Must`, `Should`, or `Could`
- Status: `Implemented`, `Partial`, `Planned`, or `Unverified`

## External basis

This structure is informed by ISO/IEC/IEEE 29148:2018 requirements-engineering information items, the official C4 model for retrospective architecture documentation, and lightweight Agile PRD practice. See the sources in [06 Future Recommendations](06-FUTURE-RECOMMENDATIONS-AND-ROADMAP.md).
