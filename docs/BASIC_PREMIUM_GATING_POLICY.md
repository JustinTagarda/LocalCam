# Basic/Premium Gating Policy (Restoration Source)

## Purpose
This document is the repository restoration policy for LocalCam Basic/Premium gating behavior.
If future changes unintentionally alter gating behavior, restore implementation to match this policy.

## Change Control
- Do not change this policy without explicit product decision.
- Any change touching stream start, recording, entitlement, or purchase routing must be validated against this policy.

## Scope
This policy defines feature access behavior for Basic and Premium modes.

## Entitlement Source of Truth
- Premium ownership is determined by Microsoft Store durable add-on entitlement.
- Recognized Premium durable add-on Store IDs:
  - Legacy: `9P9KCJ3NFZFT` (`localcam_premium_lifetime`).
  - Active: `9P18G2P91QV6` (`localcam_premium_lifetime_2`).
- Ownership of either recognized add-on grants Premium access, including ownership obtained through a redeemed Microsoft Store promotional code.
- All new in-app Premium purchases must target only active add-on Store ID `9P18G2P91QV6`.
- Premium unlock must not come from editable local flags.

## Mode Definitions
- Premium: full access to all currently available app features without gating.
- Basic: access with specific limits defined below.

## Basic Limits
- Detection/discovery: unlimited.
- Active live streams: maximum 2 concurrent streams.
- Recording: allowed, but limited to 30 minutes total per local day.
- All other currently available features remain usable.

## Premium Access
- No stream-count or recording-duration gating.
- All currently available app features remain fully accessible.

## Development Mode Exception (Unpackaged / Non-Store Run)
When LocalCam runs as a local development build (for example, launched directly from Debug executable output and not Store-installed/package-identity runtime):
- Do not surface Basic/Premium gating UX.
- Keep `Basic/Premium` status text hidden/collapsed/clipped.
- Keep `Upgrade` button hidden/collapsed/clipped.
- Do not trigger Basic/Premium upsell prompts from this development-mode path.

Scope and non-override:
- This exception applies only to unpackaged/non-Store development runs.
- Packaged Store-installed behavior remains governed by Store entitlement verification and the existing Basic/Premium rules in this document.

## Blocked Action UX
When a Basic limit blocks an action:
- Show a modal dialog explaining what was blocked and why.
- Dialog includes an `Upgrade` button.
- `Upgrade` must use the existing shared in-app purchase route (`RequestPurchaseAsync`), not a direct Store PDP as primary path.

## Stream Limit Enforcement
Basic 2-stream cap must be enforced for:
- toolbar Start All
- per-card Play
- auto-start flow (if it attempts additional starts)

Behavior:
- If active stream count is already 2, block further starts and show the gating dialog.
- Do not auto-stop existing streams to make room.

## Recording Limit Enforcement
Basic 30-minute/day cap must be enforced for:
- recording start requests
- active recording duration rollover to daily limit

Behavior:
- If daily remaining recording time is 0, block start and show the gating dialog.
- If recording is active and remaining time is consumed, stop recording and show the gating dialog.
- Daily usage resets on local-day rollover.

## Persistence Requirements
- Persist Basic recording usage in settings.
- Persist local-day key with usage.
- On day change, usage resets for the new local day.

## Logging Requirements
- Blocked actions should be diagnosable in logs.
- Do not introduce noisy logs during normal interaction.

## Acceptance Criteria
- Basic cannot exceed 2 active streams.
- Basic cannot exceed 30 minutes total recording per local day.
- Premium has no gating for these limits.
- Every Basic-gated block path shows the upgrade dialog.
- Upgrade dialog routes through shared in-app purchase path targeting active add-on Store ID `9P18G2P91QV6`.
- Ownership of either the legacy or active durable add-on grants Premium access.
- App remains stable and builds via required FAST build.

## Implementation Touchpoints (Current)
- `MainWindow.xaml.cs`: stream-start gating, recording gating, upgrade-block dialog routing.
- `Models/LocalCamSettings.cs`: Basic recording daily usage persistence fields.
- `BasicFeatureGateDialog.xaml` and `BasicFeatureGateDialog.xaml.cs`: blocked-action dialog.
- `Services/PremiumEntitlementService.cs`: entitlement resolution.
- `Services/PremiumPurchaseService.cs`: in-app purchase path.

## Restoration Procedure
If regressions occur, restore in this order:
1. Entitlement source: confirm both recognized add-on Store IDs and entitlement check behavior.
2. Purchase target: confirm all new purchases target only active add-on Store ID `9P18G2P91QV6`.
3. Stream gating: re-apply 2-stream Basic cap to all stream-start paths.
4. Recording gating: re-apply 30-minute/day Basic cap and active-session stop-at-limit behavior.
5. Blocked dialog: re-apply modal dialog with Upgrade button using shared purchase route.
6. Persistence: confirm daily usage storage/reset behavior.
7. Validation: execute checklist in `docs/BASIC_PREMIUM_GATING_TEST_CHECKLIST.md`.
