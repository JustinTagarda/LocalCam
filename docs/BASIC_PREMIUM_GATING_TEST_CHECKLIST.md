# Basic/Premium Gating Test Checklist

Use this checklist whenever stream/recording/entitlement/purchase code is changed.

## Preconditions
- Build configuration can run app locally.
- Ability to test these states:
  - Basic (no owned Premium entitlement)
  - Premium through legacy add-on `9P9KCJ3NFZFT`
  - Premium through active add-on `9P18G2P91QV6`
  - Development mode (unpackaged/non-Store run, such as Debug executable launch)

## Development Mode Checks (Unpackaged / Non-Store)
1. `Basic/Premium` status text remains hidden.
2. `Upgrade` button remains hidden.
3. Basic/Premium upsell prompts are not surfaced from development-mode gating UX paths.
4. Packaged-only entitlement/purchase UX is not required for development-mode visibility behavior.

## Basic Mode Checks
1. Detection/discovery has no imposed cap and still works as expected.
2. Start stream on camera 1 succeeds.
3. Start stream on camera 2 succeeds.
4. Attempt to start a 3rd concurrent stream is blocked.
5. Blocked action shows modal explanation dialog with `Upgrade` button.
6. Clicking `Upgrade` uses in-app purchase route targeting active add-on `9P18G2P91QV6`.
7. Recording can start while under daily remaining limit.
8. After total recording reaches 30 minutes for current local day, recording is blocked/stopped.
9. Daily recording-limit block shows modal explanation dialog with `Upgrade` button.
10. Non-gated features remain usable in Basic (settings, snapshots, detection controls, etc.).

## Premium Mode Checks
1. Purchased legacy add-on `9P9KCJ3NFZFT` grants Premium.
2. Redeemed promo code for legacy add-on `9P9KCJ3NFZFT` grants Premium.
3. Purchased active add-on `9P18G2P91QV6` grants Premium.
4. Redeemed promo code for active add-on `9P18G2P91QV6` grants Premium.
5. Returning to LocalCam after redeeming either promo code refreshes entitlement and grants Premium.
6. Active stream count is not capped at 2.
7. Recording is not capped at 30 minutes/day.
8. No Basic gating dialogs appear for stream/record actions.

## Purchase Routing
1. A Basic account that owns neither add-on sees `Upgrade`.
2. Every `Upgrade` entry point opens the Microsoft Store purchase UI for active add-on `9P18G2P91QV6`.
3. The Store purchase UI shows the active add-on's configured price.
4. No new purchase request targets legacy add-on `9P9KCJ3NFZFT`.

## Persistence and Day Rollover
1. Basic daily recording usage persists across app restart on same local day.
2. On local-day change, usage resets and recording allowance is available again.

## Stability and Build
1. App does not crash during blocked actions.
2. Build passes with required FAST build command:
   `MSBuild LocalCam.csproj /t:Build /p:Configuration=Debug /p:RunAnalyzers=false /m`

## Regression Outcome Rule
If any item fails, treat as gating regression and restore behavior using:
- `docs/BASIC_PREMIUM_GATING_POLICY.md`
