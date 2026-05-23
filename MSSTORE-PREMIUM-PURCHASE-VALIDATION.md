# Microsoft Store Premium Purchase Validation Runbook

This runbook verifies the LocalCam Premium purchase path end-to-end against the in-repo implementation and Microsoft Store production behavior.

## 1) Code and test verification (local)

From `D:\Projects\LocalCam`:

```powershell
dotnet test .\LocalCam.Tests\LocalCam.Tests.csproj -c Debug
```

Expected coverage from these tests:
- Premium Upgrade CTA calls `IStorePurchaseService.RequestPremiumPurchaseAsync`.
- Restore action refreshes entitlement only.
- Update check action is separate from Premium purchase.
- Not-supported and blocked purchase outcomes do not route to Premium PDP navigation fallback.

## 2) Store package build (FULL-BUILD, required for Store validation)

Store validation requires packaged identity and must use packaging build paths.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Build-StorePackage.ps1 -Configuration Release -Platform x64
```

Confirm artifacts exist:
- `AppPackages\LocalCam.Package_<version>_x64.msixupload`
- `AppPackages\LocalCam.Package_<version>_x64_Test\LocalCam.Package_<version>_x64.msix`

## 3) Production Store-installed validation

Run these checks on a Microsoft Store-installed build (not unpackaged local debug executable):

1. Sign in with an account that does not own Premium.
2. Trigger every Premium CTA:
   - Footer/tier upgrade action.
   - Basic recording-limit upgrade modal CTA.
3. Confirm each CTA opens in-app purchase UI via `RequestPurchaseAsync`.
4. Cancel purchase and verify user sees cancellation message.
5. Complete purchase and verify entitlement refresh unlocks Premium.
6. Restart app and verify Premium remains unlocked via Store entitlement.
7. Run app as administrator; verify purchase is blocked with clear message.
8. Disable network; verify clear network/server failure messaging.
9. Confirm no Premium CTA opens `ms-windows-store://pdp/?productid=...` for purchase.

## 4) Partner Center cross-check

Before blaming app code, verify:
- Premium add-on Store ID in code matches published add-on.
- Add-on is in same app identity/package family.
- Add-on is published, available in target market, and audience allows test account.
- Availability schedule is active.

## 5) Evidence to capture

Capture screenshots/log snippets for:
- In-app purchase UI open.
- Cancel outcome.
- Success outcome + entitlement verified owned.
- Elevated blocked outcome.
- Network/server failure outcome.
- Confirmation that no Premium CTA uses PDP purchase navigation.
