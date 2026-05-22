using System.Security.Principal;
using LocalCam.Models;
using PurchaseResult = LocalCam.Models.StorePurchaseResult;
using Windows.Services.Store;

namespace LocalCam.Services.Store {
    internal sealed class StorePurchaseService : IStorePurchaseService {
        private const string Category = "store_entitlement";
        private readonly IStoreContextProvider _contextProvider;
        private readonly IStoreLicenseService _licenseService;
        private readonly IStoreNavigationService _navigationService;

        public StorePurchaseService(
            IStoreContextProvider contextProvider,
            IStoreLicenseService licenseService,
            IStoreNavigationService navigationService) {
            _contextProvider = contextProvider;
            _licenseService = licenseService;
            _navigationService = navigationService;
        }

        public async Task<PurchaseResult> RequestPremiumPurchaseAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            var snapshot = await _licenseService.EnsureReadyAsync(cancellationToken).ConfigureAwait(false);
            if (snapshot.IsPremium) {
                return new PurchaseResult(
                    StorePurchaseOutcome.AlreadyOwned,
                    snapshot,
                    "Premium is already unlocked.");
            }

            if (IsElevated()) {
                JsonLogStore.Warning("premium_purchase_blocked_elevated", "Premium purchase blocked because the app is running elevated.", Category);
                return new PurchaseResult(
                    StorePurchaseOutcome.Unavailable,
                    snapshot,
                    "Premium purchase unavailable in this build.");
            }

            var context = _contextProvider.GetContext(ownerWindowHandle);
            if (context is null) {
                var opened = await _navigationService.OpenPremiumPurchasePageAsync(cancellationToken).ConfigureAwait(false);
                if (opened) {
                    JsonLogStore.Information(
                        "premium_purchase_store_page_opened",
                        "Microsoft Store purchase page was opened for Premium.",
                        Category,
                        new Dictionary<string, object?> {
                            ["storeId"] = StoreProductConfiguration.PremiumStoreId,
                            ["productId"] = StoreProductConfiguration.PremiumProductId
                        });
                    return new PurchaseResult(
                        StorePurchaseOutcome.OpenedStorePage,
                        snapshot,
                        "Opening Microsoft Store.");
                }

                if (!opened) {
                    JsonLogStore.Warning("premium_purchase_unavailable", "Premium purchase unavailable because Store context and Store navigation are unavailable.", Category);
                }

                return new PurchaseResult(
                    StorePurchaseOutcome.Unavailable,
                    snapshot,
                    "Premium purchase unavailable in this build.");
            }

            try {
                JsonLogStore.Information(
                    "premium_purchase_requested",
                    "Premium durable add-on purchase flow requested.",
                    Category,
                    new Dictionary<string, object?> {
                        ["storeId"] = StoreProductConfiguration.PremiumStoreId,
                        ["productId"] = StoreProductConfiguration.PremiumProductId
                    });

                var result = await context.RequestPurchaseAsync(StoreProductConfiguration.PremiumStoreId);
                JsonLogStore.Information(
                    "premium_purchase_completed",
                    "Premium durable add-on purchase flow completed.",
                    Category,
                    new Dictionary<string, object?> {
                        ["status"] = result.Status.ToString(),
                        ["extendedError"] = result.ExtendedError?.Message
                    });

                var refreshed = await _licenseService.RefreshAsync(ownerWindowHandle, cancellationToken).ConfigureAwait(false);
                return refreshed.IsPremium
                    ? new PurchaseResult(
                        result.Status == StorePurchaseStatus.AlreadyPurchased
                            ? StorePurchaseOutcome.AlreadyOwned
                            : StorePurchaseOutcome.Purchased,
                        refreshed,
                        result.Status == StorePurchaseStatus.AlreadyPurchased
                            ? "Premium is already unlocked."
                            : "Premium unlocked. Continuous recording is now available.")
                    : result.Status switch {
                        StorePurchaseStatus.NotPurchased => new PurchaseResult(
                            StorePurchaseOutcome.Cancelled,
                            refreshed,
                            "Premium purchase was not completed."),
                        StorePurchaseStatus.NetworkError or StorePurchaseStatus.ServerError => new PurchaseResult(
                            StorePurchaseOutcome.Failed,
                            refreshed,
                            "Premium purchase failed."),
                        StorePurchaseStatus.Succeeded or StorePurchaseStatus.AlreadyPurchased => new PurchaseResult(
                            StorePurchaseOutcome.Failed,
                            refreshed,
                            "Premium purchase could not be verified yet."),
                        _ => new PurchaseResult(
                            StorePurchaseOutcome.Failed,
                            refreshed,
                            "Premium purchase failed.")
                    };
            }
            catch (OperationCanceledException) {
                throw;
            }
            catch (Exception ex) {
                JsonLogStore.Error("premium_purchase_failed", "Premium purchase flow failed.", Category, ex);
                var refreshed = await _licenseService.RefreshAsync(ownerWindowHandle, cancellationToken).ConfigureAwait(false);
                return new PurchaseResult(
                    StorePurchaseOutcome.Failed,
                    refreshed,
                    "Premium purchase failed.");
            }
        }

        public Task<StoreEntitlementSnapshot> RestorePremiumPurchaseAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            return _licenseService.RefreshAsync(ownerWindowHandle, cancellationToken);
        }

        public async Task<StoreRedemptionResult> RedeemPromoCodeAsync(string promoCode, IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            var snapshot = await _licenseService.EnsureReadyAsync(cancellationToken).ConfigureAwait(false);
            if (snapshot.IsPremium) {
                return new StoreRedemptionResult(
                    StoreRedemptionOutcome.Completed,
                    snapshot,
                    "Premium is already unlocked.");
            }

            if (string.IsNullOrWhiteSpace(promoCode)) {
                return new StoreRedemptionResult(
                    StoreRedemptionOutcome.InvalidCode,
                    snapshot,
                    "Enter a valid Premium promo code.");
            }

            if (IsElevated()) {
                JsonLogStore.Warning("premium_redeem_blocked_elevated", "Premium promo-code redemption blocked because the app is running elevated.", Category);
                return new StoreRedemptionResult(
                    StoreRedemptionOutcome.Unavailable,
                    snapshot,
                    "Premium promo-code redemption unavailable in this build.");
            }

            var opened = await _navigationService.OpenPromotionalCodeRedeemUrlAsync(promoCode, cancellationToken).ConfigureAwait(false);
            if (!opened) {
                JsonLogStore.Warning("premium_redeem_store_unavailable", "Microsoft Store redeem URL could not be opened for Premium promo-code redemption.", Category);
                return new StoreRedemptionResult(
                    StoreRedemptionOutcome.Failed,
                    snapshot,
                    "Premium promo-code redemption unavailable in this build.");
            }

            JsonLogStore.Information(
                "premium_redeem_store_opened",
                "Microsoft Store redeem URL was opened to support Premium promo-code redemption.",
                Category,
                new Dictionary<string, object?> {
                    ["storeId"] = StoreProductConfiguration.PremiumStoreId,
                    ["productId"] = StoreProductConfiguration.PremiumProductId,
                    ["promoCodeLength"] = promoCode.Length
                });

            var refreshed = await _licenseService.RefreshAsync(ownerWindowHandle, cancellationToken).ConfigureAwait(false);
            return new StoreRedemptionResult(
                refreshed.IsPremium ? StoreRedemptionOutcome.Completed : StoreRedemptionOutcome.OpenedRedeemPage,
                refreshed,
                refreshed.IsPremium
                    ? "Premium unlocked."
                    : "Redeem the Premium promo code in Microsoft Store, then restore purchases.");
        }

        private static bool IsElevated() {
            try {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch {
                return false;
            }
        }
    }
}
