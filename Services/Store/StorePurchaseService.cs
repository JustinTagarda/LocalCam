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
        private readonly Func<bool> _isElevatedProbe;

        public StorePurchaseService(
            IStoreContextProvider contextProvider,
            IStoreLicenseService licenseService,
            IStoreNavigationService navigationService,
            Func<bool>? isElevatedProbe = null) {
            _contextProvider = contextProvider;
            _licenseService = licenseService;
            _navigationService = navigationService;
            _isElevatedProbe = isElevatedProbe ?? IsElevated;
        }

        public async Task<PurchaseResult> RequestPremiumPurchaseAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            var snapshot = await _licenseService.EnsureReadyAsync(cancellationToken).ConfigureAwait(false);
            var isElevated = _isElevatedProbe();
            JsonLogStore.Information(
                "premium_purchase_attempt_started",
                "Premium purchase attempt started.",
                Category,
                new Dictionary<string, object?> {
                    ["isPackagedBuild"] = _contextProvider.IsStoreSupported,
                    ["isElevated"] = isElevated,
                    ["storeId"] = StoreProductConfiguration.PremiumStoreId,
                    ["productId"] = StoreProductConfiguration.PremiumProductId
                });

            if (snapshot.IsPremium) {
                return new PurchaseResult(
                    StorePurchaseOutcome.AlreadyOwned,
                    snapshot,
                    "Premium is already unlocked.");
            }

            if (isElevated) {
                JsonLogStore.Warning("premium_purchase_blocked_elevated", "Premium purchase blocked because the app is running elevated.", Category);
                return new PurchaseResult(
                    StorePurchaseOutcome.Blocked,
                    snapshot,
                    "Close the app and reopen it normally. Microsoft Store purchase is unavailable while running as administrator.");
            }

            var context = _contextProvider.GetContext(ownerWindowHandle);
            if (context is null) {
                JsonLogStore.Warning("premium_purchase_not_supported", "Premium purchase unavailable because Store context is unavailable.", Category);
                return new PurchaseResult(
                    StorePurchaseOutcome.NotSupported,
                    snapshot,
                    "Premium purchase is available only in the Microsoft Store version.");
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
                            : StorePurchaseOutcome.Succeeded,
                        refreshed,
                        result.Status == StorePurchaseStatus.AlreadyPurchased
                            ? "Premium is already unlocked."
                            : "Premium unlocked. Continuous recording is now available.")
                    : result.Status switch {
                        StorePurchaseStatus.NotPurchased => new PurchaseResult(
                            StorePurchaseOutcome.Cancelled,
                            refreshed,
                            "Premium purchase canceled."),
                        StorePurchaseStatus.NetworkError => new PurchaseResult(
                            StorePurchaseOutcome.NetworkError,
                            refreshed,
                            "Premium purchase failed due to a network error. Check your connection and try again."),
                        StorePurchaseStatus.ServerError => new PurchaseResult(
                            StorePurchaseOutcome.ServerError,
                            refreshed,
                            "Microsoft Store could not complete the purchase right now. Try again later."),
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
