using LocalCam.Models;
using Windows.Services.Store;

namespace LocalCam.Services {
    internal sealed class PremiumEntitlementService : IPremiumEntitlementService {
        private readonly IStoreContextProvider _storeContextProvider;
        private readonly Func<LocalCamSettings> _settingsProvider;
        private readonly Action<Action<LocalCamSettings>> _updateSettings;
        private readonly Func<IntPtr> _ownerWindowHandleProvider;
        private readonly string _premiumAddOnStoreId;
        private readonly string? _premiumAddOnOfferToken;

        public PremiumEntitlementService(
            IStoreContextProvider storeContextProvider,
            Func<LocalCamSettings> settingsProvider,
            Action<Action<LocalCamSettings>> updateSettings,
            Func<IntPtr> ownerWindowHandleProvider,
            string premiumAddOnStoreId,
            string? premiumAddOnOfferToken = null) {
            _storeContextProvider = storeContextProvider;
            _settingsProvider = settingsProvider;
            _updateSettings = updateSettings;
            _ownerWindowHandleProvider = ownerWindowHandleProvider;
            _premiumAddOnStoreId = premiumAddOnStoreId.Trim();
            _premiumAddOnOfferToken = premiumAddOnOfferToken?.Trim();
        }

        public async Task<PremiumEntitlementResult> CheckPremiumEntitlementAsync(CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            var settings = _settingsProvider();

            if (string.IsNullOrWhiteSpace(_premiumAddOnStoreId)) {
                return ResolveFallback(settings, "Premium add-on Store ID not configured.");
            }

            var storeContext = _storeContextProvider.TryGetStoreContext(_ownerWindowHandleProvider());
            if (storeContext is null) {
                JsonLogStore.Warning(
                    eventName: "premium_entitlement_storecontext_unavailable",
                    message: "Premium entitlement check could not obtain StoreContext.",
                    category: "store",
                    data: new Dictionary<string, object?> {
                        ["premiumAddOnStoreId"] = _premiumAddOnStoreId,
                        ["hasPackageIdentity"] = _storeContextProvider.HasPackageIdentity
                    });
                return ResolveFallback(settings, "Microsoft Store entitlement is unavailable in this environment.");
            }

            try {
                var license = await storeContext.GetAppLicenseAsync();
                cancellationToken.ThrowIfCancellationRequested();

                var owned = license.AddOnLicenses.Values.Any(addOnLicense =>
                    addOnLicense is not null &&
                    PremiumEntitlementRules.MatchesPremiumLicense(
                        _premiumAddOnStoreId,
                        _premiumAddOnOfferToken,
                        addOnLicense.SkuStoreId,
                        addOnLicense.InAppOfferToken,
                        addOnLicense.IsActive));

                if (!owned) {
                    owned = await IsPremiumInUserCollectionAsync(storeContext, cancellationToken);
                }

                if (owned) {
                    _updateSettings(current => {
                        current.HasVerifiedPremiumEntitlementCache = true;
                        current.VerifiedPremiumEntitlementOwned = true;
                        current.VerifiedPremiumEntitlementCheckedUtc = DateTimeOffset.UtcNow;
                    });
                    return new PremiumEntitlementResult(true, true, false, "Premium entitlement verified from Microsoft Store.");
                }

                _updateSettings(current => {
                    current.HasVerifiedPremiumEntitlementCache = false;
                    current.VerifiedPremiumEntitlementOwned = false;
                    current.VerifiedPremiumEntitlementCheckedUtc = DateTimeOffset.UtcNow;
                });
                return new PremiumEntitlementResult(false, true, false, "Premium entitlement not owned.");
            }
            catch (Exception ex) {
                JsonLogStore.Error(
                    eventName: "premium_entitlement_check_failed",
                    message: "Premium entitlement check failed and fell back to cache or unavailable state.",
                    category: "store",
                    exception: ex,
                    data: new Dictionary<string, object?> {
                        ["premiumAddOnStoreId"] = _premiumAddOnStoreId,
                        ["hasFallbackCache"] = settings.HasVerifiedPremiumEntitlementCache,
                        ["fallbackCacheOwned"] = settings.VerifiedPremiumEntitlementOwned
                    });
                return ResolveFallback(settings, "Store entitlement check failed.");
            }
        }

        private async Task<bool> IsPremiumInUserCollectionAsync(
            StoreContext storeContext,
            CancellationToken cancellationToken) {
            var collectionResult = await storeContext.GetUserCollectionAsync(["Durable"]);
            cancellationToken.ThrowIfCancellationRequested();

            if (collectionResult.ExtendedError is not null) {
                throw collectionResult.ExtendedError;
            }

            return collectionResult.Products.Values.Any(product =>
                product is not null &&
                PremiumEntitlementRules.MatchesPremiumCollectionProduct(
                    _premiumAddOnStoreId,
                    product.StoreId,
                    product.IsInUserCollection));
        }

        private static PremiumEntitlementResult ResolveFallback(LocalCamSettings settings, string reason) {
            if (settings.HasVerifiedPremiumEntitlementCache && settings.VerifiedPremiumEntitlementOwned) {
                return new PremiumEntitlementResult(true, false, true, $"{reason} Using previously verified Premium cache.");
            }

            return new PremiumEntitlementResult(false, false, false, reason);
        }
    }
}
