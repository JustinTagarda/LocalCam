using LocalCam.Models;
using Windows.Services.Store;

namespace LocalCam.Services {
    internal sealed class PremiumEntitlementService : IPremiumEntitlementService {
        private readonly IStoreContextProvider _storeContextProvider;
        private readonly LocalCamSettings _settings;
        private readonly Func<IntPtr> _ownerWindowHandleProvider;
        private readonly HashSet<string> _recognizedPremiumAddOnStoreIds;

        public PremiumEntitlementService(
            IStoreContextProvider storeContextProvider,
            LocalCamSettings settings,
            Func<IntPtr> ownerWindowHandleProvider,
            IEnumerable<string> recognizedPremiumAddOnStoreIds) {
            _storeContextProvider = storeContextProvider;
            _settings = settings;
            _ownerWindowHandleProvider = ownerWindowHandleProvider;
            _recognizedPremiumAddOnStoreIds = NormalizeStoreIds(recognizedPremiumAddOnStoreIds);
        }

        public async Task<PremiumEntitlementResult> CheckPremiumEntitlementAsync(CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();

            if (_recognizedPremiumAddOnStoreIds.Count == 0) {
                return ResolveFallback("Premium add-on Store IDs not configured.");
            }

            var storeContext = _storeContextProvider.TryGetStoreContext(_ownerWindowHandleProvider());
            if (storeContext is null) {
                return ResolveFallback("Microsoft Store entitlement is unavailable in this environment.");
            }

            try {
                var license = await storeContext.GetAppLicenseAsync();
                cancellationToken.ThrowIfCancellationRequested();

                var owned = license.AddOnLicenses.Any(entry =>
                    IsRecognizedPremiumStoreId(entry.Key) &&
                    entry.Value is not null &&
                    entry.Value.IsActive);

                if (!owned) {
                    owned = await IsPremiumInUserCollectionAsync(storeContext, cancellationToken);
                }

                if (owned) {
                    _settings.HasVerifiedPremiumEntitlementCache = true;
                    _settings.VerifiedPremiumEntitlementOwned = true;
                    _settings.VerifiedPremiumEntitlementCheckedUtc = DateTimeOffset.UtcNow;
                    SettingsStore.Save(_settings);
                    return new PremiumEntitlementResult(true, true, false, "Premium entitlement verified from Microsoft Store.");
                }

                _settings.HasVerifiedPremiumEntitlementCache = false;
                _settings.VerifiedPremiumEntitlementOwned = false;
                _settings.VerifiedPremiumEntitlementCheckedUtc = DateTimeOffset.UtcNow;
                SettingsStore.Save(_settings);
                return new PremiumEntitlementResult(false, true, false, "Premium entitlement not owned.");
            }
            catch (Exception) {
                return ResolveFallback("Store entitlement check failed.");
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
                product.IsInUserCollection &&
                IsRecognizedPremiumStoreId(product.StoreId));
        }

        internal bool IsRecognizedPremiumStoreId(string? storeId) {
            return !string.IsNullOrWhiteSpace(storeId) &&
                   _recognizedPremiumAddOnStoreIds.Contains(storeId.Trim());
        }

        internal static HashSet<string> NormalizeStoreIds(IEnumerable<string>? storeIds) {
            return storeIds?
                .Where(storeId => !string.IsNullOrWhiteSpace(storeId))
                .Select(storeId => storeId.Trim())
                .ToHashSet(StringComparer.OrdinalIgnoreCase)
                ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        private PremiumEntitlementResult ResolveFallback(string reason) {
            if (_settings.HasVerifiedPremiumEntitlementCache && _settings.VerifiedPremiumEntitlementOwned) {
                return new PremiumEntitlementResult(true, false, true, $"{reason} Using previously verified Premium cache.");
            }

            return new PremiumEntitlementResult(false, false, false, reason);
        }
    }
}
