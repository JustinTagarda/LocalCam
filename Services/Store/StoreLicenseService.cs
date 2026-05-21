using LocalCam.Models;
using Windows.Services.Store;

namespace LocalCam.Services.Store {
    internal sealed class StoreLicenseService : IStoreLicenseService {
        private const string Category = "store_entitlement";
        private readonly IStoreContextProvider _contextProvider;
        private readonly IPremiumEntitlementCache _cache;
        private readonly object _syncRoot = new();
        private readonly TaskCompletionSource<StoreEntitlementSnapshot> _firstRefresh = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public StoreLicenseService(IStoreContextProvider contextProvider, IPremiumEntitlementCache cache) {
            _contextProvider = contextProvider;
            _cache = cache;
            Snapshot = new StoreEntitlementSnapshot(
                StoreEntitlementState.Unknown,
                IsPremium: false,
                IsPurchaseAvailable: false,
                "Premium license has not been checked.",
                MatchReason: null);
        }

        public event Action<StoreEntitlementSnapshot>? SnapshotChanged;

        public StoreEntitlementSnapshot Snapshot { get; private set; }

        public async Task StartAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            Publish(StoreEntitlementState.Checking, false, false, "Checking Premium license.", null);
            await RefreshAsync(ownerWindowHandle, cancellationToken).ConfigureAwait(false);
        }

        public async Task<StoreEntitlementSnapshot> EnsureReadyAsync(CancellationToken cancellationToken) {
            var snapshot = Snapshot;
            if (snapshot.State != StoreEntitlementState.Unknown && snapshot.State != StoreEntitlementState.Checking) {
                return snapshot;
            }

            using var registration = cancellationToken.Register(() => _firstRefresh.TrySetCanceled(cancellationToken));
            return await _firstRefresh.Task.ConfigureAwait(false);
        }

        public async Task<StoreEntitlementSnapshot> RefreshAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            var context = _contextProvider.GetContext(ownerWindowHandle);
            if (context is null) {
                return PublishFallback("Premium license verification is unavailable in this build.", "store_context_unavailable", null);
            }

            try {
                var result = await QueryEntitlementAsync(context, cancellationToken).ConfigureAwait(false);
                if (result.IsPremium) {
                    _cache.SaveVerifiedPremium();
                }
                else if (result.State == StoreEntitlementState.VerifiedNotOwned) {
                    _cache.Clear();
                }

                Publish(result.State, result.IsPremium, result.IsPurchaseAvailable, result.StatusMessage, result.MatchReason);
                return Snapshot;
            }
            catch (OperationCanceledException) {
                throw;
            }
            catch (Exception ex) {
                return PublishFallback("Unable to verify Premium license.", "store_query_failed", ex);
            }
        }

        private async Task<EntitlementQueryResult> QueryEntitlementAsync(StoreContext context, CancellationToken cancellationToken) {
            var licenseKeys = Array.Empty<string>();
            var licenseDetails = new List<IReadOnlyDictionary<string, object?>>();
            var collectionDetails = new List<IReadOnlyDictionary<string, object?>>();
            var associatedDetails = new List<IReadOnlyDictionary<string, object?>>();
            string? matchReason = null;
            var isPurchaseAvailable = false;

            var appLicense = await context.GetAppLicenseAsync();
            cancellationToken.ThrowIfCancellationRequested();

            licenseKeys = appLicense.AddOnLicenses.Keys.ToArray();
            foreach (var pair in appLicense.AddOnLicenses) {
                var license = pair.Value;
                licenseDetails.Add(new Dictionary<string, object?> {
                    ["key"] = pair.Key,
                    ["skuStoreId"] = license.SkuStoreId,
                    ["inAppOfferToken"] = license.InAppOfferToken,
                    ["isActive"] = license.IsActive
                });

                if (license.IsActive && IsMatchingLicense(pair.Key, license, out var reason)) {
                    matchReason ??= reason;
                }
            }

            StoreProductQueryResult? collection = await context.GetUserCollectionAsync(["Durable"]);
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var pair in collection.Products) {
                var product = pair.Value;
                collectionDetails.Add(BuildProductLogPayload(pair.Key, product));
                if (IsMatchingProduct(pair.Key, product, out var reason)) {
                    matchReason ??= reason;
                }
            }

            var associatedProducts = await context.GetAssociatedStoreProductsAsync(["Durable"]);
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var pair in associatedProducts.Products) {
                var product = pair.Value;
                associatedDetails.Add(BuildProductLogPayload(pair.Key, product));
                if (IsPremiumCatalogProduct(pair.Key, product)) {
                    isPurchaseAvailable = true;
                }

                if (product.IsInUserCollection && IsMatchingProduct(pair.Key, product, out var reason)) {
                    matchReason ??= reason;
                }
            }

            var isPremium = !string.IsNullOrWhiteSpace(matchReason);
            JsonLogStore.Information(
                "premium_entitlement_refreshed",
                "Premium durable add-on entitlement refresh completed.",
                Category,
                new Dictionary<string, object?> {
                    ["configuredStoreIds"] = new[] { StoreProductConfiguration.PremiumStoreId },
                    ["configuredProductIds"] = new[] { StoreProductConfiguration.PremiumProductId },
                    ["addOnLicenseKeys"] = licenseKeys,
                    ["licenses"] = licenseDetails.ToArray(),
                    ["userCollectionProducts"] = collectionDetails.ToArray(),
                    ["associatedProducts"] = associatedDetails.ToArray(),
                    ["finalMatchReason"] = matchReason,
                    ["isPurchaseAvailable"] = isPurchaseAvailable,
                    ["finalState"] = isPremium ? StoreEntitlementState.VerifiedOwned.ToString() : StoreEntitlementState.VerifiedNotOwned.ToString()
                });

            return new EntitlementQueryResult(
                isPremium ? StoreEntitlementState.VerifiedOwned : StoreEntitlementState.VerifiedNotOwned,
                isPremium,
                isPurchaseAvailable,
                isPremium ? "Premium license verified." : "Premium license was not found.",
                matchReason);
        }

        private StoreEntitlementSnapshot PublishFallback(string statusMessage, string reason, Exception? exception) {
            var allowCachedPremium = _cache.HasVerifiedPremium();
            if (exception is not null) {
                JsonLogStore.Error("premium_entitlement_failed", statusMessage, Category, exception, new Dictionary<string, object?> {
                    ["allowCachedPremium"] = allowCachedPremium,
                    ["reason"] = reason,
                    ["configuredStoreIds"] = new[] { StoreProductConfiguration.PremiumStoreId },
                    ["configuredProductIds"] = new[] { StoreProductConfiguration.PremiumProductId }
                });
            }
            else {
                JsonLogStore.Warning("premium_entitlement_unavailable", statusMessage, Category, new Dictionary<string, object?> {
                    ["allowCachedPremium"] = allowCachedPremium,
                    ["reason"] = reason
                });
            }

            Publish(
                StoreEntitlementState.VerificationFailed,
                allowCachedPremium,
                false,
                allowCachedPremium ? "Using verified Premium while Store is unavailable." : statusMessage,
                allowCachedPremium ? "protected_verified_owned_cache" : reason);
            return Snapshot;
        }

        private void Publish(StoreEntitlementState state, bool isPremium, bool isPurchaseAvailable, string statusMessage, string? matchReason) {
            var snapshot = new StoreEntitlementSnapshot(state, isPremium, isPurchaseAvailable, statusMessage, matchReason);
            lock (_syncRoot) {
                Snapshot = snapshot;
            }

            if (state != StoreEntitlementState.Unknown && state != StoreEntitlementState.Checking) {
                _firstRefresh.TrySetResult(snapshot);
            }

            JsonLogStore.Information(
                "premium_entitlement_state_changed",
                "Premium entitlement state changed.",
                Category,
                new Dictionary<string, object?> {
                    ["state"] = state.ToString(),
                    ["isPremium"] = isPremium,
                    ["isPurchaseAvailable"] = isPurchaseAvailable,
                    ["matchReason"] = matchReason
                });

            try {
                SnapshotChanged?.Invoke(snapshot);
            }
            catch (Exception ex) {
                JsonLogStore.Error("premium_entitlement_subscriber_failed", "Premium entitlement subscriber failed.", Category, ex);
            }
        }

        private static bool IsMatchingLicense(string key, StoreLicense license, out string reason) {
            if (IsMatchingStoreId(key)) {
                reason = "license_key_store_id";
                return true;
            }

            if (IsMatchingStoreId(license.SkuStoreId)) {
                reason = "license_sku_store_id";
                return true;
            }

            if (string.Equals(license.InAppOfferToken, StoreProductConfiguration.PremiumProductId, StringComparison.OrdinalIgnoreCase)) {
                reason = "license_offer_token";
                return true;
            }

            reason = string.Empty;
            return false;
        }

        private static bool IsMatchingProduct(string key, StoreProduct product, out string reason) {
            if (IsMatchingStoreId(key) || IsMatchingStoreId(product.StoreId)) {
                reason = product.IsInUserCollection ? "product_store_id_in_collection" : "product_store_id";
                return product.IsInUserCollection;
            }

            if (string.Equals(product.InAppOfferToken, StoreProductConfiguration.PremiumProductId, StringComparison.OrdinalIgnoreCase)) {
                reason = product.IsInUserCollection ? "product_offer_token_in_collection" : "product_offer_token";
                return product.IsInUserCollection;
            }

            reason = string.Empty;
            return false;
        }

        private static bool IsPremiumCatalogProduct(string key, StoreProduct product) {
            return IsMatchingStoreId(key)
                || IsMatchingStoreId(product.StoreId)
                || string.Equals(product.InAppOfferToken, StoreProductConfiguration.PremiumProductId, StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsMatchingStoreId(string? value) {
            if (string.IsNullOrWhiteSpace(value)) {
                return false;
            }

            return string.Equals(value, StoreProductConfiguration.PremiumStoreId, StringComparison.OrdinalIgnoreCase)
                || value.StartsWith(StoreProductConfiguration.PremiumStoreId + "/", StringComparison.OrdinalIgnoreCase);
        }

        private static IReadOnlyDictionary<string, object?> BuildProductLogPayload(string key, StoreProduct product) {
            return new Dictionary<string, object?> {
                ["key"] = key,
                ["storeId"] = product.StoreId,
                ["inAppOfferToken"] = product.InAppOfferToken,
                ["isInUserCollection"] = product.IsInUserCollection,
                ["productKind"] = product.ProductKind,
                ["title"] = product.Title
            };
        }

        private sealed record EntitlementQueryResult(
            StoreEntitlementState State,
            bool IsPremium,
            bool IsPurchaseAvailable,
            string StatusMessage,
            string? MatchReason);
    }
}
