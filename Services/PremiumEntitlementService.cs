using LocalCam.Models;
using Windows.Services.Store;
using WinRT.Interop;

namespace LocalCam.Services {
    internal sealed class PremiumEntitlementService : IPremiumEntitlementService {
        private const string Category = "store_entitlement";
        private const string PremiumStoreId = "9P9KCJ3NFZFT";
        private const string PremiumProductId = "localcam_premium_lifetime";
        private static readonly TimeSpan OwnedGracePeriod = TimeSpan.FromHours(24);

        private readonly IAppVersionProvider _versionProvider;
        private readonly object _syncRoot = new();
        private readonly TaskCompletionSource<StoreEntitlementSnapshot> _firstRefresh =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private StoreContext? _context;
        private DateTimeOffset? _lastVerifiedOwnedAt;

        public PremiumEntitlementService(IAppVersionProvider versionProvider) {
            _versionProvider = versionProvider;
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

            try {
                if (!_versionProvider.IsPackaged()) {
                    Publish(StoreEntitlementState.VerificationFailed, false, false, "Premium license verification is unavailable in unpackaged builds.", "unpackaged_build");
                    return;
                }

                _context = StoreContext.GetDefault();
                InitializeContextWindow(_context, ownerWindowHandle);
                await RefreshAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) {
                throw;
            }
            catch (Exception ex) {
                PublishFailureWithGrace(ex, "Premium license verification failed.");
            }
        }

        public async Task<StoreEntitlementSnapshot> EnsureReadyAsync(CancellationToken cancellationToken) {
            var snapshot = Snapshot;
            if (snapshot.State != StoreEntitlementState.Unknown && snapshot.State != StoreEntitlementState.Checking) {
                return snapshot;
            }

            using var registration = cancellationToken.Register(() => _firstRefresh.TrySetCanceled(cancellationToken));
            return await _firstRefresh.Task.ConfigureAwait(false);
        }

        public async Task<bool> RequestPremiumPurchaseAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            var snapshot = await EnsureReadyAsync(cancellationToken).ConfigureAwait(false);
            if (snapshot.State != StoreEntitlementState.VerifiedNotOwned || !snapshot.IsPurchaseAvailable) {
                JsonLogStore.Warning(
                    "premium_purchase_blocked",
                    "Premium purchase was blocked because entitlement state or purchase availability is invalid.",
                    Category,
                    new Dictionary<string, object?> {
                        ["state"] = snapshot.State.ToString(),
                        ["isPremium"] = snapshot.IsPremium,
                        ["isPurchaseAvailable"] = snapshot.IsPurchaseAvailable
                    });
                return false;
            }

            try {
                var context = _context ?? StoreContext.GetDefault();
                _context = context;
                InitializeContextWindow(context, ownerWindowHandle);

                JsonLogStore.Information(
                    "premium_purchase_requested",
                    "Premium durable add-on purchase flow requested.",
                    Category,
                    new Dictionary<string, object?> {
                        ["storeId"] = PremiumStoreId,
                        ["productId"] = PremiumProductId
                    });

                var result = await context.RequestPurchaseAsync(PremiumStoreId);
                JsonLogStore.Information(
                    "premium_purchase_completed",
                    "Premium durable add-on purchase flow completed.",
                    Category,
                    new Dictionary<string, object?> {
                        ["status"] = result.Status.ToString(),
                        ["extendedError"] = result.ExtendedError?.Message
                    });

                await RefreshAsync(cancellationToken).ConfigureAwait(false);
                return Snapshot.IsPremium;
            }
            catch (OperationCanceledException) {
                throw;
            }
            catch (Exception ex) {
                JsonLogStore.Error("premium_purchase_failed", "Premium purchase flow failed.", Category, ex);
                PublishFailureWithGrace(ex, "Premium purchase could not be completed.");
                return false;
            }
        }

        private async Task RefreshAsync(CancellationToken cancellationToken) {
            var context = _context ?? StoreContext.GetDefault();
            _context = context;

            var licenseKeys = Array.Empty<string>();
            var licenseDetails = new List<IReadOnlyDictionary<string, object?>>();
            var userCollectionDetails = new List<IReadOnlyDictionary<string, object?>>();
            var associatedProductDetails = new List<IReadOnlyDictionary<string, object?>>();
            string? matchReason = null;
            var isPurchaseAvailable = false;
            Exception? userCollectionError = null;

            var appLicense = await context.GetAppLicenseAsync();
            cancellationToken.ThrowIfCancellationRequested();

            licenseKeys = appLicense.AddOnLicenses.Keys.ToArray();
            foreach (var pair in appLicense.AddOnLicenses) {
                var license = pair.Value;
                var detail = new Dictionary<string, object?> {
                    ["key"] = pair.Key,
                    ["skuStoreId"] = license.SkuStoreId,
                    ["inAppOfferToken"] = license.InAppOfferToken,
                    ["isActive"] = license.IsActive
                };
                licenseDetails.Add(detail);

                if (license.IsActive && IsMatchingLicense(pair.Key, license, out var reason)) {
                    matchReason ??= reason;
                }
            }

            StoreProductQueryResult? userCollection = null;
            try {
                userCollection = await context.GetUserCollectionAsync(["Durable"]);
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var pair in userCollection.Products) {
                    var product = pair.Value;
                    userCollectionDetails.Add(BuildProductLogPayload(pair.Key, product));
                    if (IsMatchingProduct(pair.Key, product, out var reason)) {
                        matchReason ??= reason;
                    }
                }
            }
            catch (Exception ex) {
                userCollectionError = ex;
                JsonLogStore.Error("premium_user_collection_query_failed", "Store user collection query failed.", Category, ex);
            }

            try {
                var associatedProducts = await context.GetAssociatedStoreProductsAsync(["Durable"]);
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var pair in associatedProducts.Products) {
                    var product = pair.Value;
                    associatedProductDetails.Add(BuildProductLogPayload(pair.Key, product));
                    if (IsPremiumCatalogProduct(pair.Key, product)) {
                        isPurchaseAvailable = true;
                    }

                    if (product.IsInUserCollection && IsMatchingProduct(pair.Key, product, out var reason)) {
                        matchReason ??= reason;
                    }
                }
            }
            catch (Exception ex) {
                JsonLogStore.Error("premium_associated_products_query_failed", "Store associated products query failed.", Category, ex);
            }

            var isPremium = !string.IsNullOrWhiteSpace(matchReason);
            if (!isPremium && userCollectionError is not null) {
                JsonLogStore.Warning(
                    "premium_entitlement_incomplete",
                    "Premium durable add-on entitlement refresh could not complete all required ownership checks.",
                    Category,
                    new Dictionary<string, object?> {
                        ["configuredStoreIds"] = new[] { PremiumStoreId },
                        ["configuredProductIds"] = new[] { PremiumProductId },
                        ["addOnLicenseKeys"] = licenseKeys,
                        ["licenses"] = licenseDetails.ToArray(),
                        ["userCollectionErrorType"] = userCollectionError.GetType().FullName,
                        ["userCollectionErrorMessage"] = userCollectionError.Message,
                        ["associatedProducts"] = associatedProductDetails.ToArray()
                    });
                PublishFailureWithGrace(userCollectionError, "Premium license verification failed because Store ownership checks were incomplete.");
                return;
            }

            if (isPremium) {
                _lastVerifiedOwnedAt = DateTimeOffset.Now;
            }

            JsonLogStore.Information(
                "premium_entitlement_refreshed",
                "Premium durable add-on entitlement refresh completed.",
                Category,
                new Dictionary<string, object?> {
                    ["configuredStoreIds"] = new[] { PremiumStoreId },
                    ["configuredProductIds"] = new[] { PremiumProductId },
                    ["addOnLicenseKeys"] = licenseKeys,
                    ["licenses"] = licenseDetails.ToArray(),
                    ["userCollectionProducts"] = userCollectionDetails.ToArray(),
                    ["associatedProducts"] = associatedProductDetails.ToArray(),
                    ["finalMatchReason"] = matchReason,
                    ["isPurchaseAvailable"] = isPurchaseAvailable,
                    ["finalState"] = isPremium ? StoreEntitlementState.VerifiedOwned.ToString() : StoreEntitlementState.VerifiedNotOwned.ToString()
                });

            Publish(
                isPremium ? StoreEntitlementState.VerifiedOwned : StoreEntitlementState.VerifiedNotOwned,
                isPremium,
                isPurchaseAvailable,
                isPremium ? "Premium license verified." : "Premium license was not found.",
                matchReason);
        }

        private void PublishFailureWithGrace(Exception ex, string message) {
            var allowGrace = _lastVerifiedOwnedAt.HasValue && DateTimeOffset.Now - _lastVerifiedOwnedAt.Value <= OwnedGracePeriod;
            JsonLogStore.Error(
                "premium_entitlement_failed",
                message,
                Category,
                ex,
                new Dictionary<string, object?> {
                    ["configuredStoreIds"] = new[] { PremiumStoreId },
                    ["configuredProductIds"] = new[] { PremiumProductId },
                    ["allowGrace"] = allowGrace,
                    ["lastVerifiedOwnedAt"] = _lastVerifiedOwnedAt
                });

            Publish(
                StoreEntitlementState.VerificationFailed,
                allowGrace,
                false,
                allowGrace ? "Using recent Premium verification while Store is unavailable." : "Unable to verify Premium license.",
                allowGrace ? "recent_verified_owned_grace" : null);
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

            if (string.Equals(license.InAppOfferToken, PremiumProductId, StringComparison.OrdinalIgnoreCase)) {
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

            if (string.Equals(product.InAppOfferToken, PremiumProductId, StringComparison.OrdinalIgnoreCase)) {
                reason = product.IsInUserCollection ? "product_offer_token_in_collection" : "product_offer_token";
                return product.IsInUserCollection;
            }

            reason = string.Empty;
            return false;
        }

        private static bool IsPremiumCatalogProduct(string key, StoreProduct product) {
            return IsMatchingStoreId(key)
                || IsMatchingStoreId(product.StoreId)
                || string.Equals(product.InAppOfferToken, PremiumProductId, StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsMatchingStoreId(string? value) {
            if (string.IsNullOrWhiteSpace(value)) {
                return false;
            }

            return string.Equals(value, PremiumStoreId, StringComparison.OrdinalIgnoreCase)
                || value.StartsWith(PremiumStoreId + "/", StringComparison.OrdinalIgnoreCase);
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

        private static void InitializeContextWindow(StoreContext context, IntPtr ownerWindowHandle) {
            if (ownerWindowHandle == IntPtr.Zero) {
                return;
            }

            try {
                InitializeWithWindow.Initialize(context, ownerWindowHandle);
            }
            catch (Exception ex) {
                JsonLogStore.Error("store_context_window_init_failed", "Failed to initialize Store context with owner window.", Category, ex);
            }
        }
    }
}
