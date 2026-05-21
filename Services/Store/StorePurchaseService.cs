using System.Security.Principal;
using LocalCam.Models;
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

        public async Task<bool> RequestPremiumPurchaseAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            var snapshot = await _licenseService.EnsureReadyAsync(cancellationToken).ConfigureAwait(false);
            if (snapshot.IsPremium) {
                return true;
            }

            if (IsElevated()) {
                JsonLogStore.Warning("premium_purchase_blocked_elevated", "Premium purchase blocked because the app is running elevated.", Category);
                return false;
            }

            var context = _contextProvider.GetContext(ownerWindowHandle);
            if (context is null) {
                var opened = await _navigationService.OpenPremiumPurchasePageAsync(cancellationToken).ConfigureAwait(false);
                if (!opened) {
                    JsonLogStore.Warning("premium_purchase_unavailable", "Premium purchase unavailable because Store context and Store navigation are unavailable.", Category);
                }

                return false;
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

                await _licenseService.RefreshAsync(ownerWindowHandle, cancellationToken).ConfigureAwait(false);
                return _licenseService.Snapshot.IsPremium;
            }
            catch (OperationCanceledException) {
                throw;
            }
            catch (Exception ex) {
                JsonLogStore.Error("premium_purchase_failed", "Premium purchase flow failed.", Category, ex);
                await _licenseService.RefreshAsync(ownerWindowHandle, cancellationToken).ConfigureAwait(false);
                return false;
            }
        }

        public Task<StoreEntitlementSnapshot> RestorePremiumPurchaseAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            return _licenseService.RefreshAsync(ownerWindowHandle, cancellationToken);
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
