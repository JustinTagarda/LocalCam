using Windows.System;

namespace LocalCam.Services.Store {
    internal sealed class StoreNavigationService : IStoreNavigationService {
        private const string Category = "store_navigation";

        public StoreNavigationService() {
        }

        public Task<bool> OpenPremiumPurchasePageAsync(CancellationToken cancellationToken) {
            return LaunchStoreUriAsync(new Uri($"ms-windows-store://pdp/?ProductId={StoreProductConfiguration.PremiumStoreId}"), "store_premium_page_open_failed", cancellationToken);
        }

        private static async Task<bool> LaunchStoreUriAsync(Uri uri, string failureEventName, CancellationToken cancellationToken) {
            try {
                cancellationToken.ThrowIfCancellationRequested();
                var launched = await Launcher.LaunchUriAsync(uri);
                JsonLogStore.Information("store_navigation_requested", "Microsoft Store navigation requested.", Category, new Dictionary<string, object?> {
                    ["uri"] = uri.ToString(),
                    ["launched"] = launched
                });
                return launched;
            }
            catch (OperationCanceledException) {
                throw;
            }
            catch (Exception ex) {
                JsonLogStore.Error(failureEventName, "Failed to open Microsoft Store navigation URI.", Category, ex, new Dictionary<string, object?> {
                    ["uri"] = uri.ToString()
                });
                return false;
            }
        }
    }
}
