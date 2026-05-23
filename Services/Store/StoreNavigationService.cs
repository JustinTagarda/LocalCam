using Windows.System;

namespace LocalCam.Services.Store {
    internal sealed class StoreNavigationService : IStoreNavigationService {
        private const string Category = "store_navigation";

        public StoreNavigationService() {
        }

        public Task<bool> OpenPromotionalCodeRedeemUrlAsync(string promoCode, CancellationToken cancellationToken) {
            var normalized = NormalizePromoCode(promoCode);
            if (normalized is null) {
                return Task.FromResult(false);
            }

            var redeemUri = new Uri($"https://go.microsoft.com/fwlink/?LinkId=532540&mstoken={Uri.EscapeDataString(normalized)}");
            return LaunchStoreUriAsync(redeemUri, "store_promo_redeem_open_failed", cancellationToken);
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

        private static string? NormalizePromoCode(string promoCode) {
            if (string.IsNullOrWhiteSpace(promoCode)) {
                return null;
            }

            var trimmed = new string(promoCode
                .Trim()
                .ToUpperInvariant()
                .Where(ch => char.IsLetterOrDigit(ch) || ch == '-')
                .ToArray());

            return trimmed.Length == 29 && System.Text.RegularExpressions.Regex.IsMatch(trimmed, "^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$")
                ? trimmed
                : null;
        }
    }
}
