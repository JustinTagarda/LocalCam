using Windows.Services.Store;

namespace LocalCam.Services {
    internal sealed class PremiumPurchaseService : IPremiumPurchaseService {
        private readonly IStoreContextProvider _storeContextProvider;
        private readonly Func<IntPtr> _ownerWindowHandleProvider;
        private readonly string _premiumAddOnStoreId;

        public PremiumPurchaseService(
            IStoreContextProvider storeContextProvider,
            Func<IntPtr> ownerWindowHandleProvider,
            string premiumAddOnStoreId) {
            _storeContextProvider = storeContextProvider;
            _ownerWindowHandleProvider = ownerWindowHandleProvider;
            _premiumAddOnStoreId = premiumAddOnStoreId.Trim();
        }

        public async Task<PremiumPurchaseResult> PurchasePremiumAsync(CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();

            if (!_storeContextProvider.IsPackaged || string.IsNullOrWhiteSpace(_premiumAddOnStoreId)) {
                return new PremiumPurchaseResult(
                    PremiumPurchaseOutcome.NotSupported,
                    "In-app Premium purchase is available only in packaged Store builds with a configured add-on Store ID.");
            }

            if (_storeContextProvider.IsElevated) {
                return new PremiumPurchaseResult(
                    PremiumPurchaseOutcome.Blocked,
                    "In-app purchase is blocked while running as administrator. Run without elevation and try again.");
            }

            var storeContext = _storeContextProvider.TryGetStoreContext(_ownerWindowHandleProvider());
            if (storeContext is null) {
                return new PremiumPurchaseResult(
                    PremiumPurchaseOutcome.NotSupported,
                    "Microsoft Store purchase context is unavailable.");
            }

            try {
                var purchaseResult = await storeContext.RequestPurchaseAsync(_premiumAddOnStoreId);
                cancellationToken.ThrowIfCancellationRequested();

                return purchaseResult.Status switch {
                    StorePurchaseStatus.Succeeded => new PremiumPurchaseResult(PremiumPurchaseOutcome.Succeeded, "Premium purchase succeeded."),
                    StorePurchaseStatus.AlreadyPurchased => new PremiumPurchaseResult(PremiumPurchaseOutcome.AlreadyOwned, "Premium is already owned."),
                    StorePurchaseStatus.NotPurchased => new PremiumPurchaseResult(PremiumPurchaseOutcome.Canceled, "Premium purchase was canceled."),
                    StorePurchaseStatus.NetworkError => new PremiumPurchaseResult(PremiumPurchaseOutcome.NetworkError, "Network error while contacting Microsoft Store."),
                    StorePurchaseStatus.ServerError => new PremiumPurchaseResult(PremiumPurchaseOutcome.ServerError, "Microsoft Store server error during purchase."),
                    _ => new PremiumPurchaseResult(PremiumPurchaseOutcome.Failed, "Premium purchase failed.")
                };
            }
            catch {
                return new PremiumPurchaseResult(
                    PremiumPurchaseOutcome.Failed,
                    "Premium purchase failed due to a Store API error.");
            }
        }
    }
}
