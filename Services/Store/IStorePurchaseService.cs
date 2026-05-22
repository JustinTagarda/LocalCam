using LocalCam.Models;

namespace LocalCam.Services.Store {
    internal interface IStorePurchaseService {
        Task<StorePurchaseResult> RequestPremiumPurchaseAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken);
        Task<StoreEntitlementSnapshot> RestorePremiumPurchaseAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken);
        Task<StoreRedemptionResult> RedeemPromoCodeAsync(string promoCode, IntPtr ownerWindowHandle, CancellationToken cancellationToken);
    }
}
