namespace LocalCam.Services.Store {
    internal interface IStorePurchaseService {
        Task<bool> RequestPremiumPurchaseAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken);
        Task<LocalCam.Models.StoreEntitlementSnapshot> RestorePremiumPurchaseAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken);
    }
}
