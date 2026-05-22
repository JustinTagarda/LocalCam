namespace LocalCam.Services.Store {
    internal interface IStoreNavigationService {
        Task<bool> OpenPremiumPurchasePageAsync(CancellationToken cancellationToken);
        Task<bool> OpenPromotionalCodeRedeemUrlAsync(string promoCode, CancellationToken cancellationToken);
    }
}
