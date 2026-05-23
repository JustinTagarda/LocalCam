namespace LocalCam.Services.Store {
    internal interface IStoreNavigationService {
        Task<bool> OpenPromotionalCodeRedeemUrlAsync(string promoCode, CancellationToken cancellationToken);
    }
}
