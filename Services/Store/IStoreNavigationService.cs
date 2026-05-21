namespace LocalCam.Services.Store {
    internal interface IStoreNavigationService {
        Task<bool> OpenPremiumPurchasePageAsync(CancellationToken cancellationToken);
    }
}
