namespace LocalCam.Services {
    internal interface IStoreNavigationService {
        bool TryOpenStoreListing(string productId);
    }
}
