using Windows.Services.Store;

namespace LocalCam.Services {
    internal interface IStoreContextProvider {
        bool IsPackaged { get; }
        bool IsElevated { get; }
        StoreContext? TryGetStoreContext(IntPtr ownerWindowHandle);
    }
}
