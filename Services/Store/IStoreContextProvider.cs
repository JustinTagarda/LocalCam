using Windows.Services.Store;

namespace LocalCam.Services.Store {
    internal interface IStoreContextProvider {
        bool IsStoreSupported { get; }
        StoreContext? GetContext(IntPtr ownerWindowHandle);
    }
}
