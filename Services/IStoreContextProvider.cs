using Windows.Services.Store;

namespace LocalCam.Services {
    internal interface IStoreContextProvider {
        bool IsPackaged { get; }
        bool HasPackageIdentity { get; }
        string? TryGetPackageFullName();
        string? TryGetPackageVersion();
        string? TryGetPackageSignatureKind();
        StoreContext? TryGetStoreContext(IntPtr ownerWindowHandle);
    }
}
