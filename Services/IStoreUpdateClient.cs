using LocalCam.Models;

namespace LocalCam.Services {
    internal interface IStoreUpdateClient {
        bool SupportsStoreApis { get; }
        Task<IReadOnlyList<StorePackageUpdateInfo>> GetAvailableUpdatesAsync(CancellationToken cancellationToken);
        bool CanSilentlyDownloadStorePackageUpdates();
        Task<bool> DownloadUpdatesAsync(IReadOnlyList<StorePackageUpdateInfo> updates, IProgress<double>? progress, CancellationToken cancellationToken);
        Task<bool> DownloadAndInstallUpdatesAsync(IReadOnlyList<StorePackageUpdateInfo> updates, IProgress<double>? progress, CancellationToken cancellationToken);
        Task<StoreUpdateOperationResult> RequestDownloadAndInstallUpdatesAsync(IReadOnlyList<StorePackageUpdateInfo> updates, IProgress<double>? progress, CancellationToken cancellationToken);
    }
}
