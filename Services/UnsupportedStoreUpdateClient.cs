using LocalCam.Models;

namespace LocalCam.Services {
    internal sealed class UnsupportedStoreUpdateClient : IStoreUpdateClient {
        public bool SupportsStoreApis => false;

        public Task<IReadOnlyList<StorePackageUpdateInfo>> GetAvailableUpdatesAsync(CancellationToken cancellationToken) {
            _ = cancellationToken;
            return Task.FromResult<IReadOnlyList<StorePackageUpdateInfo>>([]);
        }

        public bool CanSilentlyDownloadStorePackageUpdates() {
            return false;
        }

        public Task<bool> DownloadUpdatesAsync(
            IReadOnlyList<StorePackageUpdateInfo> updates,
            IProgress<double>? progress,
            CancellationToken cancellationToken) {
            _ = updates;
            _ = progress;
            _ = cancellationToken;
            return Task.FromResult(false);
        }

        public Task<StoreUpdateOperationResult> RequestDownloadStorePackageUpdatesAsync(
            IReadOnlyList<StorePackageUpdateInfo> updates,
            IProgress<double>? progress,
            CancellationToken cancellationToken) {
            _ = updates;
            _ = progress;
            _ = cancellationToken;
            return Task.FromResult(new StoreUpdateOperationResult(StoreUpdateOperationState.Unknown, "Store update UI is unavailable.", 0, WasAttempted: false));
        }

        public Task<bool> DownloadAndInstallUpdatesAsync(
            IReadOnlyList<StorePackageUpdateInfo> updates,
            IProgress<double>? progress,
            CancellationToken cancellationToken) {
            _ = updates;
            _ = progress;
            _ = cancellationToken;
            return Task.FromResult(false);
        }

        public Task<StoreUpdateOperationResult> RequestDownloadAndInstallUpdatesAsync(
            IReadOnlyList<StorePackageUpdateInfo> updates,
            IProgress<double>? progress,
            CancellationToken cancellationToken) {
            _ = updates;
            _ = progress;
            _ = cancellationToken;
            return Task.FromResult(new StoreUpdateOperationResult(StoreUpdateOperationState.Unknown, "Store update UI is unavailable."));
        }
    }
}
