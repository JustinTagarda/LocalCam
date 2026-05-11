using LocalCam.Models;
using Windows.ApplicationModel;
using Windows.Services.Store;

namespace LocalCam.Services {
    internal sealed class StoreUpdateClient : IStoreUpdateClient {
        private readonly StoreContext _context;
        private IReadOnlyList<StorePackageUpdate> _cachedUpdates = [];

        public StoreUpdateClient(bool isSupported) {
            SupportsStoreApis = isSupported;
            _context = StoreContext.GetDefault();
        }

        public bool SupportsStoreApis { get; }

        public async Task<IReadOnlyList<StorePackageUpdateInfo>> GetAvailableUpdatesAsync(CancellationToken cancellationToken) {
            _ = cancellationToken;
            if (!SupportsStoreApis) {
                _cachedUpdates = [];
                return [];
            }

            var updates = await _context.GetAppAndOptionalStorePackageUpdatesAsync();
            _cachedUpdates = updates.ToList();

            return _cachedUpdates
                .Select(update => new StorePackageUpdateInfo(
                    PackageFamilyName: update.Package.Id.FamilyName,
                    Version: FormatVersion(update.Package.Id.Version),
                    IsMandatory: update.Mandatory))
                .ToArray();
        }

        public bool CanSilentlyDownloadStorePackageUpdates() {
            return SupportsStoreApis && _context.CanSilentlyDownloadStorePackageUpdates;
        }

        public async Task<bool> DownloadUpdatesAsync(
            IReadOnlyList<StorePackageUpdateInfo> updates,
            IProgress<double>? progress,
            CancellationToken cancellationToken) {
            _ = updates;
            _ = cancellationToken;
            if (!SupportsStoreApis || _cachedUpdates.Count == 0) {
                return true;
            }

            var operation = _context.TrySilentDownloadStorePackageUpdatesAsync(_cachedUpdates);
            operation.Progress = (_, status) => progress?.Report(ClampProgress(status.PackageDownloadProgress));
            var result = await operation;
            return result.OverallState == StorePackageUpdateState.Completed;
        }

        public async Task<bool> DownloadAndInstallUpdatesAsync(
            IReadOnlyList<StorePackageUpdateInfo> updates,
            IProgress<double>? progress,
            CancellationToken cancellationToken) {
            _ = updates;
            _ = cancellationToken;
            if (!SupportsStoreApis || _cachedUpdates.Count == 0) {
                return true;
            }

            var operation = _context.TrySilentDownloadAndInstallStorePackageUpdatesAsync(_cachedUpdates);
            operation.Progress = (_, status) => progress?.Report(ClampProgress(status.PackageDownloadProgress));
            var result = await operation;
            return result.OverallState == StorePackageUpdateState.Completed;
        }

        private static string FormatVersion(PackageVersion version) {
            return $"{version.Major}.{version.Minor}.{version.Build}.{version.Revision}";
        }

        private static double ClampProgress(double value) {
            if (double.IsNaN(value) || double.IsInfinity(value)) {
                return 0;
            }

            return Math.Clamp(value, 0, 1);
        }
    }
}
