using LocalCam.Models;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.ApplicationModel;
using Windows.Services.Store;
using WinRT.Interop;

namespace LocalCam.Services {
    internal sealed class StoreUpdateClient : IStoreUpdateClient {
        private readonly Func<IntPtr> _getOwnerWindowHandle;
        private StoreContext? _context;
        private IntPtr _initializedOwnerWindowHandle;
        private IReadOnlyList<StorePackageUpdate> _cachedUpdates = [];

        public StoreUpdateClient()
            : this(() => IntPtr.Zero) {
        }

        public StoreUpdateClient(IntPtr ownerWindowHandle) {
            _getOwnerWindowHandle = () => ownerWindowHandle;
        }

        public StoreUpdateClient(Func<IntPtr> getOwnerWindowHandle) {
            _getOwnerWindowHandle = getOwnerWindowHandle;
        }

        public bool SupportsStoreApis => true;

        public async Task<IReadOnlyList<StorePackageUpdateInfo>> GetAvailableUpdatesAsync(CancellationToken cancellationToken) {
            var context = EnsureContext();
            if (context is null) {
                _cachedUpdates = [];
                return [];
            }

            var updates = await context.GetAppAndOptionalStorePackageUpdatesAsync().AsTask(cancellationToken);
            _cachedUpdates = updates.ToList();

            return _cachedUpdates
                .Select(update => new StorePackageUpdateInfo(
                    PackageFamilyName: update.Package.Id.FamilyName,
                    Version: FormatVersion(update.Package.Id.Version),
                    PackageIdentitySnapshot: BuildPackageIdentitySnapshot(update.Package.Id.FamilyName, update.Package.Id.Version),
                    IsMandatory: update.Mandatory))
                .ToArray();
        }

        public bool CanSilentlyDownloadStorePackageUpdates() {
            var context = EnsureContext();
            return context is not null && context.CanSilentlyDownloadStorePackageUpdates;
        }

        public async Task<bool> DownloadUpdatesAsync(
            IReadOnlyList<StorePackageUpdateInfo> updates,
            IProgress<double>? progress,
            CancellationToken cancellationToken) {
            _ = updates;
            var context = EnsureContext();
            if (context is null) {
                return false;
            }

            if (_cachedUpdates.Count == 0) {
                return false;
            }

            var operation = context.TrySilentDownloadStorePackageUpdatesAsync(_cachedUpdates);
            operation.Progress = (_, status) => progress?.Report(ClampProgress(status.PackageDownloadProgress));
            var result = await operation.AsTask(cancellationToken);
            return result.OverallState == StorePackageUpdateState.Completed;
        }

        public async Task<StoreUpdateOperationResult> RequestDownloadStorePackageUpdatesAsync(
            IReadOnlyList<StorePackageUpdateInfo> updates,
            IProgress<double>? progress,
            CancellationToken cancellationToken) {
            _ = updates;
            var context = EnsureContext();
            if (context is null) {
                return new StoreUpdateOperationResult(StoreUpdateOperationState.Unknown, "Store update UI is unavailable.", 0, WasAttempted: false);
            }

            if (_cachedUpdates.Count == 0) {
                return new StoreUpdateOperationResult(StoreUpdateOperationState.Unknown, "No update is queued for download.", 0, WasAttempted: false);
            }

            var operation = context.RequestDownloadStorePackageUpdatesAsync(_cachedUpdates);
            operation.Progress = (_, status) => progress?.Report(ClampProgress(status.PackageDownloadProgress));
            var result = await operation.AsTask(cancellationToken);
            var state = MapState(result.OverallState);
            return new StoreUpdateOperationResult(state, $"Store download request completed: {result.OverallState}.", 0, WasAttempted: true);
        }

        public async Task<bool> DownloadAndInstallUpdatesAsync(
            IReadOnlyList<StorePackageUpdateInfo> updates,
            IProgress<double>? progress,
            CancellationToken cancellationToken) {
            _ = updates;
            var context = EnsureContext();
            if (context is null) {
                return false;
            }

            if (_cachedUpdates.Count == 0) {
                return false;
            }

            var operation = context.TrySilentDownloadAndInstallStorePackageUpdatesAsync(_cachedUpdates);
            operation.Progress = (_, status) => progress?.Report(ClampProgress(status.PackageDownloadProgress));
            var result = await operation.AsTask(cancellationToken);
            return result.OverallState == StorePackageUpdateState.Completed;
        }

        public async Task<StoreUpdateOperationResult> RequestDownloadAndInstallUpdatesAsync(
            IReadOnlyList<StorePackageUpdateInfo> updates,
            IProgress<double>? progress,
            CancellationToken cancellationToken) {
            _ = updates;
            var context = EnsureContext();
            if (context is null) {
                return new StoreUpdateOperationResult(StoreUpdateOperationState.Unknown, "Store update UI is unavailable.", 0, WasAttempted: false);
            }

            if (_cachedUpdates.Count == 0) {
                return new StoreUpdateOperationResult(StoreUpdateOperationState.Unknown, "No update is queued for installation.", 0, WasAttempted: false);
            }

            var operation = context.RequestDownloadAndInstallStorePackageUpdatesAsync(_cachedUpdates);
            operation.Progress = (_, status) => progress?.Report(ClampProgress(status.PackageDownloadProgress));
            var result = await operation.AsTask(cancellationToken);
            var state = MapState(result.OverallState);
            return new StoreUpdateOperationResult(state, $"Store update request completed: {result.OverallState}.", 0, WasAttempted: true);
        }

        private StoreContext? EnsureContext() {
            if (_context is not null) {
                TryInitializeWithWindow(_context, _getOwnerWindowHandle());
                return _context;
            }

            try {
                _context = StoreContext.GetDefault();
                TryInitializeWithWindow(_context, _getOwnerWindowHandle());
                return _context;
            }
            catch (Exception ex) {
                JsonLogStore.Error("store_update_client_context_init_failed", "Failed to initialize Store update client context.", "updater", ex);
                return null;
            }
        }

        private void TryInitializeWithWindow(StoreContext context, IntPtr ownerWindowHandle) {
            if (ownerWindowHandle == IntPtr.Zero || ownerWindowHandle == _initializedOwnerWindowHandle) {
                return;
            }

            try {
                InitializeWithWindow.Initialize(context, ownerWindowHandle);
                _initializedOwnerWindowHandle = ownerWindowHandle;
            }
            catch (Exception ex) {
                JsonLogStore.Error("store_update_client_window_init_failed", "Failed to initialize Store update client with owner window.", "updater", ex);
            }
        }

        private static StoreUpdateOperationState MapState(StorePackageUpdateState state) {
            return state switch {
                StorePackageUpdateState.Completed => StoreUpdateOperationState.Completed,
                StorePackageUpdateState.Canceled => StoreUpdateOperationState.Canceled,
                StorePackageUpdateState.OtherError => StoreUpdateOperationState.OtherError,
                StorePackageUpdateState.ErrorLowBattery => StoreUpdateOperationState.ErrorLowBattery,
                StorePackageUpdateState.ErrorWiFiRecommended => StoreUpdateOperationState.ErrorWiFiRecommended,
                StorePackageUpdateState.ErrorWiFiRequired => StoreUpdateOperationState.ErrorWiFiRequired,
                _ => StoreUpdateOperationState.Unknown
            };
        }

        private static string FormatVersion(PackageVersion version) {
            return $"{version.Major}.{version.Minor}.{version.Build}.{version.Revision}";
        }

        private static string BuildPackageIdentitySnapshot(string packageFamilyName, PackageVersion version) {
            return $"{packageFamilyName}:{FormatVersion(version)}";
        }

        private static double ClampProgress(double value) {
            if (double.IsNaN(value) || double.IsInfinity(value)) {
                return 0;
            }

            return Math.Clamp(value, 0, 1);
        }
    }
}
