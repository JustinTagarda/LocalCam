using LocalCam.Models;

namespace LocalCam.Services {
    internal sealed class AppUpdateService : IAppUpdateService {
        private static readonly TimeSpan StartupDelay = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan InstallRetryDelay = TimeSpan.FromSeconds(20);
        private static readonly TimeSpan CheckRetryDelay = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan QuietPeriodBeforeInstall = TimeSpan.FromSeconds(5);

        private readonly IAppVersionProvider _versionProvider;
        private readonly IStoreUpdateClient _storeUpdateClient;
        private readonly Func<bool> _isAppBusy;
        private readonly object _syncRoot = new();
        private bool _started;
        private bool _retryScheduled;

        public AppUpdateService(IAppVersionProvider versionProvider, IStoreUpdateClient storeUpdateClient, Func<bool> isAppBusy) {
            _versionProvider = versionProvider;
            _storeUpdateClient = storeUpdateClient;
            _isAppBusy = isAppBusy;
            Snapshot = new AppUpdateSnapshot(
                State: AppUpdateState.Idle,
                StageText: "Idle",
                StatusMessage: string.Empty,
                IsMandatoryUpdateAvailable: false,
                IsProgressVisible: false,
                ProgressValue: 0,
                InstalledVersion: _versionProvider.GetInstalledVersionText(),
                AvailableVersion: null);
        }

        public event Action<AppUpdateSnapshot>? SnapshotChanged;

        public AppUpdateSnapshot Snapshot { get; private set; }

        public async Task StartAsync(CancellationToken cancellationToken) {
            lock (_syncRoot) {
                if (_started) {
                    return;
                }

                _started = true;
            }

            await Task.Delay(StartupDelay, cancellationToken);
            await RunUpdateFlowAsync(cancellationToken);
        }

        private async Task RunUpdateFlowAsync(CancellationToken cancellationToken) {
            if (!_versionProvider.IsPackaged()) {
                Publish(AppUpdateState.Idle, "Idle", "Store updates are disabled in unpackaged builds.", false, false, 0, null);
                JsonLogStore.Information("update_check_skipped_unpacked", "Store update check skipped because app is unpackaged.", "updater");
                return;
            }

            if (!_storeUpdateClient.SupportsStoreApis) {
                Publish(
                    AppUpdateState.Deferred,
                    "Store updater active",
                    "This packaged build relies on Microsoft Store automatic updates.",
                    false,
                    false,
                    0,
                    null);
                JsonLogStore.Warning("store_api_unavailable", "Store API integration is unavailable in the current runtime/toolchain.", "updater");
                return;
            }

            try {
                JsonLogStore.Information("update_check_started", "Store update check started.", "updater");
                Publish(AppUpdateState.Checking, "Checking for updates", "Checking Microsoft Store updates.", false, true, 0, null);

                var updates = await _storeUpdateClient.GetAvailableUpdatesAsync(cancellationToken);
                if (updates.Count == 0) {
                    Publish(AppUpdateState.Idle, "Idle", "App is up to date.", false, false, 0, null);
                    JsonLogStore.Information("no_updates_available", "No Store updates available.", "updater");
                    return;
                }

                var hasMandatory = updates.Any(update => update.IsMandatory);
                var availableVersion = updates.Select(update => update.Version).OrderByDescending(version => version).FirstOrDefault();
                Publish(AppUpdateState.UpdateAvailable, "Update available", "New version found. Preparing background update.", hasMandatory, false, 0, availableVersion);
                JsonLogStore.Information("updates_available", "Store updates are available.", "updater", new Dictionary<string, object?> {
                    ["updateCount"] = updates.Count,
                    ["isMandatory"] = hasMandatory,
                    ["availableVersion"] = availableVersion
                });

                if (!_storeUpdateClient.CanSilentlyDownloadStorePackageUpdates()) {
                    Publish(AppUpdateState.Deferred, "Update deferred", "Background Store download is currently unavailable. Will retry automatically.", hasMandatory, false, 0, availableVersion);
                    JsonLogStore.Warning("silent_download_unavailable", "Silent download capability unavailable.", "updater");
                    ScheduleRetry(CheckRetryDelay, cancellationToken);
                    return;
                }

                Publish(AppUpdateState.Downloading, "Downloading update", "Downloading Store update in the background.", hasMandatory, true, 0, availableVersion);
                var downloadSucceeded = await _storeUpdateClient.DownloadUpdatesAsync(updates, new Progress<double>(value => {
                    Publish(AppUpdateState.Downloading, "Downloading update", "Downloading Store update in the background.", hasMandatory, true, value, availableVersion);
                }), cancellationToken);

                if (!downloadSucceeded) {
                    Publish(AppUpdateState.Deferred, "Update deferred", "Download did not complete. Will retry automatically.", hasMandatory, false, 0, availableVersion);
                    JsonLogStore.Warning("download_failed", "Store download failed.", "updater");
                    ScheduleRetry(CheckRetryDelay, cancellationToken);
                    return;
                }

                JsonLogStore.Information("download_completed", "Store update download completed.", "updater");
                while (_isAppBusy()) {
                    Publish(AppUpdateState.Deferred, "Update deferred", "Update is ready and will install when app is idle.", hasMandatory, false, 0, availableVersion);
                    await Task.Delay(InstallRetryDelay, cancellationToken);
                }

                await Task.Delay(QuietPeriodBeforeInstall, cancellationToken);
                if (_isAppBusy()) {
                    Publish(AppUpdateState.Deferred, "Update deferred", "App became busy again. Install deferred.", hasMandatory, false, 0, availableVersion);
                    ScheduleRetry(InstallRetryDelay, cancellationToken);
                    return;
                }

                Publish(AppUpdateState.Installing, "Installing update", "Installing downloaded update in background.", hasMandatory, true, 0, availableVersion);
                var installSucceeded = await _storeUpdateClient.DownloadAndInstallUpdatesAsync(updates, new Progress<double>(value => {
                    Publish(AppUpdateState.Installing, "Installing update", "Installing downloaded update in background.", hasMandatory, true, value, availableVersion);
                }), cancellationToken);

                if (!installSucceeded) {
                    Publish(AppUpdateState.Deferred, "Update deferred", "Install did not complete. Will retry automatically.", hasMandatory, false, 0, availableVersion);
                    JsonLogStore.Warning("install_failed", "Store install failed.", "updater");
                    ScheduleRetry(InstallRetryDelay, cancellationToken);
                    return;
                }

                Publish(AppUpdateState.Completed, "Update installed", "Restart to run the newly installed version.", hasMandatory, false, 1, availableVersion);
                JsonLogStore.Information("install_completed", "Store update install completed.", "updater");
            }
            catch (OperationCanceledException) {
            }
            catch (Exception ex) {
                Publish(AppUpdateState.Failed, "Update check failed", "Unable to complete Store update check. Will retry automatically.", false, false, 0, null);
                JsonLogStore.Error("update_check_failed", "Store update flow failed.", "updater", ex);
                ScheduleRetry(CheckRetryDelay, cancellationToken);
            }
        }

        private void ScheduleRetry(TimeSpan delay, CancellationToken cancellationToken) {
            lock (_syncRoot) {
                if (_retryScheduled) {
                    return;
                }

                _retryScheduled = true;
            }

            _ = Task.Run(async () => {
                try {
                    await Task.Delay(delay, cancellationToken);
                    lock (_syncRoot) {
                        _retryScheduled = false;
                    }

                    await RunUpdateFlowAsync(cancellationToken);
                }
                catch (OperationCanceledException) {
                    lock (_syncRoot) {
                        _retryScheduled = false;
                    }
                }
                catch (Exception ex) {
                    JsonLogStore.Error("background_retry_failed", "Background updater retry failed.", "updater", ex);
                    lock (_syncRoot) {
                        _retryScheduled = false;
                    }
                }
            }, cancellationToken);
        }

        private void Publish(
            AppUpdateState state,
            string stageText,
            string statusMessage,
            bool isMandatory,
            bool isProgressVisible,
            double progressValue,
            string? availableVersion) {
            var normalizedProgress = Math.Clamp(progressValue, 0, 1);
            var snapshot = new AppUpdateSnapshot(
                State: state,
                StageText: stageText,
                StatusMessage: statusMessage,
                IsMandatoryUpdateAvailable: isMandatory,
                IsProgressVisible: isProgressVisible,
                ProgressValue: normalizedProgress,
                InstalledVersion: _versionProvider.GetInstalledVersionText(),
                AvailableVersion: availableVersion);

            Snapshot = snapshot;

            try {
                SnapshotChanged?.Invoke(snapshot);
            }
            catch (Exception ex) {
                JsonLogStore.Error("snapshot_subscriber_failed", "Snapshot subscriber failed.", "updater", ex);
            }
        }
    }
}
