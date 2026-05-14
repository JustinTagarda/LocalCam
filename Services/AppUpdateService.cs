using LocalCam.Models;

namespace LocalCam.Services {
    internal sealed class AppUpdateService : IAppUpdateService {
        private static readonly TimeSpan StartupDelay = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan CheckRetryDelay = TimeSpan.FromMinutes(5);

        private readonly IAppVersionProvider _versionProvider;
        private readonly IStoreUpdateClient _storeUpdateClient;
        private readonly Func<bool> _isAppBusy;
        private readonly object _syncRoot = new();
        private bool _started;
        private bool _retryScheduled;
        private bool _applyInProgress;
        private IReadOnlyList<StorePackageUpdateInfo> _downloadedUpdates = [];
        private string? _downloadedAvailableVersion;
        private bool _downloadedHasMandatory;

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
                IsRestartRequired: false,
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

            try {
                await Task.Delay(StartupDelay, cancellationToken);
                await RunUpdateFlowAsync(cancellationToken);
            }
            catch (OperationCanceledException) {
            }
            catch (Exception ex) {
                JsonLogStore.Error("background_task_failed", "Background updater task failed.", "updater", ex);
            }
        }

        public async Task<bool> ApplyUpdateAsync(CancellationToken cancellationToken) {
            if (!_versionProvider.IsPackaged()) {
                JsonLogStore.Information("update_install_skipped_unpacked", "Store update install skipped because app is unpackaged.", "updater");
                return false;
            }

            if (!_storeUpdateClient.SupportsStoreApis) {
                Publish(AppUpdateState.Deferred, "Store updater active", "Microsoft Store update APIs are unavailable.", false, false, 0, false, null);
                JsonLogStore.Warning("update_install_skipped_store_api_unavailable", "Store update install skipped because Store APIs are unavailable.", "updater");
                return false;
            }

            IReadOnlyList<StorePackageUpdateInfo> updates;
            string? availableVersion;
            bool hasMandatory;
            lock (_syncRoot) {
                if (_applyInProgress) {
                    return false;
                }

                _applyInProgress = true;
                updates = _downloadedUpdates.ToArray();
                availableVersion = _downloadedAvailableVersion;
                hasMandatory = _downloadedHasMandatory;
            }

            try {
                if (updates.Count == 0) {
                    Publish(AppUpdateState.Deferred, "Update deferred", "No downloaded Store update is ready yet. Will retry automatically.", false, false, 0, false, null);
                    JsonLogStore.Warning("update_install_skipped_no_download", "Store update install skipped because no downloaded update is cached.", "updater");
                    ScheduleRetry(CheckRetryDelay, cancellationToken);
                    return false;
                }

                if (_isAppBusy()) {
                    Publish(AppUpdateState.Deferred, "Update ready", "Close active work before restarting to finish the update.", hasMandatory, false, 1, true, availableVersion);
                    JsonLogStore.Information("update_install_deferred_app_busy", "User-initiated Store update install deferred because app is busy.", "updater");
                    return false;
                }

                JsonLogStore.Information("user_initiated_update_install_started", "User initiated Store update install boundary.", "updater", new Dictionary<string, object?> {
                    ["updateCount"] = updates.Count,
                    ["isMandatory"] = hasMandatory,
                    ["availableVersion"] = availableVersion
                });
                Publish(AppUpdateState.Installing, "Installing update", "Installing Store update. The app may close.", hasMandatory, true, 0, false, availableVersion);

                var installSucceeded = await _storeUpdateClient.DownloadAndInstallUpdatesAsync(updates, new Progress<double>(value => {
                    Publish(AppUpdateState.Installing, "Installing update", "Installing Store update. The app may close.", hasMandatory, true, value, false, availableVersion);
                }), cancellationToken);

                if (!installSucceeded) {
                    Publish(AppUpdateState.Deferred, "Update ready", "Install did not complete. Restart again when ready.", hasMandatory, false, 1, true, availableVersion);
                    JsonLogStore.Warning("install_failed", "Store install failed.", "updater", new Dictionary<string, object?> {
                        ["updateCount"] = updates.Count,
                        ["availableVersion"] = availableVersion
                    });
                    ScheduleRetry(CheckRetryDelay, cancellationToken);
                    return false;
                }

                Publish(AppUpdateState.Completed, "Update installed", "Update installed. Restart required.", hasMandatory, false, 1, true, availableVersion);
                JsonLogStore.Information("install_completed", "Store update install completed.", "updater", new Dictionary<string, object?> {
                    ["updateCount"] = updates.Count,
                    ["availableVersion"] = availableVersion
                });
                return true;
            }
            catch (OperationCanceledException) {
                return false;
            }
            catch (Exception ex) {
                Publish(AppUpdateState.Deferred, "Update ready", "Install did not complete. Restart again when ready.", hasMandatory, false, 1, true, availableVersion);
                JsonLogStore.Error("install_failed", "Store install failed.", "updater", ex, new Dictionary<string, object?> {
                    ["updateCount"] = updates.Count,
                    ["availableVersion"] = availableVersion
                });
                ScheduleRetry(CheckRetryDelay, cancellationToken);
                return false;
            }
            finally {
                lock (_syncRoot) {
                    _applyInProgress = false;
                }
            }
        }

        private async Task RunUpdateFlowAsync(CancellationToken cancellationToken) {
            if (!_versionProvider.IsPackaged()) {
                ClearDownloadedUpdate();
                Publish(AppUpdateState.Idle, "Idle", "Store updates are disabled in unpackaged builds.", false, false, 0, false, null);
                JsonLogStore.Information("update_check_skipped_unpacked", "Store update check skipped because app is unpackaged.", "updater");
                return;
            }

            if (!_storeUpdateClient.SupportsStoreApis) {
                ClearDownloadedUpdate();
                Publish(
                    AppUpdateState.Deferred,
                    "Store updater active",
                    "This packaged build relies on Microsoft Store automatic updates.",
                    false,
                    false,
                    0,
                    false,
                    null);
                JsonLogStore.Warning("store_api_unavailable", "Store API integration is unavailable in the current runtime/toolchain.", "updater");
                return;
            }

            try {
                JsonLogStore.Information("update_check_started", "Store update check started.", "updater");
                Publish(AppUpdateState.Checking, "Checking for updates", "Checking Microsoft Store updates.", false, true, 0, false, null);

                var updates = await _storeUpdateClient.GetAvailableUpdatesAsync(cancellationToken);
                if (updates.Count == 0) {
                    ClearDownloadedUpdate();
                    Publish(AppUpdateState.Idle, "Idle", "App is up to date.", false, false, 0, false, null);
                    JsonLogStore.Information("no_updates_available", "No Store updates available.", "updater");
                    return;
                }

                var hasMandatory = updates.Any(update => update.IsMandatory);
                var availableVersion = updates.Select(update => update.Version).OrderByDescending(version => version).FirstOrDefault();
                Publish(AppUpdateState.UpdateAvailable, "Update available", "New version found. Preparing background update.", hasMandatory, false, 0, false, availableVersion);
                JsonLogStore.Information("updates_available", "Store updates are available.", "updater", new Dictionary<string, object?> {
                    ["updateCount"] = updates.Count,
                    ["isMandatory"] = hasMandatory,
                    ["availableVersion"] = availableVersion
                });

                if (!_storeUpdateClient.CanSilentlyDownloadStorePackageUpdates()) {
                    ClearDownloadedUpdate();
                    Publish(AppUpdateState.Deferred, "Update deferred", "Background Store download is currently unavailable. Will retry automatically.", hasMandatory, false, 0, false, availableVersion);
                    JsonLogStore.Warning("silent_download_unavailable", "Silent download capability unavailable.", "updater");
                    ScheduleRetry(CheckRetryDelay, cancellationToken);
                    return;
                }

                Publish(AppUpdateState.Downloading, "Downloading update", "Downloading Store update in the background.", hasMandatory, true, 0, false, availableVersion);
                var downloadSucceeded = await _storeUpdateClient.DownloadUpdatesAsync(updates, new Progress<double>(value => {
                    Publish(AppUpdateState.Downloading, "Downloading update", "Downloading Store update in the background.", hasMandatory, true, value, false, availableVersion);
                }), cancellationToken);

                if (!downloadSucceeded) {
                    ClearDownloadedUpdate();
                    Publish(AppUpdateState.Deferred, "Update deferred", "Download did not complete. Will retry automatically.", hasMandatory, false, 0, false, availableVersion);
                    JsonLogStore.Warning("download_failed", "Store download failed.", "updater");
                    ScheduleRetry(CheckRetryDelay, cancellationToken);
                    return;
                }

                lock (_syncRoot) {
                    _downloadedUpdates = updates.ToArray();
                    _downloadedAvailableVersion = availableVersion;
                    _downloadedHasMandatory = hasMandatory;
                }

                Publish(AppUpdateState.Deferred, "Update ready", "Update downloaded. Restart required to finish installing.", hasMandatory, false, 1, true, availableVersion);
                JsonLogStore.Information("download_completed", "Store update download completed; install deferred to user restart action.", "updater", new Dictionary<string, object?> {
                    ["updateCount"] = updates.Count,
                    ["isMandatory"] = hasMandatory,
                    ["availableVersion"] = availableVersion
                });
            }
            catch (OperationCanceledException) {
            }
            catch (Exception ex) {
                ClearDownloadedUpdate();
                Publish(AppUpdateState.Failed, "Update check failed", "Unable to complete Store update check. Will retry automatically.", false, false, 0, false, null);
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

            JsonLogStore.Information("background_retry_scheduled", "Background updater retry scheduled.", "updater", new Dictionary<string, object?> {
                ["delaySeconds"] = delay.TotalSeconds
            });

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

        private void ClearDownloadedUpdate() {
            lock (_syncRoot) {
                _downloadedUpdates = [];
                _downloadedAvailableVersion = null;
                _downloadedHasMandatory = false;
            }
        }

        private void Publish(
            AppUpdateState state,
            string stageText,
            string statusMessage,
            bool isMandatory,
            bool isProgressVisible,
            double progressValue,
            bool isRestartRequired,
            string? availableVersion) {
            var normalizedProgress = Math.Clamp(progressValue, 0, 1);
            var snapshot = new AppUpdateSnapshot(
                State: state,
                StageText: stageText,
                StatusMessage: statusMessage,
                IsMandatoryUpdateAvailable: isMandatory,
                IsProgressVisible: isProgressVisible,
                ProgressValue: normalizedProgress,
                IsRestartRequired: isRestartRequired,
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
