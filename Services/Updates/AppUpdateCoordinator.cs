using LocalCam.Models;
using LocalCam.Services.Store;

namespace LocalCam.Services.Updates {
    internal sealed class AppUpdateCoordinator : IAppUpdateCoordinator {
        private const string Category = "updater";
        private static readonly TimeSpan MinimumCheckInterval = TimeSpan.FromHours(12);
        private static readonly TimeSpan MinimumRetryInterval = TimeSpan.FromHours(12);
        private readonly object _syncRoot = new();
        private readonly IStoreUpdateClient _storeUpdateClient;
        private readonly IStoreNavigationService _storeNavigationService;
        private readonly IAppVersionProvider _versionProvider;
        private readonly IDeferredUpdateStateStore _stateStore;
        private readonly Func<CancellationToken, Task<StoreUpdateOperationResult>> _runStoreFallbackUiAsync;
        private DeferredUpdateState? _cachedState;
        private readonly SemaphoreSlim _operationGate = new(1, 1);

        public AppUpdateCoordinator(
            IStoreUpdateClient storeUpdateClient,
            IStoreNavigationService storeNavigationService,
            IAppVersionProvider versionProvider,
            IDeferredUpdateStateStore stateStore,
            Func<CancellationToken, Task<StoreUpdateOperationResult>> runStoreFallbackUiAsync) {
            _storeUpdateClient = storeUpdateClient;
            _storeNavigationService = storeNavigationService;
            _versionProvider = versionProvider;
            _stateStore = stateStore;
            _runStoreFallbackUiAsync = runStoreFallbackUiAsync;
        }

        public async Task<bool> HasDeferredInstallPendingAsync(CancellationToken cancellationToken) {
            try {
                var state = await LoadStateAsync(cancellationToken);
                return state?.InstallDeferred == true;
            }
            catch (OperationCanceledException) {
                throw;
            }
            catch (Exception ex) {
                JsonLogStore.Error("store_update_deferred_state_probe_failed", "Failed to read deferred update state.", Category, ex);
                return false;
            }
        }

        public async Task RunStartupUpdateFlowAsync(CancellationToken cancellationToken) {
            await _operationGate.WaitAsync(cancellationToken);
            try {
                if (!_versionProvider.IsPackaged() || !_storeUpdateClient.SupportsStoreApis) {
                    JsonLogStore.Information("store_update_skipped_runtime", "Store update check skipped because Store update APIs are unavailable for this runtime context.", Category);
                    lock (_syncRoot) {
                        _cachedState = null;
                    }
                    return;
                }

                var existingState = await LoadStateAsync(cancellationToken);
                var checkUtc = DateTimeOffset.UtcNow;
                if (existingState is not null && existingState.InstallDeferred) {
                    JsonLogStore.Information("store_update_deferred_pending", "Startup Store update check found deferred install state and will wait for exit-time install.", Category, BuildStateLogData(existingState));
                }

                if (existingState is not null &&
                    existingState.LastFailureUtc is not null &&
                    existingState.PackageIdentitySnapshot is not null &&
                    !existingState.InstallDeferred &&
                    DateTimeOffset.UtcNow - existingState.LastFailureUtc < MinimumRetryInterval) {
                    existingState.LastCheckUtc = checkUtc;
                    await SaveStateAsync(existingState, cancellationToken);
                    JsonLogStore.Information("store_update_throttled", "Startup Store update check skipped because a recent failed exit-time install is still within the retry throttle window.", Category, BuildStateLogData(existingState));
                    return;
                }

                JsonLogStore.Information("store_update_check_started", "Startup Store update check started.", Category);
                var updates = await _storeUpdateClient.GetAvailableUpdatesAsync(cancellationToken);
                var state = existingState ?? new DeferredUpdateState();
                state.LastCheckUtc = checkUtc;

                if (updates.Count == 0) {
                    await ClearStateAsync(cancellationToken);
                    JsonLogStore.Information("store_update_check_no_updates", "Startup Store update check completed with no updates.", Category);
                    return;
                }

                var snapshot = BuildPackageIdentitySnapshot(updates);
                state.LastAvailableUtc = checkUtc;
                state.PackageFamilyName = updates[0].PackageFamilyName;
                state.AvailableVersion = updates[0].Version;
                state.PackageIdentitySnapshot = snapshot;

                JsonLogStore.Information("store_update_available", "Startup Store update check found updates.", Category, new Dictionary<string, object?> {
                    ["updateCount"] = updates.Count,
                    ["isSilentCapable"] = _storeUpdateClient.CanSilentlyDownloadStorePackageUpdates(),
                    ["packageIdentitySnapshot"] = snapshot
                });

                if (HasDeferredUpdateForSnapshot(existingState, snapshot)) {
                    existingState!.LastCheckUtc = checkUtc;
                    existingState.LastAvailableUtc = checkUtc;
                    existingState.PackageFamilyName = state.PackageFamilyName;
                    existingState.AvailableVersion = state.AvailableVersion;
                    existingState.PackageIdentitySnapshot = snapshot;
                    await SaveStateAsync(existingState, cancellationToken);
                    lock (_syncRoot) {
                        _cachedState = existingState;
                    }

                    JsonLogStore.Information("store_update_deferred_already_saved", "Startup Store update check confirmed an existing deferred update state for the current package identity.", Category, BuildStateLogData(existingState!));
                    return;
                }

                if (ShouldThrottleNewDeferredState(existingState, snapshot)) {
                    existingState!.LastCheckUtc = checkUtc;
                    existingState.LastAvailableUtc = checkUtc;
                    existingState.PackageFamilyName = state.PackageFamilyName;
                    existingState.AvailableVersion = state.AvailableVersion;
                    existingState.PackageIdentitySnapshot = snapshot;
                    await SaveStateAsync(existingState, cancellationToken);
                    JsonLogStore.Information("store_update_deferred_throttled", "Startup Store update check skipped recreating deferred install state because a recent close-time install failure is still throttled.", Category, BuildStateLogData(existingState!));
                    return;
                }

                if (_storeUpdateClient.CanSilentlyDownloadStorePackageUpdates()) {
                    var downloaded = await _storeUpdateClient.DownloadUpdatesAsync(updates, progress: null, cancellationToken);
                    if (downloaded) {
                        if (!ShouldPersistDeferredInstallState(existingState, snapshot)) {
                            await ClearStateAsync(cancellationToken);
                            JsonLogStore.Information("store_update_silent_download_not_persisted", "Silent Store update download completed but deferred install state was not persisted because the retry policy blocked it.", Category, new Dictionary<string, object?> {
                                ["packageIdentitySnapshot"] = snapshot,
                                ["existingState"] = existingState is null ? null : BuildStateLogData(existingState)
                            });
                            return;
                        }

                        state.InstallDeferred = true;
                        state.LastDownloadUtc = checkUtc;
                        state.RetryCount = 0;
                        state.LastFailureUtc = null;
                        state.LastFailureCategory = null;
                        state.LastInstallAttemptUtc = null;
                        state.LastInstallSuccessUtc = null;
                        state.LastSuccessUtc = null;
                        await SaveStateAsync(state, cancellationToken);
                        JsonLogStore.Information("store_update_silent_download_completed", "Silent Store update download completed during startup flow and install was deferred until exit.", Category, BuildStateLogData(state));
                        return;
                    }

                    JsonLogStore.Warning("store_update_silent_download_failed", "Silent Store update download did not complete; fallback update UI may be shown.", Category, BuildStateLogData(state));
                }
                else {
                    JsonLogStore.Information("store_update_silent_unavailable", "Silent Store update download is unavailable and the startup flow will use fallback Store/OS update UI.", Category, BuildStateLogData(state));
                }

                var fallbackResult = await _runStoreFallbackUiAsync(cancellationToken);
                if (fallbackResult.Succeeded) {
                    await ClearStateAsync(cancellationToken);
                    JsonLogStore.Information("store_update_fallback_completed", "Store fallback update UI completed successfully.", Category);
                    return;
                }

                await ClearStateAsync(cancellationToken);
                JsonLogStore.Warning("store_update_fallback_not_completed", "Store fallback update UI did not complete update installation.", Category, new Dictionary<string, object?> {
                    ["state"] = fallbackResult.State.ToString(),
                    ["statusMessage"] = fallbackResult.StatusMessage,
                    ["wasAttempted"] = fallbackResult.WasAttempted
                });
            }
            catch (OperationCanceledException) {
            }
            catch (Exception ex) {
                JsonLogStore.Error("store_update_flow_failed", "Startup Store update flow failed.", Category, ex);
            }
            finally {
                _operationGate.Release();
            }
        }

        public async Task<StoreUpdateCheckResult> RunUserInitiatedUpdateFlowAsync(CancellationToken cancellationToken) {
            await _operationGate.WaitAsync(cancellationToken);
            try {
                if (!_versionProvider.IsPackaged() || !_storeUpdateClient.SupportsStoreApis) {
                    JsonLogStore.Information("store_update_user_flow_skipped_runtime", "User-initiated Store update flow skipped because Store update APIs are unavailable for this runtime context.", Category);
                    return new StoreUpdateCheckResult(StoreUpdateCheckState.Unavailable, "Update check unavailable.", null);
                }

                JsonLogStore.Information("store_update_user_check_started", "User-initiated Store update check started.", Category);
                var updates = await _storeUpdateClient.GetAvailableUpdatesAsync(cancellationToken);
                if (updates.Count == 0) {
                    await ClearStaleDeferredStateAsync(cancellationToken);
                    JsonLogStore.Information("store_update_user_no_updates", "User-initiated Store update check completed with no updates.", Category);
                    return new StoreUpdateCheckResult(StoreUpdateCheckState.NotAvailable, "No update available", null);
                }

                var snapshot = BuildPackageIdentitySnapshot(updates);
                JsonLogStore.Information("store_update_user_available", "User-initiated Store update check found updates.", Category, new Dictionary<string, object?> {
                    ["updateCount"] = updates.Count,
                    ["packageIdentitySnapshot"] = snapshot,
                    ["isMandatory"] = updates.Any(update => update.IsMandatory)
                });

                var opened = await _storeNavigationService.OpenStoreUpdatesPageAsync(cancellationToken).ConfigureAwait(false);
                if (opened) {
                    JsonLogStore.Information("store_update_user_store_page_opened", "User-initiated Store update flow opened the Microsoft Store updates page.", Category, new Dictionary<string, object?> {
                        ["packageIdentitySnapshot"] = snapshot
                    });
                    return new StoreUpdateCheckResult(StoreUpdateCheckState.Available, "Update available. Opening Microsoft Store.", updates[0].Version);
                }

                JsonLogStore.Warning("store_update_user_store_page_open_failed", "User-initiated Store update flow could not open the Microsoft Store updates page.", Category, new Dictionary<string, object?> {
                    ["packageIdentitySnapshot"] = snapshot
                });
                return new StoreUpdateCheckResult(StoreUpdateCheckState.Failed, "Update available, but Microsoft Store could not be opened.", updates[0].Version);
            }
            catch (OperationCanceledException) {
                throw;
            }
            catch (Exception ex) {
                JsonLogStore.Error("store_update_user_flow_failed", "User-initiated Store update flow failed.", Category, ex);
                return new StoreUpdateCheckResult(StoreUpdateCheckState.Failed, "Update check failed.", null);
            }
            finally {
                _operationGate.Release();
            }
        }

        public async Task<StoreUpdateOperationResult> RunDeferredInstallOnExitAsync(IProgress<double>? progress, CancellationToken cancellationToken) {
            await _operationGate.WaitAsync(cancellationToken);
            try {
                var state = await LoadStateAsync(cancellationToken);
                if (!HasDeferredUpdateForSnapshot(state, state?.PackageIdentitySnapshot)) {
                    return new StoreUpdateOperationResult(StoreUpdateOperationState.Unknown, "No deferred update install is pending.", 0, WasAttempted: false);
                }

                try {
                    var updates = await _storeUpdateClient.GetAvailableUpdatesAsync(cancellationToken);
                    if (updates.Count == 0) {
                        await ClearStateAsync(cancellationToken);
                        JsonLogStore.Information("store_update_exit_install_stale_state_cleared", "Deferred update install state was cleared because no Store updates are currently available.", Category, BuildStateLogData(state!));
                        return new StoreUpdateOperationResult(StoreUpdateOperationState.Unknown, "Deferred update is no longer available.", 0, WasAttempted: false);
                    }

                    var snapshot = BuildPackageIdentitySnapshot(updates);
                    if (!HasDeferredUpdateForSnapshot(state, snapshot)) {
                        await ClearStateAsync(cancellationToken);
                        JsonLogStore.Information("store_update_exit_install_snapshot_mismatch", "Deferred update install state was cleared because the available Store update snapshot changed.", Category, new Dictionary<string, object?> {
                            ["currentSnapshot"] = snapshot,
                            ["storedSnapshot"] = state?.PackageIdentitySnapshot
                        });
                        return new StoreUpdateOperationResult(StoreUpdateOperationState.Unknown, "Deferred update is stale.", 0, WasAttempted: false);
                    }

                    if (ShouldThrottleExitInstallRetry(state!, snapshot)) {
                        JsonLogStore.Information("store_update_exit_install_throttled", "Deferred update install was skipped because the retry throttle window has not elapsed.", Category, BuildStateLogData(state!));
                        return new StoreUpdateOperationResult(StoreUpdateOperationState.Unknown, "Deferred update retry is throttled.", 0, WasAttempted: false);
                    }

                    var workingState = state!;
                    workingState.LastInstallAttemptUtc = DateTimeOffset.UtcNow;
                    workingState.RetryCount = Math.Max(workingState.RetryCount, 0);
                    workingState.PackageIdentitySnapshot = snapshot;
                    workingState.LastFailureCategory = null;
                    await SaveStateAsync(workingState, cancellationToken);

                    JsonLogStore.Information("store_update_exit_install_started", "Deferred update install started during app close.", Category, BuildStateLogData(workingState));

                    var installed = await _storeUpdateClient.DownloadAndInstallUpdatesAsync(updates, progress, cancellationToken);
                    if (installed) {
                        await ClearStateAsync(cancellationToken);
                        JsonLogStore.Information("store_update_exit_install_completed", "Deferred update install completed successfully during app close.", Category, new Dictionary<string, object?> {
                            ["packageIdentitySnapshot"] = snapshot
                        });
                        return new StoreUpdateOperationResult(StoreUpdateOperationState.Completed, "Deferred update installed successfully.", 1, WasAttempted: true);
                    }

                    return await RecordExitInstallFailureAsync(workingState, snapshot, "silent_install_failed", StoreUpdateOperationState.OtherError, "Deferred update install did not complete.", cancellationToken);
                }
                catch (OperationCanceledException) {
                    return await RecordExitInstallFailureAsync(state!, state!.PackageIdentitySnapshot!, "silent_install_canceled", StoreUpdateOperationState.Canceled, "Deferred update install was canceled or timed out.", cancellationToken);
                }
                catch (Exception ex) {
                    JsonLogStore.Error("store_update_exit_install_query_failed", "Deferred update install could not recheck Store updates before install.", Category, ex);
                    return await RecordExitInstallFailureAsync(state!, state!.PackageIdentitySnapshot!, "store_query_failed", StoreUpdateOperationState.OtherError, "Deferred update install could not recheck Store updates.", cancellationToken);
                }
            }
            catch (OperationCanceledException) {
                throw;
            }
            catch (Exception ex) {
                JsonLogStore.Error("store_update_exit_install_failed", "Deferred update install flow failed.", Category, ex);
                return new StoreUpdateOperationResult(StoreUpdateOperationState.OtherError, "Deferred update install failed.", 0, WasAttempted: true);
            }
            finally {
                _operationGate.Release();
            }
        }

        private async Task<StoreUpdateOperationResult> RecordExitInstallFailureAsync(
            DeferredUpdateState state,
            string snapshot,
            string failureCategory,
            StoreUpdateOperationState resultState,
            string statusMessage,
            CancellationToken cancellationToken) {
            state.InstallDeferred = false;
            state.PackageIdentitySnapshot = snapshot;
            state.LastFailureUtc = DateTimeOffset.UtcNow;
            state.LastInstallAttemptUtc = DateTimeOffset.UtcNow;
            state.LastFailureCategory = failureCategory;
            state.RetryCount = Math.Max(1, state.RetryCount + 1);
            state.LastSuccessUtc = null;
            await SaveStateAsync(state, cancellationToken);
            JsonLogStore.Warning("store_update_exit_install_not_completed", "Deferred update install did not complete during app close.", Category, BuildStateLogData(state));
            return new StoreUpdateOperationResult(resultState, statusMessage, 0, WasAttempted: true);
        }

        private async Task<DeferredUpdateState?> LoadStateAsync(CancellationToken cancellationToken) {
            var state = await _stateStore.LoadAsync(cancellationToken);
            lock (_syncRoot) {
                _cachedState = state;
            }

            return state;
        }

        private async Task SaveStateAsync(DeferredUpdateState state, CancellationToken cancellationToken) {
            await _stateStore.SaveAsync(state, cancellationToken);
            lock (_syncRoot) {
                _cachedState = state;
            }
        }

        private async Task ClearStateAsync(CancellationToken cancellationToken) {
            await _stateStore.ClearAsync(cancellationToken);
            lock (_syncRoot) {
                _cachedState = null;
            }
        }

        private async Task ClearStaleDeferredStateAsync(CancellationToken cancellationToken) {
            var current = await LoadStateAsync(cancellationToken);
            if (current is null) {
                return;
            }

            if (!current.InstallDeferred) {
                return;
            }

            await ClearStateAsync(cancellationToken);
        }

        private static bool HasDeferredUpdateForSnapshot(DeferredUpdateState? state, string? snapshot) {
            return state is not null &&
                   state.InstallDeferred &&
                   !string.IsNullOrWhiteSpace(state.PackageIdentitySnapshot) &&
                   !string.IsNullOrWhiteSpace(snapshot) &&
                   string.Equals(state.PackageIdentitySnapshot, snapshot, StringComparison.OrdinalIgnoreCase);
        }

        private static bool ShouldThrottleNewDeferredState(DeferredUpdateState? state, string snapshot) {
            if (state is null || string.IsNullOrWhiteSpace(state.PackageIdentitySnapshot)) {
                return false;
            }

            if (!string.Equals(state.PackageIdentitySnapshot, snapshot, StringComparison.OrdinalIgnoreCase)) {
                return false;
            }

            if (state.InstallDeferred) {
                return false;
            }

            return state.LastFailureUtc is not null &&
                   DateTimeOffset.UtcNow - state.LastFailureUtc < MinimumRetryInterval;
        }

        private static bool ShouldPersistDeferredInstallState(DeferredUpdateState? existingState, string snapshot) {
            if (existingState is null) {
                return true;
            }

            if (existingState.InstallDeferred && string.Equals(existingState.PackageIdentitySnapshot, snapshot, StringComparison.OrdinalIgnoreCase)) {
                return true;
            }

            return !ShouldThrottleNewDeferredState(existingState, snapshot);
        }

        private static bool ShouldThrottleExitInstallRetry(DeferredUpdateState state, string snapshot) {
            if (!string.Equals(state.PackageIdentitySnapshot, snapshot, StringComparison.OrdinalIgnoreCase)) {
                return false;
            }

            if (state.LastFailureUtc is null) {
                return false;
            }

            if (state.RetryCount <= 0) {
                return false;
            }

            return DateTimeOffset.UtcNow - state.LastFailureUtc < MinimumRetryInterval;
        }

        private static string BuildPackageIdentitySnapshot(IReadOnlyList<StorePackageUpdateInfo> updates) {
            return string.Join(
                "|",
                updates
                    .OrderBy(update => update.PackageFamilyName, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(update => update.Version, StringComparer.OrdinalIgnoreCase)
                    .Select(update => update.PackageIdentitySnapshot));
        }

        private static IReadOnlyDictionary<string, object?> BuildStateLogData(DeferredUpdateState state) {
            return new Dictionary<string, object?> {
                ["installDeferred"] = state.InstallDeferred,
                ["retryCount"] = state.RetryCount,
                ["packageFamilyName"] = state.PackageFamilyName,
                ["availableVersion"] = state.AvailableVersion,
                ["packageIdentitySnapshot"] = state.PackageIdentitySnapshot,
                ["lastCheckUtc"] = state.LastCheckUtc,
                ["lastAvailableUtc"] = state.LastAvailableUtc,
                ["lastDownloadUtc"] = state.LastDownloadUtc,
                ["lastInstallAttemptUtc"] = state.LastInstallAttemptUtc,
                ["lastInstallSuccessUtc"] = state.LastInstallSuccessUtc,
                ["lastFailureUtc"] = state.LastFailureUtc,
                ["lastFailureCategory"] = state.LastFailureCategory,
                ["lastSuccessUtc"] = state.LastSuccessUtc
            };
        }
    }
}
