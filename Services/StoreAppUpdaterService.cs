using Windows.Foundation;
using Windows.Services.Store;
using LocalCam.Models;

namespace LocalCam.Services {
    internal sealed class StoreAppUpdaterService {
        private const string StoreDiagnosticsCategory = "store_update";
        private static readonly TimeSpan CheckCooldown = TimeSpan.FromMinutes(30);
        private static readonly TimeSpan CheckWindow = TimeSpan.FromHours(24);
        private const int MaxChecksPerWindow = 10;
        private static readonly TimeSpan RetryDelay = TimeSpan.FromHours(1);

        private readonly IStoreContextProvider _storeContextProvider;
        private readonly Func<IntPtr> _ownerWindowHandleProvider;
        private readonly Action<StoreUpdateUiState> _stateCallback;
        private readonly Func<LocalCamSettings> _settingsProvider;
        private readonly Action _persistSettings;
        private readonly List<StorePackageUpdate> _cachedUpdates = new();
        private readonly List<DateTimeOffset> _checkHistoryUtc = new();
        private readonly List<StoreQueueItem> _trackedQueueItems = new();
        private readonly object _sync = new();

        private CancellationTokenSource? _retryCts;
        private StoreContext? _storeContext;
        private IAsyncOperationWithProgress<StorePackageUpdateResult, StorePackageUpdateStatus>? _activeInstallOperation;
        private bool _isShutdown;
        private bool _isUpdateInProgress;

        public StoreAppUpdaterService(
            IStoreContextProvider storeContextProvider,
            Func<IntPtr> ownerWindowHandleProvider,
            Func<LocalCamSettings> settingsProvider,
            Action persistSettings,
            Action<StoreUpdateUiState> stateCallback) {
            _storeContextProvider = storeContextProvider;
            _ownerWindowHandleProvider = ownerWindowHandleProvider;
            _stateCallback = stateCallback;
            _settingsProvider = settingsProvider;
            _persistSettings = persistSettings;
        }

        public async Task InitializeAfterFirstRenderAsync(CancellationToken cancellationToken) {
            var packaged = TryResolveStoreRuntime(out _storeContext);
            if (!packaged || _storeContext is null) {
                PushState(StoreUpdateUiState.Hidden());
                return;
            }

            LoadCheckHistory();
            await RestoreQueueStateAsync(_storeContext, cancellationToken).ConfigureAwait(false);
            if (_isUpdateInProgress) {
                return;
            }

            await CheckAvailabilityAsync(_storeContext, hidden: true, cancellationToken).ConfigureAwait(false);
        }

        public async Task StartUpdateAsync(CancellationToken cancellationToken) {
            if (_isUpdateInProgress) {
                return;
            }

            if (!TryResolveStoreRuntime(out _storeContext) || _storeContext is null) {
                PushState(StoreUpdateUiState.Hidden());
                return;
            }

            var updates = await ResolveUpdatesForInstallAsync(_storeContext, cancellationToken).ConfigureAwait(false);
            if (updates.Count == 0) {
                var state = StoreUpdateUiState.Hidden();
                PushState(state);
                PersistLastKnownUiState(state);
                return;
            }

            _isUpdateInProgress = true;
            PushState(new StoreUpdateUiState(
                IsUpdateButtonVisible: true,
                IsUpdateButtonEnabled: false,
                IsProgressVisible: true,
                PhaseText: "Preparing",
                ProgressPercent: 0,
                DetailText: "Preparing Microsoft Store update...",
                ResultText: string.Empty));

            try {
                _activeInstallOperation = _storeContext.RequestDownloadAndInstallStorePackageUpdatesAsync(updates);
                _activeInstallOperation.Progress = (_, progress) => HandleProgress(progress);
                var result = await _activeInstallOperation;
                HandleTerminalState(result.OverallState);
            }
            catch (OperationCanceledException) {
                HandleTerminalText("Canceled", "Update canceled.");
            }
            catch (Exception ex) {
                JsonLogStore.Error(
                    eventName: "store_update_install_failed",
                    message: "Store update request failed.",
                    category: StoreDiagnosticsCategory,
                    exception: ex);
                HandleTerminalText("Failed", "Failed. Retry later.");
            }
            finally {
                _activeInstallOperation = null;
                _isUpdateInProgress = false;
                await CheckAvailabilityAsync(_storeContext, hidden: false, cancellationToken).ConfigureAwait(false);
            }
        }

        public void Shutdown() {
            _isShutdown = true;
            lock (_sync) {
                _retryCts?.Cancel();
                _retryCts?.Dispose();
                _retryCts = null;
            }

            foreach (var item in _trackedQueueItems) {
                item.StatusChanged -= OnQueueItemStatusChanged;
            }
            _trackedQueueItems.Clear();
        }

        private async Task CheckAvailabilityAsync(StoreContext storeContext, bool hidden, CancellationToken cancellationToken) {
            if (_isShutdown) {
                return;
            }
            cancellationToken.ThrowIfCancellationRequested();

            var now = DateTimeOffset.UtcNow;
            var (shouldCallStore, reason) = EvaluateThrottle(now);
            var resultCount = _cachedUpdates.Count;
            if (shouldCallStore) {
                RecordCheck(now);
                try {
                    var updates = await storeContext.GetAppAndOptionalStorePackageUpdatesAsync();
                    cancellationToken.ThrowIfCancellationRequested();
                    CacheUpdates(updates);
                    resultCount = updates.Count;
                    JsonLogStore.Information(
                        eventName: "store_update_check_completed",
                        message: "Store update availability check completed.",
                        category: StoreDiagnosticsCategory,
                        data: BuildCheckDiagnosticsData(updates.Count, skipped: false, reason: string.Empty));
                }
                catch (Exception ex) {
                    JsonLogStore.Error(
                        eventName: "store_update_check_failed",
                        message: "Store update availability check failed.",
                        category: StoreDiagnosticsCategory,
                        exception: ex,
                        data: BuildCheckDiagnosticsData(0, skipped: false, reason: string.Empty));
                    PushState(StoreUpdateUiState.Hidden());
                    return;
                }
            }
            else {
                JsonLogStore.Information(
                    eventName: "store_update_check_skipped",
                    message: "Store update availability check skipped due to local throttle policy.",
                    category: StoreDiagnosticsCategory,
                    data: BuildCheckDiagnosticsData(resultCount, skipped: true, reason));
            }

            if (_cachedUpdates.Count > 0) {
                var availableState = StoreUpdateUiState.IdleAvailable();
                PushState(availableState);
                PersistLastKnownUiState(availableState);
            }
            else {
                PushState(GetLastKnownUiState());
                if (hidden || shouldCallStore) {
                    ScheduleRetry();
                }
            }
        }

        private async Task<IReadOnlyList<StorePackageUpdate>> ResolveUpdatesForInstallAsync(StoreContext context, CancellationToken cancellationToken) {
            if (_cachedUpdates.Count > 0) {
                return _cachedUpdates.ToArray();
            }

            cancellationToken.ThrowIfCancellationRequested();
            var updates = await context.GetAppAndOptionalStorePackageUpdatesAsync();
            cancellationToken.ThrowIfCancellationRequested();
            CacheUpdates(updates);
            return _cachedUpdates.ToArray();
        }

        private void CacheUpdates(IEnumerable<StorePackageUpdate> updates) {
            _cachedUpdates.Clear();
            foreach (var update in updates) {
                _cachedUpdates.Add(update);
            }
        }

        private void HandleProgress(StorePackageUpdateStatus status) {
            var stateText = status.PackageUpdateState switch {
                StorePackageUpdateState.Pending => "Preparing",
                StorePackageUpdateState.Downloading => "Downloading",
                StorePackageUpdateState.Deploying => "Installing",
                StorePackageUpdateState.Completed => "Completed",
                StorePackageUpdateState.Canceled => "Canceled",
                StorePackageUpdateState.OtherError => "Failed",
                StorePackageUpdateState.ErrorLowBattery => "Failed",
                StorePackageUpdateState.ErrorWiFiRecommended => "Failed",
                StorePackageUpdateState.ErrorWiFiRequired => "Failed",
                _ => "Preparing"
            };

            var percent = 0;
            if (status.TotalDownloadProgress > 0) {
                percent = Math.Clamp((int)Math.Round(status.TotalDownloadProgress * 100), 0, 100);
            }
            else if (status.PackageDownloadProgress > 0) {
                percent = Math.Clamp((int)Math.Round(status.PackageDownloadProgress * 100), 0, 100);
            }

            var detail = string.Empty;
            if (status.PackageDownloadSizeInBytes > 0) {
                detail = $"{status.PackageBytesDownloaded:n0}/{status.PackageDownloadSizeInBytes:n0} bytes";
            }

            var state = new StoreUpdateUiState(
                IsUpdateButtonVisible: true,
                IsUpdateButtonEnabled: false,
                IsProgressVisible: true,
                PhaseText: stateText,
                ProgressPercent: percent,
                DetailText: detail,
                ResultText: string.Empty);
            PushState(state);
            PersistLastKnownUiState(state);
        }

        private void HandleTerminalState(StorePackageUpdateState state) {
            if (state == StorePackageUpdateState.Completed) {
                _cachedUpdates.Clear();
                HandleTerminalText("Completed", "Completed.");
                return;
            }

            var resultText = state switch {
                StorePackageUpdateState.Canceled => "Canceled. Retry when ready.",
                StorePackageUpdateState.ErrorLowBattery => "Failed. Charge battery and retry.",
                StorePackageUpdateState.ErrorWiFiRecommended => "Failed. Connect to Wi-Fi and retry.",
                StorePackageUpdateState.ErrorWiFiRequired => "Failed. Wi-Fi is required.",
                _ => "Failed. Retry later."
            };

            HandleTerminalText(state == StorePackageUpdateState.Canceled ? "Canceled" : "Failed", resultText);
        }

        private void HandleTerminalText(string phase, string resultText) {
            var state = new StoreUpdateUiState(
                IsUpdateButtonVisible: _cachedUpdates.Count > 0,
                IsUpdateButtonEnabled: true,
                IsProgressVisible: true,
                PhaseText: phase,
                ProgressPercent: phase == "Completed" ? 100 : 0,
                DetailText: string.Empty,
                ResultText: resultText);
            PushState(state);
            PersistLastKnownUiState(state);
        }

        private bool TryResolveStoreRuntime(out StoreContext? context) {
            context = null;
            var packageIdentityPresent = _storeContextProvider.HasPackageIdentity;
            if (!packageIdentityPresent) {
                JsonLogStore.Information(
                    eventName: "store_update_runtime_not_packaged",
                    message: "Updater is unavailable because package identity is missing.",
                    category: StoreDiagnosticsCategory,
                    data: BuildCheckDiagnosticsData(0, skipped: true, reason: "not_packaged"));
                return false;
            }

            context = _storeContextProvider.TryGetStoreContext(_ownerWindowHandleProvider());
            if (context is null) {
                JsonLogStore.Warning(
                    eventName: "store_update_storecontext_unavailable",
                    message: "Updater is unavailable because StoreContext could not be created.",
                    category: StoreDiagnosticsCategory,
                    data: BuildCheckDiagnosticsData(0, skipped: true, reason: "store_context_unavailable"));
                return false;
            }

            return true;
        }

        private IReadOnlyDictionary<string, object?> BuildCheckDiagnosticsData(int resultCount, bool skipped, string reason) {
            return new Dictionary<string, object?> {
                ["packageIdentityPresent"] = _storeContextProvider.HasPackageIdentity,
                ["packageFullName"] = _storeContextProvider.TryGetPackageFullName() ?? "not_found",
                ["packageVersion"] = _storeContextProvider.TryGetPackageVersion() ?? "not_found",
                ["packageSignatureKind"] = _storeContextProvider.TryGetPackageSignatureKind() ?? "not_found",
                ["attemptUtc"] = DateTimeOffset.UtcNow,
                ["skipped"] = skipped,
                ["skipReason"] = reason,
                ["checksLast24Hours"] = _checkHistoryUtc.Count,
                ["resultCount"] = resultCount
            };
        }

        private (bool ShouldCallStore, string Reason) EvaluateThrottle(DateTimeOffset now) {
            PruneCheckHistory(now);
            if (_checkHistoryUtc.Count >= MaxChecksPerWindow) {
                return (false, "daily_limit_reached");
            }

            var lastCheck = _checkHistoryUtc.LastOrDefault();
            if (lastCheck != default && now - lastCheck < CheckCooldown) {
                return (false, "cooldown_active");
            }

            return (true, string.Empty);
        }

        private void RecordCheck(DateTimeOffset timestampUtc) {
            _checkHistoryUtc.Add(timestampUtc);
            PruneCheckHistory(timestampUtc);
            var settings = _settingsProvider();
            settings.StoreUpdateCheckHistoryUtc = _checkHistoryUtc.Select(v => v.UtcDateTime.ToString("O")).ToList();
            _persistSettings();
        }

        private void PruneCheckHistory(DateTimeOffset now) {
            _checkHistoryUtc.RemoveAll(ts => now - ts > CheckWindow);
        }

        private void LoadCheckHistory() {
            _checkHistoryUtc.Clear();
            var settings = _settingsProvider();
            foreach (var raw in settings.StoreUpdateCheckHistoryUtc) {
                if (DateTimeOffset.TryParse(raw, out var parsed)) {
                    _checkHistoryUtc.Add(parsed.ToUniversalTime());
                }
            }

            PruneCheckHistory(DateTimeOffset.UtcNow);
        }

        private void ScheduleRetry() {
            lock (_sync) {
                _retryCts?.Cancel();
                _retryCts?.Dispose();
                _retryCts = new CancellationTokenSource();
                var retryToken = _retryCts.Token;
                _ = Task.Run(async () => {
                    try {
                        await Task.Delay(RetryDelay, retryToken).ConfigureAwait(false);
                        if (retryToken.IsCancellationRequested || _isShutdown || _storeContext is null) {
                            return;
                        }

                        await CheckAvailabilityAsync(_storeContext, hidden: true, retryToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) {
                        // shutdown/next schedule replaces this retry
                    }
                }, retryToken);
            }
        }

        private async Task RestoreQueueStateAsync(StoreContext storeContext, CancellationToken cancellationToken) {
            try {
                cancellationToken.ThrowIfCancellationRequested();
                var queueItems = await storeContext.GetAssociatedStoreQueueItemsAsync();
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var tracked in _trackedQueueItems) {
                    tracked.StatusChanged -= OnQueueItemStatusChanged;
                }
                _trackedQueueItems.Clear();

                foreach (var item in queueItems) {
                    _trackedQueueItems.Add(item);
                    item.StatusChanged += OnQueueItemStatusChanged;
                }

                UpdateStateFromQueueItems();
            }
            catch (OperationCanceledException) {
                // App is shutting down.
            }
            catch (Exception ex) {
                JsonLogStore.Warning(
                    eventName: "store_update_queue_restore_failed",
                    message: "Failed to restore Store queue status.",
                    category: StoreDiagnosticsCategory,
                    data: new Dictionary<string, object?> {
                        ["exception"] = ex.Message
                    });
            }
        }

        private void OnQueueItemStatusChanged(StoreQueueItem sender, object args) {
            _ = sender;
            _ = args;
            UpdateStateFromQueueItems();
        }

        private void UpdateStateFromQueueItems() {
            if (_trackedQueueItems.Count == 0) {
                _isUpdateInProgress = false;
                return;
            }

            var active = _trackedQueueItems.FirstOrDefault(IsQueueItemInProgress);
            if (active is null) {
                _isUpdateInProgress = false;
                var terminal = _trackedQueueItems
                    .Select(item => item.GetCurrentStatus().UpdateStatus.PackageUpdateState)
                    .ToArray();
                if (terminal.Any(state => state == StorePackageUpdateState.Completed)) {
                    HandleQueueTerminalText("Completed", "Completed.");
                    return;
                }

                if (terminal.Any(state => state == StorePackageUpdateState.Canceled)) {
                    HandleQueueTerminalText("Canceled", "Canceled. Retry when ready.");
                    return;
                }

                if (terminal.Any(state => state == StorePackageUpdateState.ErrorLowBattery)) {
                    HandleQueueTerminalText("Failed", "Failed. Charge battery and retry.");
                    return;
                }

                if (terminal.Any(state => state == StorePackageUpdateState.ErrorWiFiRequired)) {
                    HandleQueueTerminalText("Failed", "Failed. Wi-Fi is required.");
                    return;
                }

                if (terminal.Any(state => state == StorePackageUpdateState.ErrorWiFiRecommended)) {
                    HandleQueueTerminalText("Failed", "Failed. Connect to Wi-Fi and retry.");
                    return;
                }

                if (terminal.Any(state => state == StorePackageUpdateState.OtherError)) {
                    HandleQueueTerminalText("Failed", "Failed. Retry later.");
                    return;
                }
                return;
            }

            var updateStatus = active.GetCurrentStatus().UpdateStatus;
            var phaseText = updateStatus.PackageUpdateState switch {
                StorePackageUpdateState.Pending => "Preparing",
                StorePackageUpdateState.Downloading => "Downloading",
                StorePackageUpdateState.Deploying => "Installing",
                StorePackageUpdateState.Completed => "Completed",
                StorePackageUpdateState.Canceled => "Canceled",
                StorePackageUpdateState.ErrorLowBattery => "Failed",
                StorePackageUpdateState.ErrorWiFiRecommended => "Failed",
                StorePackageUpdateState.ErrorWiFiRequired => "Failed",
                _ => "Failed"
            };
            var percent = 0;
            if (updateStatus.TotalDownloadProgress > 0) {
                percent = Math.Clamp((int)Math.Round(updateStatus.TotalDownloadProgress * 100), 0, 100);
            }
            else if (updateStatus.PackageDownloadProgress > 0) {
                percent = Math.Clamp((int)Math.Round(updateStatus.PackageDownloadProgress * 100), 0, 100);
            }
            var detail = updateStatus.PackageDownloadSizeInBytes > 0
                ? $"{updateStatus.PackageBytesDownloaded:n0}/{updateStatus.PackageDownloadSizeInBytes:n0} bytes"
                : string.Empty;

            _isUpdateInProgress = true;
            var state = new StoreUpdateUiState(
                IsUpdateButtonVisible: true,
                IsUpdateButtonEnabled: false,
                IsProgressVisible: true,
                PhaseText: phaseText,
                ProgressPercent: percent,
                DetailText: detail,
                ResultText: string.Empty);
            PushState(state);
            PersistLastKnownUiState(state);
        }

        private static bool IsQueueItemInProgress(StoreQueueItem queueItem) {
            var state = queueItem.GetCurrentStatus().UpdateStatus.PackageUpdateState;
            return state == StorePackageUpdateState.Pending ||
                   state == StorePackageUpdateState.Downloading ||
                   state == StorePackageUpdateState.Deploying;
        }

        private void HandleQueueTerminalText(string phase, string resultText) {
            var state = new StoreUpdateUiState(
                IsUpdateButtonVisible: true,
                IsUpdateButtonEnabled: true,
                IsProgressVisible: true,
                PhaseText: phase,
                ProgressPercent: phase == "Completed" ? 100 : 0,
                DetailText: string.Empty,
                ResultText: resultText);
            PushState(state);
            PersistLastKnownUiState(state);
        }

        private StoreUpdateUiState GetLastKnownUiState() {
            var settings = _settingsProvider();
            if (!settings.StoreUpdateLastKnownAvailable) {
                return StoreUpdateUiState.Hidden();
            }

            return new StoreUpdateUiState(
                IsUpdateButtonVisible: true,
                IsUpdateButtonEnabled: true,
                IsProgressVisible: !string.IsNullOrWhiteSpace(settings.StoreUpdateLastKnownPhase),
                PhaseText: settings.StoreUpdateLastKnownPhase ?? string.Empty,
                ProgressPercent: Math.Clamp(settings.StoreUpdateLastKnownProgressPercent, 0, 100),
                DetailText: settings.StoreUpdateLastKnownDetailText ?? string.Empty,
                ResultText: settings.StoreUpdateLastKnownResultText ?? string.Empty);
        }

        private void PersistLastKnownUiState(StoreUpdateUiState state) {
            var settings = _settingsProvider();
            settings.StoreUpdateLastKnownAvailable = state.IsUpdateButtonVisible;
            settings.StoreUpdateLastKnownPhase = state.PhaseText;
            settings.StoreUpdateLastKnownProgressPercent = state.ProgressPercent;
            settings.StoreUpdateLastKnownDetailText = state.DetailText;
            settings.StoreUpdateLastKnownResultText = state.ResultText;
            _persistSettings();
        }

        private void PushState(StoreUpdateUiState state) {
            _stateCallback(state);
        }
    }

    internal sealed record StoreUpdateUiState(
        bool IsUpdateButtonVisible,
        bool IsUpdateButtonEnabled,
        bool IsProgressVisible,
        string PhaseText,
        int ProgressPercent,
        string DetailText,
        string ResultText) {
        public static StoreUpdateUiState Hidden() =>
            new(false, false, false, string.Empty, 0, string.Empty, string.Empty);

        public static StoreUpdateUiState IdleAvailable() =>
            new(true, true, false, string.Empty, 0, string.Empty, string.Empty);
    }
}
