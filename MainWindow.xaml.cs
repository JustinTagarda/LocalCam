using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;
using Windows.ApplicationModel;
using LibVLCSharp.Shared;
using LibVLCSharp.WPF;
using LocalCam.Networking;
using LocalCam.Models;
using LocalCam.Services;
using System.Runtime.InteropServices;
using Geometry = System.Windows.Media.Geometry;
using IOPath = System.IO.Path;
using VlcMediaPlayer = LibVLCSharp.Shared.MediaPlayer;

namespace LocalCam {
    internal enum StreamFailureKind {
        Credential,
        Network,
        DeviceOrDecode,
        PlaybackStalled,
        Unknown
    }

    internal sealed record StreamFailureDetails(
        StreamFailureKind Kind,
        string UserMessage,
        string? Suggestion,
        string DiagnosticReason) {
        public bool RequiresSettings => Kind == StreamFailureKind.Credential;
    }

    internal static class StreamFailureClassifier {
        public static StreamFailureDetails Classify(string? reason, string? exceptionMessage, string? libVlcMessage) {
            var diagnosticText = string.Join(
                " | ",
                new[] { reason, exceptionMessage, libVlcMessage }
                    .Where(static value => !string.IsNullOrWhiteSpace(value)))
                .Trim();
            var normalized = diagnosticText.ToLowerInvariant();

            if (ContainsAny(
                    normalized,
                    "401",
                    "403",
                    "unauthorized",
                    "authentication",
                    "auth failed",
                    "auth failure",
                    "credential",
                    "invalid username",
                    "invalid password",
                    "access denied",
                    "login")) {
                return new StreamFailureDetails(
                    StreamFailureKind.Credential,
                    "RTSP credentials were rejected by this camera.",
                    "Check the RTSP username and password in Settings.",
                    diagnosticText);
            }

            if (ContainsAny(
                    normalized,
                    "connection refused",
                    "connection reset",
                    "timed out",
                    "timeout",
                    "no route",
                    "unreachable",
                    "host not found",
                    "couldn't connect",
                    "cannot connect",
                    "network")) {
                return new StreamFailureDetails(
                    StreamFailureKind.Network,
                    "Unable to reach this camera.",
                    "Check the camera's network connection.",
                    diagnosticText);
            }

            if (ContainsAny(
                    normalized,
                    "decode",
                    "decoder",
                    "codec",
                    "hardware",
                    "demux",
                    "video output",
                    "vout",
                    "direct3d",
                    "d3d",
                    "buffer deadlock",
                    "render",
                    "thumbnail",
                    "0x800706f4")) {
                return new StreamFailureDetails(
                    StreamFailureKind.DeviceOrDecode,
                    "Camera playback failed.",
                    "Check the camera hardware and RTSP stream compatibility.",
                    diagnosticText);
            }

            return new StreamFailureDetails(
                StreamFailureKind.Unknown,
                "Camera playback failed.",
                null,
                string.IsNullOrWhiteSpace(diagnosticText) ? "unknown" : diagnosticText);
        }

        private static bool ContainsAny(string value, params string[] candidates) {
            return candidates.Any(candidate => value.Contains(candidate, StringComparison.Ordinal));
        }
    }

    public partial class MainWindow : Window {
        private delegate IntPtr MouseHookProc(int nCode, IntPtr wParam, IntPtr lParam);

        private sealed class StreamRecoveryState {
            public DateTimeOffset WindowStartedAt { get; set; }
            public DateTimeOffset CooldownUntil { get; set; }
            public int AttemptsInWindow { get; set; }
            public bool Exhausted { get; set; }
        }

        private sealed class LibVlcLogThrottleState {
            public DateTimeOffset LastLoggedAt { get; set; }
            public int SuppressedCount { get; set; }
        }

        private sealed class InlineProgress<T>(Action<T> handler) : IProgress<T> {
            public void Report(T value) => handler(value);
        }

        private sealed class CameraTileControls {
            public required Border Card { get; init; }
            public required Border Placeholder { get; init; }
            public required Border Badge { get; init; }
            public required TextBlock Label { get; init; }
            public required VideoView VideoView { get; init; }
            public required Border VideoBlanker { get; init; }
            public required Button EnlargeButton { get; init; }
            public required Button RestoreButton { get; init; }
            public required Button InformationButton { get; init; }
            public required Button PlayButton { get; init; }
            public required Button StopButton { get; init; }
            public required Button SnapshotButton { get; init; }
            public required Button RecordButton { get; init; }
            public required Border OverlayToolbar { get; init; }
            public required Border RecordingBadge { get; init; }
            public required TextBlock RecordingElapsedText { get; init; }
            public required TextBlock PlaybackErrorText { get; init; }
            public VlcMediaPlayer? MediaPlayer { get; set; }
            public string? CameraIdentity { get; set; }
            public string? CameraIpAddress { get; set; }
            public string? CameraMacAddress { get; set; }
            public long CameraBindingVersion { get; set; }
            public bool IsSnapshotSaving { get; set; }
        }

        private const int WmSetIcon = 0x0080;
        private const int WmMove = 0x0003;
        private const int WmSize = 0x0005;
        private const int WmPowerBroadcast = 0x0218;
        private const int WmWindowPosChanged = 0x0047;
        private const int WmLButtonDown = 0x0201;
        private const int WmLButtonUp = 0x0202;
        private const int WmMoving = 0x0216;
        private const int PbtApmSuspend = 0x0004;
        private const int PbtApmResumeAutomatic = 0x0012;
        private const int PbtApmResumeSuspend = 0x0007;
        private const int PbtApmResumeCritical = 0x0006;
        private const int WhMouse = 7;
        private const int WhMouseLl = 14;
        private const int HcAction = 0;
        private const int IconSmall = 0;
        private const int IconBig = 1;
        private const int GclpHIcon = -14;
        private const int GclpHIconSm = -34;
        private const int SmCxDoubleClk = 36;
        private const int SmCyDoubleClk = 37;
        private const string InputDiagnosticsCategory = "InputDiagnostics";
        private const string SnapshotDiagnosticsCategory = "SnapshotDiagnostics";
        private const string RecordingDiagnosticsCategory = "RecordingDiagnostics";
        private const string RtspSettingsInvalidMessage = "RTSP credentials are missing or invalid.";
        private const string PremiumAddOnStoreId = "9P9KCJ3NFZFT";
        private const string PremiumAddOnOfferToken = "localcam_premium_lifetime";
        private const int BasicConcurrentStreamLimit = 2;
        private static readonly TimeSpan CameraMonitorCycleInterval = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan CameraMonitorIdleInterval = TimeSpan.FromSeconds(1);
        private static readonly TimeSpan CameraMonitorStartupGracePeriod = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan CameraMonitorStaleAfter = TimeSpan.FromSeconds(8);
        private static readonly TimeSpan CameraMonitorRestartSettleDelay = TimeSpan.FromMilliseconds(250);
        private static readonly TimeSpan CameraMonitorRecoveryCooldown = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan CameraMonitorRecoveryWindow = TimeSpan.FromMinutes(1);
        private const int CameraMonitorUnhealthySampleLimit = 3;
        private const int CameraMonitorRecoveryAttemptLimit = 3;
        private const int TerminalStreamRecoveryAttemptLimit = 1;
        private static readonly TimeSpan PlaybackConfirmationTimeout = TimeSpan.FromSeconds(8);
        private static readonly TimeSpan LibVlcRepeatedLogInterval = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan BasicRecordingDailyLimit = TimeSpan.FromMinutes(30);
        private static readonly TimeSpan RecordingSegmentDuration = TimeSpan.FromMinutes(60);
        private static readonly TimeSpan RecentCameraReconnectConfirmationTimeout = TimeSpan.FromSeconds(8);
                        private static readonly Geometry EnlargeButtonGeometry = Geometry.Parse("M2,6 L2,2 L6,2 M10,2 L14,2 L14,6 M14,10 L14,14 L10,14 M6,14 L2,14 L2,10");

        private IReadOnlyList<TapoCameraDetection> _detections = Array.Empty<TapoCameraDetection>();
        private readonly HashSet<string> _discoveryAutoStartedCameraIdentities = new(StringComparer.Ordinal);
        private readonly Dictionary<int, long> _cacheReconnectAttemptIdsByTile = [];
        private readonly Dictionary<long, TapoCameraDetection> _cacheReconnectDetectionsByAttempt = [];
        private readonly Dictionary<long, CancellationTokenSource> _cacheReconnectTimeoutsByAttempt = [];
        private long _nextCacheReconnectAttemptId;
        private bool _isRecoveryDiscoveryQueued;
        private readonly List<CameraTileControls> _cameraTiles = new();
        private LibVLC? _libVlc;
        private bool _isStreamingEngineReady;
        private bool _isStreamingEngineInitializing;
        private bool _hasStartedStreamingEngineInitialization;
        private bool _hasStartedStartupCameraFlow;
        private CancellationTokenSource? _scanCancellation;
        private bool _isClosing;
        private bool _isScanning;
        private bool _isUserScanCancelRequested;
        private bool _scanStoppedForMissingSettings;
        private bool _scanHasPublishedDetections;
        private bool _isDetectButtonToggleDelayActive;
        private int _detectButtonToggleVersion;
        private bool _streamsRunning;
        private bool _isApplyingPersistedWindowBounds;
        private bool _hasAppliedPersistedWindowBounds;
        private Rect? _lastNormalWindowBounds;
        private bool _layoutRetryPending;
        private bool _isSettingsDialogOpen;
        private int? _expandedCameraIndex;
        private readonly object _cameraMonitorSync = new();
        private CancellationTokenSource? _cameraMonitorCancellation;
        private Task? _cameraMonitorTask;
        private IntPtr _mouseHookHandle;
        private IntPtr _lowLevelMouseHookHandle;
        private MouseHookProc? _mouseHookProc;
        private MouseHookProc? _lowLevelMouseHookProc;
        private int? _lastToggleTileIndex;
        private long _lastToggleTicks;
        private int? _lastDoubleClickTileIndex;
        private long _lastDoubleClickTicks;
        private long _lastUnmatchedMouseLogTicks;
        private int _lastDoubleClickX;
        private int _lastDoubleClickY;
        private LocalCamSettings _settings = new();
                                                                private VlcMediaPlayer? _recordingMediaPlayer;
        private int? _activeRecordingTileIndex;
        private int _recordingSegmentNumber;
        private long _recordingSessionId;
        private long _nextRecordingSessionId = 1;
        private bool _isRecordingOperationProcessing;
        private DateTimeOffset? _recordingSegmentStartedAt;
        private string? _recordingOutputPath;
                private DispatcherTimer? _recordingElapsedTimer;
        private DispatcherTimer? _recordingSegmentTimer;
        private CancellationTokenSource? _recordingOutputValidationCts;
        private readonly Dictionary<int, long> _streamStartOrder = new();
        private readonly Dictionary<int, StreamFailureDetails> _streamFailureReasons = new();
        private readonly Dictionary<int, StreamHealthState> _streamHealthStates = new();
        private readonly Dictionary<int, StreamRecoveryState> _streamRecoveryStates = new();
        private readonly Dictionary<int, int> _terminalStreamRecoveryAttempts = new();
        private readonly HashSet<VlcMediaPlayer> _intentionalStoppedMediaPlayers = [];
        private readonly Dictionary<VlcMediaPlayer, TaskCompletionSource<bool>> _playbackConfirmationWaiters = new();
        private readonly object _libVlcLogSync = new();
        private readonly Dictionary<string, LibVlcLogThrottleState> _libVlcLogThrottleStates = new();
        private long _streamRecoveryGeneration;
        private long _nextStreamStartOrder = 1;
        private string? _lastLibVlcErrorMessage;
        private readonly IStoreContextProvider _storeContextProvider;
        private readonly IPremiumPurchaseService _premiumPurchaseService;
        private readonly IPremiumEntitlementService _premiumEntitlementService;
        private bool _hasResolvedPremiumUiState;
        private bool _isPremiumOwned;
        private bool _isPremiumPurchaseBusy;
        private bool _isPremiumEntitlementRefreshBusy;
        private DispatcherTimer? _basicRecordingDailyLimitTimer;
        private System.Drawing.Icon? _windowIconHandle;

        public MainWindow()
            : this(Array.Empty<TapoCameraDetection>()) {
        }

        public MainWindow(IReadOnlyList<TapoCameraDetection> detections) {
            _detections = detections.ToArray();
            _settings = LoadSettings();
            AppThemeService.Apply(_settings.ThemePreference);
            _storeContextProvider = new StoreContextProvider();

            InitializeComponent();
            ApplyWindowIcon();
            SourceInitialized += MainWindow_SourceInitialized;
            Activated += MainWindow_Activated;
            LocationChanged += Window_LocationChanged;
            SizeChanged += Window_SizeChanged;
            _premiumPurchaseService = new PremiumPurchaseService(
                _storeContextProvider,
                ResolvePurchaseOwnerWindowHandle,
                PremiumAddOnStoreId);
            _premiumEntitlementService = new PremiumEntitlementService(
                _storeContextProvider,
                GetSettingsSnapshotForService,
                UpdateSettingsForService,
                ResolvePurchaseOwnerWindowHandle,
                PremiumAddOnStoreId,
                PremiumAddOnOfferToken);
            UpdatePremiumUiVisibility();
            ApplyPersistedWindowBounds();
            PopulateCameraTiles(_detections);
            CameraTilesPanel.Visibility = _detections.Count > 0
                ? Visibility.Visible
                : Visibility.Collapsed;
            ApplyResponsiveCameraLayout();
            SetStreamingEngineStartingState();
        }

        private void QueueStreamingEngineInitialization(bool isRetry) {
            if (_isClosing || _isStreamingEngineReady || _isStreamingEngineInitializing) {
                return;
            }

            _isStreamingEngineInitializing = true;
            SetStreamingEngineStartingState();
            _ = InitializeStreamingEngineAfterFirstRenderAsync(isRetry);
        }

        private async Task InitializeStreamingEngineAfterFirstRenderAsync(bool isRetry) {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            JsonLogStore.Information(
                eventName: "video_engine_initialization_started",
                message: "Video engine initialization started after the main window became eligible to render.",
                category: "camera_connect",
                data: new Dictionary<string, object?> {
                    ["isRetry"] = isRetry
                });

            try {
                var result = await Task.Run(CreateStreamingEngine);
                if (_isClosing) {
                    result.Engine?.Dispose();
                    return;
                }

                if (result.Engine is null || result.LibVlcDirectory is null) {
                    JsonLogStore.Warning(
                        eventName: "video_engine_native_assets_missing",
                        message: "LibVLC native assets were not found for the current process architecture.",
                        category: "camera_connect",
                        data: new Dictionary<string, object?> {
                            ["processArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
                            ["baseDirectory"] = AppContext.BaseDirectory
                        });
                    SetStreamingEngineFailedState($"Video engine is unavailable for {RuntimeInformation.ProcessArchitecture}.");
                    return;
                }

                _libVlc = result.Engine;
                _libVlc.Log += LibVlc_Log;
                JsonLogStore.Information(
                    eventName: "video_engine_initialized",
                    message: "LibVLC video engine initialized.",
                    category: "camera_connect",
                    data: new Dictionary<string, object?> {
                        ["libVlcDirectory"] = result.LibVlcDirectory,
                        ["processArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
                        ["elapsedMs"] = stopwatch.ElapsedMilliseconds,
                        ["isRetry"] = isRetry
                    });
                _isStreamingEngineReady = true;
                EnsureCameraTileCount(_detections.Count);
                SetStreamingEngineReadyState();
                _isStreamingEngineInitializing = false;
                UpdateActionButtons();

                if (_detections.Count > 0) {
                    ShowDetections(_detections);
                }
                else {
                    ShowEmptyCameraSlots();
                }

                await StartStartupCameraFlowAsync();
            }
            catch (Exception ex) {
                JsonLogStore.Error(
                    eventName: "video_engine_initialization_failed",
                    message: "LibVLC video engine initialization failed.",
                    category: "camera_connect",
                    exception: ex,
                    data: new Dictionary<string, object?> {
                        ["processArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
                        ["baseDirectory"] = AppContext.BaseDirectory,
                        ["elapsedMs"] = stopwatch.ElapsedMilliseconds,
                        ["isRetry"] = isRetry
                    });
                if (!_isClosing) {
                    SetStreamingEngineFailedState($"Video engine initialization failed: {ex.Message}");
                }
            }
            finally {
                _isStreamingEngineInitializing = false;
                if (!_isClosing) {
                    UpdateActionButtons();
                }
            }
        }

        private static (LibVLC? Engine, string? LibVlcDirectory) CreateStreamingEngine() {
            var libVlcDirectory = ResolveLibVlcDirectory();
            if (libVlcDirectory is null) {
                return (null, null);
            }

            Core.Initialize(libVlcDirectory);
            var engine = new LibVLC("--network-caching=300", "--live-caching=300", "--rtsp-tcp", "--no-video-title-show");
            return (engine, libVlcDirectory);
        }

        private void SetStreamingEngineStartingState() {
            StreamingStatusText.Text = "Preparing video engine...";
            SearchProgressBar.Visibility = Visibility.Visible;
            RetryVideoEngineButton.Visibility = Visibility.Collapsed;
            RetryVideoEngineButton.Focusable = false;
            UpdateActionButtons();
        }

        private void SetStreamingEngineReadyState() {
            SearchProgressBar.Visibility = Visibility.Collapsed;
            RetryVideoEngineButton.Visibility = Visibility.Collapsed;
            RetryVideoEngineButton.Focusable = false;
        }

        private void SetStreamingEngineFailedState(string message) {
            _isStreamingEngineReady = false;
            SearchProgressBar.Visibility = Visibility.Collapsed;
            RetryVideoEngineButton.Visibility = Visibility.Visible;
            RetryVideoEngineButton.Focusable = true;
            StreamingStatusText.Text = $"{message} Retry initialization.";
            UpdateActionButtons();
        }

        private static LocalCamSettings LoadSettings() {
            if (SettingsStore.TryLoad(out var savedSettings)) {
                return savedSettings;
            }

            var defaultUser = Environment.GetEnvironmentVariable("LOCALCAM_RTSP_USERNAME");
            var defaultPassword = Environment.GetEnvironmentVariable("LOCALCAM_RTSP_PASSWORD");

            return new LocalCamSettings {
                RtspUsername = defaultUser ?? string.Empty,
                RtspPassword = defaultPassword ?? string.Empty,
                StreamPath = "stream1",
                ReconnectRecentCamerasOnStartup = true
            };
        }

        private static string GetStoreVersionDisplayText() {
            if (TryGetPackageVersion(out var packageVersionText)) {
                return packageVersionText;
            }

            var fileVersion = System.Diagnostics.FileVersionInfo
                .GetVersionInfo(typeof(MainWindow).Assembly.Location)
                .FileVersion;
            if (Version.TryParse(fileVersion, out var parsedVersion)) {
                return $"{parsedVersion.Major}.{parsedVersion.Minor}.{parsedVersion.Build}.0";
            }

            return "1.0.0.0";
        }

        private static bool TryGetPackageVersion(out string versionText) {
            versionText = string.Empty;
            try {
                var packageVersion = Package.Current.Id.Version;
                versionText = $"{packageVersion.Major}.{packageVersion.Minor}.{packageVersion.Build}.0";
                return true;
            }
            catch {
                return false;
            }
        }

        private void ApplyPersistedWindowBounds() {
            if (_hasAppliedPersistedWindowBounds) {
                return;
            }

            _hasAppliedPersistedWindowBounds = true;

            if (!HasPersistedWindowBounds()) {
                CenterWindowOnPrimaryScreen();
                return;
            }

            _isApplyingPersistedWindowBounds = true;
            try {
                Left = _settings.MainWindowLeft ?? Left;
                Top = _settings.MainWindowTop ?? Top;
                Width = _settings.MainWindowWidth ?? Width;
                Height = _settings.MainWindowHeight ?? Height;

                if (!IsWindowVisibleOnScreen()) {
                    CenterWindowOnPrimaryScreen();
                }
            }
            finally {
                _isApplyingPersistedWindowBounds = false;
            }
        }

        private bool HasPersistedWindowBounds() {
            return _settings.MainWindowLeft.HasValue &&
                   _settings.MainWindowTop.HasValue &&
                   _settings.MainWindowWidth.HasValue &&
                   _settings.MainWindowHeight.HasValue &&
                   _settings.MainWindowWidth.Value > 0 &&
                   _settings.MainWindowHeight.Value > 0;
        }

        private bool IsWindowVisibleOnScreen() {
            var windowBounds = GetWindowBoundsForPersistence();
            var virtualScreenBounds = new Rect(
                SystemParameters.VirtualScreenLeft,
                SystemParameters.VirtualScreenTop,
                SystemParameters.VirtualScreenWidth,
                SystemParameters.VirtualScreenHeight);
            var intersection = Rect.Intersect(windowBounds, virtualScreenBounds);
            return !intersection.IsEmpty && intersection.Width >= 120 && intersection.Height >= 120;
        }

        private void CenterWindowOnPrimaryScreen() {
            var workingArea = SystemParameters.WorkArea;
            var width = Math.Max(MinWidth, Width);
            var height = Math.Max(MinHeight, Height);

            Left = workingArea.Left + Math.Max(0, (workingArea.Width - width) / 2);
            Top = workingArea.Top + Math.Max(0, (workingArea.Height - height) / 2);
            Width = width;
            Height = height;
        }

        private Rect GetWindowBoundsForPersistence() {
            if (WindowState == WindowState.Normal) {
                return new Rect(
                    Left,
                    Top,
                    ActualWidth > 0 ? ActualWidth : Width,
                    ActualHeight > 0 ? ActualHeight : Height);
            }

            var restoreBounds = RestoreBounds;
            if (restoreBounds.Width > 0 && restoreBounds.Height > 0) {
                return restoreBounds;
            }

            if (_lastNormalWindowBounds is Rect lastNormalBounds &&
                lastNormalBounds.Width > 0 && lastNormalBounds.Height > 0) {
                return lastNormalBounds;
            }

            return new Rect(
                Left,
                Top,
                ActualWidth > 0 ? ActualWidth : Width,
                ActualHeight > 0 ? ActualHeight : Height);
        }

        private void PersistWindowBounds() {
            if (_isClosing || !_hasAppliedPersistedWindowBounds || _isApplyingPersistedWindowBounds) {
                return;
            }

            var bounds = GetWindowBoundsForPersistence();
            if (bounds.Width <= 0 || bounds.Height <= 0) {
                return;
            }

            _settings.MainWindowLeft = bounds.Left;
            _settings.MainWindowTop = bounds.Top;
            _settings.MainWindowWidth = bounds.Width;
            _settings.MainWindowHeight = bounds.Height;
            if (WindowState == WindowState.Normal) {
                _lastNormalWindowBounds = bounds;
            }
            TrySaveSettings("settings_window_bounds_save_failed", "Failed to persist main window bounds.");
        }

        private void PopulateCameraTiles(IReadOnlyList<TapoCameraDetection> detections) {
            EnsureCameraTileCount(detections.Count);
            for (var i = 0; i < _cameraTiles.Count; i++) {
                var tile = _cameraTiles[i];
                var detection = detections[i];
                var identity = GetCameraIdentity(detection, detections);
                if (!string.Equals(tile.CameraIdentity, identity, StringComparison.Ordinal)) {
                    if (IsSameCameraEndpoint(tile, detection)) {
                        if (tile.CameraIdentity is string previousIdentity &&
                            _discoveryAutoStartedCameraIdentities.Remove(previousIdentity)) {
                            _discoveryAutoStartedCameraIdentities.Add(identity);
                        }
                        tile.CameraIdentity = identity;
                    }
                    else {
                        if (_expandedCameraIndex == i) {
                            _expandedCameraIndex = null;
                        }
                        ResetCameraTileForDetectionChange(i);
                        tile.CameraIdentity = identity;
                    }
                }

                tile.CameraIpAddress = detection.IpAddress.ToString();
                tile.CameraMacAddress = detection.MacAddress;
                tile.Label.Text = $"camera {i + 1} - detected ({detection.IpAddress})";
                if (tile.MediaPlayer is null || (!IsStreamRunning(i) && !IsStreamTransitioning(i))) {
                    SetVideoSurfaceActive(i, isActive: false);
                }
            }

            if (_expandedCameraIndex is int expandedIndex && expandedIndex >= _cameraTiles.Count) {
                _expandedCameraIndex = null;
            }

            ApplyResponsiveCameraLayout();
        }

        private void EnsureCameraTileCount(int count) {
            count = Math.Max(0, count);

            while (_cameraTiles.Count > count) {
                var tile = _cameraTiles[^1];
                if (tile.CameraIdentity is string removedIdentity) {
                    _discoveryAutoStartedCameraIdentities.Remove(removedIdentity);
                }
                if (_activeRecordingTileIndex == _cameraTiles.Count - 1) {
                    StopRecordingSession("camera_removed", updateStatus: false);
                }
                _streamHealthStates.Remove(_cameraTiles.Count - 1);
                _streamStartOrder.Remove(_cameraTiles.Count - 1);
                StopMediaPlayerIntentionally(tile.MediaPlayer);
                tile.VideoView.MediaPlayer = null;
                DisposeMediaPlayer(tile.MediaPlayer);
                CameraTilesPanel.Children.Remove(tile.Card);
                _cameraTiles.RemoveAt(_cameraTiles.Count - 1);
            }

            while (_cameraTiles.Count < count) {
                var tile = CreateCameraTile(_cameraTiles.Count);
                _cameraTiles.Add(tile);
                CameraTilesPanel.Children.Add(tile.Card);
            }
        }

        private static string GetCameraIdentity(
            TapoCameraDetection detection,
            IReadOnlyCollection<TapoCameraDetection> detections) {
            return CameraDetectionReconciler.GetIdentity(detection, detections);
        }

        private static bool IsSameCameraEndpoint(CameraTileControls tile, TapoCameraDetection detection) {
            return string.Equals(tile.CameraIpAddress, detection.IpAddress.ToString(), StringComparison.Ordinal)
                && string.Equals(
                    tile.CameraMacAddress?.Trim(),
                    detection.MacAddress?.Trim(),
                    StringComparison.OrdinalIgnoreCase);
        }

        private void ResetCameraTileForDetectionChange(int tileIndex) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count) {
                return;
            }

            var tile = _cameraTiles[tileIndex];
            tile.CameraBindingVersion++;
            if (tile.CameraIdentity is string previousIdentity) {
                _discoveryAutoStartedCameraIdentities.Remove(previousIdentity);
            }

            if (_activeRecordingTileIndex == tileIndex) {
                StopRecordingSession("camera_detection_changed", updateStatus: false);
            }

            CancelCachedReconnectAttempt(tileIndex);
            _streamHealthStates.Remove(tileIndex);
            _streamStartOrder.Remove(tileIndex);
            ClearPlaybackFailure(tileIndex);
            _terminalStreamRecoveryAttempts.Remove(tileIndex);

            StopMediaPlayerIntentionally(tile.MediaPlayer);
            tile.VideoView.MediaPlayer = null;
            DisposeMediaPlayer(tile.MediaPlayer);
            tile.MediaPlayer = null;
        }

        private CameraTileControls CreateCameraTile(int tileIndex) {
            var card = new Border {
                Style = (Style)FindResource("CameraCardStyle")
            };
            card.SizeChanged += (_, _) => ApplyRoundedClip(card, 0);
            ApplyRoundedClip(card, 0);
            var root = new Grid {
                ClipToBounds = true
            };

            var placeholder = new Border {
                Style = (Style)FindResource("CameraPlaceholderStyle"),
                Margin = new Thickness(0)
            };

            var videoHost = new Border {
                Style = (Style)FindResource("CameraVideoHostStyle")
            };
            var videoView = new VideoView {
                Style = (Style)FindResource("CameraVideoViewStyle"),
                Margin = new Thickness(0)
            };
            videoHost.Child = videoView;

            var videoBlanker = new Border {
                Background = AppThemeService.GetBrush("CardBackgroundBrush"),
                HorizontalAlignment = HorizontalAlignment.Stretch,
                VerticalAlignment = VerticalAlignment.Stretch,
                Visibility = Visibility.Collapsed,
                IsHitTestVisible = false
            };

            var playbackErrorText = new TextBlock {
                HorizontalAlignment = HorizontalAlignment.Stretch,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(16),
                FontSize = 14,
                FontWeight = FontWeights.SemiBold,
                TextAlignment = TextAlignment.Center,
                TextWrapping = TextWrapping.Wrap,
                Visibility = Visibility.Collapsed,
                IsHitTestVisible = false
            };
            playbackErrorText.SetResourceReference(TextBlock.ForegroundProperty, "ErrorBrush");

            var badge = new Border {
                Style = (Style)FindResource("CameraBadgeStyle"),
                VerticalAlignment = VerticalAlignment.Top,
                HorizontalAlignment = HorizontalAlignment.Left
            };
            var label = new TextBlock {
                Foreground = (System.Windows.Media.Brush)FindResource("TitleBarIconBrush"),
                FontSize = 13,
                Text = $"camera {tileIndex + 1} - empty"
            };
            badge.Child = label;

            var informationButton = new Button {
                Style = (Style)FindResource("CameraOverlayIconButtonStyle"),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
                ToolTip = "Information",
                Content = CreateInformationButtonContent(),
                Background = AppThemeService.GetBrush("OverlayBackgroundBrush"),
                BorderBrush = AppThemeService.GetBrush("OverlayBorderBrush"),
                BorderThickness = new Thickness(1)
            };
            System.Windows.Automation.AutomationProperties.SetName(informationButton, "Information");
            informationButton.Click += (_, _) => ShowCameraInformation(tileIndex);

            var enlargeButton = new Button {
                Style = (Style)FindResource("CameraOverlayIconButtonStyle"),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0),
                ToolTip = "Enlarge",
                Background = AppThemeService.GetBrush("OverlayBackgroundBrush"),
                BorderBrush = AppThemeService.GetBrush("OverlayBorderBrush"),
                BorderThickness = new Thickness(1)
            };
            enlargeButton.Content = CreateEnlargeButtonContent();
            enlargeButton.Click += (_, _) => ToggleCameraTileEnlargeRestore(tileIndex);

            var restoreButton = new Button {
                Style = (Style)FindResource("CameraOverlayIconButtonStyle"),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0),
                ToolTip = "Restore",
                Content = CreateRestoreButtonContent(),
                Background = AppThemeService.GetBrush("OverlayBackgroundBrush"),
                BorderBrush = AppThemeService.GetBrush("OverlayBorderBrush"),
                BorderThickness = new Thickness(1)
            };
            restoreButton.Click += (_, _) => ToggleCameraTileEnlargeRestore(tileIndex);

            var playButton = new Button {
                Style = (Style)FindResource("CameraOverlayIconButtonStyle"),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
                ToolTip = "Play",
                Content = CreateStartButtonContent(),
                Background = AppThemeService.GetBrush("OverlayBackgroundBrush"),
                BorderBrush = AppThemeService.GetBrush("OverlayBorderBrush"),
                BorderThickness = new Thickness(1)
            };
            playButton.Click += async (_, _) => {
                if (tileIndex >= 0 && tileIndex < _detections.Count) {
                    _discoveryAutoStartedCameraIdentities.Remove(GetCameraIdentity(_detections[tileIndex], _detections));
                }
                await StartSingleStreamAsync(tileIndex);
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
            };

            var stopButton = new Button {
                Style = (Style)FindResource("CameraOverlayIconButtonStyle"),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
                ToolTip = "Stop Stream",
                Content = CreateStopButtonContent(),
                Background = AppThemeService.GetBrush("OverlayBackgroundBrush"),
                BorderBrush = AppThemeService.GetBrush("OverlayBorderBrush"),
                BorderThickness = new Thickness(1)
            };
            stopButton.Click += (_, _) => {
                StopSingleStream(tileIndex);
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
            };

            var snapshotButton = new Button {
                Style = (Style)FindResource("CameraOverlayIconButtonStyle"),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
                ToolTip = "Snapshot",
                Content = CreateSnapshotButtonContent(),
                Background = AppThemeService.GetBrush("OverlayBackgroundBrush"),
                BorderBrush = AppThemeService.GetBrush("OverlayBorderBrush"),
                BorderThickness = new Thickness(1)
            };
            snapshotButton.Click += async (_, _) => {
                await SaveSnapshotAsync(tileIndex);
            };

            var recordButton = new Button {
                Style = (Style)FindResource("CameraOverlayIconButtonStyle"),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
                ToolTip = "Record",
                Content = CreateRecordStartButtonContent(),
                Background = AppThemeService.GetBrush("OverlayBackgroundBrush"),
                BorderBrush = AppThemeService.GetBrush("OverlayBorderBrush"),
                BorderThickness = new Thickness(1)
            };
            recordButton.Click += async (_, _) => {
                await ToggleRecordingAsync(tileIndex);
            };

            card.AddHandler(
                UIElement.PreviewMouseLeftButtonDownEvent,
                new MouseButtonEventHandler((_, e) => {
                    if (IsEventFromControl(e.OriginalSource as DependencyObject, playButton) ||
                        IsEventFromControl(e.OriginalSource as DependencyObject, informationButton) ||
                        IsEventFromControl(e.OriginalSource as DependencyObject, stopButton) ||
                        IsEventFromControl(e.OriginalSource as DependencyObject, snapshotButton) ||
                        IsEventFromControl(e.OriginalSource as DependencyObject, recordButton) ||
                        IsEventFromControl(e.OriginalSource as DependencyObject, enlargeButton) ||
                        IsEventFromControl(e.OriginalSource as DependencyObject, restoreButton)) {
                        return;
                    }

                    var screenPoint = card.PointToScreen(e.GetPosition(card));
                    LogCardMouseDown(
                        "CardPreviewMouseDown",
                        "WPF preview mouse down inside camera card.",
                        tileIndex,
                        (int)Math.Round(screenPoint.X),
                        (int)Math.Round(screenPoint.Y),
                        e.ClickCount,
                        handledBefore: e.Handled);

                    if (e.ClickCount == 2) {
                        if (IsSettingsDialogOpen()) {
                            return;
                        }
                        if (!IsStreamRunning(tileIndex)) {
                            return;
                        }

                        LogDoubleClickToggleAttempt("WpfCardPreview", tileIndex, (int)Math.Round(screenPoint.X), (int)Math.Round(screenPoint.Y));
                        ToggleCameraTileEnlargeRestore(tileIndex);
                        e.Handled = true;
                    }
                }),
                handledEventsToo: true);

            var videoOverlay = new Grid {
                HorizontalAlignment = HorizontalAlignment.Stretch,
                VerticalAlignment = VerticalAlignment.Stretch
            };
            videoOverlay.Children.Add(videoBlanker);
            Panel.SetZIndex(videoBlanker, 0);
            videoOverlay.Children.Add(playbackErrorText);
            Panel.SetZIndex(playbackErrorText, 2);
            var overlayToolbarButtons = new StackPanel {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Center
            };
            overlayToolbarButtons.Children.Add(informationButton);
            overlayToolbarButtons.Children.Add(playButton);
            overlayToolbarButtons.Children.Add(stopButton);
            overlayToolbarButtons.Children.Add(snapshotButton);
            overlayToolbarButtons.Children.Add(recordButton);
            overlayToolbarButtons.Children.Add(enlargeButton);
            overlayToolbarButtons.Children.Add(restoreButton);
            var overlayToolbar = new Border {
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(0, 4, 4, 0),
                Background = AppThemeService.GetBrush("OverlayToolbarBrush"),
                BorderBrush = System.Windows.Media.Brushes.Transparent,
                BorderThickness = new Thickness(0),
                CornerRadius = new CornerRadius(0),
                Padding = new Thickness(4)
            };
            overlayToolbar.Child = overlayToolbarButtons;
            videoOverlay.Children.Add(overlayToolbar);
            Panel.SetZIndex(overlayToolbar, 1);
            var recordingElapsedText = new TextBlock {
                Foreground = AppThemeService.GetBrush("StopBrush"),
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                Text = "REC 00:00"
            };
            var recordingBadge = new Border {
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(4, 4, 0, 0),
                Background = AppThemeService.GetBrush("RecordingBrush"),
                CornerRadius = new CornerRadius(0),
                Padding = new Thickness(8, 4, 8, 4),
                Child = recordingElapsedText,
                Visibility = Visibility.Collapsed
            };
            videoOverlay.Children.Add(recordingBadge);
            Panel.SetZIndex(recordingBadge, 1);
            videoView.Content = videoOverlay;

            root.Children.Add(placeholder);
            Panel.SetZIndex(placeholder, 0);
            root.Children.Add(videoHost);
            Panel.SetZIndex(videoHost, 1);
            root.Children.Add(badge);
            Panel.SetZIndex(badge, 2);
            card.Child = root;

            return new CameraTileControls {
                Card = card,
                Placeholder = placeholder,
                Badge = badge,
                Label = label,
                VideoView = videoView,
                VideoBlanker = videoBlanker,
                EnlargeButton = enlargeButton,
                RestoreButton = restoreButton,
                InformationButton = informationButton,
                PlayButton = playButton,
                StopButton = stopButton,
                SnapshotButton = snapshotButton,
                RecordButton = recordButton,
                OverlayToolbar = overlayToolbar,
                RecordingBadge = recordingBadge,
                RecordingElapsedText = recordingElapsedText,
                PlaybackErrorText = playbackErrorText
            };
        }

        private void RefreshCameraThemeResources() {
            foreach (var tile in _cameraTiles) {
                var overlayBackground = AppThemeService.GetBrush("OverlayBackgroundBrush");
                var overlayBorder = AppThemeService.GetBrush("OverlayBorderBrush");
                var stopBrush = AppThemeService.GetBrush("StopBrush");

                tile.VideoBlanker.Background = AppThemeService.GetBrush("CardBackgroundBrush");
                tile.EnlargeButton.Background = overlayBackground;
                tile.EnlargeButton.BorderBrush = overlayBorder;
                tile.RestoreButton.Background = overlayBackground;
                tile.RestoreButton.BorderBrush = overlayBorder;
                tile.PlayButton.Background = overlayBackground;
                tile.PlayButton.BorderBrush = overlayBorder;
                tile.StopButton.Background = overlayBackground;
                tile.StopButton.BorderBrush = overlayBorder;
                tile.SnapshotButton.Background = overlayBackground;
                tile.SnapshotButton.BorderBrush = overlayBorder;
                tile.RecordButton.Background = overlayBackground;
                tile.RecordButton.BorderBrush = overlayBorder;
                tile.InformationButton.Background = overlayBackground;
                tile.InformationButton.BorderBrush = overlayBorder;
                tile.InformationButton.Content = CreateInformationButtonContent();
                tile.OverlayToolbar.Background = AppThemeService.GetBrush("OverlayToolbarBrush");
                tile.RecordingBadge.Background = AppThemeService.GetBrush("RecordingBrush");
                tile.RecordingElapsedText.Foreground = stopBrush;
                tile.PlaybackErrorText.Foreground = AppThemeService.GetBrush("ErrorBrush");

                if (tile.PlayButton.Content is Path playPath) {
                    playPath.Fill = AppThemeService.GetBrush("PlayBrush");
                }
                if (tile.StopButton.Content is Shape stopShape) {
                    stopShape.Fill = stopBrush;
                }
            }
        }

        private static FrameworkElement CreateEnlargeButtonContent() {
            var expandImagePath = IOPath.Combine(AppContext.BaseDirectory, "Assets", "expand.png");
            return CreateButtonImageContentOrFallback(expandImagePath);
        }

        private static FrameworkElement CreateRestoreButtonContent() {
            var collapseImagePath = IOPath.Combine(AppContext.BaseDirectory, "Assets", "collapse.png");
            return CreateButtonImageContentOrFallback(collapseImagePath);
        }

        private static FrameworkElement CreateStartButtonContent() {
            return new Grid {
                Width = 16,
                Height = 16,
                Children = {
                    new Path {
                        Data = Geometry.Parse("M4,3 L13,8 L4,13 Z"),
                        Fill = AppThemeService.GetBrush("PlayBrush"),
                        Stretch = System.Windows.Media.Stretch.Uniform,
                        Width = 14,
                        Height = 14,
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment = VerticalAlignment.Center
                    }
                }
            };
        }

        private static FrameworkElement CreateStopButtonContent() {
            return new Grid {
                Width = 16,
                Height = 16,
                Children = {
                    new Rectangle {
                        Fill = AppThemeService.GetBrush("StopBrush"),
                        Width = 11,
                        Height = 11,
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment = VerticalAlignment.Center
                    }
                }
            };
        }

        private static FrameworkElement CreateSnapshotButtonContent() {
            var root = new Grid {
                Width = 16,
                Height = 16
            };
            root.Children.Add(new Rectangle {
                Width = 14,
                Height = 10,
                RadiusX = 2,
                RadiusY = 2,
                Stroke = AppThemeService.GetBrush("StopBrush"),
                StrokeThickness = 1.4,
                Fill = System.Windows.Media.Brushes.Transparent,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            });
            root.Children.Add(new Ellipse {
                Width = 4.5,
                Height = 4.5,
                Stroke = AppThemeService.GetBrush("StopBrush"),
                StrokeThickness = 1.4,
                Fill = System.Windows.Media.Brushes.Transparent,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            });

            return root;
        }

        private static FrameworkElement CreateRecordStartButtonContent() {
            return new Grid {
                Width = 16,
                Height = 16,
                Children = {
                    new Ellipse {
                        Width = 12,
                        Height = 12,
                        Fill = AppThemeService.GetBrush("StopBrush"),
                        Stroke = AppThemeService.GetBrush("StopBrush"),
                        StrokeThickness = 1.2,
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment = VerticalAlignment.Center
                    }
                }
            };
        }

        private static FrameworkElement CreateRecordStopButtonContent() {
            return new Grid {
                Width = 16,
                Height = 16,
                Children = {
                    new Rectangle {
                        Width = 10,
                        Height = 10,
                        RadiusX = 1.5,
                        RadiusY = 1.5,
                        Fill = AppThemeService.GetBrush("RecordingBrush"),
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment = VerticalAlignment.Center
                    }
                }
            };
        }

        private static FrameworkElement CreateInformationButtonContent() {
            var icon = new Canvas {
                Width = 16,
                Height = 16,
                ClipToBounds = false
            };
            icon.Children.Add(new Ellipse {
                Width = 13,
                Height = 13,
                Margin = new Thickness(1.5),
                Stroke = AppThemeService.GetBrush("PrimaryTextBrush"),
                StrokeThickness = 1.25
            });
            icon.Children.Add(new Ellipse {
                Width = 1.5,
                Height = 1.5,
                Margin = new Thickness(7.25, 3.7, 0, 0),
                Fill = AppThemeService.GetBrush("PrimaryTextBrush")
            });
            icon.Children.Add(new Line {
                X1 = 8,
                Y1 = 6.5,
                X2 = 8,
                Y2 = 11.8,
                Stroke = AppThemeService.GetBrush("PrimaryTextBrush"),
                StrokeThickness = 1.35,
                StrokeStartLineCap = System.Windows.Media.PenLineCap.Round,
                StrokeEndLineCap = System.Windows.Media.PenLineCap.Round
            });
            return icon;
        }

        private void ShowCameraInformation(int tileIndex) {
            if (tileIndex < 0 || tileIndex >= _detections.Count || tileIndex >= _cameraTiles.Count) {
                return;
            }

            var detection = _detections[tileIndex];
            var tile = _cameraTiles[tileIndex];
            var rows = new List<(string Section, string Label, string Value)> {
                ("Camera", "Camera", $"Camera {tileIndex + 1}"),
                ("Camera", "IP address", detection.IpAddress.ToString()),
                ("Camera", "Host name", DisplayAvailableValue(detection.HostName)),
                ("Camera", "MAC address", DisplayAvailableValue(detection.MacAddress)),
                ("Discovery", "Method", "Not retained per camera"),
                ("Discovery", "Detection reason", MakeDetectionReasonBrandNeutral(detection.DetectionReason)),
                ("Discovery", "Confidence", detection.ConfidenceScore.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture)),
                ("Discovery", "Open ports", detection.OpenPorts.Count > 0
                    ? string.Join(", ", detection.OpenPorts.Order())
                    : "None recorded"),
                ("Connection", "Protocol", "RTSP"),
                ("Connection", "Host", detection.IpAddress.ToString()),
                ("Connection", "Port", detection.RtspPort.ToString(System.Globalization.CultureInfo.InvariantCulture)),
                ("Connection", "Stream path", NormalizeStreamPath(_settings.StreamPath)),
                ("Connection", "Stream path status", string.IsNullOrWhiteSpace(_settings.StreamPath)
                    ? "Missing"
                    : "Configured"),
                ("Connection", "Shared credentials", HasCompleteStreamingSettings(
                    _settings.RtspUsername.Trim(), _settings.RtspPassword)
                    ? "Configured (values hidden)"
                    : "Missing (values hidden)"),
                ("Playback", "Status", IsStreamRunning(tileIndex) ? "Playing" : GetStreamLifecyclePhase(tileIndex).ToString()),
                ("Playback", "Lifecycle", GetStreamLifecyclePhase(tileIndex).ToString())
            };

            if (tile.MediaPlayer is { } mediaPlayer && IsStreamRunning(tileIndex)) {
                rows.Add(("Playback", "Position", FormatMediaTime(mediaPlayer.Time)));
                if (mediaPlayer.Length > 0) {
                    rows.Add(("Playback", "Duration", FormatMediaTime(mediaPlayer.Length)));
                }
            }

            var playbackError = tile.PlaybackErrorText.Text?.Trim();
            if (tile.PlaybackErrorText.Visibility == Visibility.Visible && !string.IsNullOrWhiteSpace(playbackError)) {
                rows.Add(("Playback", "Last error", playbackError));
            }

            if (_activeRecordingTileIndex == tileIndex) {
                var elapsed = _recordingSegmentStartedAt is DateTimeOffset startedAt
                    ? FormatElapsedTime(DateTimeOffset.Now - startedAt)
                    : "Starting";
                rows.Add(("Recording", "Status", "Recording"));
                rows.Add(("Recording", "Elapsed", elapsed));
                rows.Add(("Recording", "Output", DisplayAvailableValue(_recordingOutputPath)));
            } else {
                rows.Add(("Recording", "Status", "Not recording"));
            }

            var dialog = new InformationWindow($"Camera {tileIndex + 1} Information", rows) {
                Owner = this
            };
            dialog.ShowDialog();
        }

        private static string DisplayAvailableValue(string? value) {
            return string.IsNullOrWhiteSpace(value) ? "Not available" : value.Trim();
        }

        private static string MakeDetectionReasonBrandNeutral(string? reason) {
            if (string.IsNullOrWhiteSpace(reason)) {
                return "Not available";
            }

            return reason
                .Replace("TP-Link/Tapo", "camera vendor", StringComparison.OrdinalIgnoreCase)
                .Replace("Tapo/TP-Link", "camera vendor", StringComparison.OrdinalIgnoreCase)
                .Replace("TP-Link", "camera vendor", StringComparison.OrdinalIgnoreCase)
                .Replace("Tapo", "camera", StringComparison.OrdinalIgnoreCase);
        }

        private static string FormatMediaTime(long milliseconds) {
            var time = TimeSpan.FromMilliseconds(Math.Max(0, milliseconds));
            return time.TotalHours >= 1
                ? $"{(int)time.TotalHours:00}:{time.Minutes:00}:{time.Seconds:00}"
                : $"{time.Minutes:00}:{time.Seconds:00}";
        }

        private static string FormatElapsedTime(TimeSpan elapsed) {
            return elapsed.TotalHours >= 1
                ? $"{(int)elapsed.TotalHours:00}:{elapsed.Minutes:00}:{elapsed.Seconds:00}"
                : $"{elapsed.Minutes:00}:{elapsed.Seconds:00}";
        }

        private static FrameworkElement CreateButtonImageContentOrFallback(string imagePath) {
            if (!System.IO.File.Exists(imagePath)) {
                return new Grid {
                    Width = 16,
                    Height = 16,
                    Children = {
                        new System.Windows.Shapes.Path {
                            Data = EnlargeButtonGeometry,
                            Fill = System.Windows.Media.Brushes.Transparent,
                            Stroke = AppThemeService.GetBrush("StopBrush"),
                            StrokeThickness = 1.6,
                            StrokeStartLineCap = System.Windows.Media.PenLineCap.Round,
                            StrokeEndLineCap = System.Windows.Media.PenLineCap.Round,
                            StrokeLineJoin = System.Windows.Media.PenLineJoin.Round,
                            Width = 16,
                            Height = 16,
                            Stretch = System.Windows.Media.Stretch.Uniform,
                            HorizontalAlignment = HorizontalAlignment.Center,
                            VerticalAlignment = VerticalAlignment.Center
                        }
                    }
                };
            }

            var imageSource = new BitmapImage();
            imageSource.BeginInit();
            imageSource.CacheOption = BitmapCacheOption.OnLoad;
            imageSource.UriSource = new Uri(imagePath);
            imageSource.EndInit();
            imageSource.Freeze();

            return new Image {
                Source = imageSource,
                Width = 16,
                Height = 16,
                Stretch = System.Windows.Media.Stretch.Uniform
            };
        }

        private void UpdateTileButtonStates() {
            var expandedIndex = _expandedCameraIndex;
            for (var i = 0; i < _cameraTiles.Count; i++) {
                var tile = _cameraTiles[i];
                var isCardVisible = CameraTilesPanel.Visibility == Visibility.Visible && tile.Card.Visibility == Visibility.Visible;
                var isExpanded = expandedIndex.HasValue && expandedIndex.Value == i;
                var isRunning = IsStreamRunning(i);
                var isTransitioning = IsStreamTransitioning(i);
                var isDetectedCard = i < _detections.Count;

                tile.InformationButton.Visibility = isCardVisible && isDetectedCard
                    ? Visibility.Visible
                    : Visibility.Collapsed;
                tile.InformationButton.IsEnabled = isDetectedCard;

                tile.PlayButton.Visibility = isCardVisible && isDetectedCard && !isRunning && _isStreamingEngineReady
                    ? Visibility.Visible
                    : Visibility.Collapsed;
                tile.StopButton.Visibility = isCardVisible && isDetectedCard && isRunning ? Visibility.Visible : Visibility.Collapsed;
                tile.SnapshotButton.Visibility = isCardVisible && isDetectedCard && isRunning ? Visibility.Visible : Visibility.Collapsed;
                tile.RecordButton.Visibility = isCardVisible && isDetectedCard && isRunning ? Visibility.Visible : Visibility.Collapsed;
                tile.PlayButton.IsEnabled = _isStreamingEngineReady && !isTransitioning;
                tile.StopButton.IsEnabled = true;
                tile.SnapshotButton.IsEnabled = !tile.IsSnapshotSaving;
                var isRecordingThisTile = _activeRecordingTileIndex == i;
                tile.RecordButton.IsEnabled = !_isRecordingOperationProcessing;
                tile.RecordButton.Content = isRecordingThisTile
                    ? CreateRecordStopButtonContent()
                    : CreateRecordStartButtonContent();
                tile.RecordButton.ToolTip = isRecordingThisTile ? "Stop Recording" : "Record";
                tile.RecordingBadge.Visibility = isCardVisible && isRecordingThisTile ? Visibility.Visible : Visibility.Collapsed;

                tile.EnlargeButton.Visibility = isCardVisible && isRunning && !isExpanded ? Visibility.Visible : Visibility.Collapsed;
                tile.RestoreButton.Visibility = isCardVisible && isRunning && isExpanded ? Visibility.Visible : Visibility.Collapsed;
                tile.EnlargeButton.IsEnabled = true;
                tile.RestoreButton.IsEnabled = true;

                // Keep in-video controls available for visible cards, but force-hide hidden cards.
                tile.VideoView.Visibility = isCardVisible ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        private bool IsCameraTileActive(int tileIndex) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count) {
                return false;
            }

            var tile = _cameraTiles[tileIndex];
            return tile.VideoView.Visibility == Visibility.Visible ||
                   (tile.MediaPlayer is not null && tile.MediaPlayer.IsPlaying);
        }

        private void AttachMediaPlayer(CameraTileControls tile, TapoCameraDetection detection) {
            if (_libVlc is null || tile.MediaPlayer is not null) {
                return;
            }

            var cameraBindingVersion = tile.CameraBindingVersion;
            var mediaPlayer = new VlcMediaPlayer(_libVlc) {
                EnableHardwareDecoding = false,
                EnableMouseInput = false,
                Mute = true
            };
            mediaPlayer.Playing += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                var tileIndex = _cameraTiles.IndexOf(tile);
                if (tileIndex < 0 || !ReferenceEquals(tile.MediaPlayer, mediaPlayer) ||
                    tile.CameraBindingVersion != cameraBindingVersion) {
                    return;
                }

                if (GetStreamLifecyclePhase(tileIndex) is StreamLifecyclePhase.Stopped or StreamLifecyclePhase.Stopping) {
                    CompletePlaybackConfirmation(mediaPlayer, confirmed: false);
                    return;
                }

                _intentionalStoppedMediaPlayers.Remove(mediaPlayer);
                _terminalStreamRecoveryAttempts.Remove(tileIndex);
                var playbackSample = CaptureStreamSample(mediaPlayer);
                MarkStreamStarted(tileIndex, playbackSample);
                ClearPlaybackFailureOnPlaybackConfirmed(tileIndex, playbackSample);
                CompletePlaybackConfirmation(mediaPlayer, confirmed: true);
                _streamsRunning = IsAnyStreamRunning();
                if (tileIndex < _detections.Count && tile.CameraBindingVersion == cameraBindingVersion) {
                    var cachedDetection = CompleteCachedReconnectAttempt(tileIndex);
                    RecentCameraConnectionCache.ConfirmPlayback(
                        _settings,
                        cachedDetection ?? detection,
                        DateTimeOffset.UtcNow,
                        _detections);
                    TrySaveSettings("recent_camera_connection_save_failed", "Failed to save a recent camera connection.");
                }
                JsonLogStore.Information(
                    eventName: "camera_playback_confirmed",
                    message: "LibVLC confirmed RTSP playback for a camera.",
                    category: "camera_connect",
                    data: new Dictionary<string, object?> {
                        ["cameraIndex"] = tileIndex + 1,
                        ["ipAddress"] = tileIndex < _detections.Count ? _detections[tileIndex].IpAddress.ToString() : null,
                        ["voutCount"] = mediaPlayer.VoutCount,
                        ["videoOutputObserved"] = StreamHealthEvaluator.HasVideoEvidence(playbackSample),
                        ["mediaTime"] = playbackSample.MediaTime,
                        ["position"] = playbackSample.Position,
                        ["displayedPictures"] = playbackSample.DisplayedPictures,
                        ["decodedVideo"] = playbackSample.DecodedVideo,
                        ["readBytes"] = playbackSample.ReadBytes
                    });
                UpdateActionButtons();
                RequestCameraMonitoring();
            }));
            mediaPlayer.Stopped += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                var tileIndex = _cameraTiles.IndexOf(tile);
                CompletePlaybackConfirmation(mediaPlayer, confirmed: false);
                if (tileIndex >= 0 && ReferenceEquals(tile.MediaPlayer, mediaPlayer)) {
                    SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
                    _streamStartOrder.Remove(tileIndex);
                    _streamHealthStates.Remove(tileIndex);
                    SetVideoSurfaceActive(tileIndex, isActive: false);
                }
                if (_activeRecordingTileIndex == tileIndex && tileIndex >= 0 && ReferenceEquals(tile.MediaPlayer, mediaPlayer)) {
                    StopRecordingSession("stream_stopped", updateStatus: true);
                }
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
            }));
            mediaPlayer.EndReached += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                var tileIndex = _cameraTiles.IndexOf(tile);
                var wasIntentionalStop = _intentionalStoppedMediaPlayers.Contains(mediaPlayer);
                CompletePlaybackConfirmation(mediaPlayer, confirmed: false);
                if (!wasIntentionalStop && tileIndex >= 0 && ReferenceEquals(tile.MediaPlayer, mediaPlayer)) {
                    var failure = StreamFailureClassifier.Classify("stream ended", null, null);
                    SetPlaybackFailure(tileIndex, failure);
                    SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
                    _streamStartOrder.Remove(tileIndex);
                    _streamHealthStates.Remove(tileIndex);
                    SetVideoSurfaceActive(tileIndex, isActive: false);
                }
                if (_activeRecordingTileIndex == tileIndex && tileIndex >= 0 && ReferenceEquals(tile.MediaPlayer, mediaPlayer)) {
                    StopRecordingSession("stream_ended", updateStatus: true);
                }
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
                if (!wasIntentionalStop && tileIndex >= 0 && ReferenceEquals(tile.MediaPlayer, mediaPlayer) && !HandleCachedReconnectFailure(tileIndex)) {
                    _ = RecoverTerminalStreamAsync(tileIndex, "ended");
                }
            }));
            mediaPlayer.EncounteredError += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                var tileIndex = _cameraTiles.IndexOf(tile);
                var wasIntentionalStop = _intentionalStoppedMediaPlayers.Contains(mediaPlayer);
                var wasCachedReconnect = false;
                CompletePlaybackConfirmation(mediaPlayer, confirmed: false);
                if (!wasIntentionalStop && tileIndex >= 0 && ReferenceEquals(tile.MediaPlayer, mediaPlayer)) {
                    var hasExistingFailure = _streamFailureReasons.TryGetValue(tileIndex, out var existingFailure);
                    var failure = hasExistingFailure && existingFailure!.Kind != StreamFailureKind.Unknown
                        ? existingFailure
                        : StreamFailureClassifier.Classify(
                            hasExistingFailure ? existingFailure!.DiagnosticReason : null,
                            null,
                            _lastLibVlcErrorMessage);
                    SetPlaybackFailure(tileIndex, failure);
                    SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
                    _streamStartOrder.Remove(tileIndex);
                    _streamHealthStates.Remove(tileIndex);
                    SetVideoSurfaceActive(tileIndex, isActive: false);
                    StreamingStatusText.Text = $"Camera {tileIndex + 1} stream failed: {failure.UserMessage}";
                    JsonLogStore.Warning(
                        eventName: "camera_connect_playback_error",
                        message: "LibVLC reported a playback error for an RTSP stream.",
                        category: "camera_connect",
                        data: new Dictionary<string, object?> {
                            ["cameraIndex"] = tileIndex + 1,
                            ["ipAddress"] = tileIndex < _detections.Count ? _detections[tileIndex].IpAddress.ToString() : null,
                            ["reason"] = failure.DiagnosticReason,
                            ["failureKind"] = failure.Kind.ToString()
                        });
                    HandleCredentialRelatedPlaybackFailure(failure, tileIndex);
                    wasCachedReconnect = !wasIntentionalStop && HandleCachedReconnectFailure(tileIndex);
                }
                if (!wasIntentionalStop && _activeRecordingTileIndex == tileIndex && tileIndex >= 0 && ReferenceEquals(tile.MediaPlayer, mediaPlayer)) {
                    StopRecordingSession("stream_error", updateStatus: true);
                }
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
                if (!wasIntentionalStop && tileIndex >= 0 && ReferenceEquals(tile.MediaPlayer, mediaPlayer) && !wasCachedReconnect) {
                    _ = RecoverTerminalStreamAsync(tileIndex, "error");
                }
            }));

            tile.MediaPlayer = mediaPlayer;
            tile.VideoView.MediaPlayer = mediaPlayer;
        }

        private void EnsureVideoSurfaceAttached(int index) {
            if (index < 0 || index >= _cameraTiles.Count) {
                return;
            }

            var tile = _cameraTiles[index];
            if (tile.MediaPlayer is null) {
                return;
            }

            if (!ReferenceEquals(tile.VideoView.MediaPlayer, tile.MediaPlayer)) {
                tile.VideoView.MediaPlayer = tile.MediaPlayer;
            }
        }

        private void ClearVideoSurface(int index) {
            if (index < 0 || index >= _cameraTiles.Count) {
                return;
            }

            var tile = _cameraTiles[index];
            if (tile.VideoView.MediaPlayer is not null) {
                tile.VideoView.MediaPlayer = null;
            }
        }

        private void SetVideoSurfaceActive(int index, bool isActive) {
            if (index < 0 || index >= _cameraTiles.Count) {
                return;
            }

            var tile = _cameraTiles[index];
            if (isActive) {
                EnsureVideoSurfaceAttached(index);
            }
            else {
                ClearVideoSurface(index);
            }

            tile.VideoView.Visibility = Visibility.Visible;
            tile.VideoBlanker.Visibility = isActive ? Visibility.Collapsed : Visibility.Visible;
            tile.Placeholder.Visibility = isActive ? Visibility.Collapsed : Visibility.Visible;
            tile.Badge.Visibility = isActive ? Visibility.Collapsed : Visibility.Visible;
            UpdateTileButtonStates();
        }

        private void SetPlaybackFailure(int tileIndex, StreamFailureDetails failure) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count) {
                return;
            }

            _streamFailureReasons[tileIndex] = failure;
            var tile = _cameraTiles[tileIndex];
            tile.PlaybackErrorText.Text = string.IsNullOrWhiteSpace(failure.Suggestion)
                ? failure.UserMessage
                : $"{failure.UserMessage}{Environment.NewLine}{failure.Suggestion}";
            tile.PlaybackErrorText.Visibility = Visibility.Visible;
        }

        private void ClearPlaybackFailure(int tileIndex) {
            _streamFailureReasons.Remove(tileIndex);
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count) {
                return;
            }

            var errorText = _cameraTiles[tileIndex].PlaybackErrorText;
            errorText.Text = string.Empty;
            errorText.Visibility = Visibility.Collapsed;
        }

        private void ClearVideoOutputFailure(int tileIndex) {
            if (_streamFailureReasons.TryGetValue(tileIndex, out var failure) &&
                failure.DiagnosticReason == StreamHealthEvaluator.VideoOutputNotConfirmedReason) {
                ClearPlaybackFailure(tileIndex);
            }
        }

        private static StreamFailureDetails CreateVideoOutputFailure() {
            return new StreamFailureDetails(
                StreamFailureKind.PlaybackStalled,
                "The stream connected, but no video frames arrived.",
                "Check the camera's video stream settings and compatibility.",
                StreamHealthEvaluator.VideoOutputNotConfirmedReason);
        }

        private void HandleCredentialRelatedPlaybackFailure(StreamFailureDetails failure, int? tileIndex = null) {
            if (!failure.RequiresSettings || _isClosing) {
                return;
            }

            if (tileIndex is int index && index >= 0 && index < _detections.Count &&
                _discoveryAutoStartedCameraIdentities.Contains(GetCameraIdentity(_detections[index], _detections))) {
                JsonLogStore.Information(
                    eventName: "camera_discovery_playback_failure_kept_on_card",
                    message: "A discovery-started camera rejected playback credentials; the error remains on its card while discovery continues.",
                    category: "camera_search",
                    data: new Dictionary<string, object?> {
                        ["cameraIndex"] = index + 1,
                        ["ipAddress"] = _detections[index].IpAddress.ToString(),
                        ["failureKind"] = failure.Kind.ToString()
                    });
                return;
            }

            StreamingStatusText.Text = failure.UserMessage;
            OpenSettingsDialog(RtspSettingsInvalidMessage, highlightMissingCredentials: true);
        }

        private void ToggleCameraTileEnlargeRestore(int tileIndex) {
            if (IsSettingsDialogOpen()) {
                JsonLogStore.Information(
                    "ExpandCollapseToggleSuppressed",
                    "Expand/collapse toggle suppressed because the settings dialog is open.",
                    InputDiagnosticsCategory,
                    new Dictionary<string, object?> {
                        ["tileIndex"] = tileIndex,
                        ["expandedCameraIndex"] = _expandedCameraIndex
                    });
                return;
            }

            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count) {
                JsonLogStore.Warning(
                    "ExpandCollapseToggleRejected",
                    "Expand/collapse toggle rejected because the camera tile index is out of range.",
                    InputDiagnosticsCategory,
                    new Dictionary<string, object?> {
                        ["tileIndex"] = tileIndex,
                        ["tileCount"] = _cameraTiles.Count
                    });
                return;
            }

            if (!IsStreamRunning(tileIndex)) {
                JsonLogStore.Information(
                    "ExpandCollapseToggleSuppressed",
                    "Expand/collapse toggle suppressed because the camera tile is not active.",
                    InputDiagnosticsCategory,
                    new Dictionary<string, object?> {
                        ["tileIndex"] = tileIndex,
                        ["expandedCameraIndex"] = _expandedCameraIndex
                    });
                return;
            }

            var now = Environment.TickCount64;
            if (_lastToggleTileIndex == tileIndex && now - _lastToggleTicks <= 150) {
                JsonLogStore.Information(
                    "ExpandCollapseToggleSuppressed",
                    "Duplicate expand/collapse toggle suppressed.",
                    InputDiagnosticsCategory,
                    new Dictionary<string, object?> {
                        ["tileIndex"] = tileIndex,
                        ["elapsedMs"] = now - _lastToggleTicks,
                        ["expandedCameraIndex"] = _expandedCameraIndex
                    });
                return;
            }

            var previousExpandedIndex = _expandedCameraIndex;
            _expandedCameraIndex = _expandedCameraIndex == tileIndex ? null : tileIndex;
            _lastToggleTileIndex = tileIndex;
            _lastToggleTicks = now;

            JsonLogStore.Information(
                "ExpandCollapseToggleApplied",
                "Expand/collapse toggle applied.",
                InputDiagnosticsCategory,
                new Dictionary<string, object?> {
                    ["tileIndex"] = tileIndex,
                    ["previousExpandedCameraIndex"] = previousExpandedIndex,
                    ["newExpandedCameraIndex"] = _expandedCameraIndex,
                    ["tileCount"] = _cameraTiles.Count
                });

            ApplyResponsiveCameraLayout();
        }

        private void InstallMouseHook() {
            if (_mouseHookHandle != IntPtr.Zero && _lowLevelMouseHookHandle != IntPtr.Zero) {
                JsonLogStore.Information(
                    "MouseHookInstallSkipped",
                    "Mouse hook install skipped because hooks are already active.",
                    InputDiagnosticsCategory,
                    new Dictionary<string, object?> {
                        ["hookHandle"] = _mouseHookHandle.ToInt64(),
                        ["lowLevelHookHandle"] = _lowLevelMouseHookHandle.ToInt64(),
                        ["threadId"] = GetCurrentThreadId()
                    });
                return;
            }

            var threadId = GetCurrentThreadId();
            if (_mouseHookHandle == IntPtr.Zero) {
                _mouseHookProc = MouseHookCallback;
                _mouseHookHandle = SetWindowsHookEx(
                    WhMouse,
                    _mouseHookProc,
                    IntPtr.Zero,
                    threadId);
            }

            var mouseHookError = Marshal.GetLastWin32Error();
            if (_lowLevelMouseHookHandle == IntPtr.Zero) {
                _lowLevelMouseHookProc = LowLevelMouseHookCallback;
                _lowLevelMouseHookHandle = SetWindowsHookEx(
                    WhMouseLl,
                    _lowLevelMouseHookProc,
                    IntPtr.Zero,
                    0);
            }

            var lowLevelHookError = Marshal.GetLastWin32Error();
            JsonLogStore.Information(
                _mouseHookHandle == IntPtr.Zero && _lowLevelMouseHookHandle == IntPtr.Zero
                    ? "MouseHookInstallFailed"
                    : "MouseHookInstalled",
                "Mouse hook install attempted.",
                InputDiagnosticsCategory,
                new Dictionary<string, object?> {
                    ["hookHandle"] = _mouseHookHandle.ToInt64(),
                    ["lowLevelHookHandle"] = _lowLevelMouseHookHandle.ToInt64(),
                    ["threadId"] = threadId,
                    ["mouseHookLastWin32Error"] = mouseHookError,
                    ["lowLevelHookLastWin32Error"] = lowLevelHookError
                });
        }

        private void UninstallMouseHook() {
            var hookHandle = _mouseHookHandle;
            var lowLevelHookHandle = _lowLevelMouseHookHandle;
            if (_mouseHookHandle != IntPtr.Zero) {
                UnhookWindowsHookEx(_mouseHookHandle);
                _mouseHookHandle = IntPtr.Zero;
                _mouseHookProc = null;
            }

            if (_lowLevelMouseHookHandle != IntPtr.Zero) {
                UnhookWindowsHookEx(_lowLevelMouseHookHandle);
                _lowLevelMouseHookHandle = IntPtr.Zero;
                _lowLevelMouseHookProc = null;
            }

            JsonLogStore.Information(
                "MouseHookUninstalled",
                "Mouse hooks uninstalled.",
                InputDiagnosticsCategory,
                new Dictionary<string, object?> {
                    ["hookHandle"] = hookHandle.ToInt64(),
                    ["lowLevelHookHandle"] = lowLevelHookHandle.ToInt64()
                });
        }

        private IntPtr MouseHookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
            if (nCode >= HcAction && wParam == WmLButtonDown) {
                var mouseInfo = Marshal.PtrToStructure<MouseHookStruct>(lParam);
                LogMouseHookDown(mouseInfo);
                HandleThreadMouseDown(mouseInfo.pt.x, mouseInfo.pt.y);
            }

            return CallNextHookEx(_mouseHookHandle, nCode, wParam, lParam);
        }

        private IntPtr LowLevelMouseHookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
            if (nCode >= HcAction && wParam == WmLButtonDown) {
                var mouseInfo = Marshal.PtrToStructure<LowLevelMouseHookStruct>(lParam);
                LogLowLevelMouseDown(mouseInfo);
                HandleThreadMouseDown(mouseInfo.pt.x, mouseInfo.pt.y);
            }

            return CallNextHookEx(_lowLevelMouseHookHandle, nCode, wParam, lParam);
        }

        private void HandleThreadMouseDown(int screenX, int screenY) {
            if (IsSettingsDialogOpen()) {
                ResetDoubleClickTracking();
                return;
            }

            var tileIndex = GetCameraTileIndexAtScreenPoint(screenX, screenY);
            if (!tileIndex.HasValue) {
                LogUnmatchedMouseDown(screenX, screenY);
                ResetDoubleClickTracking();
                return;
            }
            if (!IsCameraTileActive(tileIndex.Value)) {
                ResetDoubleClickTracking();
                return;
            }
            if (IsScreenPointInsideControl(_cameraTiles[tileIndex.Value].PlayButton, screenX, screenY) ||
                IsScreenPointInsideControl(_cameraTiles[tileIndex.Value].InformationButton, screenX, screenY) ||
                IsScreenPointInsideControl(_cameraTiles[tileIndex.Value].StopButton, screenX, screenY) ||
                IsScreenPointInsideControl(_cameraTiles[tileIndex.Value].SnapshotButton, screenX, screenY) ||
                IsScreenPointInsideControl(_cameraTiles[tileIndex.Value].RecordButton, screenX, screenY) ||
                IsScreenPointInsideControl(_cameraTiles[tileIndex.Value].EnlargeButton, screenX, screenY) ||
                IsScreenPointInsideControl(_cameraTiles[tileIndex.Value].RestoreButton, screenX, screenY)) {
                ResetDoubleClickTracking();
                return;
            }

            var now = Environment.TickCount64;
            var isDoubleClick = _lastDoubleClickTileIndex == tileIndex.Value &&
                                _lastDoubleClickTicks > 0 &&
                                now - _lastDoubleClickTicks <= GetDoubleClickTime() &&
                                Math.Abs(screenX - _lastDoubleClickX) <= GetSystemMetrics(SmCxDoubleClk) &&
                                Math.Abs(screenY - _lastDoubleClickY) <= GetSystemMetrics(SmCyDoubleClk);

            JsonLogStore.Information(
                "MouseDownMatchedCameraCard",
                "Mouse down matched a camera card.",
                InputDiagnosticsCategory,
                new Dictionary<string, object?> {
                    ["tileIndex"] = tileIndex.Value,
                    ["screenX"] = screenX,
                    ["screenY"] = screenY,
                    ["previousTileIndex"] = _lastDoubleClickTileIndex,
                    ["elapsedMs"] = _lastDoubleClickTicks > 0 ? now - _lastDoubleClickTicks : null,
                    ["doubleClickTimeMs"] = GetDoubleClickTime(),
                    ["doubleClickWidth"] = GetSystemMetrics(SmCxDoubleClk),
                    ["doubleClickHeight"] = GetSystemMetrics(SmCyDoubleClk),
                    ["isDoubleClick"] = isDoubleClick,
                    ["expandedCameraIndex"] = _expandedCameraIndex
                });

            if (isDoubleClick) {
                ResetDoubleClickTracking();
                LogDoubleClickToggleAttempt("MouseHook", tileIndex.Value, screenX, screenY);
                ToggleCameraTileEnlargeRestore(tileIndex.Value);
                return;
            }

            _lastDoubleClickTileIndex = tileIndex.Value;
            _lastDoubleClickTicks = now;
            _lastDoubleClickX = screenX;
            _lastDoubleClickY = screenY;
        }

        private int? GetCameraTileIndexAtScreenPoint(int screenX, int screenY) {
            var screenPoint = new Point(screenX, screenY);
            for (var i = 0; i < _cameraTiles.Count; i++) {
                var card = _cameraTiles[i].Card;
                if (!card.IsVisible || card.ActualWidth <= 0 || card.ActualHeight <= 0) {
                    continue;
                }

                var cardPoint = card.PointFromScreen(screenPoint);
                if (cardPoint.X >= 0 &&
                    cardPoint.Y >= 0 &&
                    cardPoint.X <= card.ActualWidth &&
                    cardPoint.Y <= card.ActualHeight) {
                    return i;
                }
            }

            return null;
        }

        private void ResetDoubleClickTracking() {
            _lastDoubleClickTileIndex = null;
            _lastDoubleClickTicks = 0;
        }

        private void LogMouseHookDown(MouseHookStruct mouseInfo) {
            JsonLogStore.Information(
                "MouseHookLeftButtonDown",
                "UI-thread mouse hook observed left button down.",
                InputDiagnosticsCategory,
                new Dictionary<string, object?> {
                    ["screenX"] = mouseInfo.pt.x,
                    ["screenY"] = mouseInfo.pt.y,
                    ["hwnd"] = mouseInfo.hwnd.ToInt64(),
                    ["hitTestCode"] = mouseInfo.wHitTestCode,
                    ["tileCount"] = _cameraTiles.Count,
                    ["expandedCameraIndex"] = _expandedCameraIndex
                });
        }

        private void LogLowLevelMouseDown(LowLevelMouseHookStruct mouseInfo) {
            var tileIndex = GetCameraTileIndexAtScreenPoint(mouseInfo.pt.x, mouseInfo.pt.y);
            JsonLogStore.Information(
                "LowLevelMouseHookLeftButtonDown",
                "Low-level mouse hook observed left button down.",
                InputDiagnosticsCategory,
                new Dictionary<string, object?> {
                    ["screenX"] = mouseInfo.pt.x,
                    ["screenY"] = mouseInfo.pt.y,
                    ["mouseData"] = mouseInfo.mouseData,
                    ["flags"] = mouseInfo.flags,
                    ["time"] = mouseInfo.time,
                    ["matchedTileIndex"] = tileIndex,
                    ["tileCount"] = _cameraTiles.Count,
                    ["expandedCameraIndex"] = _expandedCameraIndex
                });
        }

        private void LogCardMouseDown(
            string eventName,
            string message,
            int tileIndex,
            int screenX,
            int screenY,
            int clickCount,
            bool handledBefore) {
            JsonLogStore.Information(
                eventName,
                message,
                InputDiagnosticsCategory,
                new Dictionary<string, object?> {
                    ["tileIndex"] = tileIndex,
                    ["screenX"] = screenX,
                    ["screenY"] = screenY,
                    ["clickCount"] = clickCount,
                    ["handledBefore"] = handledBefore,
                    ["expandedCameraIndex"] = _expandedCameraIndex
                });
        }

        private void LogDoubleClickToggleAttempt(string source, int tileIndex, int screenX, int screenY) {
            JsonLogStore.Information(
                "DoubleClickToggleAttempt",
                "Double-click detection is attempting to toggle expand/collapse.",
                InputDiagnosticsCategory,
                new Dictionary<string, object?> {
                    ["source"] = source,
                    ["tileIndex"] = tileIndex,
                    ["screenX"] = screenX,
                    ["screenY"] = screenY,
                    ["expandedCameraIndex"] = _expandedCameraIndex
                });
        }

        private void LogUnmatchedMouseDown(int screenX, int screenY) {
            var now = Environment.TickCount64;
            if (now - _lastUnmatchedMouseLogTicks < 1000) {
                return;
            }

            _lastUnmatchedMouseLogTicks = now;
            JsonLogStore.Information(
                "MouseDownDidNotMatchCameraCard",
                "Mouse hook observed left button down, but no visible camera card contained the screen point.",
                InputDiagnosticsCategory,
                new Dictionary<string, object?> {
                    ["screenX"] = screenX,
                    ["screenY"] = screenY,
                    ["tileCount"] = _cameraTiles.Count,
                    ["expandedCameraIndex"] = _expandedCameraIndex,
                    ["visibleTileCount"] = _cameraTiles.Count(tile => tile.Card.IsVisible)
                });
        }

        private void Window_Loaded(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            if (_isStreamingEngineReady) {
                _ = StartStartupCameraFlowAsync();
            }
        }

        private void Window_ContentRendered(object? sender, EventArgs e) {
            _ = sender;
            _ = e;
            if (!_hasStartedStreamingEngineInitialization) {
                _hasStartedStreamingEngineInitialization = true;
                _ = Dispatcher.BeginInvoke(
                    new Action(() => QueueStreamingEngineInitialization(isRetry: false)),
                    DispatcherPriority.Background);
            }

            if (!_hasResolvedPremiumUiState) {
                _hasResolvedPremiumUiState = true;
                _ = Dispatcher.BeginInvoke(new Action(async () => {
                    await RefreshPremiumEntitlementAsync("post_render");
                }), DispatcherPriority.Background);
            }

        }

        private async Task StartStartupCameraFlowAsync() {
            if (_hasStartedStartupCameraFlow || _isClosing || !_isStreamingEngineReady) {
                return;
            }

            _hasStartedStartupCameraFlow = true;
            if (_settings.ReconnectRecentCamerasOnStartup == true) {
                await StartRecentCameraReconnectAsync();
                return;
            }

            ShowEmptyCameraSlots();
        }

        private void RetryVideoEngineButton_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            QueueStreamingEngineInitialization(isRetry: true);
        }

        private LocalCamSettings GetSettingsSnapshotForService() {
            if (Dispatcher.CheckAccess()) {
                return SettingsStore.Clone(_settings);
            }

            return Dispatcher.Invoke(() => SettingsStore.Clone(_settings));
        }

        private void UpdateSettingsForService(Action<LocalCamSettings> update) {
            void ApplyUpdateAndPersist() {
                update(_settings);
                TrySaveSettings(
                    eventName: "service_settings_save_failed",
                    logMessage: "Failed to persist service-managed settings.");
            }

            if (Dispatcher.CheckAccess()) {
                ApplyUpdateAndPersist();
                return;
            }

            try {
                Dispatcher.Invoke(ApplyUpdateAndPersist);
            }
            catch (Exception ex) {
                JsonLogStore.Error(
                    eventName: "service_settings_dispatch_failed",
                    message: "Failed to marshal service-managed settings persistence to the UI thread.",
                    category: "settings",
                    exception: ex);
            }
        }

        private async Task RefreshPremiumEntitlementAsync(string source) {
            if (_isPremiumEntitlementRefreshBusy) {
                return;
            }

            _isPremiumEntitlementRefreshBusy = true;
            try {
                var result = await _premiumEntitlementService.CheckPremiumEntitlementAsync();
                _isPremiumOwned = result.IsPremiumOwned;
                UpdatePremiumUiVisibility();
                JsonLogStore.Information(
                    eventName: "premium_entitlement_checked",
                    message: "Premium entitlement check completed.",
                    category: "store",
                    data: new Dictionary<string, object?> {
                        ["source"] = source,
                        ["isPremiumOwned"] = _isPremiumOwned,
                        ["isFromStore"] = result.IsFromStore,
                        ["usedFallbackCache"] = result.UsedFallbackCache,
                        ["message"] = result.Message
                    });
            }
            catch (Exception ex) {
                _isPremiumOwned = false;
                UpdatePremiumUiVisibility();
                JsonLogStore.Error(
                    eventName: "premium_entitlement_check_failed",
                    message: "Premium entitlement check failed.",
                    category: "store",
                    exception: ex,
                    data: new Dictionary<string, object?> {
                        ["source"] = source
                    });
            }
            finally {
                _isPremiumEntitlementRefreshBusy = false;
            }
        }

        private async void MainWindow_Activated(object? sender, EventArgs e) {
            _ = sender;
            _ = e;

            if (!_storeContextProvider.IsPackaged ||
                !_hasResolvedPremiumUiState ||
                _isPremiumOwned ||
                _isPremiumPurchaseBusy) {
                return;
            }

            await RefreshPremiumEntitlementAsync("window_activated");
        }

        private void UpdatePremiumUiVisibility() {
            var settingsWindow = FindOpenSettingsWindow();
            settingsWindow?.ApplyPremiumUiState(
                isVisible: _storeContextProvider.IsPackaged && _hasResolvedPremiumUiState,
                isPremiumOwned: _isPremiumOwned,
                isPurchaseBusy: _isPremiumPurchaseBusy);
        }

        private async Task TryStartPremiumPurchaseFlowAsync(
            bool requireConfirmationDialog = false,
            Window? interactionOwner = null) {
            if (!Dispatcher.CheckAccess()) {
                await Dispatcher.InvokeAsync(async () => {
                    await TryStartPremiumPurchaseFlowAsync(requireConfirmationDialog, interactionOwner);
                });
                return;
            }

            if (_isPremiumPurchaseBusy || _isPremiumOwned) {
                return;
            }

            var ownerWindow = interactionOwner is not null && interactionOwner.IsVisible && interactionOwner.IsLoaded
                ? interactionOwner
                : this;

            if (requireConfirmationDialog) {
                var confirmationDialog = new BasicFeatureGateDialog("Upgrade to Premium for full access.") {
                    Owner = ownerWindow
                };
                var confirmationResult = confirmationDialog.ShowDialog();
                if (confirmationResult != true || !confirmationDialog.UpgradeRequested) {
                    return;
                }
            }

            _isPremiumPurchaseBusy = true;
            UpdatePremiumUiVisibility();

            try {
                var purchaseResult = await _premiumPurchaseService.PurchasePremiumAsync();
                StreamingStatusText.Text = purchaseResult.Message;
                JsonLogStore.Information(
                    eventName: "premium_purchase_attempted",
                    message: "Premium purchase flow completed.",
                    category: "store",
                    data: new Dictionary<string, object?> {
                        ["outcome"] = purchaseResult.Outcome.ToString(),
                        ["message"] = purchaseResult.Message
                    });

                if (purchaseResult.Outcome is PremiumPurchaseOutcome.Succeeded or PremiumPurchaseOutcome.AlreadyOwned) {
                    await RefreshPremiumEntitlementAsync("purchase_result");
                }
            }
            catch (Exception ex) {
                StreamingStatusText.Text = "Premium purchase failed due to an unexpected error.";
                JsonLogStore.Error(
                    eventName: "premium_purchase_failed",
                    message: "Premium purchase flow failed.",
                    category: "store",
                    exception: ex);
            }
            finally {
                RestoreWindowAccessibilityAfterStoreFlow(ownerWindow);
                _isPremiumPurchaseBusy = false;
                UpdatePremiumUiVisibility();
            }
        }

        private IntPtr ResolvePurchaseOwnerWindowHandle() {
            Window? ownerWindow = null;
            try {
                ownerWindow = Application.Current?.Windows
                    .OfType<Window>()
                    .FirstOrDefault(window => window.IsVisible && window.IsActive && window.IsLoaded);
            }
            catch {
                ownerWindow = null;
            }

            if (ownerWindow is null || ownerWindow == this || !ownerWindow.IsVisible || !ownerWindow.IsLoaded) {
                ownerWindow = this;
            }

            try {
                return new WindowInteropHelper(ownerWindow).Handle;
            }
            catch {
                return new WindowInteropHelper(this).Handle;
            }
        }

        private void RestoreWindowAccessibilityAfterStoreFlow(Window? preferredWindow = null) {
            var focusWindow = preferredWindow is not null && preferredWindow.IsVisible && preferredWindow.IsLoaded
                ? preferredWindow
                : this;

            try {
                if (!focusWindow.IsEnabled) {
                    focusWindow.IsEnabled = true;
                }

                focusWindow.Activate();
                focusWindow.Focus();
                Keyboard.Focus(focusWindow);
            }
            catch {
                // Best-effort accessibility recovery; keep flow non-fatal.
            }

            if (focusWindow != this) {
                return;
            }

            try {
                if (Application.Current?.MainWindow is Window mainWindow) {
                    if (!mainWindow.IsEnabled) {
                        mainWindow.IsEnabled = true;
                    }

                    mainWindow.Activate();
                    mainWindow.Focus();
                    Keyboard.Focus(mainWindow);
                }
            }
            catch {
                // Best-effort accessibility recovery; keep flow non-fatal.
            }
        }

        private async Task ShowBasicFeatureGateDialogAsync(string blockedReason) {
            if (!_storeContextProvider.IsPackaged) {
                return;
            }

            var message = $"{blockedReason} Upgrade to Premium for full access.";
            var dialog = new BasicFeatureGateDialog(message) {
                Owner = this
            };

            var result = dialog.ShowDialog();
            if (result == true && dialog.UpgradeRequested) {
                await TryStartPremiumPurchaseFlowAsync(requireConfirmationDialog: false);
            }
        }

        private bool IsBasicPremiumGatingEnabled() {
            return _storeContextProvider.IsPackaged && !_isPremiumOwned;
        }

        private void UpdateActionButtons() {
            var anyPlaying = IsAnyStreamRunning();
            var anyNotPlaying = HasAnyStoppedDetectedCamera();

            DetectCameraButtonLabel.Text = _isScanning ? "Cancel Detection" : "Detect and Play";
            DetectCameraIcon.Visibility = _isScanning ? Visibility.Collapsed : Visibility.Visible;
            DetectCameraSpinner.Visibility = _isScanning ? Visibility.Visible : Visibility.Collapsed;
            DetectCameraButton.IsEnabled = !_isDetectButtonToggleDelayActive;
            ToolbarPlayAllButton.IsEnabled = _isStreamingEngineReady && anyNotPlaying;
            ToolbarStopButton.IsEnabled = anyPlaying;
            SettingsButton.IsEnabled = true;
            UpdateTileButtonStates();
        }

        private async Task StartRecentCameraReconnectAsync() {
            if (_isClosing || _isScanning) return;
            if (!_isStreamingEngineReady) {
                StreamingStatusText.Text = _isStreamingEngineInitializing
                    ? "Video engine is still starting..."
                    : "Video engine is unavailable. Retry initialization.";
                return;
            }

            var cachedDetections = RecentCameraConnectionCache.GetValidDetections(_settings, DateTimeOffset.UtcNow);
            if (cachedDetections.Count == 0) {
                StreamingStatusText.Text = "Searching local network for cameras...";
                await StartLocalCameraSearchAsync();
                return;
            }
            JsonLogStore.Information("recent_camera_reconnect_requested", "Attempting to reconnect recent cameras before local discovery.", "camera_reconnect", new Dictionary<string, object?> { ["cameraCount"] = cachedDetections.Count });
            ShowDetections(cachedDetections);
            CancelCachedReconnectAttempts();
            for (var index = 0; index < _detections.Count; index++) StartCachedReconnectConfirmation(index, _detections[index]);
            StreamingStatusText.Text = "Reconnecting to recent cameras...";
            await PlayAllStreamsAsync();

            if (_isClosing || !HasValidStreamStartSettings(_settings.RtspUsername.Trim(), _settings.RtspPassword, _settings.StreamPath)) {
                return;
            }

            JsonLogStore.Information(
                eventName: "recent_camera_discovery_refresh_requested",
                message: "Starting a discovery refresh after recent-camera playback requests to find cameras missing from the reconnect cache.",
                category: "camera_reconnect",
                data: new Dictionary<string, object?> {
                    ["cachedCameraCount"] = cachedDetections.Count,
                    ["alreadyScanning"] = _isScanning
                });
            await StartLocalCameraSearchAsync(
                preserveCachedReconnectAttempts: true,
                promptToRetryWithoutDetections: false);
        }

        private bool HandleCachedReconnectFailure(int tileIndex) {
            var detection = CompleteCachedReconnectAttempt(tileIndex);
            if (detection is null) return false;
            var evicted = RecentCameraConnectionCache.RegisterReconnectFailure(_settings, detection, _detections);
            TrySaveSettings("recent_camera_connection_failure_save_failed", "Failed to save recent camera reconnect state.");
            JsonLogStore.Warning(evicted ? "recent_camera_connection_evicted" : "recent_camera_reconnect_failed", evicted ? "A recent camera connection was removed after repeated reconnect failures." : "A recent camera reconnect failed; local discovery will be attempted.", "camera_reconnect", new Dictionary<string, object?> { ["cameraIndex"] = tileIndex + 1, ["ipAddress"] = detection.IpAddress.ToString(), ["evicted"] = evicted });
            if (_isRecoveryDiscoveryQueued || _isClosing || _isScanning) return true;
            _isRecoveryDiscoveryQueued = true;
            StreamingStatusText.Text = "Searching local network for cameras for failed reconnections...";
            Dispatcher.BeginInvoke(new Action(async () => {
                try { await StartLocalCameraSearchAsync(preserveCachedReconnectAttempts: true); }
                finally { _isRecoveryDiscoveryQueued = false; }
            }), DispatcherPriority.Background);
            return true;
        }

        private void StartCachedReconnectConfirmation(int tileIndex, TapoCameraDetection detection) {
            var attemptId = unchecked(++_nextCacheReconnectAttemptId);
            var timeout = new CancellationTokenSource();
            _cacheReconnectAttemptIdsByTile[tileIndex] = attemptId;
            _cacheReconnectDetectionsByAttempt[attemptId] = detection;
            _cacheReconnectTimeoutsByAttempt[attemptId] = timeout;
            _ = ConfirmCachedReconnectAsync(tileIndex, attemptId, timeout.Token);
        }

        private async Task ConfirmCachedReconnectAsync(int tileIndex, long attemptId, CancellationToken cancellationToken) {
            try {
                await Task.Delay(RecentCameraReconnectConfirmationTimeout, cancellationToken);
            }
            catch (OperationCanceledException) {
                return;
            }

            if (_isClosing) return;
            await Dispatcher.InvokeAsync(() => {
                if (_cacheReconnectAttemptIdsByTile.TryGetValue(tileIndex, out var activeAttemptId) && activeAttemptId == attemptId) {
                    JsonLogStore.Warning("recent_camera_reconnect_timed_out", "A recent camera did not confirm playback before the reconnect deadline.", "camera_reconnect", new Dictionary<string, object?> { ["cameraIndex"] = tileIndex + 1 });
                    StopSingleStream(tileIndex, updateStatus: false);
                    HandleCachedReconnectFailure(tileIndex);
                }
            });
        }

        private TapoCameraDetection? CompleteCachedReconnectAttempt(int tileIndex) {
            if (!_cacheReconnectAttemptIdsByTile.Remove(tileIndex, out var attemptId)) return null;
            _cacheReconnectTimeoutsByAttempt.Remove(attemptId, out var timeout);
            timeout?.Cancel();
            timeout?.Dispose();
            _cacheReconnectDetectionsByAttempt.Remove(attemptId, out var detection);
            return detection;
        }

        private void CancelCachedReconnectAttempts() {
            foreach (var timeout in _cacheReconnectTimeoutsByAttempt.Values) {
                timeout.Cancel();
                timeout.Dispose();
            }
            _cacheReconnectTimeoutsByAttempt.Clear();
            _cacheReconnectAttemptIdsByTile.Clear();
            _cacheReconnectDetectionsByAttempt.Clear();
        }

        private void CancelCachedReconnectAttempt(int tileIndex) {
            if (!_cacheReconnectAttemptIdsByTile.Remove(tileIndex, out var attemptId)) {
                return;
            }

            _cacheReconnectTimeoutsByAttempt.Remove(attemptId, out var timeout);
            timeout?.Cancel();
            timeout?.Dispose();
            _cacheReconnectDetectionsByAttempt.Remove(attemptId);
        }

        private async Task StartLocalCameraSearchAsync(
            bool preserveCachedReconnectAttempts = false,
            bool promptToRetryWithoutDetections = true) {
            if (_isClosing || _isScanning) {
                return;
            }

            JsonLogStore.Information(
                eventName: "camera_search_requested",
                message: "User requested a local network camera search.",
                category: "camera_search",
                data: new Dictionary<string, object?> {
                    ["source"] = "main_window",
                    ["isClosing"] = _isClosing,
                    ["isScanning"] = _isScanning
                });

            while (!_isClosing) {
                if (!preserveCachedReconnectAttempts) {
                    CancelCachedReconnectAttempts();
                }
                _isScanning = true;
                _isUserScanCancelRequested = false;
                _scanStoppedForMissingSettings = false;
                _scanHasPublishedDetections = false;
                _scanCancellation = new CancellationTokenSource();
                _ = BeginDetectButtonToggleDelayAsync();
                var progress = new InlineProgress<TapoCameraScanActivity>(activity => {
                    if (!Dispatcher.CheckAccess()) {
                        Dispatcher.Invoke(() => HandleCameraScanActivity(activity));
                        return;
                    }

                    HandleCameraScanActivity(activity);
                });
                var preferredMethod = ResolvePreferredDetectionMethod();
                SetScanningState(preferredMethod);

                try {
                    var recentCameraAddresses = RecentCameraConnectionCache
                        .GetValidDetections(_settings, DateTimeOffset.UtcNow)
                        .Select(static detection => detection.IpAddress)
                        .ToArray();
                    var scanResult = await TapoCameraScanner.ScanLocalNetworkForTapoCamerasWithDiagnosticsAsync(
                        preferredFirstMethod: preferredMethod,
                        progress: progress,
                        cancellationToken: _scanCancellation.Token,
                        recentCameraAddresses: recentCameraAddresses,
                        streamPath: _settings.StreamPath);

                    if (_isClosing) {
                        return;
                    }

                    if (scanResult.Detections.Count > 0) {
                        PersistSuccessfulDetectionMethod(scanResult.SuccessfulMethod);
                        JsonLogStore.Information(
                            eventName: "camera_search_detections_available",
                            message: "Local network scan found one or more likely Tapo cameras.",
                            category: "camera_search",
                            data: new Dictionary<string, object?> {
                                ["detectionCount"] = scanResult.Detections.Count,
                                ["detectedIps"] = scanResult.Detections.Select(d => d.IpAddress.ToString()).ToArray(),
                                ["successfulMethod"] = scanResult.SuccessfulMethod?.ToString()
                            });
                        ShowDetections(scanResult.Detections, scanResult.SuccessfulMethod);
                    }
                    else {
                        JsonLogStore.Warning(
                            eventName: "camera_search_no_detections",
                            message: "Local network scan completed without any likely Tapo cameras.",
                            category: "camera_search",
                            data: new Dictionary<string, object?> {
                                ["attemptedMethods"] = scanResult.AttemptedMethods.Select(a => a.Method.ToString()).ToArray()
                            });
                        ShowNoDetections(BuildNoDetectionsMessage(scanResult.AttemptedMethods));
                    }
                }
                catch (OperationCanceledException) when (_isClosing) {
                    return;
                }
                catch (OperationCanceledException) {
                    if (!_isClosing && !_scanStoppedForMissingSettings) {
                        JsonLogStore.Warning(
                            eventName: "camera_search_operation_canceled",
                            message: "Local network search was canceled.",
                            category: "camera_search");
                        ShowNoDetections("Scan canceled.");
                    }
                }
                catch (Exception ex) {
                    if (!_isClosing) {
                        JsonLogStore.Error(
                            eventName: "camera_search_operation_failed",
                            message: "Local network search failed in the main window.",
                            category: "camera_search",
                            exception: ex);
                        ShowNoDetections($"Scan failed: {ex.Message}");
                    }
                }
                finally {
                    _scanCancellation?.Dispose();
                    _scanCancellation = null;
                    _isScanning = false;
                    SearchProgressBar.Visibility = Visibility.Collapsed;
                    _ = BeginDetectButtonToggleDelayAsync();
                    if (!_isClosing) {
                        UpdateActionButtons();
                    }
                }

                if (_isClosing) {
                    return;
                }

                if (_scanStoppedForMissingSettings) {
                    _scanStoppedForMissingSettings = false;
                    OpenSettingsDialog(RtspSettingsInvalidMessage, highlightMissingCredentials: true);
                    return;
                }

                if (_isUserScanCancelRequested) {
                    return;
                }

                if (_scanHasPublishedDetections || !promptToRetryWithoutDetections) {
                    return;
                }

                var retry = MessageBox.Show(
                    this,
                    "No local camera was found. Retry search?",
                    "LocalCam",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (retry != MessageBoxResult.Yes) {
                    return;
                }
            }
        }

        private void HandleCameraScanActivity(TapoCameraScanActivity activity) {
            if (_isClosing || !_isScanning) {
                return;
            }

            if (activity.Detections is not { Count: > 0 } detections) {
                StreamingStatusText.Text = activity.StatusMessage;
                return;
            }

            var previousDetections = _detections;
            var knownIdentities = previousDetections
                .Select(detection => GetCameraIdentity(detection, previousDetections))
                .ToHashSet(StringComparer.Ordinal);
            ShowDetections(detections, activity.Method, scanInProgress: true);
            _scanHasPublishedDetections = true;

            var newCameraIndexes = Enumerable.Range(0, _detections.Count)
                .Where(index => {
                    var detection = _detections[index];
                    var identity = GetCameraIdentity(detection, _detections);
                    if (knownIdentities.Contains(identity)) {
                        return false;
                    }

                    return !identity.StartsWith("ip:", StringComparison.Ordinal)
                        || !previousDetections.Any(previous =>
                            previous.IpAddress.Equals(detection.IpAddress)
                            && !string.IsNullOrWhiteSpace(detection.MacAddress)
                            && string.Equals(previous.MacAddress?.Trim(), detection.MacAddress.Trim(), StringComparison.OrdinalIgnoreCase));
                })
                .ToArray();
            if (newCameraIndexes.Length == 0) {
                return;
            }

            if (!HasValidStreamStartSettings(_settings.RtspUsername.Trim(), _settings.RtspPassword, _settings.StreamPath)) {
                _scanStoppedForMissingSettings = true;
                _scanCancellation?.Cancel();
                StreamingStatusText.Text = RtspSettingsInvalidMessage;
                JsonLogStore.Warning(
                    eventName: "camera_search_stopped_for_missing_rtsp_settings",
                    message: "Camera discovery stopped after the first camera was found because RTSP settings are incomplete.",
                    category: "camera_search",
                    data: new Dictionary<string, object?> {
                        ["detectedCameraCount"] = _detections.Count,
                        ["missingUsername"] = string.IsNullOrWhiteSpace(_settings.RtspUsername),
                        ["missingPassword"] = string.IsNullOrWhiteSpace(_settings.RtspPassword),
                        ["missingStreamPath"] = string.IsNullOrWhiteSpace(_settings.StreamPath)
                    });
                return;
            }

            foreach (var tileIndex in newCameraIndexes) {
                var identity = GetCameraIdentity(_detections[tileIndex], _detections);
                if (!_discoveryAutoStartedCameraIdentities.Add(identity)) {
                    continue;
                }

                _ = StartSingleStreamAsync(tileIndex, updateStatus: false);
            }
        }

        private void SetScanningState(TapoDetectionMethod? preferredMethod) {
            StreamingStatusText.Text = preferredMethod is TapoDetectionMethod method
                ? $"Trying last successful method: {GetDetectionMethodDisplayName(method)}..."
                : "Searching local network for cameras...";
            CameraTilesPanel.Visibility = _detections.Count > 0
                ? Visibility.Visible
                : Visibility.Collapsed;
            UpdateTileButtonStates();
            UpdateActionButtons();
            SearchProgressBar.Visibility = Visibility.Visible;
        }

        private void ShowEmptyCameraSlots() {
            StreamingStatusText.Text = "Search local camera to populate the empty camera cards.";
            CameraTilesPanel.Visibility = Visibility.Collapsed;
            UpdateTileButtonStates();
            UpdateActionButtons();
            SearchProgressBar.Visibility = Visibility.Collapsed;
        }

        private void ShowDetections(IReadOnlyList<TapoCameraDetection> detections, TapoDetectionMethod? successfulMethod = null, bool scanInProgress = false) {
            _detections = CameraDetectionReconciler.Reconcile(_detections, detections);
            CameraTilesPanel.Visibility = Visibility.Visible;
            PopulateCameraTiles(_detections);
            ApplyResponsiveCameraLayout();
            StreamingStatusText.Text = scanInProgress
                ? $"Found {_detections.Count} {Pluralize(_detections.Count, "camera")}. Continuing search for more cameras..."
                : BuildDetectionsStatusText(_detections.Count, successfulMethod);
            UpdateActionButtons();
            SearchProgressBar.Visibility = scanInProgress ? Visibility.Visible : Visibility.Collapsed;
        }

        private void QueueDetectedStreamStart() {
            Dispatcher.BeginInvoke(
                new Action(StartDetectedStreamsIfReady),
                System.Windows.Threading.DispatcherPriority.Background);
        }

        private void ShowNoDetections(string? prefixMessage = null) {
            var hasExistingDetections = _detections.Count > 0;
            if (!hasExistingDetections) {
                _expandedCameraIndex = null;
            }
            CameraTilesPanel.Visibility = hasExistingDetections
                ? Visibility.Visible
                : Visibility.Collapsed;
            UpdateTileButtonStates();
            UpdateActionButtons();
            SearchProgressBar.Visibility = Visibility.Collapsed;

            if (!string.IsNullOrWhiteSpace(prefixMessage)) {
                if (hasExistingDetections && prefixMessage.StartsWith("No compatible camera detected.", StringComparison.Ordinal)) {
                    prefixMessage = prefixMessage.Replace(
                        "No compatible camera detected.",
                        "No additional camera detected.",
                        StringComparison.Ordinal);
                    StreamingStatusText.Text = $"{prefixMessage} Existing camera cards remain visible. Retry search?";
                }
                else {
                    StreamingStatusText.Text = hasExistingDetections
                        ? $"{prefixMessage} Existing camera cards remain visible."
                        : $"{prefixMessage} Retry search?";
                }
                return;
            }

            StreamingStatusText.Text = hasExistingDetections
                ? "No new camera was detected. Existing camera cards remain visible. Retry search?"
                : "No compatible camera detected. Retry search?";
        }

        private void DetectAndPlayButton_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;

            if (_isScanning) {
                _isUserScanCancelRequested = true;
                _scanCancellation?.Cancel();
                return;
            }

            _ = StartRecentCameraReconnectAsync();
        }

        private async Task BeginDetectButtonToggleDelayAsync() {
            var version = unchecked(++_detectButtonToggleVersion);
            _isDetectButtonToggleDelayActive = true;
            UpdateActionButtons();

            try {
                await Task.Delay(1000);
            }
            finally {
                if (version == _detectButtonToggleVersion) {
                    _isDetectButtonToggleDelayActive = false;
                    if (!_isClosing) {
                        UpdateActionButtons();
                    }
                }
            }
        }

        private async void ToolbarPlayAllButton_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            await PlayAllStreamsAsync();
        }

        private void ToolbarStopButton_Click(object sender, RoutedEventArgs e) {
            StopAllStreams();
            StreamingStatusText.Text = "Streams stopped.";
            UpdateActionButtons();
        }

        private void SettingsButton_Click(object sender, RoutedEventArgs e) {
            OpenSettingsDialog();
        }

        private void OpenSettingsDialog(
            string? inlineErrorMessage = null,
            bool highlightMissingCredentials = false,
            bool focusUsername = false) {
            var text = (inlineErrorMessage ?? string.Empty).Trim();
            var openSettingsWindow = FindOpenSettingsWindow();
            if (openSettingsWindow is not null) {
                if (highlightMissingCredentials) {
                    openSettingsWindow.ShowCredentialValidation(focusUsername);
                }
                else {
                    openSettingsWindow.ShowInlineError(text);
                }
                openSettingsWindow.Activate();
                return;
            }

            var dialog = new SettingsWindow(_settings, GetStoreVersionDisplayText()) {
                Owner = this
            };
            dialog.SetPremiumUpgradeHandler(() => TryStartPremiumPurchaseFlowAsync(
                requireConfirmationDialog: true,
                interactionOwner: dialog));
            dialog.ApplyPremiumUiState(
                isVisible: _storeContextProvider.IsPackaged && _hasResolvedPremiumUiState,
                isPremiumOwned: _isPremiumOwned,
                isPurchaseBusy: _isPremiumPurchaseBusy);

            if (highlightMissingCredentials) {
                dialog.ShowCredentialValidation(focusUsername);
            }
            else if (!string.IsNullOrWhiteSpace(text)) {
                dialog.ShowInlineError(text);
            }

            _isSettingsDialogOpen = true;
            try {
                dialog.ShowDialog();
                if (dialog.DidSave) {
                    var rtspConfigurationChanged = !string.Equals(_settings.RtspUsername, dialog.Settings.RtspUsername, StringComparison.Ordinal) ||
                        !string.Equals(_settings.RtspPassword, dialog.Settings.RtspPassword, StringComparison.Ordinal) ||
                        !string.Equals(NormalizeStreamPath(_settings.StreamPath), NormalizeStreamPath(dialog.Settings.StreamPath), StringComparison.Ordinal);
                    SettingsWindow.ApplyEditableSettings(_settings, dialog.Settings);
                    if (rtspConfigurationChanged) {
                        RecentCameraConnectionCache.InvalidateAll(_settings);
                        TrySaveSettings("recent_camera_connection_invalidation_save_failed", "Failed to clear recent camera connections after RTSP configuration changed.");
                        JsonLogStore.Information("recent_camera_connections_invalidated", "Recent camera connections were cleared because RTSP configuration changed.", "camera_reconnect");
                    }
                    AppThemeService.Apply(_settings.ThemePreference);
                    RefreshCameraThemeResources();
                    if (highlightMissingCredentials) {
                        StartDetectedStreamsIfReady();
                    }
                }
            }
            finally {
                _isSettingsDialogOpen = false;
                ResetDoubleClickTracking();
            }
        }

        private SettingsWindow? FindOpenSettingsWindow() {
            foreach (Window ownedWindow in OwnedWindows) {
                if (ownedWindow is SettingsWindow settingsWindow && settingsWindow.IsVisible) {
                    return settingsWindow;
                }
            }

            return null;
        }

        private bool IsSettingsDialogOpen() {
            if (_isSettingsDialogOpen) {
                return true;
            }

            foreach (Window ownedWindow in OwnedWindows) {
                if (ownedWindow is SettingsWindow && ownedWindow.IsVisible) {
                    return true;
                }
            }

            return false;
        }

        private async Task PlayAllStreamsAsync() {
            if (!_isStreamingEngineReady || _libVlc is null) {
                JsonLogStore.Warning(
                    eventName: "camera_connect_blocked",
                    message: "RTSP stream start was blocked because the video engine is unavailable.",
                    category: "camera_connect");
                StreamingStatusText.Text = "Cannot start streams: video engine is unavailable.";
                return;
            }

            if (_detections.Count == 0) {
                JsonLogStore.Warning(
                    eventName: "camera_connect_blocked",
                    message: "RTSP stream start was blocked because no cameras were detected.",
                    category: "camera_connect");
                StreamingStatusText.Text = "Cannot start streams: no cameras were detected.";
                return;
            }

            var username = _settings.RtspUsername.Trim();
            var password = _settings.RtspPassword;
            var streamPath = NormalizeStreamPath(_settings.StreamPath);
            var isBasicMode = IsBasicPremiumGatingEnabled();
            var remainingBasicSlots = isBasicMode ? Math.Max(0, BasicConcurrentStreamLimit - CountActiveStreams()) : int.MaxValue;

            if (!HasValidStreamStartSettings(username, password, _settings.StreamPath)) {
                JsonLogStore.Warning(
                    eventName: "camera_connect_blocked",
                    message: "RTSP stream start was blocked because credentials or stream path are invalid.",
                    category: "camera_connect",
                    data: new Dictionary<string, object?> {
                        ["cameraCount"] = _detections.Count,
                        ["streamPath"] = streamPath
                    });
                StreamingStatusText.Text = RtspSettingsInvalidMessage;
                OpenSettingsDialog(RtspSettingsInvalidMessage, highlightMissingCredentials: true);
                return;
            }

            if (isBasicMode && remainingBasicSlots <= 0) {
                StreamingStatusText.Text = $"Basic supports up to {BasicConcurrentStreamLimit} active live streams.";
                await ShowBasicFeatureGateDialogAsync($"Basic mode supports up to {BasicConcurrentStreamLimit} active live streams at a time.");
                return;
            }

            
            JsonLogStore.Information(
                eventName: "camera_connect_requested",
                message: "Starting RTSP connections for detected cameras.",
                category: "camera_connect",
                data: new Dictionary<string, object?> {
                    ["cameraCount"] = _detections.Count,
                    ["streamPath"] = streamPath,
                    ["hasUsername"] = !string.IsNullOrWhiteSpace(username),
                    });

            UpdateActionButtons();

            var startedCount = 0;
            var failedEndpoints = new List<string>();
            var blockedByBasicLimit = false;
            var credentialFailureDetected = false;
            EnsureCameraTileCount(_detections.Count);
            for (var i = 0; i < _cameraTiles.Count && i < _detections.Count; i++) {
                if (!CanStartStream(i)) {
                    continue;
                }
                if (isBasicMode && remainingBasicSlots <= 0) {
                    blockedByBasicLimit = true;
                    break;
                }
                var ipAddress = _detections[i].IpAddress.ToString();
                var streamUrl = BuildRtspUrl(ipAddress, username, password, streamPath, _detections[i].RtspPort);
                VlcMediaPlayer? mediaPlayer = null;

                try {
                    JsonLogStore.Information(
                        eventName: "camera_connect_attempt",
                        message: "Attempting to start an RTSP stream.",
                        category: "camera_connect",
                        data: new Dictionary<string, object?> {
                            ["cameraIndex"] = i + 1,
                        ["ipAddress"] = ipAddress,
                        ["streamPath"] = streamPath
                    });

                    _streamRecoveryStates.Remove(i);
                    SetStreamLifecyclePhase(i, StreamLifecyclePhase.Starting);
                    EnsureVideoSurfaceAttached(i);
                    using var media = CreateRtspPlaybackMedia(streamUrl);

                    ReplaceMediaPlayer(i, _detections[i]);
                    mediaPlayer = _cameraTiles[i].MediaPlayer;
                    _lastLibVlcErrorMessage = null;
                    TaskCompletionSource<bool>? confirmationWaiter = null;
                    if (mediaPlayer is not null) {
                        confirmationWaiter = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                        _playbackConfirmationWaiters[mediaPlayer] = confirmationWaiter;
                    }
                    if (mediaPlayer is not null && mediaPlayer.Play(media)) {
                        startedCount++;
                        if (isBasicMode) {
                            remainingBasicSlots--;
                        }
                        SetVideoSurfaceActive(i, isActive: true);
                        if (confirmationWaiter is not null) {
                            _ = MonitorPlaybackConfirmationAsync(i, mediaPlayer, confirmationWaiter, ipAddress, streamPath);
                        }
                        JsonLogStore.Information(
                            eventName: "camera_play_request_accepted",
                            message: "LibVLC accepted an RTSP playback request; confirmation is pending.",
                            category: "camera_connect",
                            data: new Dictionary<string, object?> {
                                ["cameraIndex"] = i + 1,
                                ["ipAddress"] = ipAddress,
                                ["streamPath"] = streamPath
                            });
                    }
                    else {
                        if (mediaPlayer is not null) {
                            CompletePlaybackConfirmation(mediaPlayer, confirmed: false);
                        }
                        var failure = StreamFailureClassifier.Classify(
                            "media player returned false",
                            null,
                            _lastLibVlcErrorMessage);
                        SetPlaybackFailure(i, failure);
                        credentialFailureDetected |= failure.RequiresSettings;
                        failedEndpoints.Add(ipAddress);
                        SetVideoSurfaceActive(i, isActive: false);
                        SetStreamLifecyclePhase(i, StreamLifecyclePhase.Stopped);
                        _streamStartOrder.Remove(i);
                        JsonLogStore.Warning(
                            eventName: "camera_connect_failed",
                            message: "RTSP stream failed to start.",
                            category: "camera_connect",
                            data: new Dictionary<string, object?> {
                                ["cameraIndex"] = i + 1,
                                ["ipAddress"] = ipAddress,
                                ["streamPath"] = streamPath,
                                ["reason"] = failure.DiagnosticReason,
                                ["failureKind"] = failure.Kind.ToString()
                            });
                        HandleCachedReconnectFailure(i);
                    }
                }
                catch (Exception ex) {
                    if (mediaPlayer is not null) {
                        CompletePlaybackConfirmation(mediaPlayer, confirmed: false);
                    }
                    SetStreamLifecyclePhase(i, StreamLifecyclePhase.Stopped);
                    var failure = StreamFailureClassifier.Classify(null, ex.Message, _lastLibVlcErrorMessage);
                    SetPlaybackFailure(i, failure);
                    credentialFailureDetected |= failure.RequiresSettings;
                    failedEndpoints.Add(ipAddress);
                    SetVideoSurfaceActive(i, isActive: false);
                    _streamStartOrder.Remove(i);
                    JsonLogStore.Error(
                        eventName: "camera_connect_exception",
                        message: "RTSP stream start threw an exception.",
                        category: "camera_connect",
                        exception: ex,
                        data: new Dictionary<string, object?> {
                            ["cameraIndex"] = i + 1,
                            ["ipAddress"] = ipAddress,
                            ["streamPath"] = streamPath
                        });
                    HandleCachedReconnectFailure(i);
                }
            }

            _streamsRunning = startedCount > 0 || IsAnyStreamRunning();
            if (blockedByBasicLimit) {
                await ShowBasicFeatureGateDialogAsync($"Basic mode supports up to {BasicConcurrentStreamLimit} active live streams at a time.");
            }
            if (failedEndpoints.Count == 0) {
                JsonLogStore.Information(
                        eventName: "camera_connect_completed",
                        message: "RTSP playback requests were submitted for all detected cameras.",
                    category: "camera_connect",
                    data: new Dictionary<string, object?> {
                            ["acceptedCount"] = startedCount,
                        ["failedCount"] = 0,
                        ["cameraCount"] = _detections.Count,
                        ["streamPath"] = streamPath
                    });
                StreamingStatusText.Text = $"Starting playback for {startedCount} {Pluralize(startedCount, "camera")}.";
                UpdateActionButtons();
                return;
            }

            JsonLogStore.Warning(
                eventName: "camera_connect_completed_with_failures",
                message: "RTSP playback requests were submitted with one or more failures.",
                category: "camera_connect",
                data: new Dictionary<string, object?> {
                    ["startedCount"] = startedCount,
                    ["failedCount"] = failedEndpoints.Count,
                    ["cameraCount"] = _detections.Count,
                    ["failedEndpoints"] = failedEndpoints.ToArray(),
                    ["streamPath"] = streamPath
                });
            StreamingStatusText.Text =
                $"Starting {startedCount} {Pluralize(startedCount, "stream")}. Failed to submit: {string.Join(", ", failedEndpoints)}.";
            UpdateActionButtons();
            if (credentialFailureDetected) {
                HandleCredentialRelatedPlaybackFailure(
                    new StreamFailureDetails(
                        StreamFailureKind.Credential,
                        "RTSP credentials were rejected by one or more cameras.",
                        "Check the RTSP username and password in Settings.",
                        "one or more camera playback failures were classified as credential-related"));
            }
        }

        private void StartDetectedStreamsIfReady() {
            if (_isClosing || _isScanning) {
                return;
            }

            if (!_isStreamingEngineReady || _libVlc is null || _detections.Count == 0) {
                return;
            }

            if (!HasValidStreamStartSettings(_settings.RtspUsername.Trim(), _settings.RtspPassword, _settings.StreamPath)) {
                StreamingStatusText.Text = RtspSettingsInvalidMessage;
                OpenSettingsDialog(RtspSettingsInvalidMessage, highlightMissingCredentials: true);
                return;
            }

            _ = PlayAllStreamsAsync();
        }

        private void StopAllStreams() {
            InvalidateAutomaticStreamRecovery();
            _expandedCameraIndex = null;
            StopRecordingSession("all_streams_stopped", updateStatus: false);
            for (var i = 0; i < _cameraTiles.Count; i++) {
                SetStreamLifecyclePhase(i, StreamLifecyclePhase.Stopping);
                ClearPlaybackFailure(i);
                var mediaPlayer = _cameraTiles[i].MediaPlayer;
                if (mediaPlayer is null) {
                    continue;
                }

                StopMediaPlayerIntentionally(mediaPlayer);

                SetVideoSurfaceActive(i, isActive: false);
                SetStreamLifecyclePhase(i, StreamLifecyclePhase.Stopped);
            }

            _streamStartOrder.Clear();
            _streamFailureReasons.Clear();
            _streamHealthStates.Clear();
            _streamRecoveryStates.Clear();
            _terminalStreamRecoveryAttempts.Clear();
            _streamsRunning = false;
            ApplyResponsiveCameraLayout();
            UpdateActionButtons();
        }

        private async Task<bool> StartSingleStreamAsync(
            int tileIndex,
            bool updateStatus = true,
            bool requestMonitorWake = true,
            bool isMonitorRecovery = false,
            CancellationToken cancellationToken = default) {
            if (!_isStreamingEngineReady || _libVlc is null || tileIndex < 0 || tileIndex >= _cameraTiles.Count || tileIndex >= _detections.Count) {
                return false;
            }

            if (!CanStartStream(tileIndex)) {
                return false;
            }

            if (!isMonitorRecovery) {
                _streamRecoveryStates.Remove(tileIndex);
            }

            if (IsBasicPremiumGatingEnabled() && CountActiveStreams() >= BasicConcurrentStreamLimit) {
                StreamingStatusText.Text = $"Basic supports up to {BasicConcurrentStreamLimit} active live streams.";
                await ShowBasicFeatureGateDialogAsync($"Basic mode supports up to {BasicConcurrentStreamLimit} active live streams at a time.");
                return false;
            }

            var username = _settings.RtspUsername.Trim();
            var password = _settings.RtspPassword;
            if (!HasValidStreamStartSettings(username, password, _settings.StreamPath)) {
                StreamingStatusText.Text = RtspSettingsInvalidMessage;
                OpenSettingsDialog(RtspSettingsInvalidMessage, highlightMissingCredentials: true);
                return false;
            }

            var streamPath = NormalizeStreamPath(_settings.StreamPath);
            var ipAddress = _detections[tileIndex].IpAddress.ToString();
            VlcMediaPlayer? mediaPlayer = null;
            StreamFailureDetails? failure = null;

            try {
                SetStreamLifecyclePhase(tileIndex, isMonitorRecovery ? StreamLifecyclePhase.Restarting : StreamLifecyclePhase.Starting);
                EnsureVideoSurfaceAttached(tileIndex);

                using var media = new Media(_libVlc, BuildRtspUrl(ipAddress, username, password, streamPath, _detections[tileIndex].RtspPort), FromType.FromLocation);
                media.AddOption(":network-caching=300");
                media.AddOption(":live-caching=300");
                media.AddOption(":clock-jitter=0");
                media.AddOption(":clock-synchro=0");

                ReplaceMediaPlayer(tileIndex, _detections[tileIndex]);
                mediaPlayer = _cameraTiles[tileIndex].MediaPlayer;
                _lastLibVlcErrorMessage = null;
                TaskCompletionSource<bool>? confirmationWaiter = null;
                if (mediaPlayer is not null) {
                    confirmationWaiter = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    _playbackConfirmationWaiters[mediaPlayer] = confirmationWaiter;
                }

                if (mediaPlayer is not null && mediaPlayer.Play(media)) {

                    SetVideoSurfaceActive(tileIndex, isActive: true);
                    if (updateStatus) {
                        StreamingStatusText.Text = isMonitorRecovery
                            ? $"Restarting camera {tileIndex + 1}."
                            : $"Starting camera {tileIndex + 1}.";
                    }
                    if (requestMonitorWake) {
                        RequestCameraMonitoring();
                    }

                    if (confirmationWaiter is not null) {
                        if (isMonitorRecovery) {
                            var confirmed = await WaitForPlaybackConfirmationAsync(mediaPlayer, confirmationWaiter, cancellationToken);
                            if (!confirmed) {
                                failure = StreamFailureClassifier.Classify(
                                    "playback confirmation timed out",
                                    null,
                                    null);
                                StopSingleStream(tileIndex, updateStatus: false, invalidateAutomaticRecovery: false);
                                SetPlaybackFailure(tileIndex, failure);
                                LogPlaybackConfirmationTimeout(tileIndex, ipAddress, streamPath);
                                HandleCredentialRelatedPlaybackFailure(failure, tileIndex);
                                return false;
                            }
                            else {
                                return true;
                            }
                        }
                        else {
                            _ = MonitorPlaybackConfirmationAsync(tileIndex, mediaPlayer, confirmationWaiter, ipAddress, streamPath);
                        }
                    }

                    JsonLogStore.Information(
                        eventName: "camera_play_request_accepted",
                        message: "LibVLC accepted an RTSP playback request; confirmation is pending.",
                        category: "camera_connect",
                        data: new Dictionary<string, object?> {
                            ["cameraIndex"] = tileIndex + 1,
                            ["ipAddress"] = ipAddress,
                            ["streamPath"] = streamPath,
                            ["isMonitorRecovery"] = isMonitorRecovery
                        });
                    return true;
                }
            }
            catch (Exception ex) {
                SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
                failure = StreamFailureClassifier.Classify(null, ex.Message, _lastLibVlcErrorMessage);
                JsonLogStore.Error(
                    eventName: "camera_connect_exception",
                    message: "Single-camera RTSP stream start threw an exception.",
                    category: "camera_connect",
                    exception: ex,
                    data: new Dictionary<string, object?> {
                        ["cameraIndex"] = tileIndex + 1,
                        ["ipAddress"] = ipAddress,
                        ["streamPath"] = streamPath
                    });
            }

            if (mediaPlayer is not null) {
                CompletePlaybackConfirmation(mediaPlayer, confirmed: false);
            }
            SetVideoSurfaceActive(tileIndex, isActive: false);
            SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
            _streamStartOrder.Remove(tileIndex);
            failure ??= StreamFailureClassifier.Classify(
                "media player returned false",
                null,
                _lastLibVlcErrorMessage);
            SetPlaybackFailure(tileIndex, failure);
            if (updateStatus) {
                StreamingStatusText.Text = $"Failed to start camera {tileIndex + 1}: {failure.UserMessage}";
            }
            HandleCredentialRelatedPlaybackFailure(failure, tileIndex);
            return false;
        }

        private async Task<bool> WaitForPlaybackConfirmationAsync(
            VlcMediaPlayer mediaPlayer,
            TaskCompletionSource<bool> waiter,
            CancellationToken cancellationToken) {
            try {
                var completed = await Task.WhenAny(
                    waiter.Task,
                    Task.Delay(PlaybackConfirmationTimeout, cancellationToken));
                if (completed == waiter.Task) {
                    return await waiter.Task;
                }

                return false;
            }
            catch (OperationCanceledException) {
                return false;
            }
            finally {
                if (_playbackConfirmationWaiters.TryGetValue(mediaPlayer, out var currentWaiter) && ReferenceEquals(currentWaiter, waiter)) {
                    _playbackConfirmationWaiters.Remove(mediaPlayer);
                }
            }
        }

        private async Task MonitorPlaybackConfirmationAsync(
            int tileIndex,
            VlcMediaPlayer mediaPlayer,
            TaskCompletionSource<bool> waiter,
            string ipAddress,
            string streamPath) {
            var confirmed = await WaitForPlaybackConfirmationAsync(mediaPlayer, waiter, CancellationToken.None);
            if (confirmed || _isClosing || tileIndex < 0 || tileIndex >= _cameraTiles.Count ||
                !ReferenceEquals(_cameraTiles[tileIndex].MediaPlayer, mediaPlayer) ||
                GetStreamLifecyclePhase(tileIndex) is not (StreamLifecyclePhase.Starting or StreamLifecyclePhase.Restarting)) {
                return;
            }

            var failure = StreamFailureClassifier.Classify(
                "playback confirmation timed out",
                null,
                null);
            StopSingleStream(tileIndex, updateStatus: false, invalidateAutomaticRecovery: false);
            SetPlaybackFailure(tileIndex, failure);
            LogPlaybackConfirmationTimeout(tileIndex, ipAddress, streamPath);
            HandleCredentialRelatedPlaybackFailure(failure, tileIndex);
            _streamsRunning = IsAnyStreamRunning();
            UpdateActionButtons();
        }

        private void LogPlaybackConfirmationTimeout(int tileIndex, string ipAddress, string streamPath) {
            JsonLogStore.Warning(
                eventName: "camera_playback_confirmation_timeout",
                message: "A camera playback request did not reach confirmed playback within the timeout.",
                category: "camera_connect",
                data: new Dictionary<string, object?> {
                    ["cameraIndex"] = tileIndex + 1,
                    ["ipAddress"] = ipAddress,
                    ["streamPath"] = streamPath,
                    ["timeoutSeconds"] = PlaybackConfirmationTimeout.TotalSeconds
                });
        }

        private void StopSingleStream(int tileIndex, bool updateStatus = true, bool invalidateAutomaticRecovery = true) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count) {
                return;
            }

            if (_activeRecordingTileIndex == tileIndex) {
                StopRecordingSession("stream_stopped", updateStatus: false);
            }

            if (invalidateAutomaticRecovery) {
                InvalidateAutomaticStreamRecovery();
            }

            ClearPlaybackFailure(tileIndex);
            SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopping);
            var mediaPlayer = _cameraTiles[tileIndex].MediaPlayer;
            StopMediaPlayerIntentionally(mediaPlayer);

            SetVideoSurfaceActive(tileIndex, isActive: false);
            SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
            _streamHealthStates.Remove(tileIndex);
            _streamStartOrder.Remove(tileIndex);
            _terminalStreamRecoveryAttempts.Remove(tileIndex);
            if (invalidateAutomaticRecovery) {
                _streamRecoveryStates.Remove(tileIndex);
            }
            if (updateStatus) {
                StreamingStatusText.Text = $"Stopped camera {tileIndex + 1}.";
            }
        }

        private void ReplaceMediaPlayer(int tileIndex, TapoCameraDetection detection) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count) {
                return;
            }

            var tile = _cameraTiles[tileIndex];
            StopMediaPlayerIntentionally(tile.MediaPlayer);
            tile.VideoView.MediaPlayer = null;
            DisposeMediaPlayer(tile.MediaPlayer);
            tile.MediaPlayer = null;
            AttachMediaPlayer(tile, detection);
        }

        private void InvalidateAutomaticStreamRecovery() {
            _streamRecoveryGeneration = unchecked(_streamRecoveryGeneration + 1);
        }

        private void StopMediaPlayerIntentionally(VlcMediaPlayer? mediaPlayer) {
            if (mediaPlayer is null) {
                return;
            }

            _intentionalStoppedMediaPlayers.Add(mediaPlayer);
            mediaPlayer.Stop();
        }

        private void DisposeMediaPlayer(VlcMediaPlayer? mediaPlayer) {
            if (mediaPlayer is null) {
                return;
            }

            _intentionalStoppedMediaPlayers.Remove(mediaPlayer);
            CompletePlaybackConfirmation(mediaPlayer, confirmed: false);
            mediaPlayer.Dispose();
        }

        private void CompletePlaybackConfirmation(VlcMediaPlayer mediaPlayer, bool confirmed) {
            if (_playbackConfirmationWaiters.Remove(mediaPlayer, out var waiter)) {
                waiter.TrySetResult(confirmed);
            }
        }

        private bool IsStreamRunning(int tileIndex) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count) {
                return false;
            }

            var mediaPlayer = _cameraTiles[tileIndex].MediaPlayer;
            return mediaPlayer is not null && mediaPlayer.IsPlaying;
        }

        private bool HasAnyStoppedDetectedCamera() {
            var count = Math.Min(_cameraTiles.Count, _detections.Count);
            for (var i = 0; i < count; i++) {
                if (CanStartStream(i)) {
                    return true;
                }
            }

            return false;
        }

        private void MarkStreamStarted(int tileIndex, StreamHealthSample sample) {
            SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Running);
            _streamStartOrder[tileIndex] = _nextStreamStartOrder++;
            var state = GetOrCreateStreamHealthState(tileIndex);
            if (state is not null) {
                StreamHealthEvaluator.StartPlayback(state, sample);
            }
        }

        private void ClearPlaybackFailureOnPlaybackConfirmed(int tileIndex, StreamHealthSample sample) {
            if (_streamFailureReasons.TryGetValue(tileIndex, out var failure) &&
                failure.DiagnosticReason == StreamHealthEvaluator.VideoOutputNotConfirmedReason &&
                !StreamHealthEvaluator.HasVideoEvidence(sample)) {
                return;
            }

            ClearPlaybackFailure(tileIndex);
        }

        private StreamHealthState? GetOrCreateStreamHealthState(int tileIndex) {
            if (tileIndex < 0) {
                return null;
            }

            if (!_streamHealthStates.TryGetValue(tileIndex, out var state)) {
                state = new StreamHealthState();
                _streamHealthStates[tileIndex] = state;
            }

            return state;
        }

        private StreamLifecyclePhase GetStreamLifecyclePhase(int tileIndex) {
            return _streamHealthStates.TryGetValue(tileIndex, out var state)
                ? state.LifecyclePhase
                : StreamLifecyclePhase.Stopped;
        }

        private void SetStreamLifecyclePhase(int tileIndex, StreamLifecyclePhase phase) {
            var state = GetOrCreateStreamHealthState(tileIndex);
            if (state is null) {
                return;
            }

            state.LifecyclePhase = phase;
        }

        private bool IsStreamTransitioning(int tileIndex) {
            return GetStreamLifecyclePhase(tileIndex) is StreamLifecyclePhase.Starting or StreamLifecyclePhase.Stopping or StreamLifecyclePhase.Restarting;
        }

        private bool CanStartStream(int tileIndex) {
            return !IsStreamRunning(tileIndex) && !IsStreamTransitioning(tileIndex);
        }

        private void RequestCameraMonitoring() {
            if (_isClosing || _libVlc is null) {
                return;
            }

            lock (_cameraMonitorSync) {
                if (_cameraMonitorTask is null || _cameraMonitorTask.IsCompleted) {
                    _cameraMonitorCancellation?.Dispose();
                    _cameraMonitorCancellation = new CancellationTokenSource();
                    _cameraMonitorTask = RunCameraMonitoringLoopAsync(_cameraMonitorCancellation.Token);
                }
            }
        }

        private async Task RunCameraMonitoringLoopAsync(CancellationToken cancellationToken) {
            try {
                await Task.Yield();
                while (!cancellationToken.IsCancellationRequested) {
                    var activeTileIndexes = await InvokeCameraMonitorOnUiThreadAsync(GetMonitoredTileIndexes, cancellationToken);
                    if (activeTileIndexes.Length == 0) {
                        await Task.Delay(CameraMonitorIdleInterval, cancellationToken);
                        continue;
                    }

                    foreach (var tileIndex in activeTileIndexes) {
                        if (cancellationToken.IsCancellationRequested) {
                            break;
                        }

                        try {
                            var health = await InvokeCameraMonitorOnUiThreadAsync(
                                () => EvaluateStreamHealth(tileIndex),
                                cancellationToken);
                            if (health.RequiresRecovery) {
                                await InvokeCameraMonitorOnUiThreadAsync(
                                    () => RestartCameraStreamAsync(tileIndex, health.Reason, cancellationToken),
                                    cancellationToken);
                            }
                        }
                        catch (OperationCanceledException) {
                            throw;
                        }
                        catch (Exception ex) {
                            JsonLogStore.Error(
                                eventName: "camera_stream_monitor_tile_failed",
                                message: "The camera stream monitor failed while inspecting a tile.",
                                category: "camera_connect",
                                exception: ex,
                                data: new Dictionary<string, object?> {
                                    ["cameraIndex"] = tileIndex + 1,
                                    ["ipAddress"] = tileIndex < _detections.Count ? _detections[tileIndex].IpAddress.ToString() : null
                                });
                        }
                    }

                    if (cancellationToken.IsCancellationRequested) {
                        break;
                    }

                    await Task.Delay(CameraMonitorCycleInterval, cancellationToken);
                }
            }
            catch (OperationCanceledException) {
            }
            catch (Exception ex) {
                JsonLogStore.Error(
                    eventName: "camera_stream_monitor_failed",
                    message: "The camera stream monitor failed unexpectedly.",
                    category: "camera_connect",
                    exception: ex);
            }
        }

        private Task InvokeCameraMonitorOnUiThreadAsync(Action action, CancellationToken cancellationToken) {
            if (Dispatcher.CheckAccess()) {
                action();
                return Task.CompletedTask;
            }

            return Dispatcher.InvokeAsync(action, DispatcherPriority.Background, cancellationToken).Task;
        }

        private Task<T> InvokeCameraMonitorOnUiThreadAsync<T>(Func<T> action, CancellationToken cancellationToken) {
            if (Dispatcher.CheckAccess()) {
                return Task.FromResult(action());
            }

            return Dispatcher.InvokeAsync(action, DispatcherPriority.Background, cancellationToken).Task;
        }

        private Task InvokeCameraMonitorOnUiThreadAsync(Func<Task> action, CancellationToken cancellationToken) {
            if (Dispatcher.CheckAccess()) {
                return action();
            }

            return Dispatcher.InvokeAsync(action, DispatcherPriority.Background, cancellationToken).Task.Unwrap();
        }

        private int[] GetMonitoredTileIndexes() {
            return _streamStartOrder
                .OrderBy(pair => pair.Value)
                .Select(pair => pair.Key)
                .Where(index => index >= 0 && index < _cameraTiles.Count && index < _detections.Count)
                .Where(index => GetStreamLifecyclePhase(index) == StreamLifecyclePhase.Running)
                .ToArray();
        }

        private StreamHealthEvaluation EvaluateStreamHealth(int tileIndex) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count || tileIndex >= _detections.Count) {
                return new StreamHealthEvaluation(
                    StreamHealthEvaluationKind.Stale,
                    HasProgressed: false,
                    "camera tile is no longer available");
            }

            var mediaPlayer = _cameraTiles[tileIndex].MediaPlayer;
            if (mediaPlayer is null) {
                return new StreamHealthEvaluation(
                    StreamHealthEvaluationKind.Unhealthy,
                    HasProgressed: false,
                    "media player is unavailable");
            }

            var state = GetOrCreateStreamHealthState(tileIndex);
            if (state is null) {
                return new StreamHealthEvaluation(
                    StreamHealthEvaluationKind.Unhealthy,
                    HasProgressed: false,
                    "stream health state is unavailable");
            }

            var sample = CaptureStreamSample(mediaPlayer);
            var hadVideoEvidence = state.VideoOutputConfirmedAt.HasValue;
            var evaluation = StreamHealthEvaluator.Observe(
                state,
                sample,
                CameraMonitorStartupGracePeriod,
                CameraMonitorStaleAfter,
                CameraMonitorUnhealthySampleLimit);
            if (!hadVideoEvidence && state.VideoOutputConfirmedAt is DateTimeOffset videoEvidenceAt) {
                JsonLogStore.Information(
                    eventName: "camera_video_frame_progress_observed",
                    message: "LibVLC exposed video output or decoded/displayed frame progress for a camera.",
                    category: "camera_connect",
                    data: new Dictionary<string, object?> {
                        ["cameraIndex"] = tileIndex + 1,
                        ["ipAddress"] = _detections[tileIndex].IpAddress.ToString(),
                        ["elapsedSincePlaybackMs"] = (long)(videoEvidenceAt - (state.PlaybackConfirmedAt ?? videoEvidenceAt)).TotalMilliseconds,
                        ["voutCount"] = mediaPlayer.VoutCount,
                        ["mediaTime"] = sample.MediaTime,
                        ["position"] = sample.Position,
                        ["displayedPictures"] = sample.DisplayedPictures,
                        ["decodedVideo"] = sample.DecodedVideo,
                        ["readBytes"] = sample.ReadBytes
                    });
                ClearVideoOutputFailure(tileIndex);
            }

            if (evaluation.Kind == StreamHealthEvaluationKind.Unhealthy && state.ConsecutiveUnhealthySamples == 1) {
                JsonLogStore.Information(
                    eventName: "camera_stream_health_degraded",
                    message: "A camera stream health sample did not show usable playback progress.",
                    category: "camera_connect",
                    data: new Dictionary<string, object?> {
                        ["cameraIndex"] = tileIndex + 1,
                        ["ipAddress"] = _detections[tileIndex].IpAddress.ToString(),
                        ["reason"] = evaluation.Reason,
                        ["consecutiveUnhealthySamples"] = state.ConsecutiveUnhealthySamples,
                        ["voutCount"] = mediaPlayer.VoutCount,
                        ["mediaTime"] = sample.MediaTime,
                        ["position"] = sample.Position,
                        ["displayedPictures"] = sample.DisplayedPictures,
                        ["decodedVideo"] = sample.DecodedVideo,
                        ["readBytes"] = sample.ReadBytes,
                        ["videoOutputObserved"] = state.VideoOutputConfirmedAt.HasValue
                    });
            }

            if (evaluation.Kind == StreamHealthEvaluationKind.Stale &&
                evaluation.Reason == StreamHealthEvaluator.VideoOutputNotConfirmedReason &&
                (!_streamFailureReasons.TryGetValue(tileIndex, out var existingFailure) ||
                 existingFailure!.DiagnosticReason != StreamHealthEvaluator.VideoOutputNotConfirmedReason)) {
                SetPlaybackFailure(tileIndex, CreateVideoOutputFailure());
                JsonLogStore.Warning(
                    eventName: "camera_video_output_confirmation_timeout",
                    message: "A camera stream started, but LibVLC did not report video output or frame progress before the health deadline.",
                    category: "camera_connect",
                    data: new Dictionary<string, object?> {
                        ["cameraIndex"] = tileIndex + 1,
                        ["ipAddress"] = _detections[tileIndex].IpAddress.ToString(),
                        ["elapsedSincePlaybackMs"] = (long)(sample.Timestamp - (state.PlaybackConfirmedAt ?? sample.Timestamp)).TotalMilliseconds,
                        ["voutCount"] = mediaPlayer.VoutCount,
                        ["mediaTime"] = sample.MediaTime,
                        ["position"] = sample.Position,
                        ["displayedPictures"] = sample.DisplayedPictures,
                        ["decodedVideo"] = sample.DecodedVideo,
                        ["readBytes"] = sample.ReadBytes
                    });
            }

            return evaluation;
        }

        private static StreamHealthSample CaptureStreamSample(VlcMediaPlayer mediaPlayer) {
            var displayedPictures = 0;
            var decodedVideo = 0;
            var readBytes = 0;
            using (var media = mediaPlayer.Media) {
                if (media is not null) {
                    var stats = media.Statistics;
                    displayedPictures = stats.DisplayedPictures;
                    decodedVideo = stats.DecodedVideo;
                    readBytes = stats.ReadBytes;
                }
            }

            return new StreamHealthSample(
                DateTimeOffset.UtcNow,
                mediaPlayer.IsPlaying && mediaPlayer.State == VLCState.Playing,
                mediaPlayer.VoutCount > 0,
                mediaPlayer.Time,
                mediaPlayer.Position,
                displayedPictures,
                decodedVideo,
                readBytes);
        }

        private async Task RestartCameraStreamAsync(int tileIndex, string reason, CancellationToken cancellationToken) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count || tileIndex >= _detections.Count) {
                return;
            }

            if (GetStreamLifecyclePhase(tileIndex) != StreamLifecyclePhase.Running || !IsStreamRunning(tileIndex)) {
                return;
            }

            if (!TryBeginCameraMonitorRecovery(tileIndex, out var attempt, out var recoveryBlockedReason)) {
                if (recoveryBlockedReason == "attempt_limit_reached") {
                    MarkCameraMonitorRecoveryExhausted(tileIndex, reason);
                }
                return;
            }

            var recoveryGeneration = _streamRecoveryGeneration;
            var ipAddress = _detections[tileIndex].IpAddress.ToString();
            var streamPath = NormalizeStreamPath(_settings.StreamPath);
            JsonLogStore.Warning(
                eventName: "camera_stream_recovery_requested",
                message: "A camera stream remained unhealthy and will be restarted.",
                category: "camera_connect",
                data: new Dictionary<string, object?> {
                    ["cameraIndex"] = tileIndex + 1,
                    ["ipAddress"] = ipAddress,
                    ["streamPath"] = streamPath,
                    ["reason"] = reason,
                    ["attempt"] = attempt
                });

            SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopping);
            StopSingleStream(tileIndex, updateStatus: false, invalidateAutomaticRecovery: false);
            if (reason == StreamHealthEvaluator.VideoOutputNotConfirmedReason) {
                SetPlaybackFailure(tileIndex, CreateVideoOutputFailure());
            }

            try {
                await Task.Delay(CameraMonitorRestartSettleDelay, cancellationToken);
            }
            catch (OperationCanceledException) {
                return;
            }

            if (cancellationToken.IsCancellationRequested || _isClosing || recoveryGeneration != _streamRecoveryGeneration) {
                return;
            }

            if (GetStreamLifecyclePhase(tileIndex) != StreamLifecyclePhase.Stopped) {
                return;
            }

            if (await StartSingleStreamAsync(
                    tileIndex,
                    updateStatus: false,
                    requestMonitorWake: false,
                    isMonitorRecovery: true,
                    cancellationToken: cancellationToken)) {
                JsonLogStore.Information(
                    eventName: "camera_stream_recovery_confirmed",
                    message: "A camera stream recovery reached confirmed playback.",
                    category: "camera_connect",
                    data: new Dictionary<string, object?> {
                        ["cameraIndex"] = tileIndex + 1,
                        ["ipAddress"] = ipAddress,
                        ["streamPath"] = streamPath,
                        ["attempt"] = attempt
                    });
                return;
            }

            JsonLogStore.Warning(
                eventName: "camera_stream_recovery_failed",
                message: "A camera stream recovery did not reach confirmed playback.",
                category: "camera_connect",
                data: new Dictionary<string, object?> {
                    ["cameraIndex"] = tileIndex + 1,
                    ["ipAddress"] = ipAddress,
                    ["streamPath"] = streamPath,
                    ["attempt"] = attempt
                });
        }

        private bool TryBeginCameraMonitorRecovery(int tileIndex, out int attempt, out string reason) {
            var now = DateTimeOffset.UtcNow;
            if (!_streamRecoveryStates.TryGetValue(tileIndex, out var state)) {
                state = new StreamRecoveryState();
                _streamRecoveryStates[tileIndex] = state;
            }

            if (now < state.CooldownUntil) {
                attempt = state.AttemptsInWindow;
                reason = "cooldown_active";
                return false;
            }

            if (state.WindowStartedAt == default || now - state.WindowStartedAt >= CameraMonitorRecoveryWindow) {
                state.WindowStartedAt = now;
                state.AttemptsInWindow = 0;
                state.Exhausted = false;
            }

            if (state.AttemptsInWindow >= CameraMonitorRecoveryAttemptLimit) {
                attempt = state.AttemptsInWindow;
                reason = "attempt_limit_reached";
                return false;
            }

            state.AttemptsInWindow++;
            state.CooldownUntil = now + CameraMonitorRecoveryCooldown;
            attempt = state.AttemptsInWindow;
            reason = string.Empty;
            return true;
        }

        private void MarkCameraMonitorRecoveryExhausted(int tileIndex, string? recoveryReason = null) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count || tileIndex >= _detections.Count ||
                !_streamRecoveryStates.TryGetValue(tileIndex, out var recoveryState) || recoveryState.Exhausted) {
                return;
            }

            recoveryState.Exhausted = true;
            var failure = recoveryReason == StreamHealthEvaluator.VideoOutputNotConfirmedReason
                ? new StreamFailureDetails(
                    StreamFailureKind.PlaybackStalled,
                    "The stream connected, but no video frames arrived.",
                    "Automatic recovery could not get video frames. Check the camera's stream settings and try Play again.",
                    StreamHealthEvaluator.VideoOutputNotConfirmedReason)
                : new StreamFailureDetails(
                    StreamFailureKind.PlaybackStalled,
                    "Camera playback is not advancing.",
                    "Try Play again or check the camera connection.",
                    "automatic stream recovery attempt limit reached");
            StopSingleStream(tileIndex, updateStatus: false, invalidateAutomaticRecovery: false);
            SetPlaybackFailure(tileIndex, failure);
            JsonLogStore.Warning(
                eventName: "camera_stream_recovery_exhausted",
                message: "Automatic recovery stopped for a camera after repeated stale playback.",
                category: "camera_connect",
                data: new Dictionary<string, object?> {
                    ["cameraIndex"] = tileIndex + 1,
                    ["ipAddress"] = _detections[tileIndex].IpAddress.ToString(),
                    ["attemptLimit"] = CameraMonitorRecoveryAttemptLimit,
                    ["recoveryReason"] = recoveryReason
                });
            _streamsRunning = IsAnyStreamRunning();
            UpdateActionButtons();
        }

        private async Task RecoverTerminalStreamAsync(int tileIndex, string reason) {
            if (_isClosing || tileIndex < 0 || tileIndex >= _cameraTiles.Count || tileIndex >= _detections.Count) {
                return;
            }

            var attemptCount = _terminalStreamRecoveryAttempts.TryGetValue(tileIndex, out var existingAttempts)
                ? existingAttempts + 1
                : 1;
            if (attemptCount > TerminalStreamRecoveryAttemptLimit) {
                return;
            }

            var recoveryGeneration = _streamRecoveryGeneration;
            _terminalStreamRecoveryAttempts[tileIndex] = attemptCount;
            var ipAddress = _detections[tileIndex].IpAddress.ToString();
            JsonLogStore.Warning(
                eventName: "camera_stream_terminal_recovery_requested",
                message: "A camera stream ended unexpectedly and will be restarted.",
                category: "camera_connect",
                data: new Dictionary<string, object?> {
                    ["cameraIndex"] = tileIndex + 1,
                    ["ipAddress"] = ipAddress,
                    ["reason"] = reason,
                    ["attempt"] = attemptCount
                });

            try {
                await Task.Delay(CameraMonitorRestartSettleDelay);
            }
            catch (OperationCanceledException) {
                return;
            }

            if (_isClosing || recoveryGeneration != _streamRecoveryGeneration || IsStreamRunning(tileIndex) || IsStreamTransitioning(tileIndex)) {
                return;
            }

            if (await StartSingleStreamAsync(tileIndex, updateStatus: false, requestMonitorWake: false, isMonitorRecovery: true)) {
                StreamingStatusText.Text = $"Restarting camera {tileIndex + 1} after stream {reason}.";
                return;
            }

            StreamingStatusText.Text = $"Camera {tileIndex + 1} stopped after stream {reason}; restart failed.";
            JsonLogStore.Warning(
                eventName: "camera_stream_terminal_recovery_failed",
                message: "A terminal camera stream recovery attempt failed.",
                category: "camera_connect",
                data: new Dictionary<string, object?> {
                    ["cameraIndex"] = tileIndex + 1,
                    ["ipAddress"] = ipAddress,
                    ["reason"] = reason,
                    ["attempt"] = attemptCount
                });
        }

        private int CountRunningStreams() {
            var count = 0;
            for (var i = 0; i < _cameraTiles.Count; i++) {
                if (IsStreamRunning(i)) {
                    count++;
                }
            }

            return count;
        }

        private async Task SaveSnapshotAsync(int tileIndex) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count) {
                return;
            }

            var tile = _cameraTiles[tileIndex];
            if (tile.IsSnapshotSaving) {
                return;
            }

            var mediaPlayer = tile.MediaPlayer;
            if (mediaPlayer is null || !mediaPlayer.IsPlaying) {
                return;
            }

            if (!TryGetEffectiveSnapshotDirectory(out var targetDirectory, out var resolutionError)) {
                StreamingStatusText.Text = $"Snapshot failed: {resolutionError}";
                JsonLogStore.Warning(
                    "SnapshotSaveRejected",
                    "Snapshot save rejected because snapshot folder resolution failed.",
                    SnapshotDiagnosticsCategory,
                    new Dictionary<string, object?> {
                        ["tileIndex"] = tileIndex,
                        ["reason"] = resolutionError
                    });
                return;
            }

            var fileName = $"camera-{tileIndex + 1}-{DateTime.Now:yyyyMMdd-HHmmss-fff}.png";
            var snapshotPath = IOPath.Combine(targetDirectory, fileName);

            tile.IsSnapshotSaving = true;
            UpdateTileButtonStates();
            try {
                await Task.Run(() => {
                    System.IO.Directory.CreateDirectory(targetDirectory);
                    var saved = mediaPlayer.TakeSnapshot(0, snapshotPath, 0, 0);
                    if (!saved) {
                        throw new InvalidOperationException("Media player snapshot capture returned false.");
                    }
                });

                StreamingStatusText.Text = $"Saved snapshot for camera {tileIndex + 1} to {snapshotPath}.";
                JsonLogStore.Information(
                    "SnapshotSaved",
                    "Snapshot image saved successfully.",
                    SnapshotDiagnosticsCategory,
                    new Dictionary<string, object?> {
                        ["tileIndex"] = tileIndex,
                        ["path"] = snapshotPath
                    });
            }
            catch (Exception ex) {
                StreamingStatusText.Text = $"Snapshot failed for camera {tileIndex + 1}: {ex.Message}";
                JsonLogStore.Warning(
                    "SnapshotSaveFailed",
                    "Snapshot image save failed.",
                    SnapshotDiagnosticsCategory,
                    new Dictionary<string, object?> {
                        ["tileIndex"] = tileIndex,
                        ["path"] = snapshotPath,
                        ["exceptionType"] = ex.GetType().FullName,
                        ["exceptionMessage"] = ex.Message
                    });
            }
            finally {
                tile.IsSnapshotSaving = false;
                UpdateTileButtonStates();
            }
        }

        private bool TryGetEffectiveSnapshotDirectory(out string directoryPath, out string error) {
            var picturesPath = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
            if (string.IsNullOrWhiteSpace(picturesPath)) {
                directoryPath = string.Empty;
                error = "Pictures folder path is unavailable.";
                return false;
            }

            var configuredPath = (_settings.SnapshotSaveFolder ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(configuredPath)) {
                directoryPath = IOPath.Combine(picturesPath, "LocalCam");
                error = string.Empty;
                return true;
            }

            string configuredFullPath;
            string picturesFullPath;
            try {
                configuredFullPath = IOPath.GetFullPath(configuredPath)
                    .TrimEnd(IOPath.DirectorySeparatorChar, IOPath.AltDirectorySeparatorChar);
                picturesFullPath = IOPath.GetFullPath(picturesPath)
                    .TrimEnd(IOPath.DirectorySeparatorChar, IOPath.AltDirectorySeparatorChar);
            }
            catch {
                directoryPath = string.Empty;
                error = "Snapshot folder path is invalid.";
                return false;
            }

            var sameAsPictures = string.Equals(
                configuredFullPath,
                picturesFullPath,
                StringComparison.OrdinalIgnoreCase);

            directoryPath = sameAsPictures
                ? IOPath.Combine(picturesPath, "LocalCam")
                : configuredPath;
            error = string.Empty;
            return true;
        }

        private async Task ToggleRecordingAsync(int tileIndex) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count || tileIndex >= _detections.Count || _isRecordingOperationProcessing) {
                LogRecordingWarning(
                    "RecordingToggleIgnored",
                    "Recording toggle request ignored because state was invalid.",
                    tileIndex,
                    reason: "invalid_tile_or_operation_in_progress");
                return;
            }

            _isRecordingOperationProcessing = true;
            LogRecordingInfo(
                "RecordingToggleRequested",
                "Recording toggle requested from card toolbar.",
                tileIndex);
            UpdateTileButtonStates();
            try {
                if (_activeRecordingTileIndex == tileIndex) {
                    StopRecordingSession("user_stop", updateStatus: true);
                    return;
                }

                if (IsBasicPremiumGatingEnabled()) {
                    var remaining = GetBasicRecordingRemaining();
                    if (remaining <= TimeSpan.Zero) {
                        ReportRecordingActivity("Basic daily recording limit reached (30 minutes).");
                        await ShowBasicFeatureGateDialogAsync("Recording is limited to 30 minutes per day in Basic mode.");
                        return;
                    }
                }

                string? successStatusMessage = null;
                if (_activeRecordingTileIndex is int previousTileIndex) {
                    StopRecordingSession("switched", updateStatus: false);
                    successStatusMessage = $"Recording switched from camera {previousTileIndex + 1} to camera {tileIndex + 1}.";
                    LogRecordingInfo(
                        "RecordingSwitched",
                        "Recording switched from one camera card to another.",
                        tileIndex,
                        data: new Dictionary<string, object?> {
                            ["previousTileIndex"] = previousTileIndex,
                            ["newTileIndex"] = tileIndex
                        });
                }

                await StartRecordingSessionAsync(tileIndex, segmentNumber: 1, reason: "user_start", successStatusMessage);
            }
            finally {
                _isRecordingOperationProcessing = false;
                UpdateTileButtonStates();
            }
        }

        private async Task<bool> StartRecordingSessionAsync(
            int tileIndex,
            int segmentNumber,
            string reason,
            string? successStatusMessage = null) {
            if (_libVlc is null) {
                ReportRecordingActivity("Recording failed: video engine is unavailable.");
                LogRecordingWarning(
                    "RecordingStartRejected",
                    "Recording start rejected because the video engine is unavailable.",
                    tileIndex,
                    reason: "video_engine_unavailable");
                return false;
            }

            if (!IsStreamRunning(tileIndex)) {
                ReportRecordingActivity($"Recording failed: camera {tileIndex + 1} is not playing.");
                LogRecordingWarning(
                    "RecordingStartRejected",
                    "Recording start rejected because the camera stream is not playing.",
                    tileIndex,
                    reason: "stream_not_playing");
                return false;
            }

            if (!TryGetEffectiveRecordingDirectory(out var targetDirectory, out var resolutionError)) {
                ReportRecordingActivity($"Recording failed: {resolutionError}");
                LogRecordingWarning(
                    "RecordingStartRejected",
                    "Recording start rejected because recording folder resolution failed.",
                    tileIndex,
                    reason: resolutionError);
                return false;
            }

            var username = _settings.RtspUsername.Trim();
            var password = _settings.RtspPassword;
            var streamPath = NormalizeStreamPath(_settings.StreamPath);
            if (!HasCompleteStreamingSettings(username, password)) {
                ReportRecordingActivity(BuildMissingSettingsPrompt());
                LogRecordingWarning(
                    "RecordingStartRejected",
                    "Recording start rejected because streaming credentials are incomplete.",
                    tileIndex,
                    reason: "incomplete_streaming_settings");
                return false;
            }

            var ipAddress = _detections[tileIndex].IpAddress.ToString();
            var recordingPath = CreateUniqueRecordingPath(targetDirectory, tileIndex, segmentNumber);
            var basicRemaining = IsBasicPremiumGatingEnabled() ? GetBasicRecordingRemaining() : TimeSpan.Zero;

            try {
                await Task.Run(() => System.IO.Directory.CreateDirectory(targetDirectory));

                var recorder = new VlcMediaPlayer(_libVlc) {
                    EnableHardwareDecoding = false,
                    EnableMouseInput = false,
                    Mute = true
                };
                AttachRecordingEventHandlers(recorder, tileIndex, recordingPath);

                using var media = CreateRtspPlaybackMedia(BuildRtspUrl(ipAddress, username, password, streamPath, _detections[tileIndex].RtspPort));
                media.AddOption(BuildRecordingSoutOption(recordingPath));

                if (!recorder.Play(media)) {
                    recorder.Dispose();
                    throw new InvalidOperationException("Media player recording start returned false.");
                }

                _recordingMediaPlayer = recorder;
                _activeRecordingTileIndex = tileIndex;
                _recordingSegmentNumber = segmentNumber;
                _recordingSessionId = _nextRecordingSessionId++;
                _recordingOutputPath = recordingPath;
                _recordingSegmentStartedAt = DateTimeOffset.Now;
                StartRecordingTimers();
                StartBasicRecordingDailyLimitTimerIfNeeded(basicRemaining);
                UpdateRecordingElapsedText();
                StartRecordingOutputValidation(tileIndex, recordingPath, segmentNumber);
                ReportRecordingActivity(successStatusMessage ?? (segmentNumber == 1
                    ? $"Recording camera {tileIndex + 1} to {recordingPath}."
                    : $"Recording camera {tileIndex + 1} segment {segmentNumber}."));

                LogRecordingInfo(
                    "RecordingStarted",
                    "Video recording started.",
                    tileIndex,
                    data: new Dictionary<string, object?> {
                        ["tileIndex"] = tileIndex,
                        ["ipAddress"] = ipAddress,
                        ["streamPath"] = streamPath,
                        ["path"] = recordingPath,
                        ["segmentNumber"] = segmentNumber,
                        ["reason"] = reason,
                        });
                return true;
            }
            catch (Exception ex) {
                ReportRecordingActivity($"Recording failed for camera {tileIndex + 1}: {ex.Message}");
                LogRecordingWarning(
                    "RecordingStartFailed",
                    "Video recording start failed.",
                    tileIndex,
                    data: new Dictionary<string, object?> {
                        ["ipAddress"] = ipAddress,
                        ["streamPath"] = streamPath,
                        ["path"] = recordingPath,
                        ["exceptionType"] = ex.GetType().FullName,
                        ["exceptionMessage"] = ex.Message
                    });
                return false;
            }
        }

        private void AttachRecordingEventHandlers(VlcMediaPlayer recorder, int tileIndex, string recordingPath) {
            recorder.Playing += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                if (!ReferenceEquals(_recordingMediaPlayer, recorder)) {
                    return;
                }

                LogRecordingInfo(
                    "RecordingPlaybackConfirmed",
                    "LibVLC reported that the recording media player is playing.",
                    tileIndex,
                    data: new Dictionary<string, object?> {
                        ["path"] = recordingPath
                    });
            }));

            recorder.Stopped += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                if (ReferenceEquals(_recordingMediaPlayer, recorder)) {
                    StopRecordingSession("recording_stopped", updateStatus: true);
                }
            }));

            recorder.EndReached += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                if (ReferenceEquals(_recordingMediaPlayer, recorder)) {
                    StopRecordingSession("recording_ended", updateStatus: true);
                }
            }));

            recorder.EncounteredError += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                if (ReferenceEquals(_recordingMediaPlayer, recorder)) {
                    StopRecordingSession("recording_error", updateStatus: true);
                }
            }));
        }

        private void StopRecordingSession(string reason, bool updateStatus) {
            var recorder = _recordingMediaPlayer;
            var tileIndex = _activeRecordingTileIndex;
            var outputPath = _recordingOutputPath;
            var startedAt = _recordingSegmentStartedAt;
            var sessionId = _recordingSessionId;
            StopRecordingTimers();

            _recordingMediaPlayer = null;
            _activeRecordingTileIndex = null;
            _recordingOutputPath = null;
            _recordingSegmentStartedAt = null;
            _recordingSegmentNumber = 0;
            _recordingSessionId = 0;
            CancelRecordingOutputValidation();
            StopBasicRecordingDailyLimitTimer();

            try {
                if (recorder is not null) {
                    if (recorder.IsPlaying) {
                        recorder.Stop();
                    }

                    recorder.Dispose();
                }
            }
            catch (Exception ex) {
                LogRecordingWarning(
                    "RecordingStopFailed",
                    "Video recording stop failed.",
                    tileIndex,
                    data: new Dictionary<string, object?> {
                        ["path"] = outputPath,
                        ["reason"] = reason,
                        ["sessionId"] = sessionId,
                        ["exceptionType"] = ex.GetType().FullName,
                        ["exceptionMessage"] = ex.Message
                    });
            }

            if (tileIndex is int stoppedTileIndex) {
                var duration = startedAt.HasValue ? DateTimeOffset.Now - startedAt.Value : TimeSpan.Zero;
                if (IsBasicPremiumGatingEnabled() && duration > TimeSpan.Zero) {
                    AddBasicRecordingUsage(duration);
                }
                LogRecordingInfo(
                    "RecordingStopped",
                    "Video recording stopped.",
                    stoppedTileIndex,
                    data: new Dictionary<string, object?> {
                        ["path"] = outputPath,
                        ["reason"] = reason,
                        ["sessionId"] = sessionId,
                        ["durationSeconds"] = Math.Round(duration.TotalSeconds, 1)
                    });

                if (updateStatus) {
                    ReportRecordingActivity(reason switch {
                        "daily_limit_reached" => "Recording stopped: Basic daily limit reached (30 minutes).",
                        "stream_stopped" => $"Recording stopped because camera {stoppedTileIndex + 1} stopped.",
                        "stream_ended" => $"Recording stopped because camera {stoppedTileIndex + 1} ended.",
                        "stream_error" => $"Recording stopped because camera {stoppedTileIndex + 1} had a stream error.",
                        "recording_stopped" => $"Recording stopped for camera {stoppedTileIndex + 1}.",
                        "recording_ended" => $"Recording ended for camera {stoppedTileIndex + 1}.",
                        "recording_error" => $"Recording failed for camera {stoppedTileIndex + 1}.",
                                                _ => $"Stopped recording camera {stoppedTileIndex + 1}."
                    });
                }
            }

            UpdateTileButtonStates();
        }

        private async void RecordingSegmentTimer_Tick(object? sender, EventArgs e) {
            if (_isRecordingOperationProcessing || _activeRecordingTileIndex is not int tileIndex) {
                return;
            }

            if (!IsStreamRunning(tileIndex)) {
                StopRecordingSession("stream_stopped", updateStatus: true);
                return;
            }

            _isRecordingOperationProcessing = true;
            UpdateTileButtonStates();
            try {
                var nextSegmentNumber = _recordingSegmentNumber + 1;
                StopRecordingSession("segment_limit_reached", updateStatus: false);
                var started = await StartRecordingSessionAsync(tileIndex, nextSegmentNumber, reason: "segment_rollover");
                if (started) {
                    LogRecordingInfo(
                        "RecordingSegmentRolled",
                        "Video recording rolled to a new segment after reaching the segment duration limit.",
                        tileIndex,
                        data: new Dictionary<string, object?> {
                            ["segmentNumber"] = nextSegmentNumber,
                            ["segmentDurationMinutes"] = RecordingSegmentDuration.TotalMinutes
                        });
                }
            }
            finally {
                _isRecordingOperationProcessing = false;
                UpdateTileButtonStates();
            }
        }

        private void StartRecordingTimers() {
            StopRecordingTimers();

            _recordingElapsedTimer = new DispatcherTimer {
                Interval = TimeSpan.FromSeconds(1)
            };
            _recordingElapsedTimer.Tick += (_, _) => UpdateRecordingElapsedText();
            _recordingElapsedTimer.Start();

            _recordingSegmentTimer = new DispatcherTimer {
                Interval = RecordingSegmentDuration
            };
            _recordingSegmentTimer.Tick += RecordingSegmentTimer_Tick;
            _recordingSegmentTimer.Start();
        }

        private void StartBasicRecordingDailyLimitTimerIfNeeded(TimeSpan remaining) {
            StopBasicRecordingDailyLimitTimer();
            if (!IsBasicPremiumGatingEnabled() || remaining <= TimeSpan.Zero) {
                return;
            }

            _basicRecordingDailyLimitTimer = new DispatcherTimer {
                Interval = remaining
            };
            _basicRecordingDailyLimitTimer.Tick += BasicRecordingDailyLimitTimer_Tick;
            _basicRecordingDailyLimitTimer.Start();
        }

        private void StopBasicRecordingDailyLimitTimer() {
            if (_basicRecordingDailyLimitTimer is null) {
                return;
            }

            _basicRecordingDailyLimitTimer.Stop();
            _basicRecordingDailyLimitTimer.Tick -= BasicRecordingDailyLimitTimer_Tick;
            _basicRecordingDailyLimitTimer = null;
        }

        private async void BasicRecordingDailyLimitTimer_Tick(object? sender, EventArgs e) {
            _ = sender;
            _ = e;
            StopBasicRecordingDailyLimitTimer();
            if (!IsBasicPremiumGatingEnabled()) {
                return;
            }
            if (_activeRecordingTileIndex is null) {
                return;
            }

            StopRecordingSession("daily_limit_reached", updateStatus: true);
            await ShowBasicFeatureGateDialogAsync("Recording is limited to 30 minutes per day in Basic mode.");
        }

        private void StartRecordingOutputValidation(int tileIndex, string recordingPath, int segmentNumber) {
            CancelRecordingOutputValidation();
            var cts = new CancellationTokenSource();
            _recordingOutputValidationCts = cts;
            _ = ValidateRecordingOutputAsync(tileIndex, recordingPath, segmentNumber, cts.Token);
        }

        private void CancelRecordingOutputValidation() {
            if (_recordingOutputValidationCts is null) {
                return;
            }

            _recordingOutputValidationCts.Cancel();
            _recordingOutputValidationCts.Dispose();
            _recordingOutputValidationCts = null;
        }

        private async Task ValidateRecordingOutputAsync(int tileIndex, string recordingPath, int segmentNumber, CancellationToken cancellationToken) {
            try {
                await Task.Delay(1200, cancellationToken);
                for (var attempt = 0; attempt < 6; attempt++) {
                    cancellationToken.ThrowIfCancellationRequested();

                    var hasOutput = false;
                    try {
                        if (System.IO.File.Exists(recordingPath)) {
                            var info = new System.IO.FileInfo(recordingPath);
                            hasOutput = info.Exists && info.Length > 0;
                        }
                    }
                    catch {
                        hasOutput = false;
                    }

                    if (hasOutput) {
                        LogRecordingInfo(
                            "RecordingOutputConfirmed",
                            "Recording output file was confirmed after start.",
                            tileIndex,
                            data: new Dictionary<string, object?> {
                                ["path"] = recordingPath,
                                ["segmentNumber"] = segmentNumber
                            });
                        return;
                    }

                    await Task.Delay(600, cancellationToken);
                }

                await Dispatcher.InvokeAsync(() => {
                    if (_activeRecordingTileIndex != tileIndex || !string.Equals(_recordingOutputPath, recordingPath, StringComparison.Ordinal)) {
                        return;
                    }

                    StopRecordingSession("recording_output_unavailable", updateStatus: false);
                    ReportRecordingActivity($"Recording failed for camera {tileIndex + 1}: output file was not created.");
                    LogRecordingWarning(
                        "RecordingOutputMissing",
                        "Recording output file was not created after recorder start.",
                        tileIndex,
                        data: new Dictionary<string, object?> {
                            ["path"] = recordingPath,
                            ["segmentNumber"] = segmentNumber
                        });
                });
            }
            catch (OperationCanceledException) {
                // Expected when recording stops or switches.
            }
            catch (Exception ex) {
                await Dispatcher.InvokeAsync(() => {
                    LogRecordingWarning(
                        "RecordingOutputValidationFailed",
                        "Recording output validation failed unexpectedly.",
                        tileIndex,
                        data: new Dictionary<string, object?> {
                            ["path"] = recordingPath,
                            ["segmentNumber"] = segmentNumber,
                            ["exceptionType"] = ex.GetType().FullName,
                            ["exceptionMessage"] = ex.Message
                        });
                });
            }
        }

        private void StopRecordingTimers() {
            if (_recordingElapsedTimer is not null) {
                _recordingElapsedTimer.Stop();
                _recordingElapsedTimer = null;
            }

            if (_recordingSegmentTimer is not null) {
                _recordingSegmentTimer.Stop();
                _recordingSegmentTimer.Tick -= RecordingSegmentTimer_Tick;
                _recordingSegmentTimer = null;
            }
        }

        private void UpdateRecordingElapsedText() {
            if (_activeRecordingTileIndex is not int tileIndex ||
                tileIndex < 0 ||
                tileIndex >= _cameraTiles.Count ||
                !_recordingSegmentStartedAt.HasValue) {
                return;
            }

            var elapsed = DateTimeOffset.Now - _recordingSegmentStartedAt.Value;
            var text = elapsed.TotalHours >= 1
                ? $"REC {(int)elapsed.TotalHours:00}:{elapsed.Minutes:00}:{elapsed.Seconds:00}"
                : $"REC {elapsed.Minutes:00}:{elapsed.Seconds:00}";
            _cameraTiles[tileIndex].RecordingElapsedText.Text = text;
        }

        private bool TryGetEffectiveRecordingDirectory(out string directoryPath, out string error) {
            var videosPath = Environment.GetFolderPath(Environment.SpecialFolder.MyVideos);
            if (string.IsNullOrWhiteSpace(videosPath)) {
                directoryPath = string.Empty;
                error = "Videos folder path is unavailable.";
                return false;
            }

            var configuredPath = (_settings.RecordingSaveFolder ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(configuredPath)) {
                directoryPath = IOPath.Combine(videosPath, "LocalCam");
                error = string.Empty;
                return true;
            }

            string configuredFullPath;
            string videosFullPath;
            try {
                configuredFullPath = IOPath.GetFullPath(configuredPath)
                    .TrimEnd(IOPath.DirectorySeparatorChar, IOPath.AltDirectorySeparatorChar);
                videosFullPath = IOPath.GetFullPath(videosPath)
                    .TrimEnd(IOPath.DirectorySeparatorChar, IOPath.AltDirectorySeparatorChar);
            }
            catch {
                directoryPath = string.Empty;
                error = "Recording folder path is invalid.";
                return false;
            }

            var sameAsVideos = string.Equals(
                configuredFullPath,
                videosFullPath,
                StringComparison.OrdinalIgnoreCase);

            directoryPath = sameAsVideos
                ? IOPath.Combine(videosPath, "LocalCam")
                : configuredPath;
            error = string.Empty;
            return true;
        }

        private static string CreateUniqueRecordingPath(string directoryPath, int tileIndex, int segmentNumber) {
            var baseFileName = $"camera-{tileIndex + 1}-{DateTime.Now:yyyyMMdd-HHmmss}";
            if (segmentNumber > 1) {
                baseFileName = $"{baseFileName}-part-{segmentNumber:00}";
            }

            var candidate = IOPath.Combine(directoryPath, $"{baseFileName}.ts");
            var suffix = 1;
            while (System.IO.File.Exists(candidate)) {
                candidate = IOPath.Combine(directoryPath, $"{baseFileName}-{suffix}.ts");
                suffix++;
            }

            return candidate;
        }

        private static string BuildRecordingSoutOption(string recordingPath) {
            var escapedPath = IOPath.GetFullPath(recordingPath)
                .Replace('\\', '/')
                .Replace("'", "\\'", StringComparison.Ordinal);
            return $":sout=#std{{access=file,mux=ts,dst='{escapedPath}'}}";
        }

        private void LogRecordingInfo(
            string eventName,
            string message,
            int? tileIndex = null,
            string? reason = null,
            IReadOnlyDictionary<string, object?>? data = null) {
            var payload = BuildRecordingLogPayload(tileIndex, reason, data);
            JsonLogStore.Information(eventName, message, RecordingDiagnosticsCategory, payload);
        }

        private void LogRecordingWarning(
            string eventName,
            string message,
            int? tileIndex = null,
            string? reason = null,
            IReadOnlyDictionary<string, object?>? data = null) {
            var payload = BuildRecordingLogPayload(tileIndex, reason, data);
            JsonLogStore.Warning(eventName, message, RecordingDiagnosticsCategory, payload);
        }

        private Dictionary<string, object?> BuildRecordingLogPayload(
            int? tileIndex = null,
            string? reason = null,
            IReadOnlyDictionary<string, object?>? data = null) {
            var payload = new Dictionary<string, object?> {
                ["sessionId"] = _recordingSessionId == 0 ? null : _recordingSessionId,
                ["activeRecordingTileIndex"] = _activeRecordingTileIndex,
                ["activeRecordingCameraIndex"] = _activeRecordingTileIndex.HasValue ? _activeRecordingTileIndex.Value + 1 : null,
                ["segmentNumber"] = _recordingSegmentNumber,
                ["isRecordingOperationProcessing"] = _isRecordingOperationProcessing
            };

            if (tileIndex.HasValue) {
                payload["tileIndex"] = tileIndex.Value;
                payload["cameraIndex"] = tileIndex.Value + 1;
            }

            if (!string.IsNullOrWhiteSpace(reason)) {
                payload["reason"] = reason;
            }

            if (data is not null) {
                foreach (var pair in data) {
                    payload[pair.Key] = pair.Value;
                }
            }

            return payload;
        }

        private void ReportRecordingActivity(string message) {
            StreamingStatusText.Text = message;
        }

        private bool IsAnyStreamRunning() {
            for (var i = 0; i < _cameraTiles.Count; i++) {
                var mediaPlayer = _cameraTiles[i].MediaPlayer;
                if (mediaPlayer is not null && mediaPlayer.IsPlaying) {
                    return true;
                }
            }

            return false;
        }

        private int CountActiveStreams() {
            var active = 0;
            for (var i = 0; i < _cameraTiles.Count; i++) {
                var mediaPlayer = _cameraTiles[i].MediaPlayer;
                if (mediaPlayer is not null && mediaPlayer.IsPlaying) {
                    active++;
                }
            }

            return active;
        }

        private static string GetLocalDayKey() {
            return DateTime.Now.ToString("yyyy-MM-dd");
        }

        private void EnsureBasicRecordingUsageDate() {
            var today = GetLocalDayKey();
            if (string.Equals(_settings.BasicRecordingUsageDateLocal, today, StringComparison.Ordinal)) {
                return;
            }

            _settings.BasicRecordingUsageDateLocal = today;
            _settings.BasicRecordingUsageSeconds = 0;
            TrySaveSettings(
                eventName: "basic_recording_usage_reset_failed",
                logMessage: "Failed to reset Basic recording usage for a new local day.");
        }

        private TimeSpan GetBasicRecordingRemaining() {
            EnsureBasicRecordingUsageDate();
            var used = TimeSpan.FromSeconds(Math.Max(0, _settings.BasicRecordingUsageSeconds));
            var remaining = BasicRecordingDailyLimit - used;
            return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
        }

        private void AddBasicRecordingUsage(TimeSpan elapsed) {
            EnsureBasicRecordingUsageDate();
            var nextValue = Math.Max(0, _settings.BasicRecordingUsageSeconds + Math.Max(0, elapsed.TotalSeconds));
            _settings.BasicRecordingUsageSeconds = Math.Min(BasicRecordingDailyLimit.TotalSeconds, nextValue);
            TrySaveSettings(
                eventName: "basic_recording_usage_save_failed",
                logMessage: "Failed to persist Basic recording usage.");
        }

        private static bool IsEventFromControl(DependencyObject? source, DependencyObject target) {
            var current = source;
            while (current is not null) {
                if (ReferenceEquals(current, target)) {
                    return true;
                }

                current = System.Windows.Media.VisualTreeHelper.GetParent(current);
            }

            return false;
        }

        private static bool IsScreenPointInsideControl(FrameworkElement control, int screenX, int screenY) {
            if (!control.IsVisible || control.ActualWidth <= 0 || control.ActualHeight <= 0) {
                return false;
            }

            var localPoint = control.PointFromScreen(new Point(screenX, screenY));
            return localPoint.X >= 0 &&
                   localPoint.Y >= 0 &&
                   localPoint.X <= control.ActualWidth &&
                   localPoint.Y <= control.ActualHeight;
        }

        private static void ApplyRoundedClip(Border border, double cornerRadius) {
            if (border.ActualWidth <= 0 || border.ActualHeight <= 0) {
                return;
            }

            border.Clip = new System.Windows.Media.RectangleGeometry(
                new Rect(0, 0, border.ActualWidth, border.ActualHeight),
                cornerRadius,
                cornerRadius);
        }

        private void ApplyResponsiveCameraLayout() {
            if (CameraTilesPanel is null) {
                return;
            }

            var count = _cameraTiles.Count;
            if (count == 0) {
                CameraTilesPanel.RowDefinitions.Clear();
                CameraTilesPanel.ColumnDefinitions.Clear();
                UpdateTileButtonStates();
                return;
            }

            if (CameraTilesPanel.ActualWidth <= 1 || CameraTilesPanel.ActualHeight <= 1) {
                if (!_layoutRetryPending) {
                    _layoutRetryPending = true;
                    Dispatcher.BeginInvoke(new Action(() => {
                        _layoutRetryPending = false;
                        ApplyResponsiveCameraLayout();
                    }), System.Windows.Threading.DispatcherPriority.Render);
                }

                return;
            }

            if (_expandedCameraIndex is int expandedIndex) {
                if (expandedIndex < 0 || expandedIndex >= count) {
                    _expandedCameraIndex = null;
                }
                else {
                    CameraTilesPanel.RowDefinitions.Clear();
                    CameraTilesPanel.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
                    CameraTilesPanel.ColumnDefinitions.Clear();
                    CameraTilesPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

                    for (var i = 0; i < _cameraTiles.Count; i++) {
                        var card = _cameraTiles[i].Card;
                        if (i == expandedIndex) {
                            card.Visibility = Visibility.Visible;
                            card.Width = double.NaN;
                            card.Height = double.NaN;
                            card.HorizontalAlignment = HorizontalAlignment.Stretch;
                            card.VerticalAlignment = VerticalAlignment.Stretch;
                            card.Margin = new Thickness(0);
                            Grid.SetRow(card, 0);
                            Grid.SetColumn(card, 0);
                        }
                        else {
                            card.Visibility = Visibility.Collapsed;
                        }
                    }

                    UpdateTileButtonStates();
                    return;
                }
            }

            var (columns, rows, cardWidth, cardHeight) = CalculateVideoDrivenGrid(
                count,
                CameraTilesPanel.ActualWidth,
                CameraTilesPanel.ActualHeight);

            CameraTilesPanel.RowDefinitions.Clear();
            for (var i = 0; i < rows; i++) {
                CameraTilesPanel.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            }

            CameraTilesPanel.ColumnDefinitions.Clear();
            for (var i = 0; i < columns; i++) {
                CameraTilesPanel.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            }

            for (var i = 0; i < _cameraTiles.Count; i++) {
                var card = _cameraTiles[i].Card;
                card.Visibility = Visibility.Visible;
                card.Width = cardWidth;
                card.Height = cardHeight;
                card.HorizontalAlignment = HorizontalAlignment.Center;
                card.VerticalAlignment = VerticalAlignment.Center;
                card.Margin = GetTileMargin(i, columns, rows);
                var row = i / columns;
                var column = i % columns;
                Grid.SetRow(card, row);
                Grid.SetColumn(card, column);
            }

            UpdateTileButtonStates();
        }

        private static (int Columns, int Rows, double CardWidth, double CardHeight) CalculateVideoDrivenGrid(
            int count,
            double panelWidth,
            double panelHeight) {
            const double videoAspect = 16d / 9d;
            const double gridGap = 6d;
            const double cardChromeHorizontal = 8d;
            const double cardChromeVertical = 8d;

            var bestColumns = 1;
            var bestRows = count;
            var bestCardWidth = panelWidth;
            var bestCardHeight = panelHeight / Math.Max(1, count);
            var bestVideoArea = double.NegativeInfinity;

            for (var columns = 1; columns <= count; columns++) {
                var rows = (int)Math.Ceiling(count / (double)columns);
                var totalGapWidth = Math.Max(0, columns - 1) * (2d * gridGap);
                var totalGapHeight = Math.Max(0, rows - 1) * (2d * gridGap);
                var slotWidth = Math.Max(1d, (panelWidth - totalGapWidth) / columns);
                var slotHeight = Math.Max(1d, (panelHeight - totalGapHeight) / rows);
                var maxVideoWidth = Math.Max(1d, slotWidth - cardChromeHorizontal);
                var maxVideoHeight = Math.Max(1d, slotHeight - cardChromeVertical);

                var videoWidth = Math.Min(maxVideoWidth, maxVideoHeight * videoAspect);
                var videoHeight = videoWidth / videoAspect;

                if (videoHeight > maxVideoHeight) {
                    videoHeight = maxVideoHeight;
                    videoWidth = videoHeight * videoAspect;
                }

                var cardWidth = Math.Max(1d, videoWidth + cardChromeHorizontal);
                var cardHeight = Math.Max(1d, videoHeight + cardChromeVertical);
                var videoArea = videoWidth * videoHeight;

                if (videoArea > bestVideoArea) {
                    bestVideoArea = videoArea;
                    bestColumns = columns;
                    bestRows = rows;
                    bestCardWidth = cardWidth;
                    bestCardHeight = cardHeight;
                }
            }

            return (bestColumns, bestRows, bestCardWidth, bestCardHeight);
        }

        private static Thickness GetTileMargin(int index, int columns, int rows) {
            const double gap = 6;
            var row = index / columns;
            var column = index % columns;
            return new Thickness(
                left: column == 0 ? 0 : gap,
                top: row == 0 ? 0 : gap,
                right: column == columns - 1 ? 0 : gap,
                bottom: row == rows - 1 ? 0 : gap);
        }

        private void ShutdownStreamingEngine() {
            StopAllStreams();

            foreach (var tile in _cameraTiles) {
                tile.VideoView.MediaPlayer = null;
                DisposeMediaPlayer(tile.MediaPlayer);
                tile.MediaPlayer = null;
            }

            if (_libVlc is not null) {
                _libVlc.Log -= LibVlc_Log;
            }
            _libVlc?.Dispose();
            _libVlc = null;
        }

        private Media CreateRtspPlaybackMedia(string streamUrl) {
            if (_libVlc is null) {
                throw new InvalidOperationException("Video engine is unavailable.");
            }

            var media = new Media(_libVlc, streamUrl, FromType.FromLocation);
            media.AddOption(":rtsp-tcp");
            media.AddOption(":network-caching=300");
            media.AddOption(":live-caching=300");
            media.AddOption(":clock-jitter=0");
            media.AddOption(":clock-synchro=0");
            media.AddOption(":avcodec-hw=none");
            return media;
        }

        private static string? ResolveLibVlcDirectory() {
            var architectureFolder = RuntimeInformation.ProcessArchitecture switch {
                Architecture.X64 => "win-x64",
                Architecture.X86 => "win-x86",
                _ => null
            };

            if (architectureFolder is null) {
                return null;
            }

            var candidates = new[] {
                IOPath.Combine(AppContext.BaseDirectory, "libvlc", architectureFolder),
                IOPath.Combine(AppContext.BaseDirectory, "..", "libvlc", architectureFolder)
            };

            foreach (var candidate in candidates) {
                var fullPath = IOPath.GetFullPath(candidate);
                if (System.IO.File.Exists(IOPath.Combine(fullPath, "libvlc.dll")) &&
                    System.IO.File.Exists(IOPath.Combine(fullPath, "libvlccore.dll")) &&
                    System.IO.Directory.Exists(IOPath.Combine(fullPath, "plugins"))) {
                    return fullPath;
                }
            }

            return null;
        }

        private void LibVlc_Log(object? sender, LogEventArgs e) {
            if (e.Level != LogLevel.Error && e.Level != LogLevel.Warning) {
                return;
            }

            var message = SanitizeLibVlcLogMessage(e.Message);
            if (string.IsNullOrWhiteSpace(message)) {
                return;
            }

            if (e.Level == LogLevel.Error) {
                _lastLibVlcErrorMessage = message;
            }

            var logKey = $"{e.Level}|{e.Module}|{message}";
            var now = DateTimeOffset.UtcNow;
            var suppressedCount = 0;
            lock (_libVlcLogSync) {
                if (_libVlcLogThrottleStates.TryGetValue(logKey, out var throttleState) &&
                    now - throttleState.LastLoggedAt < LibVlcRepeatedLogInterval) {
                    throttleState.SuppressedCount++;
                    return;
                }

                if (throttleState is null) {
                    throttleState = new LibVlcLogThrottleState();
                    _libVlcLogThrottleStates[logKey] = throttleState;
                }

                suppressedCount = throttleState.SuppressedCount;
                throttleState.SuppressedCount = 0;
                throttleState.LastLoggedAt = now;
            }

            var data = new Dictionary<string, object?> {
                ["level"] = e.Level.ToString(),
                ["module"] = e.Module,
                ["message"] = message
            };
            if (suppressedCount > 0) {
                data["suppressedCount"] = suppressedCount;
            }

            JsonLogStore.Warning(
                eventName: "libvlc_runtime_log",
                message: "LibVLC emitted a runtime warning or error.",
                category: "camera_connect",
                data: data);
        }

        private static string SanitizeLibVlcLogMessage(string? message) {
            if (string.IsNullOrWhiteSpace(message)) {
                return string.Empty;
            }

            return System.Text.RegularExpressions.Regex.Replace(
                message,
                @"rtsp://[^:\s/@]+:[^@\s]+@",
                "rtsp://***:***@",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase,
                TimeSpan.FromMilliseconds(100));
        }

        private static string NormalizeStreamPath(string? input) {
            var normalized = (input ?? string.Empty).Trim().TrimStart('/');
            return string.IsNullOrWhiteSpace(normalized)
                ? "stream1"
                : normalized;
        }

        private static bool HasCompleteStreamingSettings(string username, string password) {
            return !string.IsNullOrWhiteSpace(username) && !string.IsNullOrWhiteSpace(password);
        }

        private static bool HasValidStreamStartSettings(string username, string password, string? streamPath) {
            return HasCompleteStreamingSettings(username, password) &&
                   !string.IsNullOrWhiteSpace((streamPath ?? string.Empty).Trim());
        }

        private static string Pluralize(int count, string singular, string? plural = null) {
            return count == 1
                ? singular
                : plural ?? $"{singular}s";
        }

        private static string BuildMissingSettingsPrompt() {
            return "Open Settings and provide the RTSP username, password, and stream path before starting streams.";
        }

        private string BuildDetectionsStatusText(int cameraCount, TapoDetectionMethod? successfulMethod = null) {
            if (cameraCount <= 0) {
                return "No compatible camera detected. Retry search?";
            }

            var detectionPrefix = successfulMethod is TapoDetectionMethod method
                ? $"Detected {cameraCount} {Pluralize(cameraCount, "camera")} using {GetDetectionMethodDisplayName(method)}."
                : $"Detected {cameraCount} {Pluralize(cameraCount, "camera")}.";

            return HasCompleteStreamingSettings(_settings.RtspUsername.Trim(), _settings.RtspPassword)
                ? $"{detectionPrefix} Ready to play."
                : $"{detectionPrefix} Open Settings and provide the RTSP username, password, and stream path.";
        }

        private TapoDetectionMethod? ResolvePreferredDetectionMethod() {
            var storedMethod = _settings.LastSuccessfulDetectionMethod;
            if (string.IsNullOrWhiteSpace(storedMethod)) {
                return null;
            }

            if (TapoCameraScanner.TryParseDetectionMethod(storedMethod, out var preferredMethod)) {
                JsonLogStore.Information(
                    eventName: "camera_search_preferred_method_resolved",
                    message: "Loaded the last successful camera detection method from settings.",
                    category: "camera_search",
                    data: new Dictionary<string, object?> {
                        ["preferredMethod"] = preferredMethod.ToString()
                    });
                return preferredMethod;
            }

            JsonLogStore.Warning(
                eventName: "camera_search_preferred_method_invalid",
                message: "Ignoring an unknown persisted camera detection method.",
                category: "camera_search",
                data: new Dictionary<string, object?> {
                    ["storedMethod"] = storedMethod
                });
            return null;
        }

        private void PersistSuccessfulDetectionMethod(TapoDetectionMethod? successfulMethod) {
            if (successfulMethod is not TapoDetectionMethod method) {
                return;
            }

            if (method == TapoDetectionMethod.AdaptiveRtspVerificationProbe) {
                return;
            }

            var persistedValue = method.ToString();
            if (string.Equals(_settings.LastSuccessfulDetectionMethod, persistedValue, StringComparison.Ordinal)) {
                return;
            }

            var previousValue = _settings.LastSuccessfulDetectionMethod;
            _settings.LastSuccessfulDetectionMethod = persistedValue;
            if (!TrySaveSettings(
                    "camera_search_preferred_method_save_failed",
                    "Failed to persist the successful camera detection method.")) {
                _settings.LastSuccessfulDetectionMethod = previousValue;
                return;
            }

            JsonLogStore.Information(
                eventName: "camera_search_preferred_method_saved",
                message: "Saved the successful camera detection method to settings.",
                category: "camera_search",
                data: new Dictionary<string, object?> {
                    ["previousMethod"] = previousValue,
                    ["successfulMethod"] = persistedValue
                });
        }

        private bool TrySaveSettings(string eventName, string logMessage, bool showStatus = false) {
            try {
                SettingsStore.Save(_settings);
                return true;
            }
            catch (Exception ex) {
                JsonLogStore.Error(
                    eventName: eventName,
                    message: logMessage,
                    category: "settings",
                    exception: ex);

                if (showStatus && StreamingStatusText is not null) {
                    StreamingStatusText.Text = $"Settings save failed: {ex.Message}";
                }

                return false;
            }
        }

        private static string BuildNoDetectionsMessage(IReadOnlyList<TapoDetectionMethodAttempt> attemptedMethods) {
            if (attemptedMethods.Count == 0) {
                return "No compatible camera detected.";
            }

            var attemptedNames = attemptedMethods
                .Select(static attempt => GetDetectionMethodDisplayName(attempt.Method))
                .ToArray();
            return $"No compatible camera detected. Tried: {string.Join(", ", attemptedNames)}.";
        }

        private static string GetDetectionMethodDisplayName(TapoDetectionMethod method) {
            return method switch {
                TapoDetectionMethod.AdaptiveRtspVerificationProbe => "extended network search",
                TapoDetectionMethod.OnvifWsDiscovery => "ONVIF",
                TapoDetectionMethod.SsdpUpnpSearch => "SSDP",
                TapoDetectionMethod.TapoUdpBroadcast => "local discovery",
                TapoDetectionMethod.MdnsDnsSdSweep => "mDNS",
                TapoDetectionMethod.ArpSeededTargetProbe => "ARP probe",
                TapoDetectionMethod.SubnetProbeFallback => "subnet probe",
                TapoDetectionMethod.RtspOptionsProbe => "RTSP",
                _ => method.ToString()
            };
        }

        private static string BuildRtspUrl(string host, string username, string password, string streamPath, int port = 554) {
            var escapedUsername = Uri.EscapeDataString(username);
            var escapedPassword = Uri.EscapeDataString(password);
            var supportedPort = port is 554 or 8554 ? port : 554;
            return $"rtsp://{escapedUsername}:{escapedPassword}@{host}:{supportedPort}/{streamPath}";
        }

        private void Window_StateChanged(object sender, EventArgs e) {
            PersistWindowBounds();
        }

        [DllImport("user32.dll")]
        private static extern uint GetDoubleClickTime();

        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int nIndex);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(
            int idHook,
            MouseHookProc lpfn,
            IntPtr hmod,
            uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(
            IntPtr hhk,
            int nCode,
            IntPtr wParam,
            IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        private struct MouseHookStruct {
            public PointNative pt;
            public IntPtr hwnd;
            public uint wHitTestCode;
            public UIntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LowLevelMouseHookStruct {
            public PointNative pt;
            public uint mouseData;
            public uint flags;
            public uint time;
            public UIntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PointNative {
            public int x;
            public int y;
        }

        private void MainWindow_SourceInitialized(object? sender, EventArgs e) {
            _ = sender;
            _ = e;

            var handle = new WindowInteropHelper(this).Handle;
            if (handle == IntPtr.Zero) {
                return;
            }

            SetWindowIconHandle(handle);
            var source = HwndSource.FromHwnd(handle);
            source?.AddHook(WndProc);
            InstallMouseHook();
        }

        private void ApplyWindowIcon() {
            try {
                var iconUri = new Uri("pack://application:,,,/Assets/icon.ico", UriKind.Absolute);
                var streamInfo = Application.GetResourceStream(iconUri);
                if (streamInfo == null) {
                    return;
                }

                using var stream = streamInfo.Stream;
                using var memory = new System.IO.MemoryStream();
                stream.CopyTo(memory);
                memory.Position = 0;

                var iconImage = BitmapFrame.Create(memory, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
                iconImage.Freeze();
                Icon = iconImage;

                _windowIconHandle?.Dispose();
                memory.Position = 0;
                _windowIconHandle = new System.Drawing.Icon(memory);
            }
            catch {
                // Leave the existing XAML icon in place if the resource cannot be loaded.
            }
        }

        private void SetWindowIconHandle(IntPtr handle) {
            if (handle == IntPtr.Zero || _windowIconHandle == null) {
                return;
            }

            SendMessage(handle, WmSetIcon, (IntPtr)IconBig, _windowIconHandle.Handle);
            SendMessage(handle, WmSetIcon, (IntPtr)IconSmall, _windowIconHandle.Handle);
            SetClassLongPtr(handle, GclpHIcon, _windowIconHandle.Handle);
            SetClassLongPtr(handle, GclpHIconSm, _windowIconHandle.Handle);
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", EntryPoint = "SetClassLongPtrW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr SetClassLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

        private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled) {
            if (msg == WmPowerBroadcast) {
                if (TryLogPowerBroadcastSuspend(hwnd, wParam) || TryLogPowerBroadcastResume(hwnd, wParam)) {
                    handled = true;
                    return IntPtr.Zero;
                }
            }

            return IntPtr.Zero;
        }

        private bool TryLogPowerBroadcastSuspend(IntPtr hwnd, IntPtr wParam) {
            var powerBroadcastReason = unchecked((int)wParam.ToInt64());
            if (powerBroadcastReason != PbtApmSuspend) {
                return false;
            }

            var activeStreamCount = CountRunningStreams();
            var wasRecording = _activeRecordingTileIndex.HasValue;
            StopAllStreams();
            StreamingStatusText.Text = "Streams stopped for system suspend.";

            LogPowerNotification(
                eventName: "power_suspend_streams_stopped",
                message: "Streams and any active recording were stopped for system suspend.",
                notificationKindName: "suspendKind",
                notificationKind: "PBT_APMSUSPEND",
                hwnd: hwnd,
                powerBroadcastReason: powerBroadcastReason,
                additionalData: new Dictionary<string, object?> {
                    ["stoppedStreamCount"] = activeStreamCount,
                    ["recordingWasActive"] = wasRecording
                });
            return true;
        }

        private bool TryLogPowerBroadcastResume(IntPtr hwnd, IntPtr wParam) {
            var powerBroadcastReason = unchecked((int)wParam.ToInt64());
            var resumeKind = powerBroadcastReason switch {
                PbtApmResumeAutomatic => "PBT_APMRESUMEAUTOMATIC",
                PbtApmResumeSuspend => "PBT_APMRESUMESUSPEND",
                PbtApmResumeCritical => "PBT_APMRESUMECRITICAL",
                _ => null
            };

            if (resumeKind is null) {
                return false;
            }

            LogPowerNotification(
                eventName: "power_resume_streams_remain_stopped",
                message: "System resume was observed; streams remain stopped.",
                notificationKindName: "resumeKind",
                notificationKind: resumeKind,
                hwnd: hwnd,
                powerBroadcastReason: powerBroadcastReason);
            return true;
        }

        private void LogPowerNotification(
            string eventName,
            string message,
            string notificationKindName,
            string notificationKind,
            IntPtr hwnd,
            int powerBroadcastReason,
            IReadOnlyDictionary<string, object?>? additionalData = null) {
            var payload = new Dictionary<string, object?> {
                ["source"] = "WM_POWERBROADCAST",
                [notificationKindName] = notificationKind,
                ["wParam"] = powerBroadcastReason,
                ["windowHandle"] = hwnd == IntPtr.Zero ? null : hwnd.ToInt64()
            };

            if (additionalData is not null) {
                foreach (var pair in additionalData) {
                    payload[pair.Key] = pair.Value;
                }
            }

            JsonLogStore.Information(
                eventName: eventName,
                message: message,
                category: "app",
                data: payload);
        }

        protected override void OnClosed(EventArgs e) {
            _isClosing = true;
            UninstallMouseHook();
            StopCameraMonitoring();
            _scanCancellation?.Cancel();
            CancelCachedReconnectAttempts();
            ShutdownStreamingEngine();
            _windowIconHandle?.Dispose();
            _windowIconHandle = null;

            base.OnClosed(e);
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e) {
            StopCameraMonitoring();
            _scanCancellation?.Cancel();
            CancelCachedReconnectAttempts();
            PersistWindowBounds();
            _isClosing = true;
            base.OnClosing(e);
        }

        private void StopCameraMonitoring() {
            lock (_cameraMonitorSync) {
                _cameraMonitorCancellation?.Cancel();
            }
        }

        private void Window_LocationChanged(object? sender, EventArgs e) {
            _ = sender;
            PersistWindowBounds();
        }

        private void Window_SizeChanged(object? sender, SizeChangedEventArgs e) {
            _ = sender;
            _ = e;
            PersistWindowBounds();
            ApplyResponsiveCameraLayout();
        }

    }
}

