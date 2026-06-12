using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Win32;
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
    public partial class MainWindow : Window {
        private delegate IntPtr MouseHookProc(int nCode, IntPtr wParam, IntPtr lParam);

        private sealed class CameraTileControls {
            public required Border Card { get; init; }
            public required Border Placeholder { get; init; }
            public required Border Badge { get; init; }
            public required TextBlock Label { get; init; }
            public required VideoView VideoView { get; init; }
            public required Button ExpandButton { get; init; }
            public required Button CollapseButton { get; init; }
            public required Button PlayButton { get; init; }
            public required Button StopButton { get; init; }
            public required Button SnapshotButton { get; init; }
            public required Button RecordButton { get; init; }
            public required Border RecordingBadge { get; init; }
            public required TextBlock RecordingElapsedText { get; init; }
            public VlcMediaPlayer? MediaPlayer { get; set; }
            public bool IsSnapshotSaving { get; set; }
        }

        private sealed class StreamHealthState {
            public long? LastTime { get; set; }
            public double LastPosition { get; set; }
            public int LastDisplayedPictures { get; set; }
            public int LastDecodedVideo { get; set; }
            public int LastReadBytes { get; set; }
            public DateTimeOffset LastProgressAt { get; set; }
            public DateTimeOffset LastStartedAt { get; set; }
            public DateTimeOffset LastRestartAttemptAt { get; set; }
            public int ConsecutiveStaleChecks { get; set; }
            public int LifecycleRevision { get; set; }
            public StreamLifecyclePhase LifecyclePhase { get; set; } = StreamLifecyclePhase.Stopped;
        }

        private enum StreamLifecyclePhase {
            Stopped,
            Starting,
            Running,
            Stopping,
            Restarting
        }

        private static readonly Geometry MaximizeGeometry = Geometry.Parse("M2,2 L12,2 12,12 2,12 Z");
        private static readonly Geometry RestoreGeometry = Geometry.Parse("M4,2 L12,2 12,10 M4,2 L4,10 12,10 M2,4 L10,4 10,12 2,12 Z");
        private const int WmSetIcon = 0x0080;
        private const int WmMove = 0x0003;
        private const int WmSize = 0x0005;
        private const int WmGetMinMaxInfo = 0x0024;
        private const int WmWindowPosChanged = 0x0047;
        private const int WmLButtonDown = 0x0201;
        private const int WmLButtonUp = 0x0202;
        private const int WmMoving = 0x0216;
        private const int WhMouse = 7;
        private const int WhMouseLl = 14;
        private const int HcAction = 0;
        private const int IconSmall = 0;
        private const int IconBig = 1;
        private const int GclpHIcon = -14;
        private const int GclpHIconSm = -34;
        private const int SmCxDoubleClk = 36;
        private const int SmCyDoubleClk = 37;
        private const uint MonitorDefaultToNearest = 2;
        private const string InputDiagnosticsCategory = "InputDiagnostics";
        private const string SnapshotDiagnosticsCategory = "SnapshotDiagnostics";
        private const string RecordingDiagnosticsCategory = "RecordingDiagnostics";
        private const string RtspSettingsInvalidMessage = "RTSP credentials are missing or invalid.";
        private const string PremiumAddOnStoreId = "9P9KCJ3NFZFT";
        private const string PremiumAddOnOfferToken = "localcam_premium_lifetime";
        private const int BasicConcurrentStreamLimit = 2;
        private static readonly TimeSpan StreamHealthCheckInterval = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan StreamHealthWarmup = TimeSpan.FromSeconds(45);
        private static readonly TimeSpan StreamHealthStaleThreshold = TimeSpan.FromMinutes(3);
        private static readonly TimeSpan StreamHealthRestartCooldown = TimeSpan.FromMinutes(2);
        private const int StreamHealthRequiredStaleChecks = 2;
        private static readonly TimeSpan BasicRecordingDailyLimit = TimeSpan.FromMinutes(30);
        private static readonly TimeSpan RecordingSegmentDuration = TimeSpan.FromMinutes(60);
                        private static readonly Geometry ExpandButtonGeometry = Geometry.Parse("M2,6 L2,2 L6,2 M10,2 L14,2 L14,6 M14,10 L14,14 L10,14 M6,14 L2,14 L2,10");

        private IReadOnlyList<TapoCameraDetection> _detections = Array.Empty<TapoCameraDetection>();
        private readonly List<CameraTileControls> _cameraTiles = new();
        private LibVLC? _libVlc;
        private CancellationTokenSource? _scanCancellation;
        private bool _isClosing;
        private bool _isScanning;
        private bool _isUserScanCancelRequested;
        private bool _isDetectButtonToggleDelayActive;
        private int _detectButtonToggleVersion;
        private bool _streamsRunning;
        private bool _isApplyingPersistedWindowBounds;
        private bool _hasAppliedPersistedWindowBounds;
        private bool _layoutRetryPending;
        private bool _isSettingsDialogOpen;
        private int? _expandedCameraIndex;
        private bool _isRecoveringStreamsAfterResume;
        private bool _isStreamHealthCheckRunning;
        private int _streamHealthCheckCursor;
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
        private readonly Dictionary<int, string> _streamFailureReasons = new();
        private readonly Dictionary<int, StreamHealthState> _streamHealthStates = new();
        private readonly HashSet<int> _streamIntentionalRestartTiles = new();
        private readonly Dictionary<int, CancellationTokenSource> _streamRestartCancellationSources = new();
        private long _nextStreamStartOrder = 1;
        private string? _lastLibVlcErrorMessage;
        private readonly IStoreContextProvider _storeContextProvider;
        private readonly IPremiumPurchaseService _premiumPurchaseService;
        private readonly IPremiumEntitlementService _premiumEntitlementService;
        private readonly StoreAppUpdaterService _storeAppUpdaterService;
        private bool _hasResolvedPremiumUiState;
        private bool _hasInitializedStoreUpdater;
        private bool _isPremiumOwned;
        private bool _isPremiumPurchaseBusy;
        private bool _isPremiumEntitlementRefreshBusy;
        private DispatcherTimer? _basicRecordingDailyLimitTimer;
        private DispatcherTimer? _streamHealthTimer;
        private CancellationTokenSource? _storeUpdaterCts;
        private StoreUpdateProgressWindow? _storeUpdateProgressWindow;
        private System.Drawing.Icon? _windowIconHandle;

        public MainWindow()
            : this(Array.Empty<TapoCameraDetection>()) {
        }

        public MainWindow(IReadOnlyList<TapoCameraDetection> detections) {
            _detections = detections.ToArray();
            _storeContextProvider = new StoreContextProvider();

            InitializeComponent();
            ApplyWindowIcon();
            UpdateFooterVersionText();
            SourceInitialized += MainWindow_SourceInitialized;
            Activated += MainWindow_Activated;
            LocationChanged += Window_LocationChanged;
            SizeChanged += Window_SizeChanged;
            SystemEvents.PowerModeChanged += SystemEvents_PowerModeChanged;
            LoadSettings();
            StartStreamHealthMonitor();
            _premiumPurchaseService = new PremiumPurchaseService(
                _storeContextProvider,
                ResolvePurchaseOwnerWindowHandle,
                PremiumAddOnStoreId);
            _premiumEntitlementService = new PremiumEntitlementService(
                _storeContextProvider,
                _settings,
                ResolvePurchaseOwnerWindowHandle,
                PremiumAddOnStoreId,
                PremiumAddOnOfferToken);
            _storeAppUpdaterService = new StoreAppUpdaterService(
                _storeContextProvider,
                ResolvePurchaseOwnerWindowHandle,
                () => _settings,
                PersistSettingsForUpdater,
                ApplyStoreUpdateUiState);
            UpdatePremiumUiVisibility();
            ApplyStoreUpdateUiState(StoreUpdateUiState.Hidden());
            ApplyPersistedWindowBounds();
            UpdateMaximizeButtonIcon();
            PopulateCameraTiles(_detections);
            var engineReady = InitializeStreamingEngine();

            if (engineReady) {
                if (_detections.Count > 0) {
                    ShowDetections(_detections);
                }
                else {
                    ShowEmptyCameraSlots();
                }
            }
        }

        private bool InitializeStreamingEngine() {
            try {
                var libVlcDirectory = ResolveLibVlcDirectory();
                if (libVlcDirectory is null) {
                    JsonLogStore.Warning(
                        eventName: "video_engine_native_assets_missing",
                        message: "LibVLC native assets were not found for the current process architecture.",
                        category: "camera_connect",
                        data: new Dictionary<string, object?> {
                            ["processArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
                            ["baseDirectory"] = AppContext.BaseDirectory
                        });
                    StreamingStatusText.Text = $"Video engine is unavailable for {RuntimeInformation.ProcessArchitecture}.";
                    return false;
                }

                Core.Initialize(libVlcDirectory);
                _libVlc = new LibVLC("--network-caching=300", "--live-caching=300", "--rtsp-tcp", "--no-video-title-show");
                _libVlc.Log += LibVlc_Log;
                JsonLogStore.Information(
                    eventName: "video_engine_initialized",
                    message: "LibVLC video engine initialized.",
                    category: "camera_connect",
                    data: new Dictionary<string, object?> {
                        ["libVlcDirectory"] = libVlcDirectory,
                        ["processArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString()
                    });
                EnsureCameraTileCount(_detections.Count);
                return true;
            }
            catch (Exception ex) {
                JsonLogStore.Error(
                    eventName: "video_engine_initialization_failed",
                    message: "LibVLC video engine initialization failed.",
                    category: "camera_connect",
                    exception: ex,
                    data: new Dictionary<string, object?> {
                        ["processArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
                        ["baseDirectory"] = AppContext.BaseDirectory
                    });
                StreamingStatusText.Text = $"Video engine initialization failed: {ex.Message}";
                return false;
            }
        }

        private void LoadSettings() {
            if (SettingsStore.TryLoad(out var savedSettings)) {
                _settings = savedSettings;
                return;
            }

            var defaultUser = Environment.GetEnvironmentVariable("LOCALCAM_RTSP_USERNAME");
            var defaultPassword = Environment.GetEnvironmentVariable("LOCALCAM_RTSP_PASSWORD");

            _settings = new LocalCamSettings {
                RtspUsername = defaultUser ?? string.Empty,
                RtspPassword = defaultPassword ?? string.Empty,
                StreamPath = "stream1",
                AutoStreamVideo = true,
                AutoDetectOnStartup = true
            };
        }

        private void UpdateFooterVersionText() {
            FooterVersionText.Text = $"v{GetStoreVersionDisplayText()}";
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
                Width = Math.Max(MinWidth, _settings.MainWindowWidth ?? Width);
                Height = Math.Max(MinHeight, _settings.MainWindowHeight ?? Height);

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
            TrySaveSettings("settings_window_bounds_save_failed", "Failed to persist main window bounds.");
        }

        private void PopulateCameraTiles(IReadOnlyList<TapoCameraDetection> detections) {
            _expandedCameraIndex = null;
            EnsureCameraTileCount(detections.Count);
            for (var i = 0; i < _cameraTiles.Count; i++) {
                _cameraTiles[i].Label.Text = $"camera {i + 1} - live streaming ({detections[i].IpAddress})";
                SetVideoSurfaceActive(i, isActive: false);
            }

            ApplyResponsiveCameraLayout();
        }

        private void EnsureCameraTileCount(int count) {
            count = Math.Max(0, count);

            while (_cameraTiles.Count > count) {
                var tile = _cameraTiles[^1];
                if (_activeRecordingTileIndex == _cameraTiles.Count - 1) {
                    StopRecordingSession("camera_removed", updateStatus: false);
                }
                BumpStreamLifecycleRevision(_cameraTiles.Count - 1);
                _streamHealthStates.Remove(_cameraTiles.Count - 1);
                _streamIntentionalRestartTiles.Remove(_cameraTiles.Count - 1);
                CancelStreamRestartAttempt(_cameraTiles.Count - 1);
                _streamStartOrder.Remove(_cameraTiles.Count - 1);
                tile.MediaPlayer?.Stop();
                tile.VideoView.MediaPlayer = null;
                tile.MediaPlayer?.Dispose();
                CameraTilesPanel.Children.Remove(tile.Card);
                _cameraTiles.RemoveAt(_cameraTiles.Count - 1);
            }

            while (_cameraTiles.Count < count) {
                var tile = CreateCameraTile(_cameraTiles.Count);
                _cameraTiles.Add(tile);
                CameraTilesPanel.Children.Add(tile.Card);
                AttachMediaPlayer(tile);
            }
        }

        private CameraTileControls CreateCameraTile(int tileIndex) {
            var card = new Border {
                Style = (Style)FindResource("CameraCardStyle")
            };
            card.SizeChanged += (_, _) => ApplyRoundedClip(card, 8);
            ApplyRoundedClip(card, 8);
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

            var expandButton = new Button {
                Style = (Style)FindResource("CameraOverlayIconButtonStyle"),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0),
                ToolTip = "Expand",
                Background = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#AA111827")!,
                BorderBrush = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#CC365070")!,
                BorderThickness = new Thickness(1)
            };
            expandButton.Content = CreateExpandButtonContent();
            expandButton.Click += (_, _) => ToggleCameraTileExpandCollapse(tileIndex);

            var collapseButton = new Button {
                Style = (Style)FindResource("CameraOverlayIconButtonStyle"),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0),
                ToolTip = "Collapse",
                Content = CreateCollapseButtonContent(),
                Background = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#AA111827")!,
                BorderBrush = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#CC365070")!,
                BorderThickness = new Thickness(1)
            };
            collapseButton.Click += (_, _) => ToggleCameraTileExpandCollapse(tileIndex);

            var playButton = new Button {
                Style = (Style)FindResource("CameraOverlayIconButtonStyle"),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
                ToolTip = "Play",
                Content = CreateStartButtonContent(),
                Background = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#AA111827")!,
                BorderBrush = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#CC365070")!,
                BorderThickness = new Thickness(1)
            };
            playButton.Click += async (_, _) => {
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
                Background = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#AA111827")!,
                BorderBrush = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#CC365070")!,
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
                Background = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#AA111827")!,
                BorderBrush = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#CC365070")!,
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
                Background = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#AA111827")!,
                BorderBrush = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#CC365070")!,
                BorderThickness = new Thickness(1)
            };
            recordButton.Click += async (_, _) => {
                await ToggleRecordingAsync(tileIndex);
            };

            card.AddHandler(
                UIElement.PreviewMouseLeftButtonDownEvent,
                new MouseButtonEventHandler((_, e) => {
                    if (IsEventFromControl(e.OriginalSource as DependencyObject, playButton) ||
                        IsEventFromControl(e.OriginalSource as DependencyObject, stopButton) ||
                        IsEventFromControl(e.OriginalSource as DependencyObject, snapshotButton) ||
                        IsEventFromControl(e.OriginalSource as DependencyObject, recordButton) ||
                        IsEventFromControl(e.OriginalSource as DependencyObject, expandButton) ||
                        IsEventFromControl(e.OriginalSource as DependencyObject, collapseButton)) {
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
                        ToggleCameraTileExpandCollapse(tileIndex);
                        e.Handled = true;
                    }
                }),
                handledEventsToo: true);

            var videoOverlay = new Grid {
                HorizontalAlignment = HorizontalAlignment.Stretch,
                VerticalAlignment = VerticalAlignment.Stretch
            };
            var overlayToolbarButtons = new StackPanel {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Center
            };
            overlayToolbarButtons.Children.Add(playButton);
            overlayToolbarButtons.Children.Add(stopButton);
            overlayToolbarButtons.Children.Add(snapshotButton);
            overlayToolbarButtons.Children.Add(recordButton);
            overlayToolbarButtons.Children.Add(expandButton);
            overlayToolbarButtons.Children.Add(collapseButton);
            var overlayToolbar = new Border {
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(0, 4, 4, 0),
                Background = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#CC1B2231")!,
                BorderBrush = System.Windows.Media.Brushes.Transparent,
                BorderThickness = new Thickness(0),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(4)
            };
            overlayToolbar.Child = overlayToolbarButtons;
            videoOverlay.Children.Add(overlayToolbar);
            var recordingElapsedText = new TextBlock {
                Foreground = System.Windows.Media.Brushes.White,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                Text = "REC 00:00"
            };
            var recordingBadge = new Border {
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(4, 4, 0, 0),
                Background = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#CCB91C1C")!,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(8, 4, 8, 4),
                Child = recordingElapsedText,
                Visibility = Visibility.Collapsed
            };
            videoOverlay.Children.Add(recordingBadge);
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
                ExpandButton = expandButton,
                CollapseButton = collapseButton,
                PlayButton = playButton,
                StopButton = stopButton,
                SnapshotButton = snapshotButton,
                RecordButton = recordButton,
                RecordingBadge = recordingBadge,
                RecordingElapsedText = recordingElapsedText
            };
        }

        private static FrameworkElement CreateExpandButtonContent() {
            var expandImagePath = IOPath.Combine(AppContext.BaseDirectory, "Assets", "expand.png");
            return CreateButtonImageContentOrFallback(expandImagePath);
        }

        private static FrameworkElement CreateCollapseButtonContent() {
            var collapseImagePath = IOPath.Combine(AppContext.BaseDirectory, "Assets", "collapse.png");
            return CreateButtonImageContentOrFallback(collapseImagePath);
        }

        private static FrameworkElement CreateStartButtonContent() {
            return new Path {
                Data = Geometry.Parse("M4,3 L13,8 L4,13 Z"),
                Fill = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#22C55E")!,
                Stretch = System.Windows.Media.Stretch.Uniform,
                Width = 14,
                Height = 14
            };
        }

        private static FrameworkElement CreateStopButtonContent() {
            return new Rectangle {
                Fill = System.Windows.Media.Brushes.White,
                Width = 11,
                Height = 11
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
                Stroke = System.Windows.Media.Brushes.White,
                StrokeThickness = 1.4,
                Fill = System.Windows.Media.Brushes.Transparent,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            });
            root.Children.Add(new Ellipse {
                Width = 4.5,
                Height = 4.5,
                Stroke = System.Windows.Media.Brushes.White,
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
                        Fill = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#E11D48")!,
                        Stroke = System.Windows.Media.Brushes.White,
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
                        Fill = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString("#E11D48")!,
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment = VerticalAlignment.Center
                    }
                }
            };
        }

        private static FrameworkElement CreateButtonImageContentOrFallback(string imagePath) {
            if (!System.IO.File.Exists(imagePath)) {
                return new System.Windows.Shapes.Path {
                    Data = ExpandButtonGeometry,
                    Fill = System.Windows.Media.Brushes.Transparent,
                    Stroke = System.Windows.Media.Brushes.White,
                    StrokeThickness = 1.6,
                    StrokeStartLineCap = System.Windows.Media.PenLineCap.Round,
                    StrokeEndLineCap = System.Windows.Media.PenLineCap.Round,
                    StrokeLineJoin = System.Windows.Media.PenLineJoin.Round
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

                tile.PlayButton.Visibility = isCardVisible && isDetectedCard && !isRunning ? Visibility.Visible : Visibility.Collapsed;
                tile.StopButton.Visibility = isCardVisible && isDetectedCard && isRunning ? Visibility.Visible : Visibility.Collapsed;
                tile.SnapshotButton.Visibility = isCardVisible && isDetectedCard && isRunning ? Visibility.Visible : Visibility.Collapsed;
                tile.RecordButton.Visibility = isCardVisible && isDetectedCard && isRunning ? Visibility.Visible : Visibility.Collapsed;
                tile.PlayButton.IsEnabled = !isTransitioning;
                tile.StopButton.IsEnabled = true;
                tile.SnapshotButton.IsEnabled = !tile.IsSnapshotSaving;
                var isRecordingThisTile = _activeRecordingTileIndex == i;
                tile.RecordButton.IsEnabled = !_isRecordingOperationProcessing;
                tile.RecordButton.Content = isRecordingThisTile
                    ? CreateRecordStopButtonContent()
                    : CreateRecordStartButtonContent();
                tile.RecordButton.ToolTip = isRecordingThisTile ? "Stop Recording" : "Record";
                tile.RecordingBadge.Visibility = isCardVisible && isRecordingThisTile ? Visibility.Visible : Visibility.Collapsed;

                tile.ExpandButton.Visibility = isCardVisible && isRunning && !isExpanded ? Visibility.Visible : Visibility.Collapsed;
                tile.CollapseButton.Visibility = isCardVisible && isRunning && isExpanded ? Visibility.Visible : Visibility.Collapsed;
                tile.ExpandButton.IsEnabled = true;
                tile.CollapseButton.IsEnabled = true;

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

        private void AttachMediaPlayer(CameraTileControls tile) {
            if (_libVlc is null || tile.MediaPlayer is not null) {
                return;
            }

            var mediaPlayer = new VlcMediaPlayer(_libVlc) {
                EnableHardwareDecoding = false,
                EnableMouseInput = false,
                Mute = true
            };
            mediaPlayer.Playing += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                var tileIndex = _cameraTiles.IndexOf(tile);
                if (tileIndex >= 0) {
                    _streamFailureReasons.Remove(tileIndex);
                }
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
            }));
            mediaPlayer.Stopped += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                var tileIndex = _cameraTiles.IndexOf(tile);
                if (tileIndex >= 0) {
                    if (_streamIntentionalRestartTiles.Contains(tileIndex)) {
                        return;
                    }
                    SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
                    _streamStartOrder.Remove(tileIndex);
                    _streamHealthStates.Remove(tileIndex);
                    SetVideoSurfaceActive(tileIndex, isActive: false);
                }
                if (_isRecoveringStreamsAfterResume) {
                    _streamsRunning = IsAnyStreamRunning();
                    UpdateActionButtons();
                    return;
                }
                if (_activeRecordingTileIndex == tileIndex) {
                    StopRecordingSession("stream_stopped", updateStatus: true);
                }
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
            }));
            mediaPlayer.EndReached += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                var tileIndex = _cameraTiles.IndexOf(tile);
                if (tileIndex >= 0) {
                    if (_streamIntentionalRestartTiles.Contains(tileIndex)) {
                        return;
                    }
                    SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
                    _streamStartOrder.Remove(tileIndex);
                    _streamHealthStates.Remove(tileIndex);
                    SetVideoSurfaceActive(tileIndex, isActive: false);
                }
                if (_isRecoveringStreamsAfterResume) {
                    _streamsRunning = IsAnyStreamRunning();
                    UpdateActionButtons();
                    return;
                }
                if (_activeRecordingTileIndex == tileIndex) {
                    StopRecordingSession("stream_ended", updateStatus: true);
                }
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
            }));
            mediaPlayer.EncounteredError += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                var tileIndex = _cameraTiles.IndexOf(tile);
                if (tileIndex >= 0) {
                    if (_streamIntentionalRestartTiles.Contains(tileIndex)) {
                        return;
                    }
                    SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
                    _streamStartOrder.Remove(tileIndex);
                    _streamHealthStates.Remove(tileIndex);
                    SetVideoSurfaceActive(tileIndex, isActive: false);
                    if (_isRecoveringStreamsAfterResume) {
                        _streamsRunning = IsAnyStreamRunning();
                        UpdateActionButtons();
                        return;
                    }
                    var userReason = _streamFailureReasons.TryGetValue(tileIndex, out var lastReason)
                        ? lastReason
                        : null;
                    StreamingStatusText.Text = string.IsNullOrWhiteSpace(userReason)
                        ? $"Camera {tileIndex + 1} stream failed. Check the log for details."
                        : $"Camera {tileIndex + 1} stream failed: {userReason}";
                    JsonLogStore.Warning(
                        eventName: "camera_connect_playback_error",
                        message: "LibVLC reported a playback error for an RTSP stream.",
                        category: "camera_connect",
                        data: new Dictionary<string, object?> {
                            ["cameraIndex"] = tileIndex + 1,
                            ["ipAddress"] = tileIndex < _detections.Count ? _detections[tileIndex].IpAddress.ToString() : null,
                            ["reason"] = userReason ?? _lastLibVlcErrorMessage ?? "LibVLC reported a playback error."
                        });
                }
                if (_activeRecordingTileIndex == tileIndex) {
                    StopRecordingSession("stream_error", updateStatus: true);
                }
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
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
            tile.Placeholder.Visibility = isActive ? Visibility.Collapsed : Visibility.Visible;
            tile.Badge.Visibility = isActive ? Visibility.Collapsed : Visibility.Visible;
            UpdateTileButtonStates();
        }

        private void ToggleCameraTileExpandCollapse(int tileIndex) {
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
                IsScreenPointInsideControl(_cameraTiles[tileIndex.Value].StopButton, screenX, screenY) ||
                IsScreenPointInsideControl(_cameraTiles[tileIndex.Value].SnapshotButton, screenX, screenY) ||
                IsScreenPointInsideControl(_cameraTiles[tileIndex.Value].RecordButton, screenX, screenY) ||
                IsScreenPointInsideControl(_cameraTiles[tileIndex.Value].ExpandButton, screenX, screenY) ||
                IsScreenPointInsideControl(_cameraTiles[tileIndex.Value].CollapseButton, screenX, screenY)) {
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
                ToggleCameraTileExpandCollapse(tileIndex.Value);
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
            if (_settings.AutoDetectOnStartup) {
                _ = StartLocalCameraSearchAsync();
                return;
            }

            ShowEmptyCameraSlots();
        }

        private void Window_ContentRendered(object? sender, EventArgs e) {
            _ = sender;
            _ = e;
            if (!_hasResolvedPremiumUiState) {
                _hasResolvedPremiumUiState = true;
                _ = Dispatcher.BeginInvoke(new Action(async () => {
                    await RefreshPremiumEntitlementAsync("post_render");
                }), DispatcherPriority.Background);
            }

            if (_hasInitializedStoreUpdater) {
                return;
            }

            _hasInitializedStoreUpdater = true;
            _storeUpdaterCts = new CancellationTokenSource();
            _ = Dispatcher.BeginInvoke(new Action(async () => {
                await StartStoreUpdaterAfterFirstRenderAsync(_storeUpdaterCts.Token);
            }), DispatcherPriority.Background);
        }

        private async Task StartStoreUpdaterAfterFirstRenderAsync(CancellationToken cancellationToken) {
            try {
                await _storeAppUpdaterService.InitializeAfterFirstRenderAsync(cancellationToken);
            }
            catch (OperationCanceledException) {
                // App is shutting down.
            }
            catch (Exception ex) {
                JsonLogStore.Error(
                    eventName: "store_update_initialization_failed",
                    message: "Store updater initialization failed.",
                    category: "store_update",
                    exception: ex);
            }
        }

        private async void UpdateButton_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            if (_isClosing) {
                return;
            }

            try {
                await _storeAppUpdaterService.StartUpdateAsync(_storeUpdaterCts?.Token ?? CancellationToken.None);
            }
            catch (OperationCanceledException) {
                // App is shutting down.
            }
        }

        private void ApplyStoreUpdateUiState(StoreUpdateUiState state) {
            if (!Dispatcher.CheckAccess()) {
                Dispatcher.Invoke(() => ApplyStoreUpdateUiState(state));
                return;
            }

            if (UpdateButton is not null) {
                UpdateButton.Visibility = state.IsUpdateButtonVisible ? Visibility.Visible : Visibility.Collapsed;
                UpdateButton.IsEnabled = state.IsUpdateButtonEnabled;
                UpdateButton.Focusable = state.IsUpdateButtonVisible && state.IsUpdateButtonEnabled;
            }

            if (state.IsProgressVisible) {
                EnsureStoreUpdateProgressWindow();
                _storeUpdateProgressWindow?.ApplyState(state);
            }
            else if (_storeUpdateProgressWindow is not null) {
                _storeUpdateProgressWindow.CloseFromOwner();
                _storeUpdateProgressWindow = null;
            }
        }

        private void EnsureStoreUpdateProgressWindow() {
            if (_storeUpdateProgressWindow is not null) {
                if (!_storeUpdateProgressWindow.IsVisible) {
                    _storeUpdateProgressWindow.Show();
                }

                _storeUpdateProgressWindow.Activate();
                return;
            }

            _storeUpdateProgressWindow = new StoreUpdateProgressWindow {
                Owner = this
            };
            _storeUpdateProgressWindow.Closed += (_, _) => { _storeUpdateProgressWindow = null; };
            _storeUpdateProgressWindow.Show();
            _storeUpdateProgressWindow.Activate();
        }

        private void PersistSettingsForUpdater() {
            TrySaveSettings(
                eventName: "store_update_settings_save_failed",
                logMessage: "Failed to persist store updater settings.");
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
            if (AppModeStatusText is null || UpgradeButton is null) {
                return;
            }

            if (!_storeContextProvider.IsPackaged || !_hasResolvedPremiumUiState) {
                AppModeStatusText.Visibility = Visibility.Collapsed;
                UpgradeButton.Visibility = Visibility.Collapsed;
                UpgradeButton.IsEnabled = false;
                UpgradeButton.Focusable = false;
                return;
            }

            AppModeStatusText.Visibility = Visibility.Visible;
            AppModeStatusText.Text = _isPremiumOwned ? "Premium" : "Basic";

            var showUpgrade = !_isPremiumOwned;
            UpgradeButton.Visibility = showUpgrade ? Visibility.Visible : Visibility.Collapsed;
            UpgradeButton.IsEnabled = showUpgrade && !_isPremiumPurchaseBusy;
            UpgradeButton.Focusable = showUpgrade && !_isPremiumPurchaseBusy;
        }

        private async void UpgradeButton_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            await TryStartPremiumPurchaseFlowAsync(requireConfirmationDialog: true);
        }

        private async Task TryStartPremiumPurchaseFlowAsync(bool requireConfirmationDialog = false) {
            if (!Dispatcher.CheckAccess()) {
                await Dispatcher.InvokeAsync(async () => {
                    await TryStartPremiumPurchaseFlowAsync(requireConfirmationDialog);
                });
                return;
            }

            if (_isPremiumPurchaseBusy || _isPremiumOwned) {
                return;
            }

            if (requireConfirmationDialog) {
                var confirmationDialog = new BasicFeatureGateDialog("Upgrade to Premium for full access.") {
                    Owner = this
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
                RestoreWindowAccessibilityAfterStoreFlow();
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

        private void RestoreWindowAccessibilityAfterStoreFlow() {
            try {
                if (!IsEnabled) {
                    IsEnabled = true;
                }

                Activate();
                Focus();
                Keyboard.Focus(this);
            }
            catch {
                // Best-effort accessibility recovery; keep flow non-fatal.
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
            var message = $"{blockedReason} Upgrade to Premium for full access.";
            var dialog = new BasicFeatureGateDialog(message) {
                Owner = this
            };

            var result = dialog.ShowDialog();
            if (result == true && dialog.UpgradeRequested) {
                await TryStartPremiumPurchaseFlowAsync(requireConfirmationDialog: false);
            }
        }


        private void UpdateActionButtons() {
            var anyPlaying = IsAnyStreamRunning();
            var anyNotPlaying = HasAnyStoppedDetectedCamera();

            DetectCameraButton.Content = _isScanning ? "Cancel Detecting" : "Detect Camera";
            DetectCameraButton.IsEnabled = !_isDetectButtonToggleDelayActive;
            ToolbarStartStreamsButton.IsEnabled = anyNotPlaying;
            ToolbarStopButton.IsEnabled = anyPlaying;
            SettingsButton.IsEnabled = true;
            UpdateTileButtonStates();
        }

        private async Task StartLocalCameraSearchAsync() {
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
                _isScanning = true;
                _isUserScanCancelRequested = false;
                _scanCancellation = new CancellationTokenSource();
                _ = BeginDetectButtonToggleDelayAsync();
                var progress = new Progress<TapoCameraScanActivity>(activity => {
                    if (_isClosing || !_isScanning) {
                        return;
                    }

                    StreamingStatusText.Text = activity.StatusMessage;
                });
                var preferredMethod = ResolvePreferredDetectionMethod();
                SetScanningState(preferredMethod);

                try {
                    var scanResult = await TapoCameraScanner.ScanLocalNetworkForTapoCamerasWithDiagnosticsAsync(
                        preferredFirstMethod: preferredMethod,
                        progress: progress,
                        cancellationToken: _scanCancellation.Token);

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
                        return;
                    }

                    JsonLogStore.Warning(
                        eventName: "camera_search_no_detections",
                        message: "Local network scan completed without any likely Tapo cameras.",
                        category: "camera_search",
                        data: new Dictionary<string, object?> {
                            ["attemptedMethods"] = scanResult.AttemptedMethods.Select(a => a.Method.ToString()).ToArray()
                        });
                    ShowNoDetections(BuildNoDetectionsMessage(scanResult.AttemptedMethods));
                }
                catch (OperationCanceledException) when (_isClosing) {
                    return;
                }
                catch (OperationCanceledException) {
                    if (!_isClosing) {
                        JsonLogStore.Warning(
                            eventName: "camera_search_operation_canceled",
                            message: "Local network search was canceled.",
                            category: "camera_search");
                        ShowNoDetections("Scan canceled.");
                    }

                    if (_isUserScanCancelRequested) {
                        return;
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
                    _ = BeginDetectButtonToggleDelayAsync();
                    if (!_isClosing) {
                        UpdateActionButtons();
                    }
                }

                if (_isClosing) {
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

        private void SetScanningState(TapoDetectionMethod? preferredMethod) {
            StreamingStatusText.Text = preferredMethod is TapoDetectionMethod method
                ? $"Trying last successful method: {GetDetectionMethodDisplayName(method)}..."
                : "Searching local network for cameras...";
            CameraTilesPanel.Visibility = Visibility.Collapsed;
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

        private void ShowDetections(IReadOnlyList<TapoCameraDetection> detections, TapoDetectionMethod? successfulMethod = null) {
            _detections = detections.ToArray();
            CameraTilesPanel.Visibility = Visibility.Visible;
            PopulateCameraTiles(_detections);
            ApplyResponsiveCameraLayout();
            StreamingStatusText.Text = BuildDetectionsStatusText(_detections.Count, successfulMethod);
            UpdateActionButtons();
            SearchProgressBar.Visibility = Visibility.Collapsed;
            Dispatcher.BeginInvoke(TryAutoStartStreams, System.Windows.Threading.DispatcherPriority.Background);
        }

        private void ShowNoDetections(string? prefixMessage = null) {
            _expandedCameraIndex = null;
            CameraTilesPanel.Visibility = Visibility.Collapsed;
            UpdateTileButtonStates();
            UpdateActionButtons();
            SearchProgressBar.Visibility = Visibility.Collapsed;

            if (!string.IsNullOrWhiteSpace(prefixMessage)) {
                StreamingStatusText.Text = $"{prefixMessage} Retry search?";
                return;
            }

            StreamingStatusText.Text = "No compatible camera detected. Retry search?";
        }

        private void DetectCameraButton_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;

            if (_isScanning) {
                _isUserScanCancelRequested = true;
                _scanCancellation?.Cancel();
                return;
            }

            _ = StartLocalCameraSearchAsync();
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

        private async void ToolbarStartStreamsButton_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            await StartAllStreamsAsync();
        }

        private void ToolbarStopButton_Click(object sender, RoutedEventArgs e) {
            StopAllStreams();
            StreamingStatusText.Text = "Streams stopped.";
            UpdateActionButtons();
        }

        private void SettingsButton_Click(object sender, RoutedEventArgs e) {
            OpenSettingsDialog();
        }

        private void OpenSettingsDialog(string? inlineErrorMessage = null) {
            var text = (inlineErrorMessage ?? string.Empty).Trim();
            var openSettingsWindow = FindOpenSettingsWindow();
            if (openSettingsWindow is not null) {
                openSettingsWindow.ShowInlineError(text);
                openSettingsWindow.Activate();
                return;
            }

            var dialog = new SettingsWindow(_settings) {
                Owner = this
            };

            if (!string.IsNullOrWhiteSpace(text)) {
                dialog.ShowInlineError(text);
            }

            _isSettingsDialogOpen = true;
            try {
                dialog.ShowDialog();
                if (dialog.DidSave) {
                    _settings = dialog.Settings;
                    TryAutoStartStreams();
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

        private async Task StartAllStreamsAsync() {
            if (_libVlc is null) {
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
            var isBasicMode = !_isPremiumOwned;
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
                OpenSettingsDialog(RtspSettingsInvalidMessage);
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
                var streamUrl = BuildRtspUrl(ipAddress, username, password, streamPath);
                var mediaPlayer = _cameraTiles[i].MediaPlayer;
                if (mediaPlayer is null) {
                    failedEndpoints.Add(ipAddress);
                    SetVideoSurfaceActive(i, isActive: false);
                    continue;
                }

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

                    SetStreamLifecyclePhase(i, StreamLifecyclePhase.Starting);
                    EnsureVideoSurfaceAttached(i);
                    using var media = CreateRtspPlaybackMedia(streamUrl);

                    if (mediaPlayer.Play(media)) {
                        startedCount++;
                        if (isBasicMode) {
                            remainingBasicSlots--;
                        }
                        MarkStreamStarted(i);
                        SetVideoSurfaceActive(i, isActive: true);
                        JsonLogStore.Information(
                            eventName: "camera_connect_succeeded",
                            message: "RTSP stream started successfully.",
                            category: "camera_connect",
                            data: new Dictionary<string, object?> {
                                ["cameraIndex"] = i + 1,
                                ["ipAddress"] = ipAddress,
                                ["streamPath"] = streamPath
                            });
                    }
                    else {
                        _streamFailureReasons[i] = "The media player rejected the RTSP stream.";
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
                                ["reason"] = "media player returned false"
                            });
                    }
                }
                catch (Exception ex) {
                    SetStreamLifecyclePhase(i, StreamLifecyclePhase.Stopped);
                    _streamFailureReasons[i] = ex.Message;
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
                }
            }

            _streamsRunning = startedCount > 0 || IsAnyStreamRunning();
            if (blockedByBasicLimit) {
                await ShowBasicFeatureGateDialogAsync($"Basic mode supports up to {BasicConcurrentStreamLimit} active live streams at a time.");
            }
            if (failedEndpoints.Count == 0) {
                JsonLogStore.Information(
                    eventName: "camera_connect_completed",
                    message: "RTSP connections started for all detected cameras.",
                    category: "camera_connect",
                    data: new Dictionary<string, object?> {
                        ["startedCount"] = startedCount,
                        ["failedCount"] = 0,
                        ["cameraCount"] = _detections.Count,
                        ["streamPath"] = streamPath
                    });
                StreamingStatusText.Text = $"Streaming started for {startedCount} {Pluralize(startedCount, "camera")}.";
                UpdateActionButtons();
                return;
            }

            JsonLogStore.Warning(
                eventName: "camera_connect_completed_with_failures",
                message: "RTSP connections started with one or more failures.",
                category: "camera_connect",
                data: new Dictionary<string, object?> {
                    ["startedCount"] = startedCount,
                    ["failedCount"] = failedEndpoints.Count,
                    ["cameraCount"] = _detections.Count,
                    ["failedEndpoints"] = failedEndpoints.ToArray(),
                    ["streamPath"] = streamPath
                });
            StreamingStatusText.Text =
                $"Started {startedCount} {Pluralize(startedCount, "stream")}. Failed to start: {string.Join(", ", failedEndpoints)}.";
            UpdateActionButtons();
        }

        private void TryAutoStartStreams() {
            if (_isClosing || _isScanning || !_settings.AutoStreamVideo) {
                return;
            }

            if (_libVlc is null || _detections.Count == 0) {
                return;
            }

            if (!HasValidStreamStartSettings(_settings.RtspUsername.Trim(), _settings.RtspPassword, _settings.StreamPath)) {
                StreamingStatusText.Text = RtspSettingsInvalidMessage;
                OpenSettingsDialog(RtspSettingsInvalidMessage);
                return;
            }

            _ = StartAllStreamsAsync();
        }

        private void StopAllStreams() {
            _expandedCameraIndex = null;
            StopRecordingSession("all_streams_stopped", updateStatus: false);
            CancelAllStreamRestartAttempts();
            for (var i = 0; i < _cameraTiles.Count; i++) {
                BumpStreamLifecycleRevision(i);
                SetStreamLifecyclePhase(i, StreamLifecyclePhase.Stopping);
                var mediaPlayer = _cameraTiles[i].MediaPlayer;
                if (mediaPlayer is null) {
                    continue;
                }

                if (mediaPlayer.IsPlaying) {
                    mediaPlayer.Stop();
                }

                SetVideoSurfaceActive(i, isActive: false);
                SetStreamLifecyclePhase(i, StreamLifecyclePhase.Stopped);
            }

            _streamStartOrder.Clear();
            _streamFailureReasons.Clear();
            _streamHealthStates.Clear();
            _streamIntentionalRestartTiles.Clear();
            _streamRestartCancellationSources.Clear();
            _streamHealthCheckCursor = 0;
            _streamsRunning = false;
            ApplyResponsiveCameraLayout();
            UpdateActionButtons();
        }

        private void RecoverStreamsAfterResume() {
            if (_isClosing || _libVlc is null || _isScanning || _isRecoveringStreamsAfterResume) {
                return;
            }

            var tileIndexes = _streamStartOrder
                .OrderBy(pair => pair.Value)
                .Select(pair => pair.Key)
                .Where(index => index >= 0 && index < _cameraTiles.Count && index < _detections.Count)
                .Distinct()
                .ToArray();

            if (tileIndexes.Length == 0) {
                return;
            }

            var username = _settings.RtspUsername.Trim();
            var password = _settings.RtspPassword;
            var streamPath = NormalizeStreamPath(_settings.StreamPath);
            if (!HasValidStreamStartSettings(username, password, _settings.StreamPath)) {
                StreamingStatusText.Text = RtspSettingsInvalidMessage;
                OpenSettingsDialog(RtspSettingsInvalidMessage);
                return;
            }

            _isRecoveringStreamsAfterResume = true;
            try {
                var restartedCount = 0;
                var failedCount = 0;

                JsonLogStore.Information(
                    eventName: "camera_connect_resume_recovery_started",
                    message: "Attempting to restore active RTSP streams after system resume.",
                    category: "camera_connect",
                    data: new Dictionary<string, object?> {
                        ["cameraCount"] = tileIndexes.Length,
                        ["streamPath"] = streamPath
                    });

                foreach (var tileIndex in tileIndexes) {
                    var mediaPlayer = _cameraTiles[tileIndex].MediaPlayer;
                    if (mediaPlayer is null) {
                        failedCount++;
                        if (_activeRecordingTileIndex == tileIndex) {
                            StopRecordingSession("stream_error", updateStatus: true);
                        }
                        continue;
                    }

                    var ipAddress = _detections[tileIndex].IpAddress.ToString();
                    var streamUrl = BuildRtspUrl(ipAddress, username, password, streamPath);

                    try {
                        EnsureVideoSurfaceAttached(tileIndex);
                        JsonLogStore.Information(
                            eventName: "camera_connect_resume_recovery_attempt",
                            message: "Reconnecting an RTSP stream after system resume.",
                            category: "camera_connect",
                            data: new Dictionary<string, object?> {
                                ["cameraIndex"] = tileIndex + 1,
                                ["ipAddress"] = ipAddress,
                                ["streamPath"] = streamPath
                        });

                        _streamIntentionalRestartTiles.Add(tileIndex);
                        SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Restarting);
                        if (mediaPlayer.IsPlaying) {
                            mediaPlayer.Stop();
                        }

                        using var media = CreateRtspPlaybackMedia(streamUrl);
                        if (mediaPlayer.Play(media)) {
                            restartedCount++;
                            MarkStreamStarted(tileIndex);
                            SetVideoSurfaceActive(tileIndex, isActive: true);
                            SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Running);
                            continue;
                        }

                        failedCount++;
                        _streamFailureReasons[tileIndex] = "The media player rejected the RTSP stream after system resume.";
                        SetVideoSurfaceActive(tileIndex, isActive: false);
                        SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
                        _streamStartOrder.Remove(tileIndex);
                        _streamHealthStates.Remove(tileIndex);
                        if (_activeRecordingTileIndex == tileIndex) {
                            StopRecordingSession("stream_error", updateStatus: true);
                        }
                        JsonLogStore.Warning(
                            eventName: "camera_connect_resume_recovery_failed",
                            message: "RTSP stream failed to reconnect after system resume.",
                            category: "camera_connect",
                            data: new Dictionary<string, object?> {
                                ["cameraIndex"] = tileIndex + 1,
                                ["ipAddress"] = ipAddress,
                                ["streamPath"] = streamPath,
                                ["reason"] = "media player returned false"
                            });
                    }
                    catch (Exception ex) {
                        failedCount++;
                        _streamFailureReasons[tileIndex] = ex.Message;
                        SetVideoSurfaceActive(tileIndex, isActive: false);
                        SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
                        _streamStartOrder.Remove(tileIndex);
                        _streamHealthStates.Remove(tileIndex);
                        if (_activeRecordingTileIndex == tileIndex) {
                            StopRecordingSession("stream_error", updateStatus: true);
                        }
                        JsonLogStore.Error(
                            eventName: "camera_connect_resume_recovery_exception",
                            message: "RTSP stream reconnect threw an exception after system resume.",
                            category: "camera_connect",
                            exception: ex,
                            data: new Dictionary<string, object?> {
                                ["cameraIndex"] = tileIndex + 1,
                                ["ipAddress"] = ipAddress,
                                ["streamPath"] = streamPath
                            });
                    }
                    finally {
                        _streamIntentionalRestartTiles.Remove(tileIndex);
                    }
                }

                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
                StreamingStatusText.Text = failedCount == 0
                    ? $"Streaming resumed for {restartedCount} {Pluralize(restartedCount, "camera")}."
                    : $"Resumed {restartedCount} {Pluralize(restartedCount, "stream")}. Failed to resume {failedCount}.";
            }
            finally {
                _isRecoveringStreamsAfterResume = false;
            }
        }

        private async Task<bool> StartSingleStreamAsync(int tileIndex) {
            if (_libVlc is null || tileIndex < 0 || tileIndex >= _cameraTiles.Count || tileIndex >= _detections.Count) {
                return false;
            }

            if (!CanStartStream(tileIndex)) {
                return false;
            }

            if (!_isPremiumOwned && CountActiveStreams() >= BasicConcurrentStreamLimit) {
                StreamingStatusText.Text = $"Basic supports up to {BasicConcurrentStreamLimit} active live streams.";
                await ShowBasicFeatureGateDialogAsync($"Basic mode supports up to {BasicConcurrentStreamLimit} active live streams at a time.");
                return false;
            }

            var username = _settings.RtspUsername.Trim();
            var password = _settings.RtspPassword;
            if (!HasValidStreamStartSettings(username, password, _settings.StreamPath)) {
                StreamingStatusText.Text = RtspSettingsInvalidMessage;
                OpenSettingsDialog(RtspSettingsInvalidMessage);
                return false;
            }

            var streamPath = NormalizeStreamPath(_settings.StreamPath);
            var ipAddress = _detections[tileIndex].IpAddress.ToString();
            var mediaPlayer = _cameraTiles[tileIndex].MediaPlayer;
            if (mediaPlayer is null) {
                return false;
            }

            try {
                SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Starting);
                EnsureVideoSurfaceAttached(tileIndex);

                using var media = new Media(_libVlc, BuildRtspUrl(ipAddress, username, password, streamPath), FromType.FromLocation);
                media.AddOption(":network-caching=300");
                media.AddOption(":live-caching=300");
                media.AddOption(":clock-jitter=0");
                media.AddOption(":clock-synchro=0");

                if (mediaPlayer.Play(media)) {
                    MarkStreamStarted(tileIndex);
                    SetVideoSurfaceActive(tileIndex, isActive: true);
                    StreamingStatusText.Text = $"Started camera {tileIndex + 1}.";
                    return true;
                }
            }
            catch (Exception ex) {
                SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
                _streamFailureReasons[tileIndex] = ex.Message;
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

            SetVideoSurfaceActive(tileIndex, isActive: false);
            SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
            _streamStartOrder.Remove(tileIndex);
            _streamFailureReasons.TryAdd(tileIndex, "The media player rejected the RTSP stream.");
            StreamingStatusText.Text = $"Failed to start camera {tileIndex + 1}.";
            return false;
        }

        private void StopSingleStream(int tileIndex, bool updateStatus = true) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count) {
                return;
            }

            if (_activeRecordingTileIndex == tileIndex) {
                StopRecordingSession("stream_stopped", updateStatus: false);
            }

            BumpStreamLifecycleRevision(tileIndex);
            CancelStreamRestartAttempt(tileIndex);
            SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopping);
            var mediaPlayer = _cameraTiles[tileIndex].MediaPlayer;
            if (mediaPlayer is not null && mediaPlayer.IsPlaying) {
                mediaPlayer.Stop();
            }

            SetVideoSurfaceActive(tileIndex, isActive: false);
            SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
            _streamHealthStates.Remove(tileIndex);
            _streamIntentionalRestartTiles.Remove(tileIndex);
            _streamStartOrder.Remove(tileIndex);
            if (updateStatus) {
                StreamingStatusText.Text = $"Stopped camera {tileIndex + 1}.";
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

        private void MarkStreamStarted(int tileIndex) {
            SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Running);
            _streamStartOrder[tileIndex] = _nextStreamStartOrder++;
            UpdateStreamHealthState(tileIndex, initializeBaseline: true);
        }

        private int GetStreamLifecycleRevision(int tileIndex) {
            return _streamHealthStates.TryGetValue(tileIndex, out var state)
                ? state.LifecycleRevision
                : 0;
        }

        private int BumpStreamLifecycleRevision(int tileIndex) {
            if (tileIndex < 0) {
                return 0;
            }

            if (!_streamHealthStates.TryGetValue(tileIndex, out var state)) {
                state = new StreamHealthState();
                _streamHealthStates[tileIndex] = state;
            }

            state.LifecycleRevision++;
            return state.LifecycleRevision;
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

        private CancellationTokenSource CreateOrReplaceStreamRestartCancellationSource(int tileIndex) {
            var replacement = new CancellationTokenSource();
            if (_streamRestartCancellationSources.TryGetValue(tileIndex, out var existing)) {
                existing.Cancel();
                existing.Dispose();
            }

            _streamRestartCancellationSources[tileIndex] = replacement;
            return replacement;
        }

        private void CancelStreamRestartAttempt(int tileIndex) {
            if (!_streamRestartCancellationSources.TryGetValue(tileIndex, out var cts)) {
                return;
            }

            _streamRestartCancellationSources.Remove(tileIndex);
            try {
                cts.Cancel();
            }
            catch {
                // Best-effort cancellation only.
            }
            finally {
                cts.Dispose();
            }
        }

        private void CancelAllStreamRestartAttempts() {
            foreach (var tileIndex in _streamRestartCancellationSources.Keys.ToArray()) {
                CancelStreamRestartAttempt(tileIndex);
            }
        }

        private void UpdateStreamHealthState(int tileIndex, bool initializeBaseline) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count) {
                return;
            }

            var mediaPlayer = _cameraTiles[tileIndex].MediaPlayer;
            if (mediaPlayer is null) {
                return;
            }

            var now = DateTimeOffset.Now;
            if (!_streamHealthStates.TryGetValue(tileIndex, out var state)) {
                state = new StreamHealthState();
                _streamHealthStates[tileIndex] = state;
            }

            if (initializeBaseline || state.LastStartedAt == default) {
                state.LastStartedAt = now;
                state.LastRestartAttemptAt = now;
                state.ConsecutiveStaleChecks = 0;
            }

            CaptureStreamHealthSnapshot(mediaPlayer, state, now);
        }

        private static void CaptureStreamHealthSnapshot(VlcMediaPlayer mediaPlayer, StreamHealthState state, DateTimeOffset now) {
            state.LastTime = mediaPlayer.Time;
            state.LastPosition = mediaPlayer.Position;

            using var media = mediaPlayer.Media;
            if (media is not null) {
                var stats = media.Statistics;
                state.LastDisplayedPictures = stats.DisplayedPictures;
                state.LastDecodedVideo = stats.DecodedVideo;
                state.LastReadBytes = stats.ReadBytes;
            }

            state.LastProgressAt = now;
        }

        private void StartStreamHealthMonitor() {
            if (_streamHealthTimer is not null) {
                return;
            }

            _streamHealthTimer = new DispatcherTimer {
                Interval = StreamHealthCheckInterval
            };
            _streamHealthTimer.Tick += StreamHealthTimer_Tick;
            _streamHealthTimer.Start();
        }

        private void StopStreamHealthMonitor() {
            if (_streamHealthTimer is null) {
                return;
            }

            _streamHealthTimer.Stop();
            _streamHealthTimer.Tick -= StreamHealthTimer_Tick;
            _streamHealthTimer = null;
        }

        private async void StreamHealthTimer_Tick(object? sender, EventArgs e) {
            _ = sender;
            _ = e;

            try {
                if (_isClosing || _isScanning || _libVlc is null || _isRecoveringStreamsAfterResume) {
                    return;
                }

                if (_isStreamHealthCheckRunning || !IsAnyStreamRunning()) {
                    return;
                }

                var activeTileIndexes = _streamStartOrder
                    .OrderBy(pair => pair.Value)
                    .Select(pair => pair.Key)
                    .Where(index => index >= 0 && index < _cameraTiles.Count && index < _detections.Count)
                    .ToArray();

                if (activeTileIndexes.Length == 0) {
                    return;
                }

                _isStreamHealthCheckRunning = true;
                try {
                    if (_streamHealthCheckCursor >= activeTileIndexes.Length) {
                        _streamHealthCheckCursor = 0;
                    }

                    var tileIndex = activeTileIndexes[_streamHealthCheckCursor];
                    _streamHealthCheckCursor = (_streamHealthCheckCursor + 1) % activeTileIndexes.Length;

                    await CheckStreamHealthAsync(tileIndex);
                }
                finally {
                    _isStreamHealthCheckRunning = false;
                }
            }
            catch (Exception ex) {
                JsonLogStore.Error(
                    eventName: "camera_stream_health_monitor_failed",
                    message: "The stream health monitor failed unexpectedly.",
                    category: "camera_connect",
                    exception: ex);
                _isStreamHealthCheckRunning = false;
            }
        }

        private async Task CheckStreamHealthAsync(int tileIndex) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count || !_streamStartOrder.ContainsKey(tileIndex)) {
                return;
            }

            var mediaPlayer = _cameraTiles[tileIndex].MediaPlayer;
            if (mediaPlayer is null || !mediaPlayer.IsPlaying || mediaPlayer.State != VLCState.Playing || mediaPlayer.VoutCount == 0) {
                return;
            }

            if (!_streamHealthStates.TryGetValue(tileIndex, out var state)) {
                UpdateStreamHealthState(tileIndex, initializeBaseline: true);
                return;
            }

            var now = DateTimeOffset.Now;
            if (now - state.LastStartedAt < StreamHealthWarmup) {
                CaptureStreamHealthSnapshot(mediaPlayer, state, now);
                return;
            }

            var currentTime = mediaPlayer.Time;
            var currentPosition = mediaPlayer.Position;
            var currentDisplayedPictures = state.LastDisplayedPictures;
            var currentDecodedVideo = state.LastDecodedVideo;
            var currentReadBytes = state.LastReadBytes;

            using (var media = mediaPlayer.Media) {
                if (media is not null) {
                    var stats = media.Statistics;
                    currentDisplayedPictures = stats.DisplayedPictures;
                    currentDecodedVideo = stats.DecodedVideo;
                    currentReadBytes = stats.ReadBytes;
                }
            }

            var hasProgressed = !state.LastTime.HasValue ||
                                currentTime != state.LastTime.Value ||
                                Math.Abs(currentPosition - state.LastPosition) > 0.0001 ||
                                currentDisplayedPictures > state.LastDisplayedPictures ||
                                currentDecodedVideo > state.LastDecodedVideo ||
                                currentReadBytes > state.LastReadBytes;

            if (hasProgressed) {
                state.LastTime = currentTime;
                state.LastPosition = currentPosition;
                state.LastDisplayedPictures = currentDisplayedPictures;
                state.LastDecodedVideo = currentDecodedVideo;
                state.LastReadBytes = currentReadBytes;
                state.LastProgressAt = now;
                state.ConsecutiveStaleChecks = 0;
                return;
            }

            state.ConsecutiveStaleChecks++;
            if (now - state.LastProgressAt < StreamHealthStaleThreshold) {
                return;
            }

            if (state.ConsecutiveStaleChecks < StreamHealthRequiredStaleChecks) {
                return;
            }

            if (now - state.LastRestartAttemptAt < StreamHealthRestartCooldown) {
                return;
            }

            state.LastRestartAttemptAt = now;
            await RestartStreamAfterStaleFrameAsync(tileIndex);
        }

        private async Task RestartStreamAfterStaleFrameAsync(int tileIndex) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count || tileIndex >= _detections.Count) {
                return;
            }

            if (!_streamStartOrder.ContainsKey(tileIndex) || !IsStreamRunning(tileIndex)) {
                return;
            }

            var username = _settings.RtspUsername.Trim();
            var password = _settings.RtspPassword;
            var streamPath = NormalizeStreamPath(_settings.StreamPath);
            if (!HasValidStreamStartSettings(username, password, _settings.StreamPath)) {
                StreamingStatusText.Text = RtspSettingsInvalidMessage;
                OpenSettingsDialog(RtspSettingsInvalidMessage);
                return;
            }

            var ipAddress = _detections[tileIndex].IpAddress.ToString();
            var lifecycleRevision = GetStreamLifecycleRevision(tileIndex);
            JsonLogStore.Warning(
                eventName: "camera_stream_health_stale_detected",
                message: "A live stream stopped advancing and will be restarted.",
                category: "camera_connect",
                data: new Dictionary<string, object?> {
                    ["cameraIndex"] = tileIndex + 1,
                    ["ipAddress"] = ipAddress,
                    ["streamPath"] = streamPath
                });

            CancellationTokenSource? restartCts = null;
            try {
                var mediaPlayer = _cameraTiles[tileIndex].MediaPlayer;
                if (mediaPlayer is null) {
                    return;
                }

                _streamIntentionalRestartTiles.Add(tileIndex);
                SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Restarting);
                EnsureVideoSurfaceAttached(tileIndex);
                restartCts = CreateOrReplaceStreamRestartCancellationSource(tileIndex);
                var token = restartCts.Token;
                var started = await Task.Run(() => {
                    token.ThrowIfCancellationRequested();
                    if (lifecycleRevision != GetStreamLifecycleRevision(tileIndex)) {
                        throw new OperationCanceledException(token);
                    }
                    if (mediaPlayer.IsPlaying) {
                        mediaPlayer.Stop();
                    }

                    token.ThrowIfCancellationRequested();
                    if (lifecycleRevision != GetStreamLifecycleRevision(tileIndex)) {
                        throw new OperationCanceledException(token);
                    }
                    Thread.Sleep(250);
                    token.ThrowIfCancellationRequested();
                    if (lifecycleRevision != GetStreamLifecycleRevision(tileIndex)) {
                        throw new OperationCanceledException(token);
                    }

                    using var media = CreateRtspPlaybackMedia(BuildRtspUrl(ipAddress, username, password, streamPath));
                    token.ThrowIfCancellationRequested();
                    if (lifecycleRevision != GetStreamLifecycleRevision(tileIndex)) {
                        throw new OperationCanceledException(token);
                    }
                    var startedLocal = mediaPlayer.Play(media);
                    if (!startedLocal) {
                        return false;
                    }

                    if (token.IsCancellationRequested || lifecycleRevision != GetStreamLifecycleRevision(tileIndex)) {
                        if (mediaPlayer.IsPlaying) {
                            mediaPlayer.Stop();
                        }

                        throw new OperationCanceledException(token);
                    }

                    return true;
                }, token);

                if (token.IsCancellationRequested) {
                    return;
                }

                if (_isClosing || _isScanning || !_streamStartOrder.ContainsKey(tileIndex)) {
                    return;
                }

                if (started) {
                    MarkStreamStarted(tileIndex);
                    SetVideoSurfaceActive(tileIndex, isActive: true);
                    SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Running);
                    _streamsRunning = IsAnyStreamRunning();
                    UpdateActionButtons();
                    JsonLogStore.Information(
                        eventName: "camera_stream_health_restart_succeeded",
                        message: "A stale live stream was restarted successfully.",
                        category: "camera_connect",
                        data: new Dictionary<string, object?> {
                            ["cameraIndex"] = tileIndex + 1,
                            ["ipAddress"] = ipAddress,
                            ["streamPath"] = streamPath
                    });
                    return;
                }

                _streamFailureReasons[tileIndex] = "The media player rejected the RTSP stream during health recovery.";
                SetVideoSurfaceActive(tileIndex, isActive: false);
                SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
                _streamStartOrder.Remove(tileIndex);
                _streamHealthStates.Remove(tileIndex);
                if (_activeRecordingTileIndex == tileIndex) {
                    StopRecordingSession("stream_error", updateStatus: true);
                }
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
                JsonLogStore.Warning(
                    eventName: "camera_stream_health_restart_failed",
                    message: "A stale live stream failed to restart.",
                    category: "camera_connect",
                    data: new Dictionary<string, object?> {
                        ["cameraIndex"] = tileIndex + 1,
                        ["ipAddress"] = ipAddress,
                        ["streamPath"] = streamPath,
                        ["reason"] = "media player returned false"
                    });
            }
            catch (Exception ex) {
                if (ex is OperationCanceledException) {
                    JsonLogStore.Information(
                        eventName: "camera_stream_health_restart_canceled",
                        message: "A stale live stream restart was canceled.",
                        category: "camera_connect",
                        data: new Dictionary<string, object?> {
                            ["cameraIndex"] = tileIndex + 1,
                            ["ipAddress"] = ipAddress,
                            ["streamPath"] = streamPath
                        });
                    return;
                }

                _streamFailureReasons[tileIndex] = ex.Message;
                SetVideoSurfaceActive(tileIndex, isActive: false);
                SetStreamLifecyclePhase(tileIndex, StreamLifecyclePhase.Stopped);
                _streamStartOrder.Remove(tileIndex);
                _streamHealthStates.Remove(tileIndex);
                if (_activeRecordingTileIndex == tileIndex) {
                    StopRecordingSession("stream_error", updateStatus: true);
                }
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
                JsonLogStore.Error(
                    eventName: "camera_stream_health_restart_exception",
                    message: "Restarting a stale live stream threw an exception.",
                    category: "camera_connect",
                    exception: ex,
                    data: new Dictionary<string, object?> {
                        ["cameraIndex"] = tileIndex + 1,
                        ["ipAddress"] = ipAddress,
                        ["streamPath"] = streamPath
                    });
            }
            finally {
                _streamIntentionalRestartTiles.Remove(tileIndex);
                if (_streamRestartCancellationSources.TryGetValue(tileIndex, out var current) && ReferenceEquals(current, restartCts)) {
                    _streamRestartCancellationSources.Remove(tileIndex);
                    current.Dispose();
                }
            }
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

                if (!_isPremiumOwned) {
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
            var basicRemaining = !_isPremiumOwned ? GetBasicRecordingRemaining() : TimeSpan.Zero;

            try {
                await Task.Run(() => System.IO.Directory.CreateDirectory(targetDirectory));

                var recorder = new VlcMediaPlayer(_libVlc) {
                    EnableHardwareDecoding = false,
                    EnableMouseInput = false,
                    Mute = true
                };
                AttachRecordingEventHandlers(recorder, tileIndex, recordingPath);

                using var media = CreateRtspPlaybackMedia(BuildRtspUrl(ipAddress, username, password, streamPath));
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
                if (!_isPremiumOwned && duration > TimeSpan.Zero) {
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
            if (_isPremiumOwned || remaining <= TimeSpan.Zero) {
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
                tile.MediaPlayer?.Dispose();
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

            JsonLogStore.Warning(
                eventName: "libvlc_runtime_log",
                message: "LibVLC emitted a runtime warning or error.",
                category: "camera_connect",
                data: new Dictionary<string, object?> {
                    ["level"] = e.Level.ToString(),
                    ["module"] = e.Module,
                    ["message"] = message
                });
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
                ? $"{detectionPrefix} Click 'Start All'."
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
                TapoDetectionMethod.OnvifWsDiscovery => "ONVIF",
                TapoDetectionMethod.SsdpUpnpSearch => "SSDP",
                TapoDetectionMethod.TapoUdpBroadcast => "local discovery",
                TapoDetectionMethod.MdnsDnsSdSweep => "mDNS",
                TapoDetectionMethod.ArpSeededTargetProbe => "ARP probe",
                TapoDetectionMethod.SubnetProbeFallback => "subnet probe",
                _ => method.ToString()
            };
        }

        private static string BuildRtspUrl(string host, string username, string password, string streamPath) {
            var escapedUsername = Uri.EscapeDataString(username);
            var escapedPassword = Uri.EscapeDataString(password);
            return $"rtsp://{escapedUsername}:{escapedPassword}@{host}:554/{streamPath}";
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e) {
            if (e.ClickCount == 2) {
                ToggleMaximizeRestore();
                return;
            }

            if (e.ButtonState == MouseButtonState.Pressed) {
                DragMove();
            }
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e) {
            WindowState = WindowState.Minimized;
        }

        private void MaximizeRestoreButton_Click(object sender, RoutedEventArgs e) {
            ToggleMaximizeRestore();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e) {
            Close();
        }

        private void Window_StateChanged(object sender, EventArgs e) {
            UpdateMaximizeButtonIcon();
            PersistWindowBounds();
        }

        private void SystemEvents_PowerModeChanged(object? sender, PowerModeChangedEventArgs e) {
            _ = sender;

            if (e.Mode != PowerModes.Resume || _isClosing) {
                return;
            }

            _ = Dispatcher.BeginInvoke(new Action(RecoverStreamsAfterResume), DispatcherPriority.Background);
        }

        private void ToggleMaximizeRestore() {
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        }

        private void UpdateMaximizeButtonIcon() {
            MaximizeIconPath.Data = WindowState == WindowState.Maximized
                ? RestoreGeometry
                : MaximizeGeometry;
        }

        private static void ApplyMonitorWorkAreaToMinMaxInfo(IntPtr hwnd, IntPtr lParam) {
            if (lParam == IntPtr.Zero) {
                return;
            }

            var monitor = MonitorFromWindow(hwnd, MonitorDefaultToNearest);
            if (monitor == IntPtr.Zero) {
                return;
            }

            var monitorInfo = new MonitorInfo {
                cbSize = Marshal.SizeOf<MonitorInfo>()
            };
            if (!GetMonitorInfo(monitor, ref monitorInfo)) {
                return;
            }

            var minMaxInfo = Marshal.PtrToStructure<MinMaxInfo>(lParam);

            var workArea = monitorInfo.rcWork;
            var monitorArea = monitorInfo.rcMonitor;

            minMaxInfo.ptMaxPosition.x = workArea.Left - monitorArea.Left;
            minMaxInfo.ptMaxPosition.y = workArea.Top - monitorArea.Top;
            minMaxInfo.ptMaxSize.x = workArea.Right - workArea.Left;
            minMaxInfo.ptMaxSize.y = workArea.Bottom - workArea.Top;
            minMaxInfo.ptMaxTrackSize.x = minMaxInfo.ptMaxSize.x;
            minMaxInfo.ptMaxTrackSize.y = minMaxInfo.ptMaxSize.y;

            Marshal.StructureToPtr(minMaxInfo, lParam, true);
        }

        [DllImport("user32.dll")]
        private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MonitorInfo lpmi);

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
        private struct RectNative {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PointNative {
            public int x;
            public int y;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MinMaxInfo {
            public PointNative ptReserved;
            public PointNative ptMaxSize;
            public PointNative ptMaxPosition;
            public PointNative ptMinTrackSize;
            public PointNative ptMaxTrackSize;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct MonitorInfo {
            public int cbSize;
            public RectNative rcMonitor;
            public RectNative rcWork;
            public uint dwFlags;
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
            _ = wParam;

            if (msg == WmGetMinMaxInfo) {
                ApplyMonitorWorkAreaToMinMaxInfo(hwnd, lParam);
                handled = false;
            }

            return IntPtr.Zero;
        }

        protected override void OnClosed(EventArgs e) {
            _isClosing = true;
            UninstallMouseHook();
            SystemEvents.PowerModeChanged -= SystemEvents_PowerModeChanged;
            StopStreamHealthMonitor();
            _scanCancellation?.Cancel();            ShutdownStreamingEngine();
            _storeUpdaterCts?.Cancel();
            _storeUpdaterCts?.Dispose();
            _storeUpdaterCts = null;
            _storeAppUpdaterService.Shutdown();
            _storeUpdateProgressWindow?.CloseFromOwner();
            _storeUpdateProgressWindow = null;
            _windowIconHandle?.Dispose();
            _windowIconHandle = null;

            base.OnClosed(e);
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e) {
            _isClosing = true;
            CancelAllStreamRestartAttempts();
            _scanCancellation?.Cancel();            PersistWindowBounds();
            _storeUpdaterCts?.Cancel();
            _storeAppUpdaterService.Shutdown();
            _storeUpdateProgressWindow?.CloseFromOwner();
            _storeUpdateProgressWindow = null;
            base.OnClosing(e);
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

