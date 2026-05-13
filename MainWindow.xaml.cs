using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using LibVLCSharp.Shared;
using LibVLCSharp.WPF;
using LocalCam.Networking;
using LocalCam.Models;
using LocalCam.Services;
using System.Diagnostics;
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
            public VlcMediaPlayer? MediaPlayer { get; set; }
            public bool IsSnapshotSaving { get; set; }
        }

        private static readonly Geometry MaximizeGeometry = Geometry.Parse("M2,2 L12,2 12,12 2,12 Z");
        private static readonly Geometry RestoreGeometry = Geometry.Parse("M4,2 L12,2 12,10 M4,2 L4,10 12,10 M2,4 L10,4 10,12 2,12 Z");
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
        private const int SmCxDoubleClk = 36;
        private const int SmCyDoubleClk = 37;
        private const uint MonitorDefaultToNearest = 2;
        private const string InputDiagnosticsCategory = "InputDiagnostics";
        private const string SnapshotDiagnosticsCategory = "SnapshotDiagnostics";
        private static readonly Geometry ExpandButtonGeometry = Geometry.Parse("M2,6 L2,2 L6,2 M10,2 L14,2 L14,6 M14,10 L14,14 L10,14 M6,14 L2,14 L2,10");

        private IReadOnlyList<TapoCameraDetection> _detections = Array.Empty<TapoCameraDetection>();
        private readonly List<CameraTileControls> _cameraTiles = new();
        private LibVLC? _libVlc;
        private CancellationTokenSource? _scanCancellation;
        private bool _isClosing;
        private bool _isScanning;
        private bool _streamsRunning;
        private bool _isStartingStreams;
        private bool _isApplyingPersistedWindowBounds;
        private bool _hasAppliedPersistedWindowBounds;
        private bool _layoutRetryPending;
        private bool _isSettingsDialogOpen;
        private int? _expandedCameraIndex;
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
        private readonly IAppVersionProvider _versionProvider = new AppVersionProvider();
        private IAppUpdateService? _appUpdateService;
        private CancellationTokenSource? _appUpdateCancellation;

        public MainWindow()
            : this(Array.Empty<TapoCameraDetection>()) {
        }

        public MainWindow(IReadOnlyList<TapoCameraDetection> detections) {
            _detections = detections.ToArray();

            InitializeComponent();
            SourceInitialized += MainWindow_SourceInitialized;
            LocationChanged += Window_LocationChanged;
            SizeChanged += Window_SizeChanged;
            FooterVersionText.Text = $"v{_versionProvider.GetInstalledVersionText()}";
            LoadSettings();
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
                Core.Initialize();
                _libVlc = new LibVLC("--network-caching=300", "--rtsp-tcp", "--no-video-title-show");
                EnsureCameraTileCount(_detections.Count);
                return true;
            }
            catch (Exception ex) {
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
                AutoStreamVideo = false
            };
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
            SettingsStore.Save(_settings);
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
            playButton.Click += (_, _) => {
                StartSingleStream(tileIndex);
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
            };

            var stopButton = new Button {
                Style = (Style)FindResource("CameraOverlayIconButtonStyle"),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
                ToolTip = "Stop",
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

            card.AddHandler(
                UIElement.PreviewMouseLeftButtonDownEvent,
                new MouseButtonEventHandler((_, e) => {
                    if (IsEventFromControl(e.OriginalSource as DependencyObject, playButton) ||
                        IsEventFromControl(e.OriginalSource as DependencyObject, stopButton) ||
                        IsEventFromControl(e.OriginalSource as DependencyObject, snapshotButton) ||
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
                SnapshotButton = snapshotButton
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
                Fill = System.Windows.Media.Brushes.White,
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
                var isDetectedCard = i < _detections.Count;

                tile.PlayButton.Visibility = isCardVisible && isDetectedCard && !isRunning ? Visibility.Visible : Visibility.Collapsed;
                tile.StopButton.Visibility = isCardVisible && isDetectedCard && isRunning ? Visibility.Visible : Visibility.Collapsed;
                tile.SnapshotButton.Visibility = isCardVisible && isDetectedCard && isRunning ? Visibility.Visible : Visibility.Collapsed;
                tile.PlayButton.IsEnabled = true;
                tile.StopButton.IsEnabled = true;
                tile.SnapshotButton.IsEnabled = !tile.IsSnapshotSaving;

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
                EnableHardwareDecoding = true,
                EnableMouseInput = false,
                Mute = true
            };
            mediaPlayer.Playing += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
            }));
            mediaPlayer.Stopped += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
            }));
            mediaPlayer.EndReached += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
            }));
            mediaPlayer.EncounteredError += (_, _) => Dispatcher.BeginInvoke(new Action(() => {
                _streamsRunning = IsAnyStreamRunning();
                UpdateActionButtons();
            }));

            tile.MediaPlayer = mediaPlayer;
            tile.VideoView.MediaPlayer = mediaPlayer;
        }

        private void SetVideoSurfaceActive(int index, bool isActive) {
            if (index < 0 || index >= _cameraTiles.Count) {
                return;
            }

            var tile = _cameraTiles[index];
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
            AutoStreamVideoCheckBox.IsChecked = _settings.AutoStreamVideo;
            InitializeUpdater();
            _ = StartLocalCameraSearchAsync();
        }

        private void InitializeUpdater() {
            _appUpdateCancellation = new CancellationTokenSource();
            _appUpdateService = new AppUpdateService(_versionProvider, new StoreUpdateClient(_versionProvider.IsPackaged()), IsUpdateInstallBusy);
            _appUpdateService.SnapshotChanged += OnUpdateSnapshotChanged;
            ApplyUpdateSnapshot(_appUpdateService.Snapshot);
            _ = _appUpdateService.StartAsync(_appUpdateCancellation.Token);
        }

        private bool IsUpdateInstallBusy() {
            return _isScanning || _isStartingStreams || IsAnyStreamRunning() || _isSettingsDialogOpen;
        }

        private void OnUpdateSnapshotChanged(AppUpdateSnapshot snapshot) {
            try {
                Dispatcher.Invoke(() => ApplyUpdateSnapshot(snapshot));
            }
            catch (Exception ex) {
                JsonLogStore.Error("updater_ui_dispatch_failed", "Failed to dispatch updater snapshot to UI thread.", "updater", ex);
            }
        }

        private void ApplyUpdateSnapshot(AppUpdateSnapshot snapshot) {
            FooterVersionText.Text = $"v{snapshot.InstalledVersion}";

            var showUpdatePanel = snapshot.State is AppUpdateState.Downloading or AppUpdateState.Installing or AppUpdateState.Completed or AppUpdateState.Deferred or AppUpdateState.Failed or AppUpdateState.Checking;
            FooterDefaultPanel.Visibility = showUpdatePanel ? Visibility.Collapsed : Visibility.Visible;
            FooterUpdatePanel.Visibility = showUpdatePanel ? Visibility.Visible : Visibility.Collapsed;

            UpdateStatusText.Text = snapshot.IsMandatoryUpdateAvailable
                ? $"{snapshot.StageText}: {snapshot.StatusMessage} (mandatory)"
                : $"{snapshot.StageText}: {snapshot.StatusMessage}";

            UpdateProgressBar.Visibility = snapshot.IsProgressVisible ? Visibility.Visible : Visibility.Collapsed;
            UpdateProgressBar.Value = Math.Clamp(snapshot.ProgressValue, 0, 1);
            RestartForUpdateButton.Visibility = snapshot.State == AppUpdateState.Completed ? Visibility.Visible : Visibility.Collapsed;
        }

        private void RestartForUpdateButton_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;

            try {
                var executablePath = Environment.ProcessPath;
                if (!string.IsNullOrWhiteSpace(executablePath)) {
                    Process.Start(new ProcessStartInfo {
                        FileName = executablePath,
                        UseShellExecute = true
                    });
                }
            }
            catch (Exception ex) {
                JsonLogStore.Error("updater_restart_failed", "Failed to launch restart after update installation.", "updater", ex);
            }

            Close();
        }

        private void UpdateActionButtons() {
            var anyPlaying = IsAnyStreamRunning();
            var anyNotPlaying = HasAnyStoppedDetectedCamera();

            DetectCameraButton.IsEnabled = !_isScanning;
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
                _scanCancellation = new CancellationTokenSource();
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
                : "Searching local network for TAPO cameras...";
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

            StreamingStatusText.Text = "No TAPO camera detected. Retry search?";
        }

        private void DetectCameraButton_Click(object sender, RoutedEventArgs e) {
            _ = StartLocalCameraSearchAsync();
        }

        private void ToolbarStartStreamsButton_Click(object sender, RoutedEventArgs e) {
            StartAllStreams();
        }

        private void ToolbarStopButton_Click(object sender, RoutedEventArgs e) {
            StopAllStreams();
            StreamingStatusText.Text = "Streams stopped.";
            UpdateActionButtons();
        }

        private void SettingsButton_Click(object sender, RoutedEventArgs e) {
            var dialog = new SettingsWindow(_settings) {
                Owner = this
            };

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

        private void AutoStreamVideoCheckBox_Changed(object sender, RoutedEventArgs e) {
            _settings.AutoStreamVideo = AutoStreamVideoCheckBox.IsChecked == true;
            SettingsStore.Save(_settings);
            TryAutoStartStreams();
        }

        private void StartAllStreams() {
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

            if (!HasCompleteStreamingSettings(username, password)) {
                JsonLogStore.Warning(
                    eventName: "camera_connect_blocked",
                    message: "RTSP stream start was blocked because credentials are incomplete.",
                    category: "camera_connect",
                    data: new Dictionary<string, object?> {
                        ["cameraCount"] = _detections.Count,
                        ["streamPath"] = streamPath
                    });
                StreamingStatusText.Text = BuildMissingSettingsPrompt();
                return;
            }

            JsonLogStore.Information(
                eventName: "camera_connect_requested",
                message: "Starting RTSP connections for detected cameras.",
                category: "camera_connect",
                data: new Dictionary<string, object?> {
                    ["cameraCount"] = _detections.Count,
                    ["streamPath"] = streamPath,
                    ["hasUsername"] = !string.IsNullOrWhiteSpace(username)
                });

            _isStartingStreams = true;
            UpdateActionButtons();

            var startedCount = 0;
            var failedEndpoints = new List<string>();

            EnsureCameraTileCount(_detections.Count);
            for (var i = 0; i < _cameraTiles.Count && i < _detections.Count; i++) {
                if (IsStreamRunning(i)) {
                    continue;
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

                    using var media = new Media(_libVlc, streamUrl, FromType.FromLocation);
                    media.AddOption(":network-caching=300");
                    media.AddOption(":live-caching=300");
                    media.AddOption(":clock-jitter=0");
                    media.AddOption(":clock-synchro=0");

                    if (mediaPlayer.Play(media)) {
                        startedCount++;
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
                        failedEndpoints.Add(ipAddress);
                        SetVideoSurfaceActive(i, isActive: false);
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
                    failedEndpoints.Add(ipAddress);
                    SetVideoSurfaceActive(i, isActive: false);
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

            _isStartingStreams = false;
            _streamsRunning = startedCount > 0 || IsAnyStreamRunning();
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

            if (!HasCompleteStreamingSettings(_settings.RtspUsername.Trim(), _settings.RtspPassword)) {
                return;
            }

            StartAllStreams();
        }

        private void StopAllStreams() {
            _isStartingStreams = false;
            _expandedCameraIndex = null;
            for (var i = 0; i < _cameraTiles.Count; i++) {
                var mediaPlayer = _cameraTiles[i].MediaPlayer;
                if (mediaPlayer is null) {
                    continue;
                }

                if (mediaPlayer.IsPlaying) {
                    mediaPlayer.Stop();
                }

                SetVideoSurfaceActive(i, isActive: false);
            }

            _streamsRunning = false;
            ApplyResponsiveCameraLayout();
            UpdateActionButtons();
        }

        private bool StartSingleStream(int tileIndex) {
            if (_libVlc is null || tileIndex < 0 || tileIndex >= _cameraTiles.Count || tileIndex >= _detections.Count) {
                return false;
            }

            var username = _settings.RtspUsername.Trim();
            var password = _settings.RtspPassword;
            if (!HasCompleteStreamingSettings(username, password)) {
                StreamingStatusText.Text = BuildMissingSettingsPrompt();
                return false;
            }

            var streamPath = NormalizeStreamPath(_settings.StreamPath);
            var ipAddress = _detections[tileIndex].IpAddress.ToString();
            var mediaPlayer = _cameraTiles[tileIndex].MediaPlayer;
            if (mediaPlayer is null) {
                return false;
            }

            try {
                using var media = new Media(_libVlc, BuildRtspUrl(ipAddress, username, password, streamPath), FromType.FromLocation);
                media.AddOption(":network-caching=300");
                media.AddOption(":live-caching=300");
                media.AddOption(":clock-jitter=0");
                media.AddOption(":clock-synchro=0");

                if (mediaPlayer.Play(media)) {
                    SetVideoSurfaceActive(tileIndex, isActive: true);
                    StreamingStatusText.Text = $"Started camera {tileIndex + 1}.";
                    return true;
                }
            }
            catch (Exception ex) {
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
            StreamingStatusText.Text = $"Failed to start camera {tileIndex + 1}.";
            return false;
        }

        private void StopSingleStream(int tileIndex) {
            if (tileIndex < 0 || tileIndex >= _cameraTiles.Count) {
                return;
            }

            var mediaPlayer = _cameraTiles[tileIndex].MediaPlayer;
            if (mediaPlayer is not null && mediaPlayer.IsPlaying) {
                mediaPlayer.Stop();
            }

            SetVideoSurfaceActive(tileIndex, isActive: false);
            StreamingStatusText.Text = $"Stopped camera {tileIndex + 1}.";
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
                if (!IsStreamRunning(i)) {
                    return true;
                }
            }

            return false;
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

        private bool IsAnyStreamRunning() {
            for (var i = 0; i < _cameraTiles.Count; i++) {
                var mediaPlayer = _cameraTiles[i].MediaPlayer;
                if (mediaPlayer is not null && mediaPlayer.IsPlaying) {
                    return true;
                }
            }

            return false;
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

            _libVlc?.Dispose();
            _libVlc = null;
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
                return "No TAPO camera detected. Retry search?";
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
            SettingsStore.Save(_settings);
            JsonLogStore.Information(
                eventName: "camera_search_preferred_method_saved",
                message: "Saved the successful camera detection method to settings.",
                category: "camera_search",
                data: new Dictionary<string, object?> {
                    ["previousMethod"] = previousValue,
                    ["successfulMethod"] = persistedValue
                });
        }

        private static string BuildNoDetectionsMessage(IReadOnlyList<TapoDetectionMethodAttempt> attemptedMethods) {
            if (attemptedMethods.Count == 0) {
                return "No TAPO camera detected.";
            }

            var attemptedNames = attemptedMethods
                .Select(static attempt => GetDetectionMethodDisplayName(attempt.Method))
                .ToArray();
            return $"No TAPO camera detected. Tried: {string.Join(", ", attemptedNames)}.";
        }

        private static string GetDetectionMethodDisplayName(TapoDetectionMethod method) {
            return method switch {
                TapoDetectionMethod.OnvifWsDiscovery => "ONVIF",
                TapoDetectionMethod.SsdpUpnpSearch => "SSDP",
                TapoDetectionMethod.TapoUdpBroadcast => "Tapo UDP",
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

            var source = HwndSource.FromHwnd(handle);
            source?.AddHook(WndProc);
            InstallMouseHook();
        }

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
            _scanCancellation?.Cancel();
            _appUpdateCancellation?.Cancel();
            if (_appUpdateService is not null) {
                _appUpdateService.SnapshotChanged -= OnUpdateSnapshotChanged;
            }
            ShutdownStreamingEngine();

            base.OnClosed(e);
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e) {
            _isClosing = true;
            _scanCancellation?.Cancel();
            PersistWindowBounds();
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
