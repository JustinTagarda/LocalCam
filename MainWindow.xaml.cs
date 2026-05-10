using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using LibVLCSharp.Shared;
using LibVLCSharp.WPF;
using LocalCam.Networking;
using LocalCam.Models;
using LocalCam.Services;
using System.Reflection;
using System.Runtime.InteropServices;
using Geometry = System.Windows.Media.Geometry;
using VlcMediaPlayer = LibVLCSharp.Shared.MediaPlayer;

namespace LocalCam {
    public partial class MainWindow : Window {
        private sealed class CameraTileControls {
            public required Border Card { get; init; }
            public required Border Placeholder { get; init; }
            public required Border Badge { get; init; }
            public required TextBlock Label { get; init; }
            public required VideoView VideoView { get; init; }
            public VlcMediaPlayer? MediaPlayer { get; set; }
        }

        private static readonly Geometry MaximizeGeometry = Geometry.Parse("M2,2 L12,2 12,12 2,12 Z");
        private static readonly Geometry RestoreGeometry = Geometry.Parse("M4,2 L12,2 12,10 M4,2 L4,10 12,10 M2,4 L10,4 10,12 2,12 Z");
        private const int WmGetMinMaxInfo = 0x0024;
        private const uint MonitorDefaultToNearest = 2;

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
        private LocalCamSettings _settings = new();

        public MainWindow()
            : this(Array.Empty<TapoCameraDetection>()) {
        }

        public MainWindow(IReadOnlyList<TapoCameraDetection> detections) {
            _detections = detections.ToArray();

            InitializeComponent();
            SourceInitialized += MainWindow_SourceInitialized;
            LocationChanged += Window_LocationChanged;
            SizeChanged += Window_SizeChanged;
            FooterVersionText.Text = $"v{GetStoreSubmissionVersion()}";
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
            var root = new Grid();

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

            root.Children.Add(placeholder);
            root.Children.Add(videoHost);
            root.Children.Add(badge);
            card.Child = root;

            return new CameraTileControls {
                Card = card,
                Placeholder = placeholder,
                Badge = badge,
                Label = label,
                VideoView = videoView
            };
        }

        private void AttachMediaPlayer(CameraTileControls tile) {
            if (_libVlc is null || tile.MediaPlayer is not null) {
                return;
            }

            var mediaPlayer = new VlcMediaPlayer(_libVlc) {
                EnableHardwareDecoding = true,
                Mute = true
            };

            tile.MediaPlayer = mediaPlayer;
            tile.VideoView.MediaPlayer = mediaPlayer;
        }

        private void SetVideoSurfaceActive(int index, bool isActive) {
            if (index < 0 || index >= _cameraTiles.Count) {
                return;
            }

            var tile = _cameraTiles[index];
            tile.VideoView.Visibility = isActive ? Visibility.Visible : Visibility.Collapsed;
            tile.Placeholder.Visibility = isActive ? Visibility.Collapsed : Visibility.Visible;
            tile.Badge.Visibility = isActive ? Visibility.Collapsed : Visibility.Visible;
        }

        private void Window_Loaded(object sender, RoutedEventArgs e) {
            AutoStreamVideoCheckBox.IsChecked = _settings.AutoStreamVideo;
            _ = StartLocalCameraSearchAsync();
        }

        private static string GetStoreSubmissionVersion() {
            return Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0.0";
        }

        private void UpdateActionButtons() {
            var hasDetections = _detections.Count > 0;
            var hasCompleteSettings = HasCompleteStreamingSettings(_settings.RtspUsername.Trim(), _settings.RtspPassword);
            var hasRunningStream = IsAnyStreamRunning();
            var streamSessionActive = _streamsRunning || _isStartingStreams || hasRunningStream;

            DetectCameraButton.IsEnabled = !_isScanning && !streamSessionActive;
            ToolbarStartStreamsButton.IsEnabled = !_isScanning &&
                                                  !_isStartingStreams &&
                                                  !_streamsRunning &&
                                                  !hasRunningStream &&
                                                  _libVlc is not null &&
                                                  hasDetections &&
                                                  hasCompleteSettings;
            ToolbarStopButton.IsEnabled = !_isScanning && streamSessionActive;
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
            UpdateActionButtons();
            SearchProgressBar.Visibility = Visibility.Visible;
        }

        private void ShowEmptyCameraSlots() {
            StreamingStatusText.Text = "Search local camera to populate the empty camera cards.";
            CameraTilesPanel.Visibility = Visibility.Collapsed;
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
            CameraTilesPanel.Visibility = Visibility.Collapsed;
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
            StartStreams();
        }

        private void ToolbarStopButton_Click(object sender, RoutedEventArgs e) {
            StopStreams();
            StreamingStatusText.Text = "Streams stopped.";
            UpdateActionButtons();
        }

        private void SettingsButton_Click(object sender, RoutedEventArgs e) {
            var dialog = new SettingsWindow(_settings) {
                Owner = this
            };

            if (dialog.ShowDialog() == true) {
                _settings = dialog.Settings;
                SettingsStore.Save(_settings);
                TryAutoStartStreams();
            }
        }

        private void AutoStreamVideoCheckBox_Changed(object sender, RoutedEventArgs e) {
            _settings.AutoStreamVideo = AutoStreamVideoCheckBox.IsChecked == true;
            SettingsStore.Save(_settings);
            TryAutoStartStreams();
        }

        private void StartStreams() {
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

            StopStreams();
            UpdateActionButtons();

            _isStartingStreams = true;
            UpdateActionButtons();

            var startedCount = 0;
            var failedEndpoints = new List<string>();

            EnsureCameraTileCount(_detections.Count);
            for (var i = 0; i < _cameraTiles.Count && i < _detections.Count; i++) {
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
            _streamsRunning = startedCount > 0;
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
            if (_isClosing || _isScanning || _streamsRunning || !_settings.AutoStreamVideo) {
                return;
            }

            if (_libVlc is null || _detections.Count == 0) {
                return;
            }

            if (!HasCompleteStreamingSettings(_settings.RtspUsername.Trim(), _settings.RtspPassword)) {
                return;
            }

            StartStreams();
        }

        private void StopStreams() {
            _isStartingStreams = false;
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
            UpdateActionButtons();
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

        private void ApplyResponsiveCameraLayout() {
            if (CameraTilesPanel is null) {
                return;
            }

            var count = _cameraTiles.Count;
            if (count == 0) {
                CameraTilesPanel.RowDefinitions.Clear();
                CameraTilesPanel.ColumnDefinitions.Clear();
                return;
            }

            var (columns, rows) = CalculateGridDimensions(
                count,
                Math.Max(1, CameraTilesPanel.ActualWidth),
                Math.Max(1, CameraTilesPanel.ActualHeight));

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
                card.Width = double.NaN;
                card.Height = double.NaN;
                card.HorizontalAlignment = HorizontalAlignment.Stretch;
                card.VerticalAlignment = VerticalAlignment.Stretch;
                card.Margin = GetTileMargin(i, columns, rows);
                var row = i / columns;
                var column = i % columns;
                Grid.SetRow(card, row);
                Grid.SetColumn(card, column);
            }
        }

        private static (int Columns, int Rows) CalculateGridDimensions(int count, double width, double height) {
            const double targetAspect = 16d / 9d;
            var bestColumns = 1;
            var bestRows = count;
            var bestScore = double.NegativeInfinity;

            for (var columns = 1; columns <= count; columns++) {
                var rows = (int)Math.Ceiling(count / (double)columns);
                var tileWidth = width / columns;
                var tileHeight = height / rows;
                var tileArea = tileWidth * tileHeight;
                var tileAspect = tileWidth / tileHeight;
                var aspectPenalty = Math.Abs(Math.Log(tileAspect / targetAspect));

                // Prefer larger tiles while keeping them near a 16:9 video aspect.
                var score = tileArea - (aspectPenalty * 20000d);
                if (score > bestScore) {
                    bestScore = score;
                    bestColumns = columns;
                    bestRows = rows;
                }
            }

            return (bestColumns, bestRows);
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
            StopStreams();

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
                ? $"{detectionPrefix} Click 'Start Streams'."
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
            _scanCancellation?.Cancel();
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
