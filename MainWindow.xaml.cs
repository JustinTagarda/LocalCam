using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using LibVLCSharp.Shared;
using LibVLCSharp.WPF;
using LocalCam.Networking;
using LocalCam.Models;
using LocalCam.Services;
using System.Reflection;
using Geometry = System.Windows.Media.Geometry;
using VlcMediaPlayer = LibVLCSharp.Shared.MediaPlayer;

namespace LocalCam {
    public partial class MainWindow : Window {
        private static readonly Geometry MaximizeGeometry = Geometry.Parse("M2,2 L12,2 12,12 2,12 Z");
        private static readonly Geometry RestoreGeometry = Geometry.Parse("M4,2 L12,2 12,10 M4,2 L4,10 12,10 M2,4 L10,4 10,12 2,12 Z");

        private IReadOnlyList<TapoCameraDetection> _detections = Array.Empty<TapoCameraDetection>();
        private readonly VlcMediaPlayer[] _mediaPlayers = new VlcMediaPlayer[4];
        private LibVLC? _libVlc;
        private CancellationTokenSource? _scanCancellation;
        private bool _isClosing;
        private bool _isScanning;
        private bool _streamsRunning;
        private bool _isStartingStreams;
        private bool _isApplyingPersistedWindowBounds;
        private bool _hasAppliedPersistedWindowBounds;
        private double _activeCardAspectRatio = 16d / 9d;
        private readonly DispatcherTimer _videoAspectProbeTimer;
        private LocalCamSettings _settings = new();

        public MainWindow()
            : this(Array.Empty<TapoCameraDetection>()) {
        }

        public MainWindow(IReadOnlyList<TapoCameraDetection> detections) {
            _detections = detections.Take(4).ToArray();

            InitializeComponent();
            LocationChanged += Window_LocationChanged;
            SizeChanged += Window_SizeChanged;
            FooterVersionText.Text = $"v{GetStoreSubmissionVersion()}";
            LoadSettings();
            ApplyPersistedWindowBounds();
            UpdateMaximizeButtonIcon();
            PopulateCameraTiles(_detections);
            CameraTilesPanel.SizeChanged += CameraTilesPanel_SizeChanged;
            _videoAspectProbeTimer = new DispatcherTimer {
                Interval = TimeSpan.FromMilliseconds(400)
            };
            _videoAspectProbeTimer.Tick += VideoAspectProbeTimer_Tick;
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

                var views = new[] { VideoView1, VideoView2, VideoView3, VideoView4 };
                for (var i = 0; i < views.Length; i++) {
                    var mediaPlayer = new VlcMediaPlayer(_libVlc) {
                        EnableHardwareDecoding = true,
                        Mute = true
                    };

                    _mediaPlayers[i] = mediaPlayer;
                    views[i].MediaPlayer = mediaPlayer;
                }

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
            var cards = new[] { CameraCard1, CameraCard2, CameraCard3, CameraCard4 };
            var tileLabels = new[] { CameraTile1Label, CameraTile2Label, CameraTile3Label, CameraTile4Label };

            for (var i = 0; i < cards.Length; i++) {
                var hasDetection = i < detections.Count;
                cards[i].Visibility = hasDetection ? Visibility.Visible : Visibility.Collapsed;
                tileLabels[i].Text = hasDetection
                    ? $"camera {i + 1} - live streaming ({detections[i].IpAddress})"
                    : string.Empty;
                SetVideoSurfaceActive(i, isActive: false);
            }

            ApplyAspectLockedCameraCardLayout();
        }

        private void SetVideoSurfaceActive(int index, bool isActive) {
            var videoViews = new[] { VideoView1, VideoView2, VideoView3, VideoView4 };
            var placeholders = new[] { CameraPlaceholder1, CameraPlaceholder2, CameraPlaceholder3, CameraPlaceholder4 };
            var badges = new[] { CameraBadge1, CameraBadge2, CameraBadge3, CameraBadge4 };

            if (index < 0 || index >= videoViews.Length) {
                return;
            }

            videoViews[index].Visibility = isActive ? Visibility.Visible : Visibility.Collapsed;
            placeholders[index].Visibility = isActive ? Visibility.Collapsed : Visibility.Visible;
            badges[index].Visibility = isActive ? Visibility.Collapsed : Visibility.Visible;
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
                SetScanningState();

                try {
                    var detections = await TapoCameraScanner.ScanLocalNetworkForTapoCamerasAsync(
                        cancellationToken: _scanCancellation.Token);

                    if (_isClosing) {
                        return;
                    }

                    if (detections.Count > 0) {
                        JsonLogStore.Information(
                            eventName: "camera_search_detections_available",
                            message: "Local network scan found one or more likely Tapo cameras.",
                            category: "camera_search",
                            data: new Dictionary<string, object?> {
                                ["detectionCount"] = detections.Count,
                                ["detectedIps"] = detections.Select(d => d.IpAddress.ToString()).ToArray()
                            });
                        ShowDetections(detections);
                        return;
                    }

                    JsonLogStore.Warning(
                        eventName: "camera_search_no_detections",
                        message: "Local network scan completed without any likely Tapo cameras.",
                        category: "camera_search");
                    ShowNoDetections();
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

        private void SetScanningState() {
            StreamingStatusText.Text = "Searching local network for TAPO cameras...";
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

        private void ShowDetections(IReadOnlyList<TapoCameraDetection> detections) {
            _detections = detections.Take(4).ToArray();
            CameraTilesPanel.Visibility = Visibility.Visible;
            PopulateCameraTiles(_detections);
            StreamingStatusText.Text = BuildDetectionsStatusText(_detections.Count);
            UpdateActionButtons();
            SearchProgressBar.Visibility = Visibility.Collapsed;
            ApplyAspectLockedCameraCardLayout();
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

            for (var i = 0; i < _mediaPlayers.Length && i < _detections.Count; i++) {
                var ipAddress = _detections[i].IpAddress.ToString();
                var streamUrl = BuildRtspUrl(ipAddress, username, password, streamPath);

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

                    if (_mediaPlayers[i].Play(media)) {
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
            if (_streamsRunning) {
                _videoAspectProbeTimer.Start();
            }
            else {
                _videoAspectProbeTimer.Stop();
                _activeCardAspectRatio = 16d / 9d;
                ApplyAspectLockedCameraCardLayout();
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
            _videoAspectProbeTimer.Stop();
            _isStartingStreams = false;
            for (var i = 0; i < _mediaPlayers.Length; i++) {
                var mediaPlayer = _mediaPlayers[i];
                if (mediaPlayer is null) {
                    continue;
                }

                if (mediaPlayer.IsPlaying) {
                    mediaPlayer.Stop();
                }

                SetVideoSurfaceActive(i, isActive: false);
            }

            _streamsRunning = false;
            _activeCardAspectRatio = 16d / 9d;
            ApplyAspectLockedCameraCardLayout();
            UpdateActionButtons();
        }

        private bool IsAnyStreamRunning() {
            for (var i = 0; i < _mediaPlayers.Length; i++) {
                var mediaPlayer = _mediaPlayers[i];
                if (mediaPlayer is not null && mediaPlayer.IsPlaying) {
                    return true;
                }
            }

            return false;
        }

        private void ShutdownStreamingEngine() {
            StopStreams();

            VideoView1.MediaPlayer = null;
            VideoView2.MediaPlayer = null;
            VideoView3.MediaPlayer = null;
            VideoView4.MediaPlayer = null;

            foreach (var mediaPlayer in _mediaPlayers) {
                mediaPlayer?.Dispose();
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

        private string BuildDetectionsStatusText(int cameraCount) {
            if (cameraCount <= 0) {
                return "No TAPO camera detected. Retry search?";
            }

            return HasCompleteStreamingSettings(_settings.RtspUsername.Trim(), _settings.RtspPassword)
                ? $"Detected {cameraCount} {Pluralize(cameraCount, "camera")}. Click 'Start Streams'."
                : $"Detected {cameraCount} {Pluralize(cameraCount, "camera")}. Open Settings and provide the RTSP username, password, and stream path.";
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
            ApplyAspectLockedCameraCardLayout();
        }

        private void CameraTilesPanel_SizeChanged(object sender, SizeChangedEventArgs e) {
            _ = sender;
            _ = e;
            ApplyAspectLockedCameraCardLayout();
        }

        private void VideoAspectProbeTimer_Tick(object? sender, EventArgs e) {
            _ = sender;

            if (!_streamsRunning || _isClosing) {
                _videoAspectProbeTimer.Stop();
                return;
            }

            var updated = TryRefreshActiveCardAspectRatioFromPlayers();
            if (updated) {
                ApplyAspectLockedCameraCardLayout();
            }
        }

        private bool TryRefreshActiveCardAspectRatioFromPlayers() {
            const double epsilon = 0.0001;

            for (var i = 0; i < _mediaPlayers.Length; i++) {
                var mediaPlayer = _mediaPlayers[i];
                if (mediaPlayer is null || !mediaPlayer.IsPlaying) {
                    continue;
                }

                if (!TryGetVideoAspectRatio(mediaPlayer, out var ratio)) {
                    continue;
                }

                if (Math.Abs(_activeCardAspectRatio - ratio) <= epsilon) {
                    return false;
                }

                _activeCardAspectRatio = ratio;
                return true;
            }

            return false;
        }

        private static bool TryGetVideoAspectRatio(VlcMediaPlayer mediaPlayer, out double ratio) {
            ratio = 0d;

            try {
                uint width = 0;
                uint height = 0;
                mediaPlayer.Size(0, ref width, ref height);
                if (width == 0 || height == 0) {
                    return false;
                }

                ratio = width / (double)height;
                return ratio > 0d;
            }
            catch {
                return false;
            }
        }

        private void ApplyAspectLockedCameraCardLayout() {
            var cards = new[] { CameraCard1, CameraCard2, CameraCard3, CameraCard4 };
            var visibleCards = cards.Where(card => card.Visibility == Visibility.Visible).ToArray();
            if (visibleCards.Length == 0 || CameraTilesPanel.ActualWidth <= 0 || CameraTilesPanel.ActualHeight <= 0) {
                return;
            }

            var columns = visibleCards.Length <= 1 ? 1 : 2;
            var rows = visibleCards.Length <= 2 ? 1 : 2;
            var horizontalGap = columns == 2 ? 12d : 0d;
            var verticalGap = rows == 2 ? 12d : 0d;

            var cellWidth = Math.Max(0d, (CameraTilesPanel.ActualWidth - horizontalGap) / columns);
            var cellHeight = Math.Max(0d, (CameraTilesPanel.ActualHeight - verticalGap) / rows);
            if (cellWidth <= 0 || cellHeight <= 0) {
                return;
            }

            var ratio = _activeCardAspectRatio > 0d ? _activeCardAspectRatio : 16d / 9d;
            var widthFromHeight = cellHeight * ratio;
            var heightFromWidth = cellWidth / ratio;

            var targetWidth = widthFromHeight <= cellWidth ? widthFromHeight : cellWidth;
            var targetHeight = widthFromHeight <= cellWidth ? cellHeight : heightFromWidth;

            foreach (var card in visibleCards) {
                card.Width = targetWidth;
                card.Height = targetHeight;
                card.HorizontalAlignment = HorizontalAlignment.Center;
                card.VerticalAlignment = VerticalAlignment.Center;
            }
        }
    }
}
