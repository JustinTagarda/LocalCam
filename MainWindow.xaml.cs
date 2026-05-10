using System.Windows;
using System.Windows.Input;
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
        private LocalCamSettings _settings = new();

        public MainWindow()
            : this(Array.Empty<TapoCameraDetection>()) {
        }

        public MainWindow(IReadOnlyList<TapoCameraDetection> detections) {
            _detections = detections.Take(4).ToArray();

            InitializeComponent();
            UpdateMaximizeButtonIcon();
            FooterVersionText.Text = $"v{GetStoreSubmissionVersion()}";
            PopulateCameraTiles(_detections);
            LoadSettings();
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
                StreamPath = "stream1"
            };
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
            }
        }

        private void Window_Loaded(object sender, RoutedEventArgs e) {
            _ = StartLocalCameraSearchAsync();
        }

        private static string GetStoreSubmissionVersion() {
            return Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0.0";
        }

        private void UpdateActionButtons(bool canDetect, bool canStart, bool canStop) {
            DetectCameraButton.IsEnabled = canDetect;
            ToolbarStartStreamsButton.IsEnabled = canStart;
            ToolbarStopButton.IsEnabled = canStop;
        }

        private async Task StartLocalCameraSearchAsync() {
            if (_isClosing || _isScanning) {
                return;
            }

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
                        ShowDetections(detections);
                        return;
                    }

                    ShowNoDetections();
                }
                catch (OperationCanceledException) when (_isClosing) {
                    return;
                }
                catch (OperationCanceledException) {
                    if (!_isClosing) {
                        ShowNoDetections("Scan canceled.");
                    }
                }
                catch (Exception ex) {
                    if (!_isClosing) {
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
            UpdateActionButtons(canDetect: false, canStart: false, canStop: false);
            SearchProgressBar.Visibility = Visibility.Visible;
        }

        private void ShowEmptyCameraSlots() {
            StreamingStatusText.Text = "Search local camera to populate the empty camera cards.";
            CameraTilesPanel.Visibility = Visibility.Collapsed;
            UpdateActionButtons(canDetect: true, canStart: false, canStop: false);
            SearchProgressBar.Visibility = Visibility.Collapsed;
        }

        private void ShowDetections(IReadOnlyList<TapoCameraDetection> detections) {
            _detections = detections.Take(4).ToArray();
            CameraTilesPanel.Visibility = Visibility.Visible;
            PopulateCameraTiles(_detections);
            StreamingStatusText.Text = BuildDetectionsStatusText(_detections.Count);
            UpdateActionButtons(canDetect: true, canStart: _libVlc is not null && _detections.Count > 0, canStop: _streamsRunning);
            SearchProgressBar.Visibility = Visibility.Collapsed;
        }

        private void ShowNoDetections(string? prefixMessage = null) {
            CameraTilesPanel.Visibility = Visibility.Collapsed;
            UpdateActionButtons(canDetect: true, canStart: false, canStop: false);
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
            UpdateActionButtons(canDetect: !_isScanning, canStart: _libVlc is not null && _detections.Count > 0, canStop: false);
        }

        private void SettingsButton_Click(object sender, RoutedEventArgs e) {
            var dialog = new SettingsWindow(_settings) {
                Owner = this
            };

            if (dialog.ShowDialog() == true) {
                _settings = dialog.Settings;
                SettingsStore.Save(_settings);
            }
        }

        private void StartStreams() {
            if (_libVlc is null) {
                StreamingStatusText.Text = "Cannot start streams: video engine is unavailable.";
                return;
            }

            if (_detections.Count == 0) {
                StreamingStatusText.Text = "Cannot start streams: no cameras were detected.";
                return;
            }

            var username = _settings.RtspUsername.Trim();
            var password = _settings.RtspPassword;
            var streamPath = NormalizeStreamPath(_settings.StreamPath);

            if (!HasCompleteStreamingSettings(username, password)) {
                StreamingStatusText.Text = BuildMissingSettingsPrompt();
                return;
            }

            StopStreams();
            UpdateActionButtons(canDetect: !_isScanning, canStart: false, canStop: false);

            var startedCount = 0;
            var failedEndpoints = new List<string>();

            for (var i = 0; i < _mediaPlayers.Length && i < _detections.Count; i++) {
                var ipAddress = _detections[i].IpAddress.ToString();
                var streamUrl = BuildRtspUrl(ipAddress, username, password, streamPath);

                try {
                    using var media = new Media(_libVlc, streamUrl, FromType.FromLocation);
                    media.AddOption(":network-caching=300");
                    media.AddOption(":live-caching=300");
                    media.AddOption(":clock-jitter=0");
                    media.AddOption(":clock-synchro=0");

                    if (_mediaPlayers[i].Play(media)) {
                        startedCount++;
                    }
                    else {
                        failedEndpoints.Add(ipAddress);
                    }
                }
                catch {
                    failedEndpoints.Add(ipAddress);
                }
            }

            _streamsRunning = startedCount > 0;

            if (failedEndpoints.Count == 0) {
                StreamingStatusText.Text = $"Streaming started for {startedCount} {Pluralize(startedCount, "camera")}.";
                UpdateActionButtons(canDetect: !_isScanning, canStart: true, canStop: true);
                return;
            }

            StreamingStatusText.Text =
                $"Started {startedCount} {Pluralize(startedCount, "stream")}. Failed to start: {string.Join(", ", failedEndpoints)}.";
            UpdateActionButtons(canDetect: !_isScanning, canStart: _libVlc is not null && _detections.Count > 0, canStop: startedCount > 0);
        }

        private void StopStreams() {
            foreach (var mediaPlayer in _mediaPlayers) {
                if (mediaPlayer is null) {
                    continue;
                }

                if (mediaPlayer.IsPlaying) {
                    mediaPlayer.Stop();
                }
            }

            _streamsRunning = false;
            UpdateActionButtons(canDetect: !_isScanning, canStart: _libVlc is not null && _detections.Count > 0, canStop: false);
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
            base.OnClosing(e);
        }
    }
}
