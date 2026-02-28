using System.Windows;
using System.Windows.Input;
using LibVLCSharp.Shared;
using LibVLCSharp.WPF;
using LocalCam.Networking;
using Geometry = System.Windows.Media.Geometry;
using VlcMediaPlayer = LibVLCSharp.Shared.MediaPlayer;

namespace LocalCam {
    public partial class MainWindow : Window {
        private static readonly Geometry MaximizeGeometry = Geometry.Parse("M2,2 L12,2 12,12 2,12 Z");
        private static readonly Geometry RestoreGeometry = Geometry.Parse("M4,2 L12,2 12,10 M4,2 L4,10 12,10 M2,4 L10,4 10,12 2,12 Z");

        private readonly IReadOnlyList<TapoCameraDetection> _detections;
        private readonly VlcMediaPlayer[] _mediaPlayers = new VlcMediaPlayer[4];
        private LibVLC? _libVlc;
        private bool _streamsRunning;

        public MainWindow()
            : this(Array.Empty<TapoCameraDetection>()) {
        }

        public MainWindow(IReadOnlyList<TapoCameraDetection> detections) {
            _detections = detections.Take(4).ToArray();

            InitializeComponent();
            UpdateMaximizeButtonIcon();
            PopulateCameraTiles(_detections);
            ApplyDefaultCredentials();
            InitializeStreamingEngine();
        }

        private void InitializeStreamingEngine() {
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

                if (_detections.Count > 0) {
                    StreamingStatusText.Text =
                        $"Detected {_detections.Count} camera(s). Enter RTSP credentials and click 'Start Streams'.";
                }
                else {
                    StreamingStatusText.Text =
                        "No cameras detected for streaming. Return to startup scan or run scan again.";
                }
            }
            catch (Exception ex) {
                StreamingStatusText.Text = $"Video engine initialization failed: {ex.Message}";
            }
        }

        private void ApplyDefaultCredentials() {
            var defaultUser = Environment.GetEnvironmentVariable("LOCALCAM_RTSP_USERNAME");
            var defaultPassword = Environment.GetEnvironmentVariable("LOCALCAM_RTSP_PASSWORD");

            if (!string.IsNullOrWhiteSpace(defaultUser)) {
                RtspUsernameTextBox.Text = defaultUser;
            }

            if (!string.IsNullOrWhiteSpace(defaultPassword)) {
                RtspPasswordBox.Password = defaultPassword;
            }
        }

        private void PopulateCameraTiles(IReadOnlyList<TapoCameraDetection> detections) {
            var tileLabels = new[] { CameraTile1Label, CameraTile2Label, CameraTile3Label, CameraTile4Label };

            for (var i = 0; i < tileLabels.Length; i++) {
                var label = tileLabels[i];
                if (i < detections.Count) {
                    label.Text = $"camera {i + 1} - live streaming ({detections[i].IpAddress})";
                }
                else {
                    label.Text = $"camera {i + 1} - no detected camera";
                }
            }
        }

        private void StartStreamsButton_Click(object sender, RoutedEventArgs e) {
            StartStreams();
        }

        private void StopStreamsButton_Click(object sender, RoutedEventArgs e) {
            StopStreams();
            StreamingStatusText.Text = "Streams stopped.";
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

            var username = RtspUsernameTextBox.Text.Trim();
            var password = RtspPasswordBox.Password;
            var streamPath = NormalizeStreamPath(StreamPathTextBox.Text);

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password)) {
                StreamingStatusText.Text = "Enter RTSP username and password before starting streams.";
                return;
            }

            StopStreams();

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
                StreamingStatusText.Text = $"Streaming started for {startedCount} camera(s).";
                return;
            }

            StreamingStatusText.Text =
                $"Started {startedCount} stream(s). Failed to start: {string.Join(", ", failedEndpoints)}.";
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
        }

        private static string NormalizeStreamPath(string? input) {
            var normalized = (input ?? string.Empty).Trim().TrimStart('/');
            return string.IsNullOrWhiteSpace(normalized)
                ? "stream1"
                : normalized;
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
            StopStreams();

            foreach (var mediaPlayer in _mediaPlayers) {
                mediaPlayer?.Dispose();
            }

            _libVlc?.Dispose();
            _libVlc = null;

            base.OnClosed(e);
        }
    }
}
