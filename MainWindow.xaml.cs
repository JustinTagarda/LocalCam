using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using LocalCam.Networking;

namespace LocalCam {
    public partial class MainWindow : Window {
        private readonly ObservableCollection<CameraDetectionRow> _cameraRows = [];
        private CancellationTokenSource? _scanCancellation;
        private bool _isScanning;

        public MainWindow()
            : this(null) {
        }

        public MainWindow(IReadOnlyList<TapoCameraDetection>? initialDetections) {
            InitializeComponent();
            CameraDataGrid.ItemsSource = _cameraRows;

            if (initialDetections is { Count: > 0 }) {
                ApplyDetections(initialDetections);
                StatusText.Text = $"Startup scan detected {initialDetections.Count} likely Tapo camera(s).";
            }
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e) {
            if (_isScanning) {
                return;
            }

            _isScanning = true;
            _scanCancellation = new CancellationTokenSource();
            SetScanUiState(isScanning: true);
            StatusText.Text = "Scanning local network for Tapo cameras...";
            var startedAt = DateTime.UtcNow;

            try {
                var detections = await TapoCameraScanner.ScanLocalNetworkForTapoCamerasAsync(
                    cancellationToken: _scanCancellation.Token);

                ApplyDetections(detections);

                var elapsed = DateTime.UtcNow - startedAt;
                StatusText.Text = detections.Count == 0
                    ? $"Scan completed in {elapsed.TotalSeconds:0.0}s. No likely Tapo cameras were detected. Check same subnet and enable RTSP/ONVIF in the Tapo app."
                    : $"Scan completed in {elapsed.TotalSeconds:0.0}s. Detected {detections.Count} likely Tapo camera(s).";
            }
            catch (OperationCanceledException) {
                StatusText.Text = "Scan canceled.";
            }
            catch (Exception ex) {
                StatusText.Text = $"Scan failed: {ex.Message}";
            }
            finally {
                _scanCancellation?.Dispose();
                _scanCancellation = null;
                _isScanning = false;
                SetScanUiState(isScanning: false);
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e) {
            _scanCancellation?.Cancel();
        }

        protected override void OnClosed(EventArgs e) {
            _scanCancellation?.Cancel();
            _scanCancellation?.Dispose();
            _scanCancellation = null;
            base.OnClosed(e);
        }

        private void SetScanUiState(bool isScanning) {
            ScanButton.IsEnabled = !isScanning;
            CancelButton.IsEnabled = isScanning;
            ScanProgress.Visibility = isScanning ? Visibility.Visible : Visibility.Collapsed;
        }

        private void ApplyDetections(IEnumerable<TapoCameraDetection> detections) {
            _cameraRows.Clear();

            foreach (var detection in detections.OrderByDescending(static d => d.ConfidenceScore)) {
                _cameraRows.Add(CameraDetectionRow.FromDetection(detection));
            }
        }

        private sealed record CameraDetectionRow(
            string IpAddress,
            string HostName,
            string MacAddress,
            string OpenPorts,
            string Confidence,
            string DetectionReason) {

            public static CameraDetectionRow FromDetection(TapoCameraDetection detection) {
                var hostName = string.IsNullOrWhiteSpace(detection.HostName) ? "-" : detection.HostName;
                var macAddress = string.IsNullOrWhiteSpace(detection.MacAddress) ? "-" : detection.MacAddress;
                var openPorts = detection.OpenPorts.Count == 0 ? "-" : string.Join(", ", detection.OpenPorts);

                return new CameraDetectionRow(
                    detection.IpAddress.ToString(),
                    hostName,
                    macAddress,
                    openPorts,
                    detection.ConfidenceScore.ToString("0.00"),
                    detection.DetectionReason);
            }
        }
    }
}
