using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using LocalCam.Networking;

namespace LocalCam {
    public partial class StartupWindow : Window {
        private CancellationTokenSource? _scanCancellation;
        private bool _isScanning;
        private bool _isClosing;
        private IReadOnlyList<TapoCameraDetection> _detectedCameras = Array.Empty<TapoCameraDetection>();

        public StartupWindow() {
            InitializeComponent();
        }

        public IReadOnlyList<TapoCameraDetection> DetectedCameras => _detectedCameras;

        private async void Window_Loaded(object sender, RoutedEventArgs e) {
            await StartScanAsync();
        }

        private async void ScanAgainButton_Click(object sender, RoutedEventArgs e) {
            await StartScanAsync();
        }

        private void ExitButton_Click(object sender, RoutedEventArgs e) {
            CloseWithResult(false);
        }

        private void StartupCloseButton_Click(object sender, RoutedEventArgs e) {
            CloseWithResult(false);
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e) {
            if (e.ButtonState == MouseButtonState.Pressed) {
                DragMove();
            }
        }

        protected override void OnClosing(CancelEventArgs e) {
            _isClosing = true;
            _scanCancellation?.Cancel();
            base.OnClosing(e);
        }

        private async Task StartScanAsync() {
            if (_isScanning || _isClosing) {
                return;
            }

            _isScanning = true;
            _scanCancellation = new CancellationTokenSource();
            SetScanningState("Scanning network for TAPO cameras... please wait.");

            try {
                var detections = await TapoCameraScanner.ScanLocalNetworkForTapoCamerasAsync(
                    cancellationToken: _scanCancellation.Token);

                if (_isClosing) {
                    return;
                }

                if (detections.Count > 0) {
                    _detectedCameras = detections;
                    CloseWithResult(true);
                    return;
                }

                SetNoCameraState("No TAPO camera detected.");
            }
            catch (OperationCanceledException) when (_isClosing) {
                // Closing the window cancels active scan.
            }
            catch (OperationCanceledException) {
                SetNoCameraState("Scan canceled.");
            }
            catch (Exception ex) {
                SetNoCameraState($"Scan failed: {ex.Message}");
            }
            finally {
                _scanCancellation?.Dispose();
                _scanCancellation = null;
                _isScanning = false;
            }
        }

        private void SetScanningState(string message) {
            StatusText.Text = message;
            ScanProgress.Visibility = Visibility.Visible;
            ScanProgress.IsIndeterminate = true;
            ScanAgainButton.IsEnabled = false;
            ExitButton.IsEnabled = true;
        }

        private void SetNoCameraState(string message) {
            StatusText.Text = $"{message} Click 'Scan again' to retry or 'Exit' to close.";
            ScanProgress.Visibility = Visibility.Visible;
            ScanProgress.IsIndeterminate = false;
            ScanProgress.Value = 100;
            ScanAgainButton.IsEnabled = true;
            ExitButton.IsEnabled = true;
        }

        private void CloseWithResult(bool result) {
            if (_isClosing) {
                return;
            }

            _isClosing = true;
            DialogResult = result;
            Close();
        }
    }
}
