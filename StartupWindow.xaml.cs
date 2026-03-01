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

        private sealed record CandidateDiagnosticsRow(
            string IpAddress,
            string Result,
            string Score,
            string OpenPorts,
            string Onvif,
            string TapoUdp,
            string TapoUnicast,
            string Arp,
            string HostName,
            string MacAddress,
            string Reason);

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
                var scanResult = await TapoCameraScanner.ScanLocalNetworkForTapoCamerasWithDiagnosticsAsync(
                    cancellationToken: _scanCancellation.Token);
                var detections = scanResult.Detections;
                ApplyDiagnostics(scanResult.Diagnostics);

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
                ResetDiagnostics("Scan canceled before diagnostics were finalized.");
            }
            catch (Exception ex) {
                SetNoCameraState($"Scan failed: {ex.Message}");
                ResetDiagnostics("Scan failed before diagnostics were finalized.");
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
            ResetDiagnostics("Scan in progress...");
        }

        private void SetNoCameraState(string message) {
            StatusText.Text = $"{message} Click 'Scan again' to retry or 'Exit' to close.";
            ScanProgress.Visibility = Visibility.Visible;
            ScanProgress.IsIndeterminate = false;
            ScanProgress.Value = 100;
            ScanAgainButton.IsEnabled = true;
            ExitButton.IsEnabled = true;
        }

        private void ApplyDiagnostics(TapoScanDiagnostics diagnostics) {
            var likelyCount = diagnostics.Candidates.Count(static c => c.IsLikelyTapo);
            DiagnosticsSummaryText.Text =
                $"Subnets: {diagnostics.SubnetsScanned.Count} | Enumerated hosts: {diagnostics.EnumeratedHostCount} | " +
                $"ARP seeds: {diagnostics.ArpSeedCount} | ONVIF hints: {diagnostics.OnvifHintCount} | " +
                $"Tapo broadcast hints: {diagnostics.TapoBroadcastHintCount} | " +
                $"Tapo unicast hints: {diagnostics.TapoUnicastHintCount} | " +
                $"Responsive hosts: {diagnostics.ResponsiveHostCount} | Likely Tapo: {likelyCount}";

            DiagnosticsSubnetsText.Text = diagnostics.SubnetsScanned.Count == 0
                ? "Scanned subnets: none."
                : $"Scanned subnets: {string.Join(" | ", diagnostics.SubnetsScanned)}";

            DiagnosticsCandidateGrid.ItemsSource = diagnostics.Candidates
                .OrderByDescending(static c => c.IsLikelyTapo)
                .ThenByDescending(static c => c.ConfidenceScore)
                .ThenBy(static c => c.IpAddress.ToString())
                .Select(c => new CandidateDiagnosticsRow(
                    IpAddress: c.IpAddress.ToString(),
                    Result: c.IsLikelyTapo ? "PASS" : "FAIL",
                    Score: c.ConfidenceScore.ToString("0.00"),
                    OpenPorts: c.OpenPorts.Count == 0 ? "-" : string.Join(", ", c.OpenPorts),
                    Onvif: c.DiscoveredViaOnvif ? "Yes" : "No",
                    TapoUdp: c.DiscoveredViaTapoBroadcast ? "Yes" : "No",
                    TapoUnicast: c.DiscoveredViaTapoUnicast ? "Yes" : "No",
                    Arp: c.SeenInArpTable ? "Yes" : "No",
                    HostName: string.IsNullOrWhiteSpace(c.HostName) ? "-" : c.HostName,
                    MacAddress: string.IsNullOrWhiteSpace(c.MacAddress) ? "-" : c.MacAddress,
                    Reason: c.Reason))
                .ToArray();
        }

        private void ResetDiagnostics(string summaryMessage) {
            DiagnosticsSummaryText.Text = summaryMessage;
            DiagnosticsSubnetsText.Text = "Scanned subnets: pending.";
            DiagnosticsCandidateGrid.ItemsSource = Array.Empty<CandidateDiagnosticsRow>();
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
