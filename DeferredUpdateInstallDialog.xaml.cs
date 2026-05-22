using System.ComponentModel;
using System.Windows;

namespace LocalCam {
    public partial class DeferredUpdateInstallDialog : Window {
        private const double DownloadPhaseBoundary = 0.8;
        private bool _allowClose;

        public DeferredUpdateInstallDialog() {
            InitializeComponent();
        }

        public void ReportProgress(double progress) {
            var normalized = double.IsNaN(progress) || double.IsInfinity(progress)
                ? 0
                : Math.Clamp(progress, 0, 1);

            InstallProgressBar.IsIndeterminate = false;
            if (normalized < DownloadPhaseBoundary) {
                var downloadProgress = normalized / DownloadPhaseBoundary;
                InstallProgressBar.Value = downloadProgress * 80;
                ProgressTextBlock.Text = $"Downloading update... {Math.Round(downloadProgress * 100)}%";
                return;
            }

            var installProgress = (normalized - DownloadPhaseBoundary) / (1 - DownloadPhaseBoundary);
            InstallProgressBar.Value = 80 + installProgress * 20;
            ProgressTextBlock.Text = $"Installing update... {Math.Round(installProgress * 100)}%";
        }

        public void CloseSafely() {
            _allowClose = true;
            Close();
        }

        private void Window_Closing(object sender, CancelEventArgs e) {
            _ = sender;
            if (_allowClose) {
                return;
            }

            e.Cancel = true;
        }
    }
}
