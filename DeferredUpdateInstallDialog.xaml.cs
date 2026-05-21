using System.ComponentModel;
using System.Windows;

namespace LocalCam {
    public partial class DeferredUpdateInstallDialog : Window {
        private bool _allowClose;

        public DeferredUpdateInstallDialog() {
            InitializeComponent();
        }

        public void ReportProgress(double progress) {
            var normalized = double.IsNaN(progress) || double.IsInfinity(progress)
                ? 0
                : Math.Clamp(progress, 0, 1);

            InstallProgressBar.IsIndeterminate = false;
            InstallProgressBar.Value = normalized * 100;
            ProgressTextBlock.Text = $"Installing update... {Math.Round(normalized * 100)}%";
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
