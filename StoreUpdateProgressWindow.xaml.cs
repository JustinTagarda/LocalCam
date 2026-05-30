using System.ComponentModel;
using System.Windows;
using LocalCam.Services;

namespace LocalCam {
    public partial class StoreUpdateProgressWindow : Window {
        private bool _allowClose;

        public StoreUpdateProgressWindow() {
            InitializeComponent();
        }

        internal void ApplyState(StoreUpdateUiState state) {
            PhaseTextBlock.Text = string.IsNullOrWhiteSpace(state.PhaseText) ? "Preparing" : state.PhaseText;
            ProgressBar.Value = Math.Clamp(state.ProgressPercent, 0, 100);

            DetailTextBlock.Text = state.DetailText;
            DetailTextBlock.Visibility = string.IsNullOrWhiteSpace(state.DetailText) ? Visibility.Collapsed : Visibility.Visible;

            ResultTextBlock.Text = state.ResultText;
            ResultTextBlock.Visibility = string.IsNullOrWhiteSpace(state.ResultText) ? Visibility.Collapsed : Visibility.Visible;

            _allowClose = state.IsTerminal;
            CloseButton.IsEnabled = _allowClose;
        }

        public void CloseFromOwner() {
            _allowClose = true;
            Close();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            if (_allowClose) {
                Close();
            }
        }

        protected override void OnClosing(CancelEventArgs e) {
            if (!_allowClose) {
                e.Cancel = true;
                return;
            }

            base.OnClosing(e);
        }
    }
}
