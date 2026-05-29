using System.Windows;

namespace LocalCam {
    public partial class BasicFeatureGateDialog : Window {
        public BasicFeatureGateDialog(string message) {
            InitializeComponent();
            MessageText.Text = message;
        }

        public bool UpgradeRequested { get; private set; }

        private void Upgrade_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            UpgradeRequested = true;
            DialogResult = true;
        }

        private void Close_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            DialogResult = false;
        }
    }
}
