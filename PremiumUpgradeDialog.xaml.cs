using System.Windows;

namespace LocalCam {
    public partial class PremiumUpgradeDialog : Window {
        public PremiumUpgradeDialog() {
            InitializeComponent();
        }

        public bool ShouldUpgrade { get; private set; }

        private void Upgrade_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            ShouldUpgrade = true;
            DialogResult = true;
        }

        private void Dismiss_Click(object sender, RoutedEventArgs e) {
            _ = sender;
            _ = e;
            DialogResult = false;
        }
    }
}
