using System.Windows;
using LocalCam.Models;

namespace LocalCam {
    public partial class SettingsWindow : Window {
        private readonly LocalCamSettings _initialSettings;

        public SettingsWindow(LocalCamSettings settings) {
            InitializeComponent();
            _initialSettings = settings;

            RtspUsernameTextBox.Text = settings.RtspUsername;
            RtspPasswordBox.Password = settings.RtspPassword;
            StreamPathTextBox.Text = settings.StreamPath;
        }

        public LocalCamSettings Settings { get; private set; } = new();

        private void UpdateButton_Click(object sender, RoutedEventArgs e) {
            Settings = new LocalCamSettings {
                RtspUsername = RtspUsernameTextBox.Text.Trim(),
                RtspPassword = RtspPasswordBox.Password,
                StreamPath = NormalizeStreamPath(StreamPathTextBox.Text),
                AutoStreamVideo = _initialSettings.AutoStreamVideo,
                LastSuccessfulDetectionMethod = _initialSettings.LastSuccessfulDetectionMethod,
                MainWindowLeft = _initialSettings.MainWindowLeft,
                MainWindowTop = _initialSettings.MainWindowTop,
                MainWindowWidth = _initialSettings.MainWindowWidth,
                MainWindowHeight = _initialSettings.MainWindowHeight
            };

            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e) {
            DialogResult = false;
            Close();
        }

        private void TitleBar_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e) {
            if (e.ButtonState == System.Windows.Input.MouseButtonState.Pressed) {
                DragMove();
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e) {
            DialogResult = false;
            Close();
        }

        private static string NormalizeStreamPath(string? input) {
            var normalized = (input ?? string.Empty).Trim().TrimStart('/');
            return string.IsNullOrWhiteSpace(normalized)
                ? "stream1"
                : normalized;
        }
    }
}
