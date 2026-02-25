using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using LocalCam.Networking;

namespace LocalCam {
    public partial class MainWindow : Window {
        private static readonly Geometry MaximizeGeometry = Geometry.Parse("M2,2 L12,2 12,12 2,12 Z");
        private static readonly Geometry RestoreGeometry = Geometry.Parse("M4,2 L12,2 12,10 M4,2 L4,10 12,10 M2,4 L10,4 10,12 2,12 Z");

        public MainWindow()
            : this(Array.Empty<TapoCameraDetection>()) {
        }

        public MainWindow(IReadOnlyList<TapoCameraDetection> detections) {
            InitializeComponent();
            PopulateCameraTiles(detections);
            UpdateMaximizeButtonIcon();
        }

        private void PopulateCameraTiles(IReadOnlyList<TapoCameraDetection> detections) {
            var tileLabels = new[] { CameraTile1, CameraTile2, CameraTile3, CameraTile4 };

            for (var i = 0; i < tileLabels.Length; i++) {
                var label = tileLabels[i];
                var baseText = $"camera {i + 1} - live streaming";

                if (i < detections.Count) {
                    label.Text = $"{baseText} ({detections[i].IpAddress})";
                }
                else {
                    label.Text = baseText;
                }
            }
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
    }
}
