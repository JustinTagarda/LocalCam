using System.Windows;
using LocalCam.Networking;

namespace LocalCam {
    public partial class App : Application {
        protected override async void OnStartup(StartupEventArgs e) {
            base.OnStartup(e);

            while (true) {
                IReadOnlyList<TapoCameraDetection> detections;

                try {
                    detections = await TapoCameraScanner.ScanLocalNetworkForTapoCamerasAsync();
                }
                catch (Exception ex) {
                    var retryAfterError = MessageBox.Show(
                        $"Unable to scan for Tapo cameras.\n\n{ex.Message}\n\nScan again?",
                        "LocalCam",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Error,
                        MessageBoxResult.Yes);

                    if (retryAfterError == MessageBoxResult.Yes) {
                        continue;
                    }

                    Shutdown();
                    return;
                }

                if (detections.Count > 0) {
                    var mainWindow = new MainWindow(detections);
                    MainWindow = mainWindow;
                    mainWindow.Show();
                    return;
                }

                var scanAgain = MessageBox.Show(
                    "No Tapo cameras were detected on the local network.\n\nDo you want to scan again?",
                    "No Camera Detected",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning,
                    MessageBoxResult.Yes);

                if (scanAgain != MessageBoxResult.Yes) {
                    Shutdown();
                    return;
                }
            }
        }
    }
}
