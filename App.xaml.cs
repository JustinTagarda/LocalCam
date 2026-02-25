using System.Windows;

namespace LocalCam {
    public partial class App : Application {
        protected override void OnStartup(StartupEventArgs e) {
            base.OnStartup(e);

            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            var startupWindow = new StartupWindow();
            var startupResult = startupWindow.ShowDialog();

            if (startupResult == true && startupWindow.DetectedCameras.Count > 0) {
                var mainWindow = new MainWindow(startupWindow.DetectedCameras);
                MainWindow = mainWindow;
                ShutdownMode = ShutdownMode.OnMainWindowClose;
                mainWindow.Show();
                return;
            }

            Shutdown();
        }
    }
}
