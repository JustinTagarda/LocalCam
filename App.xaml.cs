using System.Windows;

namespace LocalCam {
    public partial class App : Application {
        protected override void OnStartup(StartupEventArgs e) {
            base.OnStartup(e);

            Services.JsonLogStore.Initialize();
            Services.JsonLogStore.Information(
                eventName: "app_started",
                message: "LocalCam application startup completed.",
                category: "app");

            var mainWindow = new MainWindow();
            MainWindow = mainWindow;
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            mainWindow.Show();
        }
    }
}
