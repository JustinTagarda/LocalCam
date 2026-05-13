using System.Threading;
using System.Windows;

namespace LocalCam {
    public partial class App : Application {
        private const string SingleInstanceMutexName = @"Local\LocalCam.SingleInstance";
        private static Mutex? _singleInstanceMutex;
        private static bool _ownsSingleInstanceMutex;

        protected override void OnStartup(StartupEventArgs e) {
            base.OnStartup(e);

            _singleInstanceMutex = new Mutex(initiallyOwned: false, name: SingleInstanceMutexName);
            _ownsSingleInstanceMutex = _singleInstanceMutex.WaitOne(0, false);
            if (!_ownsSingleInstanceMutex) {
                _singleInstanceMutex.Dispose();
                _singleInstanceMutex = null;
                Shutdown();
                return;
            }

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

        protected override void OnExit(ExitEventArgs e) {
            if (_ownsSingleInstanceMutex) {
                _singleInstanceMutex?.ReleaseMutex();
                _ownsSingleInstanceMutex = false;
            }
            _singleInstanceMutex?.Dispose();
            _singleInstanceMutex = null;
            base.OnExit(e);
        }
    }
}
