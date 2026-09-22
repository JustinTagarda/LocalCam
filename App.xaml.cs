using System.Threading;
using System.Windows;

namespace LocalCam {
    public partial class App : Application {
        private const string SingleInstanceMutexName = @"Local\LocalCam.SingleInstance";
        private const string SingleInstanceActivationEventName = @"Local\LocalCam.SingleInstance.Activate";
        private static Mutex? _singleInstanceMutex;
        private static EventWaitHandle? _singleInstanceActivationEvent;
        private static CancellationTokenSource? _singleInstanceActivationCts;
        private static bool _ownsSingleInstanceMutex;
        private static bool _activationRequestedBeforeWindowReady;

        protected override void OnStartup(StartupEventArgs e) {
            base.OnStartup(e);

            _singleInstanceMutex = new Mutex(initiallyOwned: false, name: SingleInstanceMutexName);
            _ownsSingleInstanceMutex = _singleInstanceMutex.WaitOne(0, false);
            if (!_ownsSingleInstanceMutex) {
                SignalExistingInstance();
                _singleInstanceMutex.Dispose();
                _singleInstanceMutex = null;
                Shutdown();
                return;
            }

            _singleInstanceActivationEvent = new EventWaitHandle(
                initialState: false,
                mode: EventResetMode.AutoReset,
                name: SingleInstanceActivationEventName);
            _singleInstanceActivationCts = new CancellationTokenSource();
            _ = WaitForActivationRequestsAsync(_singleInstanceActivationCts.Token);

            Services.JsonLogStore.Initialize();
            Services.JsonLogStore.Information(
                eventName: "app_started",
                message: "LocalCam application startup entered.",
                category: "app");

            var mainWindow = new MainWindow();
            MainWindow = mainWindow;
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            mainWindow.Show();
            if (_activationRequestedBeforeWindowReady) {
                _activationRequestedBeforeWindowReady = false;
                ActivateMainWindow();
            }
        }

        protected override void OnExit(ExitEventArgs e) {
            _singleInstanceActivationCts?.Cancel();
            try {
                _singleInstanceActivationEvent?.Set();
            }
            catch (ObjectDisposedException) {
                // The activation wait has already been released.
            }
            _singleInstanceActivationCts?.Dispose();
            _singleInstanceActivationCts = null;
            _singleInstanceActivationEvent?.Dispose();
            _singleInstanceActivationEvent = null;

            if (_ownsSingleInstanceMutex) {
                _singleInstanceMutex?.ReleaseMutex();
                _ownsSingleInstanceMutex = false;
            }
            _singleInstanceMutex?.Dispose();
            _singleInstanceMutex = null;
            base.OnExit(e);
        }

        private static void SignalExistingInstance() {
            try {
                using var activationEvent = EventWaitHandle.OpenExisting(SingleInstanceActivationEventName);
                activationEvent.Set();
            }
            catch (WaitHandleCannotBeOpenedException) {
                // The primary instance is still between mutex acquisition and event creation.
            }
            catch (UnauthorizedAccessException) {
                // The existing instance cannot be signaled; its own lifecycle remains unchanged.
            }
        }

        private static async Task WaitForActivationRequestsAsync(CancellationToken cancellationToken) {
            var activationEvent = _singleInstanceActivationEvent;
            if (activationEvent is null) {
                return;
            }

            try {
                await Task.Run(() => {
                    while (!cancellationToken.IsCancellationRequested) {
                        activationEvent.WaitOne();
                        if (!cancellationToken.IsCancellationRequested) {
                            Current.Dispatcher.BeginInvoke(new Action(ActivateMainWindow));
                        }
                    }
                }, cancellationToken);
            }
            catch (OperationCanceledException) {
                // App is shutting down.
            }
            catch (ObjectDisposedException) {
                // The activation event was disposed during shutdown.
            }
        }

        private static void ActivateMainWindow() {
            if (Current.MainWindow is not Window mainWindow) {
                _activationRequestedBeforeWindowReady = true;
                return;
            }

            if (mainWindow.WindowState == WindowState.Minimized) {
                mainWindow.WindowState = WindowState.Normal;
            }

            if (!mainWindow.IsVisible) {
                mainWindow.Show();
            }

            mainWindow.Activate();
            mainWindow.Focus();
        }
    }
}
