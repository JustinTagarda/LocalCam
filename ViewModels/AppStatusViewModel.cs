using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using LocalCam.Models;
using LocalCam.Services;
using LocalCam.Services.Store;
using LocalCam.Services.Updates;

namespace LocalCam.ViewModels {
    internal sealed class AppStatusViewModel : INotifyPropertyChanged {
        private readonly IAppVersionService _versionService;
        private readonly IStoreLicenseService _licenseService;
        private readonly IStorePurchaseService _purchaseService;
        private readonly IAppUpdateCoordinator _updateCoordinator;
        private readonly Func<IntPtr> _getOwnerWindowHandle;
        private CancellationTokenSource? _toastCancellation;
        private static readonly TimeSpan StoreCommandTimeout = TimeSpan.FromSeconds(20);
        private bool _isBusy;
        private string _modeText = "Basic";
        private string _modeToolTip = "Click to upgrade to Premium.";
        private string _toastText = string.Empty;
        private bool _isToastOpen;

        public AppStatusViewModel(
            IAppVersionService versionService,
            IStoreLicenseService licenseService,
            IStorePurchaseService purchaseService,
            IAppUpdateCoordinator updateCoordinator,
            Func<IntPtr> getOwnerWindowHandle) {
            _versionService = versionService;
            _licenseService = licenseService;
            _purchaseService = purchaseService;
            _updateCoordinator = updateCoordinator;
            _getOwnerWindowHandle = getOwnerWindowHandle;
            VersionText = _versionService.VersionText;
            UpgradeCommand = new AsyncRelayCommand(UpgradeAsync, () => !_isBusy && ModeText == "Basic");
            RestoreCommand = new AsyncRelayCommand(RestoreAsync, () => !_isBusy);
            RedeemPromoCodeCommand = new AsyncRelayCommand(RedeemPromoCodeAsync, () => !_isBusy);
            CheckForUpdatesCommand = new AsyncRelayCommand(CheckForUpdatesAsync, () => !_isBusy);
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public string ModeText {
            get => _modeText;
            private set {
                if (SetField(ref _modeText, value)) {
                    ModeToolTip = value == "Premium" ? "Premium mode active." : "Click to upgrade to Premium.";
                    OnPropertyChanged(nameof(IsBasic));
                    RaiseCommandStateChanged();
                }
            }
        }

        public bool IsBasic => ModeText == "Basic";

        public string ModeToolTip {
            get => _modeToolTip;
            private set => SetField(ref _modeToolTip, value);
        }

        public string VersionText { get; }

        public string ToastText {
            get => _toastText;
            private set => SetField(ref _toastText, value);
        }

        public bool IsToastOpen {
            get => _isToastOpen;
            private set => SetField(ref _isToastOpen, value);
        }

        public ICommand UpgradeCommand { get; }
        public ICommand RestoreCommand { get; }
        public ICommand RedeemPromoCodeCommand { get; }
        public ICommand CheckForUpdatesCommand { get; }

        public void ApplyEntitlementSnapshot(StoreEntitlementSnapshot snapshot) {
            ModeText = snapshot.IsPremium ? "Premium" : "Basic";
        }

        private async Task UpgradeAsync() {
            if (ModeText != "Basic") {
                return;
            }

            await RunBusyAsync(async () => {
                using var cts = CreateBoundedToken();
                var purchase = await _purchaseService.RequestPremiumPurchaseAsync(_getOwnerWindowHandle(), cts.Token);
                ApplyEntitlementSnapshot(purchase.Entitlement);
                await ShowToastAsync(purchase.StatusMessage);
            });
        }

        private async Task RestoreAsync() {
            await RunBusyAsync(async () => {
                using var cts = CreateBoundedToken();
                var snapshot = await _purchaseService.RestorePremiumPurchaseAsync(_getOwnerWindowHandle(), cts.Token);
                ApplyEntitlementSnapshot(snapshot);
                if (snapshot.IsPremium) {
                    await ShowToastAsync("Premium restored");
                }
                else if (snapshot.State == StoreEntitlementState.VerifiedNotOwned) {
                    await ShowToastAsync("No Premium purchase found");
                }
                else {
                    await ShowToastAsync("Unable to verify purchase right now");
                }
            });
        }

        private async Task RedeemPromoCodeAsync() {
            await RunBusyAsync(async () => {
                var dialog = new PromoCodeRedemptionDialog();
                var redeemRequested = dialog.ShowDialog() == true && dialog.ShouldRedeem;
                if (!redeemRequested) {
                    await ShowToastAsync("Promo-code redemption canceled.");
                    return;
                }

                using var cts = CreateBoundedToken();
                var result = await _purchaseService.RedeemPromoCodeAsync(dialog.PromoCode, _getOwnerWindowHandle(), cts.Token);
                ApplyEntitlementSnapshot(result.Entitlement);
                await ShowToastAsync(result.StatusMessage);
            });
        }

        private async Task CheckForUpdatesAsync() {
            await RunBusyAsync(async () => {
                using var cts = CreateBoundedToken();
                var result = await _updateCoordinator.RunUserInitiatedUpdateFlowAsync(cts.Token);
                await ShowToastAsync(result.StatusMessage);
            });
        }

        private static CancellationTokenSource CreateBoundedToken() {
            return new CancellationTokenSource(StoreCommandTimeout);
        }

        private async Task RunBusyAsync(Func<Task> action) {
            if (_isBusy) {
                return;
            }

            _isBusy = true;
            RaiseCommandStateChanged();
            try {
                await action();
            }
            catch (OperationCanceledException) {
                await ShowToastAsync("Store operation timed out.");
            }
            finally {
                _isBusy = false;
                RaiseCommandStateChanged();
            }
        }

        private async Task ShowToastAsync(string text) {
            _toastCancellation?.Cancel();
            _toastCancellation?.Dispose();
            var cts = new CancellationTokenSource();
            _toastCancellation = cts;
            ToastText = text;
            IsToastOpen = true;

            try {
                await Task.Delay(TimeSpan.FromSeconds(2.5), cts.Token);
                IsToastOpen = false;
            }
            catch (OperationCanceledException) {
            }
        }

        private void RaiseCommandStateChanged() {
            (UpgradeCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
            (RestoreCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
            (RedeemPromoCodeCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
            (CheckForUpdatesCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        }

        private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null) {
            if (EqualityComparer<T>.Default.Equals(field, value)) {
                return false;
            }

            field = value;
            OnPropertyChanged(propertyName);
            return true;
        }

        private void OnPropertyChanged([CallerMemberName] string? propertyName = null) {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        private sealed class AsyncRelayCommand : ICommand {
            private readonly Func<Task> _execute;
            private readonly Func<bool> _canExecute;

            public AsyncRelayCommand(Func<Task> execute, Func<bool> canExecute) {
                _execute = execute;
                _canExecute = canExecute;
            }

            public event EventHandler? CanExecuteChanged;

            public bool CanExecute(object? parameter) => _canExecute();

            public async void Execute(object? parameter) {
                try {
                    await _execute();
                }
                catch (Exception ex) {
                    JsonLogStore.Error("app_status_command_failed", "App status command failed.", "store", ex);
                }
            }

            public void RaiseCanExecuteChanged() {
                CanExecuteChanged?.Invoke(this, EventArgs.Empty);
            }
        }
    }
}
