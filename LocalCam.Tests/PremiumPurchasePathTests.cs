using LocalCam.Models;
using LocalCam.Services;
using LocalCam.Services.Store;
using LocalCam.ViewModels;
using Xunit;

namespace LocalCam.Tests;

public sealed class PremiumPurchasePathTests {
    private static readonly StoreEntitlementSnapshot BasicVerified = new(
        StoreEntitlementState.VerifiedNotOwned,
        IsPremium: false,
        IsPurchaseAvailable: true,
        StatusMessage: "Basic",
        MatchReason: null);

    private static readonly StoreEntitlementSnapshot PremiumVerified = new(
        StoreEntitlementState.VerifiedOwned,
        IsPremium: true,
        IsPurchaseAvailable: true,
        StatusMessage: "Premium",
        MatchReason: "store");

    [Fact]
    public async Task UpgradeCommand_CallsPurchaseService() {
        var purchase = new FakePurchaseService {
            PurchaseResult = new StorePurchaseResult(StorePurchaseOutcome.Succeeded, PremiumVerified, "Premium unlocked.")
        };
        var vm = CreateViewModel(purchaseService: purchase);
        vm.ApplyEntitlementSnapshot(BasicVerified);

        Assert.True(vm.UpgradeCommand.CanExecute(null));
        vm.UpgradeCommand.Execute(null);

        await WaitForAsync(() => purchase.PurchaseCalls == 1);
        Assert.Equal("Premium", vm.ModeText);
    }

    [Fact]
    public async Task RestoreCommand_OnlyRefreshesEntitlement_WithoutPurchase() {
        var purchase = new FakePurchaseService {
            RestoreResult = PremiumVerified
        };
        var vm = CreateViewModel(purchaseService: purchase);

        vm.RestoreCommand.Execute(null);

        await WaitForAsync(() => purchase.RestoreCalls == 1);
        Assert.Equal(0, purchase.PurchaseCalls);
        Assert.Equal("Premium", vm.ModeText);
    }

    [Fact]
    public async Task RequestPremiumPurchase_NotSupported_DoesNotNavigateOrPurchase() {
        var navigation = new FakeNavigationService();
        var service = new StorePurchaseService(
            new FakeContextProvider(isSupported: false),
            new FakeLicenseService(BasicVerified),
            navigation,
            isElevatedProbe: () => false);

        var result = await service.RequestPremiumPurchaseAsync(IntPtr.Zero, CancellationToken.None);

        Assert.Equal(StorePurchaseOutcome.NotSupported, result.Outcome);
        Assert.Equal("Premium purchase is available only in the Microsoft Store version.", result.StatusMessage);
        Assert.Equal(0, navigation.RedeemCalls);
    }

    [Fact]
    public async Task RequestPremiumPurchase_Blocked_DoesNotNavigateOrPurchase() {
        var navigation = new FakeNavigationService();
        var service = new StorePurchaseService(
            new FakeContextProvider(isSupported: true),
            new FakeLicenseService(BasicVerified),
            navigation,
            isElevatedProbe: () => true);

        var result = await service.RequestPremiumPurchaseAsync(IntPtr.Zero, CancellationToken.None);

        Assert.Equal(StorePurchaseOutcome.Blocked, result.Outcome);
        Assert.Equal(0, navigation.RedeemCalls);
    }

    private static AppStatusViewModel CreateViewModel(FakePurchaseService? purchaseService = null) {
        return new AppStatusViewModel(
            new FakeLicenseService(BasicVerified),
            purchaseService ?? new FakePurchaseService(),
            () => IntPtr.Zero);
    }

    private static async Task WaitForAsync(Func<bool> condition, int timeoutMs = 2000) {
        var stopAt = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < stopAt) {
            if (condition()) {
                return;
            }

            await Task.Delay(25);
        }

        Assert.True(condition());
    }

    private sealed class FakePurchaseService : IStorePurchaseService {
        public int PurchaseCalls { get; private set; }
        public int RestoreCalls { get; private set; }
        public StorePurchaseResult PurchaseResult { get; set; } = new(StorePurchaseOutcome.Cancelled, BasicVerified, "Canceled");
        public StoreEntitlementSnapshot RestoreResult { get; set; } = BasicVerified;

        public Task<StorePurchaseResult> RequestPremiumPurchaseAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            PurchaseCalls++;
            return Task.FromResult(PurchaseResult);
        }

        public Task<StoreEntitlementSnapshot> RestorePremiumPurchaseAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            RestoreCalls++;
            return Task.FromResult(RestoreResult);
        }

        public Task<StoreRedemptionResult> RedeemPromoCodeAsync(string promoCode, IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            return Task.FromResult(new StoreRedemptionResult(StoreRedemptionOutcome.Cancelled, BasicVerified, "Canceled"));
        }
    }

    private sealed class FakeLicenseService : IStoreLicenseService {
        private readonly StoreEntitlementSnapshot _snapshot;

        public FakeLicenseService(StoreEntitlementSnapshot snapshot) {
            _snapshot = snapshot;
            Snapshot = snapshot;
        }

        public event Action<StoreEntitlementSnapshot>? SnapshotChanged;

        public StoreEntitlementSnapshot Snapshot { get; private set; }

        public Task StartAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            return Task.CompletedTask;
        }

        public Task<StoreEntitlementSnapshot> EnsureReadyAsync(CancellationToken cancellationToken) {
            return Task.FromResult(_snapshot);
        }

        public Task<StoreEntitlementSnapshot> RefreshAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken) {
            Snapshot = _snapshot;
            SnapshotChanged?.Invoke(Snapshot);
            return Task.FromResult(_snapshot);
        }
    }

    private sealed class FakeContextProvider : IStoreContextProvider {
        public FakeContextProvider(bool isSupported) {
            IsStoreSupported = isSupported;
        }

        public bool IsStoreSupported { get; }

        public Windows.Services.Store.StoreContext? GetContext(IntPtr ownerWindowHandle) {
            return null;
        }
    }

    private sealed class FakeNavigationService : IStoreNavigationService {
        public int RedeemCalls { get; private set; }

        public Task<bool> OpenPromotionalCodeRedeemUrlAsync(string promoCode, CancellationToken cancellationToken) {
            RedeemCalls++;
            return Task.FromResult(false);
        }
    }
}
