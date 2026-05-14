using LocalCam.Models;

namespace LocalCam.Services {
    internal interface IPremiumEntitlementService {
        event Action<StoreEntitlementSnapshot>? SnapshotChanged;
        StoreEntitlementSnapshot Snapshot { get; }
        Task StartAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken);
        Task<StoreEntitlementSnapshot> EnsureReadyAsync(CancellationToken cancellationToken);
        Task<bool> RequestPremiumPurchaseAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken);
    }
}
