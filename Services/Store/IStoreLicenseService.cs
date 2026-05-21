using LocalCam.Models;

namespace LocalCam.Services.Store {
    internal interface IStoreLicenseService {
        event Action<StoreEntitlementSnapshot>? SnapshotChanged;
        StoreEntitlementSnapshot Snapshot { get; }
        Task StartAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken);
        Task<StoreEntitlementSnapshot> EnsureReadyAsync(CancellationToken cancellationToken);
        Task<StoreEntitlementSnapshot> RefreshAsync(IntPtr ownerWindowHandle, CancellationToken cancellationToken);
    }
}
