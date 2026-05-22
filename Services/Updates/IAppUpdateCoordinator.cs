using LocalCam.Models;

namespace LocalCam.Services.Updates {
    internal interface IAppUpdateCoordinator {
        Task RunStartupUpdateFlowAsync(CancellationToken cancellationToken);
        Task<StoreUpdateCheckResult> RunUserInitiatedUpdateFlowAsync(CancellationToken cancellationToken);
        Task<StoreUpdateOperationResult> RunDeferredInstallOnExitAsync(IProgress<double>? progress, CancellationToken cancellationToken);
        Task<bool> HasDeferredInstallPendingAsync(CancellationToken cancellationToken);
    }
}
