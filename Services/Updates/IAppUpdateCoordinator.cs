using LocalCam.Models;

namespace LocalCam.Services.Updates {
    internal interface IAppUpdateCoordinator {
        Task RunStartupUpdateFlowAsync(CancellationToken cancellationToken);
        Task<StoreUpdateOperationResult> RunUserInitiatedUpdateFlowAsync(CancellationToken cancellationToken);
        Task<StoreUpdateOperationResult> RunDeferredInstallOnExitAsync(IProgress<double>? progress, CancellationToken cancellationToken);
        Task<bool> HasDeferredInstallPendingAsync(CancellationToken cancellationToken);
    }
}
