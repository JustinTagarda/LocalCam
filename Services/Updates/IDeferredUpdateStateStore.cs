using LocalCam.Models;

namespace LocalCam.Services.Updates {
    internal interface IDeferredUpdateStateStore {
        Task<DeferredUpdateState?> LoadAsync(CancellationToken cancellationToken);
        Task SaveAsync(DeferredUpdateState state, CancellationToken cancellationToken);
        Task ClearAsync(CancellationToken cancellationToken);
    }
}
