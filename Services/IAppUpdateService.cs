using LocalCam.Models;

namespace LocalCam.Services {
    internal interface IAppUpdateService {
        event Action<AppUpdateSnapshot>? SnapshotChanged;
        AppUpdateSnapshot Snapshot { get; }
        Task StartAsync(CancellationToken cancellationToken);
    }
}
