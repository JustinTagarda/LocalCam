namespace LocalCam.Services.Store {
    internal interface IAppVersionService {
        bool IsPackaged { get; }
        string VersionText { get; }
    }
}
