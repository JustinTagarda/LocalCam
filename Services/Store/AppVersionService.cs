namespace LocalCam.Services.Store {
    internal sealed class AppVersionService : IAppVersionService {
        private readonly IAppVersionProvider _versionProvider;

        public AppVersionService(IAppVersionProvider versionProvider) {
            _versionProvider = versionProvider;
        }

        public bool IsPackaged => _versionProvider.IsPackaged();

        public string VersionText => $"v{_versionProvider.GetInstalledVersionText()}";
    }
}
