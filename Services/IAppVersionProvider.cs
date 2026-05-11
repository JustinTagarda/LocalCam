using LocalCam.Models;

namespace LocalCam.Services {
    internal interface IAppVersionProvider {
        bool IsPackaged();
        string GetInstalledVersionText();
    }
}
