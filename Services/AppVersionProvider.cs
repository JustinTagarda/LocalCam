using System.Reflection;
using Windows.ApplicationModel;

namespace LocalCam.Services {
    internal sealed class AppVersionProvider : IAppVersionProvider {
        public bool IsPackaged() {
            try {
                _ = Package.Current.Id.FullName;
                return true;
            }
            catch {
                return false;
            }
        }

        public string GetInstalledVersionText() {
            if (IsPackaged()) {
                try {
                    var version = Package.Current.Id.Version;
                    return $"{version.Major}.{version.Minor}.{version.Build}.{version.Revision}";
                }
                catch {
                }
            }

            return Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0.0";
        }
    }
}
