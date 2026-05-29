using System.Security.Principal;
using WinRT.Interop;
using Windows.ApplicationModel;
using Windows.Services.Store;

namespace LocalCam.Services {
    internal sealed class StoreContextProvider : IStoreContextProvider {
        public bool HasPackageIdentity => IsPackaged;

        public bool IsPackaged {
            get {
                try {
                    _ = Package.Current;
                    return true;
                }
                catch {
                    return false;
                }
            }
        }

        public bool IsElevated {
            get {
                try {
                    using var identity = WindowsIdentity.GetCurrent();
                    if (identity is null) {
                        return false;
                    }

                    var principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
                catch {
                    return false;
                }
            }
        }

        public string? TryGetPackageFullName() {
            try {
                return Package.Current.Id.FullName;
            }
            catch {
                return null;
            }
        }

        public string? TryGetPackageVersion() {
            try {
                var version = Package.Current.Id.Version;
                return $"{version.Major}.{version.Minor}.{version.Build}.{version.Revision}";
            }
            catch {
                return null;
            }
        }

        public string? TryGetPackageSignatureKind() {
            try {
                return Package.Current.SignatureKind.ToString();
            }
            catch {
                return null;
            }
        }

        public StoreContext? TryGetStoreContext(IntPtr ownerWindowHandle) {
            if (!IsPackaged) {
                return null;
            }

            try {
                var context = StoreContext.GetDefault();
                if (ownerWindowHandle != IntPtr.Zero) {
                    InitializeWithWindow.Initialize(context, ownerWindowHandle);
                }
                return context;
            }
            catch {
                return null;
            }
        }
    }
}
