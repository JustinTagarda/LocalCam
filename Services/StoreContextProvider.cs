using System.Security.Principal;
using WinRT.Interop;
using Windows.Services.Store;

namespace LocalCam.Services {
    internal sealed class StoreContextProvider : IStoreContextProvider {
        public bool IsPackaged {
            get {
                try {
                    _ = Windows.ApplicationModel.Package.Current;
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
