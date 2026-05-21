using Windows.Services.Store;
using WinRT.Interop;

namespace LocalCam.Services.Store {
    internal sealed class StoreContextProvider : IStoreContextProvider {
        private const string Category = "store";
        private readonly IAppVersionProvider _versionProvider;
        private StoreContext? _context;
        private IntPtr _initializedOwnerWindowHandle;

        public StoreContextProvider(IAppVersionProvider versionProvider) {
            _versionProvider = versionProvider;
        }

        public bool IsStoreSupported => _versionProvider.IsPackaged();

        public StoreContext? GetContext(IntPtr ownerWindowHandle) {
            if (!IsStoreSupported) {
                return null;
            }

            try {
                _context ??= StoreContext.GetDefault();
                if (ownerWindowHandle != IntPtr.Zero && ownerWindowHandle != _initializedOwnerWindowHandle) {
                    InitializeWithWindow.Initialize(_context, ownerWindowHandle);
                    _initializedOwnerWindowHandle = ownerWindowHandle;
                }

                return _context;
            }
            catch (Exception ex) {
                JsonLogStore.Error("store_context_create_failed", "Failed to create or initialize Store context.", Category, ex);
                return null;
            }
        }
    }
}
