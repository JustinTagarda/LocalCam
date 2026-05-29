using System.Diagnostics;

namespace LocalCam.Services {
    internal sealed class StoreNavigationService : IStoreNavigationService {
        public bool TryOpenStoreListing(string productId) {
            if (string.IsNullOrWhiteSpace(productId)) {
                return false;
            }

            try {
                var uri = $"ms-windows-store://pdp/?productid={productId.Trim()}";
                var startInfo = new ProcessStartInfo(uri) {
                    UseShellExecute = true
                };
                Process.Start(startInfo);
                return true;
            }
            catch {
                return false;
            }
        }
    }
}
