using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LocalCam.Services.Store {
    internal sealed class PremiumEntitlementCache : IPremiumEntitlementCache {
        private const string Category = "store_entitlement";
        private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

        private string CacheDirectory {
            get {
                var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                return Path.Combine(root, "LocalCam");
            }
        }

        private string CachePath => Path.Combine(CacheDirectory, "premium-entitlement.cache");

        public bool HasVerifiedPremium() {
            try {
                if (!File.Exists(CachePath)) {
                    return false;
                }

                var protectedBytes = File.ReadAllBytes(CachePath);
                var jsonBytes = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
                var payload = JsonSerializer.Deserialize<PremiumEntitlementCachePayload>(jsonBytes, JsonOptions);
                return payload is not null
                    && string.Equals(payload.PremiumStoreId, StoreProductConfiguration.PremiumStoreId, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(payload.PremiumProductId, StoreProductConfiguration.PremiumProductId, StringComparison.OrdinalIgnoreCase)
                    && payload.VerifiedOwnedAtUtc != default;
            }
            catch (Exception ex) {
                JsonLogStore.Warning("premium_cache_read_failed", "Premium entitlement cache could not be read.", Category, new Dictionary<string, object?> {
                    ["exceptionType"] = ex.GetType().FullName,
                    ["exceptionMessage"] = ex.Message
                });
                return false;
            }
        }

        public void SaveVerifiedPremium() {
            try {
                Directory.CreateDirectory(CacheDirectory);
                var payload = new PremiumEntitlementCachePayload(
                    StoreProductConfiguration.PremiumStoreId,
                    StoreProductConfiguration.PremiumProductId,
                    DateTimeOffset.UtcNow);
                var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
                var protectedBytes = ProtectedData.Protect(jsonBytes, null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(CachePath, protectedBytes);
            }
            catch (Exception ex) {
                JsonLogStore.Error("premium_cache_write_failed", "Premium entitlement cache could not be written.", Category, ex);
            }
        }

        public void Clear() {
            try {
                if (File.Exists(CachePath)) {
                    File.Delete(CachePath);
                }
            }
            catch (Exception ex) {
                JsonLogStore.Warning("premium_cache_clear_failed", "Premium entitlement cache could not be cleared.", Category, new Dictionary<string, object?> {
                    ["exceptionType"] = ex.GetType().FullName,
                    ["exceptionMessage"] = ex.Message
                });
            }
        }

        private sealed record PremiumEntitlementCachePayload(
            string PremiumStoreId,
            string PremiumProductId,
            DateTimeOffset VerifiedOwnedAtUtc);
    }
}
