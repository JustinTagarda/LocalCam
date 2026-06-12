namespace LocalCam.Services {
    internal static class PremiumEntitlementRules {
        internal static bool MatchesPremiumLicense(
            string configuredPremiumAddOnStoreId,
            string? configuredPremiumAddOnOfferToken,
            string? licenseSkuStoreId,
            string? licenseInAppOfferToken,
            bool isActive) {
            if (!isActive || string.IsNullOrWhiteSpace(configuredPremiumAddOnStoreId)) {
                return false;
            }

            return MatchesConfiguredSkuStoreId(configuredPremiumAddOnStoreId, licenseSkuStoreId) ||
                   MatchesConfiguredOfferToken(configuredPremiumAddOnOfferToken, licenseInAppOfferToken);
        }

        internal static bool MatchesPremiumCollectionProduct(
            string configuredPremiumAddOnStoreId,
            string? productStoreId,
            bool isInUserCollection) {
            if (!isInUserCollection || string.IsNullOrWhiteSpace(configuredPremiumAddOnStoreId)) {
                return false;
            }

            return MatchesConfiguredStoreId(configuredPremiumAddOnStoreId, productStoreId);
        }

        internal static bool MatchesConfiguredStoreId(string configuredStoreId, string? candidateStoreId) {
            return !string.IsNullOrWhiteSpace(candidateStoreId) &&
                   string.Equals(configuredStoreId.Trim(), candidateStoreId.Trim(), StringComparison.OrdinalIgnoreCase);
        }

        internal static bool MatchesConfiguredSkuStoreId(string configuredStoreId, string? candidateSkuStoreId) {
            if (string.IsNullOrWhiteSpace(candidateSkuStoreId)) {
                return false;
            }

            var normalizedConfiguredStoreId = configuredStoreId.Trim();
            var normalizedCandidateSkuStoreId = candidateSkuStoreId.Trim();

            if (string.Equals(normalizedConfiguredStoreId, normalizedCandidateSkuStoreId, StringComparison.OrdinalIgnoreCase)) {
                return true;
            }

            return normalizedCandidateSkuStoreId.StartsWith(normalizedConfiguredStoreId, StringComparison.OrdinalIgnoreCase);
        }

        internal static bool MatchesConfiguredOfferToken(string? configuredOfferToken, string? candidateOfferToken) {
            if (string.IsNullOrWhiteSpace(configuredOfferToken) || string.IsNullOrWhiteSpace(candidateOfferToken)) {
                return false;
            }

            return string.Equals(
                configuredOfferToken.Trim(),
                candidateOfferToken.Trim(),
                StringComparison.OrdinalIgnoreCase);
        }
    }
}
