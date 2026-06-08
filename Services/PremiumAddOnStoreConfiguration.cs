namespace LocalCam.Services {
    internal static class PremiumAddOnStoreConfiguration {
        public const string LegacyPremiumAddOnStoreId = "9P9KCJ3NFZFT";
        public const string ActivePremiumAddOnStoreId = "9P18G2P91QV6";

        public static IReadOnlyList<string> RecognizedPremiumAddOnStoreIds { get; } = [
            LegacyPremiumAddOnStoreId,
            ActivePremiumAddOnStoreId
        ];
    }
}
