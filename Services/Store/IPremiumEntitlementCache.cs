namespace LocalCam.Services.Store {
    internal interface IPremiumEntitlementCache {
        bool HasVerifiedPremium();
        void SaveVerifiedPremium();
        void Clear();
    }
}
