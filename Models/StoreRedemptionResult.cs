namespace LocalCam.Models {
    internal sealed record StoreRedemptionResult(
        StoreRedemptionOutcome Outcome,
        StoreEntitlementSnapshot Entitlement,
        string StatusMessage) {
        public bool IsPremium => Entitlement.IsPremium;
    }
}
