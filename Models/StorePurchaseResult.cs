namespace LocalCam.Models {
    internal sealed record StorePurchaseResult(
        StorePurchaseOutcome Outcome,
        StoreEntitlementSnapshot Entitlement,
        string StatusMessage) {
        public bool IsPremium => Entitlement.IsPremium;
    }
}
