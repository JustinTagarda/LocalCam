namespace LocalCam.Models {
    internal sealed record StoreEntitlementSnapshot(
        StoreEntitlementState State,
        bool IsPremium,
        bool IsPurchaseAvailable,
        string StatusMessage,
        string? MatchReason);
}
