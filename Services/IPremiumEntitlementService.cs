namespace LocalCam.Services {
    internal sealed record PremiumEntitlementResult(
        bool IsPremiumOwned,
        bool IsFromStore,
        bool UsedFallbackCache,
        string Message);

    internal interface IPremiumEntitlementService {
        Task<PremiumEntitlementResult> CheckPremiumEntitlementAsync(CancellationToken cancellationToken = default);
    }
}
