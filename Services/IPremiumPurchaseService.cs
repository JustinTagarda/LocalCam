namespace LocalCam.Services {
    internal enum PremiumPurchaseOutcome {
        Succeeded,
        AlreadyOwned,
        Canceled,
        Failed,
        NetworkError,
        ServerError,
        NotSupported,
        Blocked
    }

    internal sealed record PremiumPurchaseResult(PremiumPurchaseOutcome Outcome, string Message);

    internal interface IPremiumPurchaseService {
        Task<PremiumPurchaseResult> PurchasePremiumAsync(CancellationToken cancellationToken = default);
    }
}
