namespace LocalCam.Models {
    internal enum StorePurchaseOutcome {
        Succeeded,
        AlreadyOwned,
        Cancelled,
        NetworkError,
        ServerError,
        NotSupported,
        Blocked,
        Failed
    }
}
