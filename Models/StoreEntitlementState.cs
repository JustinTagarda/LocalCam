namespace LocalCam.Models {
    internal enum StoreEntitlementState {
        Unknown,
        Checking,
        VerifiedOwned,
        VerifiedNotOwned,
        VerificationFailed
    }
}
