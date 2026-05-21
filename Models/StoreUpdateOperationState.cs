namespace LocalCam.Models {
    internal enum StoreUpdateOperationState {
        Completed,
        Canceled,
        OtherError,
        ErrorLowBattery,
        ErrorWiFiRecommended,
        ErrorWiFiRequired,
        Unknown
    }
}
