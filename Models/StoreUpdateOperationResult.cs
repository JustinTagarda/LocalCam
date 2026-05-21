namespace LocalCam.Models {
    internal sealed record StoreUpdateOperationResult(
        StoreUpdateOperationState State,
        string StatusMessage,
        double ProgressValue = 0,
        bool WasAttempted = true) {
        public bool Succeeded => State == StoreUpdateOperationState.Completed;
        public bool Canceled => State == StoreUpdateOperationState.Canceled;
    }
}
