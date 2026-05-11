namespace LocalCam.Models {
    internal enum AppUpdateState {
        Idle,
        Checking,
        UpdateAvailable,
        Downloading,
        Installing,
        Completed,
        Deferred,
        Failed
    }
}
