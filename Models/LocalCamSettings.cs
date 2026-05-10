namespace LocalCam.Models {
    public sealed class LocalCamSettings {
        public string RtspUsername { get; set; } = string.Empty;
        public string RtspPassword { get; set; } = string.Empty;
        public string StreamPath { get; set; } = "stream1";
        public double? MainWindowLeft { get; set; }
        public double? MainWindowTop { get; set; }
        public double? MainWindowWidth { get; set; }
        public double? MainWindowHeight { get; set; }
    }
}
