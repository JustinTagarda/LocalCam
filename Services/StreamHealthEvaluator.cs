namespace LocalCam;

internal enum StreamHealthEvaluationKind {
    StartupGracePeriod,
    Healthy,
    Unhealthy,
    Stale
}

internal readonly record struct StreamHealthSample(
    DateTimeOffset Timestamp,
    bool IsPlaying,
    bool HasVideoOutput,
    long MediaTime,
    double Position,
    int DisplayedPictures,
    int DecodedVideo,
    int ReadBytes);

internal sealed record StreamHealthEvaluation(
    StreamHealthEvaluationKind Kind,
    bool HasProgressed,
    string Reason) {
    public bool RequiresRecovery => Kind == StreamHealthEvaluationKind.Stale;
}

internal sealed class StreamHealthState {
    public long? LastTime { get; set; }
    public double LastPosition { get; set; }
    public int LastDisplayedPictures { get; set; }
    public int LastDecodedVideo { get; set; }
    public int LastReadBytes { get; set; }
    public DateTimeOffset LastSampleAt { get; set; }
    public DateTimeOffset? PlaybackConfirmedAt { get; set; }
    public DateTimeOffset? VideoOutputConfirmedAt { get; set; }
    public DateTimeOffset LastProgressAt { get; set; }
    public int ConsecutiveUnhealthySamples { get; set; }
    public StreamLifecyclePhase LifecyclePhase { get; set; } = StreamLifecyclePhase.Stopped;
}

internal enum StreamLifecyclePhase {
    Stopped,
    Starting,
    Running,
    Stopping,
    Restarting
}

internal static class StreamHealthEvaluator {
    public const string VideoOutputNotConfirmedReason = "video_output_not_confirmed";

    public static bool HasVideoEvidence(StreamHealthSample sample) {
        return sample.HasVideoOutput || sample.DisplayedPictures > 0 || sample.DecodedVideo > 0;
    }

    public static void StartPlayback(StreamHealthState state, StreamHealthSample sample) {
        state.LastTime = sample.MediaTime;
        state.LastPosition = sample.Position;
        state.LastDisplayedPictures = sample.DisplayedPictures;
        state.LastDecodedVideo = sample.DecodedVideo;
        state.LastReadBytes = sample.ReadBytes;
        state.LastSampleAt = sample.Timestamp;
        state.PlaybackConfirmedAt = sample.Timestamp;
        state.VideoOutputConfirmedAt = HasVideoEvidence(sample) ? sample.Timestamp : null;
        state.LastProgressAt = sample.Timestamp;
        state.ConsecutiveUnhealthySamples = 0;
    }

    public static StreamHealthEvaluation Observe(
        StreamHealthState state,
        StreamHealthSample sample,
        TimeSpan startupGracePeriod,
        TimeSpan staleAfter,
        int unhealthySampleLimit) {
        var hasProgressed = !state.LastTime.HasValue ||
                            sample.MediaTime != state.LastTime.Value ||
                            Math.Abs(sample.Position - state.LastPosition) > 0.0001 ||
                            sample.DisplayedPictures > state.LastDisplayedPictures ||
                            sample.DecodedVideo > state.LastDecodedVideo ||
                            sample.ReadBytes > state.LastReadBytes;

        state.LastTime = sample.MediaTime;
        state.LastPosition = sample.Position;
        state.LastDisplayedPictures = sample.DisplayedPictures;
        state.LastDecodedVideo = sample.DecodedVideo;
        state.LastReadBytes = sample.ReadBytes;
        state.LastSampleAt = sample.Timestamp;
        if (state.VideoOutputConfirmedAt is null && HasVideoEvidence(sample)) {
            state.VideoOutputConfirmedAt = sample.Timestamp;
        }

        if (state.PlaybackConfirmedAt is null) {
            return new StreamHealthEvaluation(
                StreamHealthEvaluationKind.Unhealthy,
                HasProgressed: false,
                "playback has not been confirmed");
        }

        if (sample.Timestamp - state.PlaybackConfirmedAt.Value < startupGracePeriod) {
            return new StreamHealthEvaluation(
                StreamHealthEvaluationKind.StartupGracePeriod,
                hasProgressed,
                "playback is within the startup grace period");
        }

        var isHealthy = sample.IsPlaying && sample.HasVideoOutput && hasProgressed;
        if (isHealthy) {
            state.LastProgressAt = sample.Timestamp;
            state.ConsecutiveUnhealthySamples = 0;
            return new StreamHealthEvaluation(
                StreamHealthEvaluationKind.Healthy,
                HasProgressed: true,
                "playback progress detected");
        }

        state.ConsecutiveUnhealthySamples++;
        var staleDuration = sample.Timestamp - state.LastProgressAt;
        var isStale = state.ConsecutiveUnhealthySamples >= Math.Max(1, unhealthySampleLimit) &&
                      staleDuration >= staleAfter;
        return new StreamHealthEvaluation(
            isStale ? StreamHealthEvaluationKind.Stale : StreamHealthEvaluationKind.Unhealthy,
            HasProgressed: false,
            state.VideoOutputConfirmedAt is null
                ? VideoOutputNotConfirmedReason
                : sample.HasVideoOutput
                    ? "playback has not advanced"
                    : "video output is not available");
    }
}
