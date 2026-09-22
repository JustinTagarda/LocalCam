using LocalCam;
using Xunit;

namespace LocalCam.Tests;

public sealed class StreamHealthEvaluatorTests {
    [Fact]
    public void Observe_DoesNotRecoverDuringStartupGracePeriod() {
        var startedAt = DateTimeOffset.UtcNow;
        var state = new StreamHealthState();
        StreamHealthEvaluator.StartPlayback(state, Sample(startedAt, hasVideoOutput: false));

        var evaluation = StreamHealthEvaluator.Observe(
            state,
            Sample(startedAt.AddSeconds(2), hasVideoOutput: false),
            startupGracePeriod: TimeSpan.FromSeconds(5),
            staleAfter: TimeSpan.FromSeconds(8),
            unhealthySampleLimit: 3);

        Assert.Equal(StreamHealthEvaluationKind.StartupGracePeriod, evaluation.Kind);
        Assert.False(evaluation.RequiresRecovery);
    }

    [Fact]
    public void Observe_RequiresConsecutiveUnhealthySamplesBeforeRecovery() {
        var startedAt = DateTimeOffset.UtcNow;
        var state = new StreamHealthState();
        StreamHealthEvaluator.StartPlayback(state, Sample(startedAt, hasVideoOutput: true));

        var first = StreamHealthEvaluator.Observe(state, Sample(startedAt.AddSeconds(6), hasVideoOutput: false), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(8), 3);
        var second = StreamHealthEvaluator.Observe(state, Sample(startedAt.AddSeconds(8), hasVideoOutput: false), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(8), 3);
        var third = StreamHealthEvaluator.Observe(state, Sample(startedAt.AddSeconds(10), hasVideoOutput: false), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(8), 3);

        Assert.Equal(StreamHealthEvaluationKind.Unhealthy, first.Kind);
        Assert.Equal(StreamHealthEvaluationKind.Unhealthy, second.Kind);
        Assert.Equal(StreamHealthEvaluationKind.Stale, third.Kind);
        Assert.True(third.RequiresRecovery);
    }

    [Fact]
    public void Observe_ProgressResetsTheUnhealthySampleCount() {
        var startedAt = DateTimeOffset.UtcNow;
        var state = new StreamHealthState();
        StreamHealthEvaluator.StartPlayback(state, Sample(startedAt, hasVideoOutput: true));

        StreamHealthEvaluator.Observe(state, Sample(startedAt.AddSeconds(6), hasVideoOutput: false), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(8), 3);
        var healthy = StreamHealthEvaluator.Observe(
            state,
            Sample(startedAt.AddSeconds(7), hasVideoOutput: true, mediaTime: 1, displayedPictures: 1, decodedVideo: 1, readBytes: 1),
            TimeSpan.FromSeconds(5),
            TimeSpan.FromSeconds(8),
            3);

        Assert.Equal(StreamHealthEvaluationKind.Healthy, healthy.Kind);
        Assert.Equal(0, state.ConsecutiveUnhealthySamples);
    }

    private static StreamHealthSample Sample(
        DateTimeOffset timestamp,
        bool hasVideoOutput,
        long mediaTime = 0,
        double position = 0,
        int displayedPictures = 0,
        int decodedVideo = 0,
        int readBytes = 0) {
        return new StreamHealthSample(
            timestamp,
            IsPlaying: true,
            hasVideoOutput,
            mediaTime,
            position,
            displayedPictures,
            decodedVideo,
            readBytes);
    }
}
