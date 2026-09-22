using LocalCam;
using Xunit;

namespace LocalCam.Tests;

public sealed class StreamFailureClassificationTests {
    [Theory]
    [InlineData("401 Unauthorized")]
    [InlineData("RTSP authentication failed")]
    [InlineData("invalid password")]
    public void Classify_CredentialFailures_RequestsSettings(string reason) {
        var failure = StreamFailureClassifier.Classify(reason, null, null);

        Assert.Equal(StreamFailureKind.Credential, failure.Kind);
        Assert.True(failure.RequiresSettings);
        Assert.NotNull(failure.Suggestion);
    }

    [Fact]
    public void Classify_NetworkFailure_StaysOnTheCameraCard() {
        var failure = StreamFailureClassifier.Classify("connection refused", null, null);

        Assert.Equal(StreamFailureKind.Network, failure.Kind);
        Assert.False(failure.RequiresSettings);
        Assert.Equal("Check the camera's network connection.", failure.Suggestion);
    }

    [Fact]
    public void Classify_DecodeFailure_ProvidesDeviceSpecificSuggestion() {
        var failure = StreamFailureClassifier.Classify(null, "decoder error", null);

        Assert.Equal(StreamFailureKind.DeviceOrDecode, failure.Kind);
        Assert.False(failure.RequiresSettings);
        Assert.NotNull(failure.Suggestion);
    }

    [Fact]
    public void Classify_GraphicsOutputFailure_StaysOnTheCameraCard() {
        var failure = StreamFailureClassifier.Classify(null, null, "SetThumbNailClip failed: 0x800706f4");

        Assert.Equal(StreamFailureKind.DeviceOrDecode, failure.Kind);
        Assert.False(failure.RequiresSettings);
        Assert.NotNull(failure.Suggestion);
    }

    [Fact]
    public void Classify_UnknownFailure_HasNoUnsupportedSuggestion() {
        var failure = StreamFailureClassifier.Classify("media player returned false", null, null);

        Assert.Equal(StreamFailureKind.Unknown, failure.Kind);
        Assert.False(failure.RequiresSettings);
        Assert.Null(failure.Suggestion);
    }
}
