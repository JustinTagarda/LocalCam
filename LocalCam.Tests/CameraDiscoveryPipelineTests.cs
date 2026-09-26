using LocalCam.Networking;
using Xunit;

namespace LocalCam.Tests;

public sealed class CameraDiscoveryPipelineTests {
    [Fact]
    public void TryParseDetectionMethod_AcceptsPersistedRtspOptionsMethod() {
        var parsed = TapoCameraScanner.TryParseDetectionMethod("RtspOptionsProbe", out var method);

        Assert.True(parsed);
        Assert.Equal(TapoDetectionMethod.RtspOptionsProbe, method);
    }

    [Theory]
    [InlineData("nonexistent")]
    [InlineData("999")]
    public void TryParseDetectionMethod_RejectsUnknownPersistedMethods(string value) {
        Assert.False(TapoCameraScanner.TryParseDetectionMethod(value, out _));
    }
}
