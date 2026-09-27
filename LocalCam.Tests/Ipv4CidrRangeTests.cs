using System.Net;
using LocalCam.Networking;
using Xunit;

namespace LocalCam.Tests;

public sealed class Ipv4CidrRangeTests {
    [Fact]
    public void CreatesNetworkAndEnumeratesOnlyUsableHosts() {
        Assert.True(Ipv4CidrRange.TryCreate(IPAddress.Parse("192.168.254.17"), 24, out var range));

        Assert.Equal("192.168.254.0/24", range.ToString());
        Assert.Equal(254, range.EnumerateHosts().Count());
        Assert.True(range.Contains(IPAddress.Parse("192.168.254.17")));
        Assert.False(range.Contains(IPAddress.Parse("192.168.253.17")));
    }

    [Theory]
    [InlineData("192.168.1.1", 0)]
    [InlineData("192.168.1.1", 31)]
    [InlineData("2001:db8::1", 24)]
    public void RejectsUnsupportedAddressOrPrefix(string address, int prefix) {
        Assert.False(Ipv4CidrRange.TryCreate(IPAddress.Parse(address), prefix, out _));
    }
}
