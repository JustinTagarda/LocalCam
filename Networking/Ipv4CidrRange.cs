using System.Net;
using System.Net.Sockets;

namespace LocalCam.Networking;

internal readonly record struct Ipv4CidrRange(uint NetworkAddress, int PrefixLength) {
    public static bool TryCreate(IPAddress address, int prefixLength, out Ipv4CidrRange range) {
        if (address.AddressFamily != AddressFamily.InterNetwork || prefixLength is < 1 or > 30) {
            range = default;
            return false;
        }

        range = new Ipv4CidrRange(ToUInt32(address) & PrefixMask(prefixLength), prefixLength);
        return true;
    }

    public bool Contains(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetwork
        && (ToUInt32(address) & PrefixMask(PrefixLength)) == NetworkAddress;

    public IEnumerable<IPAddress> EnumerateHosts() {
        var hostCount = (1U << (32 - PrefixLength)) - 2U;
        for (uint offset = 1; offset <= hostCount; offset++) {
            yield return FromUInt32(NetworkAddress + offset);
        }
    }

    public override string ToString() => $"{FromUInt32(NetworkAddress)}/{PrefixLength}";

    private static uint PrefixMask(int prefix) => prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
    private static uint ToUInt32(IPAddress address) => BitConverter.ToUInt32(address.GetAddressBytes().Reverse().ToArray());
    private static IPAddress FromUInt32(uint value) => new(BitConverter.GetBytes(value).Reverse().ToArray());
}
