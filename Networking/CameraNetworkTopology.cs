using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace LocalCam.Networking;

internal sealed record CameraNetworkInterfaceSummary(
    string Name,
    string Kind,
    string Ipv4Address,
    string Prefix,
    bool HasGateway,
    IReadOnlyList<string> DnsAddresses,
    IReadOnlyList<string> DhcpAddresses);

internal static class CameraNetworkTopology {
    public static IReadOnlyList<CameraNetworkInterfaceSummary> GetInterfaces() {
        var results = new List<CameraNetworkInterfaceSummary>();
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces()) {
            if (adapter.OperationalStatus != OperationalStatus.Up
                || adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback) {
                continue;
            }

            IPInterfaceProperties properties;
            try {
                properties = adapter.GetIPProperties();
            }
            catch (NetworkInformationException) {
                continue;
            }

            var kind = Classify(adapter);
            var gateway = properties.GatewayAddresses.Any(static entry =>
                entry.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.Any.Equals(entry.Address));
            var dnsAddresses = properties.DnsAddresses
                .Where(static address => address.AddressFamily == AddressFamily.InterNetwork)
                .Select(static address => address.ToString())
                .ToArray();
            var dhcpAddresses = properties.DhcpServerAddresses
                .Where(static address => address.AddressFamily == AddressFamily.InterNetwork)
                .Select(static address => address.ToString())
                .ToArray();
            foreach (var unicast in properties.UnicastAddresses.Where(static item =>
                         item.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(item.Address))) {
                results.Add(new CameraNetworkInterfaceSummary(
                    adapter.Name,
                    kind,
                    unicast.Address.ToString(),
                    unicast.PrefixLength.ToString(),
                    gateway,
                    dnsAddresses,
                    dhcpAddresses));
            }
        }
        return results;
    }

    public static string ClassifyRoute(IPAddress target, IReadOnlyList<CameraNetworkInterfaceSummary> interfaces) {
        try {
            using var routeProbe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            routeProbe.Connect(target, 9);
            if (routeProbe.LocalEndPoint is not IPEndPoint localEndPoint) {
                return "no-local-route-evidence";
            }

            var selectedInterface = interfaces.FirstOrDefault(item =>
                IPAddress.TryParse(item.Ipv4Address, out var localAddress) && localAddress.Equals(localEndPoint.Address));
            if (selectedInterface is null) {
                return "route-interface-not-enumerated";
            }

            if (IsInPrefix(target, IPAddress.Parse(selectedInterface.Ipv4Address), int.Parse(selectedInterface.Prefix))) {
                return $"direct-subnet-{selectedInterface.Kind}";
            }

            return $"routed-via-{selectedInterface.Kind}";
        }
        catch (SocketException) {
            return "no-local-route-evidence";
        }
    }

    private static string Classify(NetworkInterface adapter) {
        if (adapter.NetworkInterfaceType == NetworkInterfaceType.Wireless80211) {
            return "wifi";
        }
        if (adapter.NetworkInterfaceType == NetworkInterfaceType.Tunnel) {
            return "tunnel-or-vpn";
        }

        var text = $"{adapter.Name} {adapter.Description}";
        return text.Contains("VMware", StringComparison.OrdinalIgnoreCase)
            || text.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Virtual", StringComparison.OrdinalIgnoreCase)
            ? "virtual-network"
            : "wired-or-other";
    }

    private static bool IsInPrefix(IPAddress target, IPAddress local, int prefix) {
        var targetBytes = target.GetAddressBytes();
        var localBytes = local.GetAddressBytes();
        for (var index = 0; index < 4; index++) {
            var bits = Math.Clamp(prefix - index * 8, 0, 8);
            var mask = bits == 0 ? 0 : 0xff << (8 - bits);
            if ((targetBytes[index] & mask) != (localBytes[index] & mask)) {
                return false;
            }
        }
        return true;
    }
}
