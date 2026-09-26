using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace LocalCam.Networking;

internal static class CameraDiscoveryParsers {
    private const int MaxXmlBytes = 64 * 1024;
    private const int MaxSsdpBytes = 16 * 1024;
    private const int MaxDnsRecords = 1024;

    internal sealed record SsdpResponse(string SearchTarget, string UniqueServiceName, Uri Location);
    internal sealed record DnsSdService(string InstanceName, string ServiceType, string TargetHost, int Port, IReadOnlyList<string> TextRecords, IReadOnlyList<IPAddress> Addresses);
    internal sealed record RtspOptionsResponse(string Version, int StatusCode, IReadOnlyDictionary<string, string> Headers);

    public static bool TryParseOnvifProbeMatches(string payload, out IReadOnlyList<Uri> serviceAddresses) {
        serviceAddresses = Array.Empty<Uri>();
        if (!TryLoadXml(payload, MaxXmlBytes, out var document)
            || document.Root?.Name.LocalName != "Envelope"
            || document.Root.Name.NamespaceName != "http://www.w3.org/2003/05/soap-envelope") {
            return false;
        }

        XNamespace discoveryNamespace = "http://schemas.xmlsoap.org/ws/2005/04/discovery";
        var matches = document.Descendants(discoveryNamespace + "ProbeMatch").ToArray();
        if (matches.Length == 0) {
            return false;
        }

        var addresses = new List<Uri>();
        foreach (var match in matches) {
            var types = match.Elements(discoveryNamespace + "Types").FirstOrDefault()?.Value ?? string.Empty;
            if (!types.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
                    .Any(type => IsOnvifNetworkVideoType(type, match))) {
                continue;
            }

            var xaddrs = match.Elements(discoveryNamespace + "XAddrs").FirstOrDefault()?.Value;
            if (string.IsNullOrWhiteSpace(xaddrs)) {
                continue;
            }

            foreach (var value in xaddrs.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)) {
                if (Uri.TryCreate(value, UriKind.Absolute, out var address)
                    && address.Scheme is "http" or "https"
                    && string.IsNullOrEmpty(address.UserInfo)) {
                    addresses.Add(address);
                }
            }
        }

        serviceAddresses = addresses.DistinctBy(static address => address.AbsoluteUri, StringComparer.OrdinalIgnoreCase).ToArray();
        return serviceAddresses.Count > 0;
    }

    public static bool TryParseSsdpResponse(string payload, out SsdpResponse? response) {
        response = null;
        if (Encoding.UTF8.GetByteCount(payload) > MaxSsdpBytes) {
            return false;
        }

        using var reader = new StringReader(payload);
        var statusLine = reader.ReadLine();
        if (statusLine is null) {
            return false;
        }

        var statusParts = statusLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (statusParts.Length < 2
            || statusParts[0] != "HTTP/1.1"
            || statusParts[1] != "200") {
            return false;
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (reader.ReadLine() is { } line && line.Length > 0) {
            var separator = line.IndexOf(':');
            if (separator <= 0) {
                continue;
            }

            var name = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            if (name.Length > 0 && !headers.ContainsKey(name)) {
                headers[name] = value;
            }
        }

        if (!headers.TryGetValue("ST", out var searchTarget)
            || !headers.TryGetValue("USN", out var uniqueServiceName)
            || !headers.TryGetValue("LOCATION", out var locationText)
            || !Uri.TryCreate(locationText, UriKind.Absolute, out var location)
            || location.Scheme is not ("http" or "https")
            || !string.IsNullOrEmpty(location.UserInfo)) {
            return false;
        }

        response = new SsdpResponse(searchTarget, uniqueServiceName, location);
        return true;
    }

    public static bool IsCameraDescription(string payload) {
        if (!TryLoadXml(payload, MaxXmlBytes, out var document)) {
            return false;
        }

        var cameraTerms = new[] { "camera", "video", "surveillance", "networkvideotransmitter", "nvr", "dvr" };
        return document.Descendants()
            .Where(static element => element.Name.LocalName is "deviceType" or "serviceType" or "friendlyName" or "modelName")
            .Select(static element => element.Value)
            .Any(value => cameraTerms.Any(term => value.Contains(term, StringComparison.OrdinalIgnoreCase)));
    }

    public static IReadOnlyList<DnsSdService> ParseDnsSdServices(ReadOnlySpan<byte> packet) {
        if (packet.Length < 12 || packet.Length > 9000) {
            return Array.Empty<DnsSdService>();
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        if ((flags & 0x8000) == 0) {
            return Array.Empty<DnsSdService>();
        }

        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(packet[4..]);
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(packet[6..]);
        var authorityCount = BinaryPrimitives.ReadUInt16BigEndian(packet[8..]);
        var additionalCount = BinaryPrimitives.ReadUInt16BigEndian(packet[10..]);
        if (questionCount > 128 || answerCount + authorityCount + additionalCount > MaxDnsRecords) {
            return Array.Empty<DnsSdService>();
        }

        var offset = 12;
        for (var i = 0; i < questionCount; i++) {
            if (!TryReadDnsName(packet, ref offset, out _) || !TrySkip(packet, ref offset, 4)) {
                return Array.Empty<DnsSdService>();
            }
        }

        var records = new List<DnsRecord>(answerCount + authorityCount + additionalCount);
        var recordCount = answerCount + authorityCount + additionalCount;
        for (var i = 0; i < recordCount; i++) {
            if (!TryReadDnsName(packet, ref offset, out var name) || offset + 10 > packet.Length) {
                return Array.Empty<DnsSdService>();
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(packet[offset..]);
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 8)..]);
            offset += 10;
            if (offset + dataLength > packet.Length) {
                return Array.Empty<DnsSdService>();
            }

            var dataStart = offset;
            string? targetName = null;
            var port = 0;
            IReadOnlyList<string> text = Array.Empty<string>();
            IPAddress? address = null;

            if (type == 12) {
                var nameOffset = dataStart;
                if (TryReadDnsName(packet, ref nameOffset, out var target) && nameOffset <= dataStart + dataLength) {
                    targetName = target;
                }
            }
            else if (type == 33 && dataLength >= 7) {
                port = BinaryPrimitives.ReadUInt16BigEndian(packet[(dataStart + 4)..]);
                var nameOffset = dataStart + 6;
                if (TryReadDnsName(packet, ref nameOffset, out var target) && nameOffset <= dataStart + dataLength) {
                    targetName = target;
                }
            }
            else if (type == 16) {
                text = ParseDnsTxt(packet.Slice(dataStart, dataLength));
            }
            else if (type == 1 && dataLength == 4) {
                address = new IPAddress(packet.Slice(dataStart, dataLength));
            }
            else if (type == 28 && dataLength == 16) {
                address = new IPAddress(packet.Slice(dataStart, dataLength));
            }

            records.Add(new DnsRecord(name, type, targetName, port, text, address));
            offset += dataLength;
        }

        var services = new List<DnsSdService>();
        foreach (var pointer in records.Where(static record => record.Type == 12 && record.TargetName is not null)) {
            var instance = pointer.TargetName!;
            var srv = records.FirstOrDefault(record => record.Type == 33 && NameEquals(record.Name, instance));
            if (srv?.TargetName is null || srv.Port is < 1 or > 65535) {
                continue;
            }

            var addresses = records
                .Where(record => record.Address is not null && NameEquals(record.Name, srv.TargetName))
                .Select(static record => record.Address!)
                .Distinct()
                .ToArray();
            var txt = records.FirstOrDefault(record => record.Type == 16 && NameEquals(record.Name, instance))?.Text ?? Array.Empty<string>();
            services.Add(new DnsSdService(instance, pointer.Name, srv.TargetName, srv.Port, txt, addresses));
        }

        return services
            .DistinctBy(static service => $"{service.InstanceName}|{service.TargetHost}|{service.Port}", StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static bool TryParseRtspOptionsResponse(string payload, int expectedCSeq, out RtspOptionsResponse? response) {
        response = null;
        if (payload.Length > 16 * 1024) {
            return false;
        }

        using var reader = new StringReader(payload);
        var statusLine = reader.ReadLine();
        if (statusLine is null) {
            return false;
        }

        var parts = statusLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || parts[0] is not ("RTSP/1.0" or "RTSP/2.0")
            || !int.TryParse(parts[1], out var statusCode)
            || statusCode is < 100 or > 599) {
            return false;
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (reader.ReadLine() is { } line && line.Length > 0) {
            var separator = line.IndexOf(':');
            if (separator <= 0) {
                continue;
            }

            var name = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            if (name.Length > 0 && !headers.ContainsKey(name)) {
                headers[name] = value;
            }
        }

        if (!headers.TryGetValue("CSeq", out var cseqText)
            || !int.TryParse(cseqText, out var cseq)
            || cseq != expectedCSeq) {
            return false;
        }

        response = new RtspOptionsResponse(parts[0], statusCode, headers);
        return true;
    }

    private static bool TryLoadXml(string payload, int maxBytes, out XDocument document) {
        document = new XDocument();
        if (Encoding.UTF8.GetByteCount(payload) > maxBytes) {
            return false;
        }

        try {
            using var stringReader = new StringReader(payload);
            using var xmlReader = XmlReader.Create(stringReader, new XmlReaderSettings {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = maxBytes,
                MaxCharactersFromEntities = 0
            });
            document = XDocument.Load(xmlReader, LoadOptions.None);
            return true;
        }
        catch (XmlException) {
            return false;
        }
    }

    private static IReadOnlyList<string> ParseDnsTxt(ReadOnlySpan<byte> data) {
        var entries = new List<string>();
        var offset = 0;
        while (offset < data.Length) {
            var length = data[offset++];
            if (offset + length > data.Length) {
                return Array.Empty<string>();
            }

            entries.Add(Encoding.UTF8.GetString(data.Slice(offset, length)));
            offset += length;
        }

        return entries;
    }

    private static bool TryReadDnsName(ReadOnlySpan<byte> packet, ref int offset, out string name) {
        name = string.Empty;
        var labels = new List<string>();
        var position = offset;
        var resumeOffset = -1;
        var jumps = 0;
        var expandedLength = 0;

        while (position < packet.Length) {
            var length = packet[position++];
            if (length == 0) {
                if (resumeOffset < 0) {
                    offset = position;
                }
                else {
                    offset = resumeOffset;
                }

                name = string.Join('.', labels);
                return true;
            }

            if ((length & 0xC0) == 0xC0) {
                if (position >= packet.Length || ++jumps > 16) {
                    return false;
                }

                var pointer = ((length & 0x3F) << 8) | packet[position++];
                if (pointer >= packet.Length) {
                    return false;
                }

                if (resumeOffset < 0) {
                    resumeOffset = position;
                }
                position = pointer;
                continue;
            }

            if ((length & 0xC0) != 0 || length > 63 || position + length > packet.Length) {
                return false;
            }

            expandedLength += length + 1;
            if (expandedLength > 255 || labels.Count >= 127) {
                return false;
            }

            labels.Add(Encoding.UTF8.GetString(packet.Slice(position, length)));
            position += length;
        }

        return false;
    }

    private static bool TrySkip(ReadOnlySpan<byte> packet, ref int offset, int count) {
        if (count < 0 || offset + count > packet.Length) {
            return false;
        }

        offset += count;
        return true;
    }

    private static bool IsOnvifNetworkVideoType(string type, XElement match) {
        var separator = type.IndexOf(':');
        if (separator == 0) {
            return false;
        }

        var localName = separator >= 0 ? type[(separator + 1)..] : type;
        if (!localName.Equals("NetworkVideoTransmitter", StringComparison.OrdinalIgnoreCase)) {
            return false;
        }

        var namespaceName = separator >= 0
            ? match.GetNamespaceOfPrefix(type[..separator])?.NamespaceName
            : match.GetDefaultNamespace().NamespaceName;
        return namespaceName == "http://www.onvif.org/ver10/network/wsdl";
    }

    private static bool NameEquals(string left, string right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private sealed record DnsRecord(string Name, ushort Type, string? TargetName, int Port, IReadOnlyList<string> Text, IPAddress? Address);
}
