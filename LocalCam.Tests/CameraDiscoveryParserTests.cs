using System.Buffers.Binary;
using System.Net;
using System.Text;
using LocalCam.Networking;
using Xunit;

namespace LocalCam.Tests;

public sealed class CameraDiscoveryParserTests {
    [Fact]
    public void TryParseOnvifProbeMatches_RequiresNetworkVideoTransmitterAndXAddr() {
        const string payload = """
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                        xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
                        xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
              <s:Body><d:ProbeMatches><d:ProbeMatch>
                <d:Types>dn:NetworkVideoTransmitter</d:Types>
                <d:XAddrs>http://192.168.1.60/onvif/device_service</d:XAddrs>
              </d:ProbeMatch></d:ProbeMatches></s:Body>
            </s:Envelope>
            """;

        var parsed = CameraDiscoveryParsers.TryParseOnvifProbeMatches(payload, out var addresses);

        Assert.True(parsed);
        Assert.Equal("192.168.1.60", addresses.Single().Host);
    }

    [Theory]
    [InlineData("<Envelope><ProbeMatch><Types>NetworkVideoTransmitter</Types><XAddrs>http://192.168.1.60/x</XAddrs></ProbeMatch></Envelope>")]
    [InlineData("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:dn=\"urn:example:wrong\"><s:Body><d:ProbeMatches><d:ProbeMatch><d:Types>dn:NetworkVideoTransmitter</d:Types><d:XAddrs>http://192.168.1.60/x</d:XAddrs></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>")]
    [InlineData("not xml")]
    public void TryParseOnvifProbeMatches_RejectsMalformedOrWrongNamespace(string payload) {
        Assert.False(CameraDiscoveryParsers.TryParseOnvifProbeMatches(payload, out var addresses));
        Assert.Empty(addresses);
    }

    [Fact]
    public void TryParseSsdpResponse_RequiresValidSearchResponseHeaders() {
        const string payload = """
            HTTP/1.1 200 OK
            CACHE-CONTROL: max-age=120
            LOCATION: http://192.168.1.70:80/rootDesc.xml
            ST: urn:schemas-upnp-org:device:Basic:1
            USN: uuid:camera-1::urn:schemas-upnp-org:device:Basic:1

            """;

        var parsed = CameraDiscoveryParsers.TryParseSsdpResponse(payload, out var response);

        Assert.True(parsed);
        Assert.NotNull(response);
        Assert.Equal("192.168.1.70", response.Location.Host);
        Assert.Equal("urn:schemas-upnp-org:device:Basic:1", response.SearchTarget);
    }

    [Theory]
    [InlineData("HTTP/1.1 2000 OK\r\nLOCATION: http://192.168.1.70/root.xml\r\nST: ssdp:all\r\nUSN: uuid:a\r\n\r\n")]
    [InlineData("HTTP/1.1 200 OK\r\nLOCATION: http://user@192.168.1.70/root.xml\r\nST: ssdp:all\r\nUSN: uuid:a\r\n\r\n")]
    [InlineData("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.70/root.xml\r\nUSN: uuid:a\r\n\r\n")]
    public void TryParseSsdpResponse_RejectsMalformedOrUnsafeResponse(string payload) {
        Assert.False(CameraDiscoveryParsers.TryParseSsdpResponse(payload, out _));
    }

    [Fact]
    public void IsCameraDescription_RecognizesVideoDeviceAndRejectsUnrelatedDevice() {
        const string camera = "<root><device><deviceType>urn:example:device:NetworkVideoTransmitter:1</deviceType></device></root>";
        const string printer = "<root><device><deviceType>urn:example:device:Printer:1</deviceType></device></root>";

        Assert.True(CameraDiscoveryParsers.IsCameraDescription(camera));
        Assert.False(CameraDiscoveryParsers.IsCameraDescription(printer));
    }

    [Fact]
    public void ParseDnsSdServices_ResolvesPtrSrvTxtAndAddressRecords() {
        var packet = BuildMdnsResponse();

        var service = Assert.Single(CameraDiscoveryParsers.ParseDnsSdServices(packet));

        Assert.Equal("Front._rtsp._tcp.local", service.InstanceName);
        Assert.Equal("_rtsp._tcp.local", service.ServiceType);
        Assert.Equal("camera.local", service.TargetHost);
        Assert.Equal(554, service.Port);
        Assert.Contains("path=/stream1", service.TextRecords);
        Assert.Equal(IPAddress.Parse("192.168.1.80"), Assert.Single(service.Addresses));
    }

    [Fact]
    public void ParseDnsSdServices_RejectsTruncatedPackets() {
        Assert.Empty(CameraDiscoveryParsers.ParseDnsSdServices(new byte[] { 0, 1, 0, 0 }));
        Assert.Empty(CameraDiscoveryParsers.ParseDnsSdServices(BuildMdnsResponse()[..^2]));
    }

    [Fact]
    public void ParseDnsSdServices_RejectsOverlongExpandedDnsNames() {
        var packet = new byte[300];
        packet[2] = 0x80;
        packet[7] = 1;
        var offset = 12;
        packet[offset++] = 63;
        offset += 63;
        packet[offset++] = 63;
        offset += 63;
        packet[offset++] = 63;
        offset += 63;
        packet[offset++] = 63;
        offset += 63;
        packet[offset++] = 0;

        Assert.Empty(CameraDiscoveryParsers.ParseDnsSdServices(packet));
    }

    [Fact]
    public void TryParseRtspOptionsResponse_RequiresRtspStatusAndMatchingCSeq() {
        const string good = "RTSP/1.0 200 OK\r\nCSeq: 7\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n";
        const string wrongSequence = "RTSP/1.0 200 OK\r\nCSeq: 8\r\n\r\n";
        const string http = "HTTP/1.1 200 OK\r\nCSeq: 7\r\n\r\n";

        Assert.True(CameraDiscoveryParsers.TryParseRtspOptionsResponse(good, 7, out var response));
        Assert.Equal(200, response!.StatusCode);
        Assert.False(CameraDiscoveryParsers.TryParseRtspOptionsResponse(wrongSequence, 7, out _));
        Assert.False(CameraDiscoveryParsers.TryParseRtspOptionsResponse(http, 7, out _));
    }

    [Fact]
    public void TryParseRtspResponse_RecognizesAuthenticationChallenge() {
        const string challenge = "RTSP/1.0 401 Unauthorized\r\nCSeq: 3\r\nWWW-Authenticate: Digest realm=\"camera\", nonce=\"abc\"\r\n\r\n";

        Assert.True(CameraDiscoveryParsers.TryParseRtspResponse(challenge, 3, out var response));
        Assert.True(response!.RequiresAuthentication);
        Assert.True(response.HasAuthenticationChallenge);
        Assert.Equal(401, response.StatusCode);
    }

    [Fact]
    public void TryParseRtspResponse_DoesNotTreatWrongSequenceOrHttpAsRtsp() {
        const string wrongSequence = "RTSP/1.0 401 Unauthorized\r\nCSeq: 4\r\nWWW-Authenticate: Digest realm=\"camera\"\r\n\r\n";
        const string http = "HTTP/1.1 401 Unauthorized\r\nCSeq: 3\r\nWWW-Authenticate: Basic\r\n\r\n";

        Assert.False(CameraDiscoveryParsers.TryParseRtspResponse(wrongSequence, 3, out _));
        Assert.False(CameraDiscoveryParsers.TryParseRtspResponse(http, 3, out _));
    }

    private static byte[] BuildMdnsResponse() {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.ASCII, leaveOpen: true);
        WriteUInt16(writer, 0);
        WriteUInt16(writer, 0x8400);
        WriteUInt16(writer, 0);
        WriteUInt16(writer, 4);
        WriteUInt16(writer, 0);
        WriteUInt16(writer, 0);

        WriteRecord(writer, "_rtsp._tcp.local", 12, data => WriteName(data, "Front._rtsp._tcp.local"));
        WriteRecord(writer, "Front._rtsp._tcp.local", 33, data => {
            WriteUInt16(data, 0);
            WriteUInt16(data, 0);
            WriteUInt16(data, 554);
            WriteName(data, "camera.local");
        });
        WriteRecord(writer, "Front._rtsp._tcp.local", 16, data => {
            var entry = Encoding.UTF8.GetBytes("path=/stream1");
            data.Write((byte)entry.Length);
            data.Write(entry);
        });
        WriteRecord(writer, "camera.local", 1, data => data.Write(new byte[] { 192, 168, 1, 80 }));
        writer.Flush();
        return stream.ToArray();
    }

    private static void WriteRecord(BinaryWriter writer, string name, ushort type, Action<BinaryWriter> writeData) {
        WriteName(writer, name);
        WriteUInt16(writer, type);
        WriteUInt16(writer, 1);
        writer.Write(new byte[] { 0, 0, 0, 120 });

        using var dataStream = new MemoryStream();
        using (var dataWriter = new BinaryWriter(dataStream, Encoding.ASCII, leaveOpen: true)) {
            writeData(dataWriter);
            dataWriter.Flush();
        }

        WriteUInt16(writer, checked((ushort)dataStream.Length));
        writer.Write(dataStream.ToArray());
    }

    private static void WriteName(BinaryWriter writer, string name) {
        foreach (var label in name.Split('.')) {
            var bytes = Encoding.ASCII.GetBytes(label);
            writer.Write((byte)bytes.Length);
            writer.Write(bytes);
        }

        writer.Write((byte)0);
    }

    private static void WriteUInt16(BinaryWriter writer, ushort value) {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        writer.Write(bytes);
    }
}
