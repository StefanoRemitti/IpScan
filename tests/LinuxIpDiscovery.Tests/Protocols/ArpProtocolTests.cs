using System.Net;
using System.Net.NetworkInformation;
using LinuxIpDiscovery.Core.Protocols;

namespace LinuxIpDiscovery.Tests.Protocols;

public sealed class ArpProtocolTests
{
    [Fact]
    public void BuildAndParse_Request_Roundtrip()
    {
        var mac = PhysicalAddress.Parse("001122334455");
        var payload = ArpBuilder.BuildRequest(mac, IPAddress.Parse("0.0.0.0"), IPAddress.Parse("192.168.1.10"));
        var parsed = ArpParser.Parse(payload);

        Assert.Equal((ushort)1, parsed.Operation);
        Assert.Equal(mac, parsed.SenderMac);
        Assert.Equal(IPAddress.Any, parsed.SenderIp);
        Assert.Equal(IPAddress.Parse("192.168.1.10"), parsed.TargetIp);
        Assert.Equal(ArpKind.Probe, ArpParser.Classify(parsed));
    }

    [Fact]
    public void Classifies_Gratuitous_Arp()
    {
        var packet = new ArpPacket(1, 0x0800, 6, 4, 1,
            PhysicalAddress.Parse("AABBCCDDEEFF"),
            IPAddress.Parse("10.0.0.5"),
            PhysicalAddress.None,
            IPAddress.Parse("10.0.0.5"));

        Assert.Equal(ArpKind.Gratuitous, ArpParser.Classify(packet));
    }
}
