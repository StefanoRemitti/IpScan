using System.Net;
using LinuxIpDiscovery.Core.Protocols;

namespace LinuxIpDiscovery.Tests.Protocols;

public sealed class NdpParserTests
{
    [Fact]
    public void Parses_Na_Options()
    {
        var bytes = new byte[]
        {
            136, 0, 0, 0, 0,0,0,0,
            0xfe,0x80,0,0,0,0,0,0,0x02,0x11,0x22,0xff,0xfe,0x33,0x44,0x55,
            1,1,0x00,0x11,0x22,0x33,0x44,0x55
        };

        var parsed = NdpParser.Parse(bytes);
        var mac = NdpParser.TryGetSourceMac(parsed);

        Assert.Equal((byte)136, parsed.Type);
        Assert.Equal(IPAddress.Parse("fe80::211:22ff:fe33:4455"), parsed.TargetAddress);
        Assert.NotNull(mac);
        Assert.Equal("001122334455", mac!.ToString());
    }
}
