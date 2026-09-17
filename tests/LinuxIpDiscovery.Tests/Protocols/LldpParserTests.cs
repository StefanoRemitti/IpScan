using LinuxIpDiscovery.Core.Protocols;

namespace LinuxIpDiscovery.Tests.Protocols;

public sealed class LldpParserTests
{
    [Fact]
    public void Parses_SystemName_And_PortId()
    {
        var payload = new byte[]
        {
            0x08,0x05,0x05,(byte)'e',(byte)'t',(byte)'h',(byte)'0',
            0x0A,0x06,(byte)'u',(byte)'b',(byte)'u',(byte)'n',(byte)'t',(byte)'u',
            0x00,0x00
        };

        var info = LldpParser.Parse(payload);
        Assert.Equal("ubuntu", info.SystemName);
        Assert.Equal("eth0", info.PortId);
    }
}
