using System.Net.NetworkInformation;
using LinuxIpDiscovery.Core.Protocols;

namespace LinuxIpDiscovery.Tests.Protocols;

public sealed class EthernetFrameTests
{
    [Fact]
    public void Parses_Header_And_Payload()
    {
        var frame = new EthernetFrame(
            PhysicalAddress.Parse("FFFFFFFFFFFF"),
            PhysicalAddress.Parse("001122334455"),
            0x0806,
            [1,2,3,4]);

        var parsed = EthernetFrame.Parse(frame.ToBytes());

        Assert.Equal((ushort)0x0806, parsed.EtherType);
        Assert.Equal("001122334455", parsed.Source.ToString());
        Assert.Equal([1,2,3,4], parsed.Payload);
    }
}
