using System.Net;
using LinuxIpDiscovery.Core.Protocols;

namespace LinuxIpDiscovery.Tests.Protocols;

public sealed class Icmpv6BuilderTests
{
    [Fact]
    public void Computes_Checksum_Using_PseudoHeader()
    {
        var src = IPAddress.Parse("fe80::1");
        var dst = IPAddress.Parse("ff02::1");
        var msg = Icmpv6Builder.BuildEchoRequest(1, 1, [0x41, 0x42]);
        var checksum = Icmpv6Builder.ComputeChecksum(src, dst, msg);

        Assert.NotEqual((ushort)0, checksum);
    }
}
