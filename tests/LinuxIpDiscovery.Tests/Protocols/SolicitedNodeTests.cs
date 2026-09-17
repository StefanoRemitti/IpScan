using System.Net;
using LinuxIpDiscovery.Core.Protocols;

namespace LinuxIpDiscovery.Tests.Protocols;

public sealed class SolicitedNodeTests
{
    [Fact]
    public void Computes_SolicitedNode_Multicast()
    {
        var target = IPAddress.Parse("fe80::211:22ff:fe33:4455");
        var sn = SolicitedNodeMulticast.ForAddress(target);
        Assert.Equal(IPAddress.Parse("ff02::1:ff33:4455"), sn);
    }
}
