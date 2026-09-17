using System.Net;
using System.Net.NetworkInformation;
using LinuxIpDiscovery.Core.Protocols;

namespace LinuxIpDiscovery.Tests.Protocols;

public sealed class Eui64Tests
{
    [Fact]
    public void Derive_And_Reverse_LinkLocal()
    {
        var mac = PhysicalAddress.Parse("001122334455");
        var ll = Eui64.ToLinkLocal(mac);

        Assert.Equal(IPAddress.Parse("fe80::211:22ff:fe33:4455"), ll);
        Assert.True(Eui64.TryExtractMac(ll, out var extracted));
        Assert.Equal(mac, extracted);
    }
}
