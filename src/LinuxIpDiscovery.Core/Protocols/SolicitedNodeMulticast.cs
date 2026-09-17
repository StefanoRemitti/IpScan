using System.Net;

namespace LinuxIpDiscovery.Core.Protocols;

public static class SolicitedNodeMulticast
{
    public static IPAddress ForAddress(IPAddress address)
    {
        var b = address.GetAddressBytes();
        if (b.Length != 16)
        {
            throw new ArgumentException("IPv6 required.", nameof(address));
        }

        return new IPAddress(new byte[]
        {
            0xff,0x02,0,0,0,0,0,0,0,0,0,1,0xff,b[13],b[14],b[15]
        });
    }
}
