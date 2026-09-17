using System.Net;

namespace LinuxIpDiscovery.Core.Protocols;

public static class MulticastLeakAnalyzer
{
    public static IPAddress? InferFromSolicitedNodeMulticast(IPAddress multicastAddress)
    {
        var b = multicastAddress.GetAddressBytes();
        if (b.Length != 16 || b[0] != 0xff || b[1] != 0x02 || b[11] != 0x01 || b[12] != 0xff)
        {
            return null;
        }

        return new IPAddress(new byte[]
        {
            0,0,0,0,0,0,0,0,0,0,0,0,0,b[13],b[14],b[15]
        });
    }
}
