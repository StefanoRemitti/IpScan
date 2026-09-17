using System.Net;

namespace LinuxIpDiscovery.Core.Protocols;

public static class Icmpv6Builder
{
    public static byte[] BuildEchoRequest(ushort id, ushort sequence, ReadOnlySpan<byte> payload)
    {
        var data = new byte[8 + payload.Length];
        data[0] = 128;
        data[1] = 0;
        data[4] = (byte)(id >> 8);
        data[5] = (byte)id;
        data[6] = (byte)(sequence >> 8);
        data[7] = (byte)sequence;
        payload.CopyTo(data.AsSpan(8));
        return data;
    }

    public static ushort ComputeChecksum(IPAddress source, IPAddress destination, ReadOnlySpan<byte> icmpv6)
    {
        var pseudo = new byte[40 + icmpv6.Length + (icmpv6.Length % 2)];
        source.GetAddressBytes().CopyTo(pseudo, 0);
        destination.GetAddressBytes().CopyTo(pseudo, 16);

        pseudo[32] = (byte)((icmpv6.Length >> 24) & 0xff);
        pseudo[33] = (byte)((icmpv6.Length >> 16) & 0xff);
        pseudo[34] = (byte)((icmpv6.Length >> 8) & 0xff);
        pseudo[35] = (byte)(icmpv6.Length & 0xff);
        pseudo[39] = 58;

        icmpv6.CopyTo(pseudo.AsSpan(40));
        return OnesComplement(pseudo);
    }

    private static ushort OnesComplement(ReadOnlySpan<byte> bytes)
    {
        uint sum = 0;
        for (var i = 0; i < bytes.Length; i += 2)
        {
            sum += (uint)((bytes[i] << 8) + bytes[i + 1]);
            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }

        return (ushort)~sum;
    }
}
