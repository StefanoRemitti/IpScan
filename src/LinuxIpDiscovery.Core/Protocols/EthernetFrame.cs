using System.Net.NetworkInformation;

namespace LinuxIpDiscovery.Core.Protocols;

public sealed record EthernetFrame(PhysicalAddress Destination, PhysicalAddress Source, ushort EtherType, byte[] Payload)
{
    public static EthernetFrame Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 14)
        {
            throw new ArgumentException("Frame too short.", nameof(data));
        }

        var dst = new PhysicalAddress(data[..6].ToArray());
        var src = new PhysicalAddress(data.Slice(6, 6).ToArray());
        var etherType = (ushort)((data[12] << 8) | data[13]);
        return new EthernetFrame(dst, src, etherType, data[14..].ToArray());
    }

    public byte[] ToBytes()
    {
        var buffer = new byte[14 + Payload.Length];
        Destination.GetAddressBytes().CopyTo(buffer, 0);
        Source.GetAddressBytes().CopyTo(buffer, 6);
        buffer[12] = (byte)(EtherType >> 8);
        buffer[13] = (byte)(EtherType & 0xff);
        Payload.CopyTo(buffer, 14);
        return buffer;
    }
}
