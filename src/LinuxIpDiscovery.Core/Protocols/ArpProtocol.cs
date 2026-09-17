using System.Net;
using System.Net.NetworkInformation;

namespace LinuxIpDiscovery.Core.Protocols;

public enum ArpKind
{
    Request,
    Reply,
    Gratuitous,
    Probe,
    Unknown
}

public sealed record ArpPacket(
    ushort HardwareType,
    ushort ProtocolType,
    byte HardwareSize,
    byte ProtocolSize,
    ushort Operation,
    PhysicalAddress SenderMac,
    IPAddress SenderIp,
    PhysicalAddress TargetMac,
    IPAddress TargetIp);

public static class ArpBuilder
{
    public static byte[] BuildRequest(PhysicalAddress senderMac, IPAddress senderIp, IPAddress targetIp)
        => Build(1, senderMac, senderIp, PhysicalAddress.None, targetIp);

    public static byte[] BuildReply(PhysicalAddress senderMac, IPAddress senderIp, PhysicalAddress targetMac, IPAddress targetIp)
        => Build(2, senderMac, senderIp, targetMac, targetIp);

    private static byte[] Build(ushort operation, PhysicalAddress senderMac, IPAddress senderIp, PhysicalAddress targetMac, IPAddress targetIp)
    {
        if (senderIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || targetIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            throw new ArgumentException("ARP supports IPv4 only.");
        }

        var bytes = new byte[28];
        bytes[0] = 0x00; bytes[1] = 0x01;
        bytes[2] = 0x08; bytes[3] = 0x00;
        bytes[4] = 0x06;
        bytes[5] = 0x04;
        bytes[6] = (byte)(operation >> 8); bytes[7] = (byte)operation;
        senderMac.GetAddressBytes().CopyTo(bytes, 8);
        senderIp.GetAddressBytes().CopyTo(bytes, 14);
        targetMac.GetAddressBytes().CopyTo(bytes, 18);
        targetIp.GetAddressBytes().CopyTo(bytes, 24);
        return bytes;
    }
}

public static class ArpParser
{
    public static ArpPacket Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 28)
        {
            throw new ArgumentException("ARP payload too short.", nameof(bytes));
        }

        var senderMac = new PhysicalAddress(bytes.Slice(8, 6).ToArray());
        var senderIp = new IPAddress(bytes.Slice(14, 4));
        var targetMac = new PhysicalAddress(bytes.Slice(18, 6).ToArray());
        var targetIp = new IPAddress(bytes.Slice(24, 4));

        return new ArpPacket(
            (ushort)((bytes[0] << 8) | bytes[1]),
            (ushort)((bytes[2] << 8) | bytes[3]),
            bytes[4],
            bytes[5],
            (ushort)((bytes[6] << 8) | bytes[7]),
            senderMac,
            senderIp,
            targetMac,
            targetIp);
    }

    public static ArpKind Classify(ArpPacket packet)
    {
        if (packet.Operation == 1 && packet.SenderIp.Equals(IPAddress.Any))
        {
            return ArpKind.Probe;
        }

        if (packet.Operation == 1 && packet.SenderIp.Equals(packet.TargetIp))
        {
            return ArpKind.Gratuitous;
        }

        return packet.Operation switch
        {
            1 => ArpKind.Request,
            2 => ArpKind.Reply,
            _ => ArpKind.Unknown
        };
    }
}
