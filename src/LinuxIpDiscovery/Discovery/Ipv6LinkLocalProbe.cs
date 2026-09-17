using System.Net;
using System.Net.NetworkInformation;
using LinuxIpDiscovery.Capture;
using LinuxIpDiscovery.Core.Correlation;

namespace LinuxIpDiscovery.Discovery;

public sealed class Ipv6LinkLocalProbe(PhysicalAddress sourceMac, IPAddress sourceLinkLocal) : IDiscoveryStrategy
{
    public Task ExecuteAsync(CaptureSession session, DeviceAggregator aggregator, CancellationToken cancellationToken)
    {
        var payload = Icmpv6Builder.BuildEchoRequest(0x1111, 0x1, "LinuxIpDiscovery"u8.ToArray());
        var destination = IPAddress.Parse("ff02::1");
        var checksum = Icmpv6Builder.ComputeChecksum(sourceLinkLocal, destination, payload);
        payload[2] = (byte)(checksum >> 8);
        payload[3] = (byte)checksum;

        var ethernet = new EthernetFrame(
            new PhysicalAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]),
            sourceMac,
            0x86DD,
            BuildIpv6Packet(sourceLinkLocal, destination, payload));

        session.SendPacket(ethernet.ToBytes());
        _ = aggregator;
        _ = cancellationToken;
        return Task.CompletedTask;
    }

    private static byte[] BuildIpv6Packet(IPAddress src, IPAddress dst, ReadOnlySpan<byte> payload)
    {
        var bytes = new byte[40 + payload.Length];
        bytes[0] = 0x60;
        bytes[4] = (byte)(payload.Length >> 8);
        bytes[5] = (byte)payload.Length;
        bytes[6] = 58;
        bytes[7] = 64;
        src.GetAddressBytes().CopyTo(bytes, 8);
        dst.GetAddressBytes().CopyTo(bytes, 24);
        payload.CopyTo(bytes.AsSpan(40));
        return bytes;
    }
}
