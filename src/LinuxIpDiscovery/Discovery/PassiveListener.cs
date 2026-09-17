using LinuxIpDiscovery.Capture;
using LinuxIpDiscovery.Core.Correlation;
using LinuxIpDiscovery.Core.Protocols;
using PacketDotNet;

namespace LinuxIpDiscovery.Discovery;

public sealed class PassiveListener(bool verbose = false) : IDiscoveryStrategy
{
    public Task ExecuteAsync(CaptureSession session, DeviceAggregator aggregator, CancellationToken cancellationToken)
    {
        session.PacketReceived += capture =>
        {
            var packet = Packet.ParsePacket(capture.LinkLayerType, capture.Data);
            var eth = packet.Extract<EthernetPacket>();
            if (eth is null)
            {
                return;
            }

            if (verbose)
            {
                Console.WriteLine($"[passive] {eth.SourceHardwareAddress} -> {eth.DestinationHardwareAddress} {eth.Type}");
            }

            var ip4 = packet.Extract<IPv4Packet>();
            if (ip4 is not null)
            {
                aggregator.Add(new Evidence(eth.SourceHardwareAddress, ip4.SourceAddress, EvidenceType.Ipv4SourceSeen, "Passive IPv4 frame", DateTimeOffset.UtcNow));
            }

            var ip6 = packet.Extract<IPv6Packet>();
            if (ip6 is not null)
            {
                aggregator.Add(new Evidence(eth.SourceHardwareAddress, ip6.SourceAddress, EvidenceType.Ipv6SourceSeen, "Passive IPv6 frame", DateTimeOffset.UtcNow));
            }

            if (eth.Type == EthernetType.Arp)
            {
                try
                {
                    var arp = ArpParser.Parse(eth.PayloadData);
                    var type = arp.Operation == 2 ? EvidenceType.ArpReply : EvidenceType.ArpRequest;
                    aggregator.Add(new Evidence(arp.SenderMac, arp.SenderIp, type, $"Passive ARP {arp.Operation}", DateTimeOffset.UtcNow));
                }
                catch
                {
                    // Ignore malformed ARP payload.
                }
            }
        };

        return Task.CompletedTask;
    }
}
