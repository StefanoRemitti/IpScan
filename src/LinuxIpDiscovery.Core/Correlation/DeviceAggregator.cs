using System.Net.NetworkInformation;

namespace LinuxIpDiscovery.Core.Correlation;

public sealed class DeviceAggregator
{
    private readonly Dictionary<string, DeviceRecord> _devices = new(StringComparer.OrdinalIgnoreCase);

    public void Add(Evidence evidence)
    {
        var key = NormalizeMac(evidence.Mac);
        if (!_devices.TryGetValue(key, out var device))
        {
            device = new DeviceRecord
            {
                Mac = evidence.Mac,
                Confidence = ConfidenceLevel.Tentative
            };
            _devices.Add(key, device);
        }

        if (evidence.IpAddress is not null)
        {
            device.Addresses.Add(evidence.IpAddress);
        }

        device.Evidence.Add(evidence);
        device.Confidence = ComputeConfidence(device);
    }

    public IReadOnlyCollection<DeviceRecord> Snapshot() => _devices.Values.ToArray();

    private static ConfidenceLevel ComputeConfidence(DeviceRecord device)
    {
        var direct = device.Evidence.Count(e => e.Type is EvidenceType.ArpReply or EvidenceType.NdpNeighborAdvertisement);
        if (direct >= 2)
        {
            return ConfidenceLevel.Confirmed;
        }

        if (direct == 1 || device.Evidence.Any(e => e.Type is EvidenceType.Ipv4SourceSeen or EvidenceType.Ipv6SourceSeen))
        {
            return ConfidenceLevel.Probable;
        }

        return ConfidenceLevel.Tentative;
    }

    private static string NormalizeMac(PhysicalAddress mac)
        => string.Concat(mac.GetAddressBytes().Select(b => b.ToString("X2")));
}
