using System.Net;
using System.Net.NetworkInformation;

namespace LinuxIpDiscovery.Core.Correlation;

public enum ConfidenceLevel
{
    Tentative,
    Probable,
    Confirmed
}

public enum EvidenceType
{
    ArpReply,
    ArpRequest,
    NdpNeighborAdvertisement,
    Ipv4SourceSeen,
    Ipv6SourceSeen,
    Heuristic
}

public sealed record Evidence(PhysicalAddress Mac, IPAddress? IpAddress, EvidenceType Type, string Method, DateTimeOffset Timestamp);

public sealed class DeviceRecord
{
    public required PhysicalAddress Mac { get; init; }
    public HashSet<IPAddress> Addresses { get; } = [];
    public List<Evidence> Evidence { get; } = [];
    public ConfidenceLevel Confidence { get; set; }
}
