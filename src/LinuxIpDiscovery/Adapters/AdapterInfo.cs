namespace LinuxIpDiscovery.Adapters;

public sealed record AdapterInfo(
    string Name,
    string Description,
    string Id,
    string Mac,
    bool IsUp,
    long SpeedMbps,
    bool IsLikelyVirtual,
    string? PcapName);
