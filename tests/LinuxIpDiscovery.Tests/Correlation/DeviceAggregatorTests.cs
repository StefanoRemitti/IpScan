using System.Net;
using System.Net.NetworkInformation;
using LinuxIpDiscovery.Core.Correlation;

namespace LinuxIpDiscovery.Tests.Correlation;

public sealed class DeviceAggregatorTests
{
    [Fact]
    public void Assigns_Confirmed_When_Direct_Evidence_Repeats()
    {
        var agg = new DeviceAggregator();
        var mac = PhysicalAddress.Parse("001122334455");
        var ip = IPAddress.Parse("192.168.1.10");

        agg.Add(new Evidence(mac, ip, EvidenceType.ArpReply, "arp", DateTimeOffset.UtcNow));
        agg.Add(new Evidence(mac, ip, EvidenceType.ArpReply, "arp", DateTimeOffset.UtcNow));

        var d = Assert.Single(agg.Snapshot());
        Assert.Equal(ConfidenceLevel.Confirmed, d.Confidence);
    }

    [Fact]
    public void Handles_MultiDevice_MultiNic_Cases()
    {
        var agg = new DeviceAggregator();
        var mac1 = PhysicalAddress.Parse("001122334455");
        var mac2 = PhysicalAddress.Parse("001122334466");

        agg.Add(new Evidence(mac1, IPAddress.Parse("10.0.0.5"), EvidenceType.ArpReply, "arp", DateTimeOffset.UtcNow));
        agg.Add(new Evidence(mac1, IPAddress.Parse("192.168.50.10"), EvidenceType.Ipv4SourceSeen, "passive", DateTimeOffset.UtcNow));
        agg.Add(new Evidence(mac2, null, EvidenceType.Heuristic, "mld leak", DateTimeOffset.UtcNow));

        var devices = agg.Snapshot().OrderBy(d => d.Mac.ToString()).ToArray();
        Assert.Equal(2, devices.Length);
        Assert.Equal(ConfidenceLevel.Probable, devices[0].Confidence);
        Assert.Equal(ConfidenceLevel.Tentative, devices[1].Confidence);
        Assert.Equal(2, devices[0].Addresses.Count);
    }
}
