using LinuxIpDiscovery.Core.Candidates;

namespace LinuxIpDiscovery.Tests.Candidates;

public sealed class CandidateSpaceTests
{
    [Fact]
    public void Generates_Prioritized_And_Deduplicated()
    {
        var space = new CandidateSpace();
        var user = new[] { CidrRange.Parse("192.168.1.0/32") };

        var list = space.Generate(user, includeFullPrivate: false).Take(20).ToList();

        Assert.Contains(System.Net.IPAddress.Parse("192.168.1.1"), list);
        Assert.Equal(list.Distinct().Count(), list.Count);
    }

    [Theory]
    [InlineData("192.168.1.10/32", 1)]
    [InlineData("10.0.0.0/30", 4)]
    [InlineData("10.42.16.0/21", 2048)]
    public void Parses_Cidr_Including_EdgeCases(string cidr, int count)
    {
        var range = CidrRange.Parse(cidr);
        Assert.Equal(count, range.EnumerateHosts().Count());
    }
}
