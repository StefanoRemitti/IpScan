using System.Net;

namespace LinuxIpDiscovery.Core.Candidates;

public sealed class CandidateSpace
{
    private static readonly string[] DefaultCidrs =
    [
        "192.168.0.0/24",
        "192.168.1.0/24",
        "10.0.0.0/24",
        "10.0.1.0/24",
        "172.16.0.0/24",
        "169.254.0.0/16"
    ];

    private static readonly byte[] CommonOffsets = [1, 2, 10, 20, 100, 200, 254];

    public IEnumerable<IPAddress> Generate(IEnumerable<CidrRange> userRanges, bool includeFullPrivate)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var ip in GenerateFromDefaults(includeFullPrivate))
        {
            if (seen.Add(ip.ToString()))
            {
                yield return ip;
            }
        }

        foreach (var r in userRanges)
        {
            foreach (var ip in r.EnumerateHosts())
            {
                if (seen.Add(ip.ToString()))
                {
                    yield return ip;
                }
            }
        }
    }

    private static IEnumerable<IPAddress> GenerateFromDefaults(bool includeFullPrivate)
    {
        foreach (var c in DefaultCidrs)
        {
            var range = CidrRange.Parse(c);
            var network = range.Network.GetAddressBytes();
            foreach (var offset in CommonOffsets)
            {
                yield return new IPAddress([network[0], network[1], network[2], offset]);
            }
        }

        if (!includeFullPrivate)
        {
            yield break;
        }

        foreach (var cidr in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" })
        {
            foreach (var ip in CidrRange.Parse(cidr).EnumerateHosts())
            {
                yield return ip;
            }
        }
    }
}
