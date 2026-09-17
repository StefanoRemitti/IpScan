using System.Net;

namespace LinuxIpDiscovery.Core.Candidates;

public sealed record CidrRange(IPAddress Network, int PrefixLength)
{
    public static CidrRange Parse(string value)
    {
        var parts = value.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            throw new FormatException($"Invalid CIDR: {value}");
        }

        if (!int.TryParse(parts[1], out var prefix) || prefix is < 0 or > 32)
        {
            throw new FormatException($"Invalid CIDR prefix: {value}");
        }

        var n = ToUInt32(ip);
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        return new CidrRange(FromUInt32(n & mask), prefix);
    }

    public IEnumerable<IPAddress> EnumerateHosts()
    {
        var start = ToUInt32(Network);
        var count = PrefixLength == 32 ? 1u : 1u << (32 - PrefixLength);
        for (var i = 0u; i < count; i++)
        {
            yield return FromUInt32(start + i);
        }
    }

    private static uint ToUInt32(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static IPAddress FromUInt32(uint n)
        => new([(byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n]);
}
