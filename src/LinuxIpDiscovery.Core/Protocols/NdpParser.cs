using System.Net;
using System.Net.NetworkInformation;

namespace LinuxIpDiscovery.Core.Protocols;

public sealed record NdpOption(byte Type, byte[] Value);

public sealed record NdpMessage(byte Type, IPAddress? TargetAddress, IReadOnlyList<NdpOption> Options);

public static class NdpParser
{
    public static NdpMessage Parse(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 8)
        {
            throw new ArgumentException("ICMPv6 payload too short", nameof(payload));
        }

        IPAddress? target = null;
        if ((payload[0] == 135 || payload[0] == 136) && payload.Length >= 24)
        {
            target = new IPAddress(payload.Slice(8, 16));
        }

        var options = new List<NdpOption>();
        var offset = payload[0] is 135 or 136 ? 24 : 8;
        while (offset + 2 <= payload.Length)
        {
            var type = payload[offset];
            var units = payload[offset + 1];
            if (units == 0)
            {
                break;
            }

            var bytes = units * 8;
            if (offset + bytes > payload.Length)
            {
                break;
            }

            options.Add(new NdpOption(type, payload.Slice(offset + 2, bytes - 2).ToArray()));
            offset += bytes;
        }

        return new NdpMessage(payload[0], target, options);
    }

    public static PhysicalAddress? TryGetSourceMac(NdpMessage message)
    {
        var opt = message.Options.FirstOrDefault(o => o.Type == 1 && o.Value.Length >= 6);
        return opt is null ? null : new PhysicalAddress(opt.Value.Take(6).ToArray());
    }
}
