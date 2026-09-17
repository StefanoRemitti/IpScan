using System.Text;

namespace LinuxIpDiscovery.Core.Protocols;

public sealed record LldpInfo(string? SystemName, string? PortId);

public static class LldpParser
{
    public static LldpInfo Parse(ReadOnlySpan<byte> payload)
    {
        string? system = null;
        string? port = null;
        var offset = 0;

        while (offset + 2 <= payload.Length)
        {
            var header = (ushort)((payload[offset] << 8) | payload[offset + 1]);
            var type = (header >> 9) & 0x7F;
            var len = header & 0x1FF;
            offset += 2;
            if (offset + len > payload.Length)
            {
                break;
            }

            var value = payload.Slice(offset, len);
            if (type == 0)
            {
                break;
            }

            if (type == 4 && len > 0)
            {
                port = Encoding.UTF8.GetString(value[1..]);
            }

            if (type == 5)
            {
                system = Encoding.UTF8.GetString(value);
            }

            offset += len;
        }

        return new LldpInfo(system, port);
    }
}
