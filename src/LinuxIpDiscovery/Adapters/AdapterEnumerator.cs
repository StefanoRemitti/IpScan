using System.Net.NetworkInformation;
using SharpPcap;

namespace LinuxIpDiscovery.Adapters;

public sealed class AdapterEnumerator
{
    public IReadOnlyList<AdapterInfo> GetAdapters(bool includeAll)
    {
        var pcapByMac = CaptureDeviceList.Instance
            .Select(d => new { Device = d, Mac = d.MacAddress?.GetAddressBytes() })
            .Where(x => x.Mac is { Length: > 0 })
            .GroupBy(x => Convert.ToHexString(x.Mac!))
            .ToDictionary(g => g.Key, g => g.First().Device.Name, StringComparer.OrdinalIgnoreCase);

        var adapters = new List<AdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            var isVirtual = IsVirtual(nic);
            if (!includeAll && isVirtual)
            {
                continue;
            }

            var pa = nic.GetPhysicalAddress();
            if (pa.GetAddressBytes().Length == 0)
            {
                continue;
            }

            var mac = string.Join('-', pa.GetAddressBytes().Select(b => b.ToString("X2")));
            pcapByMac.TryGetValue(Convert.ToHexString(pa.GetAddressBytes()), out var pcapName);
            adapters.Add(new AdapterInfo(
                nic.Name,
                nic.Description,
                nic.Id,
                mac,
                nic.OperationalStatus == OperationalStatus.Up,
                nic.Speed > 0 ? nic.Speed / 1_000_000 : 0,
                isVirtual,
                pcapName));
        }

        return adapters.OrderByDescending(a => a.IsUp).ThenBy(a => a.Name).ToArray();
    }

    private static bool IsVirtual(NetworkInterface nic)
    {
        var text = $"{nic.Name} {nic.Description}".ToLowerInvariant();
        return text.Contains("virtual") || text.Contains("hyper-v") || text.Contains("vpn") || text.Contains("tunnel") || text.Contains("vmware");
    }
}
