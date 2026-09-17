using System.Text.Json;
using LinuxIpDiscovery.Core.Correlation;

namespace LinuxIpDiscovery.Correlation;

public static class ResultSerializer
{
    public static void Write(string path, IEnumerable<DeviceRecord> devices)
    {
        var dto = devices.Select(d => new
        {
            mac = d.Mac.ToString(),
            confidence = d.Confidence.ToString(),
            addresses = d.Addresses.Select(a => a.ToString()).ToArray(),
            evidence = d.Evidence.Select(e => new { method = e.Method, type = e.Type.ToString(), ip = e.IpAddress?.ToString(), timestamp = e.Timestamp }).ToArray()
        });

        var json = JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json);
    }
}
