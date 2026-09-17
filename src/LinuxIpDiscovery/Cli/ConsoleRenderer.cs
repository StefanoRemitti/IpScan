using LinuxIpDiscovery.Adapters;
using LinuxIpDiscovery.Core.Correlation;

namespace LinuxIpDiscovery.Cli;

public static class ConsoleRenderer
{
    public static void PrintHeader()
    {
        Console.WriteLine("Linux IP Discovery Tool");
        Console.WriteLine("=======================");
        Console.WriteLine();
    }

    public static void PrintAdapters(IReadOnlyList<AdapterInfo> adapters)
    {
        Console.WriteLine("Available Ethernet adapters:");
        Console.WriteLine();

        for (var i = 0; i < adapters.Count; i++)
        {
            var a = adapters[i];
            Console.WriteLine($"[{i + 1}] {a.Name}");
            Console.WriteLine($"    Status: {(a.IsUp ? "Up" : "Down")}");
            Console.WriteLine($"    MAC: {a.Mac}");
            Console.WriteLine($"    Link speed: {a.SpeedMbps} Mbps");
            Console.WriteLine();
        }
    }

    public static void PrintResults(IEnumerable<DeviceRecord> devices)
    {
        Console.WriteLine();
        Console.WriteLine("Discovery completed.");
        Console.WriteLine();
        foreach (var d in devices.OrderBy(d => d.Mac.ToString()))
        {
            Console.WriteLine($"MAC: {d.Mac}");
            Console.WriteLine($"Confidence: {d.Confidence}");
            foreach (var ip in d.Addresses.OrderBy(ip => ip.ToString()))
            {
                Console.WriteLine($"  Address: {ip}");
            }

            foreach (var e in d.Evidence.Take(5))
            {
                Console.WriteLine($"  Evidence: {e.Method}");
            }

            Console.WriteLine();
        }
    }
}
