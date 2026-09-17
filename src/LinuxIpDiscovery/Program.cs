using System.Net;
using System.Net.NetworkInformation;
using System.Security.Principal;
using LinuxIpDiscovery.Adapters;
using LinuxIpDiscovery.Candidates;
using LinuxIpDiscovery.Capture;
using LinuxIpDiscovery.Cli;
using LinuxIpDiscovery.Core.Correlation;
using LinuxIpDiscovery.Correlation;
using LinuxIpDiscovery.Discovery;
using LinuxIpDiscovery.Network;
using LinuxIpDiscovery.Safety;
using SharpPcap;

const int ExitNpcapMissing = 30;
const int ExitNotAdmin = 31;
const int ExitNoAdapter = 32;

try
{
    var options = CliOptions.Parse(args);
    ConsoleRenderer.PrintHeader();

    if (!IsAdministrator())
    {
        Console.Error.WriteLine("Administrator privileges are required. Re-run as Administrator.");
        return ExitNotAdmin;
    }

    var npcapStatus = NpcapDetector.Detect();
    if (npcapStatus != NpcapStatus.Ok)
    {
        Console.Error.WriteLine("Npcap was not detected correctly.");
        Console.Error.WriteLine("Install Npcap from https://npcap.com and ensure \"WinPcap API-compatible Mode\" is enabled.");
        return ExitNpcapMissing;
    }

    var enumerator = new AdapterEnumerator();
    var adapters = enumerator.GetAdapters(options.AllAdapters);
    if (adapters.Count == 0)
    {
        Console.Error.WriteLine("No eligible Ethernet adapters were found.");
        return ExitNoAdapter;
    }

    ConsoleRenderer.PrintAdapters(adapters);

    var selected = SelectAdapter(adapters, options.AdapterSelector);
    if (selected is null)
    {
        Console.Error.WriteLine("Adapter selection failed.");
        return ExitNoAdapter;
    }

    Console.WriteLine("For best results, unplug and replug the Ethernet cable on the Linux device now — this forces gratuitous ARP and IPv6 announcements that make discovery near-certain.");

    var device = CaptureDeviceList.Instance.FirstOrDefault(d => string.Equals(d.Name, selected.PcapName, StringComparison.OrdinalIgnoreCase));
    if (device is null)
    {
        Console.Error.WriteLine("Unable to map the selected adapter to a capture device.");
        return ExitNoAdapter;
    }

    var aggregator = new DeviceAggregator();
    var sourceMac = PhysicalAddress.Parse(selected.Mac.Replace("-", string.Empty, StringComparison.OrdinalIgnoreCase));
    var candidateIps = new CandidateGenerator().Generate(options);

    using var configurator = new TemporaryIpConfigurator();
    using var guard = new CleanupGuard(() => configurator.Dispose());
    using var session = new CaptureSession(device);

    session.Start();

    var strategies = new List<IDiscoveryStrategy>
    {
        new PassiveListener(options.Verbose),
        new GratuitousArpWatcher(),
        new LinkBounceDetector(),
        new ArpSweeper(candidateIps, sourceMac, options.Rate),
        new Ipv6LinkLocalProbe(sourceMac, Eui64.ToLinkLocal(sourceMac))
    };

    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    await Task.WhenAll(strategies.Select(s => s.ExecuteAsync(session, aggregator, cts.Token)));

    var snapshot = aggregator.Snapshot();
    ConsoleRenderer.PrintResults(snapshot);

    if (!string.IsNullOrWhiteSpace(options.JsonOutput))
    {
        ResultSerializer.Write(options.JsonOutput!, snapshot);
        Console.WriteLine($"JSON results written to {options.JsonOutput}");
    }

    if (options.ConfigureIp)
    {
        var firstIp = snapshot.SelectMany(d => d.Addresses).FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
        if (firstIp is not null)
        {
            Console.Write($"Temporarily add secondary IPv4 near discovered subnet {firstIp}/24 on {selected.Name}? [y/N]: ");
            var confirm = Console.ReadLine();
            if (string.Equals(confirm, "y", StringComparison.OrdinalIgnoreCase))
            {
                var bytes = firstIp.GetAddressBytes();
                var synthetic = new IPAddress([bytes[0], bytes[1], bytes[2], 250]);
                Console.WriteLine($"Applying: add {synthetic}/24 on \"{selected.Name}\"");
                if (!configurator.TryConfigure(selected.Name, synthetic, 24))
                {
                    Console.WriteLine("Configuration failed. Recovery command:");
                    Console.WriteLine(configurator.RecoveryHint());
                }
            }
        }
    }

    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

static bool IsAdministrator()
{
    if (!OperatingSystem.IsWindows())
    {
        return true;
    }

    using var identity = WindowsIdentity.GetCurrent();
    var principal = new WindowsPrincipal(identity);
    return principal.IsInRole(WindowsBuiltInRole.Administrator);
}

static AdapterInfo? SelectAdapter(IReadOnlyList<AdapterInfo> adapters, string? selector)
{
    if (adapters.Count == 1)
    {
        Console.WriteLine($"Auto-selected adapter: {adapters[0].Name}");
        return adapters[0];
    }

    if (!string.IsNullOrWhiteSpace(selector))
    {
        if (int.TryParse(selector, out var index) && index >= 1 && index <= adapters.Count)
        {
            return adapters[index - 1];
        }

        return adapters.FirstOrDefault(a => a.Name.Contains(selector, StringComparison.OrdinalIgnoreCase));
    }

    Console.Write("Select adapter: ");
    var input = Console.ReadLine();
    if (int.TryParse(input, out var selectedIndex) && selectedIndex >= 1 && selectedIndex <= adapters.Count)
    {
        return adapters[selectedIndex - 1];
    }

    return null;
}
