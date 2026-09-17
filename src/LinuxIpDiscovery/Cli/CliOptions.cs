using LinuxIpDiscovery.Core.Candidates;

namespace LinuxIpDiscovery.Cli;

public sealed class CliOptions
{
    public bool AllAdapters { get; init; }
    public string? AdapterSelector { get; init; }
    public int Rate { get; init; } = 500;
    public bool FullPrivate { get; init; }
    public bool Verbose { get; init; }
    public bool ConfigureIp { get; init; }
    public string? JsonOutput { get; init; }
    public IReadOnlyList<CidrRange> UserRanges { get; init; } = [];

    public static CliOptions Parse(string[] args)
    {
        var all = false;
        string? adapter = null;
        var rate = 500;
        var fullPrivate = false;
        var verbose = false;
        var configure = false;
        string? json = null;
        var ranges = new List<CidrRange>();

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--all-adapters": all = true; break;
                case "--full-private": fullPrivate = true; break;
                case "--verbose": verbose = true; break;
                case "--configure-ip": configure = true; break;
                case "--adapter" when i + 1 < args.Length:
                    adapter = args[++i];
                    break;
                case "--rate" when i + 1 < args.Length && int.TryParse(args[++i], out var parsed):
                    rate = parsed;
                    break;
                case "--json" when i + 1 < args.Length:
                    json = args[++i];
                    break;
                case "--ranges" when i + 1 < args.Length:
                    foreach (var token in args[++i].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        ranges.Add(CidrRange.Parse(token));
                    }
                    break;
                case "--help":
                case "-h":
                    PrintHelp();
                    Environment.Exit(0);
                    break;
                default:
                    throw new ArgumentException($"Unknown argument: {args[i]}");
            }
        }

        return new CliOptions
        {
            AllAdapters = all,
            AdapterSelector = adapter,
            Rate = Math.Max(1, rate),
            FullPrivate = fullPrivate,
            Verbose = verbose,
            ConfigureIp = configure,
            JsonOutput = json,
            UserRanges = ranges
        };
    }

    public static void PrintHelp()
    {
        Console.WriteLine("LinuxIpDiscovery usage:");
        Console.WriteLine("  --adapter <index|name>   Select adapter");
        Console.WriteLine("  --all-adapters           Include virtual/tunnel adapters");
        Console.WriteLine("  --ranges <cidr,cidr>     Add custom IPv4 sweep ranges");
        Console.WriteLine("  --rate <pps>             ARP packets per second (default 500)");
        Console.WriteLine("  --full-private           Include full RFC1918 sweep (slow)");
        Console.WriteLine("  --configure-ip           Temporarily configure inferred subnet IP");
        Console.WriteLine("  --json <file>            Save machine-readable output");
        Console.WriteLine("  --verbose                Verbose packet logging");
    }
}
