using System.Net;
using LinuxIpDiscovery.Cli;
using LinuxIpDiscovery.Core.Candidates;

namespace LinuxIpDiscovery.Candidates;

public sealed class CandidateGenerator
{
    public IReadOnlyList<IPAddress> Generate(CliOptions options)
    {
        var space = new CandidateSpace();
        return space.Generate(options.UserRanges, options.FullPrivate).ToArray();
    }
}
