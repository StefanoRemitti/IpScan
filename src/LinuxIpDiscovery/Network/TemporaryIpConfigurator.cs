using System.Diagnostics;
using System.Net;

namespace LinuxIpDiscovery.Network;

public sealed class TemporaryIpConfigurator : IDisposable
{
    private readonly List<string> _recoveryCommands = [];

    public bool TryConfigure(string adapterName, IPAddress address, int prefix)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        var args = $"interface ip add address name=\"{adapterName}\" addr={address} mask={PrefixToMask(prefix)}";
        var exit = RunNetsh(args);
        if (exit == 0)
        {
            _recoveryCommands.Add($"netsh interface ip delete address name=\"{adapterName}\" addr={address}");
            return true;
        }

        return false;
    }

    public void Dispose()
    {
        for (var i = _recoveryCommands.Count - 1; i >= 0; i--)
        {
            RunNetsh(_recoveryCommands[i].Replace("netsh ", string.Empty, StringComparison.OrdinalIgnoreCase));
        }
    }

    public string RecoveryHint()
        => string.Join(Environment.NewLine, _recoveryCommands);

    private static int RunNetsh(string args)
    {
        var p = Process.Start(new ProcessStartInfo
        {
            FileName = "netsh",
            Arguments = args,
            CreateNoWindow = true,
            UseShellExecute = false
        });

        p?.WaitForExit(5000);
        return p?.ExitCode ?? -1;
    }

    private static string PrefixToMask(int prefix)
    {
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        return string.Join('.', new[] { (mask >> 24) & 0xff, (mask >> 16) & 0xff, (mask >> 8) & 0xff, mask & 0xff });
    }
}
