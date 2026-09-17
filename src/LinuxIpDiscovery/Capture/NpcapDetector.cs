using System.Runtime.InteropServices;

namespace LinuxIpDiscovery.Capture;

public enum NpcapStatus
{
    Ok,
    MissingDriver,
    MissingService
}

public static class NpcapDetector
{
    public static NpcapStatus Detect()
    {
        if (!OperatingSystem.IsWindows())
        {
            return NpcapStatus.Ok;
        }

        var hasWpcap = NativeLibrary.TryLoad("wpcap.dll", out var wpcap);
        var hasPacket = NativeLibrary.TryLoad("Packet.dll", out var packet);
        var hasDll = hasWpcap && hasPacket;
        if (wpcap != IntPtr.Zero) NativeLibrary.Free(wpcap);
        if (packet != IntPtr.Zero) NativeLibrary.Free(packet);

        if (!hasDll)
        {
            return NpcapStatus.MissingDriver;
        }

        try
        {
            var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = "query npcap",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                UseShellExecute = false
            });
            process!.WaitForExit(3000);
            return process.ExitCode == 0 ? NpcapStatus.Ok : NpcapStatus.MissingService;
        }
        catch
        {
            return NpcapStatus.MissingService;
        }
    }
}
