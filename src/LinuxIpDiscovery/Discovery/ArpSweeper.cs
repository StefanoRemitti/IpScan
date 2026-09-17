using System.Net;
using System.Net.NetworkInformation;
using LinuxIpDiscovery.Capture;
using LinuxIpDiscovery.Core.Correlation;
using LinuxIpDiscovery.Core.Safety;

namespace LinuxIpDiscovery.Discovery;

public sealed class ArpSweeper(
    IEnumerable<IPAddress> candidates,
    PhysicalAddress sourceMac,
    int rate,
    IPAddress? senderIp = null) : IDiscoveryStrategy
{
    public async Task ExecuteAsync(CaptureSession session, DeviceAggregator aggregator, CancellationToken cancellationToken)
    {
        var limiter = new RateLimiter(rate);
        var sender = senderIp ?? IPAddress.Any;

        foreach (var target in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var arpPayload = ArpBuilder.BuildRequest(sourceMac, sender, target);
            var frame = new EthernetFrame(
                new PhysicalAddress([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
                sourceMac,
                0x0806,
                arpPayload).ToBytes();

            session.SendPacket(frame);
            var delay = limiter.RegisterAndGetDelay();
            if (delay > TimeSpan.Zero)
            {
                await Task.Delay(delay, cancellationToken);
            }
        }

        _ = aggregator;
    }
}
