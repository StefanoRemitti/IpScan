using LinuxIpDiscovery.Capture;
using LinuxIpDiscovery.Core.Correlation;

namespace LinuxIpDiscovery.Discovery;

public sealed class LinkBounceDetector : IDiscoveryStrategy
{
    public Task ExecuteAsync(CaptureSession session, DeviceAggregator aggregator, CancellationToken cancellationToken)
    {
        _ = session;
        _ = aggregator;
        _ = cancellationToken;
        return Task.CompletedTask;
    }
}
