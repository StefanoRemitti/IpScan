using LinuxIpDiscovery.Capture;
using LinuxIpDiscovery.Core.Correlation;

namespace LinuxIpDiscovery.Discovery;

public interface IDiscoveryStrategy
{
    Task ExecuteAsync(CaptureSession session, DeviceAggregator aggregator, CancellationToken cancellationToken);
}
