namespace LinuxIpDiscovery.Core.Safety;

public sealed class RateLimiter
{
    private readonly int _packetsPerSecond;
    private DateTime _window = DateTime.UtcNow;
    private int _sentInWindow;

    public RateLimiter(int packetsPerSecond)
    {
        if (packetsPerSecond <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(packetsPerSecond));
        }

        _packetsPerSecond = packetsPerSecond;
    }

    public TimeSpan RegisterAndGetDelay()
    {
        var now = DateTime.UtcNow;
        if ((now - _window).TotalSeconds >= 1)
        {
            _window = now;
            _sentInWindow = 0;
        }

        _sentInWindow++;
        if (_sentInWindow <= _packetsPerSecond)
        {
            return TimeSpan.Zero;
        }

        var next = _window.AddSeconds(1);
        return next > now ? next - now : TimeSpan.Zero;
    }
}
