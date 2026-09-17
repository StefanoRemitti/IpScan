using LinuxIpDiscovery.Core.Safety;

namespace LinuxIpDiscovery.Tests.Safety;

public sealed class RateLimiterTests
{
    [Fact]
    public void Returns_Delay_When_Limit_Exceeded()
    {
        var limiter = new RateLimiter(2);
        Assert.Equal(TimeSpan.Zero, limiter.RegisterAndGetDelay());
        Assert.Equal(TimeSpan.Zero, limiter.RegisterAndGetDelay());
        Assert.True(limiter.RegisterAndGetDelay() > TimeSpan.Zero);
    }
}
