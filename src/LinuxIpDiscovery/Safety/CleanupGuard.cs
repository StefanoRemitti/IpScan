namespace LinuxIpDiscovery.Safety;

public sealed class CleanupGuard : IDisposable
{
    private readonly Action _cleanup;
    private int _disposed;

    public CleanupGuard(Action cleanup)
    {
        _cleanup = cleanup;
        AppDomain.CurrentDomain.ProcessExit += OnExit;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandled;
        Console.CancelKeyPress += OnCancel;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        AppDomain.CurrentDomain.ProcessExit -= OnExit;
        AppDomain.CurrentDomain.UnhandledException -= OnUnhandled;
        Console.CancelKeyPress -= OnCancel;
        _cleanup();
    }

    private void OnCancel(object? sender, ConsoleCancelEventArgs e)
    {
        e.Cancel = false;
        Dispose();
    }

    private void OnUnhandled(object sender, UnhandledExceptionEventArgs e) => Dispose();
    private void OnExit(object? sender, EventArgs e) => Dispose();
}
