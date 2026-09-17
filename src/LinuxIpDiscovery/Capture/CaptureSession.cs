using SharpPcap;

namespace LinuxIpDiscovery.Capture;

public sealed class CaptureSession : IDisposable
{
    private readonly ICaptureDevice _device;

    public CaptureSession(ICaptureDevice device)
    {
        _device = device;
    }

    public event Action<RawCapture>? PacketReceived;

    public void Start()
    {
        _device.OnPacketArrival += HandlePacketArrival;
        _device.Open(DeviceModes.Promiscuous);
        _device.StartCapture();
    }

    public void SendPacket(ReadOnlySpan<byte> frame)
    {
        if (_device is IInjectionDevice injectionDevice)
        {
            injectionDevice.SendPacket(frame.ToArray());
        }
    }

    public void Dispose()
    {
        _device.StopCapture();
        _device.Close();
        _device.OnPacketArrival -= HandlePacketArrival;
    }

    private void HandlePacketArrival(object sender, PacketCapture e)
        => PacketReceived?.Invoke(e.GetPacket());
}
