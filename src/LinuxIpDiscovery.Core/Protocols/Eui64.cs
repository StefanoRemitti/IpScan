using System.Net;
using System.Net.NetworkInformation;

namespace LinuxIpDiscovery.Core.Protocols;

public static class Eui64
{
    public static IPAddress ToLinkLocal(PhysicalAddress mac)
    {
        var m = mac.GetAddressBytes();
        if (m.Length != 6)
        {
            throw new ArgumentException("MAC must be 48-bit.", nameof(mac));
        }

        var iid = new byte[8];
        iid[0] = (byte)(m[0] ^ 0x02);
        iid[1] = m[1];
        iid[2] = m[2];
        iid[3] = 0xFF;
        iid[4] = 0xFE;
        iid[5] = m[3];
        iid[6] = m[4];
        iid[7] = m[5];

        var addr = new byte[16];
        addr[0] = 0xFE;
        addr[1] = 0x80;
        iid.CopyTo(addr, 8);
        return new IPAddress(addr);
    }

    public static bool TryExtractMac(IPAddress linkLocal, out PhysicalAddress mac)
    {
        var b = linkLocal.GetAddressBytes();
        mac = PhysicalAddress.None;
        if (b.Length != 16 || b[0] != 0xFE || b[1] != 0x80)
        {
            return false;
        }

        if (b[11] != 0xFF || b[12] != 0xFE)
        {
            return false;
        }

        var m = new byte[6];
        m[0] = (byte)(b[8] ^ 0x02);
        m[1] = b[9];
        m[2] = b[10];
        m[3] = b[13];
        m[4] = b[14];
        m[5] = b[15];
        mac = new PhysicalAddress(m);
        return true;
    }
}
