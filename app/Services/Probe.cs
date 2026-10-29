using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace VnSpoofer.Services
{
    static class Probe
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint GetSystemFirmwareTable(uint sig, uint id, byte[] buf, uint size);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
            IntPtr sa, uint disp, uint flags, IntPtr tmpl);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(SafeFileHandle h, uint code, byte[] inb, uint inl,
            byte[] outb, uint outl, out uint ret, IntPtr ov);

        const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;

        static byte[] Smbios()
        {
            try
            {
                uint sz = GetSystemFirmwareTable(0x52534D42, 0, null, 0);
                if (sz < 32) return null;
                var b = new byte[sz];
                if (GetSystemFirmwareTable(0x52534D42, 0, b, sz) != sz) return null;
                return b;
            }
            catch { return null; }
        }

        static int FindStruct(byte[] b, byte type, int minLen)
        {
            int p = 8, end = b.Length;
            while (p + 4 < end)
            {
                if (b[p] == type && b[p + 1] > minLen) return p;
                int nx = p + 4 + b[p + 1];
                while (nx + 1 < end && !(b[nx] == 0 && b[nx + 1] == 0)) nx++;
                p = nx + 2;
            }
            return -1;
        }

        static string SmbStr(byte type, int off)
        {
            var b = Smbios();
            if (b == null) return "";
            int p = FindStruct(b, type, off);
            if (p < 0) return "";
            int idx = b[p + off];
            if (idx == 0) return "";
            int s = p + 4 + b[p + 1], i = 1, end = b.Length;
            while (s < end)
            {
                int e = s;
                while (e < end && b[e] != 0) e++;
                if (i == idx) return Encoding.ASCII.GetString(b, s, e - s).Trim();
                if (e + 1 < end && b[e] == 0 && b[e + 1] == 0) return "";
                s = e + 1; i++;
            }
            return "";
        }

        static string SmbUuid()
        {
            var b = Smbios();
            if (b == null) return "";
            int p = FindStruct(b, 1, 0x18);
            if (p < 0) return "";
            var u = new byte[16];
            Buffer.BlockCopy(b, p + 8, u, 0, 16);
            return new Guid(u).ToString().ToLowerInvariant();
        }

        static string DiskSerial()
        {
            try
            {
                using var h = CreateFileW(@"\\.\PhysicalDrive0", 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
                if (h.IsInvalid) return "";
                var q = new byte[12];
                var o = new byte[1024];
                uint r;
                if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, q, 12, o, 1024, out r, IntPtr.Zero)) return "";
                int off = BitConverter.ToInt32(o, 0x18);
                if (off <= 0 || off >= o.Length) return "";
                int e = off;
                while (e < o.Length && o[e] != 0) e++;
                return Encoding.ASCII.GetString(o, off, e - off).Trim();
            }
            catch { return ""; }
        }

                static string MacReg()
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}");
                if (k == null) return "";
                using var pci = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\PCI");
                if (pci == null) return "";
                foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (n.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    if (n.GetPhysicalAddress().GetAddressBytes().Length != 6) continue;
                    foreach (var sub in k.GetSubKeyNames())
                    {
                        using var sk = k.OpenSubKey(sub);
                        if (!(sk?.GetValue("NetCfgInstanceId") is string id)) continue;
                        if (!string.Equals(id, n.Id, StringComparison.OrdinalIgnoreCase)) continue;
                        if (sk.GetValue("NetworkAddress") is string na && na.Length == 12)
                            return string.Join(":", Enumerable.Range(0, 6).Select(i => na.Substring(i * 2, 2).ToUpperInvariant()));
                    }
                }
            }
            catch { }
            return "";
        }

        static string MacIo()
        {
            try
            {
                foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (n.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    if (n.GetPhysicalAddress().GetAddressBytes().Length != 6) continue;
                    var ip = n.GetIPProperties().UnicastAddresses
                        .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
                    if (ip == null) continue;
                    using var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                    s.Bind(new System.Net.IPEndPoint(ip.Address, 0));
                    var oid = BitConverter.GetBytes(0x01010102u);
                    var o = new byte[6];
                    uint r;
                    if (Native.DeviceIoControl((IntPtr)s.Handle, 0x00170002, oid, 4, o, 6, out r, IntPtr.Zero) && r >= 6)
                        return BitConverter.ToString(o).Replace("-", ":");
                }
            }
            catch { }
            return "";
        }

        static string GpuId()
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}");
                if (k == null) return "";
                using var pci = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\PCI");
                if (pci == null) return "";
                foreach (var sub in k.GetSubKeyNames())
                {
                    using var sk = k.OpenSubKey(sub);
                    if (!(sk?.GetValue("MatchingDeviceId") is string md) || md.Length < 5) continue;
                    var m = md.StartsWith(@"pci\", StringComparison.OrdinalIgnoreCase) ? md.Substring(4) : md;
                    foreach (var n in pci.GetSubKeyNames())
                    {
                        if (!n.StartsWith(m, StringComparison.OrdinalIgnoreCase)) continue;
                        using var ek = pci.OpenSubKey(n);
                        var inst = ek?.GetSubKeyNames().FirstOrDefault();
                        if (!string.IsNullOrEmpty(inst)) return inst;
                    }
                }
            }
            catch { }
            return "";
        }
public static string Read(string key)
        {
            try
            {
                switch (key)
                {
                    case "uuid": return SmbUuid();
                    case "board": return SmbStr(2, 7);
                    case "bios": return SmbStr(0, 7);
                    case "product": return SmbStr(2, 5);
                    case "disk": return DiskSerial();
                    case "volume": return Native.VolumeSerial("C:\\");
                    case "mac":
                        {
                            var m = MacReg();
                            if (m.Length == 0) m = MacIo();
                            if (m.Length != 0) return m;
                            return NetworkInterface.GetAllNetworkInterfaces()
                                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                                         && n.GetPhysicalAddress().GetAddressBytes().Length == 6)
                                .Select(n => BitConverter.ToString(n.GetPhysicalAddress().GetAddressBytes()).Replace("-", ":"))
                                .FirstOrDefault() ?? "";
                        }
                    case "gpu": return GpuId();
                    case "guid":
                        return Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography",
                            "MachineGuid", "")?.ToString() ?? "";
                    case "ip":
                        {
                            var ups = NetworkInterface.GetAllNetworkInterfaces()
                                .Where(n => n.OperationalStatus == OperationalStatus.Up
                                         && n.NetworkInterfaceType != NetworkInterfaceType.Loopback).ToList();
                            var pick = ups.FirstOrDefault(n => n.GetIPProperties().GatewayAddresses
                                        .Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork))
                                       ?? ups.FirstOrDefault();
                            return pick?.GetIPProperties().UnicastAddresses
                                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                                .Select(a => a.Address.ToString()).FirstOrDefault() ?? "";
                        }
                    case "monitor": return MonitorSpoof.ReadCurrent();
                }
            }
            catch { }
            return "";
        }
    }
}