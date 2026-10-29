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
            return $"{BitConverter.ToString(u, 0, 4).Replace("-", "").ToLowerInvariant()}-" +
                   $"{BitConverter.ToString(u, 4, 2).Replace("-", "").ToLowerInvariant()}-" +
                   $"{BitConverter.ToString(u, 6, 2).Replace("-", "").ToLowerInvariant()}-" +
                   $"{BitConverter.ToString(u, 8, 2).Replace("-", "").ToLowerInvariant()}-" +
                   $"{BitConverter.ToString(u, 10, 6).Replace("-", "").ToLowerInvariant()}";
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
                int off = BitConverter.ToInt32(o, 0x20);
                if (off <= 0 || off >= o.Length) return "";
                int e = off;
                while (e < o.Length && o[e] != 0) e++;
                return Encoding.ASCII.GetString(o, off, e - off).Trim();
            }
            catch { return ""; }
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
                        return NetworkInterface.GetAllNetworkInterfaces()
                            .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                                     && n.GetPhysicalAddress().GetAddressBytes().Length == 6)
                            .Select(n => BitConverter.ToString(n.GetPhysicalAddress().GetAddressBytes()).Replace("-", ":"))
                            .FirstOrDefault() ?? "";
                    case "guid":
                        return Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography",
                            "MachineGuid", "")?.ToString() ?? "";
                    case "ip":
                        return NetworkInterface.GetAllNetworkInterfaces()
                            .Where(n => n.OperationalStatus == OperationalStatus.Up
                                     && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                            .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                            .Select(a => a.Address.ToString()).FirstOrDefault() ?? "";
                    case "monitor": return MonitorSpoof.ReadCurrent();
                }
            }
            catch { }
            return "";
        }
    }
}