using System;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using Microsoft.Win32;

namespace VnSpoofer.Services
{
    static class Probe
    {
        static string Wmi(string cls, string prop)
        {
            try
            {
                using var s = new ManagementObjectSearcher($"SELECT {prop} FROM {cls}");
                foreach (ManagementObject o in s.Get())
                {
                    string v = (o[prop] ?? "").ToString().Trim();
                    if (v.Length > 0 && v != "To be filled by O.E.M." && v != "Default string") return v;
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
                    case "uuid": return Wmi("Win32_ComputerSystemProduct", "UUID");
                    case "board": return Wmi("Win32_BaseBoard", "SerialNumber");
                    case "bios": return Wmi("Win32_BIOS", "SerialNumber");
                    case "product": return Wmi("Win32_BaseBoard", "Product");
                    case "disk": return Wmi("Win32_DiskDrive", "SerialNumber");
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
