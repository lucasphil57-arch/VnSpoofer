using System;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace VnSpoofer.Services
{
    static class IpSpoof
    {
        static (string name, int prefix, string ip, string gw, string dns, bool dhcp) Current()
        {
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (n.OperationalStatus != OperationalStatus.Up) continue;
                if (n.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var p = n.GetIPProperties();
                var v4 = p.UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
                var gw = p.GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork);
                if (v4 == null || gw == null) continue;
                var dns = p.DnsAddresses.FirstOrDefault(d => d.AddressFamily == AddressFamily.InterNetwork);
                bool dhcp = true;
                try { dhcp = n.GetIPProperties().DhcpServerAddresses.Count > 0; } catch { }
                return (n.Name, v4.PrefixLength, v4.Address.ToString(),
                        gw.Address.ToString(), dns?.ToString() ?? "", dhcp);
            }
            return (null, 0, null, null, null, false);
        }

        static string Mask(int prefix)
        {
            uint m = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
            return $"{(m >> 24) & 255}.{(m >> 16) & 255}.{(m >> 8) & 255}.{m & 255}";
        }

        public static void Prepare(State st)
        {
            var c = Current();
            if (c.name == null) return;

            st.Original["ip:name"] = c.name;
            st.Original["ip:dhcp"] = c.dhcp ? "1" : "0";
            st.Original["ip:addr"] = c.ip;
            st.Original["ip:mask"] = Mask(c.prefix);
            st.Original["ip:gw"] = c.gw;
            st.Original["ip:dns"] = c.dns;

            Sh("netsh", $"interface ipv4 set address name=\"{c.name}\" dhcp");
            Sh("netsh", $"interface ipv4 set dnsservers name=\"{c.name}\" dhcp");
        }

        public static string Apply(State st)
        {
            if (!st.Original.TryGetValue("ip:name", out var name)) return "";
            st.Original.TryGetValue("ip:addr", out var old);

            for (int round = 0; round < 3; round++)
            {
                Sh("ipconfig", "/release \"" + name + "\"");
                Sh("ipconfig", "/renew \"" + name + "\"");

                for (int i = 0; i < 25; i++)
                {
                    var cur = Current();
                    if (cur.name != null && !string.IsNullOrEmpty(cur.ip) && cur.ip != old)
                        return cur.ip;
                    System.Threading.Thread.Sleep(200);
                }
            }

            var last = Current();
            return last.ip ?? "";
        }

        public static void Revert(State st)
        {
            if (!st.Original.TryGetValue("ip:name", out var name)) return;
            if (st.Original.TryGetValue("ip:dhcp", out var d) && d == "1")
            {
                Sh("netsh", $"interface ipv4 set address name=\"{name}\" dhcp");
                Sh("netsh", $"interface ipv4 set dnsservers name=\"{name}\" dhcp");
            }
            else if (st.Original.TryGetValue("ip:addr", out var a))
            {
                Sh("netsh", $"interface ipv4 set address name=\"{name}\" static {a} " +
                            $"{st.Original["ip:mask"]} {st.Original["ip:gw"]}");
            }
        }

        public static void RestartNic()
        {
            var c = Current();
            if (c.name == null) return;
            Sh("powershell", "-NoProfile -Command \"Restart-NetAdapter -Name '" + c.name + "' -Confirm:$false\"");
            for (int i = 0; i < 60; i++)
            {
                if (Current().name != null) break;
                System.Threading.Thread.Sleep(250);
            }
        }
        static void Sh(string exe, string args)
        {
            try
            {
                var p = Process.Start(new ProcessStartInfo(exe, args)
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true });
                p.WaitForExit(8000);
            }
            catch { }
        }
    }
}