using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Win32;

namespace VnSpoofer.Services
{
    static class MonitorSpoof
    {
        const string Root = @"SYSTEM\CurrentControlSet\Enum\DISPLAY";

        static string Decode(byte[] e)
        {
            int m = (e[8] << 8) | e[9];
            string v = new string(new[]
            {
                (char)(((m >> 10) & 0x1F) + 64),
                (char)(((m >> 5) & 0x1F) + 64),
                (char)((m & 0x1F) + 64)
            });
            uint serial = (uint)(e[12] | (e[13] << 8) | (e[14] << 16) | (e[15] << 24));
            return $"{v}-{serial:X8}";
        }

        public static string ReadCurrent()
        {
            using var k = Registry.LocalMachine.OpenSubKey(Root);
            if (k == null) return "";
            foreach (var vendor in k.GetSubKeyNames())
            {
                using var vk = k.OpenSubKey(vendor);
                if (vk == null) continue;
                foreach (var inst in vk.GetSubKeyNames())
                {
                    using var ik = vk.OpenSubKey(inst + @"\Device Parameters");
                    if (ik?.GetValue("EDID") is byte[] e && e.Length >= 128) return Decode(e);
                }
            }
            return "";
        }

        public static string Apply(Identity id, State st)
        {
            var rnd = new Random();
            string shown = "";
            using var k = Registry.LocalMachine.OpenSubKey(Root, true);
            if (k == null) return "";
            foreach (var vendor in k.GetSubKeyNames())
            {
                using var vk = k.OpenSubKey(vendor, true);
                if (vk == null) continue;
                foreach (var inst in vk.GetSubKeyNames())
                {
                    using var ik = vk.OpenSubKey(inst + @"\Device Parameters", true);
                    if (!(ik?.GetValue("EDID") is byte[] src) || src.Length < 128) continue;

                    st.Original[$"mon:{vendor}\\{inst}"] = Convert.ToBase64String(src);
                    var e = (byte[])src.Clone();

                    int m = ((id.MonA - 64) << 10) | ((id.MonB - 64) << 5) | (id.MonC - 64);
                    e[8] = (byte)(m >> 8);
                    e[9] = (byte)(m & 0xFF);
                    uint serial = (uint)rnd.Next(int.MinValue, int.MaxValue);
                    e[12] = (byte)serial; e[13] = (byte)(serial >> 8);
                    e[14] = (byte)(serial >> 16); e[15] = (byte)(serial >> 24);
                    e[16] = (byte)rnd.Next(1, 53);
                    e[17] = (byte)(DateTime.Now.Year - 1990);

                    int sum = 0;
                    for (int i = 0; i < 127; i++) sum += e[i];
                    e[127] = (byte)(256 - (sum & 0xFF));

                    ik.SetValue("EDID", e, RegistryValueKind.Binary);
                    shown = Decode(e);
                }
            }
            return shown;
        }

        public static void Revert(State st)
        {
            using var k = Registry.LocalMachine.OpenSubKey(Root, true);
            if (k == null) return;
            foreach (var pair in st.Original)
            {
                if (!pair.Key.StartsWith("mon:")) continue;
                var parts = pair.Key.Substring(4).Split('\\');
                if (parts.Length != 2) continue;
                using var ik = k.OpenSubKey(parts[0] + "\\" + parts[1] + @"\Device Parameters", true);
                if (ik == null) continue;
                ik.SetValue("EDID", Convert.FromBase64String(pair.Value), RegistryValueKind.Binary);
            }
        }
    }
}
