using System;
using Microsoft.Win32;

namespace VnSpoofer.Services
{
    static class MacReg
    {
        const string ClassKey = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";

        public static void Backup(State st)
        {
            int i = 0;
            try
            {
                using (var root = Registry.LocalMachine.OpenSubKey(ClassKey, false))
                {
                    if (root == null) return;
                    foreach (var name in root.GetSubKeyNames())
                    {
                        using (var k = root.OpenSubKey(name, false))
                        {
                            if (k == null) continue;
                            using (var ndi = k.OpenSubKey(@"Ndi\Params\NetworkAddress"))
                            {
                                if (ndi == null) continue;
                            }
                            var v = k.GetValue("NetworkAddress") as string;
                            st.Original["mac:" + i++] = name + "|" + (v ?? "");
                        }
                    }
                }
            }
            catch { }
        }

        public static void Restore(State st)
        {
            try
            {
                using (var root = Registry.LocalMachine.OpenSubKey(ClassKey, true))
                {
                    if (root == null) return;
                    foreach (var pair in st.Original)
                    {
                        if (!pair.Key.StartsWith("mac:")) continue;
                        int bar = pair.Value.IndexOf('|');
                        if (bar < 0) continue;
                        string name = pair.Value.Substring(0, bar);
                        string old = pair.Value.Substring(bar + 1);
                        using (var k = root.OpenSubKey(name, true))
                        {
                            if (k == null) continue;
                            if (old.Length == 0) k.DeleteValue("NetworkAddress", false);
                            else k.SetValue("NetworkAddress", old, RegistryValueKind.String);
                        }
                    }
                }
            }
            catch { }
        }
    }
}