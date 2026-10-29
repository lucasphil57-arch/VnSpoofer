using System;
using System.IO;
using Microsoft.Win32;

namespace VnSpoofer.Services
{
    static class MacReg
    {
        const string ClassKey = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";

        static string File_()
        {
            var d = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VnSpoofer");
            Directory.CreateDirectory(d);
            return Path.Combine(d, "macbackup.txt");
        }

        public static void Backup(State st)
        {
            var f = File_();
            if (File.Exists(f)) return;

            var lines = new System.Collections.Generic.List<string>();
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
                            lines.Add(name + "|" + (v ?? ""));
                        }
                    }
                }
                File.WriteAllLines(f, lines);
            }
            catch { }
        }

        public static void Restore(State st)
        {
            var f = File_();
            if (!File.Exists(f)) return;

            try
            {
                using (var root = Registry.LocalMachine.OpenSubKey(ClassKey, true))
                {
                    if (root == null) return;
                    foreach (var line in File.ReadAllLines(f))
                    {
                        int bar = line.IndexOf('|');
                        if (bar < 0) continue;
                        string name = line.Substring(0, bar);
                        string old = line.Substring(bar + 1);
                        using (var k = root.OpenSubKey(name, true))
                        {
                            if (k == null) continue;
                            if (old.Length == 0) k.DeleteValue("NetworkAddress", false);
                            else k.SetValue("NetworkAddress", old, RegistryValueKind.String);
                        }
                    }
                }
                File.Delete(f);
            }
            catch { }
        }
    }
}