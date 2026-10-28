using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace VnSpoofer.Services
{
    class DriverClient
    {
        const uint IOCTL_APPLY = 0x00222000 | 0x800;
        const uint IOCTL_REVERT = 0x00222000 | 0x801;

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
        struct Cfg
        {
            public uint Flags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 24)] public string DiskSerial;
            public uint VolumeSerial;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] Mac;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] Uuid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 24)] public string BoardSerial;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 24)] public string BiosSerial;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 24)] public string SysProduct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 40)] public string MachineGuid;
        }

        IntPtr _h = new IntPtr(-1);
        public bool Mapped => _h != new IntPtr(-1);

        static string Dir => Path.Combine(Path.GetTempPath(), "VnSpoofer");

        static void Extract(string res, string dst)
        {
            using var s = typeof(DriverClient).Assembly.GetManifestResourceStream(res);
            using var f = File.Create(dst);
            s.CopyTo(f);
        }

        public async Task<bool> MapAsync(int providerIndex, Action<string, string> log)
        {
            Directory.CreateDirectory(Dir);
            string sys = Path.Combine(Dir, "VnSpoofer.sys");
            string kdu = Path.Combine(Dir, "kdu.exe");
            Extract("VnSpoofer.sys", sys);
            Extract("kdu.exe", kdu);

            var providers = new System.Collections.Generic.List<string>();
            try
            {
                var lp = Process.Start(new ProcessStartInfo(kdu, "-list")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true });
                string outp = await lp.StandardOutput.ReadToEndAsync();
                await lp.WaitForExitAsync();
                foreach (System.Text.RegularExpressions.Match m in
                         System.Text.RegularExpressions.Regex.Matches(outp, @"^\s*\[?(\d{1,3})\]?", System.Text.RegularExpressions.RegexOptions.Multiline))
                    if (!providers.Contains(m.Groups[1].Value)) providers.Add(m.Groups[1].Value);
            }
            catch { }

            if (providerIndex > 0 && providerIndex - 1 < providers.Count)
                providers = new System.Collections.Generic.List<string> { providers[providerIndex - 1] };

            foreach (var p in providers)
            {
                log($"tentative provider {p}", "#7C8797");
                try
                {
                    var mp = Process.Start(new ProcessStartInfo(kdu, $"-map \"{sys}\" -provider {p}")
                    { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true });
                    await mp.WaitForExitAsync();
                    if (mp.ExitCode == 0)
                    {
                        _h = Native.CreateFileW(@"\\.\VnSpoofer", 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
                        if (Mapped) { log($"driver mappe via provider {p}", "#33D17A"); return true; }
                    }
                }
                catch { }
            }
            return false;
        }

        static byte[] Pack(Identity id)
        {
            var c = new Cfg
            {
                Flags = 0x1F,
                DiskSerial = id.Disk,
                VolumeSerial = uint.Parse(id.Volume),
                Mac = id.Mac.Split(':').Select(x => Convert.ToByte(x, 16)).ToArray(),
                Uuid = Guid.Parse(id.Uuid).ToByteArray(),
                BoardSerial = id.Board,
                BiosSerial = id.Bios,
                SysProduct = id.Product,
                MachineGuid = id.Guid
            };
            int sz = Marshal.SizeOf<Cfg>();
            IntPtr p = Marshal.AllocHGlobal(sz);
            Marshal.StructureToPtr(c, p, false);
            var b = new byte[sz];
            Marshal.Copy(p, b, 0, sz);
            Marshal.FreeHGlobal(p);
            return b;
        }

        public bool Apply(Identity id, uint flags)
        {
            if (!Mapped) return false;
            var b = Pack(id);
            BitConverter.GetBytes(flags).CopyTo(b, 0);
            return Native.DeviceIoControl(_h, IOCTL_APPLY, b, (uint)b.Length, null, 0, out _, IntPtr.Zero);
        }

        public Task RevertAsync()
        {
            if (Mapped) Native.DeviceIoControl(_h, IOCTL_REVERT, null, 0, null, 0, out _, IntPtr.Zero);
            return Task.CompletedTask;
        }

        public void RestorePendingGuid() { }

        public void LaunchApex(Action<string, string> log)
        {
            string[] paths =
            {
                @"C:\Program Files (x86)\Steam\steamapps\common\Apex Legends\r5apex.exe",
                @"C:\Program Files\EA Games\Apex Legends\r5apex.exe",
                @"C:\Program Files\Electronic Arts\EA Games\Apex Legends\r5apex.exe"
            };
            foreach (var p in paths)
                if (File.Exists(p))
                {
                    Process.Start(new ProcessStartInfo(p) { WorkingDirectory = Path.GetDirectoryName(p) });
                    log("Apex lance.", "#33D17A");
                    return;
                }
            try { Process.Start(new ProcessStartInfo("steam://rungameid/1172470") { UseShellExecute = true }); log("Apex lance via Steam.", "#33D17A"); }
            catch { log("Apex introuvable, lance-le a la main.", "#F5A623"); }
        }
    }
}