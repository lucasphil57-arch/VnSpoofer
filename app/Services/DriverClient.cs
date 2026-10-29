using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace VnSpoofer.Services
{
    class DriverClient
    {
        const uint IOCTL_APPLY = 0x00222000;
        const uint IOCTL_REVERT = 0x00222004;
        const uint IOCTL_STATE = 0x00222008;

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

        public void Stat() { if (Mapped) Native.DeviceIoControl(_h, IOCTL_STATE, null, 0, new byte[1], 1, out _, IntPtr.Zero); }

        IntPtr _h = new IntPtr(-1);
        public bool Mapped => _h != new IntPtr(-1);

        public bool TryOpen()
        {
            if (Mapped) return true;
            _h = Native.CreateFileW(@"\\.\VnSpoofer", 0xC0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
            return Mapped;
        }

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
            Extract("drv64.dll", Path.Combine(Dir, "drv64.dll"));

            if (TryOpen()) { log("device deja present", "#33D17A"); return true; }

            var ids = new List<string>();
            string csv = Path.Combine(Dir, "prov.csv");
            try
            {
                var lp = Process.Start(new ProcessStartInfo(kdu, $"-listcsv \"{csv}\"")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, WorkingDirectory = Dir });
                await lp.WaitForExitAsync();
                if (File.Exists(csv))
                {
                    foreach (var line in File.ReadAllLines(csv))
                    {
                        var tok = line.Split(new[] { ',', ';' })[0].Trim().Trim('"');
                        if (int.TryParse(tok, out int id) && id >= 0 && id < 100 && !ids.Contains(tok)) ids.Add(tok);
                    }
                }
            }
            catch { }

            if (ids.Count == 0) { for (int i = 0; i < 71; i++) ids.Add(i.ToString()); }
            log($"{ids.Count} providers a essayer", "#7C8797");

            string last = "";
            foreach (var id in ids)
            {
                log($"tentative provider {id}", "#7C8797");
                try
                {
                    var mp = Process.Start(new ProcessStartInfo(kdu, $"-prv {id} -scv 3 -drvn VnSpoofer -drvr VnSpoofer -map \"{sys}\"")
                    { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, WorkingDirectory = Dir });
                    last = await mp.StandardOutput.ReadToEndAsync();
                    await mp.WaitForExitAsync();
                    if (TryOpen()) { log($"driver mappe via provider {id}", "#33D17A"); return true; }
                }
                catch { }
            }

            if (last.Length > 400) last = last.Substring(last.Length - 400);
            log(last.Replace("\r\n", " | "), "#5E6A7C");
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

                static byte[] ParseSeq(string s)
        {
            try
            {
                var x = (s ?? "").Replace("-", "").Trim();
                if (x.Length >= 32)
                {
                    var b = new byte[16];
                    for (int i = 0; i < 16; i++) b[i] = Convert.ToByte(x.Substring(i * 2, 2), 16);
                    return b;
                }
            }
            catch { }
            return Guid.TryParse(s, out var g) ? g.ToByteArray() : new byte[16];
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