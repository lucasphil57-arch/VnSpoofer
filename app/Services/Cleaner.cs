using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

namespace VnSpoofer.Services
{
    static class Cleaner
    {
        static readonly string[] Dirs =
        {
            @"%ProgramData%\EasyAntiCheat\Cache",
            @"%LOCALAPPDATA%\EasyAntiCheat",
            @"%APPDATA%\Respawn",
            @"%LOCALAPPDATA%\Respawn",
            @"%USERPROFILE%\Saved Games\Respawn\Apex",
            @"%TEMP%\VnSpoofer"
        };

        static readonly (string h, string k)[] Keys =
        {
            ("HKLM", @"SOFTWARE\EasyAntiCheat"),
            ("HKCU", @"Software\EasyAntiCheat"),
            ("HKLM", @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat")
        };

        static void ForceDelete(string p)
        {
            foreach (var f in Directory.GetFiles(p, "*", SearchOption.AllDirectories))
                try { File.SetAttributes(f, FileAttributes.Normal); } catch { }
            Directory.Delete(p, true);
        }
        public static async Task RunAsync(Action<string, string> log)
        {
            log("-- Cleaner --", "#5B8CFF");
            foreach (var d in Dirs)
            {
                string p = Environment.ExpandEnvironmentVariables(d);
                try { if (Directory.Exists(p)) { ForceDelete(p); log("supprime " + p, "#33D17A"); } }
                catch (Exception e) { log("echec " + p + " : " + e.Message, "#FF5C5C"); }
            }
            string pf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
            foreach (var pat in new[] { "R5APEX*.pf", "EASYANTICHEAT*.pf", "EAC*.pf" })
                try { foreach (var f in Directory.GetFiles(pf, pat)) { File.Delete(f); log("prefetch " + Path.GetFileName(f), "#33D17A"); } }
                catch { }
            foreach (var (h, k) in Keys) if (Reg.Delete(h, k)) log("cle " + h + "\\" + k, "#33D17A");
            await Sh("cmd.exe", "/c arp -d *");
            await Sh("ipconfig.exe", "/flushdns");
            await Sh("wevtutil.exe", "cl Application /q:true");
            log("Cleaner termine.", "#33D17A");
        }

        static async Task Sh(string e, string a)
        {
            try
            {
                var p = Process.Start(new ProcessStartInfo(e, a) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true });
                await p.WaitForExitAsync();
            }
            catch { }
        }
    }
}