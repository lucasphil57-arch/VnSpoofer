using System.Diagnostics;

namespace VnSpoofer.Services
{
    static class Reg
    {
        public static bool Delete(string hive, string key)
        {
            try
            {
                var p = Process.Start(new ProcessStartInfo("reg.exe", $"delete \"{hive}\\{key}\" /f")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true });
                p.WaitForExit();
                return p.ExitCode == 0;
            }
            catch { return false; }
        }
    }
}