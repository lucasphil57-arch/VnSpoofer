using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Interop;

namespace VnSpoofer.Services
{
    static class Native
    {
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);

        [DllImport("kernel32", SetLastError = true)]
        public static extern bool DeviceIoControl(IntPtr h, uint c, byte[] i, uint il, byte[] o, uint ol, out uint br, IntPtr ov);

        [DllImport("kernel32")]
        public static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetVolumeInformationW(string root, StringBuilder vol, int vsz,
            out uint serial, out uint maxLen, out uint flags, StringBuilder fs, int fsz);

        public static string VolumeSerial(string root)
        {
            var sb = new StringBuilder(32);
            var fs = new StringBuilder(32);
            if (GetVolumeInformationW(root, sb, 32, out uint s, out _, out _, fs, 32))
                return s.ToString("X8");
            return "";
        }

        [DllImport("user32")]
        public static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr w, IntPtr l);

        [DllImport("user32")]
        public static extern bool ReleaseCapture();

        public static void DragWindow(Window w)
        {
            try
            {
                var h = new WindowInteropHelper(w).Handle;
                if (h == IntPtr.Zero) return;
                ReleaseCapture();
                SendMessage(h, 0x00A1, (IntPtr)0x0002, IntPtr.Zero);
            }
            catch { }
        }

        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int val, int size);

        public static void Round(Window w)
        {
            try
            {
                var h = new WindowInteropHelper(w).EnsureHandle();
                int one = 2;
                DwmSetWindowAttribute(h, 33, ref one, sizeof(int));
            }
            catch { }
        }
    }
}
