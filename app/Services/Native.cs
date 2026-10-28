using System;
using System.Runtime.InteropServices;
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