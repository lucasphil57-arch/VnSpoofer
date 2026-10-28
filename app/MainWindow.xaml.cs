using System;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using VnSpoofer.Services;

namespace VnSpoofer
{
    public partial class MainWindow : Window
    {
        readonly DriverClient _drv = new DriverClient();
        Identity _id;

        public MainWindow()
        {
            InitializeComponent();
            Native.Round(this);
            Generate();
            Log("Pret. Provider KDU en mode rotatif.", "#7C8797");
        }

        void Drag(object s, MouseButtonEventArgs e) { try { DragMove(); } catch { } }
        void Min_Click(object s, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        void Close_Click(object s, RoutedEventArgs e) => Close();
        void Gen_Click(object s, RoutedEventArgs e) => Generate();

        void Generate()
        {
            _id = Identity.Random();
            TxUuid.Text = _id.Uuid; TxDisk.Text = _id.Disk; TxVol.Text = _id.Volume;
            TxMac.Text = _id.Mac; TxGuid.Text = _id.Guid;
        }

        void Log(string m, string c = "#E7ECF3")
        {
            Log_.Inlines.Add(new Run("[" + DateTime.Now.ToString("HH:mm:ss") + "] ")
            { Foreground = new SolidColorBrush(Color.FromRgb(0x5B, 0x8C, 0xFF)) });
            Log_.Inlines.Add(new Run(m + "\n") { Foreground = (Brush)new BrushConverter().ConvertFromString(c) });
            LogScroll.ScrollToEnd();
        }

        void Pill(string t, string c, string fg)
        {
            PillText.Text = t;
            Pill.Background = (Brush)new BrushConverter().ConvertFromString(c);
            PillText.Foreground = (Brush)new BrushConverter().ConvertFromString(fg);
        }

        uint Flags()
        {
            uint f = 0;
            if (ChkDisk.IsChecked == true) f |= 0x01;
            if (ChkVolume.IsChecked == true) f |= 0x02;
            if (ChkSmbios.IsChecked == true) f |= 0x04;
            if (ChkMac.IsChecked == true) f |= 0x08;
            if (ChkGuid.IsChecked == true) f |= 0x10;
            if (ChkGpu.IsChecked == true) f |= 0x20;
            return f;
        }

        async void Spoof_Click(object s, RoutedEventArgs e)
        {
            BtnSpoof.IsEnabled = false;
            try
            {
                if (ChkCleanBefore.IsChecked == true) await Cleaner.RunAsync(Log);
                if (!_drv.Mapped)
                {
                    Log("Mapping du driver...", "#F5A623");
                    if (!await _drv.MapAsync(CmbProvider.SelectedIndex, Log))
                    { Log("Mapping echoue : desactive la blocklist / HVCI.", "#FF5C5C"); return; }
                }
                if (!_drv.Apply(_id, Flags())) { Log("IOCTL_APPLY echoue.", "#FF5C5C"); return; }
                Pill("ACTIF", "#33D17A", "#0A0C0F");
                BtnRevert.IsEnabled = true;
                Log("Spoof applique.", "#33D17A");
                if (ChkLaunch.IsChecked == true) _drv.LaunchApex(Log);
            }
            finally { BtnSpoof.IsEnabled = true; }
        }

        async void Revert_Click(object s, RoutedEventArgs e)
        {
            await _drv.RevertAsync();
            Pill("INACTIF", "#1E242C", "#7C8797");
            BtnRevert.IsEnabled = false;
            Log("Identite restauree.", "#7C8797");
        }

        async void Clean_Click(object s, RoutedEventArgs e)
        {
            BtnClean.IsEnabled = false;
            await Cleaner.RunAsync(Log);
            BtnClean.IsEnabled = true;
        }
    }
}