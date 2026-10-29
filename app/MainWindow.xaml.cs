using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using VnSpoofer.Services;

namespace VnSpoofer
{
    public partial class MainWindow : Window
    {
        readonly DriverClient _drv = new DriverClient();
        State _st;
        Identity _id;
        int _cd;
        DispatcherTimer _timer;

        public MainWindow()
        {
            InitializeComponent();
            Native.Round(this);
            _st = State.Load();

            if (_st.Pending && _st.Id != null)
            {
                _id = _st.Id;
                Nav(2);
                _ = ResumeAsync();
            }
            else
            {
                _st = new State();
                _id = Identity.Random();
                CaptureOriginals();
                Fill();
                Nav(0);
                Log("Pret. Provider KDU en mode rotatif.", "#7C8797");
            }
        }

        void Drag(object s, MouseButtonEventArgs e) { try { DragMove(); } catch { } }
        void Min_Click(object s, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        void Close_Click(object s, RoutedEventArgs e) => Close();

        void Nav_Click(object s, RoutedEventArgs e)
        {
            if (((FrameworkElement)s).Tag is string t && int.TryParse(t, out int i)) Nav(i);
        }

        void Nav(int i)
        {
            SecDash.Visibility = i == 0 ? Visibility.Visible : Visibility.Collapsed;
            SecComp.Visibility = i == 1 ? Visibility.Visible : Visibility.Collapsed;
            SecVerif.Visibility = i == 2 ? Visibility.Visible : Visibility.Collapsed;
            SecClean.Visibility = i == 3 ? Visibility.Visible : Visibility.Collapsed;
            SecLogs.Visibility = i == 4 ? Visibility.Visible : Visibility.Collapsed;
            SecTuto.Visibility = i == 5 ? Visibility.Visible : Visibility.Collapsed;
            NavDash.IsChecked = i == 0; NavComp.IsChecked = i == 1; NavVerif.IsChecked = i == 2;
            NavClean.IsChecked = i == 3; NavLogs.IsChecked = i == 4; NavTuto.IsChecked = i == 5;
        }

        void Log(string m, string c = "#E7ECF3")
        {
            TxtLog.Inlines.Add(new Run("[" + DateTime.Now.ToString("HH:mm:ss") + "] ")
            { Foreground = new SolidColorBrush(Color.FromRgb(0x5B, 0x8C, 0xFF)) });
            TxtLog.Inlines.Add(new Run(m + "\n") { Foreground = (Brush)new BrushConverter().ConvertFromString(c) });
            LogScroll.ScrollToEnd();
        }

        void SetPill(string t, string bg, string fg)
        {
            PillText.Text = t;
            PillBg.Background = (Brush)new BrushConverter().ConvertFromString(bg);
            PillText.Foreground = (Brush)new BrushConverter().ConvertFromString(fg);
            PillDot.Fill = (Brush)new BrushConverter().ConvertFromString(fg);
        }

        void Fill()
        {
            TxtUuid.Text = _id.Uuid;
            TxtDisk.Text = _id.Disk;
            TxtMac.Text = _id.Mac;
            TxtGuid.Text = _id.Guid;
        }

        void CaptureOriginals()
        {
            foreach (var k in Keys.All) _st.Original[k] = Probe.Read(k);
        }

        uint Flags()
        {
            uint f = 0;
            if (SwSmbios.IsChecked == true) f |= 0x04;
            if (SwDisk.IsChecked == true) f |= 0x01;
            if (SwVolume.IsChecked == true) f |= 0x02;
            if (SwMac.IsChecked == true) f |= 0x08;
            if (SwGuid.IsChecked == true) f |= 0x10;
            if (SwGpu.IsChecked == true) f |= 0x20;
            return f;
        }

        async System.Threading.Tasks.Task<bool> EnsureMapped()
        {
            if (_drv.TryOpen()) return true;
            Log("Mapping du driver...", "#F5A623");
            if (await _drv.MapAsync(CmbProvider.SelectedIndex, Log)) return true;
            Log("Mapping echoue : desactive la liste de blocage des pilotes vulnerables puis redemarre.", "#FF5C5C");
            return false;
        }

        async void Spoof_Click(object s, RoutedEventArgs e)
        {
            BtnSpoof.IsEnabled = false;
            try
            {
                if (ChkCleanBefore.IsChecked == true) await Cleaner.RunAsync(Log);
                if (!await EnsureMapped()) return;

                await _drv.RevertAsync();
                IpSpoof.Revert(_st);
                MonitorSpoof.Revert(_st);

                _st = new State();
                CaptureOriginals();
                _id = Identity.Random();
                Fill();

                uint flags = Flags();
                _st.Flags = (int)flags;
                _st.Id = _id;

                if (flags != 0 && !_drv.Apply(_id, flags)) { Log("IOCTL_APPLY echoue.", "#FF5C5C"); return; }

                _st.Expected["uuid"] = _id.Uuid;
                _st.Expected["board"] = _id.Board;
                _st.Expected["bios"] = _id.Bios;
                _st.Expected["product"] = _id.Product;
                _st.Expected["disk"] = _id.Disk;
                _st.Expected["volume"] = uint.TryParse(_id.Volume, out var _vv) ? _vv.ToString("X8") : _id.Volume;
                _st.Expected["mac"] = _id.Mac;
                _st.Expected["guid"] = _id.Guid;
                if (SwGpu.IsChecked == true && _st.Original.TryGetValue("gpu", out var _go) && !string.IsNullOrEmpty(_go)) _st.Expected["gpu"] = _go + "-SPOOF";

                if (SwIp.IsChecked == true) { var _nip = IpSpoof.Apply(_st); if (!string.IsNullOrEmpty(_nip)) _st.Expected["ip"] = _nip; }
                if (SwMon.IsChecked == true) { var _nmo = MonitorSpoof.Apply(_id, _st); if (!string.IsNullOrEmpty(_nmo)) _st.Expected["monitor"] = _nmo; }
                if (SwMac.IsChecked == true) IpSpoof.RestartNic();

                _st.Pending = true;
                _st.Save();

                SetPill("SPOOFE", "#33D17A", "#0A0C0F");
                TxtDashTitle.Text = "Spoof applique";
                BtnRevert.IsEnabled = true;
                Log("Spoof applique et identite sauvegardee.", "#33D17A");
                TxtCountdown.Text = "Spoof actif. Controle ci-contre, puis lance le jeu.";
                Nav(2);
                Refresh();

            }
            finally { BtnSpoof.IsEnabled = true; }
        }

        async System.Threading.Tasks.Task ResumeAsync()
        {
            SetPill("VERIF", "#F5A623", "#0A0C0F");
            Log("Identite precedente detectee, re-application pour verification...", "#F5A623");
            if (!await EnsureMapped()) return;

            if (_st.Expected == null) _st.Expected = new Dictionary<string, string>(); if (_st.Original == null) _st.Original = new Dictionary<string, string>(); if (_id == null || string.IsNullOrEmpty(_id.Uuid))
            {
                _id = new Identity { MonA = 'A', MonB = 'A', MonC = 'A' };
                if (_st.Expected.TryGetValue("uuid", out var _u)) _id.Uuid = _u;
                if (_st.Expected.TryGetValue("board", out var _b)) _id.Board = _b;
                if (_st.Expected.TryGetValue("bios", out var _bi)) _id.Bios = _bi;
                if (_st.Expected.TryGetValue("product", out var _p)) _id.Product = _p;
                if (_st.Expected.TryGetValue("disk", out var _d)) _id.Disk = _d;
                if (_st.Expected.TryGetValue("volume", out var _v)) _id.Volume = uint.TryParse(_v, System.Globalization.NumberStyles.HexNumber, null, out var _vd) ? _vd.ToString() : _v;
                if (_st.Expected.TryGetValue("mac", out var _m)) _id.Mac = _m;
                if (_st.Expected.TryGetValue("guid", out var _g)) _id.Guid = _g;
            }

            _st.Expected["uuid"] = _id.Uuid;
            _st.Expected["board"] = _id.Board;
            _st.Expected["bios"] = _id.Bios;
            _st.Expected["product"] = _id.Product;
            _st.Expected["disk"] = _id.Disk;
            _st.Expected["volume"] = uint.TryParse(_id.Volume, out var _vv) ? _vv.ToString("X8") : _id.Volume;
            _st.Expected["mac"] = _id.Mac;
            _st.Expected["guid"] = _id.Guid;
            if (_st.Original.TryGetValue("gpu", out var _g2) && !string.IsNullOrEmpty(_g2)) _st.Expected["gpu"] = _g2 + "-SPOOF";
            uint flags = (uint)_st.Flags;
            await _drv.RevertAsync(); if (flags != 0 && _drv.Apply(_id, flags)) Log("Re-applique.", "#33D17A"); else Log("Re-application echouee.", "#E5484D");
            BtnRevert.IsEnabled = true;
            Refresh();
        }

        void Refresh()
        {
            var rows = new List<Row>();
            int ok = 0;
            foreach (var k in Keys.All)
            {
                _st.Original.TryGetValue(k, out var orig);
                _st.Expected.TryGetValue(k, out var exp);
                string act = Probe.Read(k);
                bool good = !string.IsNullOrEmpty(exp) && act == exp;
                if (good) ok++;
                rows.Add(new Row
                {
                    Label = Keys.Label(k),
                    Original = orig ?? "",
                    Expected = string.IsNullOrEmpty(exp) ? "-" : exp,
                    Actual = act,
                    Mark = good ? "OK" : "X",
                    Color = good ? "#33D17A" : "#FF5C5C"
                });
            }
            _drv.Stat();
            VerifyList.ItemsSource = rows;
            TxtVerifySum.Text = $"{ok} / {Keys.All.Length} composants conformes";
        }

        void Refresh_Click(object s, RoutedEventArgs e) => Refresh();

        async void Revert_Click(object s, RoutedEventArgs e)
        {
            await _drv.RevertAsync();
            IpSpoof.Revert(_st);
            MonitorSpoof.Revert(_st);
            State.Wipe();
            SetPill("INACTIF", "#1E242C", "#7C8797");
            TxtDashTitle.Text = "Aucun spoof actif";
            BtnRevert.IsEnabled = false;
            _st = new State();
            _id = Identity.Random();
            Fill();
            TxtCountdown.Text = "";
            Log("Identite restauree.", "#7C8797");
            Refresh();
        }

        void StartCountdown()
        {
            _cd = 15;
            TxtCountdown.Text = $"Redemarrage dans {_cd}s";
            BtnCancelCd.Visibility = Visibility.Visible;
            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _timer.Tick += (a, b) =>
            {
                _cd--;
                TxtCountdown.Text = $"Redemarrage dans {_cd}s";
                if (_cd <= 0) { _timer.Stop(); DoReboot(); }
            };
            _timer.Start();
        }

        void CancelCd_Click(object s, RoutedEventArgs e)
        {
            _timer?.Stop();
            BtnCancelCd.Visibility = Visibility.Collapsed;
            TxtCountdown.Text = "Redemarrage annule";
        }

        void Reboot_Click(object s, RoutedEventArgs e) => DoReboot();

        static void DoReboot()
        {
            try
            {
                Process.Start(new ProcessStartInfo("shutdown.exe", "/r /t 5 /c \"VnSpoofer\"")
                { UseShellExecute = false, CreateNoWindow = true });
            }
            catch { }
        }

        void Profile_Click(object s, RoutedEventArgs e)
        {
            string p = (s as FrameworkElement)?.Tag as string ?? "solo";
            SwSmbios.IsChecked = true;
            SwDisk.IsChecked = true;
            SwVolume.IsChecked = true;
            SwMac.IsChecked = true;
            SwGuid.IsChecked = true;
            SwGpu.IsChecked = true;
            SwIp.IsChecked = true;
            SwMon.IsChecked = true;
            Nav(1);
            Log($"Profil {p} charge : les 8 composants sont armes. Applique puis verifie avant de lancer le jeu.", "#33D17A");
        }
        async void Clean_Click(object s, RoutedEventArgs e)
        {
            await Cleaner.RunAsync(Log);
            Nav(4);
        }
    }
}
