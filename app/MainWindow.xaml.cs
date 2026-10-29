using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
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
        readonly List<Button> _profBtns = new List<Button>();
        State _st;
        Identity _id;
        int _cd;
        DispatcherTimer _timer;

        public MainWindow()
        {
            InitializeComponent();
            _profBtns.AddRange(new[] { ProfAll, ProfJav, ProfEac, ProfBe, ProfVg, ProfRc, ProfSolo });
            Native.Round(this);
            _st = State.Load();

            if (_st.Pending && _st.Id != null)
            {
                _id = _st.Id;
                RestoreToggles();
                Nav(2);
                _ = ResumeAsync();
            }
            else
            {
                _st = new State();
                _id = Identity.Random();
                CaptureOriginals();
                Fill();
                SelectProfile("all");
                Nav(0);
                Log("Pret. Provider KDU en mode rotatif.", "#7C8797");
            }
        }

        async void Window_Loaded(object s, RoutedEventArgs e)
        {
            SplashBar.BeginAnimation(WidthProperty,
                new System.Windows.Media.Animation.DoubleAnimation(40, 220, TimeSpan.FromMilliseconds(1900)));
            await System.Threading.Tasks.Task.Delay(2150);
            var fade = new System.Windows.Media.Animation.DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(420));
            fade.Completed += (a, b) => Splash.Visibility = Visibility.Collapsed;
            Splash.BeginAnimation(OpacityProperty, fade);
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
            BusyShow("Preparation", "Fermeture des sessions precedentes");
            try
            {
                await System.Threading.Tasks.Task.Delay(280);

                if (ChkCleanBefore.IsChecked == true)
                {
                    BusyStep_("Nettoyage des traces", "Caches anti-triche, Prefetch, ARP, DNS");
                    await Cleaner.RunAsync(Log);
                }

                BusyStep_("Mapping du driver", "Provider : " + CmbProvider.Text);
                if (!await EnsureMapped()) { Log("Mapping echoue.", "#FF5C5C"); return; }

                BusyStep_("Retour a l'etat d'origine", "Restauration avant nouvelle identite");
                await System.Threading.Tasks.Task.Run(() => _drv.RevertAsync());
                await System.Threading.Tasks.Task.Run(() => { IpSpoof.Revert(_st); MonitorSpoof.Revert(_st); MacReg.Restore(_st); });
                await System.Threading.Tasks.Task.Delay(140);

                _st = new State();
                CaptureOriginals();
                _id = Identity.Random();
                if (_st.Original.TryGetValue("gpu", out var _gp) && !string.IsNullOrEmpty(_gp))
                {
                    if (_gp.EndsWith("-SPOOF")) _gp = _gp.Substring(0, _gp.Length - 6);
                    _st.Original["gpu"] = _gp;
                    _id.Gpu = _gp;
                }
                Fill();

                uint flags = Flags();
                _st.Flags = (int)flags;
                _st.Id = _id;

                BusyStep_("Application de l'identite", "SMBIOS, disque, volume, MAC, GUID, GPU");
                if (SwMac.IsChecked == true) await System.Threading.Tasks.Task.Run(() => MacReg.Backup(_st));
                bool okApply = flags == 0 || await System.Threading.Tasks.Task.Run(() => _drv.Apply(_id, flags));
                if (!okApply) { Log("IOCTL_APPLY echoue.", "#FF5C5C"); return; }
                await System.Threading.Tasks.Task.Delay(140);

                _st.Expected["uuid"] = _id.Uuid;
                _st.Expected["board"] = _id.Board;
                _st.Expected["bios"] = _id.Bios;
                _st.Expected["product"] = _id.Product;
                _st.Expected["disk"] = _id.Disk;
                _st.Expected["volume"] = uint.TryParse(_id.Volume, out var _vv) ? _vv.ToString("X8") : _id.Volume;
                _st.Expected["mac"] = _id.Mac;
                _st.Expected["guid"] = _id.Guid;
                if (SwGpu.IsChecked == true && _st.Original.TryGetValue("gpu", out var _go) && !string.IsNullOrEmpty(_go)) _st.Expected["gpu"] = _go + "-SPOOF";

                if (SwIp.IsChecked == true) await System.Threading.Tasks.Task.Run(() => IpSpoof.Prepare(_st));
                if (SwMon.IsChecked == true)
                {
                    BusyStep_("Configuration de l'ecran", "EDID");
                    var _nmo = await System.Threading.Tasks.Task.Run(() => MonitorSpoof.Apply(_id, _st));
                    if (!string.IsNullOrEmpty(_nmo)) _st.Expected["monitor"] = _nmo;
                    await System.Threading.Tasks.Task.Delay(140);
                }
                if (SwMac.IsChecked == true)
                {
                    BusyStep_("Redemarrage de la carte reseau", "Prise en compte de la nouvelle MAC");
                    await System.Threading.Tasks.Task.Run(() => IpSpoof.RestartNic());
                }
                if (SwIp.IsChecked == true)
                {
                    BusyStep_("Renouvellement du bail", "DHCP");
                    var _nip = await System.Threading.Tasks.Task.Run(() => IpSpoof.Apply(_st));
                    if (!string.IsNullOrEmpty(_nip)) _st.Expected["ip"] = _nip;
                }

                BusyStep_("Verification", "Controle des composants");
                _st.Pending = true;
                _st.Save();
                Nav(2);
                Refresh();
                await System.Threading.Tasks.Task.Delay(320);

                SetPill("SPOOFE", "#33D17A", "#0A0C0F");
                TxtDashTitle.Text = "Spoof applique";
                BtnRevert.IsEnabled = true;
                Log("Spoof applique et identite sauvegardee.", "#33D17A");
                TxtCountdown.Text = "Spoof actif. Controle ci-contre, puis lance le jeu.";
            }
            finally { BusyHide(); }
        }

        async System.Threading.Tasks.Task ResumeAsync()
        {
            SetPill("VERIF", "#F5A623", "#0A0C0F");
            Log("Identite precedente detectee, re-application pour verification...", "#F5A623");
            BusyShow("Reprise de l'identite", "Verification apres redemarrage");
            if (!await EnsureMapped()) { BusyHide(); return; }

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
            if (_st.Original.TryGetValue("gpu", out var _g2) && !string.IsNullOrEmpty(_g2))
            {
                if (_g2.EndsWith("-SPOOF")) _g2 = _g2.Substring(0, _g2.Length - 6);
                _st.Original["gpu"] = _g2;
                _id.Gpu = _g2;
                _st.Expected["gpu"] = _g2 + "-SPOOF";
            }
            uint flags = (uint)_st.Flags;
            await System.Threading.Tasks.Task.Run(() => _drv.RevertAsync());
            bool okRe = flags == 0 || await System.Threading.Tasks.Task.Run(() => _drv.Apply(_id, flags));
            Log(okRe ? "Re-applique." : "Re-application echouee.", okRe ? "#33D17A" : "#E5484D");
            BtnRevert.IsEnabled = true;
            Refresh();
            BusyHide();
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
            BusyShow("Restauration", "Retour a l'identite d'origine");
            try
            {
                await System.Threading.Tasks.Task.Run(() => _drv.RevertAsync());
                await System.Threading.Tasks.Task.Run(() => { IpSpoof.Revert(_st); MonitorSpoof.Revert(_st); MacReg.Restore(_st); });
            }
            finally { BusyHide(); }
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

        void SelectProfile(string p)
        {
            foreach (var b in _profBtns)
                b.Background = (Brush)new BrushConverter().ConvertFromString((string)b.Tag == p ? "#1B2233" : "#12161E");

            bool gpu = p == "all" || p == "solo" || p == "javelin" || p == "eac" || p == "battleye";
            bool net = p == "all" || p == "solo";

            SwSmbios.IsChecked = true;
            SwDisk.IsChecked = true;
            SwVolume.IsChecked = true;
            SwMac.IsChecked = true;
            SwGuid.IsChecked = true;
            SwGpu.IsChecked = gpu;
            SwIp.IsChecked = net;
            SwMon.IsChecked = net;

            TxtProfDesc.Text = p switch
            {
                "all" => "Tout est arme, IP et EDID compris. Sert a verifier que la chaine complete fonctionne.",
                "javelin" => "Javelin : SMBIOS, disque, volume, MAC, GUID, GPU. IP et EDID laisses de cote.",
                "eac" => "EAC hashe un composite : tous les identifiants materiels doivent tomber ensemble.",
                "battleye" => "BattlEye : identifiants materiels complets. Il voit aussi le pilote mappe, c'est la limite.",
                "vanguard" => "Vanguard : registre, disque, volume, MAC, GUID. GPU laisse tel quel pour ne pas forcer de reinstallation.",
                "ricochet" => "Ricochet : SMBIOS, disque, volume, MAC, GUID. Profil volontairement sobre.",
                _ => "Aucun risque de detection : tout peut rester arme."
            };
            Log($"Profil {p} arme.", "#33D17A");
        }

        void RestoreToggles()
        {
            uint f = (uint)_st.Flags;
            SwSmbios.IsChecked = (f & 0x04) != 0;
            SwDisk.IsChecked = (f & 0x01) != 0;
            SwVolume.IsChecked = (f & 0x02) != 0;
            SwMac.IsChecked = (f & 0x08) != 0;
            SwGuid.IsChecked = (f & 0x10) != 0;
            SwGpu.IsChecked = (f & 0x20) != 0;
            TxtProfDesc.Text = "Identite precedente reprise, interrupteurs restaures.";
        }

        void BusyShow(string step, string sub)
        {
            BusyStep.Text = step;
            BusySub.Text = sub;
            Busy.Visibility = Visibility.Visible;
            BtnSpoof.IsEnabled = false;
            BtnRevert.IsEnabled = false;
            BtnReboot.IsEnabled = false;
        }

        void BusyStep_(string step, string sub) { BusyStep.Text = step; BusySub.Text = sub; }

        void BusyHide()
        {
            Busy.Visibility = Visibility.Collapsed;
            BtnReboot.IsEnabled = true;
            BtnRevert.IsEnabled = _st != null && _st.Pending;
        }

        void Profile_Click(object s, RoutedEventArgs e)
        {
            SelectProfile((s as FrameworkElement)?.Tag as string ?? "all");
        }
        async void Clean_Click(object s, RoutedEventArgs e)
        {
            await Cleaner.RunAsync(Log);
            Nav(4);
        }
    }
}
