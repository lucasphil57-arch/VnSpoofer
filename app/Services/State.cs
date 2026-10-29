using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace VnSpoofer.Services
{
    class State
    {
        public bool Pending { get; set; }
        public int Flags { get; set; }
        public Identity Id { get; set; } = new Identity();
        public Dictionary<string, string> Original { get; set; } = new Dictionary<string, string>();
        public Dictionary<string, string> Expected { get; set; } = new Dictionary<string, string>();

        static readonly JsonSerializerOptions Opt = new JsonSerializerOptions { IncludeFields = true, WriteIndented = true };

        static string Dir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VnSpoofer");
        static string File => Path.Combine(Dir, "state.json");

        public static State Load()
        {
            try
            {
                if (System.IO.File.Exists(File))
                    return JsonSerializer.Deserialize<State>(System.IO.File.ReadAllText(File), Opt) ?? new State();
            }
            catch { }
            return new State();
        }

        public void Save()
        {
            Directory.CreateDirectory(Dir);
            System.IO.File.WriteAllText(File, JsonSerializer.Serialize(this, Opt));
        }

        public static void Wipe()
        {
            try { System.IO.File.Delete(File); } catch { }
        }
    }
}
