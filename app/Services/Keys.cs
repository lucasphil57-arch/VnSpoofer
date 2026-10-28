namespace VnSpoofer.Services
{
    static class Keys
    {
        public static readonly string[] All =
        {
            "uuid", "board", "bios", "product", "disk", "volume", "mac", "guid", "gpu", "ip", "monitor"
        };

        public static string Label(string k) => k switch
        {
            "uuid" => "UUID carte mere",
            "board" => "Serial carte mere",
            "bios" => "Serial BIOS",
            "product" => "Modele carte mere",
            "disk" => "Serial disque",
            "volume" => "Serial volume",
            "mac" => "Adresse MAC",
            "guid" => "MachineGuid",
            "gpu" => "Identifiant GPU",
            "ip" => "Adresse IP",
            "monitor" => "Identifiant ecran",
            _ => k
        };
    }

    class Row
    {
        public string Label { get; set; }
        public string Original { get; set; }
        public string Expected { get; set; }
        public string Actual { get; set; }
        public string Mark { get; set; }
        public string Color { get; set; }
    }
}
