using System;
using System.Text;

namespace VnSpoofer.Services
{
    class Identity
    {
        public string Uuid, Disk, Volume, Mac, Guid, Board, Bios, Product;
        public char MonA, MonB, MonC;

        static readonly Random R = new Random();
        const string AN = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        static string Rnd(string a, int n)
        {
            var sb = new StringBuilder(n);
            for (int i = 0; i < n; i++) sb.Append(a[R.Next(a.Length)]);
            return sb.ToString();
        }

        public static Identity Random()
        {
            var mac = new byte[6];
            R.NextBytes(mac);
            mac[0] = (byte)((mac[0] & 0xFC) | 0x02);

            return new Identity
            {
                Uuid = System.Guid.NewGuid().ToString("D"),
                Disk = Rnd(AN, 20),
                Volume = ((uint)R.Next()).ToString(),
                Mac = BitConverter.ToString(mac).Replace("-", ":"),
                Guid = System.Guid.NewGuid().ToString("D"),
                Board = Rnd(AN, 16),
                Bios = Rnd(AN, 16),
                Product = Rnd(AN, 16),
                MonA = (char)('A' + R.Next(26)),
                MonB = (char)('A' + R.Next(26)),
                MonC = (char)('A' + R.Next(26))
            };
        }
    }
}
