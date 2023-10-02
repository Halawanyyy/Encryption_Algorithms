using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<ulong> primitive = new List<ulong>();
            List<int> Keys = new List<int>();
            ulong result = 1, y = 1, k = 1;
            ulong baseValue = (ulong)(alpha % q);
            primitive.Add(baseValue);
            //check primitive
            /* for (int i = 2; i <= q - 1; i++)
             {
                 int e = i;
                 result = 1;
                 baseValue = (ulong)(alpha % q);
                 while (e > 0)
                 {
                     if ((e & 1) != 0)
                     {
                         result = (result * baseValue) % (ulong)q;
                     }
                     e /= 2;
                     baseValue = (baseValue * baseValue) % (ulong)q;
                 }
                 if (primitive.Contains(result))
                 {
                     Keys.Add(-1);
                     Keys.Add(-1);
                     return Keys;
                 }
                 else
                 {
                     primitive.Add(result);
                 }
             }*/
            int power_y = Math.Max(xa, xb);
            ulong base_alpha = (ulong)(alpha % q);
            while (power_y > 0)
            {
                if ((power_y & 1) != 0)
                {
                    y = (y * base_alpha) % (ulong)q;
                }
                power_y /= 2;
                base_alpha = (base_alpha * base_alpha) % (ulong)q;
            }
            int power_k = Math.Min(xa, xb);
            ulong base_k = y % (ulong)q;
            while (power_k > 0)
            {
                if ((power_k & 1) != 0)
                {
                    k = (k * base_k) % (ulong)q;
                }
                power_k /= 2;
                base_k = (base_k * base_k) % (ulong)q;
            }
            Keys.Add((int)k);
            Keys.Add((int)k);
            return Keys;
        }
    }
}