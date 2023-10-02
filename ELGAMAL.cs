using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            //throw new NotImplementedException();
            int power_K = k;
            ulong base_K = (ulong)(y);
            ulong K = 1;
            while (power_K > 0)
            {
                if ((power_K & 1) != 0)
                {
                    K = (K * base_K) % (ulong)q;
                }
                power_K /= 2;
                base_K = (base_K * base_K) % (ulong)q;
            }
            int power_c1 = k;
            ulong base_c1 = (ulong)(alpha);
            ulong C1 = 1;
            while (power_c1 > 0)
            {
                if ((power_c1 & 1) != 0)
                {
                    C1 = (C1 * base_c1) % (ulong)q;
                }
                power_c1 /= 2;
                base_c1 = (base_c1 * base_c1) % (ulong)q;
            }
            long C2 = (int)((K * (ulong)m) % (ulong)q);
            List<long> Ci = new List<long>();
            Ci.Add((long)C1);
            Ci.Add((long)C2);
            return Ci;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            //throw new NotImplementedException();
            int power_K = x;
            ulong base_K = (ulong)(c1);
            ulong K = 1;
            while (power_K > 0)
            {
                if ((power_K & 1) != 0)
                {
                    K = (K * base_K) % (ulong)q;
                }
                power_K /= 2;
                base_K = (base_K * base_K) % (ulong)q;
            }
            ExtendedEuclid EX = new ExtendedEuclid();
            int temp1= EX.GetMultiplicativeInverse((int)K, q);
            int M = (int)((long)c2 * temp1)%q;
            return M;
        }
    }
}
