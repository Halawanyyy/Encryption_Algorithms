using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            for (int i = 2; i < Math.Max(p, q); i++)
            {
                if (p % i == 0 && q % i == 0)
                {
                    return -1;
                }
            }
            ulong n = (ulong)(p * q);
            ulong fay_n = (ulong)((p - 1) * (q-1));
                if ( 1 < e && (ulong)e < fay_n)
                {
                    ulong result = 1;
                    ulong baseValue =(ulong) M % n;
                    while (e > 0)
                    {
                        if ((e & 1) != 0)
                        {
                           result = (result * baseValue) % n;
                        }
                        e /= 2;
                        baseValue = (baseValue * baseValue) % n;
                    }
                    return (int)result;
                }
            
                else
                    return -1;
            }
           
        

        public int Decrypt(int p, int q, int C, int e)
        {
            for (int i = 2; i < Math.Max(p, q); i++)
            {
                if (p % i == 0 && q % i == 0)
                {
                    return -1;
                }
            }
            ulong n = (ulong)(p * q);
            ulong fay_n = (ulong)((p - 1) * (q - 1));
            ulong d = 0;
            for(ulong i = 1; i <= fay_n; i++)
            {
                if (((fay_n * i) + 1) % (ulong)e == 0)
                {
                    d = (((fay_n * i) + 1) / (ulong)e);
                    break;
                }
            }
            if (1 < e && (ulong)e < fay_n)
            {
                ulong result = 1;
                ulong baseValue = (ulong)C % n;
                while (d > 0)
                {
                    if ((d & 1) != 0)
                    {
                        result = (result * baseValue) % n;
                    }
                    d /= 2;
                    baseValue = (baseValue * baseValue) % n;
                }
                return (int)result;
            }

            else
                return -1;
        }
    }
}
