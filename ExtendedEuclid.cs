using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();
            int Q = 0;
            int A1 = 1, A2 = 0, A3 = baseN;
            int B1 = 0, B2 = 1, B3 = number;
            while (true)
            {
                if (B3 == 1)
                {
                    break;
                }
                else if (B3 == 0)
                {
                    return -1;
                }
                else
                {
                    Q = A3 / B3;
                    int tempA1 = B1;
                    int tempA2 = B2;
                    int tempA3 = B3;
                    B1 = A1 - Q * B1;
                    B2 = A2 - Q * B2;
                    B3 = A3 - Q * B3;
                    A1 = tempA1;
                    A2 = tempA2;
                    A3 = tempA3;
                    continue;
                }
            }
            while (B2<=0)
            {
                B2 += baseN;
            }
            return B2;

        }
    }
}