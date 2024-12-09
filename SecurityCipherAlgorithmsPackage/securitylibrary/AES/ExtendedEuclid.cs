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
            int Secand = baseN;
            int First = number;
            int x1 = 1, x2 = 0, x3 = Secand;
            int y1 = 0, y2 = 1, y3 = First;
            for (; y3 != 0;)
            {
                int q = x3 / y3;
                (x3, y3) = (y3, x3 - q * y3);
                (x2, y2) = (y2, x2 - q * y2);
                (x1, y1) = (y1, x1 - q * y1);
            }
            return (x3 == 1) ? ((x2 < 0) ? Secand + x2 : x2) : -1;

        }

    }
}
