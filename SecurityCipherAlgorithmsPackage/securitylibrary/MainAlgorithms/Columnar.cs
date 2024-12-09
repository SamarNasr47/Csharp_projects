using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            SortedDictionary<int, int> sortDict = new SortedDictionary<int, int>();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int plain = plainText.Length;
            double plainSize = (double)plain;
            int count = 1;
            for (count = 1; count < 1000; count++)
            {
                int num = 0;
                double wid = count;
                double hght = Math.Ceiling(plainSize / count);
                string[,] mtrx = new string[(int)hght, (int)wid];
                int g = 0;
                while (g < hght)
                {
                    for (int j = 0; j < count; j++)
                    {
                        if (num > plainSize || num == plainSize)
                        {
                            mtrx[g, j] = "";

                        }
                        else
                        {
                            mtrx[g, j] = plainText[num].ToString();
                            num++;
                        }
                    }
                    g++;
                }

                List<string> newLst = new List<string>();
                int k = 0;
                do
                {
                    string cipherT = "";
                    int j = 0;
                    while (j < hght)
                    {
                        cipherT += mtrx[j, k];
                        j++;
                    }
                    newLst.Add(cipherT);
                    k++;
                }
                while (k < count);
                bool correct = true;
                string copyCT = (string)cipherText.Clone();

                int c = 0;
                do
                {
                    int indexx = copyCT.IndexOf(newLst[c]);
                    if (indexx != -1)
                    {
                        sortDict.Add(indexx, c + 1);
                        copyCT.Replace(newLst[c], "#");
                    }
                    else
                    {
                        correct = false;
                    }
                    c++;
                }
                while (c < newLst.Count);

                if (correct)
                    break;
            }

            List<int> Final = new List<int>();
            Dictionary<int, int> Dict2 = new Dictionary<int, int>();
            int w = 0;
            while (w < sortDict.Count)
            {
                Dict2.Add(sortDict.ElementAt(w).Value, w + 1);
                w++;
            }
            int p = 1;
            do
            {
                Final.Add(Dict2[p]);
                p++;
            }

            while (p < Dict2.Count + 1);

            return Final;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            int cols = key.Count;
            double rows = (((double)cipherText.Length) / cols);
            rows = Math.Ceiling(rows);
            char[,] mtrx = new char[((int)rows), cols];

            Dictionary<int, int> newDict = new Dictionary<int, int>();
            int k = 0;
            do
            {
                newDict.Add(key[k] - 1, k);
                k++;
            }
            while (k < cols);

            int num = cipherText.Length % cols;
            int counter = 0;
            int l = 0;
            do
            {
                for (int j = 0; j < rows; j++)
                {
                    if (newDict[l] >= num && num != 0 && j == rows - 1)
                    {
                        continue;
                    }
                    mtrx[j, newDict[l]] = cipherText[counter];
                    counter++;
                }
                l++;
            } while (l < key.Count);

            StringBuilder build = new StringBuilder();
            int p = 0;
            do
            {
                int j = 0;
                while (j < cols)
                {
                    build.Append(mtrx[p, j]);
                    j++;
                }
                p++;
            } while (p < rows);
            string OutpuT = build.ToString().ToUpper();
            return OutpuT;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            int columnsCount = key.Count;
            double rowsCount = (((double)plainText.Length) / columnsCount);
            rowsCount = Math.Ceiling(rowsCount);
            char[,] mtrx = new char[((int)rowsCount), columnsCount];
            int x = 0, i = 0;
            while (i < rowsCount)
            {
                int j = 0;
                while (j < columnsCount)
                {
                    if (x > plainText.Length || x == plainText.Length)
                    {
                        mtrx[i, j] = 'x';
                    }
                    else
                    {
                        mtrx[i, j] = plainText[x];
                        x++;
                    }
                    j++;
                }
                i++;
            }
            Dictionary<int, int> Dictt = new Dictionary<int, int>();
            int m = 0;
            do
            {
                Dictt.Add(key[m] - 1, m);
                m++;
            }
            while (m < columnsCount);

            int n = 0;
            do
            {
                Console.WriteLine(Dictt[n]);
                n++;
            }
            while (n < columnsCount);

            string output = null;
            int b = 0;
            do
            {
                for (int k = 0; k < rowsCount; k++)
                {
                    output += mtrx[k, Dictt[b]];
                }
                b++;
            }
            while (b < columnsCount);

            string newOutput = output.ToUpper();
            Console.WriteLine(newOutput);
            return output;
        }
    }
}