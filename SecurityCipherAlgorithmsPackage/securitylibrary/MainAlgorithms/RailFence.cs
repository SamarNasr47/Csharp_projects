using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            List<int> key = new List<int>();
            char first = cipherText[1];
            //  int new_key = 0;
            int i = 0;
            foreach (char c in plainText)
            {
                if (c == first) key.Add(i);
                i++;
            }
            i = 0;
            foreach (int k in key)
            {
                string text = Encrypt(plainText, key[i]).ToLower();
                if (String.Equals(cipherText, text))
                {
                    return key[i];
                }
                i++;
            }
            return -1;

        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            string PT = "";
            int Contar = 0;
            int PTL = (int)Math.Ceiling((double)cipherText.Length / key);
            List<List<char>> NT = new List<List<char>>();
            int cee = (int)Math.Ceiling((double)cipherText.Length / PTL);

            for (int i = 0; i < PTL; i++)
            {
                NT.Add(new List<char>());
            }

            for (int i = 0; i < cee; i++)
            {
                for (int j = 0; j < PTL && j < cipherText.Length; j++)
                {
                    NT[j].Add(cipherText[Contar]);
                    Contar++;
                    if (Contar == cipherText.Length)
                        break;
                }
            }

            for (int j = 0; j < NT.Count; j++)
            {
                for (int i = 0; i < NT[j].Count; i++)
                {
                    PT += NT[j][i];
                }
            }
            return PT.ToLower();
        }

        public string Encrypt(string plainText, int key)
        {

            // String.Join(plainText, plainText.Split(' '));
            string CT = "";
            int contar = 0;
            List<List<char>> NT = new List<List<char>>();
            int num = (int)Math.Ceiling((double)plainText.Length / key);
            for (int i = 0; i < key; i++)
            {
                NT.Add(new List<char>());
            }

            for (int i = 0; i < num; i++)
            {
                for (int j = 0; j < key && j < plainText.Length; j++)
                {
                    NT[j].Add(plainText[contar]);
                    contar++;
                    if (contar == plainText.Length) break;
                }
            }

            for (int i = 0; i < NT.Count; i++)
            {
                for (int j = 0; j < NT[i].Count; j++)
                {
                    CT += NT[i][j];
                }
            }
            return CT.ToUpper();

        }


    }
}