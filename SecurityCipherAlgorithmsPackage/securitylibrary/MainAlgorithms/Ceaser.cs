using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            char[] Ciph_Text = new char[plainText.Length];
            for (int coun = 0; coun < plainText.Length; coun++)
            {
                char tx = plainText[coun];
                char BASE_CHAR;
               
                if (tx <= 'Z' && tx >= 'A')
                {
                    int nom = 26, Alph_Indx;
                    BASE_CHAR = 'A';
                    Alph_Indx = (((tx - BASE_CHAR) + key) % nom);
                    if (Alph_Indx <= -1)
                    {
                        Alph_Indx += nom;
                    }
                    Ciph_Text[coun] = (char)(Alph_Indx + BASE_CHAR);
                }
                else if (tx <= 'z' && tx >= 'a')
                {
                    BASE_CHAR = 'a';
                    Ciph_Text[coun] = (char)(((tx - BASE_CHAR + key) % 26 + 26) % 26 + BASE_CHAR);
                }
                else
                {
                    Ciph_Text[coun] = tx;
                }
            }
            return new string(Ciph_Text);
        
    }
       

        public string Decrypt(string cipherText, int key)
        {
            return Encrypt(cipherText, 26 - key);
        }

        public int Analyse(string plainText, string cipherText)
        {
            int[] Frequency_Of_PlainText = GetFrequency(plainText);
            int[] Frequency_Of_CipherText = GetFrequency(cipherText);

            int key = 0;
            int MM = 0;

            for (int i = 0; i < 26; i++)
            {
                int M = 0;

                for (int j = 0; j < 26; j++)
                {
                    int index = (j + i) % 26;

                    if (Frequency_Of_CipherText[index] == Frequency_Of_PlainText[j])
                    {
                        M++;
                    }
                }

                if (M > MM)
                {
                    key = i;
                    MM = M;
                }
            }

            return key;
        }


        private int[] GetFrequency(string text)
        {
            int[] TheFrequency = new int[26];
            char[] Chars = new char[26];
            for (int d = 0; d < 26; d++)
            {
                Chars[d] = (char)('a' + d);
            }

            int i = 0;
            do
            {
                char c = char.ToLower(text[i]);
                int index = -1; 
                for (int x = 0; x < Chars.Length; x++)
                {
                    if (Chars[x] == c)
                    {
                        index = x; 
                        break;     
                    }
                }

                if (index >= 0)
                {
                    TheFrequency[index]++;
                }
                i++;
            } while (i < text.Length);
            return TheFrequency;
        }

    }
}


