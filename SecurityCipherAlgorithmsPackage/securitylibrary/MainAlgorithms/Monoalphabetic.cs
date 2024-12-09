using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            string AB = "";
            for (char c = 'a'; c <= 'z'; c++)
            {
                AB += c;
            }
            char[] K = new char[26];

            int i = 1;
            while (i <= K.Length)
            {
                K[i - 1] = '\0';
                i++;
            }

            for (int j = 0; j < plainText.Length; j++)
            {
                char CiChar = cipherText[j];
                char Pchar = plainText[j];
                if (K[Pchar - 'a'] == '\0')
                {
                    K[Pchar - 'a'] = CiChar;
                    AB = AB.Replace(CiChar.ToString(), "");
                }

            }

            int v = 1, indx = 0;
            while (v <= K.Length)
            {
                if (K[v - 1] == '\0')
                {
                    K[v - 1] = AB[indx];
                    indx++;
                }
                v++;
            }

            return new string(K);
        }




        public string Decrypt(string cipherText, string key)
        {
            Dictionary<char, char> The_MapOfKey = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {
                The_MapOfKey[key[i]] = (char)('a' + i);
                The_MapOfKey[char.ToUpper(key[i])] = (char)('A' + i);
            }

            string plainText = "";
            int j = 0;
            while (j < cipherText.Length)
            {
                char d = cipherText[j];
                if (char.IsLetter(d))
                {
                    plainText += The_MapOfKey[d];
                }
                else
                {
                    plainText += d;
                }
                j++;
            }

            return plainText;
        }


        public string Encrypt(string plainText, string key)
        {
            Dictionary<char, char> The_MapOfKey = new Dictionary<char, char>();
            int i = 0;
            do
            {
                The_MapOfKey[(char)('a' + i)] = key[i];
                The_MapOfKey[(char)('A' + i)] = char.ToUpper(key[i]);
                i++;
            } while (i < 26);


            string cipherText = "";
            int j = 0;
            do
            {
                char c = plainText[j];
                if (char.IsLetter(c))
                {
                    cipherText += The_MapOfKey[c];
                }
                else
                {
                    cipherText += c;
                }
                j++;
            } while (j < plainText.Length);



            return cipherText.ToString();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            char[] freq = new char[26];
            int[] coun = new int[26];
            string charachters = "abcdefghijklmnopqrstuvwxyz";

            string rplce = "etaoinsrhldcumfpgwybvkxjqz";
            Dictionary<char, char> chMap = new Dictionary<char, char>();
            char[] AlphBet = new char[26] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            string planText = "";

            for (int k = 0; k < cipher.Length; k++)
            {
                int indx = charachters.IndexOf(cipher[k]);
                if (indx != -1)
                {
                    coun[indx] += 1;
                }
            }

            for (int i = 0; i < 26; i++)
            {
                freq[i] = charachters[i];
            }

            Array.Sort(coun, freq);
            Array.Reverse(coun);
            Array.Reverse(freq);

            for (int i = 0; i < freq.Length; i++)
            {
                chMap[freq[i]] = rplce[i];
            }

            for (int j = 0; j < cipher.Length; j++)
            {
                Char ciph = cipher[j];
                if (chMap.ContainsKey(ciph))
                {
                    planText = planText + chMap[ciph];
                }
                else
                {
                    planText = planText + ciph;
                }
            }

            return planText;

        }
    }
    }

