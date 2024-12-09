using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();

            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            string key = "";
            string ke = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                key = key + alphabet[((alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(plainText[i])) + 26) % 26];
            }
            ke = ke + key[0];
            int klength = key.Length;
            for (int i = 1; i < klength; i++)
            {
                ke = ke + key[i];
                string c = Encrypt(plainText, ke);
                if (cipherText == c)
                {
                    return ke;
                }

            }
            return key;
            //throw new 

            // throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();

            string plainText = "";
            int keyi = 0;
            string autoK = key;

            for (int i = 0; i < cipherText.Length; i++)
            {
                char c = cipherText[i];
                if (!char.IsLetter(c))
                {
                    plainText += c;
                    continue;
                }

                // subtract the key letter from the cipher letter, add 26, and then take modulo 26 to get the plain letter
                int plainIndex = (c - autoK[keyi] + 26) % 26;
                char plainl = (char)('a' + plainIndex);
                plainText += plainl;

                // append the plain letter to the autokey
                autoK += plainl;

                // increment the key index, wrapping around if necessary
                keyi++;
                if (keyi >= key.Length)
                {
                    keyi = autoK.Length - key.Length;
                }
            }

            return plainText;



            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {

            String msg = String.Copy(plainText.ToLower());
            String _Key = String.Copy(key);

            string newKey = _Key + msg;
            newKey = newKey.Substring(0, newKey.Length
                                      - _Key.Length);
            Console.WriteLine("Plaintext : " + newKey);

            String cipher_text = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                // converting in range 0-25
                int asc1 = plainText[i] - 'a';
                int asc2 = newKey[i] - 'a';


                int x = (asc1 + asc2) % 26;

                // convert into alphabets(ASCII)
                x += 'a';

                cipher_text += (char)(x);
            }
            Console.WriteLine("Plaintext : " + cipher_text);
            return cipher_text;




            //throw new NotImplementedException();
        }
    }
}

