using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
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

            for (int i = 1; i < key.Length; i++)
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


            String _cipherText = String.Copy(cipherText.ToLower());
            String _Key = String.Copy(key);

            Console.WriteLine("_cipherText : " + _cipherText + "\n");
            Console.WriteLine("_Key : " + _Key + "\n");

            for (int i = 0; _Key.Length < _cipherText.Length; i++)
            {
                _Key += _Key[i];
            }
            Console.WriteLine("new Key : " + _Key + "\n");

            String orig_text = "";

            for (int i = 0; i < _cipherText.Length && i < _Key.Length; i++)
            {
                // converting in range 0-25
                int asc1 = _cipherText[i] - 'a';
                int asc2 = _Key[i] - 'a';
                int x = (asc1 - asc2 + 26) % 26;

                // convert into alphabets(ASCII)
                x += 'a';
                orig_text += (char)(x);
            }
            Console.WriteLine("original text : " + orig_text + "\n");
            return orig_text;


            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {

            String str = plainText;
            String keykey = key;




            for (int i = 0; ; i++)
            {

                if (keykey.Length < str.Length)

                    keykey += keykey[i];
                else
                    break;
            }


            String cipher_text = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                // converting in range 0-25
                int asc1 = plainText[i] - 'a';
                int asc2 = keykey[i] - 'a';


                int x = (asc1 + asc2) % 26;

                // convert into alphabets(ASCII)
                x += 'a';

                cipher_text += (char)(x);
            }
            return cipher_text;

            // throw new NotImplementedException();
        }
    }
}