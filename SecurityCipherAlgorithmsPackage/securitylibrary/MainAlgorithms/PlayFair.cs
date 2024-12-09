using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public struct KMtrces
    {
        public Dictionary<char, Tuple<int, int>> Kmatrix;
        public List<List<char>> Omatrix;
    }

    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public HashSet<char> ModifiedKey(string K)
        {
            string AB = "abcdefghiklmnopqrstuvwxyz";
            HashSet<char> Matrixkey = new HashSet<char>();
            int kLength = K.Length;
            int i = 0;
            int j = 0;
            while (i < kLength)
            {
                if (K[i] != 'j')
                {
                    Matrixkey.Add(K[i]);
                }
                else
                {
                    Matrixkey.Add('i');
                }
                i++;
            }
            while (j < 25)
            {
                Matrixkey.Add(AB[j]);
                j++;
            }
            return Matrixkey;
        }

        public List<string> DIVIDit(string S)
        {
            List<string> LString = new List<string>();
            int XL = S.Length;
            int CHNK = 100, k = 0;
            for (; k < XL;)
            {
                if (k + CHNK > XL)
                {
                    CHNK = XL - k;
                }
                LString.Add(S.Substring(k, CHNK));
                k += CHNK;
            }
            return LString;
        }

        public KMtrces KFunc(HashSet<char> MK)
        {
            List<List<char>> OKMtrx = new List<List<char>>();
            Dictionary<char, Tuple<int, int>> KMtrx = new Dictionary<char, Tuple<int, int>>();
            int coun = 0;
            int i = 0;
            while (i < 5)
            {
                List<char> TMP = new List<char>();
                for (int k = 0; k < 5; k++)
                {
                    if (coun < 25)
                    {
                        KMtrx.Add(MK.ElementAt(coun), new Tuple<int, int>(i, k));
                        TMP.Add(MK.ElementAt(coun));
                        coun++;
                    }

                }
                OKMtrx.Add(TMP);
                i++;
            }
            KMtrces KOM = new KMtrces();
            KOM.Kmatrix = KMtrx;
            KOM.Omatrix = OKMtrx;

            return KOM;
        }

        public string Decrypt(string cipherText, string key)
        {
            List<string> Ssegs = new List<string>();
            cipherText = cipherText.ToLower();
            bool FL = false; int coun = 1;
            if (cipherText.Length > 100)
            {
                Ssegs = DIVIDit(cipherText);
                FL = true;
            }
            string Ftext = "";
            KMtrces matrix = KFunc(ModifiedKey(key));

            for (; coun <= Ssegs.Count || !FL;)
            {
                if (FL)
                {
                    cipherText = Ssegs[coun - 1];
                }
                string Ptext = "";
                int CTL = cipherText.Length;
                int k = 0;
                FL = true;
                while (k < CTL)
                {
                    char Cipher1 = cipherText[k], Cipher2 = cipherText[k + 1];
                    if (matrix.Kmatrix[Cipher1].Item1 == matrix.Kmatrix[Cipher2].Item1)
                    {
                        Ptext = Ptext + matrix.Omatrix[matrix.Kmatrix[Cipher1].Item1][(matrix.Kmatrix[Cipher1].Item2 + 4) % 5];
                        Ptext = Ptext + matrix.Omatrix[matrix.Kmatrix[Cipher2].Item1][(matrix.Kmatrix[Cipher2].Item2 + 4) % 5];
                    }
                    else if (matrix.Kmatrix[Cipher1].Item2 == matrix.Kmatrix[Cipher2].Item2)
                    {
                        Ptext = Ptext + matrix.Omatrix[(matrix.Kmatrix[Cipher1].Item1 + 4) % 5][matrix.Kmatrix[Cipher1].Item2];
                        Ptext = Ptext + matrix.Omatrix[(matrix.Kmatrix[Cipher2].Item1 + 4) % 5][matrix.Kmatrix[Cipher2].Item2];
                    }
                    else
                    {
                        Ptext = Ptext + matrix.Omatrix[matrix.Kmatrix[Cipher1].Item1][matrix.Kmatrix[Cipher2].Item2];
                        Ptext = Ptext + matrix.Omatrix[matrix.Kmatrix[Cipher2].Item1][matrix.Kmatrix[Cipher1].Item2];
                    }
                    k = k + 2;
                }

                string ANSW = Ptext;
                if (Ptext[Ptext.Length - 1] == 'x')
                {
                    ANSW = ANSW.Remove(Ptext.Length - 1);
                }
                int w = 0, b = 0;
                while (b < ANSW.Length)
                {
                    if (Ptext[b] == 'x')
                    {
                        if (Ptext[b - 1] == Ptext[b + 1])
                        {
                            if (b + w < ANSW.Length && (b - 1) % 2 == 0)
                            {
                                ANSW = ANSW.Remove(b + w, 1);
                                w--;
                            }
                        }
                    }
                    b++;
                }
                Ftext = Ftext + ANSW;
                coun++;
            }
            Console.WriteLine(Ftext);
            return Ftext;
            // throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            KMtrces KOK = KFunc(ModifiedKey(key));
            string CipherT = "";
            int x = 0, i = 0;
            while (x < (plainText.Length - 1))
            {
                if (plainText[x] == plainText[x + 1])
                {
                    plainText = plainText.Substring(0, x + 1) + 'x' + plainText.Substring(x + 1);
                }
                x = x + 2;
            }

            if (plainText.Length % 2 == 1)
            {
                plainText = plainText + 'x';
            }
            int PTL = plainText.Length;
            while (i < PTL)
            {
                char cipher1 = plainText[i], cipher2 = plainText[i + 1];
                if (KOK.Kmatrix[cipher1].Item1 == KOK.Kmatrix[cipher2].Item1)
                {
                    CipherT = CipherT + KOK.Omatrix[KOK.Kmatrix[cipher1].Item1][(KOK.Kmatrix[cipher1].Item2 + 1) % 5];
                    CipherT = CipherT + KOK.Omatrix[KOK.Kmatrix[cipher2].Item1][(KOK.Kmatrix[cipher2].Item2 + 1) % 5];
                }
                else if (KOK.Kmatrix[cipher1].Item2 == KOK.Kmatrix[cipher2].Item2)
                {
                    CipherT = CipherT + KOK.Omatrix[(KOK.Kmatrix[cipher1].Item1 + 1) % 5][KOK.Kmatrix[cipher1].Item2];
                    CipherT = CipherT + KOK.Omatrix[(KOK.Kmatrix[cipher2].Item1 + 1) % 5][KOK.Kmatrix[cipher2].Item2];
                }
                else
                {
                    CipherT = CipherT + KOK.Omatrix[KOK.Kmatrix[cipher1].Item1][KOK.Kmatrix[cipher2].Item2];
                    CipherT = CipherT + KOK.Omatrix[KOK.Kmatrix[cipher2].Item1][KOK.Kmatrix[cipher1].Item2];
                }
                i = i + 2;
            }

            Console.WriteLine(CipherT.ToUpper());
            Console.WriteLine("\n");
            return CipherT.ToUpper();

        }
    }
}