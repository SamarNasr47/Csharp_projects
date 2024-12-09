using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public static String[,] sboxRes, ShiftRowPlain, MixColPlain, final, output;
        public static String[,] transposMatrixRes = new String[4, 4];
        public static string[,] sBox = new string[16, 16]
       {
            { "63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"},
            { "ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"},
            { "b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"},
            { "04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"},
            { "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"},
            { "53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"},
            { "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"},
            { "51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"},
            { "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"},
            { "60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"},
            { "e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"},
            { "e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"},
            { "ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"},
            { "70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"},
            { "e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"},
            { "8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"}
        };
        public static string[,] Rcon =
        {
            { "01","02","04","08","10","20","40","80","1b","36"},
            { "00","00","00","00","00","00","00","00","00","00"},
            { "00","00","00","00","00","00","00","00","00","00"},
            { "00","00","00","00","00","00","00","00","00","00"}
        };
        public static string[,] MiX_columns =
        {
            { "02","03","01","01"},
            { "01","02","03","01"},
            { "01","01","02","03"},
            { "03","01","01","02"}
        };

        //___________________________________________________________________

        public static Dictionary<String, String> Inv_Box = new Dictionary<string, string>();
        public static String[,] sboxResInv, ShiftRowPlainInv, MixColPlainInv, finalInv, outputInv;
        struct Keys
        {
            public String[,] key;
        }

        public static string[,] MiX_columns_inverse =
        {
            { "0e","0b","0d","09"},
            { "09","0e","0b","0d"},
            { "0d","09","0e","0b"},
            { "0b","0d","09","0e"}
        };

        //_____________________________________________________________

        public override string Decrypt(string cipherText, string key)
        {
            Inv_Box = initalizSBOX_Inv();
            string mainCipher = cipherText;
            string mainKey = key;
            string Plain = "0x";
            Keys[] arr = new Keys[10];
            String[,] o = new String[4, 4];
            String[,] KeyMatrix = new string[4, 4];
            int c = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    KeyMatrix[j, i] = mainKey.ElementAt(c) + "" + mainKey.ElementAt(c + 1) + "";
                    c += 2;
                }
            }

            String[,] CipherMatrix = new string[4, 4];
            c = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    CipherMatrix[j, i] = mainCipher.ElementAt(c) + "" + mainCipher.ElementAt(c + 1) + "";
                    c += 2;
                }
            }
            int round = 0;
            arr[round].key = GenerateKey(KeyMatrix, round);
            round++;
            for (round = 1; round < 9; round++)
            {
                arr[round].key = GenerateKey2(arr[round - 1].key, round);

            }
            arr[round].key = GenerateKey2(arr[round - 1].key, round);

            round = 8;
            outputInv = AddRoundKeyInv(CipherMatrix, trans(arr[9].key));
            for (round = 8; round >= 0; round--)
            {
                ShiftRowPlainInv = ShiftRowInv(outputInv);
                sboxResInv = sBoxInv(ShiftRowPlainInv);
                finalInv = AddRoundKeyInv(sboxResInv, trans(arr[round].key));
                outputInv = InvMixCol(finalInv);
                outputInv = trans(outputInv);

            }
            ShiftRowPlainInv = ShiftRowInv(outputInv);
            sboxResInv = sBoxInv(ShiftRowPlainInv);

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    o[i, j] = BinaryToHex(XOR(HexToBinary(KeyMatrix[i, j]), HexToBinary(sboxResInv[i, j])));
                }
            }
            o = trans(o);
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    Plain += o[i, j];
            return Plain.ToLower();
        }



        //------------------------------------------------------------------

        // mix columns inv
        static String[,] InvMixCol(String[,] State)
        {
            String[,] Multiply = new string[4, 4];
            String[] arr = new string[4];
            int v = 0;
            int j, k;
            for (int i = 0; i < 4; i++)
            {
                j = 0;
                while (j < 4)
                {
                    v = 0;
                    k = 0;
                    while (k < 4)
                    {
                        String bin = HexToBinary(State[k, i]);
                        String x = State[k, i];
                        if (MiX_columns_inverse[j, k].Equals("09"))
                        {
                            arr[v] = bin_9(bin);
                        }
                        if (MiX_columns_inverse[j, k].Equals("0b"))
                        {

                            arr[v] = bin_11(bin);
                        }
                        if (MiX_columns_inverse[j, k].Equals("0d"))
                        {

                            arr[v] = bin_13(bin);
                        }
                        if (MiX_columns_inverse[j, k].Equals("0e"))
                        {

                            arr[v] = bin_14(bin);
                        }
                        k++;
                        v++;
                    }
                    String res = XOR(arr[0], arr[1]);
                    String res1 = XOR(arr[2], res);
                    String res2 = XOR(arr[3], res1);
                    Multiply[i, j] = BinaryToHex(res2);
                    j++;
                }
            }
            return Multiply;
        }
        //--------
        static String mix2(String bin)
        {
            byte InputByte = Convert.ToByte(bin, 2);
            byte TimeResult = (byte)(InputByte << 1);

            if ((InputByte & 0x80) != 0)
            {
                TimeResult ^= 0x1B;
            }

            return Convert.ToString(TimeResult, 2).PadLeft(8, '0');

        }
        //----------
        static String bin_9(String bin)
        {
            string mixed = mix2(mix2(mix2(bin))); // apply mix2 function three times
            string res = XOR(mixed, bin); // apply XOR function to the mixed string and the original string
            return res;
        }
        static String bin_11(String bin)
        {
            String res = XOR(mix2(XOR(mix2(mix2(bin)), bin)), bin);
            return res;
        }
        static String bin_13(String bin)
        {
            String res = XOR(mix2(mix2(XOR(mix2(bin), bin))), bin);
            return res;

        }
        static String bin_14(String bin)
        {
            String res = mix2(XOR(mix2(XOR(mix2(bin), bin)), bin));
            return res;

        }
        //Applying inv sub byte
        static String[,] sBoxInv(String[,] c)
        {

            String[,] res = new string[4, 4];
            String row, col;
            int j;
            for (int i = 0; i < 4; i++)
            {
                j = 0;
                while (j < 4)
                {
                    String arr = c[i, j];
                    row = arr[0] + ""; col = arr[1] + "";
                    res[i, j] = Inv_Box[c[i, j].ToLower()];
                    String z = res[i, j];
                    j++;

                }
            }
            return res;
        }
        //Applying shift row inverse
        static string[,] ShiftRowInv(string[,] plain)
        {
            for (int i = 1; i < 4; i++)
            {
                string[] row = new string[4];
                for (int j = 0; j < 4; j++)
                {
                    row[j] = plain[i, j];
                }
                int shift = 4 - i;
                for (int j = 0; j < 4; j++)
                {
                    plain[i, j] = row[(j + shift) % 4];
                }
            }
            return plain;
        }


        //----------- final key----------------
        static String[,] trans(String[,] c)
        {
            int n = c.GetLength(0);
            int m = c.GetLength(1);
            string[,] finalKey = new string[m, n];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    finalKey[j, i] = c[i, j];
                }
            }
            return finalKey;
        }

        //---- Add round key inverse-----------
        static String[,] AddRoundKeyInv(String[,] plain, String[,] key)
        {
            int n = plain.GetLength(0);
            int m = plain.GetLength(1);
            string[,] output = new string[n, m];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    output[i, j] = XOR(HexToBinary(plain[i, j]), HexToBinary(key[i, j]));
                    output[i, j] = BinaryToHex(output[i, j]);
                }
            }
            return output;
        }

        //------------------------------------------------------------------
        public override string Encrypt(string plainText, string key)
        {
            string mainPlain = plainText;
            string mainKey = key;
            string cipherText = "0x";
            String[,] KeyMatrix = new string[4, 4];
            int c = 2;
            int w;
            for (int i = 0; i < 4; i++)
            {
                w = 0;
                while (true)
                {
                    if (w == 4)
                        break;
                    else
                    {
                        KeyMatrix[w, i] = mainKey.ElementAt(c) + "" + mainKey.ElementAt(c + 1) + "";
                        c += 2;
                        w++;
                    }

                }
            }

            String[,] PlainMatrix = new string[4, 4];
            c = 2;
            int m;
            for (int i = 0; i < 4; i++)
            {
                m = 0;
                while (m < 4)
                {
                    PlainMatrix[m, i] = BinaryToHex(XOR(HexToBinary(mainPlain.ElementAt(c) + "" + mainPlain.ElementAt(c + 1)), HexToBinary(mainKey.ElementAt(c) + "" + mainKey.ElementAt(c + 1))));
                    c += 2;
                    m++;
                }
            }
            int count = 0;

            //Initial round
            sboxRes = sBoxMethod(PlainMatrix);
            ShiftRowPlain = ShiftRow(sboxRes);
            MixColPlain = MixColMethod(ShiftRowPlain);
            final = GenerateKey(KeyMatrix, count);
            output = AddRoundKey(MixColPlain, final);
            count++;
            //middle rounds
            for (int i = 1; i < 9; i++)
            {
                sboxRes = sBoxMethod(output);
                ShiftRowPlain = ShiftRow(sboxRes);
                MixColPlain = MixColMethod(ShiftRowPlain);
                final = GenerateKey2(final, i);
                output = AddRoundKey(MixColPlain, final);
                count++;
            }
            //Final round
            sboxRes = sBoxMethod(output);
            ShiftRowPlain = ShiftRow(sboxRes);
            final = GenerateKey2(final, count);
            String[,] finalKey = new String[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    finalKey[j, i] = final[i, j];
            output = AddRoundKey(ShiftRowPlain, finalKey);
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    cipherText += output[i, j];
            return cipherText;
        }


        //Generate key
        static String[,] GenerateKey2(String[,] ky, int round)
        {
            String[,] ssss = new String[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    ssss[j, i] = ky[i, j];
            String[,] res = new string[4, 4];
            String row, col;

            for (int j = 0; j < 4; j++)
            {
                String arr = ssss[j, 3].ToUpper();
                row = arr[0] + ""; col = arr[1] + "";
                if (arr[0] == 'A') row = "10"; if (arr[0] == 'B') row = "11"; if (arr[0] == 'C') row = "12"; if (arr[0] == 'D') row = "13"; if (arr[0] == 'E') row = "14"; if (arr[0] == 'F') row = "15";
                if (arr[1] == 'A') col = "10"; if (arr[1] == 'B') col = "11"; if (arr[1] == 'C') col = "12"; if (arr[1] == 'D') col = "13"; if (arr[1] == 'E') col = "14"; if (arr[1] == 'F') col = "15";

                res[j, 0] = sBox[int.Parse(row), int.Parse(col)];
            }
            String temp = res[0, 0];
            for (int k = 0; k < 3; k++)
            {
                res[k, 0] = res[k + 1, 0];
            }
            res[3, 0] = temp;
            for (int i = 0; i < 4; i++)
            {
                String a = XOR(HexToBinary(ssss[i, 0]), HexToBinary(Rcon[i, round]));
                String b = XOR(a, HexToBinary(res[i, 0]));
                res[i, 0] = BinaryToHex(b);
            }
            int xo1 = 0, xo2 = 1;
            for (int j = 0; j < 3; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    String b = XOR(HexToBinary(ssss[i, xo2]), HexToBinary(res[i, xo1]));
                    res[i, xo2] = BinaryToHex(b);
                }
                xo2++; xo1++;
            }
            String[,] output1 = new String[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                    output1[j, i] = res[i, j];
            }
            return output1;
        }
        static String[,] GenerateKey(String[,] key, int round)
        {
            String[,] OutPut = new string[4, 4];
            String TheRow, TheColoumns;
            for (int j = 0; j < 4; j++)
            {
                String Array = key[j, 3].ToUpper();
                TheRow = Array[0] + ""; TheColoumns = Array[1] + "";
                if (Array[0] >= 'A' && Array[0] <= 'F') TheRow = ((int)(Array[0] - 'A' + 10)).ToString();
                if (Array[1] >= 'A' && Array[1] <= 'F') TheColoumns = ((int)(Array[1] - 'A' + 10)).ToString();

                int IndexOfRow = int.Parse(TheRow);
                int IndexOfColoumns = int.Parse(TheColoumns);
                OutPut[j, 0] = sBox[IndexOfRow, IndexOfColoumns];
            }
            string[] C = new string[4];
            for (int i = 0; i < 4; i++)
            {
                C[i] = OutPut[i, 0];
            }

            string T = C[0];
            Array.Copy(C, 1, C, 0, 3);
            C[3] = T;

            for (int i = 0; i < 4; i++)
            {
                OutPut[i, 0] = C[i];
            }

            for (int i = 0; i < 4; i++)
            {
                int ValueOfKey = int.Parse(key[i, round], System.Globalization.NumberStyles.HexNumber);
                int R_Con_Value = int.Parse(Rcon[i, round], System.Globalization.NumberStyles.HexNumber);
                int Value_res = int.Parse(OutPut[i, 0], System.Globalization.NumberStyles.HexNumber);

                int TemporaryValue = ValueOfKey ^ R_Con_Value ^ Value_res;
                OutPut[i, 0] = TemporaryValue.ToString("X2");
            }

            int A1 = 0, A2 = 1;
            for (int j = 0; j < 3; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    String HexadieciemalKey = key[i, A2];
                    String HexadieciemalResult = OutPut[i, A1];
                    String HexadieciemalXor = "";

                    // Perform XOR operation on each pair of corresponding characters
                    for (int k = 0; k < HexadieciemalKey.Length; k++)
                    {
                        int Key = Convert.ToInt32(HexadieciemalKey[k].ToString(), 16);
                        int Result = Convert.ToInt32(HexadieciemalResult[k].ToString(), 16);
                        int Xor = Key ^ Result;
                        HexadieciemalXor += Xor.ToString("X");
                    }

                    OutPut[i, A2] = HexadieciemalXor;
                }
                A2++; A1++;
            }
            string[,] transposMatrixRes = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    transposMatrixRes[j, i] = OutPut[i, j];
                }
            }
            return transposMatrixRes;

        }
        //Adding round key
        static String[,] AddRoundKey(String[,] plain, String[,] key)
        {
            String[,] output = new String[4, 4];

            Enumerable.Range(0, 4).ToList().ForEach(i =>
            {
                Enumerable.Range(0, 4).ToList().ForEach(j =>
                {
                    String x = XOR(HexToBinary(plain[j, i]), HexToBinary(key[j, i]));
                    output[i, j] = BinaryToHex(x);
                });
            });

            return output;
        }
        //Applying sub byte
        static String[,] sBoxMethod(String[,] plain)
        {
            string[,] OutPut = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string Hexadeciemal = plain[i, j];
                    int TheRow = int.Parse(Hexadeciemal.Substring(0, 1), NumberStyles.HexNumber);
                    int TheColomns = int.Parse(Hexadeciemal.Substring(1, 1), NumberStyles.HexNumber);
                    OutPut[i, j] = sBox[TheRow, TheColomns];
                }
            }
            return OutPut;

        }
        //Applying shift rows
        static String[,] ShiftRow(String[,] plain)
        {
            String[,] NewMatrix = new String[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    NewMatrix[i, j] = plain[i, (j + i) % 4];
                }
            }
            return NewMatrix;

        }

        //Applying Mix Columns
        static String[,] MixColMethod(String[,] plain)
        {
            string[,] Multiply = new string[4, 4];
            for (int X = 0; X < 4; X++)
            {
                for (int Y = 0; Y < 4; Y++)
                {
                    string[] Array = new string[4];
                    for (int Z = 0; Z < 4; Z++)
                    {
                        string Binary = HexToBinary(plain[Z, X]);
                        if (MiX_columns[Y, Z].Equals("01"))
                        {
                            Array[Z] = Binary;
                        }
                        else if (MiX_columns[Y, Z].Equals("02"))
                        {
                            Array[Z] = (Binary[0] == '0') ? Binary.Remove(0, 1) + "0" : XOR(Binary.Remove(0, 1) + "0", HexToBinary("1B"));
                        }
                        else if (MiX_columns[Y, Z].Equals("03"))
                        {
                            Array[Z] = (Binary[0] == '0') ? XOR(Binary.Remove(0, 1) + "0", Binary) : XOR(XOR(Binary.Remove(0, 1) + "0", HexToBinary("1B")), Binary);
                        }
                    }
                    Multiply[X, Y] = BinaryToHex(XOR(XOR(XOR(Array[0], Array[1]), Array[2]), Array[3]));
                }
            }
            return Multiply;
        }

        //Applying XOR
        static String XOR(String plain, String Key)
        {
            if (plain.Length != Key.Length)
            {
                throw new ArgumentException("The lengths of the two input must be equal.");
            }

            string OutPut = "";
            for (int j = 0; j < plain.Length; j++)
            {
                OutPut += (plain[j] ^ Key[j]).ToString();
            }

            return OutPut;
        }

        //convert hexa to binary
        static String HexToBinary(String Hexadecieamal)
        {
            if (string.IsNullOrEmpty(Hexadecieamal))
            {
                throw new ArgumentException("The input can,t be null or empty.");
            }
            string Binary = "";
            foreach (char x in Hexadecieamal.ToUpper())
            {
                Binary += Convert.ToString(Convert.ToInt32(x.ToString(), 16), 2).PadLeft(4, '0');
            }
            return Binary;
        }

        //convert binary to hexa
        static String BinaryToHex(String Binary)
        {
            String Hexadecimal = "";
            Dictionary<String, String> DiciemalAndBinary = new Dictionary<String, string>()
            {
                {"0000","0" }, {"0001","1" }, {"0010","2" }, {"0011","3" },
                {"0100","4" }, {"0101","5" }, {"0110","6" }, {"0111","7" },
                {"1000","8" }, {"1001","9" }, {"1010","A" }, {"1011","B" },
                {"1100","C" }, {"1101","D" }, {"1110","E" }, {"1111","F" }
            };
            String T = "";
            for (int i = 0; i < Binary.Length; i++)
            {
                T += Binary[i];
                if (T.Length % 4 == 0)
                {
                    Hexadecimal += DiciemalAndBinary[T];
                    T = "";
                }
            }

            return Hexadecimal;
        }
        //___________________________________________________

        static Dictionary<String, String> initalizSBOX_Inv()
        {
            Dictionary<String, String> Inv_sBox = new Dictionary<string, string>();
            Inv_sBox.Add("00", "52");
            Inv_sBox.Add("10", "7c");
            Inv_sBox.Add("20", "54");
            Inv_sBox.Add("30", "08");
            Inv_sBox.Add("40", "72");
            Inv_sBox.Add("50", "6c");
            Inv_sBox.Add("60", "90");
            Inv_sBox.Add("70", "d0");
            Inv_sBox.Add("80", "3a");
            Inv_sBox.Add("90", "96");
            Inv_sBox.Add("a0", "47");
            Inv_sBox.Add("b0", "fc");
            Inv_sBox.Add("c0", "1f");
            Inv_sBox.Add("d0", "60");
            Inv_sBox.Add("e0", "a0");
            Inv_sBox.Add("f0", "17");


            Inv_sBox.Add("01", "09");
            Inv_sBox.Add("11", "e3");
            Inv_sBox.Add("21", "7b");
            Inv_sBox.Add("31", "2e");
            Inv_sBox.Add("41", "f8");
            Inv_sBox.Add("51", "70");
            Inv_sBox.Add("61", "d8");
            Inv_sBox.Add("71", "2c");
            Inv_sBox.Add("81", "91");
            Inv_sBox.Add("91", "ac");
            Inv_sBox.Add("a1", "f1");
            Inv_sBox.Add("b1", "56");
            Inv_sBox.Add("c1", "dd");
            Inv_sBox.Add("d1", "51");
            Inv_sBox.Add("e1", "e0");
            Inv_sBox.Add("f1", "2b");

            Inv_sBox.Add("02", "6a");
            Inv_sBox.Add("12", "39");
            Inv_sBox.Add("22", "94");
            Inv_sBox.Add("32", "a1");
            Inv_sBox.Add("42", "f6");
            Inv_sBox.Add("52", "48");
            Inv_sBox.Add("62", "ab");
            Inv_sBox.Add("72", "1e");
            Inv_sBox.Add("82", "11");
            Inv_sBox.Add("92", "74");
            Inv_sBox.Add("a2", "1a");
            Inv_sBox.Add("b2", "3e");
            Inv_sBox.Add("c2", "a8");
            Inv_sBox.Add("d2", "7f");
            Inv_sBox.Add("e2", "3b");
            Inv_sBox.Add("f2", "04");

            Inv_sBox.Add("03", "d5");
            Inv_sBox.Add("13", "82");
            Inv_sBox.Add("23", "32");
            Inv_sBox.Add("33", "66");
            Inv_sBox.Add("43", "64");
            Inv_sBox.Add("53", "50");
            Inv_sBox.Add("63", "00");
            Inv_sBox.Add("73", "8f");
            Inv_sBox.Add("83", "41");
            Inv_sBox.Add("93", "22");
            Inv_sBox.Add("a3", "71");
            Inv_sBox.Add("b3", "4b");
            Inv_sBox.Add("c3", "33");
            Inv_sBox.Add("d3", "a9");
            Inv_sBox.Add("e3", "4d");
            Inv_sBox.Add("f3", "7e");

            Inv_sBox.Add("04", "30");
            Inv_sBox.Add("14", "9b");
            Inv_sBox.Add("24", "a6");
            Inv_sBox.Add("34", "28");
            Inv_sBox.Add("44", "86");
            Inv_sBox.Add("54", "fd");
            Inv_sBox.Add("64", "8c");
            Inv_sBox.Add("74", "ca");
            Inv_sBox.Add("84", "4f");
            Inv_sBox.Add("94", "e7");
            Inv_sBox.Add("a4", "1d");
            Inv_sBox.Add("b4", "c6");
            Inv_sBox.Add("c4", "88");
            Inv_sBox.Add("d4", "19");
            Inv_sBox.Add("e4", "ae");
            Inv_sBox.Add("f4", "ba");

            Inv_sBox.Add("05", "36");
            Inv_sBox.Add("15", "2f");
            Inv_sBox.Add("25", "c2");
            Inv_sBox.Add("35", "d9");
            Inv_sBox.Add("45", "68");
            Inv_sBox.Add("55", "ed");
            Inv_sBox.Add("65", "bc");
            Inv_sBox.Add("75", "3f");
            Inv_sBox.Add("85", "67");
            Inv_sBox.Add("95", "ad");
            Inv_sBox.Add("a5", "29");
            Inv_sBox.Add("b5", "d2");
            Inv_sBox.Add("c5", "07");
            Inv_sBox.Add("d5", "b5");
            Inv_sBox.Add("e5", "2a");
            Inv_sBox.Add("f5", "77");

            Inv_sBox.Add("06", "a5");
            Inv_sBox.Add("16", "ff");
            Inv_sBox.Add("26", "23");
            Inv_sBox.Add("36", "24");
            Inv_sBox.Add("46", "98");
            Inv_sBox.Add("56", "b9");
            Inv_sBox.Add("66", "d3");
            Inv_sBox.Add("76", "0f");
            Inv_sBox.Add("86", "dc");
            Inv_sBox.Add("96", "35");
            Inv_sBox.Add("a6", "c5");
            Inv_sBox.Add("b6", "79");
            Inv_sBox.Add("c6", "c7");
            Inv_sBox.Add("d6", "4a");
            Inv_sBox.Add("e6", "f5");
            Inv_sBox.Add("f6", "d6");

            Inv_sBox.Add("07", "38");
            Inv_sBox.Add("17", "87");
            Inv_sBox.Add("27", "3d");
            Inv_sBox.Add("37", "b2");
            Inv_sBox.Add("47", "16");
            Inv_sBox.Add("57", "da");
            Inv_sBox.Add("67", "0a");
            Inv_sBox.Add("77", "02");
            Inv_sBox.Add("87", "ea");
            Inv_sBox.Add("97", "85");
            Inv_sBox.Add("a7", "89");
            Inv_sBox.Add("b7", "20");
            Inv_sBox.Add("c7", "31");
            Inv_sBox.Add("d7", "0d");
            Inv_sBox.Add("e7", "b0");
            Inv_sBox.Add("f7", "26");

            Inv_sBox.Add("08", "bf");
            Inv_sBox.Add("18", "34");
            Inv_sBox.Add("28", "ee");
            Inv_sBox.Add("38", "76");
            Inv_sBox.Add("48", "d4");
            Inv_sBox.Add("58", "5e");
            Inv_sBox.Add("68", "f7");
            Inv_sBox.Add("78", "c1");
            Inv_sBox.Add("88", "97");
            Inv_sBox.Add("98", "e2");
            Inv_sBox.Add("a8", "6f");
            Inv_sBox.Add("b8", "9a");
            Inv_sBox.Add("c8", "b1");
            Inv_sBox.Add("d8", "2d");
            Inv_sBox.Add("e8", "c8");
            Inv_sBox.Add("f8", "e1");

            Inv_sBox.Add("09", "40");
            Inv_sBox.Add("19", "8e");
            Inv_sBox.Add("29", "4c");
            Inv_sBox.Add("39", "5b");
            Inv_sBox.Add("49", "a4");
            Inv_sBox.Add("59", "15");
            Inv_sBox.Add("69", "e4");
            Inv_sBox.Add("79", "af");
            Inv_sBox.Add("89", "f2");
            Inv_sBox.Add("99", "f9");
            Inv_sBox.Add("a9", "b7");
            Inv_sBox.Add("b9", "db");
            Inv_sBox.Add("c9", "12");
            Inv_sBox.Add("d9", "e5");
            Inv_sBox.Add("e9", "eb");
            Inv_sBox.Add("f9", "69");

            Inv_sBox.Add("0a", "a3");
            Inv_sBox.Add("1a", "43");
            Inv_sBox.Add("2a", "95");
            Inv_sBox.Add("3a", "a2");
            Inv_sBox.Add("4a", "5c");
            Inv_sBox.Add("5a", "46");
            Inv_sBox.Add("6a", "58");
            Inv_sBox.Add("7a", "bd");
            Inv_sBox.Add("8a", "cf");
            Inv_sBox.Add("9a", "37");
            Inv_sBox.Add("aa", "62");
            Inv_sBox.Add("ba", "c0");
            Inv_sBox.Add("ca", "10");
            Inv_sBox.Add("da", "7a");
            Inv_sBox.Add("ea", "bb");
            Inv_sBox.Add("fa", "14");

            Inv_sBox.Add("0b", "9e");
            Inv_sBox.Add("1b", "44");
            Inv_sBox.Add("2b", "0b");
            Inv_sBox.Add("3b", "49");
            Inv_sBox.Add("4b", "cc");
            Inv_sBox.Add("5b", "57");
            Inv_sBox.Add("6b", "05");
            Inv_sBox.Add("7b", "03");
            Inv_sBox.Add("8b", "ce");
            Inv_sBox.Add("9b", "e8");
            Inv_sBox.Add("ab", "0e");
            Inv_sBox.Add("bb", "fe");
            Inv_sBox.Add("cb", "59");
            Inv_sBox.Add("db", "9f");
            Inv_sBox.Add("eb", "3c");
            Inv_sBox.Add("fb", "63");

            Inv_sBox.Add("0c", "81");
            Inv_sBox.Add("1c", "c4");
            Inv_sBox.Add("2c", "42");
            Inv_sBox.Add("3c", "6d");
            Inv_sBox.Add("4c", "5d");
            Inv_sBox.Add("5c", "a7");
            Inv_sBox.Add("6c", "b8");
            Inv_sBox.Add("7c", "01");
            Inv_sBox.Add("8c", "f0");
            Inv_sBox.Add("9c", "1c");
            Inv_sBox.Add("ac", "aa");
            Inv_sBox.Add("bc", "78");
            Inv_sBox.Add("cc", "27");
            Inv_sBox.Add("dc", "93");
            Inv_sBox.Add("ec", "83");
            Inv_sBox.Add("fc", "55");

            Inv_sBox.Add("0d", "f3");
            Inv_sBox.Add("1d", "de");
            Inv_sBox.Add("2d", "fa");
            Inv_sBox.Add("3d", "8b");
            Inv_sBox.Add("4d", "65");
            Inv_sBox.Add("5d", "8d");
            Inv_sBox.Add("6d", "b3");
            Inv_sBox.Add("7d", "13");
            Inv_sBox.Add("8d", "b4");
            Inv_sBox.Add("9d", "75");
            Inv_sBox.Add("ad", "18");
            Inv_sBox.Add("bd", "cd");
            Inv_sBox.Add("cd", "80");
            Inv_sBox.Add("dd", "c9");
            Inv_sBox.Add("ed", "53");
            Inv_sBox.Add("fd", "21");

            Inv_sBox.Add("0e", "d7");
            Inv_sBox.Add("1e", "e9");
            Inv_sBox.Add("2e", "c3");
            Inv_sBox.Add("3e", "d1");
            Inv_sBox.Add("4e", "b6");
            Inv_sBox.Add("5e", "9d");
            Inv_sBox.Add("6e", "45");
            Inv_sBox.Add("7e", "8a");
            Inv_sBox.Add("8e", "e6");
            Inv_sBox.Add("9e", "df");
            Inv_sBox.Add("ae", "be");
            Inv_sBox.Add("be", "5a");
            Inv_sBox.Add("ce", "ec");
            Inv_sBox.Add("de", "9c");
            Inv_sBox.Add("ee", "99");
            Inv_sBox.Add("fe", "0c");

            Inv_sBox.Add("0f", "fb");
            Inv_sBox.Add("1f", "cb");
            Inv_sBox.Add("2f", "4e");
            Inv_sBox.Add("3f", "25");
            Inv_sBox.Add("4f", "92");
            Inv_sBox.Add("5f", "84");
            Inv_sBox.Add("6f", "06");
            Inv_sBox.Add("7f", "6b");
            Inv_sBox.Add("8f", "73");
            Inv_sBox.Add("9f", "6e");
            Inv_sBox.Add("af", "1b");
            Inv_sBox.Add("bf", "f4");
            Inv_sBox.Add("cf", "5f");
            Inv_sBox.Add("df", "ef");
            Inv_sBox.Add("ef", "61");
            Inv_sBox.Add("ff", "7d");
            return Inv_sBox;
        }
    }
    //__________________________________________________________-

}
