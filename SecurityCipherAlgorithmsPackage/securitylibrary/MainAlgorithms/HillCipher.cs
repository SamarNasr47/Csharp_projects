using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int colSize = 2;
            int[,] fillMatrix(List<int> list, int rowSize)
            {
                int columnSize = list.Count / rowSize;
                int[,] matrix = new int[rowSize, columnSize];

                for (int i = 0; i < columnSize; i++)
                {
                    for (int j = 0; j < rowSize; j++)
                    {

                        matrix[j, i] = list[i * rowSize + j];
                    }
                }
                return matrix;
            }
            int[,] cipherMatrix = fillMatrix(cipherText, 2);
            int[,] plainMatrix = fillMatrix(plainText, 2);
            int[,] keyMatrix = new int[2, 2];
            List<int> result = new List<int>();
            int[,] matrixMultiplication(int[,] mat1, int[,] mat2, int size)
            {
                int columnSize2 = mat2.Length / size;

                int[,] matrixResult = new int[size, columnSize2];
                for (int i = 0; i < size; i++)
                {
                    for (int j = 0; j < columnSize2; j++)
                    {
                        for (int k = 0; k < size; k++)
                        {
                            matrixResult[i, j] += mat1[i, k] * mat2[k, j];
                        }
                    }
                }
                return matrixResult;
            }
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            keyMatrix[0, 0] = i;
                            keyMatrix[0, 1] = j;
                            keyMatrix[1, 0] = k;
                            keyMatrix[1, 1] = l;
                            int[,] MatrixMultiplication = matrixMultiplication(keyMatrix, plainMatrix, colSize);
                            if (cipherMatrix[0, 0] == MatrixMultiplication[0, 0] % 26 &&
                                cipherMatrix[0, 1] == MatrixMultiplication[0, 1] % 26 &&
                                cipherMatrix[1, 0] == MatrixMultiplication[1, 0] % 26 &&
                                cipherMatrix[1, 1] == MatrixMultiplication[1, 1] % 26)
                            {
                                result.Add(i);
                                result.Add(j);
                                result.Add(k);
                                result.Add(l);
                                return result;
                            }
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();

           

        }



        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> result = new List<int>();    // 3ayezha 3a4an asayev el result
            int totalTripleOrDouble = 0;  //number of the triple or double letters in the whole plain text ex. mor (1) , emo (2) and so on
            int m = 0;                 // The matrix m*1 = m*m * m*1

            int getDet()
            {
                int detResult = 0;
                detResult += key[0] * (key[4] * key[8] - key[5] * key[7]);  // a * det(efhk)
                detResult -= key[1] * (key[3] * key[8] - key[5] * key[6]);  //-b * det(dfgk)
                detResult += key[2] * (key[3] * key[7] - key[4] * key[6]);  // c * det(degh)
                return detResult % 26;
            }              // Getting the determinant of the 3x3 Matrix using a function
            int getSubDet(int i, int j, int ma, int[,] matrix)   // ma here is m which is like mxm of a matrix
            {
                int subDetResult = 0;
                List<int> subMat = new List<int>();
                for (int p = 0; p < ma; p++)
                {
                    for (int l = 0; l < ma; l++)
                    {
                        if (l == j)
                            continue;
                        else if (p == i)
                            break;
                        subMat.Add(matrix[p, l]);
                    }
                }
                subDetResult = subMat[0] * subMat[3] - subMat[1] * subMat[2];
                return subDetResult;
            }
            if (key.Count % 3 == 0)
            {
                totalTripleOrDouble = cipherText.Count / 3;
                m = 3;
            }
            else if (key.Count % 2 == 0)
            {
                totalTripleOrDouble = cipherText.Count / 2;
                m = 2;
            }
            switch (m)
            {
                case 2:
                    {

                        int determinant, inverseOfDet = 0;
                        determinant = ((key[0] * key[3]) - (key[1] * key[2])) % 26;    // We get first the determinant of the key
                        if (determinant < 0)
                            determinant += 26;
                        for (int i = 1; i <= 26; i++)             // Then its inverse
                        {

                            bool notFound = true;
                            if ((determinant * i) % 26 == 1)
                            {
                                inverseOfDet = i;
                                break;
                            }

                            if (notFound && i == 26)
                            {
                                throw new InvalidAnlysisException();  //We can remove notFound but I am
                            }                                         // keeping it for understanding only
                        }
                        int temp = 0;
                        temp = key[0];
                        key[0] = key[3];
                        key[3] = temp;
                        key[2] = -key[2];
                        key[1] = -key[1];
                        for (int i = 0; i < 4; i++)
                        {
                            key[i] = (key[i] * inverseOfDet) % 26;
                            if (key[i] < 0)
                                key[i] += 26;
                        }
                        for (int level = 0; level < totalTripleOrDouble; level++)
                        {
                            List<int> arr = new List<int>();
                            List<int> arrResult = new List<int>();
                            arr.Add(0);
                            arr.Add(0);
                            arrResult.Add(0);
                            arrResult.Add(0);
                            for (int i = 0; i < m; i++)
                                arr[i] = cipherText[i + m * level];

                            for (int i = 0; i < m; i++)
                            {
                                for (int j = 0; j < 1; j++)
                                {
                                    for (int k = 0; k < m; k++)
                                    {
                                        arrResult[i] += key[i * m + k] * arr[k];
                                    }
                                }
                                arrResult[i] = arrResult[i] % 26;
                                if (arrResult[i] < 0)
                                    arrResult[i] += 26;
                            }
                            result.AddRange(arrResult);
                            arr.Clear();
                            arrResult.Clear();
                        }
                        break;
                    }
                case 3:
                    {

                        int determinant, inverseOfDet = 0;
                        determinant = getDet();                   // Get the determinant
                        if (determinant < 0)
                            determinant += 26;
                        for (int i = 1; i <= 26; i++)
                        {

                            bool notFound = true;
                            if ((determinant * i) % 26 == 1)
                            {
                                inverseOfDet = i;
                                break;
                            }

                            if (notFound && i == 26)
                            {
                                throw new InvalidAnlysisException();  //We can remove notFound but I am
                            }                                         // keeping it for understanding only
                        }          // Then its inverse
                        int[,] keyMatrix = new int[m, m];
                        for (int i = 0; i < m; i++)
                        {
                            for (int j = 0; j < m; j++)
                            {
                                keyMatrix[i, j] = key[i * m + j];
                            }
                        }           // Storing the key in a 2D matrix instead
                                    // of a list so it can help me in later
                                    // calculations
                        int[,] keyInverse = new int[m, m];
                        for (int i = 0; i < m; i++)
                        {
                            for (int j = 0; j < m; j++)
                            {
                                keyInverse[i, j] = (int)(inverseOfDet * Math.Pow(-1, i + j) * getSubDet(i, j, m, keyMatrix));   // I did casting here because Math.Pow return double
                                keyInverse[i, j] %= 26;
                                if (keyInverse[i, j] < 0)
                                    keyInverse[i, j] += 26;
                            }
                        } // In this step we get key inverse and in the next step we get its transpose

                        int count = 1;
                        for (int i = 0; i < m; i++)
                        {
                            for (int j = 0; j < m; j++)
                            {
                                if (i == j)
                                    continue;
                                if (count == i + j)
                                {
                                    int temp = keyInverse[i, j];
                                    keyInverse[i, j] = keyInverse[j, i];
                                    keyInverse[j, i] = temp;
                                    count++;
                                }
                            }
                        } // key inverse is ready but we will convert it back to list to use a former code
                        List<int> keyInverseList = new List<int>();
                        for (int i = 0; i < m; i++)
                        {
                            for (int j = 0; j < m; j++)
                            {
                                keyInverseList.Add(0);
                                keyInverseList[i * m + j] = keyInverse[i, j];
                            }
                        }

                        for (int level = 0; level < totalTripleOrDouble; level++)
                        {



                            //int[] arr = new int[3];                //for taking the triple and matching it with the for loop
                            //int[] arrResult = new int[3];                //for the triple and then adding it to the list
                            List<int> arr = new List<int>();
                            List<int> arrResult = new List<int>();
                            arr.Add(0);
                            arr.Add(0);

                            if (m == 3)
                                arr.Add(0);
                            arrResult.Add(0);
                            arrResult.Add(0);
                            if (m == 3)
                                arrResult.Add(0);

                            for (int i = 0; i < m; i++)
                                arr[i] = cipherText[i + m * level];


                            for (int i = 0; i < m; i++)
                            {
                                for (int j = 0; j < 1; j++)
                                {
                                    for (int k = 0; k < m; k++)
                                    {
                                        arrResult[i] += keyInverseList[i * m + k] * arr[k];
                                    }
                                }
                                arrResult[i] = arrResult[i] % 26;
                            }

                            result.AddRange(arrResult);
                            arr.Clear();
                            arrResult.Clear();
                        }

                        break;
                    }
            }
            return result;
        }
        

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> result = new List<int>();    // 3ayezha 3a4an asayev el result
            int totalTripleOrDouble = 0;  //number of the triple or double letters in the whole plain text ex. mor (1) , emo (2) and so on
            int m = 0;                 // The matrix m*1 = m*m * m*1
            if (key.Count % 3 == 0)
            {
                totalTripleOrDouble = plainText.Count / 3;
                m = 3;
            }
            else if (key.Count % 2 == 0)
            {
                totalTripleOrDouble = plainText.Count / 2;
                m = 2;
            }

            for (int level = 0; level < totalTripleOrDouble; level++)
            {
                List<int> arr = new List<int>();
                List<int> arrResult = new List<int>();
                arr.Add(0);
                arr.Add(0);

                if (m == 3)
                    arr.Add(0);
                arrResult.Add(0);
                arrResult.Add(0);
                if (m == 3)
                    arrResult.Add(0);

                for (int i = 0; i < m; i++)
                    arr[i] = plainText[i + m * level];


                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < 1; j++)
                    {
                        for (int k = 0; k < m; k++)
                        {
                            arrResult[i] += key[i * m + k] * arr[k];
                        }
                    }
                    arrResult[i] = arrResult[i] % 26;
                }

                result.AddRange(arrResult);
                arr.Clear();
                arrResult.Clear();
            }
            return result;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int rSize = 3;
            int colSize = 3;
            int[,] fillMatrix(List<int> list, int rowSize)
            {
                int columnSize = list.Count / rowSize;
                int[,] matrix = new int[rowSize, columnSize];

                for (int i = 0; i < columnSize; i++)
                {
                    for (int j = 0; j < rowSize; j++)
                    {

                        matrix[j, i] = list[i * rowSize + j];
                    }
                }
                return matrix;
            }
            int[,] matrixMultiplication(int[,] mat1, int[,] mat2, int size)
            {
                int columnSize2 = mat2.Length / size;

                int[,] matrixResult = new int[size, columnSize2];
                for (int i = 0; i < size; i++)
                {
                    for (int j = 0; j < columnSize2; j++)
                    {
                        for (int k = 0; k < size; k++)
                        {
                            matrixResult[i, j] += mat1[i, k] * mat2[k, j];
                        }
                    }
                }
                return matrixResult;
            }
            int getSubDet(int i, int j, int ma, int[,] matrix)   
            {
                int subDetResult = 0;
                List<int> subMat = new List<int>();
                for (int p = 0; p < ma; p++)
                {
                    for (int l = 0; l < ma; l++)
                    {
                        if (l == j)
                            continue;
                        else if (p == i)
                            break;
                        subMat.Add(matrix[p, l]);
                    }
                }
                subDetResult = subMat[0] * subMat[3] - subMat[1] * subMat[2];
                return subDetResult;
            }
            int determinant(int[,] matrix)
            {
                int size = matrix.GetLength(0);
                if (size == 1)
                {
                    return matrix[0, 0];
                }
                int Detresult = 0;
                for (int i = 0; i < size; i++)
                {
                    Detresult += (int)Math.Pow(-1, i % 2) * matrix[0, i] * determinant(subMatrix(matrix, 0, i));
                }
                return Detresult;
            }
            int[,] subMatrix(int[,] matrix, int i, int j)
            {
                int size = matrix.GetLength(0);
                int index = 0;
                int[,] Sresult = new int[size - 1, size - 1];
                for (int k = 0; k < size; k++)
                {
                    for (int l = 0; l < size; l++)
                    {
                        if (i == k || j == l)
                        {
                            continue;
                        }
                        Sresult[index / (size - 1), index % (size - 1)] = matrix[k, l];
                        index++;
                    }
                }
                return Sresult;
            }
            int multiplicativeInverse(int a, int mod)
            {
                int Q, A1 = 1, A2 = 0, A3 = mod, B1 = 0, B2 = 1, B3 = a;
                int tB1, tB2, tB3;
                while (B3 != 1)
                {
                    Q = A3 / B3;
                    tB1 = A1 - Q * B1;
                    tB2 = A2 - Q * B2;
                    tB3 = A3 - Q * B3;
                    A1 = B1;
                    A2 = B2;
                    A3 = B3;
                    B1 = tB1;
                    B2 = tB2;
                    B3 = tB3;
                }
                return (B2 + mod) % mod;
            }
            int[,] inverse(int[,] matrix)
            {
                int[,] inverseResult = new int[matrix.GetLength(0), matrix.GetLength(0)];
                int MultiplicativeInverse = multiplicativeInverse((determinant(matrix) % 26 + 26) % 26, 26);
                for (int i = 0; i < matrix.GetLength(0); i++)
                {
                    for (int j = 0; j < matrix.GetLength(0); j++)
                    {
                        inverseResult[j, i] = MultiplicativeInverse * (int)Math.Pow(-1, i + j) * getSubDet(i, j, 3, matrix);
                        inverseResult[j, i] = ((inverseResult[j, i] % 26) + 26) % 26;
                    }
                }
                return inverseResult;
            }
            int[,] cipherMatrix = fillMatrix(cipherText, rSize);
            int[,] plainMatrix = fillMatrix(plainText, rSize);

            int[,] keyMatrix = matrixMultiplication(cipherMatrix, inverse(plainMatrix), rSize);
            List<int> result = new List<int>();
            for (int i = 0; i < rSize; i++)
            {
                for (int j = 0; j < colSize; j++)
                {
                    result.Add((keyMatrix[i, j]) % 26);
                }
            }
            return result;
        }






    }

} 

