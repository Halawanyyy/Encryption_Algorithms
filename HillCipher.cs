using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }
        public int[,] InvertMatrix(int[,] matrix)
        {
            int size = 3;
            int[,] invMatrix = new int[size, size];

            // Calculate cofactors
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    int a = matrix[(i + 1) % size, (j + 1) % size];
                    int b = matrix[(i + 1) % size, (j + 2) % size];
                    int c = matrix[(i + 2) % size, (j + 1) % size];
                    int d = matrix[(i + 2) % size, (j + 2) % size];
                    invMatrix[i, j] = a * d - b * c;
                    invMatrix[i, j] *= (int)Math.Pow(-1, i + j);
                }
            }

            // Find determinant
            int det = matrix[0, 0] * invMatrix[0, 0] - matrix[0, 1] * invMatrix[0, 1] + matrix[0, 2] * invMatrix[0, 2];
            det = Math.Abs(det) % 26;

            // Find multiplicative inverse of the determinant working modulo 26.
            int multInv = 0;
            for (int i = 0; i < 26; i++)
            {
                if ((det * i) % 26 == 1)
                {
                    multInv = i;
                    break;
                }
            }

            // Multiply cofactors with multiplicative inverse
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    invMatrix[i, j] = (int)Math.Pow(-1, i + j) * invMatrix[i, j] * multInv % 26;
                }
            }

            // Transpose the matrix
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    matrix[i, j] = invMatrix[j, i];
                }
            }

            return matrix;
        }
    

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> ConvertMatrixToList(int[,] matrix)
        {
            List<int> resultList = new List<int>();
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    resultList.Add(matrix[i, j]);
                }
            }
            return resultList;
        }


        //ListToMat function to conver List to matrix
        public int[,] ConvertListToMatrix(List<int> lst)
        {
            int[,] matrix;
            int count;

            if (lst.Count % 2 == 0)
            {
                matrix = new int[2, 2];
                count = 0;

                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        matrix[i, j] = lst[count];
                        count++;
                    }
                }
            }
            else if (lst.Count % 3 == 0)
            {
                matrix = new int[3, 3];
                count = 0;

                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        matrix[i, j] = lst[count];
                        count++;
                    }
                }
            }
            else
            {
                matrix = new int[3, 2];
            }

            return matrix;
        }

        public int CalculateDeterminant(int[,] matrix)
        {
            int determinant = 0;
            if (matrix.GetLength(0) == 2)
            {
                determinant += (matrix[0, 0] * matrix[1, 1]) - (matrix[0, 1] * matrix[1, 0]);
            }
            else
            {
                for (int i = 0; i < 3; i++)
                {
                    determinant += (matrix[0, i] * (matrix[1, (i + 1) % 3] * matrix[2, (i + 2) % 3] - matrix[1, (i + 2) % 3] * matrix[2, (i + 1) % 3]));
                }
            }
            return determinant;
        }

        //minor matrix of key function
        public int[,] GetMinorMatrix(int[,] matrix, int row, int col)
        {
            int[,] minor = new int[matrix.GetLength(0) - 1, matrix.GetLength(1) - 1];
            int m = 0, n = 0;

            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                if (i == row)
                {
                    continue;
                }
                n = 0;
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    if (j == col)
                    {
                        continue;
                    }
                    minor[m, n] = matrix[i, j];
                    n++;
                }
                m++;
            }

            return minor;
        }


        public int GetMod(int x1, int x2)
        {
            int remainder = x1 % x2;
            if (remainder < 0)
            {
                remainder += x2;
            }
            return remainder;
        }

        public int finddet(int Det)
        {
            for (int i = 1; i < 26; i++)
            {
                if ((Det * i) % 26 == 1)
                {
                    return i;
                }
            }
            return 0;
        }

        public int[,] flip2x2Matrix(int[,] matrix)
        {
            int[,] flip = new int[2, 2];
            flip[0, 0] = matrix[1, 1];
            flip[1, 1] = matrix[0, 0];
            flip[0, 1] = -matrix[0, 1];
            flip[1, 0] = -matrix[1, 0];
            return flip;
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {


            List<int> outputPlainText = new List<int>();
            //convert key list to matrix
            int[,] keyMatrix = ConvertListToMatrix(key);
            int x1 = CalculateDeterminant(keyMatrix);
            int det = GetMod(x1, 26);
            //A × A-1 = I 
            List<int> keyInverseList = new List<int>();
            int rows = keyMatrix.GetLength(0);
            int cols = keyMatrix.GetLength(1);
            int[,] keyMatInverse = new int[rows, cols];

            if (keyMatrix.GetLength(0) == 3)
            {


                int b = finddet(det);
                for (int i = 0; i < keyMatrix.GetLength(0); i++)
                {
                    for (int j = 0; j < keyMatrix.GetLength(1); j++)
                    {
                        int[,] minorMatrix = GetMinorMatrix(keyMatrix, j, i);
                        int x2 = CalculateDeterminant(minorMatrix);
                        int subdet = GetMod(x2, 26);
                        keyMatInverse[i, j] = Convert.ToInt32(b * Math.Pow(-1, i + j) * subdet);
                        keyMatInverse[i, j] = GetMod(keyMatInverse[i, j], 26);
                    }
                }
                keyInverseList = ConvertMatrixToList(keyMatInverse);
                for (int k = 0; k < cipherText.Count; k += 3)
                {
                    for (int i = 0; i < keyInverseList.Count; i += 3)
                    {
                        outputPlainText.Add(((keyInverseList[i] * cipherText[k]) + (keyInverseList[i + 1] * cipherText[k + 1]) + (keyInverseList[i + 2] * cipherText[k + 2])) % 26);
                    }
                }
            }
            else if (keyMatrix.GetLength(0) == 2)
            {
                det = CalculateDeterminant(keyMatrix);
                int[,] flipMatrix = flip2x2Matrix(keyMatrix);
                for (int i = 0; i < keyMatInverse.GetLength(0); i++)
                    for (int j = 0; j < keyMatInverse.GetLength(1); j++)
                        keyMatInverse[i, j] = GetMod(((1 / det) * flipMatrix[i, j]), 26);
                keyInverseList = ConvertMatrixToList(keyMatInverse);
                for (int k = 0; k < cipherText.Count; k += 2)
                    for (int i = 0; i < keyInverseList.Count; i += 2)
                        outputPlainText.Add(((keyInverseList[i] * cipherText[k]) + (keyInverseList[i + 1] * cipherText[k + 1])) % 26);
            }
            if (outputPlainText.FindAll(s => s.Equals(0)).Count == outputPlainText.Count)
                throw new System.Exception();
            return outputPlainText;

        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            double x1 = (float)plainText.Count / 2;
            int x = (int)Math.Ceiling(x1);
            int y = (int)Math.Sqrt(key.Count);
            int[,] pt = new int[y, x];
            int row = 0, column = 0;
            foreach (int itr in plainText)
            {
                pt[row % y, column % x] = itr;
                if (row % y == y - 1)
                {
                    column++;
                    row++;
                }
                else
                {
                    row++;
                }
            }
            row = 0;
            column = 0;
            int[,] Matrix_key = new int[y, y];
            foreach (int itr in key)
            {
                Matrix_key[row % y, column % y] = itr;
                if (row % y == y - 1)
                {
                    column++;
                    row++;
                }
                else
                {
                    row++;
                }
            }
            List<int> ct = new List<int>();
            int elnateg = 0;
            for (int i = 0; i < x; i++)
            {
                for (int j = 0; j < y; j++)
                {
                    for (int k = 0; k < y; k++)
                    {
                        elnateg += (Matrix_key[k, j] * pt[k, i]);
                    }
                    elnateg %= 26;
                    ct.Add(elnateg);
                    elnateg = 0;
                }
            }
            return ct;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public int det_matrix2x2(int a, int b, int c, int d, int s)
        {
            int det;

            if (s == 1)
            {
                det = ((a * d) - (b * c)) % 26;
            }
            else
            {
                det = ((b * c) - (a * d)) % 26;
            }

            if (det < 0)
            {
                det += 26;
            }

            return det;
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //  throw new NotImplementedException();
            List<int> plaintext = new List<int>();
            int[,] matrixkey = new int[3, 3];

            int count = 0;
            int det = 0;
            int b = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    if (plain3[count] >= 0 || plain3[count] <= 26)
                    {
                        matrixkey[i, j] = plain3[count];
                        count++;
                    }
                }
            }
            count = 0;
            // calculating det for 2x2 or 3x3 matrices

            for (int i = 0; i < 3; i++)
            {
                int j = (i + 1) % 3;
                int l = (i + 2) % 3;
                int product1 = matrixkey[1, j] * matrixkey[2, l];
                int product2 = matrixkey[1, l] * matrixkey[2, j];
                int term = matrixkey[0, i] * (product1 - product2);
                det += term;
            }

            if (det < 0)
            {
                det = det % 26 + 26;
            }
            else
            {
                det = det % 26;
            }
            // calculating b

            int k = 0;
            while (b == 0 && k < 26)
            {
                int candidateB = (k * det) % 26;
                if (candidateB < 0)
                {
                    candidateB += 26;
                }

                if (candidateB == 1)
                {
                    b = k;
                }

                k++;
            }

            int[,] inverse_key_matrix = new int[3, 3];
            int[,] transpose_matrix = new int[3, 3];
            // calculating transpose matrix for 2x2 or 3x3 matrices  
            int temp;
            int z;
            int[] signs = new int[9];

            for (int i = 0; i < signs.Length; i++)
            {
                if (i % 2 == 0)
                {
                    signs[i] = 1;
                }
                else
                {
                    signs[i] = 0;
                }
            }

            int c = 0;
            int[] i_values = new int[] { 0, 1, 2 };
            int[] j_values = new int[] { 0, 1, 2 };
            foreach (int i in i_values)
            {
                foreach (int j in j_values)
                {
                    temp = b * Convert.ToInt32(Math.Pow(-1, i + j));
                    z = det_matrix2x2(matrixkey[(i + 1) % 3, (j + 1) % 3], matrixkey[(i + 1) % 3, (j + 2) % 3], matrixkey[(i + 2) % 3, (j + 1) % 3], matrixkey[(i + 2) % 3, (j + 2) % 3], signs[c]);
                    c++;
                    inverse_key_matrix[i, j] = (((temp * z) % 26) + 26) % 26;
                    transpose_matrix[j, i] = inverse_key_matrix[i, j];
                }
            }
            count = 0;
            int acc = 0;
            int[,] test = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    test[i, j] = cipher3[count];
                    count++;
                }
            }
            int count2 = 0;
            for (int i = 0; i < cipher3.Count / 3; i++)
            {

                for (int cc = 0; cc < 3; cc++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        acc += (transpose_matrix[count2, j] * test[j, cc]);
                    }
                    plaintext.Add(((acc % 26) + 26) % 26);
                    acc = 0;
                }
                count2++;
            }
            int count3 = 0;
            int[,] show = new int[3, 3];
            int[,] show_x = new int[3, 3];

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    show[i, j] = plaintext[count3];
                    count3++;
                }
            }

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    show_x[j, i] = show[i, j];

                }
            }
            List<int> t = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    t.Add(show_x[i, j]);
                }
            }
            return t;

            //throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }
    }
}
