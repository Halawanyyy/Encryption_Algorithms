using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary
{

    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public char[] Convert_2D_to_1D(char[,] _2dArray) //to convert 2d array to 1d array to use foreach loop

        {
            return _2dArray.Cast<char>().ToArray<char>();
        }

        public char[,] Generate5x5Matrix(string key)
        {
            key = key.Replace('j', 'i').ToUpper();
            char[,] KeyMatrix = new char[5, 5];
            int row = 0, col = 0;
            foreach (char c in key)
            {
                if (col == 5) //if column==5 then row++ and col=0 to go to next row with first 
                {
                    col = 0;
                    row++;
                }
                if (!Convert_2D_to_1D(KeyMatrix).Contains(c))
                {
                    KeyMatrix[row, col] = c;
                    col++;
                }
            }
            char[] Alphabetic_Letters = "ABCDEFGHIKLMNOPQRSTUVWXYZ".ToCharArray();
            foreach (char c in Alphabetic_Letters)
            {
                if (col == 5)
                {
                    col = 0;
                    row++;
                }
                if (!Convert_2D_to_1D(KeyMatrix).Contains(c))
                {
                    KeyMatrix[row, col] = c;
                    col++;
                }
            }
            return KeyMatrix;
        }
        long[] FindPositionOfLetter(char c, char[,] Matrix)
        {
            long[] coordinates = new long[2];
            for (long i = 0; i < 5; i++)
            {
                for (long j = 0; j < 5; j++)
                {
                    if (Matrix[i, j] == c)
                    {
                        coordinates[0] = i;
                        coordinates[1] = j;
                        return coordinates;
                    }
                }
            }
            coordinates[0] = -1;
            coordinates[1] = -1;
            return coordinates;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plaintext = "";
            cipherText = cipherText.Replace('J', 'I').ToUpper();
            char[,] Decryption_Matrix = Generate5x5Matrix(key);
            List<string> SplitTwoChar = new List<string>();
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                if ((i == cipherText.Length - 1 && (cipherText.Length) % 2 != 0) || cipherText[i] == cipherText[i + 1])
                {
                    SplitTwoChar.Add(cipherText[i] + "X");
                }
                else
                    SplitTwoChar.Add(cipherText.Substring(i, 2));
            }
            foreach (String c in SplitTwoChar)
            {
                long[] coordinate1 = FindPositionOfLetter(c[0], Decryption_Matrix);
                long[] coordinate2 = FindPositionOfLetter(c[1], Decryption_Matrix);
                // If the two letters are in the same row
                if (coordinate1[0] == coordinate2[0])
                {
                    plaintext += Decryption_Matrix[coordinate1[0], (coordinate1[1] + 4) % 5];
                    plaintext += Decryption_Matrix[coordinate2[0], (coordinate2[1] + 4) % 5];
                }
                // If the two letters are in the same column
                else if (coordinate1[1] == coordinate2[1])
                {
                    plaintext += Decryption_Matrix[(coordinate1[0] + 4) % 5, coordinate1[1]];
                    plaintext += Decryption_Matrix[(coordinate2[0] + 4) % 5, coordinate2[1]];
                }
                // If the two letters are in different rows and columns,
                else
                {
                    plaintext += Decryption_Matrix[coordinate1[0], coordinate2[1]];
                    plaintext += Decryption_Matrix[coordinate2[0], coordinate1[1]];
                }
            }
            string temp = plaintext;
            if (plaintext[plaintext.Length - 1] == 'X')
            {
                temp = temp.Remove(plaintext.Length - 1);
            }
            int j = 0;
            for (int i = 0; i < temp.Length; i++)
            {
                if (plaintext[i] == 'X')
                {
                    if (plaintext[i + 1] == plaintext[i - 1])
                    {
                        if (i + j < temp.Length && (i - 1) % 2 == 0)
                        {
                            temp = temp.Remove(i + j, 1);
                            j--;
                        }
                    }
                }
            }
            return temp;
        }

        public string Encrypt(string plainText, string key)
        {
            key = key.ToUpper();
            string cipherText = "";
            plainText = plainText.Replace('J', 'I').ToUpper();
            char[,] Decryption_Matrix = Generate5x5Matrix(key);
            List<string> SplitTwoChar = new List<string>();
            for (int i = 0; i < plainText.Length; i += 2)
            {
                if (i == plainText.Length - 1)
                {
                    SplitTwoChar.Add(plainText[i] + "X");
                }
                else if (plainText[i] == plainText[i + 1])
                {
                    SplitTwoChar.Add(plainText[i] + "X");
                    i--;
                }
                else
                    SplitTwoChar.Add(plainText.Substring(i, 2));
            }
            foreach (String c in SplitTwoChar)
            {
                long[] coordinate1 = FindPositionOfLetter(c[0], Decryption_Matrix);
                long[] coordinate2 = FindPositionOfLetter(c[1], Decryption_Matrix);
                // If the two letters are in the same row
                if (coordinate1[0] == coordinate2[0])
                {
                    cipherText += Decryption_Matrix[coordinate1[0], (coordinate1[1] + 1) % 5];
                    cipherText += Decryption_Matrix[coordinate2[0], (coordinate2[1] + 1) % 5];
                }
                // If the two letters are in the same column
                else if (coordinate1[1] == coordinate2[1])
                {
                    cipherText += Decryption_Matrix[(coordinate1[0] + 1) % 5, coordinate1[1]];
                    cipherText += Decryption_Matrix[(coordinate2[0] + 1) % 5, coordinate2[1]];
                }
                // If the two letters are in different rows and columns,
                else
                {
                    cipherText += Decryption_Matrix[coordinate1[0], coordinate2[1]];
                    cipherText += Decryption_Matrix[coordinate2[0], coordinate1[1]];
                }
            }
            return cipherText;



        }
    }
}
