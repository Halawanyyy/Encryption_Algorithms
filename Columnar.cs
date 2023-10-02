using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            List<int> key = new List<int>();
            Dictionary<char, int> charIndex = new Dictionary<char, int>();
            for (int i = 0; i < plainText.Length; i++)
            {
                charIndex.Add(plainText[i], i);
            }


            for (int i = 0; i < cipherText.Length; i++)
            {
                char c = cipherText[i];
                if (charIndex.ContainsKey(c))
                {
                    if (key.Contains(charIndex[c]))
                    {
                        continue;
                    }
                    else
                    key.Add(charIndex[c]);
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            // calculate the number of columns based on the length of the key
            int numCols = key.Count;
            // calculate the number of rows based on the length of the ciphertext and the number of columns
            int numRows = (int)Math.Ceiling((double)cipherText.Length / numCols);
            // initialize the matrix to store the ciphertext
            char[,] matrix = new char[numRows, numCols];
            // initialize the index to keep track of the position in the ciphertext string
            int index = 0;
            // fill the matrix column by column
            for (int j = 0; j < numCols; j++)
            {
                // get the index of the current column in the key
                int colIndex = key.IndexOf(j + 1);
                // fill the column from top to bottom
                for (int i = 0; i < numRows; i++)
                {
                    if (index < cipherText.Length)
                    {
                        matrix[i, colIndex] = cipherText[index];
                        index++;
                    }
                    else
                    {
                        matrix[i, colIndex] = ' ';
                    }
                }
            }
            // read the matrix row by row to get the plaintext
            StringBuilder plaintextBuilder = new StringBuilder();
            for (int i = 0; i < numRows; i++)
            {
                for (int j = 0; j < numCols; j++)
                {
                    plaintextBuilder.Append(matrix[i, j]);
                }
            }
            // remove any trailing spaces
            string plaintext = plaintextBuilder.ToString().Trim();
            return plaintext;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();

            // Remove spaces and periods from the plaintext
            plainText = plainText.Replace(" ", "").Replace(".", "");
            // Determine the number of rows and columns for the matrix
            int numColumns = key.Count;
            int numRows = (int)Math.Ceiling((double)plainText.Length / numColumns);

            // Pad the plaintext with null characters if necessary
            plainText = plainText.PadRight(numRows * numColumns, '\0');
                // Build the matrix
                char[,] matrix = new char[numRows, numColumns];
                int index = 0;

                for (int row = 0; row < numRows; row++)
                {
                    for (int col = 0; col < numColumns; col++)
                    {
                        int keyIndex = key[col] - 1;
                        matrix[row, keyIndex] = plainText[index];
                        index++;
                    }
                }

                // Read the encrypted message column by column
                string ciphertext = "";

                for (int col = 0; col < numColumns; col++)
                {
                    for (int row = 0; row < numRows; row++)
                    {
                        ciphertext += matrix[row, col];
                    }
                }
            return ciphertext;
            }
        }
    }

