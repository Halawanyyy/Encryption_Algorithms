using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int key = 1;
            for (int i = 0; i < cipherText.Length - 1; i++)
            {
                key = i;
                if (plainText[i] == cipherText[1] && plainText[i * 2] == cipherText[2])
                {

                    return key;

                }
            }
            return key;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            char[,] rfmatrix = new char[key, (int)Math.Ceiling((double)cipherText.Length / key)];
            int count = 0;

            for (int i = 0; i < rfmatrix.GetLength(0); i++)
            {
                for (int j = 0; j < rfmatrix.GetLength(1); j++)
                {
                    if (count < cipherText.Length)
                    {
                        rfmatrix[i, j] = cipherText[count];
                        count++;
                    }
                }
            }

            string plainText = "";

            for (int i = 0; i < rfmatrix.GetLength(1); i++)
            {
                for (int j = 0; j < rfmatrix.GetLength(0); j++)
                {
                    plainText += rfmatrix[j, i];
                }
            }


            return plainText;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, int key)
        {
            // initialize rail fence matrix with null characters


            char[,] rfmatrix = new char[key, (int)Math.Ceiling((double)plainText.Length / key)];
            int count = 0;

            for (int i = 0; i < rfmatrix.GetLength(1); i++)
            {
                for (int j = 0; j < rfmatrix.GetLength(0); j++)
                {
                    if (count < plainText.Length)
                    {
                        rfmatrix[j, i] = plainText[count];
                        count++;
                    }
                }
            }

            string encryptedtext = "";

            for (int i = 0; i < rfmatrix.GetLength(0); i++)
            {
                for (int j = 0; j < rfmatrix.GetLength(1); j++)
                {
                    encryptedtext += rfmatrix[i, j];
                }
            }

            return encryptedtext;


            //throw new NotImplementedException();
        }
    }
}
