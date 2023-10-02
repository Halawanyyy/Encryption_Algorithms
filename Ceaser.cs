using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        string cipher;
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            string x = "abcdefghijklmnopqrstuvwxyz";
            Console.WriteLine(plainText);
            for (int i = 0; i < plainText.Length; i++)
            {
                int index = x.IndexOf(plainText[i]);
                Console.WriteLine(index);
                cipher += x[((index + key) % 26)];
                Console.WriteLine(cipher);
            }
            return cipher.ToUpper();
        }

        string plain;
        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            string x = "abcdefghijklmnopqrstuvwxyz".ToUpper();

            for (int i = 0; i < cipherText.Length; i++)
            {
                int index = x.IndexOf(cipherText[i]);
                int z = (index - key);
                if (z < 0)
                    z += 26;
                plain += x[(z % 26)];
            }

            return plain.ToLower();
        }

        int key;
        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            //throw new NotImplementedException();
            string x = "abcdefghijklmnopqrstuvwxyz";

            for (int i = 0; i < plainText.Length; i++)
            {

                int index1 = x.IndexOf(cipherText[i]);
                int index2 = x.IndexOf(plainText[i]);
                key = (index1 - index2) % 26;
                if (key < 0)
                    key += 26;


            }
            return key;
        }
    }
}