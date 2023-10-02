using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        static void Swap<T>(ref T a, ref T b)
        {
            T temp;
            temp = a;
            a = b;
            b = temp;
        }

        static string HextoString(string plainText)
        {
            string tmp = "", prefix = "";
            plainText += '1';

            for (int i = 2; i < plainText.Length; i++)
            {
                if (i % 2 == 0 && tmp.Length == 2)
                {
                    int a = 0, b = 0;
                    if (tmp[0] >= '0' && tmp[0] <= '9')
                        a = tmp[0] - '0';

                    else if (tmp[0] >= 'a' && tmp[0] <= 'f')
                        a = tmp[0] - 'a' + 10;

                    if (tmp[1] >= '0' && tmp[1] <= '9')
                        b = tmp[1] - '0';

                    else if (tmp[1] >= 'a' && tmp[1] <= 'f')
                        b = tmp[1] - 'a' + 10;


                    prefix += (char)((16 * a) + b);
                    tmp = "";
                }
                tmp += plainText[i];
            }
            return prefix;
        }
        public override string Decrypt(string cipherText, string key)
        {
            return Encrypt(cipherText, key);
        }

        public override string Encrypt(string plainText, string key)
        {


            int i, j;

            string prefix = "";
            bool Hex = false;
            if (plainText.Length >= 2)
            {
                prefix += plainText[0];
                prefix += plainText[1];
            }

            if (prefix == "0x")
            {
                Hex = true;
                plainText = HextoString(plainText);
                key = HextoString(key);
            }


            int[] s = new int[256];


            for (i = 0; i < 256; i++)
            {
                s[i] = i;
            }
            j = 0;

            for (i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i % key.Length]) % 256;
                Swap<int>(ref s[i], ref s[j]);
            }

            i = j = 0;


            string cipherText = "";
            for (int l = 0; l < plainText.Length; l++)
            {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                Swap<int>(ref s[i], ref s[j]);
                int t = (s[i] + s[j]) % 256;
                int k = s[t];
                char cipher = (char)(plainText[l] ^ k);
                cipherText += cipher;

            }

            if (Hex == true)
            {
                string ans = "0x";

                for (i = 0; i < cipherText.Length; i++)
                {
                    int x = cipherText[i];
                    int f = x / 16;
                    int v = x % 16;

                    if (f >= 0 && f <= 9)
                        f += '0';
                    if (f >= 10 && f <= 15)
                        f = 'a' + (f - 10);
                    if (v >= 0 && v <= 9)
                        v += '0';
                    if (v >= 10 && v <= 15)
                        v = 'a' + (v - 10);


                    ans += (char)(f);
                    ans += (char)(v);
                }
                return ans;

            }
            return cipherText;




        }
    }
}