using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        string el7rof = "abcdefghijklmnopqrstuvwxyz";
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            var key_stream = new StringBuilder();
            List<int> pt = new List<int>();
            List<int> ct = new List<int>();
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < el7rof.Length; j++)
                {
                    if (plainText[i] == el7rof[j])
                    {
                        pt.Add(j);
                    }
                    if (cipherText[i] == el7rof[j])
                    {
                        ct.Add(j);
                    }
                }
            }
            int index = 0;
            for (int i = 0; i < pt.Count; i++)
            {
                index = ct[i] - pt[i];
                if (index < 0)
                {
                    index = -index;
                    index %= 26;
                    index = 26 - index;
                }
                else
                {
                    index %= 26;
                }
                key_stream.Append(el7rof[index]);
            }
            int key_index = 0, simularity = 0;
            for (int i = 1; i < key_stream.Length; i++)
            {
                if (key_stream[i] == key_stream[key_index])
                {
                    if (simularity == 0)
                    {
                        index = i;
                        key_index++;
                        simularity++;
                    }
                    else
                    {
                        key_index++;
                        simularity++;
                    }

                }
                else if (key_stream[i] != key_stream[key_index])
                {
                    if (simularity == 1)
                    {
                        index = 0;
                        simularity = 0;
                        key_index = 0;
                    }
                    else
                    {
                        continue;
                    }
                }
            }
            string key = key_stream.ToString();
            if (simularity > 1)
            {
                key = key.Substring(0, index);
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            var pt = new StringBuilder();
            List<int> ct = new List<int>();
            List<int> k = new List<int>();
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < el7rof.Length; j++)
                {
                    if (cipherText[i] == el7rof[j])
                    {
                        ct.Add(j);
                    }

                }
            }
            for (int i = 0; i < key.Length; i++)
            {
                for (int j = 0; j < el7rof.Length; j++)
                {
                    if (key[i] == el7rof[j])
                    {
                        k.Add(j);
                    }

                }
            }


            int counter = cipherText.Length - key.Length;
            int index = 0;
            if (counter != 0)
            {
                for (int i = 0; i < counter; i++)
                {
                    index = k[(i % k.Count)];
                    k.Add(index);
                }
            }
            index = 0;
            for (int i = 0; i < ct.Count; i++)
            {
                index = (ct[i] - k[i]);
                if (index < 0)
                {
                    index = -index;
                    index %= 26;
                    index = 26 - index;
                }
                else
                {
                    index %= 26;
                }
                pt.Append(el7rof[index]);
            }
            string plainText = pt.ToString();
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            var ct = new StringBuilder();
            List<int> pt = new List<int>();
            List<int> k = new List<int>();
            int counter = plainText.Length - key.Length;
            if (counter != 0)
            {
                for (int i = 0; i < counter; i++)
                {
                    key = string.Concat(key, key[i]);
                }
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < el7rof.Length; j++)
                {
                    if (plainText[i] == el7rof[j])
                    {
                        pt.Add(j);
                    }
                    if (key[i] == el7rof[j])
                    {
                        k.Add(j);
                    }
                }
            }
            int index = 0;
            for (int i = 0; i < pt.Count; i++)
            {
                index = (pt[i] + k[i]) % 26;
                ct.Append(el7rof[index]);
            }
            string c = ct.ToString();
            return c;
        }
    }
}