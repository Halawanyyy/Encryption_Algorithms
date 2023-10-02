using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        string el7rof = "abcdefghijklmnopqrstuvwxyz";
        public string Analyse(string plainText, string cipherText)
        {
            string pt = string.Empty;
            string ct = string.Empty;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (!pt.Contains(plainText[i]))
                {
                    pt += plainText[i];
                }
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (!ct.Contains(cipherText[i]))
                {
                    ct += cipherText[i];
                }
            }
            var key = new StringBuilder();
            var temp = new StringBuilder();
            string checker = "\0";
            char[] arr = new char[26];
            char el7arf = 'a';
            for (int i = 0; i < pt.Length; i++)
            {
                for (int j = 0; j < el7rof.Length; j++)
                {
                    if (pt[i] == el7rof[j])
                    {
                        arr[j] = ct[i];
                        break;
                    }
                    else
                        continue;
                }
            }
            for (int i = 0; i < arr.Length; i++)
            {
                if (arr[i] != '\0')
                {
                    temp.Append(arr[i]);
                }

            }
            checker = temp.ToString();
            for (int j = 0; j < el7rof.Length; j++)
            {
                if (arr[j] == '\0')
                {
                    while (true)
                    {
                        if (checker.Contains(el7arf))
                        {
                            if (el7arf == 'Z')
                            {
                                el7arf = 'A';
                                continue;
                            }
                            else
                            {
                                el7arf++;
                                continue;
                            }
                        }
                        else
                        {
                            arr[j] = el7arf;
                            checker = string.Concat(checker, el7arf);
                            break;
                        }
                    }
                }
                else
                {
                    el7arf = arr[j];
                }
            }
            for (int j = 0; j < 26; j++)
            {
                key.Append(arr[j]);
            }
            string pt1 = key.ToString();
            pt1=pt1.ToLower();
            return pt1;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            var pt1 = new StringBuilder();
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {
                    if (cipherText[i] == key[j])
                    {
                        pt1.Append(el7rof[j]);
                        break;
                    }
                    else
                        continue;
                }
            }
            string pt = pt1.ToString();
            return pt;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            //string ct;
            var ct1 = new StringBuilder();
            for(int i = 0; i < plainText.Length; i++)
            {
                for(int j = 0; j < el7rof.Length; j++)
                {
                    if (plainText[i] == el7rof[j])
                    {
                        ct1.Append(key[j]);
                        break;
                    }
                    else
                        continue;
                }
            }
            string ct = ct1.ToString();
            return ct;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher">
        /// 
        /// </param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            string freq_info = "etaoinsrhldcumfpgwybvkxjqz";
            int freq_num = 0;
            var freq_el7rof = new Dictionary<char, int>();
            for (int i = 0; i < cipher.Length; i++)
            {
                if (!freq_el7rof.ContainsKey(cipher[i]))
                {
                    freq_el7rof.Add(cipher[i], 1);
                }
                else
                {
                    freq_num = freq_el7rof[cipher[i]];
                    freq_num++;
                    freq_el7rof[cipher[i]] = freq_num;
                }
            }
            List<KeyValuePair<char, int>> sorted_el7rof = freq_el7rof.ToList();
            sorted_el7rof.Sort(
                delegate (KeyValuePair<char, int> firt_7arf,
                KeyValuePair<char, int> second_7arf)
                {
                    return second_7arf.Value.CompareTo(firt_7arf.Value);
                }
                );
            foreach (KeyValuePair<char, int> att in sorted_el7rof)
            {
                Console.WriteLine(att.Value);
            }

            var pt = new StringBuilder();
            for (int i = 0; i < cipher.Length; i++)
            {
                int index = 0;
                foreach (KeyValuePair<char, int> att in sorted_el7rof)
                {
                    if (cipher[i] == att.Key && index < 26)
                    {
                        pt.Append(freq_info[index]);
                        break;
                    }
                    else
                    {
                        index++;
                        continue;
                    }
                }
            }
            string plain_text = pt.ToString();
            return plain_text;
            //KeyValuePair<char, int> temp=freq_el7rof.Values.;
            //foreach (KeyValuePair<char, int> k in freq_el7rof)
            //{
            //        if (k.Value < temp.Value)
            //        {
            //            temp = k;
            //        }
            //}
           
        }
    }
}