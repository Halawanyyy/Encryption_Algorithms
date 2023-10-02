using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{

    public class AES : CryptographicTechnique
    {


        // s-box of 16x16 used to substitue the values in plaintext with different values
        public static Byte[,] Tesla = {
            { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
            { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
            { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
            { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
            { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
            { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
            { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
            { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
            { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
            { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
            { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
            { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
            { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
            { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
            { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
            { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
        };

        public static Byte[,] inv_Tesla = {
            { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
            { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
            { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
            { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
            { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
            { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
            { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
            { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
            { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
            { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
            { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
            { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
            { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
            { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
            { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
            { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
        };



        public override string Decrypt(string cipherText, string key)
        {
            int numKeys = numberofBytes * (numberofRounds + 1);
            byte[,] keyexp = createMatrix(numberofBlocks, numKeys);
            byte[,] roundKey = createMatrix(numberofBlocks, numberofBytes);
            byte[,] state = ConvertToMatrix(cipherText);

            // Generate round keys
            KeyExpansion(ConvertToMatrix(key), ref keyexp);

            // Add round key for final round
            GetRoundKey(numberofRounds, keyexp, ref roundKey);
            AddRoundKey(ref state, roundKey);
            InvShiftRows(ref state);
            InvSubBytes(ref state);

            // Perform rounds numRounds-1 to 1
            for (int i = numberofRounds - 1; i >= 1; i--)
            {
                GetRoundKey(i, keyexp, ref roundKey);
                AddRoundKey(ref state, roundKey);
                InvMixColumns(ref state);
                InvShiftRows(ref state);
                InvSubBytes(ref state);
            }

            // Add round key for round 0
            GetRoundKey(0, keyexp, ref roundKey);
            AddRoundKey(ref state, roundKey);

            // Convert state matrix to plaintext string
            return ToHexString(state);
            //throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string encryptionKey)
        {
            int numKeys = numberofBytes * (numberofRounds + 1);
            //creating 2d array for the key expansion with the encryption key
            byte[,] keyexp = createMatrix(numberofBlocks, numKeys);
            //round key for the substitution
            byte[,] roundKey = createMatrix(numberofBlocks, numberofBytes);

            byte[,] state = ConvertToMatrix(plainText);

            // Generate set of expanded round keys (the number of round keys must = number of rounds+1)
            KeyExpansion(ConvertToMatrix(encryptionKey), ref keyexp);

            // Add round key for round 0
            GetRoundKey(0, keyexp, ref roundKey);
            AddRoundKey(ref state, roundKey);

            // Performing at each round substitution, shift rows, mix operations on columns, get rounded key
            for (int i = 1; i <= numberofRounds - 1; i++)
            {
                SubBytes(ref state);
                ShiftRows(ref state);
                MixColumns(ref state);
                GetRoundKey(i, keyexp, ref roundKey);
                //xoring the the each byte of the current state with the roundedkey
                AddRoundKey(ref state, roundKey);
            }

            // Final round
            SubBytes(ref state);
            ShiftRows(ref state);
            GetRoundKey(numberofRounds, keyexp, ref roundKey);
            AddRoundKey(ref state, roundKey);

            // Convert state matrix to hex string
            return ToHexString(state);


        }

        // Creates a 2D matrix with the specified number of rows and columns
        public byte[,] createMatrix(int numRows, int numCols)
        {
            byte[,] matrix = new byte[numRows, numCols];
            for (int i = 0; i < numRows; i++)
            {
                for (int j = 0; j < numCols; j++)
                {
                    matrix[i, j] = 0x00;
                }
            }
            return matrix;
        }
        int numberofRounds = 10;
        int numberofBytes = 4;
        int numberofBlocks = 4;


        // Creates a vector of bytes with the specified size
        public byte[] CreateVector(int size)
        {
            byte[] vector = new byte[numberofBytes];
            for (int i = 0; i < numberofBytes; i++)
            {
                vector[i] = 0x00;
            }
            return vector;
        }

        // Retrieves the round key for the specified round
        public void GetRoundKey(int round, byte[,] expandedkey, ref byte[,] key)
        {
            //the first byte of the round key in the current round
            int index = round * numberofBytes;
            for (int i = 0; i < numberofBytes; i++)
            {
                for (int j = 0; j < numberofBlocks; j++)
                {
                    key[j, i] = expandedkey[j, index + i];
                }
            }
        }

        // Converts the state matrix to a hex string
        public string ToHexString(byte[,] state)
        {
            string hexString = "0x";
            for (int i = 0; i < numberofBytes; i++)
            {
                for (int j = 0; j < numberofBlocks; j++)
                {
                    string value = Convert.ToString(state[j, i], 16);
                    if (value.Length == 1)
                    {
                        value = "0" + value;
                    }
                    hexString += value;
                }
            }
            return hexString;
        }

        // Converting  hexadecimal  string to a 2D matrix
        public byte[,] ConvertToMatrix(string hexaText)
        {
            byte[,] state = new byte[numberofBlocks, numberofBytes];
            hexaText = hexaText.Replace("0x", "");
            //taking two input string at a time using numberofBytes * numberofBlocks
            for (int i = 0; i < numberofBytes * numberofBlocks; i++)
            {
                //Convert each pair of hex characters to a byte using the Convert.ToInt32 method with base 16.
                int byteValue = Convert.ToInt32(hexaText.Substring(i * 2, 2), 16);
                // storing byte variable in the state
                state[i % numberofBlocks, i / numberofBlocks] = (byte)byteValue;
            }

            return state;
        }


        //xoring the the each byte of the current state with the roundedkey
        public void AddRoundKey(ref byte[,] state, byte[,] key)
        {
            for (int i = 0; i < numberofBytes; i++)
                for (int j = 0; j < numberofBlocks; j++)
                    state[j, i] = (Byte)(state[j, i] ^ key[j, i]);
        }

        public void SubBytes(ref byte[,] state)
        {
            for (int i = 0; i < numberofBytes; i++)
                for (int j = 0; j < numberofBlocks; j++)
                    state[j, i] = Tesla[state[j, i] / 16, state[j, i] % 16];
        }

        public void InvSubBytes(ref byte[,] state)
        {
            for (int i = 0; i < numberofBytes; i++)
                for (int j = 0; j < numberofBlocks; j++)
                    state[j, i] = inv_Tesla[state[j, i] / 16, state[j, i] % 16];
        }
        //shifting each row to the left
        public void ShiftRow(ref byte[,] state, int rowIndex, int numberofpositions)
        {
            for (int i = 0; i < numberofpositions; i++)
            {
                Byte temp = state[rowIndex, 0];
                for (int j = 0; j < numberofBytes - 1; j++)
                {
                    state[rowIndex, j] = state[rowIndex, j + 1];
                }
                state[rowIndex, numberofBytes - 1] = temp;
            }
        }

        public void ShiftRows(ref byte[,] state)
        {
            ShiftRow(ref state, 1, 1);
            ShiftRow(ref state, 2, 2);
            ShiftRow(ref state, 3, 3);
        }

        public void InvShiftRows(ref byte[,] state)
        {
            ShiftRow(ref state, 1, 3);
            ShiftRow(ref state, 2, 2);
            ShiftRow(ref state, 3, 1);
        }
        //mixcolumns is an operation where it is applied to each column of the state array
        //treating each column as vector of 4 bytes, each byte is multiplied by constant either 2 or 3 using xor operations
        public void MixColumns(ref byte[,] state)
        {
            for (int col = 0; col < numberofBytes; col++)
            {
                byte s0 = state[0, col];
                byte s1 = state[1, col];
                byte s2 = state[2, col];
                byte s3 = state[3, col];

                // Perform the column mixing operations
                state[0, col] = (byte)(MulBytes(0x02, s0) ^ MulBytes(0x03, s1) ^ s2 ^ s3);
                state[1, col] = (byte)(s0 ^ MulBytes(0x02, s1) ^ MulBytes(0x03, s2) ^ s3);
                state[2, col] = (byte)(s0 ^ s1 ^ MulBytes(0x02, s2) ^ MulBytes(0x03, s3));
                state[3, col] = (byte)(MulBytes(0x03, s0) ^ s1 ^ s2 ^ MulBytes(0x02, s3));
            }
        }


        public void InvMixColumns(ref byte[,] state)
        {
            for (int col = 0; col < numberofBytes; col++)
            {
                byte s0 = state[0, col];
                byte s1 = state[1, col];
                byte s2 = state[2, col];
                byte s3 = state[3, col];

                // Perform the inverse column mixing operations
                state[0, col] = (byte)(MulBytes(0x0e, s0) ^ MulBytes(0x0b, s1) ^ MulBytes(0x0d, s2) ^ MulBytes(0x09, s3));
                state[1, col] = (byte)(MulBytes(0x09, s0) ^ MulBytes(0x0e, s1) ^ MulBytes(0x0b, s2) ^ MulBytes(0x0d, s3));
                state[2, col] = (byte)(MulBytes(0x0d, s0) ^ MulBytes(0x09, s1) ^ MulBytes(0x0e, s2) ^ MulBytes(0x0b, s3));
                state[3, col] = (byte)(MulBytes(0x0b, s0) ^ MulBytes(0x0d, s1) ^ MulBytes(0x09, s2) ^ MulBytes(0x0e, s3));
            }
        }

        public void KeyExpansion(byte[,] key, ref byte[,] w)
        {
            byte[] prev = CreateVector(numberofBlocks);
            byte[] rcon = CreateVector(numberofBlocks);

            for (int i = 0; i < numberofBytes; i++)
                for (int j = 0; j < numberofBlocks; j++)
                    w[j, i] = key[j, i];
            int numberKeys = numberofBytes * (numberofRounds + 1);
            for (int i = numberofBytes; i < numberKeys; i++)
            {
                for (int j = 0; j < numberofBlocks; j++)
                    prev[j] = w[j, i - 1];
                if (i % numberofBytes == 0)
                {
                    RotWord(ref prev);
                    SubWord(ref prev);
                    Roundconstant(ref rcon, i / numberofBytes);
                    XorWords(prev, rcon, ref prev);
                }
                else if (numberofBytes > 6 && i / 4 % numberofBytes == 4)
                    SubWord(ref prev);

                for (int j = 0; j < numberofBlocks; j++)
                    w[j, i] = (Byte)(w[j, i - numberofBytes] ^ prev[j]);
            }
        }

        public Byte MulBytes(Byte b1, Byte b2)
        {
            Byte ans = 0, temp;
            for (int i = 0; i < 8; i++)
            {
                if ((b2 & 0x01) == 0x01)
                {
                    temp = b1;
                    for (int j = 0; j < i; j++)
                        temp = Xtime(temp);
                    ans = (Byte)(ans ^ temp);
                }
                b2 = (Byte)(b2 >> 1);
            }
            return ans;
        }
        public void RotWord(ref byte[] word)
        {
            byte temp = word[0];
            for (int i = 1; i < word.Length; i++)
            {
                word[i - 1] = word[i];
            }
            word[word.Length - 1] = temp;
        }


        public void SubWord(ref byte[] word)
        {
            for (int i = 0; i < 4; i++)
            {
                word[i] = Tesla[word[i] / 16, word[i] % 16];
            }
        }

        public void XorWords(byte[] a, byte[] b, ref byte[] c)
        {
            for (int i = 0; i < 4; i++)
                c[i] = (Byte)(a[i] ^ b[i]);
        }

        // Round Constant
        public void Roundconstant(ref byte[] word, int n)
        {
            Byte c = 0x01;
            for (int i = 0; i < n - 1; i++)
            {
                c = Xtime(c);
            }
            word[0] = c;
            word[1] = word[2] = word[3] = 0x00;
        }

        public Byte Xtime(Byte b)
        {
            Byte highBit = (Byte)(b & 0x80);
            b = (Byte)(b << 1);
            if (highBit > 0x00)
            {
                b = (Byte)(b ^ 0x1B);
            }
            return b;
        }
    }
}