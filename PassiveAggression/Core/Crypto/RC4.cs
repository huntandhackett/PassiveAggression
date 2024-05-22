using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PassiveAgression.Core.Crypto
{
    public class RC4
    {

        private class _RC4 : IDisposable
        {
            private byte[] s;
            private int i, j;

            public _RC4(byte[] key)
            {
                s = new byte[256];
                for (int k = 0; k < 256; k++)
                {
                    s[k] = (byte)k;
                }

                int j = 0;
                for (int k = 0; k < 256; k++)
                {
                    j = (j + key[k % key.Length] + s[k]) & 255;
                    Swap(s, k, j);
                }

                i = j = 0;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int offset, int count)
            {
                byte[] outputBuffer = new byte[count];
                for (int k = 0; k < count; k++)
                {
                    i = (i + 1)    & 255;
                    j = (j + s[i]) & 255;
                    Swap(s, i, j);
                    outputBuffer[k] = (byte)(inputBuffer[offset + k] ^ s[(s[i] + s[j]) & 255]);
                }
                return outputBuffer;
            }

            private void Swap(byte[] array, int i, int j)
            {
                byte temp = array[i];
                array[i] = array[j];
                array[j] = temp;
            }

            public void Dispose()
            {
                Array.Clear(s, 0, s.Length);
            }
        }

        /// <summary>
        /// Encrypts or decrypt data using given key
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] TransformData(byte[] encryptedData, byte[] key)
        {
            try
            {
                // Create an instance of the RC4 algorithm
                using (_RC4 rc4 = new _RC4(key))
                {

                    // Decrypt the data
                    byte[] decryptedBytes = rc4.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                    return decryptedBytes;
                }

            }
            catch (Exception ex)
            {
                // Handle any exceptions that may occur during decryption
                Console.WriteLine("Decryption error: " + ex.Message);
                return null;
            }
        }
    }
}
