using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PassiveAgression.Core.Crypto
{
    internal class Signing
    {
        /// <summary>
        /// Thx: https://github.com/fortra/impacket/blob/master/impacket/crypto.py#L211
        /// </summary>
        /// <param name="KI"></param>
        /// <param name="Label"></param>
        /// <param name="Context"></param>
        /// <param name="L"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public static byte[] ComputeHMACSha256KDFCounterMode(byte[] KI, byte[] Label, byte[] Context, int L)
        {
            int h = 256;
            int n = L / h;
            int r = 32;
            if (n == 0)
            {
                n = 1;
            }

            if (n > Math.Pow(2, r) - 1)
            {
                throw new Exception("Error computing KDF_CounterMode");
            }

            byte[] result = new byte[0];
            byte[] K      = new byte[0];

            for (int i = 1; i <= n; i++)
            {
                byte[] input = BitConverter.GetBytes(i).Reverse().ToArray()
                                           .Concat(Label)
                                           .Concat(new byte[] { 0 })
                                           .Concat(Context)
                                           .Concat(BitConverter.GetBytes(L).Reverse().ToArray())
                                           .ToArray();

                using (HMACSHA256 hmac = new HMACSHA256(KI))
                {
                    K = hmac.ComputeHash(input);
                }

                result = result.Concat(K).ToArray();
            }

            return result.Take(L / 8).ToArray();
        }

        /// <summary>
        /// Computes MD5 hash of given data
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] ComputeMD5Hash(byte[] data)
        {
            try
            {

                // Create an instance of the MD5 algorithm
                using (MD5 md5 = MD5.Create())
                {
                    // Calculate the MD5 hash
                    byte[] hashBytes = md5.ComputeHash(data);

                    return hashBytes;
                }
            }
            catch (Exception ex)
            {
                // Handle any exceptions that may occur during hash calculation
                Console.WriteLine("MD5 calculation error: " + ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Calculates HmacSHA512 key
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] CalculateHmacSha512(byte[] key, byte[] data)
        {
            using (HMACSHA512 hmac = new HMACSHA512(key))
            {
                return hmac.ComputeHash(data);
            }
        }
    }
}
