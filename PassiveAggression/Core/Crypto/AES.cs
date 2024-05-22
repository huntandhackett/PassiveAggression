using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PassiveAgression.Core.Crypto
{
    public class AES
    {
        /// <summary>
        /// Decrypts AES128 CFB8 ciphertext with given key and Iv 
        /// </summary>
        /// <param name="ciphertext"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static byte[] DecryptAES128CFB8(byte[] ciphertext, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;

                if (iv != null) { aesAlg.IV = iv; }


                aesAlg.Mode    = CipherMode.CFB;
                aesAlg.Padding = PaddingMode.None;

                using (ICryptoTransform decryptor = aesAlg.CreateDecryptor())
                {
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                    return decryptedBytes;
                }
            }
        }

        /// <summary>
        /// Decrypts AES256 cipherText with given key and Iv
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="ciphermode"></param>
        /// <returns></returns>
        public static byte[] DecryptAES256(byte[] cipherText, byte[] key, byte[] iv, CipherMode ciphermode)
        {
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key  = key;
                aesAlg.IV   = iv;
                aesAlg.Mode = ciphermode;
                //aesAlg.Padding  = PaddingMode.PKCS7;
                aesAlg.Padding = PaddingMode.None;

                using (MemoryStream msDecrypt = new MemoryStream())
                {
                    using (ICryptoTransform decryptor = aesAlg.CreateDecryptor())
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                    {
                        csDecrypt.Write(cipherText, 0, cipherText.Length);
                    }
                    return msDecrypt.ToArray();
                }
            }
        }
    }
}
