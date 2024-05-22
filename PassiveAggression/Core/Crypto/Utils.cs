using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static PassiveAgression.Core.Win32.Natives;

namespace PassiveAgression.Core.Crypto
{
    internal class Utils
    {

        public struct SChannelKeyData
        {
            /// <summary>
            /// The IV used in base message
            /// </summary>
            public byte[] iv;

            /// <summary>
            /// The base session key
            /// </summary>
            public byte[] sessionKey;

            /// <summary>
            /// IV that is encrypted with base session key
            /// </summary>
            public byte[] subIv;

            /// <summary>
            /// Session key that can be decrypted using base session key and subIv
            /// </summary>
            public byte[] subSessionKey;

        }

        /// <summary>
        ///  Derives a decryption key by taking the session key and XORing every byte with 0xf0
        /// </summary>
        /// <param name="sessionKey"></param>
        /// <returns></returns>
        static byte[] DeriveXORSChannelDecryptionKey(byte[] sessionKey)
        {
            byte[] decryptionKey = new byte[sessionKey.Length];
            for (int i = 0; i < sessionKey.Length; i++)
            {
                decryptionKey[i] = (byte)(sessionKey[i] ^ 0xF0);
            }
            return decryptionKey;
        }

        /// <summary>
        /// Creates decryption key using session key, sequence number and package digest
        /// </summary>
        /// <param name="sessionKey"></param>
        /// <param name="sequenceNumber"></param>
        /// <param name="packageDigest"></param>
        /// <returns></returns>
        public static SChannelKeyData GetSChannelKeyData(string sessionKey, string sequenceNumber, string packageDigest)
        {
            SChannelKeyData kd = new SChannelKeyData();
            kd.sessionKey = Misc.HexStringToBytes(sessionKey);

            // iv is packagedigest concatenated to itself
            var tmpIv = $"{packageDigest}{packageDigest}";
            kd.iv = Misc.HexStringToBytes(tmpIv);

            // Decryp sequencenumber
            byte[] _key       = Misc.HexStringToBytes(sessionKey);
            byte[] ciphertext = Misc.HexStringToBytes(sequenceNumber);

            byte[] decryptedIv = AES.DecryptAES128CFB8(ciphertext, kd.sessionKey, kd.iv);
            var    halfIv      = BitConverter.ToString(decryptedIv).Replace("-", "");
            var    iv          = Misc.HexStringToBytes($"{halfIv}{halfIv}");

            //Derive a decryption key by taking the session key and XORing every byte with 0xf0
            byte[] _decryptionKey = DeriveXORSChannelDecryptionKey(_key);

            kd.subSessionKey = _decryptionKey;
            kd.subIv         = iv;

            return kd;
        }

        /// <summary>
        /// Returns dictionary with Kerberos keytypes and Kerberos keybytes
        /// </summary>
        /// <param name="data"></param>
        /// <param name="start"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public static Dictionary<int, string> KeyDataNewInfo(byte[] data, int start, int count)
        {
            Dictionary<int, string> keys = new Dictionary<int, string>();
            for (int k = 0; k < count; k++)
            {
                byte[] keyDataBytes = new byte[Marshal.SizeOf(typeof(KERB_KEY_DATA_NEW))];
                Array.Copy(data, (k * Marshal.SizeOf(typeof(KERB_KEY_DATA_NEW))) + start, keyDataBytes, 0, keyDataBytes.Length);
                KERB_KEY_DATA_NEW kkd = Misc.ReadStruct<KERB_KEY_DATA_NEW>(keyDataBytes);

                byte[] keybyte = new byte[kkd.KeyLength];
                Array.Copy(data, kkd.KeyOffset, keybyte, 0, keybyte.Length);

                // we skip the iteration count for now
                keys.Add(kkd.KeyType, Misc.PrintHashBytes(keybyte));

            }
            return keys;
        }

        /// <summary>
        /// Decrypts DES enrypted data with SID as key
        /// </summary>
        /// <param name="hashEncryptedWithRID"></param>
        /// <param name="sidByteForm"></param>
        /// <returns></returns>
        public static byte[] DecryptHashUsingSID(byte[] hashEncryptedWithRID, byte[] sidByteForm)
        {
            // extract the RID from the SID
            GCHandle handle = GCHandle.Alloc(sidByteForm, GCHandleType.Pinned);
            IntPtr sidIntPtr = handle.AddrOfPinnedObject();
            IntPtr SubAuthorityCountIntPtr = GetSidSubAuthorityCount(sidIntPtr);
            byte SubAuthorityCount = Marshal.ReadByte(SubAuthorityCountIntPtr);
            IntPtr SubAuthorityIntPtr = GetSidSubAuthority(sidIntPtr, (uint)SubAuthorityCount - 1);
            uint rid = (uint)Marshal.ReadInt32(SubAuthorityIntPtr);
            handle.Free();

            // Decrypt the hash
            byte[] output = new byte[16];
            IntPtr outputPtr = Marshal.AllocHGlobal(16);
            RtlDecryptDES2blocks1DWORD(hashEncryptedWithRID, ref rid, outputPtr);
            Marshal.Copy(outputPtr, output, 0, 16);
            Marshal.FreeHGlobal(outputPtr);
            return output;
        }

        /// <summary>
        /// Decrypts replication data using session key
        /// </summary>
        /// <param name="data"></param>
        /// <param name="SessionKey"></param>
        /// <returns></returns>
        public static byte[] DecryptReplicationData(byte[] data, byte[] SessionKey)
        {
            if (data.Length < 16)
                return null;

            byte[] key;

            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
            {
                md5.TransformBlock(SessionKey, 0, SessionKey.Length, SessionKey, 0);
                md5.TransformFinalBlock(data, 0, 16);

                key = md5.Hash;

            }


            byte[] todecrypt = new byte[data.Length - 16];
            Array.Copy(data, 16, todecrypt, 0, data.Length - 16);
            CRYPTO_BUFFER todecryptBuffer = GetCryptoBuffer(todecrypt);
            CRYPTO_BUFFER keyBuffer = GetCryptoBuffer(key);
            int ret = RtlEncryptDecryptRC4(ref todecryptBuffer, ref keyBuffer);
            byte[] decrypted = new byte[todecryptBuffer.Length];
            Marshal.Copy(todecryptBuffer.Buffer, decrypted, 0, decrypted.Length);
            Marshal.FreeHGlobal(todecryptBuffer.Buffer);
            Marshal.FreeHGlobal(keyBuffer.Buffer);
            byte[] output = new byte[decrypted.Length - 4];
            Array.Copy(decrypted, 4, output, 0, decrypted.Length - 4);
            uint crc = Misc.CalcCrc32(output);
            uint expectedCrc = BitConverter.ToUInt32(decrypted, 0);
            if (crc != expectedCrc)
                return null;

            return output;
        }

        private static CRYPTO_BUFFER GetCryptoBuffer(byte[] bytes)
        {
            CRYPTO_BUFFER cpb              = new CRYPTO_BUFFER();
            cpb.Length = cpb.MaximumLength = (uint)bytes.Length;
            cpb.Buffer = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, cpb.Buffer, bytes.Length);
            return cpb;
        }

    }
}
