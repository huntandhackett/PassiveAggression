using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PassiveAgression.Core.Network;
using PassiveAgression.Core.Win32;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace PassiveAgression.Core.Events
{
    public class SamrSetInformationUser2
    {
        public bool success { get; set; }

        public TCPConnectionInfo connectionInfo  { get; set; }

        public string smbSessionId { get; set; }

        public string ClearTextPassword { get; set; }

        Natives.SAMPR_ENCRYPTED_USER_PASSWORD_NEW cryptedData { get; set; }

        public string Username { get; set; }

        public SamrSetInformationUser2(TSharkMessage message)
        {
            try
            {
                Parse(message);
                success = true;
            }
            catch
            {
                // Do nothing
            }

        }

        /// <summary>
        /// Parses data from message into structs. 
        /// </summary>
        /// <param name="message"></param>
        private void Parse(TSharkMessage message)
        {
            //// Set data to be correlated with in later packets
            connectionInfo = message.TCPInfo;
            smbSessionId   = message.FindNodeByName<string>("smb2.sesid");

            // Fetch crypted data
            string strBytes      = message.FindNodeByName<string>("samr.samr_UserInfo.info25_raw");
            byte[] pwdResetBytes = Misc.HexStringToBytes(strBytes);

            byte[] passwordBuffer = pwdResetBytes[^532..pwdResetBytes.Length];
            cryptedData = Misc.ReadStruct<Natives.SAMPR_ENCRYPTED_USER_PASSWORD_NEW>(passwordBuffer);
        }

        /// <summary>
        /// Decrypts encrypted data with keys negotiated in SMBSession
        /// </summary>
        /// <param name="SMBSessionInfo"></param>
        /// <returns>cleartext string</returns>
        public string Decrypt(SMBSessionSetup SMBSessionInfo)
        {
            string result = string.Empty;

            int    pwdLength, clearTxtPwdStart, clearTxtPwdEnd;

            byte[] digestData    = Misc.MergeBlocks(cryptedData.ClearSalt, SMBSessionInfo.SMBCrypto.ApplicationKey);
            byte[] decryptionKey = Crypto.Signing.ComputeMD5Hash(digestData);

            byte[] decrypted = Crypto.RC4.TransformData(cryptedData.crypted, decryptionKey);

            // Last 4 bytes indicate lenth of string
            byte[] bPwdLength = decrypted[^4..decrypted.Length];
            pwdLength = BitConverter.ToInt32(bPwdLength, 0);

            if (pwdLength < 0 && pwdLength > 255)
            {
                // Could not decrypt value
                return string.Empty;
            }

            byte[] clearTextPwd = new byte[pwdLength];

            clearTxtPwdStart = decrypted.Length - (4 + pwdLength);
            clearTxtPwdEnd   = decrypted.Length - 4;
            clearTextPwd     = decrypted[clearTxtPwdStart..clearTxtPwdEnd];

            ClearTextPassword = UnicodeEncoding.Unicode.GetString(clearTextPwd);

            return ClearTextPassword;
        }

    }
}
