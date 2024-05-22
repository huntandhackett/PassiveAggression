using PassiveAgression.Core.Network;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PassiveAgression.Core.Events
{
    public class SMBSessionSetup
    {

        public struct SMB_Session_Crypto
        {
            public byte[] Label;
            public byte[] Context;
            public byte[] ApplicationKey;
            public byte[] NtlmSSPKey;

        }

        public bool success { get; set; }

        public TCPConnectionInfo connectionInfo { get; set; }

        public string smbSessionId { get; set; }

        public string baseSessionKey { get; set; }
        public string sessionKey { get; set; }
        public string ntlmSspSessionKey { get; set; }
        public string account { get; set; }
        public string Preauth_Hash { get; set; }

        public SMB_Session_Crypto SMBCrypto { get; set; }

        public SMBSessionSetup(TSharkMessage message)
        {
            try
            {
                Parse(message);
                success = !string.IsNullOrEmpty(Preauth_Hash) && !string.IsNullOrEmpty(smbSessionId)
                                                              && !string.IsNullOrEmpty(ntlmSspSessionKey);
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
            connectionInfo = message.TCPInfo;
            smbSessionId   = message.FindNodeByName<string>("smb2.sesid");

            var _preauthHash = message.FindNodeByName<string>("smb2.preauth_hash");
            var _sessionKey  = message.FindNodeByName<string>("ntlmssp.auth.sesskey");

            if (string.IsNullOrEmpty(_preauthHash))
                return;

            if (string.IsNullOrEmpty(_sessionKey))
                return;

            Preauth_Hash = Misc.CleanHexData(_preauthHash);
            sessionKey   = Misc.CleanHexData(_sessionKey);
            account      = message.FindNodeByName<string>("ntlmssp.auth.username");

            var keyLines =
                message.FindNodesByName<string>("_ws.expert.message"); 


            if (keyLines != null)
            {
                // Extract keylines
                foreach (var keyLine in keyLines)
                {
                    var _kline = keyLine.ToString();
                    if (_kline.Contains("NTLMSSP SessionKey"))
                    {
                        // Extract NTLMSSP sessionKey
                        ntlmSspSessionKey = ExtractKeyFromKeyLine(_kline);
                    }

                    if (_kline.Contains("BaseSessionKey"))
                    {
                        // Extract basesessionkey
                        baseSessionKey = ExtractKeyFromKeyLine(_kline);
                    }

                }

                if (string.IsNullOrEmpty(ntlmSspSessionKey))
                    return;

                SMB_Session_Crypto Crypto = new SMB_Session_Crypto();
                
                // Precaulcate crypto values.
                // We assume that if the preauth hash is present, dialect == 3.1.1
                // https://github.com/fortra/impacket/blob/master/impacket/smb3.py#L863
                byte[] context, label;
                context = Encoding.UTF8.GetBytes("SmbRpc\x00");
                label   = Encoding.UTF8.GetBytes("SMB2APP\x00");
                if (!string.IsNullOrEmpty(Preauth_Hash))
                {
                    label   = Encoding.UTF8.GetBytes("SMBAppKey\x00");
                    context = Misc.HexStringToBytes(Preauth_Hash);
                }

                Crypto.Context    = context;
                Crypto.Label      = label;
                Crypto.NtlmSSPKey = Misc.HexStringToBytes(ntlmSspSessionKey);
                Crypto.ApplicationKey = Core.Crypto.Signing.ComputeHMACSha256KDFCounterMode(Crypto.NtlmSSPKey,
                    Crypto.Label,
                    Crypto.Context, 128);
                SMBCrypto = Crypto;
            }



        }

        /// <summary>
        /// Extracts sessionkey from a keyline, such as: NTLMv2 BaseSessionKey (xxxxxxxxx)
        /// </summary>
        /// <param name="keyLine"></param>
        /// <returns></returns>
        private static string ExtractKeyFromKeyLine(string keyLine)
        {
            var result = "";
            try
            {
                result = keyLine.Split('(')[1].TrimEnd(')');
            }
            catch (Exception e)
            {
                result = "";
            }

            return result;
        }

    }

}
