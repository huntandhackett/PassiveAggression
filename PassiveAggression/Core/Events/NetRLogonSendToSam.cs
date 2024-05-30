using PassiveAgression.Core.Network;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PassiveAgression.Core.Crypto;
using static PassiveAgression.Core.Win32.Natives;
using System.Runtime.InteropServices;

namespace PassiveAgression.Core.Events
{
    public class NetRLogonSendToSam
    {

        public bool success { get; set; }

        private string encrypted_stub_data;
        private string package_digest;
        private string package_sequence;


        public string NTLMHash { get; private set; }
        public string LMHash { get; private set; }
        public string UserRef { get; private set; }
        public int rID { get; private set; }
        public TCPConnectionInfo connectionInfo { get; set; }

        public string sessionKey;

        private struct CredentialData
        {
            public int offset;
            public int length;
        }

        struct NetrLogonSendToSam
        {
            public string PrimaryName;
            public string ComputerName;
            public NETLOGON_AUTHENTICATOR Authenticator;

            public PASSWORD_UPDATE_TYPE PwdUpdType;
            public int Size;

            internal byte[] CryptedOpaqueBuffer;
            public int OpaqueBufferSize;

            public int IndexHelper;
        }

        /// <summary>
        /// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sams/e6d9295f-dbb8-46a5-98f7-f4d3f970f36b
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct NetrLogonSendToSamOpaqueBuffer
        {
            PASSWORD_UPDATE_FLAGS Flags;
            public int MessageSize;
            public int AccountRid;
            public byte PasswordExp;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] reserved;
        }

        public NetRLogonSendToSam(TSharkMessage message)
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

            package_sequence    = Misc.CleanHexData(message.FindNodeByName<string>("netlogon.secchan.seq"));
            package_digest      = Misc.CleanHexData(message.FindNodeByName<string>("netlogon.secchan.digest"));
            encrypted_stub_data = Misc.CleanHexData(message.FindNodeByName<string>("dcerpc.encrypted_stub_data"));
        }

        /// <summary>
        /// Decrypts data with given session key
        /// </summary>
        /// <param name="sessionKey"></param>
        public void Decrypt(string sessionKey)
        {
            this.sessionKey = sessionKey;
            success         = false;
            try
            {
                DecryptData();
                success = true;
            }
            catch
            {
                // Do nothing
            }
        }

        private void DecryptData()
        {
            success = false;

            byte[] bCipherText = Misc.HexStringToBytes(encrypted_stub_data);

            // Generate the correct keydata based on sequence number and digest
            var keyData = Crypto.Utils.GetSChannelKeyData(sessionKey, package_sequence, package_digest);

            // Decrypt data using new keyset
            byte[] decrypted = AES.DecryptAES128CFB8(bCipherText, keyData.subSessionKey, keyData.subIv);

            // Dissect the packet
            NetrLogonSendToSam packet = Dissect(ref decrypted);

            // Decrypt buffer. We do this by decrypting the whole packet with the base session key
            // and get the contents based on the size in the last field of the outer message
            // The message size and message type are not double encrypted. Prepend the bytearray with these 8 bytes so
            // we end up with a byte array containing only decrypted values
            byte[] subPackdecrypted = AES.DecryptAES128CFB8(decrypted, keyData.sessionKey, keyData.iv);

            //Misc.DisplayHexDump(subPackdecrypted);
            int packetLength         = subPackdecrypted.Length;
            int decryptedBufferStart = packet.IndexHelper   + 8;
            int decryptedBufferEnd   = decryptedBufferStart + packet.OpaqueBufferSize;

            byte[] oBuffer = subPackdecrypted[decryptedBufferStart..decryptedBufferEnd];

            NetrLogonSendToSamOpaqueBuffer t = DissectBuffer(ref oBuffer);
        }

        /// <summary>
        /// Dissect byte array into NetrLogonSendToSam packet
        /// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/b06e6b30-fe57-4e0f-ba1a-5214c953a5df
        /// </summary>
        /// <param name="packet"></param>
        /// <returns></returns>
        private NetrLogonSendToSam Dissect(ref byte[] packet)
        {
            NetrLogonSendToSam rawSendToSamPacket = new NetrLogonSendToSam();

            // Check if byte 17..24 are 00bytes
            int startIndex = 0;
            if (Misc.AllItemsAreSame(packet[16..24]))
            {
                startIndex = 32;
            }
            byte[] dData = packet[startIndex..packet.Length];

            // If the last 8 bytes are 0bytes, trim those
            if (Misc.AllItemsAreSame(packet[(packet.Length - 8)..packet.Length]))
            {
                dData = dData[0..(dData.Length - 8)];
            }

            // Read handle name. Calculate alignment
            rawSendToSamPacket.PrimaryName = Misc.ReadWChars(ref dData);
            startIndex = rawSendToSamPacket.PrimaryName.Length * 2;
            startIndex += 8 - (startIndex % 8);

            // Next are 24 bytes of undefined data
            startIndex += 24;

            // Next is the netbiosname of the calling computer
            dData = dData[startIndex..dData.Length];
            rawSendToSamPacket.ComputerName = Misc.ReadWChars(ref dData);


            // Align data
            startIndex = rawSendToSamPacket.ComputerName.Length * 2;
            startIndex += 8 - (startIndex % 8);

            // Parse authenticator
            dData = dData[startIndex..dData.Length];
            rawSendToSamPacket.Authenticator = Misc.ReadStruct<NETLOGON_AUTHENTICATOR>(dData);
            startIndex = Marshal.SizeOf(rawSendToSamPacket.Authenticator);

            rawSendToSamPacket.PwdUpdType = (PASSWORD_UPDATE_TYPE)BitConverter.ToUInt32(dData[startIndex..(startIndex + 4)]);
            startIndex += 4;

            // Read msg size
            rawSendToSamPacket.Size = BitConverter.ToInt32(dData, startIndex);

            // startIndex should be at the startindex of where the opaque buffer starts.
            // We also know the size of the buffer
            int bufferStart = startIndex + 8;
            int bufferEnd = bufferStart + rawSendToSamPacket.Size;

            rawSendToSamPacket.CryptedOpaqueBuffer = dData[bufferStart..bufferEnd];
            rawSendToSamPacket.IndexHelper = Misc.FindSequence(packet, rawSendToSamPacket.CryptedOpaqueBuffer);

            // next 4 bytes should be the opaquebuffer size
            startIndex = bufferEnd;
            rawSendToSamPacket.OpaqueBufferSize = BitConverter.ToInt32(dData, startIndex);


            return rawSendToSamPacket;
        }


        /// <summary>
        /// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sams/e6d9295f-dbb8-46a5-98f7-f4d3f970f36b
        /// </summary>
        /// <param name="decryptedBuffer"></param>
        /// <returns></returns>
        private NetrLogonSendToSamOpaqueBuffer DissectBuffer(ref byte[] decryptedBuffer)
        {
            NetrLogonSendToSamOpaqueBuffer buffer = new NetrLogonSendToSamOpaqueBuffer();
            buffer = Misc.ReadStruct<NetrLogonSendToSamOpaqueBuffer>(decryptedBuffer);
            rID = buffer.AccountRid;

            int dataStart = buffer.MessageSize;
            int startIndex = Marshal.SizeOf(buffer);
            byte[] headerData = decryptedBuffer[startIndex..dataStart];

            int arrayCount = headerData.Length / 8;
            CredentialData[] credData = new CredentialData[arrayCount];

            startIndex = 0;
            for (int i = 0; i < arrayCount; i++)
            {
                CredentialData cred = new CredentialData();
                cred.offset = BitConverter.ToInt32(headerData, startIndex);
                cred.length = BitConverter.ToInt32(headerData, startIndex + 4);

                credData[i] = cred;

                startIndex += 8;
            }

            // Filter out credentialdata with lengths
            CredentialData[] credWithData = credData.Where(c => c.length > 0).ToArray();

            // Data is positioned in this order:
            // Name
            // NTLM
            // LM

            if (credWithData.Length > 2)
            {
                byte[] LMhash = GetArrayData(credWithData[1], dataStart, ref decryptedBuffer);
                byte[] NTHash = GetArrayData(credWithData[2], dataStart, ref decryptedBuffer);
                byte[] Name = GetArrayData(credWithData[0], dataStart, ref decryptedBuffer);

                this.LMHash = Misc.PrintHashBytes(LMhash);
                this.NTLMHash = Misc.PrintHashBytes(NTHash);
                this.UserRef = Encoding.UTF8.GetString(Name);
            }
            else
            {
                byte[] LMhash = GetArrayData(credWithData[1], dataStart, ref decryptedBuffer);
                byte[] NTHash = GetArrayData(credWithData[2], dataStart, ref decryptedBuffer);

                this.LMHash   = Misc.PrintHashBytes(LMhash);
                this.NTLMHash = Misc.PrintHashBytes(NTHash);
            }

            return buffer;
        }


        /// <summary>
        /// Returns arraydata based on index and offsets
        /// </summary>
        /// <param name="d"></param>
        /// <param name="dataStart"></param>
        /// <param name="decryptedData"></param>
        /// <returns></returns>
        private byte[] GetArrayData(CredentialData d, int dataStart, ref byte[] decryptedData)
        {
            int offset = d.offset;
            int len    = d.length;

            return decryptedData[(dataStart + offset)..(dataStart + offset + len)];
        }
    }
    
}
