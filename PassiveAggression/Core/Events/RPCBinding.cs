using PassiveAgression.Core.Network;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PassiveAgression.Core.Static;

namespace PassiveAgression.Core.Events
{
    public class RPCBinding
    {

        public bool success { get; set; }
        public TCPConnectionInfo connectionInfo { get; set; }

        public string[] sessionKey;

        public int kerberosKeyType;

        public bool IsAck;

        public RPCBinding(TSharkMessage message)
        {
            try
            {
                Parse(message);
                success = sessionKey.Length > 0;
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

            var kerbKeys = message.FindNodesByName<string>("kerberos.keyvalue"); //message["_source"]["layers"]["kerberos.keyvalue"];

            // Return empty message when no keys are found
            if (kerbKeys == null)
                return;

            // It is possible that multiple keys are in the message.
            // This may result in duplicate keys, but we ignore that for now.
            sessionKey = new string[kerbKeys.Length];
            for (int i = 0; i < kerbKeys.Length; i++)
            {
                // Make sure to remove delimiters
                sessionKey[i] = Misc.CleanHexData(kerbKeys[i]);
            }

            IsAck           = message.DCERPC_PacketType == Enums.PKT_DCERPC.BINDACK;
            kerberosKeyType = message.FindNodeByName<int>("kerberos.keytype");


        }
    }
}
