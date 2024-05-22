using PassiveAgression.Core.Network;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PassiveAgression.Core.Events
{
    public class LookupNamesRequest
    {

        public bool success { get; set; }

        public TCPConnectionInfo connectionInfo { get; set; }

        public string smbSessionId { get; set; }

        public string Username { get; set; }

        public LookupNamesRequest(TSharkMessage message)
        {
            try
            {
                Parse(message);
                success = !string.IsNullOrEmpty(Username) && !string.IsNullOrEmpty(smbSessionId);
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

            Username = message.FindNodeByName<string>("samr.samr_LookupNames.names");

        }


    }
}
