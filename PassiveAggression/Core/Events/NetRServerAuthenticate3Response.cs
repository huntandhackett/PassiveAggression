using PassiveAgression.Core.Network;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PassiveAgression.Core.Events
{
    public class NetRServerAuthenticate3Response
    {

        public bool success { get; set; }

        public TCPConnectionInfo connectionInfo { get; set; }

        public string sessionKey;

        public NetRServerAuthenticate3Response(TSharkMessage message)
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

            var keyLine = message.FindNodeByName<string>("_ws.expert.message");
            if (null != keyLine)
            {
                //return empty resultobj if no session key is available
                if (!keyLine.Contains("session key"))
                    return;

                sessionKey = keyLine.Split('(')[1].TrimEnd(')');

            }
        }
    }
}
