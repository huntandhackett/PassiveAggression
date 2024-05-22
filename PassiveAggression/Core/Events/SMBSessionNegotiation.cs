using PassiveAgression.Core.Network;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PassiveAgression.Core.Static;
using static PassiveAgression.Core.Static.Enums;

namespace PassiveAgression.Core.Events
{
    public class SMBSessionNegotiation
    {

        public bool success { get; set; }

        public TCPConnectionInfo connectionInfo { get; set; }

        public SMB_Dialect SMB_Dialect;

        public SMBSessionNegotiation(TSharkMessage message)
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

            if (!message.SMBResponse)
                return;

            string SmbDialect = message.FindNodeByName<string>("smb2.dialect");
            int    dialectNbr = Convert.ToInt32(SmbDialect, 16);
            SMB_Dialect = (Enums.SMB_Dialect)dialectNbr;

        }

    }
}
