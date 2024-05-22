using System.Diagnostics;
using PassiveAgression.Core;
using PassiveAgression.Core.Events;
using PassiveAgression.Core.Network;
using static PassiveAgression.Core.Win32.Natives;
using PassiveAgression.Core.Static;

namespace PassiveAgression
{
    internal class Program
    {
        #region Properties

        /// <summary>
        /// Location to pcap containing network info
        /// </summary>
        private static string pcapLocation { get; set; }

        /// <summary>
        /// Location to keytab containing credentials
        /// </summary>
        private static string keytabLocation { get; set; }

        /// <summary>
        /// Location to Tshark
        /// </summary>
        private static string tsharkLocation = @"C:\Program Files\Wireshark\tshark.exe";

        private static DataHandler dataHandler;

        #endregion

        static async Task Main(string[] args)
        {

            dataHandler = new DataHandler();
            Task handlerStart = dataHandler.Start();

            keytabLocation = @"C:\Code\PassiveAggression\PassiveAggression\TestData\Pwdreset\pwdreset.keytab";
            pcapLocation   = @"C:\Code\PassiveAggression\PassiveAggression\TestData\Pwdreset\pwdreset.pcapng";

            
            var tsharkArguments = GetTsharkArguments();


            TShark tshark = new TShark(tsharkLocation, tsharkArguments);
            tshark.Run(ProcessEvent);

            // Let the handler know all data in the pcap has been processed
            dataHandler.Stop();

            await handlerStart;
            
        }

        /// <summary>
        /// Composes the cmdline argument for tshark that does the following:
        /// - filter out packets not needed
        /// - extract raw data for needed protocols
        /// - read data from pcap
        /// - decrypt kerberos data using keytab file
        /// - double pass, so fragmented packets can be reassembled
        /// - sets output type to json
        /// </summary>
        /// <returns></returns>
        private static string GetTsharkArguments()
        {
            // Tshark filters

            string RPC_SESSIONKEY_NEG            = $"(netlogon.opnum == {(int)Enums.OP_NETLOGON.NetrServerAuthenticate3} && dcerpc.pkt_type == {(int)Enums.PKT_DCERPC.RESPONSE})";
            string KRB_KPASSWD                   = "(kpasswd)";
            string SMB_SESSION_SETUP_REQUEST     = $"(smb2.cmd == {(int)Enums.SMB_CMD.SESSION_SETUP})";
            string SMB_SESSION_SETUP_RESPONSE    = $"(smb2.cmd == {(int)Enums.SMB_CMD.NEGOTIATE})";
            string SAMR_SETUSERINFO2             = $"(samr.opnum == {(int)Enums.OP_SAMR.SamrSetInformationUser2} || samr.opnum == {(int)Enums.OP_SAMR.SamrLookupNamesInDomain})";
            string RPC_BINDS                     = $"(dcerpc.pkt_type == {(int)Enums.PKT_DCERPC.BIND} || dcerpc.pkt_type == {(int)Enums.PKT_DCERPC.BINDACK})";
            string RPC_REPLICATION               = $"(dcerpc.pkt_type == {(int)Enums.PKT_DCERPC.RESPONSE} && dcerpc.opnum == {(int)Enums.OP_DCERPC.DRSGetNCChanges})";
            string RPC_NETRLOGONSENDTOSAM        = $"(netlogon.opnum == {(int)Enums.OP_NETLOGON.NetrLogonSendToSam} && dcerpc.pkt_type == {(int)Enums.PKT_DCERPC.REQUEST})";

            // compose a filter to filter out all the noise
            string filter = string.Join(" || ", SMB_SESSION_SETUP_REQUEST, SMB_SESSION_SETUP_RESPONSE,
                                                SAMR_SETUSERINFO2,
                                                RPC_SESSIONKEY_NEG,
                                                RPC_NETRLOGONSENDTOSAM,
                                                KRB_KPASSWD,
                                                RPC_BINDS,
                                                RPC_REPLICATION);

            // These protocols must be extracted raw.
            // Most of these can be extracted using field filters, but some of them are not returned correctly
            // and must be fetched using this approach
            string[] rawProtocolsToExtract = new string[]
            {
                "ip",
                "tcp",
                "rpc_netlogon",
                "smb2",
                "smb",
                "samr",
                "rpc",
                "dcerpc",
                "kerberos",
                "drsuapi"
            };
            var rawProtocolArg = string.Join(" ", rawProtocolsToExtract);

            // Output should be in json format
            var outputType = "json";

            var arguments = $"-2 -r \"{pcapLocation}\" -K \"{keytabLocation}\" -Y \"{filter}\"  -T {outputType} -J " +
                            $"\"{rawProtocolArg}\" -x";

            return arguments ;

        }

        /// <summary>
        /// This function is invoked after deserialization.
        /// In this function, we parse data and handle all the logic
        /// </summary>
        /// <param name="msg"></param>
        public static void ProcessEvent(TSharkMessage msg)
        {

            // Process password reset events
            if (msg.SAMR_Opnum        == Enums.OP_SAMR.SamrSetInformationUser2 &&
                msg.DCERPC_PacketType == Enums.PKT_DCERPC.REQUEST)
            {
                SamrSetInformationUser2 pwdset = new SamrSetInformationUser2(msg);
                dataHandler.AddSetInformationUser2(pwdset);
            }

            // Process SMB Session negotiation
            if (msg.SMBRequest && msg.SMB_CMD == Enums.SMB_CMD.SESSION_SETUP)
            {
                SMBSessionSetup setup = new SMBSessionSetup(msg);
                dataHandler.AddSMBSessionSetup(setup);
            }

            // Process LookupNames request
            if (msg.SAMR_Opnum == Enums.OP_SAMR.SamrLookupNamesInDomain)
            {
                LookupNamesRequest req = new LookupNamesRequest(msg);
                dataHandler.AddLookupNamesRequest(req);
            }
        }
    }
}