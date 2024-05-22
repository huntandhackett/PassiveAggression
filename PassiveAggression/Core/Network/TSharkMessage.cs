using Newtonsoft.Json.Linq;
using PassiveAgression.Core.Static;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.Serialization;
using static PassiveAgression.Core.Static.Enums;
using static PassiveAgression.Core.Win32.Natives;

namespace PassiveAgression.Core.Network
{

    public struct TCPConnectionInfo
    {
        public string SourceIP;
        public string DestinationIP;
        public int SourcePort;
        public int DestinationPort;
        public int StreamIndex;
    }

    public class TSharkMessage
    {

        /// <summary>
        /// Cache descendants to prevent re-requesting the same items
        /// </summary>
        private IEnumerable<JToken> DescendantsAndSelf;

        private JObject _tsharkMessage;

        private string rawJson;

        #region Generic TCPFields
        public int StreamIndex
        {
            get
            {
                return FindNodeByName<int>("tcp.stream");
            }
        }

        public string SourceIP
        {
            get
            {
                return FindNodeByName<string>("ip.src");
            }
        }

        public string DestinationIP
        {
            get
            {
                return FindNodeByName<string>("ip.dst");
            }
        }

        public int SourcePort
        {
            get
            {
                return FindNodeByName<int>("tcp.srcport");
            }
        }

        public int DestinationPort
        {
            get
            {
                return FindNodeByName<int>("tcp.dstport");
            }
        }

        public TCPConnectionInfo TCPInfo
        {
            get
            {
                return new TCPConnectionInfo
                {
                    DestinationIP = DestinationIP,
                    DestinationPort = DestinationPort,
                    SourceIP = SourceIP,
                    SourcePort = SourcePort,
                    StreamIndex = StreamIndex,
                };
            }
        }

        #endregion

        #region SAMR

        public Enums.OP_SAMR SAMR_Opnum
        {
            get
            {
                return (Enums.OP_SAMR)FindNodeByName<int>("samr.opnum");
            }
        }

        #endregion

        #region DCERPC

        public Enums.OP_DCERPC DCERPC_Opnum
        {
            get
            {
                return (Enums.OP_DCERPC)FindNodeByName<int>("dcerpc.opnum");
            }
        }

        public Enums.PKT_DCERPC DCERPC_PacketType
        {
            get
            {
                return (Enums.PKT_DCERPC)FindNodeByName<int>("dcerpc.pkt_type");
            }
        }

        #endregion

        #region NETLOGON

        public Enums.OP_NETLOGON NETLOGON_Opnum
        {
            get
            {
                return (Enums.OP_NETLOGON)FindNodeByName<int>("netlogon.opnum");
            }
        }


        #endregion

        #region SMB

        public Enums.SMB_CMD SMB_CMD
        {
            get
            {
                return (Enums.SMB_CMD)FindNodeByName<int>("smb2.cmd");
            }
        }

        public SMB2_FLAGS SMB2Flags
        {
            get
            {
                uint flag = uint.MinValue;

                string smbflag = FindNodeByName<string>("smb2.flags");
                if (!string.IsNullOrEmpty(smbflag))
                    flag = Convert.ToUInt32(smbflag, 16);

                SMB2_FLAGS smbflags = (SMB2_FLAGS)flag;
                return smbflags;
            }
        }

        /// <summary>
        /// True if message is an SMB request
        /// </summary>
        public bool SMBRequest
        {
            get
            {
                return !SMB2Flags.HasFlag(SMB2_FLAGS.SMB2_FLAGS_SERVER_TO_REDIR);
            }
        }

        /// <summary>
        /// True is message is an SMB response
        /// </summary>
        public bool SMBResponse
        {
            get
            {
                return SMB2Flags.HasFlag(SMB2_FLAGS.SMB2_FLAGS_SERVER_TO_REDIR);
            }
        }

        #endregion

        public TSharkMessage(string message)
        {
            _tsharkMessage = JObject.Parse(message);
            rawJson = message;
        }

        /// <summary>
        /// Finds node in JObject and returns the value of type T
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="nodeName"></param>
        /// <returns></returns>
        public T FindNodeByName<T>(string nodeName)
        {
            if (null == DescendantsAndSelf)
                DescendantsAndSelf = _tsharkMessage.DescendantsAndSelf();

            foreach (var token in DescendantsAndSelf)
            {
                if (token is JProperty property && property.Name == nodeName)
                {
                    JToken jVal;
                    bool isJArray = property.Type == JTokenType.Array;
                    int numItem = property.Value.Count();

                    if (!isJArray && numItem < 2)
                    {
                        jVal = property.Value;
                        if (jVal.Type == JTokenType.Array)
                            jVal = jVal.First();
                    }
                    else
                    {
                        jVal = property.Value[0];
                    }

                    return GetValue<T>(jVal);
                }
            }

            // Make sure to return int.MinValue, since 0 will refer
            // to items in element of flags
            if (typeof(T) == typeof(int))
            {
                return (T)(object)(int.MinValue);
            }

            if (typeof(T) == typeof(uint))
            {
                return (T)(object)(uint.MinValue);
            }

            return default(T);
        }

        /// <summary>
        /// Finds nodes in JObject and returns array with values of type T
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="nodeName"></param>
        /// <returns></returns>
        public T[] FindNodesByName<T>(string nodeName)
        {
            if (null == DescendantsAndSelf)
                DescendantsAndSelf = _tsharkMessage.DescendantsAndSelf();

            foreach (var token in DescendantsAndSelf)
            {
                if (token is JProperty property && property.Name == nodeName)
                {
                    int items = property.Value.Count() > 1 ? property.Value.Count() : 1;
                    // return array
                    T[] retArray = new T[items];
                    for (int i = 0; i < items; i++)
                    {
                        JToken jVal = items > 1 ? property.Value[i] : property.Value;
                        retArray[i] = GetValue<T>(jVal);
                    }
                    return retArray;
                }

            }
            return default(T[]);
        }

        /// <summary>
        /// Checks if message contains a specific node
        /// </summary>
        /// <returns></returns>
        public bool ContainsNode(string nodeName)
        {
            if (null == DescendantsAndSelf)
                DescendantsAndSelf = _tsharkMessage.DescendantsAndSelf();

            foreach (var token in DescendantsAndSelf)
            {
                if (token is JProperty property && property.Name == nodeName)
                {
                    return true;
                }
            }

            return false;
        }


        private T GetValue<T>(JToken token)
        {
            if (token is JValue jValue)
            {
                try
                {
                    return (T)Convert.ChangeType(jValue.Value, typeof(T));
                }
                catch (InvalidCastException)
                {
                    return default(T);
                }
            }
            return default(T);
        }
    }


}
