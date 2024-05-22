using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PassiveAgression.Core.Network;


namespace PassiveAgression.Core
{
    public class TShark
    {

        private readonly string _TSharkLocation;
        private readonly string _TSharkParameters;

        /// <summary>
        /// Contains the source message. Can be turned on for debugging
        /// </summary>
        private string src_message;

        /// <summary>
        /// Use UTF8 encoding when deserializing tshark messages
        /// </summary>
        private Encoding encoding = Encoding.UTF8;

        /// <summary>
        /// Function to invoke after deserialization
        /// </summary>
        private Action<TSharkMessage> callbackAction;

        /// <summary>
        /// Creates a Tshark instance
        /// </summary>
        /// <param name="TSharkLocation"></param>
        /// <param name="TSharkParameters"></param>
        public TShark(string TSharkLocation, string TSharkParameters) 
        {
            if (string.IsNullOrEmpty(TSharkLocation))
                throw new ArgumentNullException("TSharkLocation is empty");

            if (string.IsNullOrEmpty(TSharkParameters))
                throw new ArgumentNullException("TSharkParameters is empty");

            if (!File.Exists(TSharkLocation))
                throw new ArgumentException($"Location does not exist: {TSharkLocation}");

            // Check if MessageType has baseclass of TSharMessage

            this._TSharkLocation   = TSharkLocation;
            this._TSharkParameters = TSharkParameters;

        }
        


        /// <summary>
        /// Runs Tshark from the specified location with given parameters
        /// Every message is deserialized into a TSharkMessage object and returned to the specified delegate
        /// </summary>
        internal void Run(Action<TSharkMessage> callbackAction)
        {
            this.callbackAction = callbackAction;

            ProcessStartInfo startInfo = new ProcessStartInfo(_TSharkLocation, _TSharkParameters)
            {
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                UseShellExecute        = false
            };

            Process? tshark = Process.Start(startInfo);

            int           lineCount = 0;
            int           msgCount  = 0;
            StreamReader  reader    = tshark!.StandardOutput;
            StringBuilder sb        = new StringBuilder();

            while (true)
            {
                string line = reader.ReadLine();

                if (!string.IsNullOrEmpty(line) && line.Contains("\"_index\""))
                {
                    msgCount++;
                    if (msgCount >= 1)
                    {

                        //string trimmed = TrimJsonMessage(sb.ToString());
                        var trimmed = TrimJsonMessage(sb.ToString());
                        ProcessTsharkMessage(trimmed);
                        sb.Clear();
                        msgCount = 0;

                        sb.AppendLine("{");
                    }
                }

                if (line == null)
                {
                    //string trimmed = TrimJsonMessage(sb.ToString());
                    var trimmed = TrimJsonMessage(sb.ToString());

                    ProcessTsharkMessage(trimmed);
                    sb.Clear();
                    break;
                }

                //writer.WriteLine(line);
                sb.AppendLine(line);
                lineCount++;
            }

            while (true)
            {
                tshark.Refresh();
                if (tshark.HasExited || tshark.WaitForExit(500))
                {
                    break;
                }
            }
        }


        /// <summary>
        /// Trims specific json line characters from string
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        private string TrimJsonMessage(string message)
        {
            var trimmed = message.Trim();
            trimmed = trimmed.TrimStart(' ', '[', '\r', '\n');
            trimmed = trimmed.TrimEnd(' ', ',', '\r', '\n', '{');
            trimmed = trimmed.TrimEnd(']').TrimEnd('\r').TrimEnd('\n');

            return trimmed;
        }


        /// <summary>
        /// Deserializes the TShark message and invokes callbackfunction
        /// </summary>
        /// <param name="message"></param>
        private void ProcessTsharkMessage(string message)
        {

            if (string.IsNullOrEmpty(message))
                return;

            TSharkMessage tMessage = new TSharkMessage(message);

            callbackAction(tMessage);

        }
    }
}
