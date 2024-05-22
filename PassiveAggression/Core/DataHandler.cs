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

        #region adding methods

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
    }
}
