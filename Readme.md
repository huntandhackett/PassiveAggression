
# Passive Aggression
This repo contains test samples and proof-of-concept code for achieving passive persistence in Active Directory (AD) environments, even after remediation efforts. Some of these techniques may result in an eternal persistence scenario, where an attacker does not need to have access to domain controllers or domain joined machines, allowing them to continuously persist in the network without detection. 

More PoCs and samples will be added in the coming weeks.

## How to use
- Add reference to `.\NtApiDotNet\NtApiDotNet.dll`
- Specify `pcapng` and `keytab` in `main.cs`
- Compile and profit

Read our blog series for more information: https://www.huntandhackett.com/blog/how-to-achieve-eternal-persistence


# Legal disclaimer
Please make sure that you use __PassiveAggression__ in a responsible manner: assess whether there are any characteristics of the environment, or applicable (internal or external) laws, rules or regulations, that prevent you from using __PassiveAggression__.  
You remain solely responsible for any damage or consequences that might occur as a result of, or related to the use of __PassiveAggression__ or any of the information as included in this blogpost.  