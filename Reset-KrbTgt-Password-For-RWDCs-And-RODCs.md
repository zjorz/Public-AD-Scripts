# SCRIPT: Reset-KrbTgt-Password-For-RWDCs-And-RODCs

## NOTIFICATION 2025-01-23

It is OK to use the current published version of the script (v3.4, 2023-03-04).

However, I have updated the script with new enhancements, improvements and features.

The new version will be v3.6 (v3.5 was never published). The updated script is currently being tested.

It will be published in the very near future! Stay tuned!

## AUTHOR/FEEDBACK

* Written By: Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]
* Re-Written By: N.A.
* Company: IAMTEC &gt;&gt; Identity | Security | Recovery [https://www.iamtec.eu/]
* Blog: Jorge's Quest For Knowledge [http://jorgequestforknowledge.wordpress.com/]
* For Feedback/Questions: scripts DOT gallery AT iamtec.eu
  * Please Describe Your Scenario As Best As Possible With As Much Detail As Possible.
  * If Applicable Describe What Does and/Or Does Not Work.
  * If Applicable Describe What Should Be/Work Different And Explain Why/How.
  * Please Add Screendumps.

## ORIGINAL SOURCE(S)

* Script:  <https://github.com/zjorz/Public-AD-Scripts/blob/master/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1>
* XML File: <https://github.com/zjorz/Public-AD-Scripts/blob/master/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml>

## DISCLAIMER

* The script is FREEWARE, you are free to distribute/update it, but always refer to the original source(s) as the location where you got it
* This script is furnished "AS IS". NO warranty is expressed or implied!
* I HAVE NOT tested it in every scenario or environment
* ALWAYS TEST FIRST in lab environment to see if it meets your needs!
* Use this script at YOUR OWN RISK! YOU ARE RESPONSIBLE FOR ANY OUTCOME/RESULT BY USING THIS SCRIPT!
* I DO NOT warrant this script to be fit for any purpose, use or environment!
* I have tried to check everything that needed to be checked, but I DO NOT guarantee the script does not have bugs!
* I DO NOT guarantee the script will not damage or destroy your system(s), environment or anything else due to improper use or bugs!
* I DO NOT accept liability in any way when making mistakes, use the script wrong or in any other way where damage is caused to your environment/systems!
* If you do not accept these terms DO NOT use the script in any way and delete it immediately!

## KNOWN ISSUES/BUGS

* When targeting a remote AD forest for which no trust exist with the AD forest the running account belongs to, the public profile of WinRM may be used. In that case the PSSession for 'Get-GPOReport' may fail due to the default firewall exception only allowing access from remote computers on the same local subnet. In that case the default 'MaxTicketAge' (default 10 hours) and 'MaxClockSkew' (default 5 minutes) is used instead. You may see the following error:

```Text
[<FQDN TARGET DC>] Connecting to remote server <FQDN TARGET DC> failed with the following error message : WinRM cannot complete the operation. Verify that the specified computer name is valid, that the computer is accessible over the network, and that a firewall exception for the WinRM service is enabled and allows access from this computer. By default, the WinRM firewall exception for public profiles limits access to remote computers within the same local subnet. For more information, see the about_Remote_Troubleshooting Help topic.
+ CategoryInfo: OpenError: (<FQDN TARGET DC>:String) [], PSRemotingTransportException
+ FullyQualifiedErrorId: WinRMOperationTimeout,PSSessionStateBroken
```

* Although this script can be used in an environment with Windows Server 2000/2003 RWDCs, it is NOT supported to do this. Windows Server 2000/2003 RWDCs cannot do KDC PAC validation using the previous (N-1) krbtgt password. Those RWDCs only attempt that with the current (N) password. That means that in the subset of KRB AP exchanges where KDC PAC validation is performed, authentication issues could be experienced because the target server gets a PAC validation error when asking the KDC (domain controller) to validate the KDC signature of the PAC that is inside the service ticket that was presented by the client to the server. This problem would potentially persist for the lifetime of the service ticket(s). It is also highly recommended NOT to use products that have reached their end support. Please upgrade as soon as possible.
* This is not related to this script. When increasing the DFL from Windows Server 2003 to any higher level, the password of the KrbTgt Account will be reset automatically due to the introduction of AES encryption for Kerberos and the requirement to regenerate new keys for DES, RC4, AES128, AES256!

## RELEASE NOTES

* v3.4, 2023-03-04, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Bug Fix: The PowerShell CMDlets from the ActiveDirectory module DO recognize the 2016 FFL and DFL. The script DOES NOT use those anymore, but instead uses S.DS.P.. The issue appears to be that MSFT did update the ActiveDirectory module to recognize the 2016 FFL/DFl, but they apparently did not update the S.DS.P. DLLs to do the same. The script itself now detects this and reports the correct FFL/DFL when it is 2016
* v3.3, 2022-12-20, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Bug Fix: updated the attribute type when specifying the number of the AD domain instead of the actual FQDN of the AD domain
* v3.2, 2022-11-05, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * New Feature: Adding support for scheduled/automated password reset of KrbTgt account password for either all RWDCs, all individual RODCs or specific RODCs
  * New Feature: Added mail function and parameter to mail the log file for review after execution with results
  * New Feature: Adding support for signed mail
  * New Feature: Adding support for encrypted mail
  * Bug Fix: Minor textual fixes
  * Bug Fix: fix an issue where one confirmation of continueOrStop would be inherited by the next
  * Bug Fix: fix an issue where the forest root domain would always be chosen as the source for replication and GPOs instead of the chosen AD domain when using custom credentials.
    This caused replicate single object to fail and for the determination of the Kerberos settings in the resultant GPO
  * Code Improvement: Added function getServerNames to retrieve server related names/FQDNs
  * Code Improvement: Added support for disjoint namespace, e.g. AD domain FQDN = ADDOMAIN.COM and DCs FQDN for that AD domain = &lt;DC NAME&gt;.SOMEDNSDOMAIN.COM
  * Code Improvement: Removed ALL dependencies for the ActiveDirectory PoSH module and replaced those with alternatives
  * Code Improvement: Redefinition of tables holding data for processing
  * Code Improvement: Upgraded to S.DS.P PowerShell Module v2.1.5 (2022-09-20)
  * Improved User Experience: Added the NetBIOS name of the AD domain to the list of AD domains in an AD forest
  * Improved User Experience: Added the option to the function to install required PoSH modules when not available
  * Improved User Experience: Added support to specify the number of an AD domain in the list instead of its FQDN
* v3.1, 2022-06-06, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Improved User Experience: The S.DS.P PowerShell Module v2.1.4 has been included into this script (with permission and under GPL license) to remove the dependency of the AD PowerShell Module when querying objects in AD. The
    ActiveDirectory PowerShell module is still used to get forest, domain, and domaincontroller information.
  * Improved User Experience: Removed dependency for port 135 (RPC Endpoint Mapper) and 9389 (AD Web Service)
  * Bug Fix: Getting the description of the Test KrbTgt accounts in remote AD forest with explicit credentials to compare and fix later
  * Code Improvement: In addition to check for the correct description, also check if the test KrbTgt accounts are member of the correct groups
  * Code Improvement: Updated function createTestKrbTgtADAccount
  * Bug Fix: Minor textual fixes
* v3.0, 2022-05-27, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Bug Fix: Changed variable from $pwd to $passwd
  * Bug Fix: Variable used in single-quoted string. Wrapped in double-quote to fix
  * Bug Fix: Fix missing conditions and eventually credentials when connecting to a remote untrusted AD forest
  * Code Improvement: Minor improvements through scripts
  * Code Improvement: Changed variable from $passwordNrChars to $passwdNrChars
  * Code Improvement: Updated function confirmPasswordIsComplex
  * Code Improvement: Instead of assuming the "Max Tgt Lifetime In Hours" And the "Max Clock Skew In Minutes" is configured in the Default Domain GPO policy (the default)
    It now performs an RSoP to determine which GPO provides the authoritative values, and then uses the values from that GPO
  * Code Improvement: Added check for required PowerShell module on remote RWDC when running Invoke-Command CMDlet
  * Code Improvement: Added function 'requestForAdminCreds' to request for admin credentials
  * Improved User Experience: Specifically mentioned the requirement for the ADDS PoSH CMDlets and the GP PoSH CMDlets
  * Improved User Experience: Checking AD forest existence through RootDse connection in addition to DNS resolution
  * Code Improvement: Added a variable for connectionTimeout and changed the default of 500ms to 2000ms
* v2.9, 2021-05-04, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Improved User Experience: Added additional info and recommendations
  * New Feature: Added function to check UAC elevation status, and if not elevated to start the script automatically using an elevated PowerShell Command Prompt
* v2.8, 2020-04-02, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Bug fix: Fixed an issue when the RODC itself is not reachable/available, whereas in that case, the source should be the RWDC with the PDC FSMO
  * Improved User Experience: Checks to make sure both the RWDC with the PDC FSMO role and the nearest RWDC are available. If either one is not available, the script will abort
* v2.7, 2020-04-02, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Code Improvement: Added DNS name resolution check to the portConnectionCheck function
  * Code Improvement: Removed usage of $remoteADforest variable and only use the $localADforest variable
  * Code Improvement: Removed usage of $remoteCredsUsed variable and only use the $adminCrds variable (Was $adminCreds)
  * Code Improvement: Sections with '#XXX' have been removed
  * Code Improvement: Calls using the CMDlet 'Get-ADReplicationAttributeMetadata' (W2K12 and higher) have been replaced with .NET calls to support older OS'es such as W2K8 and W2K8R2. A function has been created to retrieve metadata
  * Code Improvement: Some parts were rewritten/optimized
  * Improved User Experience: To test membership of the administrators group in a remote AD forest the "title" attribute is now used instead of the "displayName" attribute to try to write to it
  * Improved User Experience: Added a warning if the special purpose krbtgt account 'Krbtgt_AzureAD' is discovered in the AD domain
  * Improved User Experience: If the number of RODCs in the AD domain is 0, then it will not present the options for RODCs
  * Improved User Experience: If the number of RODCs in the AD domain is 1 of more, and you chose to manually specify the FQDN of RODCs to process, it will present a list of RODCs to choose from
  * Improved User Experience: Operational modes have been changed (WARNING: pay attention to what you choose!). The following modes are the new modes
  * 1 - Informational Mode (No Changes At All)
  * 2 - Simulation Mode | Temporary Canary Object Created To Test Replication Convergence!
  * 3 - Simulation Mode | Use KrbTgt TEST/BOGUS Accounts - No Password Reset/WhatIf Mode!
  * 4 - Real Reset Mode | Use KrbTgt TEST/BOGUS Accounts - Password Will Be Reset Once!
  * 5 - Simulation Mode | Use KrbTgt PROD/REAL Accounts - No Password Reset/WhatIf Mode!
  * 6 - Real Reset Mode | Use KrbTgt PROD/REAL Accounts - Password Will Be Reset Once!
  * Improved User Experience: When choosing RODC Krb Tgt Account scope the following will now occur:
  * If the RODC is not reachable, the real source RWDC of the RODC cannot be determined. In that case, the RWDC with the PDC FSMO role is used as the source for the change and replication
  * If the RODC is reachable, but the real source RWDC of the RODC is not reachable it cannot be used as the source for the change and replication. In that case, the RWDC with the PDC FSMO role is used as the source for the change and replication
* v2.6, 2020-02-25, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Code Improvement: Removed code that was commented out
  * Code Improvement: In addition to the port 135 (RPC Endpoint Mapper) and 389 (LDAP), the script will also check for port 9389 (AD Web Service) which is used by the ADDS PoSH CMDlets
  * Code Improvement: Updated script to included more 'try/catch' and more (error) logging, incl. line where it fails, when things go wrong to make troubleshooting easier
  * Improved User Experience: Logging where the script is being executed from
  * Improved User Experience: Updated the function 'createTestKrbTgtADAccount' to also include the FQDN of the RODC for which the Test KrbTgt account is created for better recognition
* v2.5, 2020-02-17, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Code Improvement: To improve performance, for some actions the nearest RWDC is discovered instead of using the RWDC with the PDC FSMO Role
* v2.4, 2020-02-10, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Bug Fix: Fixed language specific issue with the groups 'Allowed RODC Password Replication Group' and 'Denied RODC Password Replication Group'
  * Code Improvement: Checked script with Visual Studio Code and fixed all "problems" identified by Visual Studio Code
  * Variable "$remoteCredsUsed" is ignored by me, as the problem is due to the part 'Creds' in the variable name
  * Variable "$adminCreds" is ignored by me, as the problem is due to the part 'Creds' in the variable name
  * New Feature: Added support to execute this script against a remote AD forest, either with or without a trust
* v2.3, 2019-02-25, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Code Improvement: Removed the language specific error checking. Has been replaced with another check. This solution also resolved another
    issue when checking if a (RW/RO)DC was available or not
* v2.2, 2019-02-12, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Code Improvement: Instead of searching for "Domain Admins" or "Enterprise Admins" membership, it resolves the default RIDs of those
    groups, combined with the corresponding domain SID, to the actual name of those domain groups. This helps in supporting non-english
    names of those domain groups
* v2.1, 2019-02-11, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Code Improvement: Added a try catch when enumerating details about a specific AD domain that appears not to be available
  * New Feature: Read and display metadata of the KrbTgt accounts before and after to assure it was only updated once!
* v2.0, 2018-12-30, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Code Improvement: Full rewrite and major release
  * New Feature: Added possibility to also reset KrbTgt account in use by RODCs
  * New Feature: Added possibility to try this procedure using a temp canary object (contact object)
  * New Feature: Added possibility to try this procedure using a TEST krbtgt accounts and perform password reset on those TEST krbtgt accounts
  * New Feature: Added possibility to create TEST krbtgt accounts if required
  * New Feature: Added possibility to delete TEST krbtgt accounts if required
  * New Feature: Check if an RODC account is indeed in use by a Windows RODC and not something simulating an RODC (e.g. Riverbed)
  * New Feature: Removed dependency for REPADMIN.EXE
  * New Feature: Removed dependency for RPCPING.EXE
  * New Feature: Extensive logging to both screen and file
  * New Feature: Added more checks, such as permissions check, etc.
  * Script Improvement: Renamed script to Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1
* v1.7, Jared Poeppelman, Microsoft
  * Code Improvement: Modified rpcping.exe call to use "-u 9 -a connect" parameters to accomodate tighter RPC security settings as specified in
    DISA STIG ID: 5.124 Rule ID: SV-32395r1_rule , Vuln ID: V-14254 (thanks Adam Haynes)
* v1.6, Jared Poeppelman, Microsoft
  * Code Improvement: Removed 'finally' block of Get-GPOReport error handling (not a bug, just not needed)
* v1.5, Jared Poeppelman, Microsoft
  * Bug Fix: Fixed bug of attempting PDC to PDC replication
  * Code Improvement: Added logic for GroupPolicy Powershell module dependency
  * Code Improvement: Replaced function for password generation
  * Code Improvement: Renamed functions to use appropriate Powershell verbs
  * Code Improvement: Added error handling around Get-GpoReport for looking up MaxTicketAge and MaxClockSkew
  * Script Improvement: Renamed script to New-CtmADKrbtgtKeys.ps1
* v1.4, Jared Poeppelman, Microsoft
  * First version published on TechNet Script Gallery

## SYNOPSIS/DESCRIPTION

This PoSH Script Resets The KrbTgt Password For RWDCs And RODCs In A Controlled Manner.

This PoSH script provides the following functions:

* Single Password Reset for the KrbTgt account in use by RWDCs in a specific AD domain, using either TEST or PROD KrbTgt accounts
* Single Password Reset for the KrbTgt account in use by an individual RODC in a specific AD domain, using either TEST or PROD KrbTgt accounts
  * A single RODC in a specific AD domain
  * A specific list of RODCs in a specific AD domain
  * All RODCs in a specific AD domain
* Resetting the password/keys of the KrbTgt Account can be done for multiple reasons such as for example:
  * From a security perspective as mentioned in <https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/>
  * From an AD recovery perspective as mentioned in <https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password>
* For all scenarios, an informational mode, which is mode 1 with no changes
* For all scenarios, a simulation mode, which is mode 2 where replication is tested through the replication of a temporary canary object that is created and deleted afterwards. No Password Resets involved here as the temporary canary object is a contact object
* For all scenarios, a simulation mode, which is mode 3 where NO password reset of the chosen TEST KrbTgt account occurs. Basically this just checks the status of the objects on scoped DCs. NOTHING is changed. Can be scoped for RWDCs and RODCs (single, multiple, all)
* For all scenarios, a real reset mode, which is mode 4 where the password reset of the chosen TEST KrbTgt account is actually executed and replication of it is monitored through the environment for its duration. Can be scoped for RWDCs and RODCs (single, multiple, all)
* For all scenarios, a simulation mode, which is mode 5 where NO password reset of the chosen PROD KrbTgt account occurs. Basically this just checks the status of the objects on scoped DCs. NOTHING is changed. Can be scoped for RWDCs and RODCs (single, multiple, all)
* For all scenarios, a real reset mode, which is mode 6 where the password reset of the chosen PROD KrbTgt account is actually executed and replication of it is monitored through the environment for its duration
* The creation of Test KrbTgt Accounts, which is mode 8
* The deletion of Test KrbTgt Accounts, which is mode 9
* It is possible to run the script in a scheduled and automated manner by specifying the correct parameters and the correct information
* When running in a scheduled and automated manner, it is possible to have the log file mailed to some defined mailbox
* When mailing it is possible to sign and/or encrypt the mail message, provided the correct certificates are available for signing and/or encryption
* Certificates can either be in the User Store or in a PFX file with the password available (Signing and Encryption) or in a CER file (Encryption Only)
* When mailing of the log file is needed in ANY way, a configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml" is needed with settings to control mailing behavior. The configuration XML file is expected to be in the same folder as the script itself. See below in the NOTES for the structure

This PoSH script presents the following behavior:

* In this script a DC is reachable/available, if its name is resolvable and connectivity is possible for all of the following ports: TCP:389 (LDAP)
* In mode 1 you will always get a list of all RWDCs, and alls RODCs if applicable, in the targeted AD domain that are available/reachable or not
* In mode 2 it will create the temporary canary object and, depending on the scope, it will check if it exists in the AD database of the remote DC(s) (RWDC/RODC)
* In mode 3, depending on the scope, it uses TEST/BOGUS krbtgt account(s). It just checks and compares the state of the pwdLastSet attribute on the source RWDC with other scoped DCs. Nothing is changed/updated!
* For RWDCs it uses the TEST/BOGUS krbtgt account "krbtgt_TEST" (All RWDCs) (= Created when running mode 8)
* For RODCs it uses the TEST/BOGUS krbtgt account "krbtgt_&lt;Numeric Value&gt;_TEST" (RODC Specific) (= Created when running mode 8)
* In mode 4, depending on the scope, it uses TEST/BOGUS krbtgt account(s) to reset the password on an originating RWDC. After that it checks if pwdLastSet attribute value of the targeted TEST/BOGUS krbtgt account(s) on the remote DC(s) (RWDC/RODC) matches the pwdLastSet attribute value of the same TEST/BOGUS krbtgt account on the originating RWDC
* For RWDCs it uses the TEST/BOGUS krbtgt account "krbtgt_TEST" (All RWDCs) (= Created when running mode 8)
* For RODCs it uses the TEST/BOGUS krbtgt account "krbtgt_&lt;Numeric Value&gt;_TEST" (RODC Specific) (= Created when running mode 8)
* In mode 5, depending on the scope, it uses PROD/REAL krbtgt account(s). It just checks and compares the state of the pwdLastSet attribute on the source RWDC with other scoped DCs. Nothing is changed/updated!
* In mode 6, depending on the scope, it uses PROD/REAL krbtgt account(s) to reset the password on an originating RWDC. After that it checks if pwdLastSet attribute value of the targeted PROD/REAL krbtgt account(s) on the remote DC(s) (RWDC/RODC) matches the pwdLastSet attribute value of the same PROD/REAL krbtgt account on the originating RWDC
* For RWDCs it uses the PROD/REAL krbtgt account "krbtgt" (All RWDCs)
* For RODCs it uses the PROD/REAL krbtgt account "krbtgt_&lt;Numeric Value&gt;_TEST" (RODC Specific)
* In mode 8, for RWDCs it creates (in disabled state!) the TEST/BOGUS krbtgt account "krbtgt_TEST" and adds it to the AD group "Denied RODC Password Replication Group". If any RODC exists in the targeted AD domain, it reads the attribute "msDS-KrbTgtLink" of each RODC computer account to determine the RODC specific krbtgt account and creates (in disabled state!) the TEST/BOGUS krbtgt account "krbtgt_&lt;Numeric Value&gt;_TEST" and adds it to the AD group "Allowed RODC Password Replication Group"
* In mode 9, for RWDCs it deletes the TEST/BOGUS krbtgt account "krbtgt_TEST" if it exists. If any RODC exists in the targeted AD domain, it reads the attribute "msDS-KrbTgtLink" of each RODC computer account to determine the RODC specific krbtgt account and deletes the TEST/BOGUS krbtgt account "krbtgt_&lt;Numeric Value&gt;_TEST" if it exists.
* In mode 2, 3, 4, 5 or 6, if a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if the change made reached it or not.
* In mode 2 when performing the "replicate single object" operation, it will always be for the full object, no matter if the remote DC is an RWDC or an RODC
* In mode 3, 4, 5 or 6 when performing the "replicate single object" operation, it will always be for the full object, if the remote DC is an RWDC. If the remote DC is an RODC it will always be for the partial object and more specifically "secrets only"
* When targeting the krbtgt account (TEST/BOGUS or PROD/REAL) in use by all the RWDCs, the originating RWDC is the RWDC with the PDC FSMO and all other available/reachable RWDCs will be checked against to see if the change has reached them. No RODCs are involved as those do not use the krbtg account in use by the RWDCs and also do not store/cache its password.
* When targeting the krbtgt account (TEST/BOGUS or PROD/REAL) in use by an RODC, the originating RWDC is the direct replication RWDC if available/reachable and when not available the RWDC with the PDC FSMO is used as the originating RWDC. Only the RODC that uses the specific krbtgt account is checked against to see if the change has reached them, but only if the RODCs is available/reachable. If the RODC itself is not available, then the RWDC with the PDC FSMO is used as the originating RWDC and the change will eventually replicate to the RODC
* If the operating system attribute of an RODC computer account does not have a value, it is determined to be unknown (not a real RODC), and therefore something else. It could for example be a Riverbed appliance in "RODC mode".
* The only DC that knows what the real replication partner is of an RODC, is the RODC itself. Only the RODC manages a connection object that only exists in the AD database of the RODC and does not replicate out to other DCs as RODCs do not support outbound replication. Therefore, assuming the RODC is available, the CO is looked up in the RODC AD database and from that CO, the "source" server is determined. In case the RODC is not available or its "source" server is not available, the RWDC with the PDC FSMO is used to reset the password of the krbtgt account in use by that RODC. If the RODC is available a check will be done against its database, and if not available the check is skipped

## PARAMETER(S)

noInfo

* With this parameter it is possible to skip the information at the beginning of the script when running the script in an automated manner such as in a Scheduled Task

modeOfOperation

* With this parameter it is possible to specify the mode of operation for the script. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen! Accepted values are: "infoMode", "simulModeCanaryObject", "simulModeKrbTgtTestAccountsWhatIf", "resetModeKrbTgtTestAccountsResetOnce", "simulModeKrbTgtProdAccountsWhatIf", "resetModeKrbTgtProdAccountsResetOnce"

targetedADforestFQDN

* With this parameter it is possible to specify the FQDN of an AD forest that will be targeted. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

targetedADdomainFQDN

* With this parameter it is possible to specify the FQDN of an AD domain that will be targeted within the specified AD forest. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

targetKrbTgtAccountScope

* With this parameter it is possible to specify the scope of the targeted KrbTgt account. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen! Accepted values are: "allRWDCs", "allRODCs", "specificRODCs"

targetRODCFQDNList

* With this parameter it is possible to specify one or more RODCs through a comma-separated list. This parameter is ONLY needed when the targetKrbTgtAccountScope is set to specificRODCs. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

continueOps

* With this parameter it is possible to specify the script should continue where it is needed to confirm the operation depending of whether there is impact or not. If the script determines there is impact, the script will abort to prevent impact. Only when running ON-DEMAND without any parameters will it be possible to continue and still have domain wide impact, in other words ignore there is impact. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

sendMailWithLogFile

* With this parameter it is possible to specify the script should mail the LOG file at any moment when the script stops running, whether it finished succesfully or due to encountered issue(s). This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

## EXAMPLE(S)

Execute The Script - On-Demand

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1
```

Execute The Script - Automated Without Sending The Log File Through Mail - Mode 2 With All RWDCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeCanaryObject -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps
```

Execute The Script - Automated And Sending The Log File Through Mail - Mode 2 With All RWDCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeCanaryObject -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile
```

Execute The Script - Automated And Sending The Log File Through Mail - Mode 3 With All RWDCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeKrbTgtTestAccountsWhatIf -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile
```

Execute The Script - Automated And Sending The Log File Through Mail - Mode 4 With All RWDCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtTestAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile
```

Execute The Script - Automated And Sending The Log File Through Mail - Mode 5 With All RWDCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeKrbTgtProdAccountsWhatIf -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile
```

Execute The Script - Automated And Sending The Log File Through Mail - Mode 6 With All RWDCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile
```

Execute The Script - Automated And Sending The Log File Through Mail - Mode 3 With All RODCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeKrbTgtTestAccountsWhatIf -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRODCs -continueOps -sendMailWithLogFile
```

Execute The Script - Automated And Sending The Log File Through Mail - Mode 4 With All RODCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtTestAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRODCs -continueOps -sendMailWithLogFile
```

Execute The Script - Automated And Sending The Log File Through Mail - Mode 5 With All RODCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeKrbTgtProdAccountsWhatIf -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRODCs -continueOps -sendMailWithLogFile
```

Execute The Script - Automated And Sending The Log File Through Mail - Mode 6 With All RODCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRODCs -continueOps -sendMailWithLogFile
```

Execute The Script - Automated And Sending The Log File Through Mail - Mode 6 With Specific RODCs (But Not All) As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope specificRODCs -targetRODCFQDNList "RODC1.DOMAIN.COM","RODC2.DOMAIN.COM","RODC3.DOMAIN.COM" -continueOps -sendMailWithLogFile
```

## NOTES

* Required PoSH CMDlets: GPMC PoSH CMDlets on all targeted RWDCs!!! (and the S.DS.P Posh CMDlets are INCLUDED in this script!)
* To execute this script, the account running the script MUST be a member of the "Domain Admins" or Administrators group in the targeted AD domain.
* If the account used is from another AD domain in the same AD forest, then the account running the script MUST be a member of the "Enterprise Admins" group in the AD forest or Administrators group in the targeted AD domain. For all AD domains in the same AD forest, membership of the "Enterprise Admins" group is easier as by default it is a member of the Administrators group in every AD domain in the AD forest
* If the account used is from another AD domain in another AD forest, then the account running the script MUST be a member of the "Administrators" group in the targeted AD domain. This also applies to any other target AD domain in that same AD forest
* This is due to the reset of the password for the targeted KrbTgt account(s) and forcing (single object) replication between DCs
* Testing "Domain Admins" membership is done through "IsInRole" method as the group is domain specific
* Testing "Enterprise Admins" membership is done through "IsInRole" method as the group is forest specific
* Testing "Administrators" membership cannot be done through "IsInRole" method as the group exist in every AD domain with the same SID. To still test for required permissions in that case, the value of the Description attribute of the KRBTGT account is copied
  into the Title attribute and cleared afterwards. If both those actions succeed it is proven the required permissions are in place!
* If User Account Control (UAC) is in effect (i.e. enabled) the script MUST be executed in an elevated Powershell Command Prompt Window!
* When running the script on-demand with an account that does have the correct permissions, the script will ask for credentials with the correct permissions
* When running the script automated with an account that does have the correct permissions, the script will NOT ask for credentials with the correct permissions. It will just stop. Therefore in an automated manner, the running account MUST have the correct permissions!
* When mailing of the log file is needed and the mail message must be signed and/or encrypted, then an external DLL is needed to provide such functionality. The source code can be download from <https://www.codeproject.com/Articles/41727/An-S-MIME-Library-for-Sending-Signed-and-Encrypted> and you must compile it yourself! I have NOT reviewed that source code in any way. You MUST review that source code yourself and determine if you use it or not!. The path of the DLL must be specified in the configuration XML file so that the script can find it and load it
* When there is a need to SIGN the mail message, then a certificate with a private key (PFX file or in the User Store) is needed for the sender
* When there is a need to ENCRYPT the mail message, then a certificate (CER file or in the User Store) is needed for EVERY recipient! In turn, every recipient must have the corresponding certificate with a private key (in the User Store) to be able to decrypt the mail
* When there is a need to SIGN and ENCRYPT the mail message, both of the previous requirements must be met
* To SIGN and/or ENCRYPT the mail message, the correct certificate must be issued and used, such as one with EKU "Secure Email (1.3.6.1.5.5.7.3.4)"
* Configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml" structure

============ Configuration XML file ============ (Use sample in: <https://github.com/zjorz/Public-AD-Scripts/blob/master/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml>)
<BR>
&lt;?xml version="1.0" encoding="utf-8"?&gt;
<BR>
&lt;resetKrbTgtPassword xmlns:xsi="<http://www.w3.org/2001/XMLSchema-instance>" xmlns:xsd="<http://www.w3.org/2001/XMLSchema>"&gt;
<BR>
<BR>
&lt;!-- FQDN Of The Mail Server Or Mail Relay --&gt;
<BR>
&lt;smtpServer&gt;REPLACE_WITH_MAIL_SERVER_FQDN&lt;/smtpServer&gt;
<BR>
<BR>
&lt;!-- SMTP Port To Use --&gt;
<BR>
&lt;smtpPort&gt;REPLACE_WITH_MAIL_SERVER_SMTP_PORT_NUMERIC_VALUE&lt;/smtpPort&gt;
<BR>
<BR>
&lt;!-- SSL FOR SMTP - TRUE OR FALSE --&gt;
<BR>
&lt;useSSLForSMTP&gt;TRUE_OR_FALSE&lt;/useSSLForSMTP&gt;
<BR>
<BR>
&lt;!-- SMTP Credentials To Use - UserName/Password --&gt;
<BR>
&lt;smtpCredsUserName&gt;LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_REPLACE_WITH_USERNAME_IF_USED&lt;/smtpCredsUserName&gt;
<BR>
&lt;smtpCredsPassword&gt;LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_REPLACE_WITH_PASSWORD_IF_USED&lt;/smtpCredsPassword&gt;
<BR>
<BR>
&lt;!-- Mail Subject To Use --&gt;
<BR>
&lt;mailSubject&gt;KrbTgt Password Reset Result&lt;/mailSubject&gt;
<BR>
<BR>
&lt;!-- The Priority Of The Message: Low, Normal, High --&gt;
<BR>
&lt;mailPriority&gt;High&lt;/mailPriority&gt;
<BR>
<BR>
&lt;!-- Mail Body To Use --&gt;
<BR>
 &lt;mailBody&gt;
<BR>
&lt;!DOCTYPE html&gt;
<BR>
&lt;html&gt;
<BR>
&lt;head&gt;
<BR>
&lt;title&gt;KrbTgt_Password_Reset&lt;/title&gt;
<BR>
&lt;style type="text/css"&gt;
<BR>
&lt;/style&gt;
<BR>
&lt;/head&gt;
<BR>
&lt;body&gt;
<BR>
&lt;B&gt;&lt;P align="center" style="font-size: 24pt; font-family: Arial Narrow, sans-serif; color: red"&gt;!!! ATTENTION | FYI - ACTION REQUIRED !!!&lt;/P&gt;&lt;/B&gt;
&lt;hr size=2 width="95%" align=center&gt;
<BR>
&lt;BR&gt;
<BR>
&lt;P style="font-size: 12pt; font-family: Arial Narrow, sans-serif;"&gt;Hello,&lt;/P&gt;
<BR>
&lt;BR&gt;
<BR>
&lt;P style="font-size: 12pt; font-family: Arial Narrow, sans-serif;"&gt;Please review the attached log file.&lt;/P&gt;
<BR>
&lt;BR&gt;
<BR>
&lt;P style="font-size: 12pt; font-family: Arial Narrow, sans-serif;"&gt;Best regards&lt;/P&gt;
<BR>
&lt;/body&gt;
<BR>
&lt;/html&gt;&lt;/mailBody&gt;
<BR>
<BR>
&lt;!-- The SMTP Address Used In The FROM Field --&gt;
<BR>
&lt;mailFromSender&gt;<sender_Mail_Address@company.com>&lt;/mailFromSender&gt;
<BR>
<BR>
&lt;!-- The SMTP Address Used In The TO Field --&gt;
<BR>
&lt;mailToRecipient&gt;<recipient_To_MailAddress@company.com>&lt;/mailToRecipient&gt;
<BR>
<BR>
&lt;!-- The SMTP Address Used In The CC Field --&gt;
<BR>
&lt;mailCcRecipients&gt;
<BR>
  &lt;!-- For Every Recipient To Be Added In The CC Add A New Line --&gt;
  <BR>
  &lt;mailCcRecipient&gt;<recipient_Cc_MailAddress_1@company.com>&lt;/mailCcRecipient&gt;
  <BR>
  &lt;mailCcRecipient&gt;<recipient_Cc_MailAddress_2@company.com>&lt;/mailCcRecipient&gt;
  <BR>
&lt;/mailCcRecipients&gt;
<BR>
<BR>
&lt;!-- Enable/Disable SMIME signing and encryptionof emails: ON or OFF --&gt;
<BR>
&lt;mailSign&gt;OFF&lt;/mailSign&gt;
<BR>
&lt;mailEncrypt&gt;OFF&lt;/mailEncrypt&gt;
<BR>
<BR>
&lt;!-- Full path of Cpi.Net.SecureMail.dll --&gt;
<BR>
&lt;!-- Dll Source Code: <https://www.codeproject.com/Articles/41727/An-S-MIME-Library-for-Sending-Signed-and-Encrypted> --&gt;
<BR>
&lt;mailSignAndEncryptDllFile&gt;REPLACE_WITH_FULL_FOLDER_PATH_TO_COMPILED_DLL_FILE\Cpi.Net.SecureMail.dll&lt;/mailSignAndEncryptDllFile&gt;
<BR>
<BR>
&lt;!-- Location Of Cert To Sign/Encrypt The Mail --&gt;
<BR>
&lt;mailSignAndEncryptCertLocation&gt;STORE_OR_PFX&lt;/mailSignAndEncryptCertLocation&gt; &lt;!-- Location Of Cert To Sign/Encrypt The Mail - Options Are: PFX or STORE --&gt;
<BR>
&lt;mailEncryptCertLocation&gt;STORE_OR_CER&lt;/mailEncryptCertLocation&gt;     &lt;!-- Location Of Cert To Encrypt The Mail - Options Are: CER or STORE --&gt;
<BR>
<BR>
&lt;!-- Thumbprint Of Certificate To Sign/Encrypt Mail With - Only Used When Corresponding Value For Location Is STORE --&gt;
<BR>
&lt;mailSignAndEncryptCertThumbprint&gt;LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_REPLACE_WITH_THUMBPRINT_IF_USED&lt;/mailSignAndEncryptCertThumbprint&gt; &lt;!-- Thumbprint Of Cert To Sign/Encrypt The Mail By Sender --&gt;
<BR>
&lt;mailEncryptCertThumbprint&gt;LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_REPLACE_WITH_THUMBPRINT_IF_USED&lt;/mailEncryptCertThumbprint&gt;    &lt;!-- Thumbprint Of Cert To Encrypt The Mail For Recipient --&gt;
<BR>
<BR>
&lt;!-- Full path of a .pfx/.cer certificate file used to sign/encrypt the email message - Only Used When Corresponding Value For Location Is PFX/CER --&gt;
<BR>
&lt;mailSignAndEncryptCertPFXFile&gt;REPLACE_WITH_FULL_FOLDER_PATH_TO_PFX_FILE\cert.pfx&lt;/mailSignAndEncryptCertPFXFile&gt; &lt;!-- PFX File Of Cert/Private Key To Sign/Encrypt The Mail By Sender --&gt;
<BR>
&lt;mailEncryptCertCERFile&gt;REPLACE_WITH_FULL_FOLDER_PATH_TO_CER_FILE\cert.cer&lt;/mailEncryptCertCERFile&gt;     &lt;!-- CER File Of Cert To Encrypt The Mail For Recipient --&gt;
<BR>
<BR>
&lt;!-- The password for the .pfx certificate file - Only Used When Corresponding Value For Location Is PFX --&gt;
<BR>
&lt;mailSignAndEncryptCertPFXPassword&gt;LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_REPLACE_WITH_PFX_PASSWORD_IF_USED&lt;/mailSignAndEncryptCertPFXPassword&gt; &lt;!-- Password Of PFX File Of Cert/Private Key To Sign/Encrypt The Mail By Sender --&gt;
<BR>
&lt;/resetKrbTgtPassword&gt;
<BR>
============ Configuration XML file ============ (Use sample in: <https://github.com/zjorz/Public-AD-Scripts/blob/master/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml>)

## SCREENSHOTS

See blog <https://jorgequestforknowledge.wordpress.com/category/active-directory-domain-services-adds/krbtgt-account/>

You may need to scroll!
