# SCRIPT: Reset-KrbTgt-Password-For-RWDCs-And-RODCs

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

&nbsp;

## ORIGINAL AND OFFICIAL SOURCE(S)

* PowerShell Script...:  <https://github.com/zjorz/Public-AD-Scripts/blob/master/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1>
* XML File............: <https://github.com/zjorz/Public-AD-Scripts/blob/master/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml>
* Blog................: <https://jorgequestforknowledge.wordpress.com/category/active-directory-domain-services-adds/krbtgt-account/>

&nbsp;

## AUTHOR/OWNER/FEEDBACK/REQUESTS

* Written By: Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]
* Re-Written By: N.A.
* Company: IAMTEC &gt;&gt; Identity | Security | Recovery [https://www.iamtec.eu/]
* Blog: Jorge's Quest For Knowledge [http://jorgequestforknowledge.wordpress.com/]
* For Feedback/Questions/Requests: [GITHUB](https://github.com/zjorz/Public-AD-Scripts/issues) (<= PREFERRED) Or mail to "scripts DOT gallery AT iamtec.eu"
  * Please Describe Your Scenario As Best As Possible With As Much Detail As Possible.
  * If Applicable Describe What Does and/Or Does Not Work.
  * If Applicable Describe What Should Be/Work Different And Explain Why/How.
  * Please Add Screendumps.

&nbsp;

## RECOMMENDATION - TESTING GUIDANCE

!!! TEST FIRST IN A TEST ENVIRONMENT !!!

I can imagine that you want to test this script to get confidence in what it does, how it does it, and of course see it working as if it was for real. Customization of the configuration XML would also be beneficial without impacting the real AD environment.

The script works per AD domain, not per AD forest! Based on the defined scope (global KRBTGT account for all RWDCs, or all individual KRBTGT account of each discovered RODC, or all individual KRBTGT account of specific RODCs), the chosen mode (TEST/BOGUS KrbTgt accounts, or PROD/REAL KrbTgt accounts), the script will do its work in a controlled manner.

&nbsp;

PREPARING THE ENVIRONMENT TO TEST WITHOUT ANY IMPACT
* Start the PowerShell script, and determine which parameters to use:
  * -noInfo: to NOT see the detailed info at the beginning
  * -sendMailWithLogFile: to send an e-mail the completion of the script (requires the use and configuration of the Configuration XML file!)
* Use MODE 8 to create the TEST/BOGUS KrbTgt ACCOUNTS in the AD domain. The script determines which real KRBTGT accounts exists in the AD domain, and after doing that it creates and configures the test KRBTGT accounts. See the documentation in the script for more details. It is recommended to NOT delete these test KRBTGT accounts to be able to simulate correctly. The test KRBTGT accounts are disabled, have very strong passwords, and have no special privileges!
* Specify the AD Forest
* Specify the AD Domain
* Confirm to CONTINUE or STOP for normal operations

&nbsp;

INTERACTIVE TESTING
* Start the PowerShell script, and determine which parameters to use:
  * -noInfo: to NOT see the detailed info at the beginning
  * -sendMailWithLogFile: to send an e-mail the completion of the script (requires the use and configuration of the Configuration XML file!)
* Use mode: "4"
* Specify the AD Forest
* Specify the AD Domain
* Select the scope of testing (select either 1, 3 or 4):
  * 1 - Scope of KrbTgt in use by all RWDCs in the AD Domain
  * 2 - Scope of KrbTgt in use by specific RODC - Single/Multiple RODC(s) in the AD Domain
  * 3 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain
  * 4 - Scope of ANY KrbTgt in use by ANY DC - All RWDCs/RODCs in the AD Domain
* Confirm to CONTINUE or STOP for normal operations
* Confirm to CONTINUE, SKIP or STOP if MAJOR IMPACT is DETECTED

&nbsp;

AUTOMATED TESTING (REGULAR)
* Start the PowerShell script, and determine which parameters to use:
  * -noInfo: to NOT see the detailed info at the beginning
  * -sendMailWithLogFile: to send an e-mail the completion of the script (requires the use and configuration of the Configuration XML file!)
  * Use mode: "4" => use parameter with value -modeOfOperation resetModeKrbTgtTestAccountsResetOnce
  * Specify the AD Forest => use parameter with value -targetedADforestFQDN COMPANY.COM
  * Specify the AD Domain => use parameter with value -targetedADdomainFQDN COMPANY.COM
  * Select the scope of testing (select either 1, 3 or 4):
    * 1 - Scope of KrbTgt in use by all RWDCs in the AD Domain => use parameter with value -targetKrbTgtAccountScope allRWDCs
    * 2 - Scope of KrbTgt in use by specific RODC - Single/Multiple RODC(s) in the AD Domain => use parameter with value -targetKrbTgtAccountScope specificRODCs -targetRODCFQDNList RODC1.COMPANY.COM,RODC2.COMPANY.COM
    * 3 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain => use parameter with value -targetKrbTgtAccountScope allRODCs
    * 4 - Scope of ANY KrbTgt in use by ANY DC - All RWDCs/RODCs in the AD Domain => use parameter with value -targetKrbTgtAccountScope allRWDCsAndRODCs
  * Confirm to CONTINUE or STOP for normal operations => use parameter -continueOps
  * Confirm to CONTINUE, SKIP or STOP if MAJOR IMPACT is DETECTED => NOT SUPPORTED, which means that if this is detected, the script automatically SKIPS the processing of the specific KRBTGT account

&nbsp;

AUTOMATED TESTING (PASSWORD RESET ROUTINE)
* Start the PowerShell script, and determine which parameters to use:
  * -noInfo: to NOT see the detailed info at the beginning
  * -sendMailWithLogFile: to send an e-mail the completion of the script (requires the use and configuration of the Configuration XML file!)
  * -execResetRoutine: to use the password reset routine (requires the use and configuration of the Configuration XML file!)
  * Use mode: "4" => use parameter with value -modeOfOperation resetModeKrbTgtTestAccountsResetOnce
  * Specify the AD Forest => use parameter with value -targetedADforestFQDN COMPANY.COM
  * Specify the AD Domain => use parameter with value -targetedADdomainFQDN COMPANY.COM
  * Select the scope of testing (select either 1, 3 or 4):
    * 1 - Scope of KrbTgt in use by all RWDCs in the AD Domain => use parameter with value -targetKrbTgtAccountScope allRWDCs
    * 2 - Scope of KrbTgt in use by specific RODC - Single/Multiple RODC(s) in the AD Domain => use parameter with value -targetKrbTgtAccountScope specificRODCs -targetRODCFQDNList RODC1.COMPANY.COM,RODC2.COMPANY.COM
    * 3 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain => use parameter with value -targetKrbTgtAccountScope allRODCs
    * 4 - Scope of ANY KrbTgt in use by ANY DC - All RWDCs/RODCs in the AD Domain => use parameter with value -targetKrbTgtAccountScope allRWDCsAndRODCs
  * Confirm to CONTINUE or STOP for normal operations => use parameter -continueOps
  * Confirm to CONTINUE, SKIP or STOP if MAJOR IMPACT is DETECTED => NOT SUPPORTED, which means that if this is detected, the script automatically SKIPS the processing of the specific KRBTGT account

&nbsp;

## KNOWN ISSUES/BUGS

* The script is NOT digitally signed
* Make sure to unblock the script using the 'Unblock-File' CMDLet after downloading from the internet

* When targeting a remote AD forest for which no trust exist with the AD forest the running account belongs to, the public profile of WinRM may be used. In that case the PSSession for 'Get-GPOReport' may fail due to the default firewall exception only allowing access from remote computers on the same local subnet. In that case the default 'MaxTicketAge' (default 10 hours) and 'MaxClockSkew' (default 5 minutes) is used instead. You may see the following error:

```Text
[<FQDN TARGET DC>] Connecting to remote server <FQDN TARGET DC> failed with the following error message : WinRM cannot complete the operation. Verify that the specified computer name is valid, that the computer is accessible over the network, and that a firewall exception for the WinRM service is enabled and allows access from this computer. By default, the WinRM firewall exception for public profiles limits access to remote computers within the same local subnet. For more information, see the about_Remote_Troubleshooting Help topic.
+ CategoryInfo: OpenError: (<FQDN TARGET DC>:String) [], PSRemotingTransportException
+ FullyQualifiedErrorId: WinRMOperationTimeout,PSSessionStateBroken
```

* Although this script can be used in an environment with Windows Server 2000/2003 RWDCs, it is NOT supported to do this. Windows Server 2000/2003 RWDCs cannot do KDC PAC validation using the previous (N-1) krbtgt password. Those RWDCs only attempt that with the current (N) password. That means that in the subset of KRB AP exchanges where KDC PAC validation is performed, authentication issues could be experienced because the target server gets a PAC validation error when asking the KDC (domain controller) to validate the KDC signature of the PAC that is inside the service ticket that was presented by the client to the server. This problem would potentially persist for the lifetime of the service ticket(s). It is also highly recommended NOT to use products that have reached their end support. Please upgrade as soon as possible.
* This is not related to this script. When increasing the DFL from Windows Server 2003 to any higher level, the password of the KrbTgt Account will be reset automatically due to the introduction of AES encryption for Kerberos and the requirement to regenerate new keys for DES, RC4, AES128, AES256!
* Reachability/Availability of a DC determined by the following factors:
  * Routing from where the script is executed to the target DC is possible
  * Port connection (LDAP 389) from where the script is executed to the target RWDC is possible
  * When testing the port connection, the target RWDC responds back fast enough within the defined timeout (default 1000 ms)
* When simulating the password reset (mode 3 for TEST/BOGUS KrbTgt accounts, and mode 5 for PROD/REAL KrbTgt accounts), the script still performs an AD convergence check as if a password reset had occurred for the targeted KrbTgt account(s). The script will in this case log clearly: "REMARK: What If Mode! NO PASSWORD RESET HAS OCCURRED!"
* When executing the Password Reset Routing (mode 4 for TEST/BOGUS KrbTgt accounts, and mode 6 for PROD/REAL KrbTgt accounts), the script performs an AD convergence check whether or not the password reset has occurred for the targeted KrbTgt account(s). If the password WAS NOT reset for the targeted KrbTgt account, the script logs clearly: "NO PASSWORD HAS BEEN SET FOR [&lt;Distinguished Name Of Targeted KrbTgt Account&gt;]". If the password WAS reset for the targeted KrbTgt account, the script logs clearly: "THE NEW PASSWORD FOR [&lt;Distinguished Name Of Targeted KrbTgt Account&gt;] HAS BEEN SET on RWDC [&lt;FQDN Of Targeted RWDC For The Change&gt;]!"
* The script expects to find real DCs (RWDCs and RODCs!) in the default domain controllers OU, and NOT outside of that OU!
* When using the mailing function, NO check is done for expiring credentials (secrets, certificates, etc.)

&nbsp;

## RELEASE NOTES

* v3.6, 2026-01-01, Jorge de Almeida Pinto [MVP Identity And Access [MVP Identity And Access - Security / Lead Identity/Security Architect]:
  * Code Improvement: Optimizing code by determining required DNs once and reuse that, instead of continuously query for the same information
  * Code Improvement: Updated all functions (where applicable), except the ones from S.DS.P, to specify the data type of each parameter
  * Code Improvement: Updated the S.DS.P to v2.3.0
  * Code Improvement: Remove old outcommented code that was using AD PoSH CMDlets
  * Code Improvement: Updated the function "loadPoshModules" to support PowerShell 7 loading the GroupPolicy module
  * Code Improvement: Updated the function "portConnectionCheck"
  * Code Improvement: Updated the function "sendMailMessage" and removed capability to sign/encrypt e-mail being send due to complexity and external DLL
  * Code Improvement: Renamed the function "logging" to "writeToLog" and updated it
  * Code Improvement: Updated the function "testAdminRole"
  * Code Improvement: Added a new parameter -skipDAMembershipCheck to skip the Domain Admins membership check. This can be used if the required permissions have been assigned in a different way
  * Code Improvement: Added a new parameter -skipElevationCheck to skip the elevated session check
  * Code Improvement: Added a new parameter -ignoreProtectionForTESTAccounts to ignore the protection of not resetting the password within the Kerberos Ticket Lifetime when using the 'TEST/BOGUS KrbTgt Accounts'. This parameter will NOT work for 'PROD/REAL KrbTgt Accounts'
  * Code Improvement: Added function "testAccountIsSystemOnRWDC" to support running as "NT AUTHORITY\SYSTEM" within a scheduled task on a RWDC for the local AD forest only. Also updated the code to check for that
  * Code Improvement: Remove old outcommented code that was using AD PoSH CMDlets
  * Code Improvement: Replaced "Get-WmiObject" with "Get-CimInstance" to also support PowerShell 7.x
  * Code Improvement: Created additional function "determineUserAccountForRSoP" and updated its original logic to all use the current user if available and otherwise choose a random one that is a user and a member of either/both "Administrators" and/or "Domain Admins" group
  * Code Improvement: Created additional function "determineKerberosPolicySettings"
  * Code Improvement: Created additional function "buildAttributeSchemaMappingTables"
  * Code Improvement: Created additional function "sendMailWithAttachmentAndDisplayOutput"
  * Code Improvement: Improvement with regards to arrays/lists/objects to support strict mode
  * Code Improvement: Added function "Set-Window" to support resizing the Terminal Window from which PowerShell may be running
  * Code Improvement: Script detects from which console ("PowerShell", "PowerShell ISE", "Windows Terminal") it is being executed. Running the script from "PowerShell ISE IS NOT supported!"
  * Code Improvement: Renamed and updated function "setPasswordOfADAccount" to "editADAccount" to support the Password Reset Routine!
  * Code Improvement: Updated the code for the elevation logic to only try once to elevate and not continuously. If it fails the first time, the script will not retry again and aborts instead
  * Improved User Experience: Added additional explanation when the account 'krbtgt_AzureAD' is found due to the use of Hybrid Cloud Trust for SSO
  * Improved User Experience: Updated the structure of the "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml", added examples and simplified (Better documentation for XML configuration for mail)
  * Improved User Experience: throughout the text renamed all from 'KrbTgt TEST/BOGUS Accounts' to 'TEST/BOGUS KrbTgt Accounts' and from 'KrbTgt PROD/REAL Accounts' to 'PROD/REAL KrbTgt Accounts'
  * Improved User Experience: Added a bit more explanatory text about testing AD replication and the recommendation to not delete the TEST/BOGUS KrbTgt Accounts
  * Improved User Experience: Added a function "cleanUpOldLogs" to cleanup all the logs older than 60 (log files) / 10 (orphaned zip files) days
  * New Feature: Added a new scope option "4 - Scope of ANY KrbTgt in use by ANY DC - All RWDCs/RODCs in the AD Domain" for ALL RWDCs and ALL RODCs in an AD Domain (in addition to the existing scopes "1 - Scope of KrbTgt in use by all RWDCs in the AD Domain", "2 - Scope of KrbTgt in use by specific RODC - Single/Multiple RODC(s) in the AD Domain", "3 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain")
  * New Feature: (EXPERIMENTAL!) Added an option to monitor for Golden Tickets after a Krbtgt Password reset (Option "7 - Golden Ticket Monitor Mode | Checking Domain Controllers For Event ID 4769 With Specific Error Codes 0x6 (= KDC_ERR_C_PRINCIPAL_UNKNOWN = Client not found in Kerberos database), 0x1F (= KRB_AP_ERR_BAD_INTEGRITY = Integrity check on decrypted field failed) or 0x40 (= KDC_ERR_INVALID_SIG = The signature is invalid))
    (Inspired by https://github.com/YossiSassi/Invoke-PostKrbtgtResetMonitor)
  * New Feature: Adding support for "Password Reset Routine", which is scheduled/automated password reset of KrbTgt account password for either all RWDCs, all individual RODCs and/or specific RODCs
    (Inspired by https://github.com/MuscleBobBuff/KRBTGT/blob/main/AD%20-%20KRBTGT%20Reset%20Routines.ps1)
    1) Determines the current state, even if never used, redefines the new state and calculates the next 1st and 2nd password reset dates based upon the pre-defined intervals
	2) Resets the password of the targeted krbtgt account(s) the 1st time if the 1st calculated date equals TODAY
	3) resets the password of the targeted krbtgt account(s) the 2nd time if the 2nd calculated date equals TODAY
	4) cleans everything up after monitoring to allow for the routine to execute again a later time
  * Bug Fix: When a PowerShell Window was being used that did not have an elevated session, it restarts the script in the folder C:\Windows\System32 and the script would fail as it is not the folder the script is in. The script now restarts in the location where it is.
  * Bug Fix: In a specific section of the code, the script was searching for NTDS Settings objects in the default domain naming context, while that should be the configuration naming context. Parts of that code has been updated.
  * Bug Fix: Redefined the LDAP Connections and the "disposal" of those through the code. When processing more than about 1300 KrbTGT account (RWDC + many RODCs), the error "LDAP Server Unavailable" occurred.
  * Bug Fix: With Windows Server 2025 the Domain/Forest Functional Level is 10. The script failed to recognize that. It now recognizes it correctly
  * Bug Fix: The PowerShell CMDlets from the ActiveDirectory module DO recognize the 2025 FFL and DFL. The script DOES NOT use this, but instead uses S.DS.P.. The issue appears to be that MSFT did update the ActiveDirectory module to recognize the 2025 FFL/DFL, but they apparently did not update the S.DS.P. DLLs to do the same. The script itself now detects this and reports the correct FFL/DFL when it is 2025.
* v3.5, 2023-04-15 (Never Released), Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
  * Improved User Experience: Added banner to output
  * Code Improvement: Implemented StrictMode Latest Version (Tested On PoSH 5.x And 7.x)
  * Bug Fix: Fixed code to support StrictMode
  * Bug Fix: Updated renamed variable $rootDomain to $rootADDomainInADForest
  * Bug Fix: Updated Filter to get RWDCs from [$_."msDS-isRODC" -eq $false -Or $_.primaryGroupID -eq "516"] to [$_."msDS-isRODC" -eq $false -And $_.primaryGroupID -eq "516" -And $_.rIDSetReferences -ne $null]
  * Bug Fix: Updated Filter to get RODCs from [$_."msDS-isRODC" -eq $true -Or $_.primaryGroupID -eq "521"] to [$_."msDS-isRODC" -eq $true -And $_.primaryGroupID -eq "521" -And $_."msDS-KrbTgtLink" -match "^CN=krbtgt_\d.*"]
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
  * Code Improvement: Removed the language specific error checking. Has been replaced with another check. This solution also resolved another issue when checking if a (RW/RO)DC was available or not
* v2.2, 2019-02-12, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Code Improvement: Instead of searching for "Domain Admins" or "Enterprise Admins" membership, it resolves the default RIDs of those groups, combined with the corresponding domain SID, to the actual name of those domain groups. This helps in supporting non-english names of those domain groups
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
  * Code Improvement: Modified rpcping.exe call to use "-u 9 -a connect" parameters to accomodate tighter RPC security settings as specified in DISA STIG ID: 5.124 Rule ID: SV-32395r1_rule , Vuln ID: V-14254 (thanks Adam Haynes)
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

&nbsp;

## SYNOPSIS/DESCRIPTION

This PoSH Script Resets The KrbTgt Password For RWDCs And RODCs In A Controlled Manner.

This PoSH script provides the following functions:

* Single Password Reset for the KrbTgt account in use by RWDCs in a specific AD domain, using either TEST/BOGUS or PROD/REAL KrbTgt accounts
* Single Password Reset for the KrbTgt account in use by an individual RODC in a specific AD domain, using either TEST/BOGUS or PROD/REAL KrbTgt accounts
  * A single RODC in a specific AD domain
  * A specific list of RODCs in a specific AD domain
  * All RODCs in a specific AD domain
* Resetting the password/keys of the KrbTgt Account can be done for multiple reasons such as for example:
  * From a security perspective as mentioned in <https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/>
  * From an AD recovery perspective as mentioned in <https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password>
* For all scenarios, an informational mode, which is mode 1 with no changes
* For all scenarios, a simulation mode, which is mode 2 where replication is tested through the replication of a temporary canary object that is created and deleted afterwards. No Password Resets involved here as the temporary canary object is a contact object. This is perfect to test replication within an AD domain, assuming all DCs involved are reachable.
* For all scenarios, a simulation mode, which is mode 3 where NO password reset of the chosen TEST/BOGUS KrbTgt account occurs. Basically this just checks the status of the objects on scoped DCs. NOTHING is changed. Can be scoped for RWDCs and RODCs (single, multiple, all)
* For all scenarios, a real reset mode, which is mode 4 where the password reset of the chosen TEST/BOGUS KrbTgt account is actually executed and replication of it is monitored through the environment for its duration. Can be scoped for RWDCs and RODCs (single, multiple, all)
* For all scenarios, a simulation mode, which is mode 5 where NO password reset of the chosen PROD/REAL KrbTgt account occurs. Basically this just checks the status of the objects on scoped DCs. NOTHING is changed. Can be scoped for RWDCs and RODCs (single, multiple, all)
* For all scenarios, a real reset mode, which is mode 6 where the password reset of the chosen PROD/REAL KrbTgt account is actually executed and replication of it is monitored through the environment for its duration
* For all scenarios, failed golden ticket monitoring, which is mode 7 where all DCs in scope are contacted to get information from the Security Event Log to determine if failed golden tickets are used or not
* The creation of TEST/BOGUS KrbTgt Accounts, which is mode 8
* The deletion of TEST/BOGUS KrbTgt Accounts, which is mode 9
* It is possible to run the script in a scheduled and automated manner by specifying the correct parameters and the correct information for those parameters. This can then be used in a scheduled task that runs on a very specific interval, e.g. every week or every month, or every 6 months. To understand what happens and how, instead of immediately targeting the PROD/REAL KrbTgt account(s), you have the possibility to familiarize yourself and try it out by using the TEST/BOGUS KrbTgt account(s) WITHOUT ANY impact!
* In addition to the simple scheduled and automated manner of running the script, it is possible to configure the scheduled task to run every day in combination with a pre-defined Password Reset Routine which has its parameters defined in the configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml". An example could be to perform the first password reset 7 days after the last password reset, and the second password reset 2 days after the first password reset
* When running in a scheduled and automated manner, it is possible to have the log file (zipped!) mailed to some defined mail address(es). It also works when running it manually, as long as the correct parameter is used and all prerequisites are in place
* When mailing of the log file (zipped!) is needed in ANY way, a configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml" is needed with settings to control mailing behavior. The configuration XML file is expected to be in the same folder as the script itself. See below in the NOTES for the structure

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
  * For RODCs it uses the PROD/REAL krbtgt account "krbtgt_&lt;Numeric Value&gt;" (RODC Specific)
* In mode 7, depending on the scope, DCs are contacted to get all events with event ID 4769 generated after the last password set date/time of the Krbtgt account, and filter specifically on those events with error code 0x6 (= KDC_ERR_C_PRINCIPAL_UNKNOWN = Client not found in Kerberos database), 0x1F (= KRB_AP_ERR_BAD_INTEGRITY = Integrity check on decrypted field failed) or 0x40 (= KDC_ERR_INVALID_SIG = The signature is invalid). When such an event if found, the information recorded in a separate log file.
  REMARK: Event ID 4769 is generated every time the Key Distribution Center (KDC) receives a Kerberos Ticket Granting Service (TGS) ticket request
  <https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769>
* In mode 8, for RWDCs it creates (in disabled state!) the TEST/BOGUS krbtgt account "krbtgt_TEST" and adds it to the AD group "Denied RODC Password Replication Group". If any RODC exists in the targeted AD domain, it reads the attribute "msDS-KrbTgtLink" of each RODC computer account to determine the RODC specific krbtgt account and creates (in disabled state!) the TEST/BOGUS krbtgt account "krbtgt_&lt;Numeric Value&gt;_TEST" and adds it to the AD group "Allowed RODC Password Replication Group"
* In mode 9, for RWDCs it deletes the TEST/BOGUS krbtgt account "krbtgt_TEST" if it exists. If any RODC exists in the targeted AD domain, it reads the attribute "msDS-KrbTgtLink" of each RODC computer account to determine the RODC specific krbtgt account and deletes the TEST/BOGUS krbtgt account "krbtgt_&lt;Numeric Value&gt;_TEST" if it exists.
* In mode 2, 3, 4, 5 or 6, if a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if the change made reached it or not. In case of mode 7 no events will be gathered from the security event log.
* In mode 2 when performing the "replicate single object" operation, it will always be for the full object, no matter if the remote DC is an RWDC or an RODC
* In mode 3, 4, 5 or 6 when performing the "replicate single object" operation, it will always be for the full object, if the remote DC is an RWDC. If the remote DC is an RODC it will always be for the partial object and more specifically "secrets only"
* When targeting the krbtgt account (TEST/BOGUS or PROD/REAL) in use by all the RWDCs, the originating RWDC is the RWDC with the PDC FSMO and all other available/reachable RWDCs will be checked against to see if the change has reached them. No RODCs are involved as those do not use the krbtgt account in use by the RWDCs and also do not store/cache its password.
* When targeting the krbtgt account (TEST/BOGUS or PROD/REAL) in use by an RODC, the originating RWDC is the direct replication RWDC if available/reachable and when not available the RWDC with the PDC FSMO is used as the originating RWDC. Only the RODC that uses the specific krbtgt account is checked against to see if the change has reached them, but only if the RODCs is available/reachable. If the RODC itself is not available, then the RWDC with the PDC FSMO is used as the originating RWDC and the change will eventually replicate to the RODC
* If the operating system attribute of an RODC computer account does not have a value, it is determined to be unknown (not a real RODC), and therefore something else. It could for example be a Riverbed appliance in "RODC mode".
* The only DC that knows what the real replication partner is of an RODC, is the RODC itself. Only the RODC manages a connection object that only exists in the AD database of the RODC and does not replicate out to other DCs as RODCs do not support outbound replication. Therefore, assuming the RODC is available, the CO is looked up in the RODC AD database and from that CO, the "source" server is determined. In case the RODC is not available or its "source" server is not available, the RWDC with the PDC FSMO is used to reset the password of the krbtgt account in use by that RODC. If the RODC is available a check will be done against its database, and if not available the check is skipped

&nbsp;

## PARAMETER(S)

noInfo

* With this parameter it is possible to skip the information at the beginning of the script when running the script in an automated manner such as in a Scheduled Task

modeOfOperation

* With this parameter it is possible to specify the mode of operation for the script. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen! Accepted values are: "infoMode", "simulModeCanaryObject", "simulModeKrbTgtTestAccountsWhatIf", "resetModeKrbTgtTestAccountsResetOnce", "simulModeKrbTgtProdAccountsWhatIf", "resetModeKrbTgtProdAccountsResetOnce", "monitorForGoldenTicket"

targetedADforestFQDN

* With this parameter it is possible to specify the FQDN of an AD forest that will be targeted. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

targetedADdomainFQDN

* With this parameter it is possible to specify the FQDN of an AD domain that will be targeted within the specified AD forest. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

targetKrbTgtAccountScope

* With this parameter it is possible to specify the scope of the targeted KrbTgt account. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen! Accepted values are: "allRWDCs", "allRODCs", "specificRODCs", "allRWDCsAndRODCs"

targetRODCFQDNList

* With this parameter it is possible to specify one or more RODCs through a comma-separated list. This parameter is ONLY needed when the targetKrbTgtAccountScope is set to specificRODCs. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

continueOps

* With this parameter it is possible to specify the script should continue where it is needed to confirm the operation depending of whether there is impact or not. If the script determines there is impact, the script will abort to prevent impact. Only when running ON-DEMAND without any parameters will it be possible to continue and still have domain wide impact, in other words ignore there is impact. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

execResetRoutine

* With this parameter it is possible to execute the password reset routine according to the defined parameters. In addition to using this parameter, the configuration XML file must be configured with all related parameters (intervals and attribute names) and the node "resetRoutineEnabled" must be configured with TRUE.

ignoreProtectionForTESTAccounts

* With this parameter it is possible to ignore the protection of not resetting the password within the Kerberos Ticket Lifetime when using the 'TEST/BOGUS KrbTgt Accounts'. This parameter will NOT work for 'PROD/REAL KrbTgt Accounts'

skipDAMembershipCheck

* With this parameter it is possible to skip the Domain Admins membership check. This can be used if the required permissions have been assigned in a different way. This means the required permissions to create and/or delete 'TEST/BOGUS KrbTgt Accounts' in the USERS container, reset of the password of either 'PROD/REAL KrbTgt Accounts' and/or 'TEST/BOGUS KrbTgt Accounts', to execute replicate single object must be assigned differently. When not assigned in a different way, while using this parameter and the account is not a member of the Domain Admins group, the targeted action(s) will most likely fail

skipElevationCheck

* With this parameter it is possible to skip the elevated session check

sendMailWithLogFile

* With this parameter it is possible to specify the script should mail the LOG file at any moment when the script stops running, whether it finished successfully or due to encountered issue(s).In addition to using this parameter, the configuration XML file must be configured with all mail related parameters and the node "sendMail" must be configured with TRUE.

&nbsp;

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

Execute The Script - Automated Password Reset Routine And Sending The Log File Through Mail - Mode 4 With All RWDCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -sendMailWithLogFile -execResetRoutine -modeOfOperation resetModeKrbTgtTestAccountsResetOnce -targetKrbTgtAccountScope allRWDCs -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -continueOps
```

Execute The Script - Automated Password Reset Routine And Sending The Log File Through Mail - Mode 4 With All RWDCs And All RODCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -sendMailWithLogFile -execResetRoutine -modeOfOperation resetModeKrbTgtTestAccountsResetOnce -targetKrbTgtAccountScope allRWDCsAndRODCs -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -continueOps
```

Execute The Script - Automated Password Reset Routine And Sending The Log File Through Mail - Mode 6 With All RWDCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -sendMailWithLogFile -execResetRoutine -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetKrbTgtAccountScope allRWDCs -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -continueOps
```

Execute The Script - Automated Password Reset Routine And Sending The Log File Through Mail - Mode 6 With All RODCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -sendMailWithLogFile -execResetRoutine -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetKrbTgtAccountScope allRODCs -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -continueOps
```

Execute The Script - Automated Password Reset Routine And Sending The Log File Through Mail - Mode 6 With All RWDCs And All RODCs As Scope

``` powershell
.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -sendMailWithLogFile -execResetRoutine -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetKrbTgtAccountScope allRWDCsAndRODCs -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -continueOps
```

&nbsp;

## NOTES

* Minimum required PowerShell version: 5.1 (it is being checked and enforced!)
* Required PoSH CMDlets: GPMC PoSH CMDlets on all targeted RWDCs!!! (and the S.DS.P Posh CMDlets are INCLUDED in this script!)
* The script must either be executed from PowerShell or Windows Terminal. PowerShell ISE IS NOT supported!
* To execute this script, the account running the script MUST be a member of the "Domain Admins" or Administrators group in the targeted AD domain.
* If the account used is from another AD domain in the same AD forest, then the account running the script MUST be a member of the "Enterprise Admins" group in the AD forest or Administrators group in the targeted AD domain. For all AD domains in the same AD forest, membership of the "Enterprise Admins" group is easier as by default it is a member of the Administrators group in every AD domain in the AD forest
* If the account used is from another AD domain in another AD forest, then the account running the script MUST be a member of the "Administrators" group in the targeted AD domain. This also applies to any other target AD domain in that same AD forest
* This is due to the reset of the password for the targeted KrbTgt account(s) and forcing (single object) replication between DCs
* Testing "Domain Admins" membership is done through "IsInRole" method as the group is domain specific
* Testing "Enterprise Admins" membership is done through "IsInRole" method as the group is forest specific
* Testing "Administrators" membership cannot be done through "IsInRole" method as the group exist in every AD domain with the same SID. To still test for required permissions in that case, the value of the Description attribute of the KRBTGT account is copied into the Title attribute and cleared afterwards. If both those actions succeed it is proven the required permissions are in place!
* Script Has StrictMode Enabled For Latest Version - Tested With PowerShell 7.x
* If User Account Control (UAC) is in effect (i.e. enabled) the script MUST be executed in an elevated Powershell Command Prompt Window!
* When running the script on-demand with an account that does have the correct permissions, the script will ask for credentials with the correct permissions
* When running the script automated with an account that does have the correct permissions, the script will NOT ask for credentials with the correct permissions. It will just stop. Therefore in an automated manner, the running account MUST have the correct permissions!
* The Configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml" is needed when e-mailing of the log file (zipped!) is required and/or the password reset routine needs to be used. This is required as the XML file has the required configuration for both. This allows the script to be updated without impacting environment specific configuration related to mailing and/or password reset routine.
* To use the Configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml" and its settings, the node "useXMLConfigFileSettings" must be configured with "TRUE"
* To support mailing of the log file after the script completes, the Configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml" must be configured with the settings of the e-mail provider, the node "sendMail" MUST be configured with "TRUE" and the parameter "sendMailWithLogFile" must also be used with the script
* To support the password reset routine, the Configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml" must be configured with the settings supporting that feature, the node "resetRoutineEnabled" MUST be configured with "TRUE" and the parameter "execResetRoutine" must also be used with the script. In addition, as the password reset routing is supposed to be fully automated, all the parameters to support full automation must also be used with the script. See the examples.
* When using a scheduled task running as NT AUTHORITY\SYSTEM, make sure to configure that scheduled task on the RWDC with the PDC FSMO role. The reason for this is that NT AUTHORITY\SYSTEM, although highly privileged when running on an RWDC can only make changes against its own database instance and not against a remote database instance on another RWDC! When it concerns the KrbTgt account of RODCs, and when running as NT AUTHORITY\SYSTEM, instead of using the real source RWDC of the RODC, the RWDC with the PDC FSMO will be used instead for the previously mentioned reason. As an additional tip, make sure the scheduled task is configured in a GPO that follows the RWDC with the PDC FSMO role. To be sure everything runs correctly without issue, try it out first manually using PSEXEC -I -S POWERSHELL.EXE and then running the script with all the required parameters.
* As e-mail providers, Office 365, Gmail and a multitude of SMTP providers are supported. See the Configuration XML file for examples
* When using Office 365, modern authentication is required using an application client id with ether a client secret or a client certificate.
  * To create a self-signed certificate, see: <https://gist.github.com/zjorz/8f67712d259c440140e9d254322286c0>
  * To create an application in Entra ID with the required configuration, see: <https://gist.github.com/zjorz/ad253c009b080c91494e2a64981aca6b>
* When using application client id with a client certificate, the credential running the script must have READ access to the private key of the certificate being used. The certificate should be located in the (Personal) Local Computer Store

&nbsp;

## CONFIGURATION File

Use sample in: <https://github.com/zjorz/Public-AD-Scripts/blob/master/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml>

&nbsp;

## SAMPLE SCENARIO(S) FOR PASSWORD RESET Routine

* 1stInterval = 3 and 2ndInterval = 1, the MINIMUM values
* Password Was Reset A (Very) Long Time Ago, i.e., 100 days ago

&nbsp

* DAY0:
  * read lastResetDate =  pwdLastSet = DAY0 - 100 (ie 100 days ago)
  * read state = EMPTY
  * read 1stResetDate = attribute_for_1stResetDate = EMPTY
  * read 2ndResetDate = attribute_for_2ndResetDate = EMPTY
  * set state = 0
  * set 1stResetDate = attribute_for_1stResetDate = DAY0 - 100 + 3 = DAY0 - 97 &lt; TODAY therefore TODAY (DAY0) + 3 = DAY3
  * set 2ndResetDate = attribute_for_2ndResetDate = DAY0 - 100 + 3 + 1 = DAY0 - 96 &lt; TODAY therefore TODAY (DAY0) + 3 + 1 = DAY4
  * PWD Reset = FALSE
* DAY1:
  * read lastResetDate =  pwdLastSet = DAY0 - 100 (ie 100 days ago)
  * read state = 0
  * read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
  * read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
  * PWD Reset = FALSE
* DAY2:
  * read lastResetDate =  pwdLastSet = DAY0 - 100 (ie 100 days ago)
  * read state = 0
  * read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
  * read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
  * PWD Reset = FALSE
* DAY3:
  * read lastResetDate =  pwdLastSet = DAY0 - 100 (ie 100 days ago)
  * read state = 0
  * read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
  * read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
  * set state = 1
  * PWD Reset = TRUE
* DAY4:
  * read lastResetDate =  pwdLastSet = DAY3
  * read state = 1
  * read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
  * read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
  * set state = 2
  * PWD Reset = TRUE
* DAY5:
  * read lastResetDate =  pwdLastSet = DAY4
  * read state = 2
  * read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
  * read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
  * set state = EMPTY
  * set 1stResetDate = attribute_for_1stResetDate = EMPTY
  * set 2ndResetDate = attribute_for_2ndResetDate = EMPTY
  * PWD Reset = FALSE
* DAY6:
  * read lastResetDate =  pwdLastSet = DAY4
  * read state = EMPTY
  * read 1stResetDate = attribute_for_1stResetDate = EMPTY
  * read 2ndResetDate = attribute_for_2ndResetDate = EMPTY
  * set state = 0
  * set 1stResetDate = attribute_for_1stResetDate = DAY4 + 3 = DAY7
  * set 2ndResetDate = attribute_for_2ndResetDate = DAY4 + 3 + 1 = DAY8
  * PWD Reset = FALSE

&nbsp

* 1stInterval = 3 and 2ndInterval = 1, the MINIMUM values
* Password Was Reset A Few Days Ago

&nbsp

* DAY0:
  * 1stResetDate = attribute_for_1stResetDate = DAY0 - 1
  * 2ndResetDate = attribute_for_2ndResetDate = lastResetDate = pwdLastSet = TODAY
  * lastResetDate = pwdLastSet = TODAY = DAY0
  * state set to 2
  * PWD Reset = TRUE
* DAY1:
  * read lastResetDate =  pwdLastSet = DAY0
  * read state = 2
  * read 1stResetDate = attribute_for_1stResetDate = DAY0 - 1
  * read 2ndResetDate = attribute_for_2ndResetDate = DAY0
  * set state = EMPTY
  * set 1stResetDate = attribute_for_1stResetDate = EMPTY
  * set 2ndResetDate = attribute_for_2ndResetDate = EMPTY
  * PWD Reset = FALSE
* DAY2:
  * read lastResetDate = pwdLastSet = DAY0
  * read state = EMPTY
  * read 1stResetDate = attribute_for_1stResetDate = EMPTY
  * read 2ndResetDate = attribute_for_2ndResetDate = EMPTY
  * set state = 0
  * set 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3 &gt; TODAY therefore DAY0 + 3 = DAY3
  * set 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4 &gt; TODAY therefore DAY0 + 3 + 1 = DAY4
  * PWD Reset = FALSE
* DAY3:
  * read lastResetDate = pwdLastSet = DAY0
  * read state = 0
  * read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
  * read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
  * set state = 1
  * PWD Reset = TRUE
* DAY4:
  * read lastResetDate = pwdLastSet = DAY0 + 3 = DAY3
  * read state = 1
  * read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
  * read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
  * set state = 2
  * PWD Reset = TRUE
* DAY5:
  * read lastResetDate =  pwdLastSet = DAY0 + 3 + 1 = DAY4
  * read state = 2
  * read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
  * read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
  * set state = EMPTY
  * set 1stResetDate = attribute_for_1stResetDate = EMPTY
  * set 2ndResetDate = attribute_for_2ndResetDate = EMPTY
  * PWD Reset = FALSE

&nbsp

* Example Scheduled Task Configuration For The Password Reset Routine Targeting The Test/Bogus KrbTgt Accounts Of Both RWDCs And RODCs In The Specified AD Forest/Domain
  * ACTION - Program/Script (PoSH v5.1) = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  * ACTION - Program/Script (PoSH v7.x) = "C:\Program Files\PowerShell\7\pwsh.exe"
  * ACTION - Arguments = -NoProfile -NonInterActive -Command "D:\TEMP\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -sendMailWithLogFile -execResetRoutine -modeOfOperation resetModeKrbTgtTestAccountsResetOnce -targetKrbTgtAccountScope allRWDCsAndRODCs -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHLD.DOMAIN.COM -continueOps"
  * ACTION - Start In = D:\TEMP

&nbsp;

## SCREENSHOTS

See blog <https://jorgequestforknowledge.wordpress.com/category/active-directory-domain-services-adds/krbtgt-account/>

### RUNNING THE SCRIPT INTERACTIVELY ON-DEMAND

[Running The Script Interactively On-Demand - SAMPLE LOG FILE](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_SAMPLE-LOG-FILE.zip)

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_01.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_02.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_03.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_04.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_05.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_06.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_07.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_08.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_09.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_10.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_11.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_12.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_13.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_14.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_15.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_16.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_17.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_18.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_19.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_20.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_21.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_22.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_23.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_24.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_25.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_26.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_27.png "Running The Script Interactively On-Demand")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Interactive_28.png "Running The Script Interactively On-Demand")

&nbsp;

### RUNNING THE SCRIPT IN SCHEDULED TASK EVERY HOUR

For The AD DOMAIN "IAMTEC.NET", In The AD FOREST "IAMTEC.NET" (Remark: Look at the time in the upper right corner)

[Running The Script In Scheduled Tasks Every Hour - SAMPLE LOG FILES - IAMTEC.NET](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_SAMPLE-LOG-FILEs_IAMTEC.NET.zip)

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_IAMTEC.NET_01.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_IAMTEC.NET_02.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_IAMTEC.NET_03.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_IAMTEC.NET_04.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_IAMTEC.NET_05.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_IAMTEC.NET_06.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_IAMTEC.NET_07.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_IAMTEC.NET_08.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_IAMTEC.NET_09.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_IAMTEC.NET_10.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_IAMTEC.NET_11.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_IAMTEC.NET_12.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_IAMTEC.NET_13.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

&nbsp;

For The AD DOMAIN "CHLD.IAMTEC.NET", In The AD FOREST "IAMTEC.NET" (Remark: Look at the time in the upper right corner)

[Running The Script In Scheduled Tasks Every Hour - SAMPLE LOG FILES - CHLD.IAMTEC.NET](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_SAMPLE-LOG-FILEs_CHLD.IAMTEC.NET.zip)

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_CHLD.IAMTEC.NET_01.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_CHLD.IAMTEC.NET_02.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_CHLD.IAMTEC.NET_03.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_CHLD.IAMTEC.NET_04.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_CHLD.IAMTEC.NET_05.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_CHLD.IAMTEC.NET_06.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_CHLD.IAMTEC.NET_07.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_CHLD.IAMTEC.NET_08.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_CHLD.IAMTEC.NET_09.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_CHLD.IAMTEC.NET_10.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_CHLD.IAMTEC.NET_11.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_CHLD.IAMTEC.NET_12.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_CHLD.IAMTEC.NET_13.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

&nbsp;

For The AD DOMAIN "TROOT.NET", In The AD FOREST "IAMTEC.NET" (Remark: Look at the time in the upper right corner)

[Running The Script In Scheduled Tasks Every Hour - SAMPLE LOG FILES - TROOT.NET](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_SAMPLE-LOG-FILEs_TROOT.NET.zip)

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_TROOT.NET_01.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_TROOT.NET_02.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_TROOT.NET_03.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_TROOT.NET_04.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_TROOT.NET_05.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_TROOT.NET_06.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_TROOT.NET_07.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_TROOT.NET_08.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_TROOT.NET_09.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_TROOT.NET_10.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_TROOT.NET_11.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_TROOT.NET_12.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Regular_TROOT.NET_13.png "Running The Script In Scheduled Task WITHOUT The Password Reset Routine")

&nbsp;

### RUNNING THE SCRIPT IN SCHEDULED TASK EVERY DAY WITH THE PASSWORD RESET ROUTINE

#### GENERIC

This applies every time the script executes.

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_GENERIC_01.png "Running The Script In Scheduled Task WITH The Password Reset Routine - GENERIC")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_GENERIC_02.png "Running The Script In Scheduled Task WITH The Password Reset Routine - GENERIC")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_GENERIC_03.png "Running The Script In Scheduled Task WITH The Password Reset Routine - GENERIC")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_GENERIC_04.png "Running The Script In Scheduled Task WITH The Password Reset Routine - GENERIC")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_GENERIC_05.png "Running The Script In Scheduled Task WITH The Password Reset Routine - GENERIC")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_GENERIC_06.png "Running The Script In Scheduled Task WITH The Password Reset Routine - GENERIC")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_GENERIC_07.png "Running The Script In Scheduled Task WITH The Password Reset Routine - GENERIC")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_GENERIC_08.png "Running The Script In Scheduled Task WITH The Password Reset Routine - GENERIC")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_GENERIC_09.png "Running The Script In Scheduled Task WITH The Password Reset Routine - GENERIC")

&nbsp;

#### ANOMALY DETECTIONS

This applies when the script detects an anomaly in the data of the specific KRBTGT account that is used by the Password Reset Routine.

ANOMALY #01 (2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - ANOMALY DETECTION # 01](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_ANOMALY-DETECTION-01.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_ANOMALY_01.png "Running The Script In Scheduled Task WITH The Password Reset Routine - ANOMALIES")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_ANOMALY_02.png "Running The Script In Scheduled Task WITH The Password Reset Routine - ANOMALIES")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_ANOMALY_03.png "Running The Script In Scheduled Task WITH The Password Reset Routine - ANOMALIES")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_ANOMALY_04.png "Running The Script In Scheduled Task WITH The Password Reset Routine - ANOMALIES")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_ANOMALY_05.png "Running The Script In Scheduled Task WITH The Password Reset Routine - ANOMALIES")

&nbsp;

ANOMALY #02 (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - ANOMALY DETECTION # 02](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_ANOMALY-DETECTION-02.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_ANOMALY_06.png "Running The Script In Scheduled Task WITH The Password Reset Routine - ANOMALIES")

&nbsp;

ANOMALY #03 (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - ANOMALY DETECTION # 03](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_ANOMALY-DETECTION-03.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_ANOMALY_07.png "Running The Script In Scheduled Task WITH The Password Reset Routine - ANOMALIES")

&nbsp;

ANOMALY #04 (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - ANOMALY DETECTION # 04](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_ANOMALY-DETECTION-04.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_ANOMALY_08.png "Running The Script In Scheduled Task WITH The Password Reset Routine - ANOMALIES")

&nbsp;

ANOMALY #05 (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - ANOMALY DETECTION # 05](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_ANOMALY-DETECTION-05.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_ANOMALY_09.png "Running The Script In Scheduled Task WITH The Password Reset Routine - ANOMALIES")

&nbsp;

ANOMALY #06 (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - ANOMALY DETECTION # 06](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_ANOMALY-DETECTION-06.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_ANOMALY_10.png "Running The Script In Scheduled Task WITH The Password Reset Routine - ANOMALIES")

&nbsp;

ANOMALY #07 (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - ANOMALY DETECTION # 07](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_ANOMALY-DETECTION-07.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_ANOMALY_11.png "Running The Script In Scheduled Task WITH The Password Reset Routine - ANOMALIES")

&nbsp;

ANOMALY #08 (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - ANOMALY DETECTION # 08](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_ANOMALY-DETECTION-08.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_ANOMALY_12.png "Running The Script In Scheduled Task WITH The Password Reset Routine - ANOMALIES")

&nbsp;

ANOMALY #09 (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - ANOMALY DETECTION # 09](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_ANOMALY-DETECTION-09.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_ANOMALY_13.png "Running The Script In Scheduled Task WITH The Password Reset Routine - ANOMALIES")

&nbsp;

#### NORMAL RUNS

This applies when the script executes as configured without any issues related to the Password Reset Routine.

FROM State "EMPTY" to "0": Configuring Action Dates For THIS Account | NO Password Reset (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - #1: State EMPTY To 0](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_NORMAL-RUN-01.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_01.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_02.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

&nbsp;

NO STATE CHANGE: Nothing Done As Condition Is Not Yet Met (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - #2: NO State Change](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_NORMAL-RUN-02.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_03.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_04.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

&nbsp;

NO STATE CHANGE: Nothing Done As Condition Is Not Yet Met (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - #3: NO State Change](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_NORMAL-RUN-03.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_05.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_06.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

&nbsp;

NO STATE CHANGE: Nothing Done As Condition Is Not Yet Met (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - #4: NO State Change](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_NORMAL-RUN-04.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_07.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_08.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

&nbsp;

FROM State "0" to "1": Primary Password Reset For THIS Account (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - #5: State 0 To 1](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_NORMAL-RUN-05.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_09.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_10.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

&nbsp;

FROM State "1" to "2": Secondary Password Reset For THIS Account (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - #6: State 1 To 2](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_NORMAL-RUN-06.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_11.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_12.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

&nbsp;

FROM State "2" to "EMPTY": Resetting Process To Initial State For Another Cycle For THIS Account (ONLY 1 of the 2 KRBTGT Accounts Displayed)

[Running The Script In Scheduled Tasks Every Day With Password Reset Routine - SAMPLE LOG FILE - #7: State 2 To EMPTY](SampleLogs/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Scheduled-Password-Reset-Routine_SAMPLE-LOG-FILE_NORMAL-RUN-07.log.txt)

REMARK: To open the link in a new browser tab, on Windows and Linux "CTRL"+"Click Link" and on MacOS "CMD"+"Click Link".

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_13.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

![Alt](Images/Reset-KrbTgt-Password-For-RWDCs-And-RODCs_Password-Reset-Routine_NORMAL-RUN_14.png "Running The Script In Scheduled Task WITH The Password Reset Routine - NORMAL RUN")

&nbsp;