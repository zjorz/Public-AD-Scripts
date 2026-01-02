###
# Parameters Used By Script
###
Param (
	[switch]$noInfo,
	[ValidateSet("infoMode", "simulModeCanaryObject", "simulModeKrbTgtTestAccountsWhatIf", "resetModeKrbTgtTestAccountsResetOnce", "simulModeKrbTgtProdAccountsWhatIf", "resetModeKrbTgtProdAccountsResetOnce", "monitorForGoldenTicket")]
	[string]$modeOfOperation,
	[string]$targetedADforestFQDN,
	[string]$targetedADdomainFQDN,
	[ValidateSet("allRWDCs", "allRODCs", "specificRODCs", "allRWDCsAndRODCs")]
	[string]$targetKrbTgtAccountScope,
	[string[]]$targetRODCFQDNList,
	[switch]$continueOps,
	[switch]$ignoreProtectionForTESTAccounts,
	[switch]$skipDAMembershipCheck,
	[switch]$skipElevationCheck,
	[switch]$execResetRoutine,
	[switch]$sendMailWithLogFile
)

###
# Version Of Script
###
$version = "v3.6, 2026-01-01"

<#
	AUTHOR
		Written By........................: Jorge de Almeida Pinto [Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:]
		Re-Written By.....................: N.A.
		Company...........................: IAMTEC >> Identity | Security | Recovery [https://www.iamtec.eu/]
		Blog..............................: Jorge's Quest For Knowledge [http://jorgequestforknowledge.wordpress.com/]
		For Feedback/Questions/Requests...: [GITHUB](https://github.com/zjorz/Public-AD-Scripts/issues) (<= PREFERRED) Or mail to "scripts DOT gallery AT iamtec.eu"
			--> Please Describe Your Scenario As Best As Possible With As Much Detail As Possible.
			--> If Applicable Describe What Does and/Or Does Not Work.
			--> If Applicable Describe What Should Be/Work Different And Explain Why/How.
			--> Please Add Screendumps.

	ORIGINAL SOURCES
		- https://github.com/zjorz/Public-AD-Scripts/blob/master/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.md
		- https://github.com/zjorz/Public-AD-Scripts/blob/master/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1
		- https://jorgequestforknowledge.wordpress.com/category/active-directory-domain-services-adds/krbtgt-account/

	DISCLAIMER
		- The script is FREEWARE, you are free to distribute/update it, but always refer to the original source(s) as the location where you got it
		- This script is furnished "AS IS". NO warranty is expressed or implied!
		- I HAVE NOT tested it in every scenario or environment
		- ALWAYS TEST FIRST in lab environment to see if it meets your needs!
		- Use this script at YOUR OWN RISK! YOU ARE RESPONSIBLE FOR ANY OUTCOME/RESULT BY USING THIS SCRIPT!
		- I DO NOT warrant this script to be fit for any purpose, use or environment!
		- I have tried to check everything that needed to be checked, but I DO NOT guarantee the script does not have bugs!
		- I DO NOT guarantee the script will not damage or destroy your system(s), environment or anything else due to improper use or bugs!
		- I DO NOT accept liability in any way when making mistakes, use the script wrong or in any other way where damage is caused to your environment/systems!
		- If you do not accept these terms DO NOT use the script in any way and delete it immediately!

	TODO
		- N.A.

	KNOWN ISSUES/BUGS
		- The script is NOT digitally signed
		- Make sure to unblock the script using the 'Unblock-File' CMDLet after downloading from the internet
		- When targeting a remote AD forest for which no trust exist with the AD forest the running account belongs to, the public profile of WinRM may be
			used. In that case the PSSession for 'Get-GPOReport' may fail due to the default firewall exception only allowing access from remote computers
			on the same local subnet. In that case the default 'MaxTicketAge' (default 10 hours) and 'MaxClockSkew' (default 5 minutes) is used instead.
			You may see the following error:
			[<FQDN TARGET DC>] Connecting to remote server <FQDN TARGET DC> failed with the following error message : WinRM cannot complete the operation.
			Verify that the specified computer name is valid, that the computer is accessible over the network, and that a firewall exception for the WinRM
			service is enabled and allows access from this computer. By default, the WinRM firewall exception for public profiles limits access to remote
			computers within the same local subnet. For more information, see the about_Remote_Troubleshooting Help topic.
			+ CategoryInfo          : OpenError: (<FQDN TARGET DC>:String) [], PSRemotingTransportException
			+ FullyQualifiedErrorId : WinRMOperationTimeout,PSSessionStateBroken
		- Although this script can be used in an environment with Windows Server 2000/2003 RWDCs, it is NOT supported to do this. Windows Server
			2000/2003 RWDCs cannot do KDC PAC validation using the previous (N-1) krbtgt password. Those RWDCs only attempt that with the current
			(N) password. That means that in the subset of KRB AP exchanges where KDC PAC validation is performed, authentication issues could be
			experienced because the target server gets a PAC validation error when asking the KDC (domain controller) to validate the KDC signature
			of the PAC that is inside the service ticket that was presented by the client to the server. This problem would potentially persist
			for the lifetime of the service ticket(s). It is also highly recommended NOT to use products that have reached their end support.
			Please upgrade as soon as possible.
		- This is not related to this script. When increasing the DFL from Windows Server 2003 to any higher level, the password of the KrbTgt
			Account will be reset automatically due to the introduction of AES encryption for Kerberos and the requirement to regenerate new keys
			for DES, RC4, AES128, AES256!
		- Reachability/Availability of a DC determined by the following factors:
			- Routing from where the script is executed to the target DC is possible
			- Port connection (LDAP 389) from where the script is executed to the target RWDC is possible
			- When testing the port connection, the target RWDC responds back fast enough within the defined timeout (default 1000 ms)
		- When simulating the password reset (mode 3 for TEST/BOGUS KrbTgt accounts, and mode 5 for PROD/REAL KrbTgt accounts), the script still performs an
			AD convergence check as if a password reset had occurred for the targeted KrbTgt account(s). The script will in this case log clearly:
			"REMARK: What If Mode! NO PASSWORD RESET HAS OCCURRED!"
		- When executing the Password Reset Routing (mode 4 for TEST/BOGUS KrbTgt accounts, and mode 6 for PROD/REAL KrbTgt accounts), the script performs an
			AD convergence check whether or not the password reset has occurred for the targeted KrbTgt account(s).
			If the password WAS NOT reset for the targeted KrbTgt account, the script logs clearly: "NO PASSWORD HAS BEEN SET FOR [<Distinguished Name Of Targeted KrbTgt Account>]"
			If the password WAS reset for the targeted KrbTgt account, the script logs clearly: "THE NEW PASSWORD FOR [<Distinguished Name Of Targeted KrbTgt Account>]
			HAS BEEN SET on RWDC [<FQDN Of Targeted RWDC For The Change>]!"
		- The script expects to find real DCs (RWDCs and RODCs!) in the default domain controllers OU, and NOT outside of that OU!
		- When using the mailing function, NO check is done for expiring credentials (secrets, certificates, etc.)

	RELEASE NOTES
		v3.6, 2026-01-01, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Code Improvement: Optimizing code by determining required DNs once and reuse that, instead of continuously query for the same information
			- Code Improvement: Updated all functions (where applicable), except the ones from S.DS.P, to specify the data type of each parameter
			- Code Improvement: Updated the S.DS.P to v2.3.0
			- Code Improvement: Remove old outcommented code that was using AD PoSH CMDlets
			- Code Improvement: Updated the function "loadPoshModules" to support PowerShell 7 loading the GroupPolicy module
			- Code Improvement: Updated the function "portConnectionCheck"
			- Code Improvement: Updated the function "sendMailMessage" and removed capability to sign/encrypt e-mail being send due to complexity and external DLL
			- Code Improvement: Renamed the function "logging" to "writeToLog" and updated it
			- Code Improvement: Updated the function "testAdminRole"
			- Code Improvement: Added a new parameter -skipDAMembershipCheck to skip the Domain Admins membership check. This can be used if the required permissions have been assigned in a different way
			- Code Improvement: Added a new parameter -skipElevationCheck to skip the elevated session check
			- Code Improvement: Added a new parameter -ignoreProtectionForTESTAccounts to ignore the protection of not resetting the password within the Kerberos Ticket Lifetime when using the 'TEST/BOGUS KrbTgt Accounts'. This parameter will NOT work for 'PROD/REAL KrbTgt Accounts'
			- Code Improvement: Added function "testAccountIsSystemOnRWDC" to support running as "NT AUTHORITY\SYSTEM" within a scheduled task on a RWDC for the local AD forest only. Also updated the code to check for that
			- Code Improvement: Remove old outcommented code that was using AD PoSH CMDlets
			- Code Improvement: Replaced "Get-WmiObject" with "Get-CimInstance" to also support PowerShell 7.x
			- Code Improvement: Created additional function "determineUserAccountForRSoP" and updated its original logic to all use the current user if available and otherwise choose a random one that is a user and a member of either/both "Administrators" and/or "Domain Admins" group
			- Code Improvement: Created additional function "determineKerberosPolicySettings"
			- Code Improvement: Created additional function "buildAttributeSchemaMappingTables"
			- Code Improvement: Created additional function "sendMailWithAttachmentAndDisplayOutput"
			- Code Improvement: Improvement with regards to arrays/lists/objects to support strict mode
			- Code Improvement: Added function "Set-Window" to support resizing the Terminal Window from which PowerShell may be running
			- Code Improvement: Script detects from which console ("PowerShell", "PowerShell ISE", "Windows Terminal") it is being executed. Running the script from "PowerShell ISE IS NOT supported!"
			- Code Improvement: Renamed and updated function "setPasswordOfADAccount" to "editADAccount" to support the Password Reset Routine!
			- Code Improvement: Updated the code for the elevation logic to only try once to elevate and not continuously. If it fails the first time, the script will not retry again and aborts instead
			- Improved User Experience: Added additional explanation when the account 'krbtgt_AzureAD' is found due to the use of Hybrid Cloud Trust for SSO
			- Improved User Experience: Updated the structure of the "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml", added examples and simplified (Better documentation for XML configuration for mail)
			- Improved User Experience: throughout the text renamed all from 'KrbTgt TEST/BOGUS Accounts' to 'TEST/BOGUS KrbTgt Accounts' and from 'KrbTgt PROD/REAL Accounts' to 'PROD/REAL KrbTgt Accounts'
			- Improved User Experience: Added a bit more explanatory text about testing AD replication and the recommendation to not delete the TEST/BOGUS KrbTgt Accounts
			- Improved User Experience: Added a function "cleanUpOldLogs" to cleanup all the logs older than 60 (log files) / 10 (orphaned zip files) days
			- New Feature: Added a new scope option "4 - Scope of ANY KrbTgt in use by ANY DC - All RWDCs/RODCs in the AD Domain" for ALL RWDCs and ALL RODCs in an AD Domain (in addition to the existing scopes
				"1 - Scope of KrbTgt in use by all RWDCs in the AD Domain", "2 - Scope of KrbTgt in use by specific RODC - Single/Multiple RODC(s) in the AD Domain", "3 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain")
			- New Feature: (EXPERIMENTAL!) Added an option to monitor for Golden Tickets after a Krbtgt Password reset (Option "7 - Golden Ticket Monitor Mode | Checking Domain Controllers For Event ID 4769 With Specific Error Codes
				0x6 (= KDC_ERR_C_PRINCIPAL_UNKNOWN = Client not found in Kerberos database), 0x1F (= KRB_AP_ERR_BAD_INTEGRITY = Integrity check on decrypted field failed) or 0x40 (= KDC_ERR_INVALID_SIG = The signature is invalid))
				(Inspired by https://github.com/YossiSassi/Invoke-PostKrbtgtResetMonitor)
			- New Feature: Adding support for "Password Reset Routine", which is scheduled/automated password reset of KrbTgt account password for either all RWDCs, all individual RODCs and/or specific RODCs
				(Inspired by https://github.com/MuscleBobBuff/KRBTGT/blob/main/AD%20-%20KRBTGT%20Reset%20Routines.ps1)
				1) Determines the current state, even if never used, redefines the new state and calculates the next 1st and 2nd password reset dates based upon the pre-defined intervals
				2) Resets the password of the targeted krbtgt account(s) the 1st time if the 1st calculated date equals TODAY
				3) resets the password of the targeted krbtgt account(s) the 2nd time if the 2nd calculated date equals TODAY
				4) cleans everything up after monitoring to allow for the routine to execute again a later time
			- Bug Fix: When a PowerShell Window was being used that did not have an elevated session, it restarts the script in the folder C:\Windows\System32 and the script would fail as it is not the folder the script is in.
				The script now restarts in the location where it is.
			- Bug Fix: In a specific section of the code, the script was searching for NTDS Settings objects in the default domain naming context, while that should be the configuration naming context. Parts of that code has been updated.
			- Bug Fix: Redefined the LDAP Connections and the "disposal" of those through the code. When processing more than about 1300 KrbTGT account (RWDC + many RODCs), the error "LDAP Server Unavailable" occurred.
			- Bug Fix: With Windows Server 2025 the Domain/Forest Functional Level is 10. The script failed to recognize that. It now recognizes it correctly
			- Bug Fix: The PowerShell CMDlets from the ActiveDirectory module DO recognize the 2025 FFL and DFL. The script DOES NOT use this, but instead uses S.DS.P.. The issue appears to be that MSFT did update the
				ActiveDirectory module to recognize the 2025 FFL/DFL, but they apparently did not update the S.DS.P. DLLs to do the same. The script itself now detects this and reports the correct FFL/DFL when it is 2025

		v3.5, 2023-04-15 (Never Released), Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Improved User Experience: Added banner to output
			- Code Improvement: Implemented StrictMode Latest Version (Tested On PoSH 5.x And 7.x)
			- Bug Fix: Fixed code to support StrictMode
			- Bug Fix: Updated renamed variable $rootDomain to $rootADDomainInADForest
			- Bug Fix: Updated Filter to get RWDCs from [$_."msDS-isRODC" -eq $false -Or $_.primaryGroupID -eq "516"] to [$_."msDS-isRODC" -eq $false -And $_.primaryGroupID -eq "516" -And $_.rIDSetReferences -ne $null]
			- Bug Fix: Updated Filter to get RODCs from [$_."msDS-isRODC" -eq $true -Or $_.primaryGroupID -eq "521"] to [$_."msDS-isRODC" -eq $true -And $_.primaryGroupID -eq "521" -And $_."msDS-KrbTgtLink" -match "^CN=krbtgt_\d.*"]

		v3.4, 2023-03-04, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Bug Fix: The PowerShell CMDlets from the ActiveDirectory module DO recognize the 2016 FFL and DFL. The script DOES NOT use this, but instead uses S.DS.P.. The issue appears to be that MSFT did update the
				ActiveDirectory module to recognize the 2016 FFL/DFL, but they apparently did not update the S.DS.P. DLLs to do the same. The script itself now detects this and reports the correct FFL/DFL when it is 2016

		v3.3, 2022-12-20, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Bug Fix: updated the attribute type when specifying the number of the AD domain instead of the actual FQDN of the AD domain

		v3.2, 2022-11-05, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- New Feature: Adding support for scheduled/automated password reset of KrbTgt account password for either all RWDCs, all individual RODCs or specific RODCs
			- New Feature: Added mail function and parameter to mail the log file for review after execution with results
			- New Feature: Adding support for signed mail
			- New Feature: Adding support for encrypted mail
			- Bug Fix: Minor textual fixes
			- Bug Fix: fix an issue where one confirmation of continueOrStop would be inherited by the next
			- Bug Fix: fix an issue where the forest root domain would always be chosen as the source for replication and GPOs instead of the chosen AD domain when using custom credentials.
				This caused replicate single object to fail and for the determination of the Kerberos settings in the resultant GPO
			- Code Improvement: Added function getServerNames to retrieve server related names/FQDNs
			- Code Improvement: Added support for disjoint namespace, e.g. AD domain FQDN = ADDOMAIN.COM and DCs FQDN for that AD domain = <DC NAME>.SOMEDNSDOMAIN.COM
			- Code Improvement: Removed ALL dependencies for the ActiveDirectory PoSH module and replaced those with alternatives
			- Code Improvement: Redefinition of tables holding data for processing
			- Code Improvement: Upgraded to S.DS.P PowerShell Module v2.1.5 (2022-09-20)
			- Improved User Experience: Added the NetBIOS name of the AD domain to the list of AD domains in an AD forest
			- Improved User Experience: Added the option to the function to install required PoSH modules when not available
			- Improved User Experience: Added support to specify the number of an AD domain in the list instead of its FQDN

		v3.1, 2022-06-06, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Improved User Experience: The S.DS.P PowerShell Module v2.1.4 has been included into this script (with permission and under GPL license) to remove the dependency of the AD PowerShell Module when querying objects in AD. The
				ActiveDirectory PowerShell module is still used to get forest, domain, and domaincontroller information.
			- Improved User Experience: Removed dependency for port 135 (RPC Endpoint Mapper) and 9389 (AD Web Service)
			- Bug Fix: Getting the description of the TEST/BOGUS KrbTgt accounts in remote AD forest with explicit credentials to compare and fix later
			- Code Improvement: In addition to check for the correct description, also check if the TEST/BOGUS KrbTgt accounts are member of the correct groups
			- Code Improvement: Updated function createTestKrbTgtADAccount
			- Bug Fix: Minor textual fixes

		v3.0, 2022-05-27, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Bug Fix: Changed variable from $pwd to $passwd
			- Bug Fix: Variable used in single-quoted string. Wrapped in double-quote to fix
			- Bug Fix: Fix missing conditions and eventually credentials when connecting to a remote untrusted AD forest
			- Code Improvement: Minor improvements through scripts
			- Code Improvement: Changed variable from $passwordNrChars to $passwdNrChars
			- Code Improvement: Updated function confirmPasswordIsComplex
			- Code Improvement: Instead of assuming the "Max Tgt Lifetime In Hours" And the "Max Clock Skew In Minutes" is configured in the Default Domain GPO policy (the default)
				It now performs an RSoP to determine which GPO provides the authoritative values, and then uses the values from that GPO
			- Code Improvement: Added check for required PowerShell module on remote RWDC when running Invoke-Command CMDlet
			- Code Improvement: Added function 'requestForAdminCreds' to request for admin credentials
			- Improved User Experience: Specifically mentioned the requirement for the ADDS PoSH CMDlets and the GP PoSH CMDlets
			- Improved User Experience: Checking AD forest existence through RootDse connection in addition to DNS resolution
			- Code Improvement: Added a variable for connectionTimeout and changed the default of 500ms to 2000ms

		v2.9, 2021-05-04, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Improved User Experience: Added additional info and recommendations
			- New Feature: Added function to check UAC elevation status, and if not elevated to start the script automatically using an elevated PowerShell Command Prompt

		v2.8, 2020-04-02, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Bug fix: Fixed an issue when the RODC itself is not reachable/available, whereas in that case, the source should be the RWDC with the PDC FSMO
			- Improved User Experience: Checks to make sure both the RWDC with the PDC FSMO role and the nearest RWDC are available. If either one is not available, the script will abort

		v2.7, 2020-04-02, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Code Improvement: Added DNS name resolution check to the portConnectionCheck function
			- Code Improvement: Removed usage of $remoteADforest variable and only use the $localADforest variable
			- Code Improvement: Removed usage of $remoteCredsUsed variable and only use the $adminCrds variable (Was $adminCreds)
			- Code Improvement: Sections with '#XXX' have been removed
			- Code Improvement: Calls using the CMDlet 'Get-ADReplicationAttributeMetadata' (W2K12 and higher) have been replaced with .NET calls to support older OS'es such as W2K8 and W2K8R2. A function has been created to retrieve metadata
			- Code Improvement: Some parts were rewritten/optimized
			- Improved User Experience: To test membership of the administrators group in a remote AD forest the "title" attribute is now used instead of the "displayName" attribute to try to write to it
			- Improved User Experience: Added a warning if the special purpose krbtgt account 'Krbtgt_AzureAD' is discovered in the AD domain
			- Improved User Experience: If the number of RODCs in the AD domain is 0, then it will not present the options for RODCs
			- Improved User Experience: If the number of RODCs in the AD domain is 1 of more, and you chose to manually specify the FQDN of RODCs to process, it will present a list of RODCs to choose from
			- Improved User Experience: Operational modes have been changed (WARNING: pay attention to what you choose!). The following modes are the new modes
				- 1 - Informational Mode (No Changes At All)
				- 2 - Simulation Mode | Temporary Canary Object Created To Test Replication Convergence!
				- 3 - Simulation Mode | Use TEST/BOGUS KrbTgt Accounts - No Password Reset/WhatIf Mode!
				- 4 - Real Reset Mode | Use TEST/BOGUS KrbTgt Accounts - Password Will Be Reset Once!
				- 5 - Simulation Mode | Use PROD/REAL KrbTgt Accounts - No Password Reset/WhatIf Mode!
				- 6 - Real Reset Mode | Use PROD/REAL KrbTgt Accounts - Password Will Be Reset Once!
			- Improved User Experience: When choosing RODC Krb Tgt Account scope the following will now occur:
				- If the RODC is not reachable, the real source RWDC of the RODC cannot be determined. In that case, the RWDC with the PDC FSMO role is used as the source for the change and replication
				- If the RODC is reachable, but the real source RWDC of the RODC is not reachable it cannot be used as the source for the change and replication. In that case, the RWDC with the PDC FSMO role is used as the source for the change and replication

		v2.6, 2020-02-25, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Code Improvement: Removed code that was commented out
			- Code Improvement: In addition to the port 135 (RPC Endpoint Mapper) and 389 (LDAP), the script will also check for port 9389 (AD Web Service) which is used by the ADDS PoSH CMDlets
			- Code Improvement: Updated script to included more 'try/catch' and more (error) logging, incl. line where it fails, when things go wrong to make troubleshooting easier
			- Improved User Experience: Logging where the script is being executed from
			- Improved User Experience: Updated the function 'createTestKrbTgtADAccount' to also include the FQDN of the RODC for which the TEST/BOGUS KrbTgt account is created for better recognition

		v2.5, 2020-02-17, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Code Improvement: To improve performance, for some actions the nearest RWDC is discovered instead of using the RWDC with the PDC FSMO Role

		v2.4, 2020-02-10, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Bug Fix: Fixed language specific issue with the groups 'Allowed RODC Password Replication Group' and 'Denied RODC Password Replication Group'
			- Code Improvement: Checked script with Visual Studio Code and fixed all "problems" identified by Visual Studio Code
				- Variable "$remoteCredsUsed" is ignored by me, as the problem is due to the part 'Creds' in the variable name
				- Variable "$adminCreds" is ignored by me, as the problem is due to the part 'Creds' in the variable name
			- New Feature: Added support to execute this script against a remote AD forest, either with or without a trust

		v2.3, 2019-02-25, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Code Improvement: Removed the language specific error checking. Has been replaced with another check. This solution also resolved another
				issue when checking if a (RW/RO)DC was available or not

		v2.2, 2019-02-12, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Code Improvement: Instead of searching for "Domain Admins" or "Enterprise Admins" membership, it resolves the default RIDs of those
				groups, combined with the corresponding domain SID, to the actual name of those domain groups. This helps in supporting non-english
				names of those domain groups

		v2.1, 2019-02-11, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Code Improvement: Added a try catch when enumerating details about a specific AD domain that appears not to be available
			- New Feature: Read and display metadata of the KrbTgt accounts before and after to assure it was only updated once!

		v2.0, 2018-12-30, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Code Improvement: Full rewrite and major release
			- New Feature: Added possibility to also reset KrbTgt account in use by RODCs
			- New Feature: Added possibility to try this procedure using a temp canary object (contact object)
			- New Feature: Added possibility to try this procedure using a TEST/BOGUS KrbTgt accounts and perform password reset on those TEST/BOGUS KrbTgt accounts
			- New Feature: Added possibility to create TEST/BOGUS KrbTgt accounts if required
			- New Feature: Added possibility to delete TEST/BOGUS KrbTgt accounts if required
			- New Feature: Check if an RODC account is indeed in use by a Windows RODC and not something simulating an RODC (e.g. Riverbed)
			- New Feature: Removed dependency for REPADMIN.EXE
			- New Feature: Removed dependency for RPCPING.EXE
			- New Feature: Extensive logging to both screen and file
			- New Feature: Added more checks, such as permissions check, etc.
			- Script Improvement: Renamed script to Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1

		v1.7, Jared Poeppelman, Microsoft
			- Code Improvement: Modified rpcping.exe call to use "-u 9 -a connect" parameters to accommodate tighter RPC security settings as specified in
				DISA STIG ID: 5.124 Rule ID: SV-32395r1_rule , Vuln ID: V-14254 (thanks Adam Haynes)

		v1.6, Jared Poeppelman, Microsoft
			- Code Improvement: Removed 'finally' block of Get-GPOReport error handling (not a bug, just not needed)

		v1.5, Jared Poeppelman, Microsoft
			- Bug Fix: Fixed bug of attempting PDC to PDC replication
			- Code Improvement: Added logic for GroupPolicy Powershell module dependency
			- Code Improvement: Replaced function for password generation
			- Code Improvement: Renamed functions to use appropriate Powershell verbs
			- Code Improvement: Added error handling around Get-GpoReport for looking up MaxTicketAge and MaxClockSkew
			- Script Improvement: Renamed script to New-CtmADKrbtgtKeys.ps1

		v1.4, Jared Poeppelman, Microsoft
			- First version published on TechNet Script Gallery
#>

<#
.SYNOPSIS
	This PoSH Script Resets The KrbTgt Password For RWDCs And RODCs In A Controlled Manner

.DESCRIPTION
	This PoSH script provides the following functions:
	- Single Password Reset for the KrbTgt account in use by RWDCs in a specific AD domain, using either TEST/BOGUS or PROD/REAL KrbTgt accounts
	- Single Password Reset for the KrbTgt account in use by an individual RODC in a specific AD domain, using either TEST/BOGUS or PROD/REAL KrbTgt accounts
		* A single RODC in a specific AD domain
		* A specific list of RODCs in a specific AD domain
		* All RODCs in a specific AD domain
	- Resetting the password/keys of the KrbTgt Account can be done for multiple reasons such as for example:
		* From a security perspective as mentioned in https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/
		* From an AD recovery perspective as mentioned in https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password
	- For all scenarios, an informational mode, which is mode 1 with no changes
	- For all scenarios, a simulation mode, which is mode 2 where replication is tested through the replication of a temporary canary
		object that is created and deleted afterwards. No Password Resets involved here as the temporary canary object is a contact object.
		This is perfect to test replication within an AD domain, assuming all DCs involved are reachable.
	- For all scenarios, a simulation mode, which is mode 3 where NO password reset of the chosen TEST/BOGUS KrbTgt account occurs. Basically this
		just checks the status of the objects on scoped DCs. NOTHING is changed. Can be scoped for RWDCs and RODCs (single, multiple, all)
	- For all scenarios, a real reset mode, which is mode 4 where the password reset of the chosen TEST/BOGUS KrbTgt account is actually executed
		and replication of it is monitored through the environment for its duration. Can be scoped for RWDCs and RODCs (single, multiple, all)
	- For all scenarios, a simulation mode, which is mode 5 where NO password reset of the chosen PROD/REAL KrbTgt account occurs. Basically this
		just checks the status of the objects on scoped DCs. NOTHING is changed. Can be scoped for RWDCs and RODCs (single, multiple, all)
	- For all scenarios, a real reset mode, which is mode 6 where the password reset of the chosen PROD/REAL KrbTgt account is actually executed
		and replication of it is monitored through the environment for its duration
	- For all scenarios, failed golden ticket monitoring, which is mode 7 where all DCs in scope are contacted to get information from the Security Event Log
		to determine if failed golden tickets are used or not
	- The creation of TEST/BOGUS KrbTgt Accounts, which is mode 8
	- The deletion of TEST/BOGUS KrbTgt Accounts, which is mode 9
	- It is possible to run the script in a scheduled and automated manner by specifying the correct parameters and the correct information for those
		parameters. This can then be used in a scheduled task that runs on a very specific interval, e.g. every week or every month, or every 6 months.
		To understand what happens and how, instead of immediately targeting the PROD/REAL KrbTgt account(s), you have the possibility to familiarize
		yourself and try it out by using the TEST/BOGUS KrbTgt account(s) WITHOUT ANY impact!
	- In addition to the simple scheduled and automated manner of running the script, it is possible to configure the scheduled task to run every day
		in combination with a pre-defined Password Reset Routine which has its parameters defined in the configuration XML file
		"Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml". An example could be to perform the first password reset 7 days after the last password reset,
		and the second password reset 2 days after the first password reset
	- When running in a scheduled and automated manner, it is possible to have the log file (zipped!) mailed to some defined mail address(es). It also
	    works when running it manually, as long as the correct parameter is used and all prerequisites are in place
	- When mailing of the log file (zipped!) is needed in ANY way, a configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml" is needed
		with settings to control mailing behavior. The configuration XML file is expected to be in the same folder as the script itself.
		See below in the NOTES for the structure

	Behavior:
	- In this script a DC is reachable/available, if its name is resolvable and connectivity is possible for all of the following ports:
		TCP:389 (LDAP)
	- In mode 1 you will always get a list of all RWDCs, and alls RODCs if applicable, in the targeted AD domain that are available/reachable
		or not
	- In mode 2 it will create the temporary canary object and, depending on the scope, it will check if it exists in the AD database of the
		remote DC(s) (RWDC/RODC)
	- In mode 3, depending on the scope, it uses TEST/BOGUS krbtgt account(s). It just checks and compares the state of the pwdLastSet attribute
		on the source RWDC with other scoped DCs. Nothing is changed/updated!
		* For RWDCs it uses the TEST/BOGUS krbtgt account "krbtgt_TEST" (All RWDCs) (= Created when running mode 8)
		* For RODCs it uses the TEST/BOGUS krbtgt account "krbtgt_<Numeric Value>_TEST" (RODC Specific) (= Created when running mode 8)
	- In mode 4, depending on the scope, it uses TEST/BOGUS krbtgt account(s) to reset the password on an originating RWDC. After that it
		checks if pwdLastSet attribute value of the targeted TEST/BOGUS krbtgt account(s) on the remote DC(s) (RWDC/RODC) matches the
		pwdLastSet attribute value of the same TEST/BOGUS krbtgt account on the originating RWDC
		* For RWDCs it uses the TEST/BOGUS krbtgt account "krbtgt_TEST" (All RWDCs) (= Created when running mode 8)
		* For RODCs it uses the TEST/BOGUS krbtgt account "krbtgt_<Numeric Value>_TEST" (RODC Specific) (= Created when running mode 8)
	- In mode 5, depending on the scope, it uses PROD/REAL krbtgt account(s). It just checks and compares the state of the pwdLastSet attribute
		on the source RWDC with other scoped DCs. Nothing is changed/updated!
	- In mode 6, depending on the scope, it uses PROD/REAL krbtgt account(s) to reset the password on an originating RWDC. After that it
		checks if pwdLastSet attribute value of the targeted PROD/REAL krbtgt account(s) on the remote DC(s) (RWDC/RODC) matches the pwdLastSet
		attribute value of the same PROD/REAL krbtgt account on the originating RWDC
		* For RWDCs it uses the PROD/REAL krbtgt account "krbtgt" (All RWDCs)
		* For RODCs it uses the PROD/REAL krbtgt account "krbtgt_<Numeric Value>" (RODC Specific)
	- In mode 7, depending on the scope, DCs are contacted to get all events with event ID 4769 generated after the last password set date/time
		of the Krbtgt account, and filter specifically on those events with error code 0x6 (= KDC_ERR_C_PRINCIPAL_UNKNOWN = Client not found in Kerberos database),
		0x1F (= KRB_AP_ERR_BAD_INTEGRITY = Integrity check on decrypted field failed) or 0x40 (= KDC_ERR_INVALID_SIG = The signature is invalid).
		When such an event if found, the information recorded in a separate log file.
		REMARK: Event ID 4769 is generated every time the Key Distribution Center (KDC) receives a Kerberos Ticket Granting Service (TGS) ticket request
		https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
	- In mode 8, for RWDCs it creates (in disabled state!) the TEST/BOGUS krbtgt account "krbtgt_TEST" and adds it to the AD group
		"Denied RODC Password Replication Group". If any RODC exists in the targeted AD domain, it reads the attribute "msDS-KrbTgtLink" of
		each RODC computer account to determine the RODC specific krbtgt account and creates (in disabled state!) the TEST/BOGUS krbtgt
		account "krbtgt_<Numeric Value>_TEST" and adds it to the AD group "Allowed RODC Password Replication Group"
	- In mode 9, for RWDCs it deletes the TEST/BOGUS krbtgt account "krbtgt_TEST" if it exists. If any RODC exists in the targeted AD domain,
		it reads the attribute "msDS-KrbTgtLink" of each RODC computer account to determine the RODC specific krbtgt account and deletes the
		TEST/BOGUS krbtgt account "krbtgt_<Numeric Value>_TEST" if it exists.
	- In mode 2, 3, 4, 5 or 6, if a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database
		to determine if the change made reached it or not. In case of mode 7 no events will be gathered from the security event log.
	- In mode 2 when performing the "replicate single object" operation, it will always be for the full object, no matter if the remote DC
		is an RWDC or an RODC
	- In mode 3, 4, 5 or 6 when performing the "replicate single object" operation, it will always be for the full object, if the remote DC is an
		RWDC. If the remote DC is an RODC it will always be for the partial object and more specifically "secrets only"
	- When targeting the krbtgt account (TEST/BOGUS or PROD/REAL) in use by all the RWDCs, the originating RWDC is the RWDC with the PDC FSMO
		and all other available/reachable RWDCs will be checked against to see if the change has reached them. No RODCs are involved as those
		do not use the krbtgt account in use by the RWDCs and also do not store/cache its password.
	- When targeting the krbtgt account (TEST/BOGUS or PROD/REAL) in use by an RODC, the originating RWDC is the direct replication RWDC if
		available/reachable and when not available the RWDC with the PDC FSMO is used as the originating RWDC. Only the RODC that uses the
		specific krbtgt account is checked against to see if the change has reached them, but only if the RODCs is available/reachable. If the
		RODC itself is not available, then the RWDC with the PDC FSMO is used as the originating RWDC and the change will eventually replicate
		to the RODC
	- If the operating system attribute of an RODC computer account does not have a value, it is determined to be unknown (not a real RODC),
		and therefore something else. It could for example be a Riverbed appliance in "RODC mode".
	- The only DC that knows what the real replication partner is of an RODC, is the RODC itself. Only the RODC manages a connection object
		that only exists in the AD database of the RODC and does not replicate out to other DCs as RODCs do not support outbound replication.
		Therefore, assuming the RODC is available, the CO is looked up in the RODC AD database and from that CO, the "source" server is
		determined. In case the RODC is not available or its "source" server is not available, the RWDC with the PDC FSMO is used to reset
		the password of the krbtgt account in use by that RODC. If the RODC is available a check will be done against its database, and if
		not available the check is skipped

.PARAMETER noInfo
	With this parameter it is possible to skip the information at the beginning of the script when running the script in an automated manner such
	as in a Scheduled Task

.PARAMETER modeOfOperation
	With this parameter it is possible to specify the mode of operation for the script. This should only be used in an automated manner such as in
	a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!
	Accepted values are: "infoMode", "simulModeCanaryObject", "simulModeKrbTgtTestAccountsWhatIf", "resetModeKrbTgtTestAccountsResetOnce",
	"simulModeKrbTgtProdAccountsWhatIf", "resetModeKrbTgtProdAccountsResetOnce", "monitorForGoldenTicket"

.PARAMETER targetedADforestFQDN
	With this parameter it is possible to specify the FQDN of an AD forest that will be targeted. This should only be used in an automated manner
	such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

.PARAMETER targetedADdomainFQDN
	With this parameter it is possible to specify the FQDN of an AD domain that will be targeted within the specified AD forest. This should only
	be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

.PARAMETER targetKrbTgtAccountScope
	With this parameter it is possible to specify the scope of the targeted KrbTgt account. This should only be used in an automated manner such
	as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!
	Accepted values are: "allRWDCs", "allRODCs", "specificRODCs", "allRWDCsAndRODCs"

.PARAMETER targetRODCFQDNList
	With this parameter it is possible to specify one or more RODCs through a comma-separated list. This parameter is ONLY needed when the
	targetKrbTgtAccountScope is set to specificRODCs. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after
	testing an getting confidence of what will happen!

.PARAMETER continueOps
	With this parameter it is possible to specify the script should continue where it is needed to confirm the operation depending of whether there
	is impact or not. If the script determines there is impact, the script will abort to prevent impact. Only when running ON-DEMAND without any
	parameters will it be possible to continue and still have domain wide impact, in other words ignore there is impact. This should only be used
	in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

.PARAMETER execResetRoutine
	With this parameter it is possible to execute the password reset routine according to the defined parameters. In addition to using this parameter,
	the configuration XML file must be configured with all related parameters (intervals and attribute names) and the node "resetRoutineEnabled"
	must be configured with TRUE.

.PARAMETER ignoreProtectionForTESTAccounts
	With this parameter it is possible to ignore the protection of not resetting the password within the Kerberos Ticket Lifetime when using the
	'TEST/BOGUS KrbTgt Accounts'. This parameter will NOT work for 'PROD/REAL KrbTgt Accounts'

.PARAMETER skipDAMembershipCheck
	With this parameter it is possible to skip the Domain Admins membership check. This can be used if the required permissions have been assigned
	in a different way. This means the required permissions to create and/or delete 'TEST/BOGUS KrbTgt Accounts' in the USERS container, reset
	of the password of either 'PROD/REAL KrbTgt Accounts' and/or 'TEST/BOGUS KrbTgt Accounts', to execute replicate single object must be assigned
	differently. When not assigned in a different way, while using this parameter and the account is not a member of the Domain Admins group, the
	targeted action(s) will most likely fail

.PARAMETER skipElevationCheck
	With this parameter it is possible to skip the elevated session check

.PARAMETER sendMailWithLogFile
	With this parameter it is possible to specify the script should mail the LOG file at any moment when the script stops running, whether it
	finished successfully or due to encountered issue(s).In addition to using this parameter, the configuration XML file must be configured with
	all mail related parameters and the node "sendMail" must be configured with TRUE.

.EXAMPLE
	Execute The Script - On-Demand

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1

.EXAMPLE
	Execute The Script - Automated Without Sending The Log File Through Mail - Mode 2 With All RWDCs As Scope

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeCanaryObject -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 2 With All RWDCs As Scope

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeCanaryObject -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 3 With All RWDCs As Scope (TEST/BOGUS KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeKrbTgtTestAccountsWhatIf -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 4 With All RWDCs As Scope (TEST/BOGUS KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtTestAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 5 With All RWDCs As Scope (PROD/REAL KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeKrbTgtProdAccountsWhatIf -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 6 With All RWDCs As Scope (PROD/REAL KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 3 With All RODCs As Scope (TEST/BOGUS KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeKrbTgtTestAccountsWhatIf -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRODCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 4 With All RODCs As Scope (TEST/BOGUS KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtTestAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRODCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 5 With All RODCs As Scope (PROD/REAL KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeKrbTgtProdAccountsWhatIf -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRODCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 6 With All RODCs As Scope (PROD/REAL KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRODCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 6 With Specific RODCs (But Not All) As Scope (PROD/REAL KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope specificRODCs -targetRODCFQDNList "RODC1.DOMAIN.COM","RODC2.DOMAIN.COM","RODC3.DOMAIN.COM" -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated Password Reset Routine And Sending The Log File Through Mail - Mode 4 With All RWDCs As Scope (TEST/BOGUS KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -sendMailWithLogFile -execResetRoutine -modeOfOperation resetModeKrbTgtTestAccountsResetOnce -targetKrbTgtAccountScope allRWDCs -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -continueOps

.EXAMPLE
	Execute The Script - Automated Password Reset Routine And Sending The Log File Through Mail - Mode 4 With All RWDCs And All RODCs As Scope (TEST/BOGUS KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -sendMailWithLogFile -execResetRoutine -modeOfOperation resetModeKrbTgtTestAccountsResetOnce -targetKrbTgtAccountScope allRWDCsAndRODCs -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -continueOps

.EXAMPLE
	Execute The Script - Automated Password Reset Routine And Sending The Log File Through Mail - Mode 6 With All RWDCs As Scope (PROD/REAL KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -sendMailWithLogFile -execResetRoutine -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetKrbTgtAccountScope allRWDCs -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -continueOps

.EXAMPLE
	Execute The Script - Automated Password Reset Routine And Sending The Log File Through Mail - Mode 6 With All RODCs As Scope (PROD/REAL KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -sendMailWithLogFile -execResetRoutine -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetKrbTgtAccountScope allRODCs -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -continueOps

.EXAMPLE
	Execute The Script - Automated Password Reset Routine And Sending The Log File Through Mail - Mode 6 With All RWDCs And All RODCs As Scope (PROD/REAL KrbTgt accounts)

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -sendMailWithLogFile -execResetRoutine -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetKrbTgtAccountScope allRWDCsAndRODCs -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -continueOps

.NOTES
	- Minimum required PowerShell version: 5.1 (it is being checked and enforced!)
	- Required PoSH CMDlets: GPMC PoSH CMDlets on all targeted RWDCs!!! (and the S.DS.P Posh CMDlets are INCLUDED in this script!)
	- The script must either be executed from PowerShell or Windows Terminal. PowerShell ISE IS NOT supported!
	- To execute this script, the account running the script MUST be a member of the "Domain Admins" or Administrators group in the
		targeted AD domain.
	- If the account used is from another AD domain in the same AD forest, then the account running the script MUST be a member of the
		"Enterprise Admins" group in the AD forest or Administrators group in the targeted AD domain. For all AD domains in the same
		AD forest, membership of the "Enterprise Admins" group is easier as by default it is a member of the Administrators group in
		every AD domain in the AD forest
	- If the account used is from another AD domain in another AD forest, then the account running the script MUST be a member of the
		"Administrators" group in the targeted AD domain. This also applies to any other target AD domain in that same AD forest
	- This is due to the reset of the password for the targeted KrbTgt account(s) and forcing (single object) replication between DCs
	- Testing "Domain Admins" membership is done through "IsInRole" method as the group is domain specific
	- Testing "Enterprise Admins" membership is done through "IsInRole" method as the group is forest specific
	- Testing "Administrators" membership cannot be done through "IsInRole" method as the group exist in every AD domain with the same
		SID. To still test for required permissions in that case, the value of the Description attribute of the KRBTGT account is copied
		into the Title attribute and cleared afterwards. If both those actions succeed it is proven the required permissions are
		in place!
	- Script Has StrictMode Enabled For Latest Version - Tested With PowerShell 7.x
	- If User Account Control (UAC) is in effect (i.e. enabled) the script MUST be executed in an elevated Powershell Command Prompt Window!
	- When running the script on-demand with an account that does have the correct permissions, the script will ask for credentials with the
		correct permissions
	- When running the script automated with an account that does have the correct permissions, the script will NOT ask for credentials with
		the correct permissions. It will just stop. Therefore in an automated manner, the running account MUST have the correct permissions!
	- The Configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml" is needed when e-mailing of the log file (zipped!) is required
		and/or the password reset routine needs to be used. This is required as the XML file has the required configuration for both. This
		allows the script to be updated without impacting environment specific configuration related to mailing and/or password reset routine.
	- To use the Configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml" and its settings, the node "useXMLConfigFileSettings"
		must be configured with "TRUE"
	- To support mailing of the log file after the script completes, the Configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml"
		must be configured with the settings of the e-mail provider, the node "sendMail" MUST be configured with "TRUE" and the parameter
		"sendMailWithLogFile" must also be used with the script
	- To support the password reset routine, the Configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml" must be configured with
		the settings supporting that feature, the node "resetRoutineEnabled" MUST be configured with "TRUE" and the parameter
		"execResetRoutine" must also be used with the script. In addition, as the password reset routing is supposed to be fully automated,
		all the parameters to support full automation must also be used with the script. See the examples.
	- When using a scheduled task running as NT AUTHORITY\SYSTEM, make sure to configure that scheduled task on the RWDC with the PDC FSMO role.
		The reason for this is that NT AUTHORITY\SYSTEM, although highly privileged when running on an RWDC can only make changes against its
		own database instance and not against a remote database instance on another RWDC! When it concerns the KrbTgt account of RODCs, and
		when running as NT AUTHORITY\SYSTEM, instead of using the real source RWDC of the RODC, the RWDC with the PDC FSMO will be used instead
		for the previously mentioned reason. As an additional tip, make sure the scheduled task is configured in a GPO that follows the RWDC
		with the PDC FSMO role.
		To be sure everything runs correctly without issue, try it out first manually using PSEXEC -I -S POWERSHELL.EXE and then running the
		script with all the required parameters.
	- As e-mail providers, Office 365, Gmail and a multitude of SMTP providers are supported. See the Configuration XML file for examples
	- When using Office 365, modern authentication is required using an application client id with ether a client secret or a client certificate.
		To create a self-signed certificate, see: https://gist.github.com/zjorz/8f67712d259c440140e9d254322286c0
		To create an application in Entra ID with the required configuration, see: https://gist.github.com/zjorz/ad253c009b080c91494e2a64981aca6b
	- When using application client id with a client certificate, the credential running the script must have READ access to the private key of the
		certificate being used. The certificate should be located in the (Personal) Local Computer Store
	- Configuration XML file > Use sample in: https://github.com/zjorz/Public-AD-Scripts/blob/master/Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml
	- SCENARIO (1stInterval = 3, 2ndInterval = 1, the MINIMUM values)
		DAY0:
		* read lastResetDate =  pwdLastSet = DAY0 - 100 (ie 100 days ago)
		* read state = EMPTY
		* read 1stResetDate = attribute_for_1stResetDate = EMPTY
		* read 2ndResetDate = attribute_for_2ndResetDate = EMPTY
		* set state = 0
		* set 1stResetDate = attribute_for_1stResetDate = DAY0 - 100 + 3 = DAY0 - 97 < TODAY therefore TODAY (DAY0) + 3 = DAY3
		* set 2ndResetDate = attribute_for_2ndResetDate = DAY0 - 100 + 3 + 1 = DAY0 - 96 < TODAY therefore TODAY (DAY0) + 3 + 1 = DAY4
		* PWD Reset = FALSE

		DAY1:
		* read lastResetDate =  pwdLastSet = DAY0 - 100 (ie 100 days ago)
		* read state = 0
		* read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
		* read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
		* PWD Reset = FALSE

		DAY2:
		* read lastResetDate =  pwdLastSet = DAY0 - 100 (ie 100 days ago)
		* read state = 0
		* read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
		* read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
		* PWD Reset = FALSE

		DAY3:
		* read lastResetDate =  pwdLastSet = DAY0 - 100 (ie 100 days ago)
		* read state = 0
		* read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
		* read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
		* set state = 1
		* PWD Reset = TRUE

		DAY4:
		* read lastResetDate =  pwdLastSet = DAY3
		* read state = 1
		* read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
		* read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
		* set state = 2
		* PWD Reset = TRUE

		DAY5:
		* read lastResetDate =  pwdLastSet = DAY4
		* read state = 2
		* read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
		* read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
		* set state = EMPTY
		* set 1stResetDate = attribute_for_1stResetDate = EMPTY
		* set 2ndResetDate = attribute_for_2ndResetDate = EMPTY
		* PWD Reset = FALSE

		DAY6:
		* read lastResetDate =  pwdLastSet = DAY4
		* read state = EMPTY
		* read 1stResetDate = attribute_for_1stResetDate = EMPTY
		* read 2ndResetDate = attribute_for_2ndResetDate = EMPTY
		* set state = 0
		* set 1stResetDate = attribute_for_1stResetDate = DAY4 + 3 = DAY7
		* set 2ndResetDate = attribute_for_2ndResetDate = DAY4 + 3 + 1 = DAY8
		* PWD Reset = FALSE

	- SCENARIO (1stInterval = 3, 2ndInterval = 1, the MINIMUM values)
		DAY0:
		* 1stResetDate = attribute_for_1stResetDate = DAY0 - 1
		* 2ndResetDate = attribute_for_2ndResetDate = lastResetDate = pwdLastSet = TODAY
		* lastResetDate = pwdLastSet = TODAY = DAY0
		* state set to 2
		* PWD Reset = TRUE

		DAY1:
		* read lastResetDate =  pwdLastSet = DAY0
		* read state = 2
		* read 1stResetDate = attribute_for_1stResetDate = DAY0 - 1
		* read 2ndResetDate = attribute_for_2ndResetDate = DAY0
		* set state = EMPTY
		* set 1stResetDate = attribute_for_1stResetDate = EMPTY
		* set 2ndResetDate = attribute_for_2ndResetDate = EMPTY
		* PWD Reset = FALSE

		DAY2:
		* read lastResetDate = pwdLastSet = DAY0
		* read state = EMPTY
		* read 1stResetDate = attribute_for_1stResetDate = EMPTY
		* read 2ndResetDate = attribute_for_2ndResetDate = EMPTY
		* set state = 0
		* set 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3 > TODAY therefore DAY0 + 3 = DAY3
		* set 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4 > TODAY therefore DAY0 + 3 + 1 = DAY4
		* PWD Reset = FALSE

		DAY3:
		* read lastResetDate = pwdLastSet = DAY0
		* read state = 0
		* read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
		* read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
		* set state = 1
		* PWD Reset = TRUE

		DAY4:
		* read lastResetDate = pwdLastSet = DAY0 + 3 = DAY3
		* read state = 1
		* read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
		* read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
		* set state = 2
		* PWD Reset = TRUE

		DAY5:
		* read lastResetDate =  pwdLastSet = DAY0 + 3 + 1 = DAY4
		* read state = 2
		* read 1stResetDate = attribute_for_1stResetDate = DAY0 + 3 = DAY3
		* read 2ndResetDate = attribute_for_2ndResetDate = DAY0 + 3 + 1 = DAY4
		* set state = EMPTY
		* set 1stResetDate = attribute_for_1stResetDate = EMPTY
		* set 2ndResetDate = attribute_for_2ndResetDate = EMPTY
		* PWD Reset = FALSE

	- Example Scheduled Task Configuration For The Password Reset Routine Targeting The Test/Bogus KrbTgt Accounts Of Both RWDCs And RODCs In The Specified AD Forest/Domain
		ACTION - Program/Script (PoSH v5.1) = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
		ACTION - Program/Script (PoSH v7.x) = "C:\Program Files\PowerShell\7\pwsh.exe"
		ACTION - Arguments = -NoProfile -NonInterActive -Command "D:\TEMP\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -sendMailWithLogFile -execResetRoutine -modeOfOperation resetModeKrbTgtTestAccountsResetOnce -targetKrbTgtAccountScope allRWDCsAndRODCs -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHLD.DOMAIN.COM -continueOps"
		ACTION - Start In = D:\TEMP
#>

###
# External S.DS.P. PowerShell Module INCLUDED In This Script
###

################### S.DS.P PowerShell Module HELPERS v2.3.0 (2025-08-05): https://github.com/jformacek/S.DS.P ####################
# vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# File In Repo: https://github.com/jformacek/S.DS.P/blob/master/Module/S.DS.P/Helpers/Flattener.cs (https://github.com/jformacek/S.DS.P/blob/master/Module/S.DS.P/Helpers)
$flattener = @"
public static class Flattener
{
	public static System.Object FlattenArray(System.Object[] arr)
	{
		if(arr==null) return null;
		switch(arr.Length)
		{
			case 0:
				return null;
			case 1:
				return arr[0];
			default:
				return arr;
		}
	}
}
"@

# File In Repo: https://github.com/jformacek/S.DS.P/blob/master/Module/S.DS.P/Helpers/NamingContext.cs (https://github.com/jformacek/S.DS.P/blob/master/Module/S.DS.P/Helpers)
$namingContext = @"
public class NamingContext
{
	public System.Security.Principal.SecurityIdentifier SID {get; set;}
	public System.Guid GUID {get; set;}
	public string distinguishedName {get; set;}
	public override string ToString() {return distinguishedName;}
	public static NamingContext Parse(string ctxDef)
	{
		NamingContext retVal = new NamingContext();
		var parts = ctxDef.Split(';');
		if(parts.Length == 1)
		{
			retVal.distinguishedName = parts[0];
		}
		else
		{
			foreach(string part in parts)
			{
				if(part.StartsWith("<GUID="))
				{
					try
					{
						retVal.GUID=System.Guid.Parse(part.Substring(6,part.Length-7));
					}
					catch(System.Exception)
					{
						//swallow any errors
					}
					continue;
				}
				if(part.StartsWith("<SID="))
				{
					try
					{
						retVal.SID=new System.Security.Principal.SecurityIdentifier(part.Substring(5,part.Length-6));
					}
					catch(System.Exception)
					{
						//swallow any errors
					}
					continue;
				}
				retVal.distinguishedName=part;
			}
		}
		return retVal;
	}
}
"@

# --------------------------------------------------------------------------------------------------------------------------------

$sdspModuleHelpers = New-Object -TypeName PSObject -Property @{
	flattener     = $flattener
	namingContext = $namingContext
}

# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
################### S.DS.P PowerShell Module HELPERS v2.3.0 (2025-08-05): https://github.com/jformacek/S.DS.P ####################

######################## S.DS.P PowerShell Module v2.3.0 (2025-08-05): https://github.com/jformacek/S.DS.P #######################
# SEARCH FOR SDSP_INDIVIDUAL_UPDATES For Updates Done To Support Strict Mode
# vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# Github Repo:  https://github.com/jformacek/S.DS.P
# Applicable License: https://github.com/jformacek/S.DS.P/blob/master/LICENSE.TXT
# Owner: Jiri Formacek
# File In Repo: https://github.com/jformacek/S.DS.P/blob/master/Module/S.DS.P/S.DS.P.psm1
#region Public commands
Function Add-LdapObject {
	<#
.SYNOPSIS
	Creates a new object in LDAP server

.DESCRIPTION
	Creates a new object in LDAP server.
	Optionally performs attribute transforms registered for Save action before saving changes

.OUTPUTS
	Nothing

.EXAMPLE
$obj = [PSCustomObject]@{distinguishedName=$null; objectClass=$null; sAMAccountName=$null; unicodePwd=$null; userAccountControl=0}
$obj.DistinguishedName = "cn=user1,cn=users,dc=mydomain,dc=com"
$obj.sAMAccountName = "User1"
$obj.ObjectClass = "User"
$obj.unicodePwd = "P@ssw0rd"
$obj.userAccountControl = "512"

$Ldap = Get-LdapConnection -LdapServer "mydc.mydomain.com" -EncryptionType Kerberos
Register-LdapAttributeTransform -name UnicodePwd -AttributeName unicodePwd
Add-LdapObject -LdapConnection $Ldap -Object $obj -BinaryProps unicodePwd

Description
-----------
Creates new user account in domain.
Password is transformed to format expected by LDAP services by registered attribute transform

.LINK
More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx

#>
	Param (
		[parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[PSObject]
		#Source object to copy properties from
		$Object,

		[parameter()]
		[String[]]
		#Properties to ignore on source object
		$IgnoredProps = @(),

		[parameter(Mandatory = $false)]
		[String[]]
		#List of properties that we want to handle as byte stream.
		#Note: Properties not listed here are handled as strings
		#Default: empty list, which means that all properties are handled as strings
		$BinaryProps = @(),

		[parameter()]
		[System.DirectoryServices.Protocols.LdapConnection]
		#Existing LDAPConnection object.
		$LdapConnection = $script:LdapConnection,

		[parameter(Mandatory = $false)]
		[System.DirectoryServices.Protocols.DirectoryControl[]]
		#Additional controls that caller may need to add to request
		$AdditionalControls = @(),

		[parameter(Mandatory = $false)]
		[Timespan]
		#Time before connection times out.
		#Default: [TimeSpan]::Zero, which means that no specific timeout provided
		$Timeout = [TimeSpan]::Zero,

		[Switch]
		#When turned on, command returns created object to pipeline
		#This is useful when further processing needed on object
		$Passthrough
	)

	begin {
		EnsureLdapConnection -LdapConnection $LdapConnection
	}

	Process {
		if ([string]::IsNullOrEmpty($Object.DistinguishedName)) {
			throw (new-object System.ArgumentException("Input object missing DistinguishedName property"))
		}
		[System.DirectoryServices.Protocols.AddRequest]$rqAdd = new-object System.DirectoryServices.Protocols.AddRequest
		$rqAdd.DistinguishedName = $Object.DistinguishedName

		#add additional controls that caller may have passed
		foreach ($ctrl in $AdditionalControls) { $rqAdd.Controls.Add($ctrl) > $null }

		foreach ($prop in (Get-Member -InputObject $Object -MemberType NoteProperty)) {
			if ($prop.Name -eq "distinguishedName") { continue }
			if ($IgnoredProps -contains $prop.Name) { continue }
			[System.DirectoryServices.Protocols.DirectoryAttribute]$propAdd = new-object System.DirectoryServices.Protocols.DirectoryAttribute
			$transform = $script:RegisteredTransforms[$prop.Name]
			$binaryInput = ($null -ne $transform -and $transform.BinaryInput -eq $true) -or ($prop.Name -in $BinaryProps)
			$propAdd.Name = $prop.Name

			if ($null -ne $transform -and $null -ne $transform.OnSave) {
				#transform defined -> transform to form accepted by directory
				$attrVal = @(& $transform.OnSave -Values $Object.($prop.Name))
			} else {
				#no transform defined - take value as-is
				$attrVal = $Object.($prop.Name)
			}

			if ($null -ne $attrVal) { #ignore empty props
				if ($binaryInput) {
					foreach ($val in $attrVal) {
						$propAdd.Add([byte[]]$val) > $null
					}
				} else {
					$propAdd.AddRange([string[]]($attrVal))
				}

				# SDSP_INDIVIDUAL_UPDATES Updated: $xxx.Count to $($xxx | Measure-Object).Count
				if ($($propAdd | Measure-Object).Count -gt 0) {
					$rqAdd.Attributes.Add($propAdd) > $null
				}
			}
		}
		# SDSP_INDIVIDUAL_UPDATES Updated: $xxx.Count to $($xxx | Measure-Object).Count
		if ($($rqAdd.Attributes | Measure-Object).Count -gt 0) {
			if ($Timeout -ne [TimeSpan]::Zero) {
				$response = $LdapConnection.SendRequest($rqAdd, $Timeout) -as [System.DirectoryServices.Protocols.AddResponse]
			} else {
				$response = $LdapConnection.SendRequest($rqAdd) -as [System.DirectoryServices.Protocols.AddResponse]
            }
            #handle failed operation that does not throw itself
            if($null -ne $response -and $response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                throw (new-object System.DirectoryServices.Protocols.LdapException(([int]$response.ResultCode), "$($rqAdd.DistinguishedName)`: $($response.ResultCode)`: $($response.ErrorMessage)", $response.ErrorMessage))
            }
		}
		if ($Passthrough) {
			$Object
		}
	}
}
Function Edit-LdapObject {
	<#
.SYNOPSIS
	Modifies existing object in LDAP server

.DESCRIPTION
	Modifies existing object in LDAP server.
	Optionally performs attribute transforms registered for Save action before saving changes

.OUTPUTS
	Nothing

.EXAMPLE
$obj =  [PSCustomObject]@{distinguishedName=$null; employeeNumber=$null}
$obj.DistinguishedName = "cn=user1,cn=users,dc=mydomain,dc=com"
$obj.employeeNumber = "12345"

$Ldap = Get-LdapConnection -LdapServer "mydc.mydomain.com" -EncryptionType Kerberos
Edit-LdapObject -LdapConnection $Ldap -Object $obj

Description
-----------
Modifies existing user account in domain.

.EXAMPLE
$conn = Get-LdapConnection -LdapServer "mydc.mydomain.com" -EncryptionType Kerberos
$dse = Get-RootDSE -LdapConnection $conn
$User = Find-LdapObject -LdapConnection $conn -searchFilter '(&(objectClass=user)(objectCategory=organizationalPerson)(sAMAccountName=myUser1))' -searchBase $dse.defaultNamingContext
$Group = Find-LdapObject -LdapConnection $conn -searchFilter '(&(objectClass=group)(objectCategory=group)(cn=myGroup1))' -searchBase $dse.defaultNamingContext -AdditionalProperties @('member')
$Group.member=@($User.distinguishedName)
Edit-LdapObject -LdapConnection $conn -Object $Group -Mode Add

Description
-----------
Finds user account in LDAP server and adds it to group

.EXAMPLE
#get connection and sotre in session variable
Get-LdapConnection -LdapServer "mydc.mydomain.com"
#get root DSE object
$dse = Get-RootDse
#do work
Find-LdapObject `
	-searchFilter '(&(objectClass=user)(objectCategory=organizationalPerson)(l=Prague))' `
	-searchBase $dse.defaultNamingContext `
	-PropertiesToLoad 'adminDescription' `
| foreach-object{$_.adminDescription = 'Prague'; $_} `
| Edit-LdapObject -IncludedProps 'adminDescription' -Passthrough `
| Find-LdapObject -searchFilter '(objectClass=*)' -searchScope Base -PropertiesToLoad 'adminDescription'

Description
-----------
This sample demonstrates pipeline capabilities of various commands by updating an attribute value on many objects and reading updated objects from server

.LINK
More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx

#>
	Param (
		[parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[PSObject]
		#Source object to copy properties from
		$Object,

		[parameter()]
		[String[]]
		#Properties to ignore on source object. If not specified, no props are ignored
		$IgnoredProps = @(),

		[parameter()]
		[String[]]
		#Properties to include on source object. If not specified, all props are included
		$IncludedProps = @(),

		[parameter(Mandatory = $false)]
		[String[]]
		#List of properties that we want to handle as byte stream.
		#Note: Those properties must also be present in IncludedProps parameter. Properties not listed here are handled as strings
		#Default: empty list, which means that all properties are handled as strings
		$BinaryProps = @(),

		[parameter()]
		[System.DirectoryServices.Protocols.LdapConnection]
		#Existing LDAPConnection object.
		$LdapConnection = $script:LdapConnection,

		[parameter(Mandatory = $false)]
		[System.DirectoryServices.Protocols.DirectoryAttributeOperation]
		#Mode of operation
		#Replace: Replaces attribute values on target
		#Add: Adds attribute values to existing values on target
		#Delete: Removes attribute values from existing values on target
		$Mode = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,

		[parameter(Mandatory = $false)]
		[System.DirectoryServices.Protocols.DirectoryControl[]]
		#Additional controls that caller may need to add to request
		$AdditionalControls = @(),

		[parameter(Mandatory = $false)]
		[timespan]
		#Time before request times out.
		#Default: [TimeSpan]::Zero, which means that no specific timeout provided
		$Timeout = [TimeSpan]::Zero,

		[switch]
		#When turned on, command does not allow permissive modify and returns error if adding value to collection that's already there, or deleting value that's not there
		#when not specified, permissive modify is enabled on the request
		$NoPermissiveModify,

		[Switch]
		#When turned on, command returns modified object to pipeline
		#This is useful when different types of modifications need to be done on single object
		$Passthrough
	)

	begin {
		EnsureLdapConnection -LdapConnection $LdapConnection
	}

	Process {
		if ([string]::IsNullOrEmpty($Object.DistinguishedName)) {
			throw (new-object System.ArgumentException("Input object missing DistinguishedName property"))
		}

		[System.DirectoryServices.Protocols.ModifyRequest]$rqMod = new-object System.DirectoryServices.Protocols.ModifyRequest
		$rqMod.DistinguishedName = $Object.DistinguishedName.ToString()
		#only add permissive modify control if allowed
		if ($NoPermissiveModify -eq $false) {
			$permissiveModifyRqc = new-object System.DirectoryServices.Protocols.PermissiveModifyControl
			$permissiveModifyRqc.IsCritical = $false
			$rqMod.Controls.Add($permissiveModifyRqc) > $null
		}

		#add additional controls that caller may have passed
		foreach ($ctrl in $AdditionalControls) { $rqMod.Controls.Add($ctrl) > $null }

		foreach ($prop in (Get-Member -InputObject $Object -MemberType NoteProperty)) {
			if ($prop.Name -eq "distinguishedName") { continue } #Dn is always ignored
			if ($IgnoredProps -contains $prop.Name) { continue }
			# SDSP_INDIVIDUAL_UPDATES Updated: $xxx.Count to $($xxx | Measure-Object).Count
			if (($($IncludedProps | Measure-Object).Count -gt 0) -and ($IncludedProps -notcontains $prop.Name)) { continue }
			[System.DirectoryServices.Protocols.DirectoryAttribute]$propMod = new-object System.DirectoryServices.Protocols.DirectoryAttributeModification
			$transform = $script:RegisteredTransforms[$prop.Name]
			$binaryInput = ($null -ne $transform -and $transform.BinaryInput -eq $true) -or ($prop.Name -in $BinaryProps)
			$propMod.Name = $prop.Name

			if ($null -ne $transform -and $null -ne $transform.OnSave) {
				#transform defined -> transform to form accepted by directory
				$attrVal = @(& $transform.OnSave -Values $Object.($prop.Name))
			} else {
				#no transform defined - take value as-is
				$attrVal = $Object.($prop.Name)
			}

			if ($null -ne $attrVal) {
				# SDSP_INDIVIDUAL_UPDATES Updated: $xxx.Count to $($xxx | Measure-Object).Count
				if ($($attrVal | Measure-Object).Count -gt 0) {
					$propMod.Operation = $Mode
					if ($binaryInput) {
						foreach ($val in $attrVal) {
							$propMod.Add([byte[]]$val) > $null
						}
					} else {
						$propMod.AddRange([string[]]($attrVal))
					}
					$rqMod.Modifications.Add($propMod) > $null
				}
			} else {
				#source object has no value for property - we're removing value on target
				$propMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
				$rqMod.Modifications.Add($propMod) > $null
			}
		}
		# SDSP_INDIVIDUAL_UPDATES Updated: $xxx.Count to $($xxx | Measure-Object).Count
		if ($($rqMod.Modifications | Measure-Object).Count -gt 0) {
			if ($Timeout -ne [TimeSpan]::Zero) {
				$response = $LdapConnection.SendRequest($rqMod, $Timeout) -as [System.DirectoryServices.Protocols.ModifyResponse]
			} else {
                $response = $LdapConnection.SendRequest($rqMod) -as [System.DirectoryServices.Protocols.ModifyResponse]
            }
            #handle failed operation that does not throw itself
            if($null -ne $response -and $response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                throw (new-object System.DirectoryServices.Protocols.LdapException(([int]$response.ResultCode), "$($rqMod.DistinguishedName)`: $($response.ResultCode)`: $($response.ErrorMessage)", $response.ErrorMessage))
            }
		}
		#if requested, pass the object to pipeline for further processing
		if ($Passthrough) { $Object }
	}
}
Function Find-LdapObject {
	<#
.SYNOPSIS
	Searches LDAP server in given search root and using given search filter

.DESCRIPTION
	Searches LDAP server identified by LDAP connection passed as parameter.
	Attributes of returned objects are retrieved via ranged attribute retrieval by default. This allows to retrieve all attributes, including computed ones, but has impact on performance as each attribute generated own LDAP server query. Tu turn ranged attribute retrieval off, set parameter RangeSize to zero.
	Optionally, attribute values can be transformed to complex types using transform registered for an attribute with 'Load' action.

.OUTPUTS
	Search results as PSCustomObjects with requested properties as strings, byte streams or complex types produced by transforms

.EXAMPLE
Find-LdapObject -LdapConnection [string]::Empty -SearchFilter:"(&(sn=smith)(objectClass=user)(objectCategory=organizationalPerson))" -SearchBase:"cn=Users,dc=myDomain,dc=com"

Description
-----------
This command connects to domain controller of caller's domain on port 389 and performs the search

.EXAMPLE
$Ldap = Get-LdapConnection
Find-LdapObject -LdapConnection $Ldap -SearchFilter:'(&(cn=jsmith)(objectClass=user)(objectCategory=organizationalPerson))' -SearchBase:'ou=Users,dc=myDomain,dc=com' -PropertiesToLoad:@('sAMAccountName','objectSid') -BinaryProps:@('objectSid')

Description
-----------
This command connects to to domain controller of caller's domain and performs the search, returning value of objectSid attribute as byte stream

.EXAMPLE
$Ldap = Get-LdapConnection -LdapServer:mydc.mydomain.com -EncryptionType:SSL
Find-LdapObject -LdapConnection $Ldap -SearchFilter:"(&(sn=smith)(objectClass=user)(objectCategory=organizationalPerson))" -SearchBase:"ou=Users,dc=myDomain,dc=com"

Description
-----------
This command connects to given LDAP server and performs the search via SSL

.EXAMPLE
$Ldap = Get-LdapConnection -LdapServer "mydc.mydomain.com"

Find-LdapObject -LdapConnection:$Ldap -SearchFilter:"(&(sn=smith)(objectClass=user)(objectCategory=organizationalPerson))" -SearchBase:"cn=Users,dc=myDomain,dc=com"

Find-LdapObject -LdapConnection:$Ldap -SearchFilter:"(&(cn=myComputer)(objectClass=computer)(objectCategory=organizationalPerson))" -SearchBase:"ou=Computers,dc=myDomain,dc=com" -PropertiesToLoad:@("cn","managedBy")

Description
-----------
This command creates the LDAP connection object and passes it as parameter. Connection remains open and ready for reuse in subsequent searches

.EXAMPLE
Get-LdapConnection -LdapServer "mydc.mydomain.com" > $null

$Dse = Get-RootDse

Find-LdapObject -SearchFilter:"(&(sn=smith)(objectClass=user)(objectCategory=organizationalPerson))" -SearchBase:"cn=Users,dc=myDomain,dc=com"

Find-LdapObject -SearchFilter:"(&(cn=myComputer)(objectClass=computer)(objectCategory=organizationalPerson))" -SearchBase:"ou=Computers,dc=myDomain,dc=com" -PropertiesToLoad:@("cn","managedBy")

Description
-----------
This command creates the LDAP connection object and stores it in session variable. Following commands take the connection information from session variable, so the connection object does not need to be passed from command line.

.EXAMPLE
$Ldap = Get-LdapConnection -LdapServer "mydc.mydomain.com"
Find-LdapObject -LdapConnection:$Ldap -SearchFilter:"(&(cn=SEC_*)(objectClass=group)(objectCategory=group))" -SearchBase:"cn=Groups,dc=myDomain,dc=com" | `
Find-LdapObject -LdapConnection:$Ldap -ASQ:"member" -SearchScope:"Base" -SearchFilter:"(&(objectClass=user)(objectCategory=organizationalPerson))" -propertiesToLoad:@("sAMAccountName","givenName","sn") | `
Select-Object * -Unique

Description
-----------
This one-liner lists sAMAccountName, first and last name, and DN of all users who are members of at least one group whose name starts with "SEC_" string

.EXAMPLE
$Ldap = Get-LdapConnection -Credential (Get-Credential)
Find-LdapObject -LdapConnection $Ldap -SearchFilter:"(&(cn=myComputer)(objectClass=computer)(objectCategory=organizationalPerson))" -SearchBase:"ou=Computers,dc=myDomain,dc=com" -PropertiesToLoad:@("cn","managedBy") -RangeSize 0

Description
-----------
This command creates explicit credential and uses it to authenticate LDAP query.
Then command retrieves data without ranged attribute value retrieval.

.EXAMPLE
$Users = Find-LdapObject -LdapConnection (Get-LdapConnection) -SearchFilter:"(&(sn=smith)(objectClass=user)(objectCategory=organizationalPerson))" -SearchBase:"cn=Users,dc=myDomain,dc=com" -AdditionalProperties:@("Result")
foreach($user in $Users)
{
	try
	{
		#do some processing
		$user.Result="OK"
	}
	catch
	{
		#report processing error
		$user.Result=$_.Exception.Message
	}
}
#report users with results of processing for each of them
$Users

Description
-----------
This command connects to domain controller of caller's domain on port 389 and performs the search.
For each user found, it also defines 'Result' property on returned object. Property is later used to store result of processing on user account

.EXAMPLE
$Ldap = Get-LdapConnection -LdapServer:ldap.mycorp.com -AuthType:Anonymous
Find-LdapObject -LdapConnection $ldap -SearchFilter:"(&(sn=smith)(objectClass=user)(objectCategory=organizationalPerson))" -SearchBase:"ou=People,ou=mycorp,o=world"

Description
-----------
This command connects to given LDAP server and performs the search anonymously.

.EXAMPLE
$Ldap = Get-LdapConnection -LdapServer:ldap.mycorp.com
$dse = Get-RootDSE -LdapConnection $conn
Find-LdapObject -LdapConnection $ldap -SearchFilter:"(&(objectClass=user)(objectCategory=organizationalPerson))" -SearchBase:"ou=People,ou=mycorp,o=world" -PropertiesToLoad *

Description
-----------
This command connects to given LDAP server and performs the direct search, retrieving all properties with value from objects found by search

.EXAMPLE
$Ldap = Get-LdapConnection -LdapServer:ldap.mycorp.com
$dse = Get-RootDSE -LdapConnection $conn
Find-LdapObject -LdapConnection $ldap -SearchFilter:"(&(objectClass=group)(objectCategory=group)(cn=MyVeryLargeGroup))" -SearchBase:"ou=People,ou=mycorp,o=world" -PropertiesToLoad member -RangeSize 1000

Description
-----------
This command connects to given LDAP server on default port with Negotiate authentication
Next commands use the connection to get Root DSE object and list of all members of a group, using ranged retrieval ("paging support on LDAP attributes")

.EXAMPLE
$creds=Get-Credential -UserName 'CN=MyUser,CN=Users,DC=mydomain,DC=com' -Message 'Enter password to user with this DN' -Title 'Password needed'
Get-LdapConnection -LdapServer dc.mydomain.com -Port 636 -AuthType Basic -Credential $creds > $null
$dse = Get-RootDSE

Description
-----------
This command connects to given LDAP server with simple bind over TLS (TLS needed for basic authentication), storing the connection in session variable.
Next command uses connection from session variable to get Root DSE object.
Usage of Basic authentication is typically way to go on client platforms that do not support other authentication schemes, such as Negotiate

.EXAMPLE
Get-LdapConnection -LdapServer dc.mydomain.com > $null
$dse = Get-RootDSE
#obtain initial sync cookie valid from now on
Find-LdapObject -searchBase $dse.defaultNamingContext -searchFilter '(objectClass=domainDns)' -PropertiesToLoad 'name' -DirSync Standard > $null
$show the cookie
Get-LdapDirSyncCookie

Description
-----------
This command connects to given LDAP server and obtains initial cookie that represents current time - output does not contain full sync.

.LINK
More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx
#>
	Param (
		[parameter()]
		[System.DirectoryServices.Protocols.LdapConnection]
		#existing LDAPConnection object retrieved with cmdlet Get-LdapConnection
		#When we perform many searches, it is more effective to use the same connection rather than create new connection for each search request.
		$LdapConnection = $script:LdapConnection,

		[parameter(Mandatory = $true)]
		[String]
		#Search filter in LDAP syntax
		$searchFilter,

		[parameter(Mandatory = $false, ValueFromPipeline = $true)]
		[Object]
		#DN of container where to search
		$searchBase,

		[parameter(Mandatory = $false)]
		[System.DirectoryServices.Protocols.SearchScope]
		#Search scope
		#Ignored for DirSync searches
		#Default: Subtree
		$searchScope = 'Subtree',

		[parameter(Mandatory = $false)]
		[String[]]
		#List of properties we want to return for objects we find.
		#Default: empty array, meaning no properties are returned
		$PropertiesToLoad = @(),

		[parameter(Mandatory = $false)]
		[String]
		#Name of attribute for Attribute Scoped Query (ASQ)
		#Note: searchScope must be set to Base for ASQ
		#Note: #Ignored for DirSync searches
		#Default: empty string
		$ASQ,

		[parameter(Mandatory = $false)]
		[UInt32]
		#Page size for paged search. Zero means that paging is disabled
		#Ignored for DirSync searches
		#Default: 500
		$PageSize = 500,

		[parameter(Mandatory = $false)]
		[Int32]
		# Specification of attribute value retrieval mode
		# Negative value means that attribute values are loaded directly with list of objects
		# Zero means that ranged attribute value retrieval is disabled and attribute values are returned in single request.
		# Positive value  means that each attribute value is loaded in dedicated requests in batches of given size. Usable for loading of group members
		# Ignored for DirSync searches
		# Note: Default in query policy in AD is 1500; make sure that you do not use here higher value than allowed by LDAP server
		# Default: -1 (means that ranged attribute retrieval is not used by default)
		# IMPORTANT: default changed in v2.1.1 - previously it was 1000. Changed because it typically caused large performance impact when using -PropsToLoad '*'
		$RangeSize = -1,

		[parameter(Mandatory = $false)]
		[Int32]
		#Max number of results to return from the search
		#Negative number means that all available results are returned
		#Ignored for DirSync searches
		$SizeLimit = -1,
		[parameter(Mandatory = $false)]
		[alias('BinaryProperties')]
		[String[]]
		#List of properties that we want to load as byte stream.
		#Note: Those properties must also be present in PropertiesToLoad parameter. Properties not listed here are loaded as strings
		#Note: When using transform for a property, then transform "knows" if it's binary or not, so no need to specify it in BinaryProps
		#Default: empty list, which means that all properties are loaded as strings
		$BinaryProps = @(),

		[parameter(Mandatory = $false)]
		[String[]]
		<#
			List of properties that we want to be defined on output object, but we do not want to load them from AD.
			Properties listed here must NOT occur in propertiesToLoad list
			Command defines properties on output objects and sets the value to $null
			Good for having output object with all props that we need for further processing, so we do not need to add them ourselves
			Default: empty list, which means that we don't want any additional properties defined on output object
			#>
		$AdditionalProperties = @(),

        [parameter()]
        [String[]]
        #Properties to ignore when loading objects from LDAP
        #Default: empty list, which means that no properties are ignored
        $IgnoredProperties=@(),

		[parameter(Mandatory = $false)]
		[System.DirectoryServices.Protocols.DirectoryControl[]]
		#additional controls that caller may need to add to request
		$AdditionalControls = @(),

		[parameter(Mandatory = $false)]
		[Timespan]
		#Number of seconds before request times out.
		#Default: [TimeSpan]::Zero, which means that no specific timeout provided
		$Timeout = [TimeSpan]::Zero,

		[Parameter(Mandatory = $false)]
		[ValidateSet('None', 'Standard', 'ObjectSecurity', 'StandardIncremental', 'ObjectSecurityIncremental')]
		[string]
		#whether to issue search with DirSync. Allowed options:
		#None: Standard search without DirSync
		#Standard: Dirsync search using standard permissions of caller. Requires Replicate Directory Changes permission
		#ObjectSecurity: DirSync search using Replicate Directory Changes permission that reveals object that caller normally does not have permission to see. Requires Requires Replicate Directory Changes All permission
		#Note: When Standard or ObjectSecurity specified, searchBase must be set to root of directory partition
		#For specs, see https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-ADTS/2213a7f2-0a36-483c-b2a4-8574d53aa1e3
		#Default: None, which means search without DirSync
		$DirSync = 'None',

		[Switch]
		#Whether to alphabetically sort attributes on returned objects
		$SortAttributes
	)

	Begin {
		EnsureLdapConnection -LdapConnection $LdapConnection
		Function PostProcess {
			param
			(
				[Parameter(ValueFromPipeline)]
				[System.Collections.Hashtable]$data,
				[bool]$Sort
			)

			process {
				#Flatten
				$coll = @($data.Keys)
				foreach ($prop in $coll) {
					$data[$prop] = [Flattener]::FlattenArray($data[$prop])
					<#
					#support for DirSync struct for Add/Remove values of multivalued props
					if($data[$prop] -is [System.Collections.Hashtable])
					{
						$data[$prop] = [pscustomobject]$data[$prop]
					}
					#>
				}
				if ($Sort) {
					#flatten and sort attributes
					$coll = @($coll | Sort-Object)
					$sortedData = [ordered]@{}
					foreach ($prop in $coll) { $sortedData[$prop] = $data[$prop] }
					#return result to pipeline
					[PSCustomObject]$sortedData
				} else {
					[PSCustomObject]$data
				}
			}
		}

		#remove unwanted props
		$PropertiesToLoad = @($propertiesToLoad | where-object { $_ -notin @('distinguishedName', '1.1') })
		#if asterisk in list of props to load, load all props available on object despite of  required list
		# SDSP_INDIVIDUAL_UPDATES Updated: $xxx.Count to $($xxx | Measure-Object).Count
		if ($($propertiesToLoad | Measure-Object).Count -eq 0) { $NoAttributes = $true } else { $NoAttributes = $false }
		if ('*' -in $PropertiesToLoad) { $PropertiesToLoad = @() }

		#configure LDAP connection
		#preserve original value of referral chasing
		$referralChasing = $LdapConnection.SessionOptions.ReferralChasing
		if ($pageSize -gt 0) {
			#paged search silently fails in AD when chasing referrals
			$LdapConnection.SessionOptions.ReferralChasing = "None"
		}
	}

	Process {
		#build request
		$rq = new-object System.DirectoryServices.Protocols.SearchRequest

		#search base
		#we support passing $null as SearchBase - used for Global Catalog searches
		if ($null -ne $searchBase) {
			#we support pipelining of strings, or objects containing distinguishedName property
			switch ($searchBase.GetType().Name) {
                "String" {
                    $rq.DistinguishedName = $searchBase
                    break;
                }
                'DistinguishedName' {
                    $rq.DistinguishedName=$searchBase.ToString()
                    break;
                }
                default {
					if ($null -ne $searchBase.distinguishedName) {
                        #covers both string and DistinguishedName types
                        $rq.DistinguishedName=$searchBase.distinguishedName.ToString()
					}
				}
			}
		}

		#search filter in LDAP syntax
		$rq.Filter = $searchFilter


		if ($DirSync -eq 'None') {
			#paged search control for paged search
			#for DirSync searches, paging is not used
			if ($pageSize -gt 0) {
				[System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($pageSize)
				#asking server for best effort with paging
				$pagedRqc.IsCritical = $false
				$rq.Controls.Add($pagedRqc) > $null
			}

			#Attribute scoped query
			#Not supported for DirSync
			if (-not [String]::IsNullOrEmpty($asq)) {
				[System.DirectoryServices.Protocols.AsqRequestControl]$asqRqc = new-object System.DirectoryServices.Protocols.AsqRequestControl($ASQ)
				$rq.Controls.Add($asqRqc) > $null
			}

			#search scope
			$rq.Scope = $searchScope

			#size limit
			if ($SizeLimit -gt 0) {
				$rq.SizeLimit = $SizeLimit
			}
		} else {
			#specifics for DirSync searches

			#only supported scope is subtree
			$rq.Scope = 'Subtree'

			#Windows AD/LDS server always returns objectGuid for DirSync.
			#We do not want to hide it, we just make sure it is returned in proper format
			if ('objectGuid' -notin $BinaryProps) {
				$BinaryProps += 'objectGuid'
			}
		}

		#add additional controls that caller may have passed
		foreach ($ctrl in $AdditionalControls) { $rq.Controls.Add($ctrl) > $null }

		if ($Timeout -ne [timespan]::Zero) {
			#server side timeout
			$rq.TimeLimit = $Timeout
		}

		switch ($DirSync) {
			'None' {
				#standard search
				if ($NoAttributes) {
					#just run as fast as possible when not loading any attribs
					GetResultsDirectlyInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -IgnoredProperties $IgnoredProperties -BinaryProperties $BinaryProps -Timeout $Timeout -NoAttributes | PostProcess
				} else {
					#load attributes according to desired strategy
					switch ($RangeSize) {
						{ $_ -lt 0 } {
							#directly via single ldap call
							#some attribs may not be loaded (e.g. computed)
							GetResultsDirectlyInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -IgnoredProperties $IgnoredProperties -BinaryProperties $BinaryProps -Timeout $Timeout | PostProcess -Sort $SortAttributes
							break
						}
						0 {
							#query attributes for each object returned using base search
							#but not using ranged retrieval, so multivalued attributes with many values may not be returned completely
							GetResultsIndirectlyInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -IgnoredProperties $IgnoredProperties -AdditionalControls $AdditionalControls -BinaryProperties $BinaryProps -Timeout $Timeout | PostProcess -Sort $SortAttributes
							break
						}
						{ $_ -gt 0 } {
							#query attributes for each object returned using base search and each attribute value with ranged retrieval
							#so even multivalued attributes with many values are returned completely
							GetResultsIndirectlyRangedInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -IgnoredProperties $IgnoredProperties -AdditionalControls $AdditionalControls -BinaryProperties $BinaryProps -Timeout $Timeout -RangeSize $RangeSize | PostProcess -Sort $SortAttributes
							break
						}
					}
				}
				break;
			}
			'Standard' {
				GetResultsDirSyncInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -IgnoredProperties $IgnoredProperties -BinaryProperties $BinaryProps -Timeout $Timeout | PostProcess -Sort $SortAttributes
				break;
			}
			'ObjectSecurity' {
				GetResultsDirSyncInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -IgnoredProperties $IgnoredProperties -BinaryProperties $BinaryProps -Timeout $Timeout -ObjectSecurity | PostProcess -Sort $SortAttributes
				break;
			}
			'StandardIncremental' {
				GetResultsDirSyncInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -IgnoredProperties $IgnoredProperties -BinaryProperties $BinaryProps -Timeout $Timeout -Incremental | PostProcess -Sort $SortAttributes
				break;
			}
			'ObjectSecurityIncremental' {
				GetResultsDirSyncInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -IgnoredProperties $IgnoredProperties -BinaryProperties $BinaryProps -Timeout $Timeout -ObjectSecurity -Incremental | PostProcess -Sort $SortAttributes
				break;
			}
		}
	}

	End {
		if (($pageSize -gt 0) -and ($null -ne $ReferralChasing)) {
			#revert to original value of referral chasing on connection
			$LdapConnection.SessionOptions.ReferralChasing = $ReferralChasing
		}
	}
}
Function Get-LdapAttributeTransform {
	<#
.SYNOPSIS
	Lists registered attribute transform logic

.OUTPUTS
	List of registered transforms

.LINK
More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx
More about attribute transforms and how to create them: https://github.com/jformacek/S.DS.P

#>
	[CmdletBinding()]
	param (
		[Parameter()]
		[Switch]
		#Lists all transforms available
		$ListAvailable
	)
	if ($ListAvailable) {
		$TransformList = Get-ChildItem -Path "$PSScriptRoot\Transforms\*.ps1" -ErrorAction SilentlyContinue
		foreach ($transformFile in $TransformList) {
			$transform = (& $transformFile.FullName)
			$transform = $transform | Add-Member -MemberType NoteProperty -Name 'TransformName' -Value ([System.IO.Path]::GetFileNameWithoutExtension($transformFile.FullName)) -PassThru
			$transform | Select-Object TransformName, SupportedAttributes
		}
	} else {
		foreach ($attrName in ($script:RegisteredTransforms.Keys | Sort-object)) {
			[PSCustomObject]([Ordered]@{
					AttributeName = $attrName
					TransformName = $script:RegisteredTransforms[$attrName].Name
				})
		}
	}
}
Function Get-LdapConnection {
	<#
.SYNOPSIS
	Connects to LDAP server and returns LdapConnection object

.DESCRIPTION
	Creates connection to LDAP server according to parameters passed.
	Stores returned LdapConnection object to module cache where other commands look for it when they do not receive connection from parameter.
.OUTPUTS
	LdapConnection object

.EXAMPLE
Get-LdapConnection -LdapServer "mydc.mydomain.com" -EncryptionType Kerberos

Description
-----------
Returns LdapConnection for caller's domain controller, with active Kerberos Encryption for data transfer security

.EXAMPLE
Get-LdapConnection -LdapServer "mydc.mydomain.com" -EncryptionType Kerberos -Credential (Get-AdmPwdCredential)

Description
-----------
Returns LdapConnection for caller's domain controller, with active Kerberos Encryption for data transfer security, authenticated by automatically retrieved password from AdmPwd.E client

.EXAMPLE
$thumb = '059d5318118e61fe54fd361ae07baf4644a67347'
$cert = (dir Cert:\CurrentUser\my).Where{$_.Thumbprint -eq $Thumb}[0]
Get-LdapConnection -LdapServer "mydc.mydomain.com" -Port 636 -CertificateValidationFlags ([System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority) -ClientCertificate $cert

Description
-----------
Returns LdapConnection over SSL for given LDAP server, authenticated by a client certificate and allowing LDAP server to use self-signed certificate
.LINK
More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx
#>
	Param
	(
		[parameter(Mandatory = $false)]
		[String[]]
		#LDAP server name
		#Default: default server given by environment
		$LdapServer = [String]::Empty,

		[parameter(Mandatory = $false)]
		[Int32]
		#LDAP server port
		#Default: 389
		$Port = 389,

		[parameter(Mandatory = $false)]
		[PSCredential]
		#Use different credentials when connecting
		$Credential = $null,

		[parameter(Mandatory = $false)]
		[ValidateSet('None', 'TLS', 'SSL', 'Kerberos')]
		[string]
		#Type of encryption to use.
		$EncryptionType = 'None',

		[Switch]
		#enable support for Fast Concurrent Bind
		$FastConcurrentBind,

		[Switch]
		#enable support for UDP transport
		$ConnectionLess,

		[parameter(Mandatory = $false)]
		[Timespan]
		#Time before connection times out.
		#Default: 120 seconds
		$Timeout = [TimeSpan]::Zero,

		[Parameter(Mandatory = $false)]
		[System.DirectoryServices.Protocols.AuthType]
		#The type of authentication to use with the LdapConnection
		$AuthType,

		[Parameter(Mandatory = $false)]
		[int]
		#Requested LDAP protocol version
		$ProtocolVersion = 3,

		[Parameter(Mandatory = $false)]
		[System.Security.Cryptography.X509Certificates.X509VerificationFlags]
		#Requested LDAP protocol version
		$CertificateValidationFlags = 'NoFlag',

		[Parameter(Mandatory = $false)]
		[System.Security.Cryptography.X509Certificates.X509Certificate2]
		#Client certificate used for authentication instead of credentials
		#See https://docs.microsoft.com/en-us/windows/win32/api/winldap/nc-winldap-queryclientcert
		$ClientCertificate
	)

	Begin {
		# SDSP_INDIVIDUAL_UPDATES
		#if ($null -eq $script:ConnectionParams) {
		$script:ConnectionParams = @{}
		#}
	}
	Process {

		$FullyQualifiedDomainName = $false;
		[System.DirectoryServices.Protocols.LdapDirectoryIdentifier]$di = new-object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $Port, $FullyQualifiedDomainName, $ConnectionLess)

		if ($null -ne $Credential) {
			$LdapConnection = new-object System.DirectoryServices.Protocols.LdapConnection($di, $Credential.GetNetworkCredential())
		} else {
			$LdapConnection = new-object System.DirectoryServices.Protocols.LdapConnection($di)
		}
		$LdapConnection.SessionOptions.ProtocolVersion = $ProtocolVersion


		#store connection params for each server in global variable, so as it is reachable from callback scriptblocks
		$connectionParams = @{}
		foreach ($server in $LdapServer) { $script:ConnectionParams[$server] = $connectionParams }
		if ($CertificateValidationFlags -ne 'NoFlag') {
			$connectionParams['ServerCertificateValidationFlags'] = $CertificateValidationFlags
			#server certificate validation callback
			$LdapConnection.SessionOptions.VerifyServerCertificate = {
				param(
					[Parameter(Mandatory)][DirectoryServices.Protocols.LdapConnection]$LdapConnection,
					[Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
				)
				Write-Verbose "Validating server certificate $($Certificate.Subject) with thumbprint $($Certificate.Thumbprint) and issuer $($Certificate.Issuer)"
				[System.Security.Cryptography.X509Certificates.X509Chain] $chain = new-object System.Security.Cryptography.X509Certificates.X509Chain
				foreach ($server in $LdapConnection.Directory.Servers) {
					if ($server -in $script:ConnectionParams.Keys) {
						$connectionParam = $script:ConnectionParams[$server]
						if ($null -ne $connectionParam['ServerCertificateValidationFlags']) {
							$chain.ChainPolicy.VerificationFlags = $connectionParam['ServerCertificateValidationFlags']
							break;
						}
					}
				}
				$result = $chain.Build($Certificate)
				return $result
			}
		}

		if ($null -ne $ClientCertificate) {
			$connectionParams['ClientCertificate'] = $ClientCertificate
			#client certificate retrieval callback
			#we just support explicit certificate now
			$LdapConnection.SessionOptions.QueryClientCertificate = { param(
					[Parameter(Mandatory)][DirectoryServices.Protocols.LdapConnection]$LdapConnection,
					[Parameter(Mandatory)][byte[][]]$TrustedCAs
				)
				$clientCert = $null
				foreach ($server in $LdapConnection.Directory.Servers) {
					if ($server -in $script:ConnectionParams.Keys) {
						$connectionParam = $script:ConnectionParams[$server]
						if ($null -ne $connectionParam['ClientCertificate']) {
							$clientCert = $connectionParam['ClientCertificate']
							break;
						}
					}
				}
				if ($null -ne $clientCert) {
					Write-Verbose "Using client certificate $($clientCert.Subject) with thumbprint $($clientCert.Thumbprint) from issuer $($clientCert.Issuer)"
				}
				return $clientCert
			}
		}

		if ($null -ne $AuthType) {
			$LdapConnection.AuthType = $AuthType
		}


		switch ($EncryptionType) {
			'None' { break }
			'TLS' {
				$LdapConnection.SessionOptions.StartTransportLayerSecurity($null)
				break
			}
			'Kerberos' {
				$LdapConnection.SessionOptions.Sealing = $true
				$LdapConnection.SessionOptions.Signing = $true
				break
			}
			'SSL' {
				$LdapConnection.SessionOptions.SecureSocketLayer = $true
				break
			}
		}
		if ($Timeout -ne [TimeSpan]::Zero) {
			$LdapConnection.Timeout = $Timeout
		}

		if ($FastConcurrentBind) {
			$LdapConnection.SessionOptions.FastConcurrentBind()
		}
		$script:LdapConnection = $LdapConnection
		$LdapConnection
	}
}
Function Get-LdapDirSyncCookie {
	<#
.SYNOPSIS
	Returns DirSync cookie serialized as Base64 string.
	Caller is responsible to save and call Set-LdapDirSyncCookie when continuing data retrieval via directory synchronization

.OUTPUTS
	DirSync cookie as Base64 string

.EXAMPLE
Get-LdapConnection -LdapServer "mydc.mydomain.com"

$dse = Get-RootDse
$cookie = Get-Content .\storedCookieFromPreviousIteration.txt
$cookie | Set-LdapDirSyncCookie
$dirUpdates=Find-LdapObject -SearchBase $dse.defaultNamingContext -searchFilter '(objectClass=group)' -PropertiesToLoad 'member' -DirSync StandardIncremental
#process updates
foreach($record in $dirUpdates)
{
	#...
}

$cookie = Get-LdapDirSyncCookie
$cookie | Set-Content  .\storedCookieFromPreviousIteration.txt

Description
----------
This example loads dirsync cookie stored in file and performs dirsync search for updates that happened after cookie was generated
Then it stores updated cookie back to file for usage in next iteration

.EXAMPLE
Get-LdapConnection -LdapServer dc.mydomain.com > $null
$dse = Get-RootDSE
#obtain initial sync cookie valid from now on
Find-LdapObject -searchBase $dse.defaultNamingContext -searchFilter '(objectClass=domainDns)' -PropertiesToLoad 'name' -DirSync Standard > $null
$show the cookie
Get-LdapDirSyncCookie

Description
-----------
This example connects to given LDAP server and obtains initial cookie that represents current time - output does not contain full sync data.


.LINK
More about DirSync: https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-ADTS/2213a7f2-0a36-483c-b2a4-8574d53aa1e3

#>
	param()

	process {
		if ($null -ne $script:DirSyncCookie) {
			[Convert]::ToBase64String($script:DirSyncCookie)
		}
	}
}
Function Get-RootDSE {
	<#
	.SYNOPSIS
		Connects to LDAP server and retrieves metadata

	.DESCRIPTION
		Retrieves LDAP server metadata from Root DSE object
		Current implementation is specialized to metadata found on Windows LDAP server, so on other platforms, some metadata may be empty.
		Or other platforms may publish interesting metadata not available on Windows LDAP - feel free to add here

	.OUTPUTS
		Custom object containing information about LDAP server

	.EXAMPLE
	Get-LdapConnection | Get-RootDSE

	Description
	-----------
	This command connects to closest domain controller of caller's domain on port 389 and returns metadata about the server

	.EXAMPLE
	#connect to server and authenticate with client certificate
	$thumb = '059d5318118e61fe54fd361ae07baf4644a67347'
	cert = (dir Cert:\CurrentUser\my).Where{$_.Thumbprint -eq $Thumb}[0]
	Get-LdapConnection -LdapServer "mydc.mydomain.com" `
	  -Port 636 `
	  -ClientCertificate $cert `
	  -CertificateValidationFlags [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreRootRevocationUnknown

	Description
	-----------
	Gets Ldap connection authenticated by client certificate authentication and allowing server certificate from CA with unavailable CRL.

	.LINK
	More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx
	#>

	Param (
		[parameter(ValueFromPipeline = $true)]
		[System.DirectoryServices.Protocols.LdapConnection]
		#existing LDAPConnection object retrieved via Get-LdapConnection
		#When we perform many searches, it is more effective to use the same connection rather than create new connection for each search request.
		$LdapConnection = $script:LdapConnection
	)
	Begin {
		EnsureLdapConnection -LdapConnection $LdapConnection

		#initialize output objects via hashtable --> faster than add-member
		#create default initializer beforehand
		$propDef = [ordered]@{`
				rootDomainNamingContext = $null; configurationNamingContext = $null; schemaNamingContext = $null; `
				'defaultNamingContext' = $null; 'namingContexts' = $null; `
				'dnsHostName' = $null; 'ldapServiceName' = $null; 'dsServiceName' = $null; 'serverName' = $null; `
				'supportedLdapPolicies' = $null; 'supportedSASLMechanisms' = $null; 'supportedControl' = $null; 'supportedConfigurableSettings' = $null; `
				'currentTime' = $null; 'highestCommittedUSN' = $null; 'approximateHighestInternalObjectID' = $null; `
				'dsSchemaAttrCount' = $null; 'dsSchemaClassCount' = $null; 'dsSchemaPrefixCount' = $null; `
				'isGlobalCatalogReady' = $null; 'isSynchronized' = $null; 'pendingPropagations' = $null; `
				'domainControllerFunctionality' = $null; 'domainFunctionality' = $null; 'forestFunctionality' = $null; `
				'subSchemaSubEntry' = $null; `
				'msDS-ReplAllInboundNeighbors' = $null; 'msDS-ReplConnectionFailures' = $null; 'msDS-ReplLinkFailures' = $null; 'msDS-ReplPendingOps' = $null; `
				'dsaVersionString' = $null; 'serviceAccountInfo' = $null; 'LDAPPoliciesEffective' = $null `

  }
	}
	Process {

		#build request
		$rq = new-object System.DirectoryServices.Protocols.SearchRequest
		$rq.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
		$rq.Attributes.AddRange($propDef.Keys) > $null

		#try to get extra information with ExtendedDNControl
		#RFC4511: Server MUST ignore unsupported controls marked as not critical
		[System.DirectoryServices.Protocols.ExtendedDNControl]$exRqc = new-object System.DirectoryServices.Protocols.ExtendedDNControl('StandardString')
		$exRqc.IsCritical = $false
		$rq.Controls.Add($exRqc) > $null

		try {
			$rsp = $LdapConnection.SendRequest($rq)
		} catch {
			throw $_.Exception
			return
		}
		#if there was error, let the exception go to caller and do not continue

		#sometimes server does not return anything if we ask for property that is not supported by protocol
		# SDSP_INDIVIDUAL_UPDATES Updated: $xxx.Count to $($xxx | Measure-Object).Count
		if ($($rsp.Entries | Measure-Object).Count -eq 0) {
			return;
		}

		$data = [PSCustomObject]$propDef

		if ($rsp.Entries[0].Attributes['configurationNamingContext']) {
			$data.configurationNamingContext = [NamingContext]::Parse($rsp.Entries[0].Attributes['configurationNamingContext'].GetValues([string])[0])
		}
		if ($rsp.Entries[0].Attributes['schemaNamingContext']) {
			$data.schemaNamingContext = [NamingContext]::Parse(($rsp.Entries[0].Attributes['schemaNamingContext'].GetValues([string]))[0])
		}
		if ($rsp.Entries[0].Attributes['rootDomainNamingContext']) {
			$data.rootDomainNamingContext = [NamingContext]::Parse($rsp.Entries[0].Attributes['rootDomainNamingContext'].GetValues([string])[0])
		}
		if ($rsp.Entries[0].Attributes['defaultNamingContext']) {
			$data.defaultNamingContext = [NamingContext]::Parse($rsp.Entries[0].Attributes['defaultNamingContext'].GetValues([string])[0])
		}
		if ($null -ne $rsp.Entries[0].Attributes['approximateHighestInternalObjectID']) {
			try {
				$data.approximateHighestInternalObjectID = [long]::Parse($rsp.Entries[0].Attributes['approximateHighestInternalObjectID'].GetValues([string]))
			} catch {
				#it isn't a numeric, just return what's stored without parsing
				$data.approximateHighestInternalObjectID = $rsp.Entries[0].Attributes['approximateHighestInternalObjectID'].GetValues([string])
			}
		}
		if ($null -ne $rsp.Entries[0].Attributes['highestCommittedUSN']) {
			try {
				$data.highestCommittedUSN = [long]::Parse($rsp.Entries[0].Attributes['highestCommittedUSN'].GetValues([string]))
			} catch {
				#it isn't a numeric, just return what's stored without parsing
				$data.highestCommittedUSN = $rsp.Entries[0].Attributes['highestCommittedUSN'].GetValues([string])
			}
		}
		if ($null -ne $rsp.Entries[0].Attributes['currentTime']) {
			$val = ($rsp.Entries[0].Attributes['currentTime'].GetValues([string]))[0]
			try {
				$data.currentTime = [DateTime]::ParseExact($val, 'yyyyMMddHHmmss.fZ', [CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None)
			} catch {
				$data.currentTime = $val
			}
		}
		if ($null -ne $rsp.Entries[0].Attributes['dnsHostName']) {
			$data.dnsHostName = ($rsp.Entries[0].Attributes['dnsHostName'].GetValues([string]))[0]
		}
		if ($null -ne $rsp.Entries[0].Attributes['ldapServiceName']) {
			$data.ldapServiceName = ($rsp.Entries[0].Attributes['ldapServiceName'].GetValues([string]))[0]
		}
		if ($null -ne $rsp.Entries[0].Attributes['dsServiceName']) {
			$val = ($rsp.Entries[0].Attributes['dsServiceName'].GetValues([string]))[0]
			if ($val.Contains(';')) {
				$data.dsServiceName = $val.Split(';')
			} else {
				$data.dsServiceName = $val
			}
		}
		if ($null -ne $rsp.Entries[0].Attributes['serverName']) {
			$val = ($rsp.Entries[0].Attributes['serverName'].GetValues([string]))[0]
			if ($val.Contains(';')) {
				$data.serverName = $val.Split(';')
			} else {
				$data.serverName = $val
			}
		}
		if ($null -ne $rsp.Entries[0].Attributes['supportedControl']) {
			$data.supportedControl = ( ($rsp.Entries[0].Attributes['supportedControl'].GetValues([string])) | Sort-Object )
		}
		if ($null -ne $rsp.Entries[0].Attributes['supportedLdapPolicies']) {
			$data.supportedLdapPolicies = ( ($rsp.Entries[0].Attributes['supportedLdapPolicies'].GetValues([string])) | Sort-Object )
		}
		if ($null -ne $rsp.Entries[0].Attributes['supportedSASLMechanisms']) {
			$data.supportedSASLMechanisms = ( ($rsp.Entries[0].Attributes['supportedSASLMechanisms'].GetValues([string])) | Sort-Object )
		}
		if ($null -ne $rsp.Entries[0].Attributes['supportedConfigurableSettings']) {
			$data.supportedConfigurableSettings = ( ($rsp.Entries[0].Attributes['supportedConfigurableSettings'].GetValues([string])) | Sort-Object )
		}
		if ($null -ne $rsp.Entries[0].Attributes['namingContexts']) {
			$data.namingContexts = @()
			foreach ($ctxDef in ($rsp.Entries[0].Attributes['namingContexts'].GetValues([string]))) {
				$data.namingContexts += [NamingContext]::Parse($ctxDef)
			}
		}
		if ($null -ne $rsp.Entries[0].Attributes['dsSchemaAttrCount']) {
			[long]$outVal = -1
			[long]::TryParse($rsp.Entries[0].Attributes['dsSchemaAttrCount'].GetValues([string]), [ref]$outVal) > $null
			$data.dsSchemaAttrCount = $outVal
		}
		if ($null -ne $rsp.Entries[0].Attributes['dsSchemaClassCount']) {
			[long]$outVal = -1
			[long]::TryParse($rsp.Entries[0].Attributes['dsSchemaClassCount'].GetValues([string]), [ref]$outVal) > $null
			$data.dsSchemaClassCount = $outVal
		}
		if ($null -ne $rsp.Entries[0].Attributes['dsSchemaPrefixCount']) {
			[long]$outVal = -1
			[long]::TryParse($rsp.Entries[0].Attributes['dsSchemaPrefixCount'].GetValues([string]), [ref]$outVal) > $null
			$data.dsSchemaPrefixCount = $outVal
		}
		if ($null -ne $rsp.Entries[0].Attributes['isGlobalCatalogReady']) {
			$data.isGlobalCatalogReady = [bool]$rsp.Entries[0].Attributes['isGlobalCatalogReady'].GetValues([string])
		}
		if ($null -ne $rsp.Entries[0].Attributes['isSynchronized']) {
			$data.isSynchronized = [bool]$rsp.Entries[0].Attributes['isSynchronized'].GetValues([string])
		}
		if ($null -ne $rsp.Entries[0].Attributes['pendingPropagations']) {
			$data.pendingPropagations = $rsp.Entries[0].Attributes['pendingPropagations'].GetValues([string])
		}
		if ($null -ne $rsp.Entries[0].Attributes['subSchemaSubEntry']) {
			$data.subSchemaSubEntry = $rsp.Entries[0].Attributes['subSchemaSubEntry'].GetValues([string])[0]
		}
		if ($null -ne $rsp.Entries[0].Attributes['domainControllerFunctionality']) {
			$data.domainControllerFunctionality = [int]$rsp.Entries[0].Attributes['domainControllerFunctionality'].GetValues([string])[0]
		}
		if ($null -ne $rsp.Entries[0].Attributes['domainFunctionality']) {
			$data.domainFunctionality = [int]$rsp.Entries[0].Attributes['domainFunctionality'].GetValues([string])[0]
		}
		if ($null -ne $rsp.Entries[0].Attributes['forestFunctionality']) {
			$data.forestFunctionality = [int]$rsp.Entries[0].Attributes['forestFunctionality'].GetValues([string])[0]
		}
		if ($null -ne $rsp.Entries[0].Attributes['msDS-ReplAllInboundNeighbors']) {
			$data.'msDS-ReplAllInboundNeighbors' = @()
			foreach ($val in $rsp.Entries[0].Attributes['msDS-ReplAllInboundNeighbors'].GetValues([string])) {
				$data.'msDS-ReplAllInboundNeighbors' += [xml]$Val.SubString(0, $Val.Length - 2)
			}
		}
		if ($null -ne $rsp.Entries[0].Attributes['msDS-ReplConnectionFailures']) {
			$data.'msDS-ReplConnectionFailures' = @()
			foreach ($val in $rsp.Entries[0].Attributes['msDS-ReplConnectionFailures'].GetValues([string])) {
				$data.'msDS-ReplConnectionFailures' += [xml]$Val.SubString(0, $Val.Length - 2)
			}
		}
		if ($null -ne $rsp.Entries[0].Attributes['msDS-ReplLinkFailures']) {
			$data.'msDS-ReplLinkFailures' = @()
			foreach ($val in $rsp.Entries[0].Attributes['msDS-ReplLinkFailures'].GetValues([string])) {
				$data.'msDS-ReplLinkFailures' += [xml]$Val.SubString(0, $Val.Length - 2)
			}
		}
		if ($null -ne $rsp.Entries[0].Attributes['msDS-ReplPendingOps']) {
			$data.'msDS-ReplPendingOps' = @()
			foreach ($val in $rsp.Entries[0].Attributes['msDS-ReplPendingOps'].GetValues([string])) {
				$data.'msDS-ReplPendingOps' += [xml]$Val.SubString(0, $Val.Length - 2)
			}
		}
		if ($null -ne $rsp.Entries[0].Attributes['dsaVersionString']) {
			$data.dsaVersionString = $rsp.Entries[0].Attributes['dsaVersionString'].GetValues([string])[0]
		}
		if ($null -ne $rsp.Entries[0].Attributes['serviceAccountInfo']) {
			$data.serviceAccountInfo = $rsp.Entries[0].Attributes['serviceAccountInfo'].GetValues([string])
		}
		if ($null -ne $rsp.Entries[0].Attributes['LDAPPoliciesEffective']) {
			$data.LDAPPoliciesEffective = @{}
			foreach ($val in $rsp.Entries[0].Attributes['LDAPPoliciesEffective'].GetValues([string])) {
				$vals = $val.Split(':')
				if ($vals.Length -gt 1) {
					$data.LDAPPoliciesEffective[$vals[0]] = $vals[1]
				}
			}
		}
		$data
	}
}
function New-LdapAttributeTransformDefinition {
	<#
.SYNOPSIS
	Creates definition of transform. Used by transform implementations.

.OUTPUTS
	Transform definition

.LINK
More about attribute transforms and how to create them: https://github.com/jformacek/S.DS.P

#>
	[CmdletBinding()]
	param
	(
		[Parameter(Position = 0)]
		[string[]]$SupportedAttributes,
		[switch]
		#Whether supported attributes need to be loaded from/saved to LDAP as binary stream
		$BinaryInput
	)

	process {
		if ($null -eq $SupportedAttributes) {
			$supportedAttributes = @()
		}
		[PSCustomObject][Ordered]@{
			BinaryInput         = $BinaryInput
			SupportedAttributes = $SupportedAttributes
			OnLoad              = $null
			OnSave              = $null
		}
	}
}
# Internal holder of registered transforms
Function Register-LdapAttributeTransform {
	<#
.SYNOPSIS
	Registers attribute transform logic

.DESCRIPTION
	Registered attribute transforms are used by various cmdlets to convert value to/from format used by LDAP server to/from more convenient format
	Sample transforms can be found in GitHub repository, including template for creation of new transforms

.OUTPUTS
	Nothing

.EXAMPLE
$Ldap = Get-LdapConnection -LdapServer "mydc.mydomain.com" -EncryptionType Kerberos
#get list of available transforms
Get-LdapAttributeTransform -ListAvailable

#register transform for specific attributes only
Register-LdapAttributeTransform -Name Guid -AttributeName objectGuid
Register-LdapAttributeTransform -Name SecurityDescriptor -AttributeName ntSecurityDescriptor

#register for all supported attributes
Register-LdapAttributeTransform -Name Certificate

#find objects, applying registered transforms as necessary
# Notice that for attributes processed by a transform, there is no need to specify them in -BinaryProps parameter: transform 'knows' if it's binary or not
Find-LdapObject -LdapConnection $Ldap -SearchBase "cn=User1,cn=Users,dc=mydomain,dc=com" -SearchScope Base -PropertiesToLoad 'cn','ntSecurityDescriptor','userCert,'userCertificate'

Description
----------
This example registers transform that converts raw byte array in ntSecurityDescriptor property into instance of System.DirectoryServices.ActiveDirectorySecurity
After command completes, returned object(s) will have instance of System.DirectoryServices.ActiveDirectorySecurity in ntSecurityDescriptor property

.EXAMPLE
$Ldap = Get-LdapConnection -LdapServer "mydc.mydomain.com" -EncryptionType Kerberos
#register all available transforms
Get-LdapAttributeTransform -ListAvailable | Register-LdapAttributeTransform
#find objects, applying registered transforms as necessary
# Notice that for attributes processed by a transform, there is no need to specify them in -BinaryProps parameter: transform 'knows' if it's binary or not
Find-LdapObject -LdapConnection $Ldap -SearchBase "cn=User1,cn=Users,dc=mydomain,dc=com" -SearchScope Base -PropertiesToLoad 'cn','ntSecurityDescriptor','userCert,'userCertificate'

.LINK
More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx
More about attribute transforms and how to create them: https://github.com/jformacek/S.DS.P/tree/master/Transforms
Template for creation of new transforms: https://github.com/jformacek/S.DS.P/blob/master/TransformTemplate/_Template.ps1
#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory, ParameterSetName = 'Name', Position = 0)]
		[string]
		#Name of the transform
		$Name,
		[Parameter()]
		[string]
		#Name of the attribute that will be processed by transform
		#If not specified, transform will be registered on all supported attributes
		$AttributeName,
		[Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'TransformObject', Position = 0)]
		[PSCustomObject]
		#Transform object produced by Get-LdapAttributeTransform
		$Transform,
		[Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'TransformFilePath', Position = 0)]
		[string]
		#Full path to transform file
		$TransformFile,
		[switch]
		#Force registration of transform, even if the attribute is not contained in the list of supported attributes
		$Force
	)

	Process {
		switch ($PSCmdlet.ParameterSetName) {
			'TransformObject' {
				$TransformFile = "$PSScriptRoot\Transforms\$($transform.TransformName).ps1"
				$Name = $transform.TransformName
				break;
			}
			'Name' {
				$TransformFile = "$PSScriptRoot\Transforms\$Name.ps1"
				break;
			}
			'TransformFile' {
				$Name = [System.IO.Path]::GetFileNameWithoutExtension($transformFile)
				break;
			}
		}

		if (-not (Test-Path -Path "$TransformFile") ) {
			throw new-object System.ArgumentException "Transform "$TransformFile" not found"
		}

		$SupportedAttributes = (& "$TransformFile").SupportedAttributes
		switch ($PSCmdlet.ParameterSetName) {
			'Name' {
				if ([string]::IsNullOrEmpty($AttributeName)) {
					$attribs = $SupportedAttributes
				} else {
					if (($supportedAttributes -contains $AttributeName) -or $Force) {
						$attribs = @($AttributeName)
					} else {
						throw new-object System.ArgumentException "Transform $Name does not support attribute $AttributeName"
					}
				}
				break;
			}
			default {
				$attribs = $SupportedAttributes
				break;
			}
		}
		foreach ($attr in $attribs) {
			$t = (. "$TransformFile" -FullLoad)
			$script:RegisteredTransforms[$attr] = $t | Add-Member -MemberType NoteProperty -Name 'Name' -Value $Name -PassThru
		}
	}
}
Function Remove-LdapObject {
	<#
.SYNOPSIS
	Removes existing object from LDAP server

.DESCRIPTION
	Removes an object from LDAP server.
	All properties of object are ignored and no transforms are performed; only distinguishedName property is used to locate the object.

.OUTPUTS
	Nothing

.EXAMPLE
$Ldap = Get-LdapConnection -LdapServer "mydc.mydomain.com" -EncryptionType Kerberos
Remove-LdapObject -LdapConnection $Ldap -Object "cn=User1,cn=Users,dc=mydomain,dc=com"

Description
-----------
Removes existing user account.

.EXAMPLE
$Ldap = Get-LdapConnection
Find-LdapObject -LdapConnection (Get-LdapConnection) -SearchFilter:"(&(objectClass=organizationalUnit)(adminDescription=ToDelete))" -SearchBase:"dc=myDomain,dc=com" | Remove-LdapObject -UseTreeDelete

Description
-----------
Removes existing subtree using TreeDeleteControl

.LINK
More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx

#>
	Param (
		[parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Object]
		#Either string containing distinguishedName or object with DistinguishedName property
		$Object,
		[parameter()]
		[System.DirectoryServices.Protocols.LdapConnection]
		#Existing LDAPConnection object.
		$LdapConnection = $script:LdapConnection,

		[parameter(Mandatory = $false)]
		[System.DirectoryServices.Protocols.DirectoryControl[]]
		#Additional controls that caller may need to add to request
		$AdditionalControls = @(),

		[parameter(Mandatory = $false)]
		[Switch]
		#Whether or not to use TreeDeleteControl.
		$UseTreeDelete
	)

	begin {
		EnsureLdapConnection -LdapConnection $LdapConnection
	}

	Process {
		[System.DirectoryServices.Protocols.DeleteRequest]$rqDel = new-object System.DirectoryServices.Protocols.DeleteRequest
		#add additional controls that caller may have passed
		foreach ($ctrl in $AdditionalControls) { $rqDel.Controls.Add($ctrl) > $null }

        $rqDel.DistinguishedName = $Object | GetDnFromInput

        if($UseTreeDelete) {
            $rqDel.Controls.Add((new-object System.DirectoryServices.Protocols.TreeDeleteControl)) > $null
        }
        $response = $LdapConnection.SendRequest($rqDel) -as [System.DirectoryServices.Protocols.DeleteResponse]
        #handle failed operation that does not throw itself
        if($null -ne $response -and $response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
            throw (new-object System.DirectoryServices.Protocols.LdapException(([int]$response.ResultCode), "$($rqDel.DistinguishedName)`: $($response.ResultCode)`: $($response.ErrorMessage)", $response.ErrorMessage))
        }
	}
}
Function Rename-LdapObject {
	<#
.SYNOPSIS
	Changes RDN of existing object or moves the object to a different subtree (or both at the same time)

.DESCRIPTION
	Performs only rename of object.
	All properties of object are ignored and no transforms are performed.
	Only distinguishedName property is used to locate the object.

.OUTPUTS
	Nothing

.EXAMPLE
$Ldap = Get-LdapConnection -LdapServer "mydc.mydomain.com" -EncryptionType Kerberos
Rename-LdapObject -LdapConnection $Ldap -Object "cn=User1,cn=Users,dc=mydomain,dc=com" -NewName 'cn=User2'

Description
----------
This command changes CN of User1 object to User2. Notice that 'cn=' is part of new name. This is required by protocol, when you do not provide it, you will receive NamingViolation error.

.EXAMPLE
$Ldap = Get-LdapConnection
Rename-LdapObject -LdapConnection $Ldap -Object "cn=User1,cn=Users,dc=mydomain,dc=com" -NewName "cn=User1" -NewParent "ou=CompanyUsers,dc=mydomain,dc=com"

Description
-----------
This command Moves the User1 object to different OU. Notice the newName parameter - it's the same as old name as we do not rename the object and new name is required parameter for protocol.

.LINK
More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx

#>

	Param (
		[parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Object]
		#Either string containing distinguishedName
		#Or object with DistinguishedName property
		$Object,

		[parameter()]
		[System.DirectoryServices.Protocols.LdapConnection]
		#Existing LDAPConnection object.
		$LdapConnection = $script:LdapConnection,

		[parameter(Mandatory = $true)]
		#New name of object
		[String]
		$NewName,

		[parameter(Mandatory = $false)]
		#DN of new parent
		[String]
		$NewParent,

		#whether to delete original RDN
		[Switch]
		$KeepOldRdn,

		[parameter(Mandatory = $false)]
		[System.DirectoryServices.Protocols.DirectoryControl[]]
		#Additional controls that caller may need to add to request
		$AdditionalControls = @()
	)

	begin {
		EnsureLdapConnection -LdapConnection $LdapConnection
	}
	Process {
		[System.DirectoryServices.Protocols.ModifyDNRequest]$rqModDN = new-object System.DirectoryServices.Protocols.ModifyDNRequest

        $rqModDn.DistinguishedName = $Object | GetDnFromInput

        foreach($ctrl in $AdditionalControls) { $rqModDN.Controls.Add($ctrl) > $null }

		$rqModDn.NewName = $NewName
		if (-not [string]::IsNullOrEmpty($NewParent)) { $rqModDN.NewParentDistinguishedName = $NewParent }
		$rqModDN.DeleteOldRdn = (-not $KeepOldRdn)
        $response = $LdapConnection.SendRequest($rqModDN) -as [System.DirectoryServices.Protocols.ModifyDNResponse]
        #handle failed operation that does not throw itself
        if($null -ne $response -and $response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
            throw (new-object System.DirectoryServices.Protocols.LdapException(([int]$response.ResultCode), "$($rqModDN.DistinguishedName)`: $($response.ResultCode)`: $($response.ErrorMessage)", $response.ErrorMessage))
        }
	}
}
Function Set-LdapDirSyncCookie {
	<#
.SYNOPSIS
	Returns DirSync cookie serialized as Base64 string.
	Caller is responsible to save and call Set-LdapDirSyncCookie when continuing data retrieval via directory synchronization

.OUTPUTS
	DirSync cookie as Base64 string

.EXAMPLE
Get-LdapConnection -LdapServer "mydc.mydomain.com"

$dse = Get-RootDse
$cookie = Get-Content .\storedCookieFromPreviousIteration.txt
$cookie | Set-LdapDirSyncCookie
$dirUpdates=Find-LdapObject -SearchBase $dse.defaultNamingContext -searchFilter '(objectClass=group)' -PropertiesToLoad 'member' -DirSync Standard
#process updates
foreach($record in $dirUpdates)
{
	#...
}

$cookie = Get-LdapDirSyncCookie
$cookie | Set-Content  .\storedCookieFromPreviousIteration.txt

Description
----------
This example loads dirsync cookie stored in file and performs dirsync search for updates that happened after cookie was generated
Then it stores updated cookie back to file for usage in next iteration

.LINK
More about DirSync: https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-ADTS/2213a7f2-0a36-483c-b2a4-8574d53aa1e3

#>
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory, ValueFromPipeline)]
		[string]$Cookie
	)

	process {
		[byte[]]$script:DirSyncCookie = [System.Convert]::FromBase64String($Cookie)
	}
}

Function Test-LdapObject {
<#
.SYNOPSIS
    Checks existence of LDAP object by distinguished name.

.DESCRIPTION
    This function checks if an LDAP object exists by its distinguished name.
    It can accept a string, DistinguishedName object, or an object with a distinguishedName property.
    If the object is found, it returns $true; otherwise, it returns $false.

.OUTPUTS
    True or False, depending on whether the LDAP object was found

.EXAMPLE

.LINK
More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx

#>
    Param (
        [parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [Object]
        #Object to test existence of
        $Object,

        [parameter()]
        [System.DirectoryServices.Protocols.LdapConnection]
        #Existing LDAPConnection object.
        $LdapConnection = $script:LdapConnection
    )

    begin {
        EnsureLdapConnection -LdapConnection $LdapConnection
    }

    Process {
        $dn = $object | GetDnFromInput

        try {
            $result = Find-LdapObject `
                -LdapConnection $LdapConnection `
                -SearchBase $dn `
                -searchFilter '(objectClass=*)' `
                -searchScope Base `
                -PropertiesToLoad '1.1' `
                -ErrorAction Stop

            #some LDAP servers return null if object is not found, others throw an exception
            return ($null -ne $result)
        }
        catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
            if($_.Exception.Response.ResultCode -eq  [System.DirectoryServices.Protocols.ResultCode]::NoSuchObject) {
                return $false
            } else {
                throw
            }
        }
    }
}

Function Unregister-LdapAttributeTransform {
	<#
.SYNOPSIS

	Unregister previously registered attribute transform logic

.DESCRIPTION

	Unregister attribute transform. Attribute transforms transform attributes from simple types provided by LDAP server to more complex types. Transforms work on attribute level and do not have access to values of other attributes.
	Transforms must be constructed using specific logic, see existing transforms and template on GitHub

.EXAMPLE

$Ldap = Get-LdapConnection -LdapServer "mydc.mydomain.com" -EncryptionType Kerberos
#get list of available transforms
Get-LdapAttributeTransform -ListAvailable
#register necessary transforms
Register-LdapAttributeTransform -Name Guid -AttributeName objectGuid
#Now objectGuid property on returned object is Guid rather than raw byte array
Find-LdapObject -LdapConnection $Ldap -SearchBase "cn=User1,cn=Users,dc=mydomain,dc=com" -SearchScope Base -PropertiesToLoad 'cn',objectGuid

#we no longer need the transform, let's unregister
Unregister-LdapAttributeTransform -AttributeName objectGuid
Find-LdapObject -LdapConnection $Ldap -SearchBase "cn=User1,cn=Users,dc=mydomain,dc=com" -SearchScope Base -PropertiesToLoad 'cn',objectGuid -BinaryProperties 'objectGuid'
#now objectGuid property of returned object contains raw byte array

Description
----------
This example registers transform that converts raw byte array in objectGuid property into instance of System.Guid
After command completes, returned object(s) will have instance of System.Guid in objectGuid property
Then the transform is unregistered, so subsequent calls do not use it

.LINK

More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx
More about attribute transforms and how to create them: https://github.com/jformacek/S.DS.P/tree/master/Module/Transforms

#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory, ValueFromPipelineByPropertyName, Position = 0)]
		[string]
		#Name of the attribute to unregister transform from
		$AttributeName
	)

	Process {
		if ($script:RegisteredTransforms.Keys -contains $AttributeName) {
			$script:RegisteredTransforms.Remove($AttributeName)
		}
	}
}
#endregion Public commands

#region Internal commands
<#
	Helper that makes sure that LdapConnection is initialized in commands that need it
#>
Function EnsureLdapConnection {
	param
	(
		[parameter()]
		[System.DirectoryServices.Protocols.LdapConnection]
		$LdapConnection
	)

	process {
		if ($null -eq $LdapConnection) {
			throw (new-object System.ArgumentException("LdapConnection parameter not provided and not found in session variable. Call Get-LdapConnection first"))
		}
	}
}

function GetDnFromInput {
    Param (
        [parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [Object]
        #DN string or object with distinguishedName property
        $Object
    )

    process {
        if($null -ne $Object) {
            #we support pipelining of strings or DistinguishedName types, or objects containing distinguishedName property - string or DistinguishedName
            switch($Object.GetType().Name) {
                "String" {
                    $dn = $Object
                    break;
                }
                'DistinguishedName' {
                    $dn=$Object.ToString()
                    break;
                }
                default {
                    if($null -ne $Object.distinguishedName) {
                        #covers both string and DistinguishedName types
                        $dn = $Object.distinguishedName.ToString()
                    }
                }
            }
        }
        if([string]::IsNullOrEmpty($dn)) {
            throw (new-object System.ArgumentException("Distinguished name not present on input object"))
        }
        #we return the DN as a string
        return $dn
    }
}
<#
	Retrieves search results as single search request
	Total # of search requests produced is 1
#>
function GetResultsDirectlyInternal {
    param (
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.SearchRequest]
        $rq,
        [parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection]
        $conn,
        [parameter()]
        [String[]]
        $PropertiesToLoad=@(),
        [parameter()]
        [String[]]
        $AdditionalProperties=@(),
        [parameter()]
        [String[]]
        $IgnoredProperties=@(),
        [parameter()]
        [String[]]
        $BinaryProperties=@(),
        [parameter()]
        [Timespan]
        $Timeout,
        [switch]$NoAttributes
    )

	begin {
		$template = InitializeItemTemplateInternal -props $PropertiesToLoad -additionalProps $AdditionalProperties
	}
	process {
		$pagedRqc = $rq.Controls | Where-Object { $_ -is [System.DirectoryServices.Protocols.PageResultRequestControl] }
		if ($NoAttributes) {
			$rq.Attributes.Add('1.1') > $null
		} else {
			$rq.Attributes.AddRange($propertiesToLoad) > $null
		}
		while ($true) {
			try {
				if ($Timeout -ne [timespan]::Zero) {
					$rsp = $conn.SendRequest($rq, $Timeout) -as [System.DirectoryServices.Protocols.SearchResponse]
				} else {
					$rsp = $conn.SendRequest($rq) -as [System.DirectoryServices.Protocols.SearchResponse]
				}
			} catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
				if ($null -ne $_.Exception.Response -and $_.Exception.Response.ResultCode -eq 'SizeLimitExceeded') {
					#size limit exceeded
					$rsp = $_.Exception.Response
				} else {
					throw $_.Exception
				}
			}

			foreach ($sr in $rsp.Entries) {
				$data = $template.Clone()

                foreach($attrName in $sr.Attributes.AttributeNames) {
                    $targetAttrName = GetTargetAttr -attr $attrName
                    if($targetAttrName -in $IgnoredProperties) {continue}
					if ($targetAttrName -ne $attrName) {
						Write-Warning "Value of attribute $targetAttrName not completely retrieved as it exceeds query policy. Use ranged retrieval. Range hint: $attrName"
					} else {
						if ($null -ne $data[$attrName]) {
							#we may have already loaded partial results from ranged hint
							continue
						}
					}

                    $transform = $script:RegisteredTransforms[$targetAttrName]
                    $BinaryInput = ($null -ne $transform -and $transform.BinaryInput -eq $true) -or ($targetAttrName -in $BinaryProperties)
                    try {
                        if($null -ne $transform -and $null -ne $transform.OnLoad) {
                            if($BinaryInput -eq $true) {
                                $data[$targetAttrName] = (& $transform.OnLoad -Values ($sr.Attributes[$attrName].GetValues([byte[]])))
                            } else {
                                $data[$targetAttrName] = (& $transform.OnLoad -Values ($sr.Attributes[$attrName].GetValues([string])))
                            }
                        } else {
                            if($BinaryInput -eq $true) {
                                $data[$targetAttrName] = $sr.Attributes[$attrName].GetValues([byte[]])
                            } else {
                                $data[$targetAttrName] = $sr.Attributes[$attrName].GetValues([string])
                            }
                        }
                    } catch {
                        Write-Error -ErrorRecord $_
                    }
                }

                if([string]::IsNullOrEmpty($data['distinguishedName'])) {
                    #dn has to be present on all objects
                    #having DN processed at the end gives chance to possible transforms on this attribute
                    $transform = $script:RegisteredTransforms['distinguishedName']
                    try {
                        if($null -ne $transform -and $null -ne $transform.OnLoad) {
                            $data['distinguishedName'] = & $transform.OnLoad -Values $sr.DistinguishedName
                        } else {
                            $data['distinguishedName']=$sr.DistinguishedName
                        }
                    } catch {
                        Write-Error -ErrorRecord $_
                    }
                }
                $data
			}
			#the response may contain paged search response. If so, we will need a cookie from it
			[System.DirectoryServices.Protocols.PageResultResponseControl] $prrc = $rsp.Controls | Where-Object { $_ -is [System.DirectoryServices.Protocols.PageResultResponseControl] }
			if ($null -ne $prrc -and $prrc.Cookie.Length -ne 0 -and $null -ne $pagedRqc) {
				#pass the search cookie back to server in next paged request
				$pagedRqc.Cookie = $prrc.Cookie;
			} else {
				#either non paged search or we've processed last page
				break;
			}
		}
	}
}
<#
	Retrieves search results as dirsync request
#>
function GetResultsDirSyncInternal {
	param
	(
		[Parameter(Mandatory)]
		[System.DirectoryServices.Protocols.SearchRequest]
		$rq,
		[parameter(Mandatory)]
		[System.DirectoryServices.Protocols.LdapConnection]
		$conn,
		[parameter()]
		[String[]]
		$PropertiesToLoad = @(),
		[parameter()]
		[String[]]
		$AdditionalProperties = @(),
		[parameter()]
		[String[]]
		$BinaryProperties = @(),
		[parameter()]
		[Timespan]
		$Timeout,
		[Switch]$ObjectSecurity,
		[switch]$Incremental
	)
	begin {
		$template = InitializeItemTemplateInternal -props $PropertiesToLoad -additionalProps $AdditionalProperties
	}
	process {
		$DirSyncRqc = new-object System.DirectoryServices.Protocols.DirSyncRequestControl(, $script:DirSyncCookie)
		$DirSyncRqc.Option = [System.DirectoryServices.Protocols.DirectorySynchronizationOptions]::ParentsFirst
		if ($ObjectSecurity) {
			$DirSyncRqc.Option = $DirSyncRqc.Option -bor [System.DirectoryServices.Protocols.DirectorySynchronizationOptions]::ObjectSecurity
		}
		if ($Incremental) {
			$DirSyncRqc.Option = $DirSyncRqc.Option -bor [System.DirectoryServices.Protocols.DirectorySynchronizationOptions]::IncrementalValues
		}
		$rq.Controls.Add($DirSyncRqc) > $null
		$rq.Attributes.AddRange($propertiesToLoad) > $null

		while ($true) {
			try {
				if ($Timeout -ne [timespan]::Zero) {
					$rsp = $conn.SendRequest($rq, $Timeout) -as [System.DirectoryServices.Protocols.SearchResponse]
				} else {
					$rsp = $conn.SendRequest($rq) -as [System.DirectoryServices.Protocols.SearchResponse]
				}
			} catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
				#just throw as we do not have need case for special handling now
				throw $_.Exception
			}

            foreach ($sr in $rsp.Entries) {
                $data=$template.Clone()

                foreach($attrName in $sr.Attributes.AttributeNames) {
                    $targetAttrName = GetTargetAttr -attr $attrName
                    if($IgnoredProperties -contains $targetAttrName) {continue}
                    if($attrName -ne $targetAttrName) {
                        if($null -eq $data[$targetAttrName]) {
                            $data[$targetAttrName] = [PSCustomObject]@{
                                Add=@()
                                Remove=@()
                            }
                        }
                        #we have multi-value prop change --> need special handling
                        #Windows AD/LDS server returns attribute name as '<attr>;range=1-1' for added values and '<attr>;range=0-0' for removed values on forward-linked attributes
                        if($attrName -like '*;range=1-1') {
                            $attributeContainer = {param($val) $data[$targetAttrName].Add=$val}
                        } else {
                            $attributeContainer = {param($val) $data[$targetAttrName].Remove=$val}
                        }
                    } else {
                        $attributeContainer = {param($val) $data[$targetAttrName]=$val}
                    }

                    $transform = $script:RegisteredTransforms[$targetAttrName]
                    $BinaryInput = ($null -ne $transform -and $transform.BinaryInput -eq $true) -or ($targetAttrName -in $BinaryProperties)
                    try {
                        if($null -ne $transform -and $null -ne $transform.OnLoad) {
                            if($BinaryInput -eq $true) {
                                &$attributeContainer (& $transform.OnLoad -Values ($sr.Attributes[$attrName].GetValues([byte[]])))
                            } else {
                                &$attributeContainer (& $transform.OnLoad -Values ($sr.Attributes[$attrName].GetValues([string])))
                            }
                        } else {
                            if($BinaryInput -eq $true) {
                                &$attributeContainer $sr.Attributes[$attrName].GetValues([byte[]])
                            } else {
                                &$attributeContainer $sr.Attributes[$attrName].GetValues([string])
                            }
                        }
                    } catch {
                        Write-Error -ErrorRecord $_
                    }
                }

                if([string]::IsNullOrEmpty($data['distinguishedName'])) {
                    #dn has to be present on all objects
                    #having DN processed at the end gives chance to possible transforms on this attribute
                    $transform = $script:RegisteredTransforms['distinguishedName']
                    try {
                        if($null -ne $transform -and $null -ne $transform.OnLoad) {
                            $data['distinguishedName'] = & $transform.OnLoad -Values $sr.DistinguishedName
                        } else {
                            $data['distinguishedName']=$sr.DistinguishedName
                        }
                    } catch {
                        Write-Error -ErrorRecord $_
                    }
                }
                $data
			}
			#the response may contain dirsync response. If so, we will need a cookie from it
			[System.DirectoryServices.Protocols.DirSyncResponseControl] $dsrc = $rsp.Controls | Where-Object { $_ -is [System.DirectoryServices.Protocols.DirSyncResponseControl] }
			if ($null -ne $dsrc -and $dsrc.Cookie.Length -ne 0 -and $null -ne $DirSyncRqc) {
				#pass the search cookie back to server in next paged request
				$DirSyncRqc.Cookie = $dsrc.Cookie;
				$script:DirSyncCookie = $dsrc.Cookie
				if (-not $dsrc.MoreData) {
					break;
				}
			} else {
				#either non paged search or we've processed last page
				break;
			}
		}
	}
}
<#
	Retrieves search results as series of requests: first request just returns list of returned objects, and then each object's props are loaded by separate request.
	Total # of search requests produced is N+1, where N is # of objects found
#>

function GetResultsIndirectlyInternal {
	param
	(
		[Parameter(Mandatory)]
		[System.DirectoryServices.Protocols.SearchRequest]
		$rq,

		[parameter(Mandatory)]
		[System.DirectoryServices.Protocols.LdapConnection]
		$conn,

        [parameter()]
        [String[]]
        $PropertiesToLoad=@(),

        [parameter()]
        [String[]]
        $AdditionalProperties=@(),

        [parameter()]
        [String[]]
        $IgnoredProperties=@(),


        [parameter(Mandatory = $false)]
        [System.DirectoryServices.Protocols.DirectoryControl[]]
        #additional controls that caller may need to add to request
        $AdditionalControls=@(),

        [parameter()]
        [String[]]
        $BinaryProperties=@(),
		[parameter()]
		[Timespan]
		$Timeout
	)
	begin {
		$template = InitializeItemTemplateInternal -props $PropertiesToLoad -additionalProps $AdditionalProperties
	}
	process {
		$pagedRqc = $rq.Controls | Where-Object { $_ -is [System.DirectoryServices.Protocols.PageResultRequestControl] }
		$rq.Attributes.AddRange($propertiesToLoad) > $null
		#load only attribute names now and attribute values later
		$rq.TypesOnly = $true
		while ($true) {
			try {
				if ($Timeout -ne [timespan]::Zero) {
					$rsp = $conn.SendRequest($rq, $Timeout) -as [System.DirectoryServices.Protocols.SearchResponse]
				} else {
					$rsp = $conn.SendRequest($rq) -as [System.DirectoryServices.Protocols.SearchResponse]
				}
			} catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
                if($null -ne $_.Exception.Response -and $_.Exception.Response.ResultCode -eq 'SizeLimitExceeded') {
                    #size limit exceeded
                    $rsp = $_.Exception.Response
                } else {
                    throw $_.Exception
                }
            }

            #now process the returned list of distinguishedNames and fetch required properties directly from returned objects
            foreach ($sr in $rsp.Entries) {
                $data=$template.Clone()

                $rqAttr = new-object System.DirectoryServices.Protocols.SearchRequest
                $rqAttr.DistinguishedName = $sr.DistinguishedName
                $rqAttr.Scope = "Base"
                $rqAttr.Controls.AddRange($AdditionalControls)

                #loading just attributes indicated as present in first search
                $rqAttr.Attributes.AddRange($sr.Attributes.AttributeNames) > $null
                $rspAttr = $LdapConnection.SendRequest($rqAttr)
                foreach ($srAttr in $rspAttr.Entries) {
                    foreach($attrName in $srAttr.Attributes.AttributeNames) {
                        $targetAttrName = GetTargetAttr -attr $attrName
                        if($IgnoredProperties -contains $targetAttrName) {continue}
                        if($targetAttrName -ne $attrName) {
                            Write-Warning "Value of attribute $targetAttrName not completely retrieved as it exceeds query policy. Use ranged retrieval. Range hint: $attrName"
                        } else {
                            if($null -ne $data[$attrName]) {
                                #we may have already loaded partial results from ranged hint
                                continue
                            }
                        }

                        $transform = $script:RegisteredTransforms[$targetAttrName]
                        $BinaryInput = ($null -ne $transform -and $transform.BinaryInput -eq $true) -or ($attrName -in $BinaryProperties)
                        #protecting against LDAP servers who don't understand '1.1' prop
                        try {
                            if($null -ne $transform -and $null -ne $transform.OnLoad) {
                                if($BinaryInput -eq $true) {
                                    $data[$targetAttrName] = (& $transform.OnLoad -Values ($srAttr.Attributes[$attrName].GetValues([byte[]])))
                                } else {
                                    $data[$targetAttrName] = (& $transform.OnLoad -Values ($srAttr.Attributes[$attrName].GetValues([string])))
                                }
                            } else {
                                if($BinaryInput -eq $true) {
                                    $data[$targetAttrName] = $srAttr.Attributes[$attrName].GetValues([byte[]])
                                } else {
                                    $data[$targetAttrName] = $srAttr.Attributes[$attrName].GetValues([string])

                                }
                            }
                        } catch {
                            Write-Error -ErrorRecord $_
                        }
                    }
                }
                if([string]::IsNullOrEmpty($data['distinguishedName'])) {
                    #dn has to be present on all objects
                    $transform = $script:RegisteredTransforms['distinguishedName']
                    try {
                        if($null -ne $transform -and $null -ne $transform.OnLoad) {
                            $data['distinguishedName'] = & $transform.OnLoad -Values $sr.DistinguishedName
                        } else {
                            $data['distinguishedName']=$sr.DistinguishedName
                        }
                    } catch {
                        Write-Error -ErrorRecord $_
                    }
                }
                $data
            }
            #the response may contain paged search response. If so, we will need a cookie from it
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$rsp.Controls | Where-Object{$_ -is [System.DirectoryServices.Protocols.PageResultResponseControl]}
            if($null -ne $prrc -and $prrc.Cookie.Length -ne 0 -and $null -ne $pagedRqc) {
                #pass the search cookie back to server in next paged request
                $pagedRqc.Cookie = $prrc.Cookie;
            } else {
                #either non paged search or we've processed last page
                break;
            }
        }
    }
}
<#
	Retrieves search results as series of requests: first request just returns list of returned objects, and then each property of each object is loaded by separate request.
	When there is a lot of values in multivalued property (such as 'member' attribute of group), property may be loaded by multiple requests
	Total # of search requests produced is at least (N x P) + 1, where N is # of objects found and P is # of properties loaded for each object
#>
function GetResultsIndirectlyRangedInternal {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.DirectoryServices.Protocols.SearchRequest]
        $rq,

        [parameter(Mandatory)]
        [System.DirectoryServices.Protocols.LdapConnection]
        $conn,

        [parameter()]
        [String[]]
        $PropertiesToLoad,

        [parameter()]
        [String[]]
        $AdditionalProperties=@(),

        [parameter()]
        [System.DirectoryServices.Protocols.DirectoryControl[]]
        #additional controls that caller may need to add to request
        $AdditionalControls=@(),

        [parameter()]
        [String[]]
        $IgnoredProperties=@(),

        [parameter()]
        [String[]]
        $BinaryProperties=@(),

        [parameter()]
        [Timespan]
        $Timeout,

        [parameter()]
        [Int32]
        $RangeSize
    )
    begin {
        $template=InitializeItemTemplateInternal -props $PropertiesToLoad -additionalProps $AdditionalProperties
    }
    process {
        $pagedRqc=$rq.Controls | Where-Object{$_ -is [System.DirectoryServices.Protocols.PageResultRequestControl]}
        $rq.Attributes.AddRange($PropertiesToLoad)
        #load only attribute names now and attribute values later
        $rq.TypesOnly=$true
        while ($true) {
            try {
                if($Timeout -ne [timespan]::Zero) {
                    $rsp = $conn.SendRequest($rq, $Timeout) -as [System.DirectoryServices.Protocols.SearchResponse]
                } else {
                    $rsp = $conn.SendRequest($rq) -as [System.DirectoryServices.Protocols.SearchResponse]
                }
            } catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
                if($null -ne $_.Exception.Response -and $_.Exception.Response.ResultCode -eq 'SizeLimitExceeded') {
                    #size limit exceeded
                    $rsp = $_.Exception.Response
                } else {
                    throw $_.Exception
                }
            }

            #now process the returned list of distinguishedNames and fetch required properties directly from returned objects
            foreach ($sr in $rsp.Entries) {
                $data=$template.Clone()
                $rqAttr=new-object System.DirectoryServices.Protocols.SearchRequest
                $rqAttr.DistinguishedName=$sr.DistinguishedName
                $rqAttr.Scope="Base"
                $rqAttr.Controls.AddRange($AdditionalControls)

                #loading just attributes indicated as present in first search
                foreach($attrName in $sr.Attributes.AttributeNames) {
                    $targetAttrName = GetTargetAttr -attr $attrName
                    if($IgnoredProperties -contains $targetAttrName) {continue}
                    if($targetAttrName -ne $attrName) {
                        #skip paging hint
                        Write-Verbose "Skipping paging hint: $attrName"
                        continue
                    }
                    $transform = $script:RegisteredTransforms[$attrName]
                    $BinaryInput = ($null -ne $transform -and $transform.BinaryInput -eq $true) -or ($attrName -in $BinaryProperties)
                    $start=-$rangeSize
                    $lastRange=$false
                    while ($lastRange -eq $false) {
                        $start += $rangeSize
                        $rng = "$($attrName.ToLower());range=$start`-$($start+$rangeSize-1)"
                        $rqAttr.Attributes.Clear() > $null
                        $rqAttr.Attributes.Add($rng) > $null
                        $rspAttr = $LdapConnection.SendRequest($rqAttr)
                        foreach ($srAttr in $rspAttr.Entries) {
                            #LDAP server changes upper bound to * on last chunk
                            $returnedAttrName=$($srAttr.Attributes.AttributeNames)
                            #load binary properties as byte stream, other properties as strings
                            try {
                                if($BinaryInput) {
                                    $data[$attrName]+=$srAttr.Attributes[$returnedAttrName].GetValues([byte[]])
                                } else {
                                    $data[$attrName] += $srAttr.Attributes[$returnedAttrName].GetValues([string])
                                }
                            } catch {
                                Write-Error -ErrorRecord $_
                            }
                            if($returnedAttrName.EndsWith("-*") -or $returnedAttrName -eq $attrName) {
                                #last chunk arrived
                                $lastRange = $true
                            }
                        }
                    }

                    #perform transform if registered
                    if($null -ne $transform -and $null -ne $transform.OnLoad) {
                        try {
                            $data[$attrName] = (& $transform.OnLoad -Values $data[$attrName])

                        } catch {
                            Write-Error -ErrorRecord $_
                        }
                    }
                }
                if ([string]::IsNullOrEmpty($data['distinguishedName'])) {
                    #dn has to be present on all objects
                    $transform = $script:RegisteredTransforms['distinguishedName']
                    try {
                        if ($null -ne $transform -and $null -ne $transform.OnLoad) {
                            $data['distinguishedName'] = & $transform.OnLoad -Values $sr.DistinguishedName
                        } else {
                            $data['distinguishedName'] = $sr.DistinguishedName
                        }
                    } catch {
                        Write-Error -ErrorRecord $_
                    }
                }
                $data
            }
            #the response may contain paged search response. If so, we will need a cookie from it
            [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$rsp.Controls | Where-Object{$_ -is [System.DirectoryServices.Protocols.PageResultResponseControl]}
            if($null -ne $prrc -and $prrc.Cookie.Length -ne 0 -and $null -ne $pagedRqc) {
                #pass the search cookie back to server in next paged request
                $pagedRqc.Cookie = $prrc.Cookie;
            } else {
                #either non paged search or we've processed last page
                break;
            }
        }
    }
}
<#
    Process ranged retrieval hints
#>
function GetTargetAttr {
    param (
        [Parameter(Mandatory)]
        [string]$attr
    )

    process {
        $targetAttr = $attr
        $m = [System.Text.RegularExpressions.Regex]::Match($attr,';range=.+');  #this is to skip range hints provided by DC
        if($m.Success) {
            $targetAttr = $($attr.Substring(0,$m.Index))
        }
        $targetAttr
    }
}
<#
    Helper that creates output object template used by Find-LdapObject command, based on required properties to be returned
#>
Function InitializeItemTemplateInternal {
    param (
        [string[]]$props,
        [string[]]$additionalProps
    )

    process {
        $template=@{}
        foreach($prop in $additionalProps) {$template[$prop]= $null}
        foreach($prop in $props) {$template[$prop]=$null}
        $template
    }
}
#endregion Internal commands

#region Module initialization
$script:RegisteredTransforms = @{}
$referencedAssemblies = @()
if ($PSVersionTable.PSEdition -eq 'Core') { $referencedAssemblies += 'System.Security.Principal.Windows' }

# Add compiled helpers. Load only if not loaded previously
$helpers = $sdspModuleHelpers | Get-Member | Where-Object {$_.MemberType -eq "NoteProperty"} | ForEach-Object {$_.Name}
foreach ($helper in $helpers) {
	if ($null -eq ($helper -as [type])) {
		#$definition = Get-Content "$PSScriptRoot\Helpers\$helper.cs" -Raw
		# $sdspModuleHelpers is defined above!
		$definition = $sdspModuleHelpers.$helper
		Add-Type -TypeDefinition $definition -ReferencedAssemblies $referencedAssemblies -WarningAction SilentlyContinue -IgnoreWarnings
	}
}
#endregion Module initialization
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
######################### S.DS.P PowerShell Module v2.3.0 (2025-08-05): https://github.com/jformacek/S.DS.P #########################

################### S.DS.P PowerShell Module TRANSFORMS v2.3.0 (2025-08-05): https://github.com/jformacek/S.DS.P ####################
$script:RegisteredTransforms = @{}
# vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# File In Repo: https://github.com/jformacek/S.DS.P/blob/master/Module/S.DS.P/Transforms/DistinguishedName.ps1 (https://github.com/jformacek/S.DS.P/tree/master/Module/S.DS.P/Transforms)
<#
$DistinguishedName_ps1_ScriptBlock = {
	param (
		[Parameter()]
		[Switch]
		$FullLoad
	)

	if ($FullLoad) {
		Add-Type @'
		using System;
		using System.Collections.Generic;
		using System.Linq;

		public class DistinguishedName
		{
			private readonly static char _delimiter = ',';
			private readonly static char _escape = '\\';
			private string _distinguishedName;

			public List<DistinguishedNameToken> Segments { get; set; }
			public override string ToString()
			{
				//performance optimization - return original string instead of parsed and reconstructed
				return _distinguishedName;
				//return string.Join(_delimiter.ToString(), Segments.Select(x => x.ToString()));
			}
			public DistinguishedName(string distinguishedName)
			{
				_distinguishedName = distinguishedName;
				Segments = new List<DistinguishedNameToken>();
				int start = 0;
				for (int i = 0; i < distinguishedName.Length; i++)
				{
					if (distinguishedName[i] == _delimiter && distinguishedName[i - 1] != _escape)
					{
						Segments.Add(new DistinguishedNameToken(distinguishedName.Substring(start, i - start)));
						start = i + 1;
					}
				}
				Segments.Add(new DistinguishedNameToken(distinguishedName.Substring(start)));
			}
		}

		public class DistinguishedNameToken
		{
			private readonly static char[] _escapedChars = new char[] { ',', '\\', '#', '+', '<', '>', ';', '"', '=', '/' };
			private readonly static char _delimiter = '=';
			private readonly static char _escape = '\\';

			protected string Unescape(string value)
			{
				var result = new List<char>();
				for (int i = 0; i < value.Length; i++)
				{
					if (value[i] == _escape && value[i + 1] == '0')
					{
						if (value[i + 2] == 'D')
						{
							result.Add('\r');
							i += 2;
							continue;
						}
						if (value[i + 2] == 'A')
						{
							result.Add('\n');
							i += 2;
							continue;
						}
					}
					//first space is escaped
					if (i == 0 && value[i] == _escape)
					{
						continue;
					}
					//last space is escaped
					if (i == value.Length-2 && value[i] == _escape)
					{
						continue;
					}
					if (value[i] == _escape)
					{
						if (i + 1 < value.Length && _escapedChars.Contains(value[i + 1]))
						{
							result.Add(value[i + 1]);
							i++;
						}
						else
						{
							result.Add(value[i]);
						}
					}
					else
					{
						result.Add(value[i]);
					}
				}
				return new string(result.ToArray());
			}

			protected string Escape(string value)
			{
				var result = new List<char>();
				for (int i = 0; i < value.Length; i++)
				{
					//escaping only first and last space
					if (value[i] == ' ' && (i == 0 || i == value.Length - 1))
					{
						result.Add(_escape);
					}
					if (value[i] == '\r')
					{
						result.Add(_escape);
						result.Add('0');
						result.Add('D');
						continue;
					}
					if (value[i] == '\n')
					{
						result.Add(_escape);
						result.Add('0');
						result.Add('A');
						continue;
					}
					if (_escapedChars.Contains(value[i]))
					{
						result.Add(_escape);
					}
					result.Add(value[i]);
				}
				return new string(result.ToArray());
			}

			public string Qualifier { get; set; }
			public string Value { get; set; }

			public DistinguishedNameToken(string token)
			{
				var start = token.IndexOf(_delimiter);
				Qualifier = token.Substring(0, start).Trim();
				Value = Unescape(token.Substring(start + 1));
			}
			public override string ToString()
			{
				return string.Format("{0}{1}{2}", Qualifier, _delimiter, Escape(Value));
			}
		}
'@
	}
	$codeBlock_DistinguishedName_ps1 = New-LdapAttributeTransformDefinition -SupportedAttributes @('distinguishedName', 'member', 'memberOf', 'homeMdb')
	$codeBlock_DistinguishedName_ps1.OnLoad = {
		param(
			[string[]]$Values
		)
		Process {
			foreach ($Value in $Values) {
				new-object DistinguishedName($Value)
			}
		}
	}
	$codeBlock_DistinguishedName_ps1.OnSave = {
		param(
			[DistinguishedName[]]$Values
		)

		Process {
			foreach ($Value in $Values) {
				$Value.ToString()
			}
		}
	}
	$codeBlock_DistinguishedName_ps1
}
$DistinguishedName_ps1_attributes = $(Invoke-Command -ArgumentList $false -ScriptBlock $DistinguishedName_ps1_ScriptBlock).SupportedAttributes
$DistinguishedName_ps1_attributes | ForEach-Object {
	$attributeToProcess = $_
	$DistinguishedName_ps1_transform = Invoke-Command -ArgumentList $true -ScriptBlock $DistinguishedName_ps1_ScriptBlock
	$script:RegisteredTransforms[$attributeToProcess] = $DistinguishedName_ps1_transform | Add-Member -MemberType NoteProperty -Name "Name" -Value $attributeToProcess -PassThru
}
#>
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

# vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# File In Repo: https://github.com/jformacek/S.DS.P/blob/master/Module/S.DS.P/Transforms/fileTime.ps1 (https://github.com/jformacek/S.DS.P/tree/master/Module/S.DS.P/Transforms)
<#
$fileTime_ps1_ScriptBlock = {
	$codeBlock_fileTime_ps1 = New-LdapAttributeTransformDefinition -SupportedAttributes @('accountExpires', 'badPasswordTime', 'lastLogon', 'lastLogonTimestamp', 'ms-Mcs-AdmPwdExpirationTime', 'msDS-UserPasswordExpiryTimeComputed', 'pwdLastSet')
	$codeBlock_fileTime_ps1.OnLoad = {
		param(
			[string[]]$Values
		)
		Process {
			foreach ($Value in $Values) {
				try {
					[DateTime]::FromFileTimeUtc([long]$Value)
				} catch {
					#value outside of range for filetime
					#such as in https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f9e9b7e2-c7ac-4db6-ba38-71d9696981e9
					$Value
				}
			}
		}
	}
	$codeBlock_fileTime_ps1.OnSave = {
		param(
			[Object[]]$Values
		)

		Process {
			foreach ($Value in $Values) {
				#standard expiration
				if ($value -is [datetime]) {
					$Value.ToFileTimeUtc()
				} else {
					#values that did not transform to DateTime in OnLoad -> return as-is as string
					"$value"
				}
			}
		}
	}
	$codeBlock_fileTime_ps1
}
$fileTime_ps1_attributes = $(Invoke-Command -ScriptBlock $fileTime_ps1_ScriptBlock).SupportedAttributes
$fileTime_ps1_attributes | ForEach-Object {
	$attributeToProcess = $_
	$fileTime_ps1_transform = Invoke-Command -ScriptBlock $fileTime_ps1_ScriptBlock
	$script:RegisteredTransforms[$attributeToProcess] = $fileTime_ps1_transform | Add-Member -MemberType NoteProperty -Name "Name" -Value $attributeToProcess -PassThru
}
#>
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

# vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# File In Repo: https://github.com/jformacek/S.DS.P/blob/master/Module/S.DS.P/Transforms/guid.ps1 (https://github.com/jformacek/S.DS.P/tree/master/Module/S.DS.P/Transforms)
#helper to convert Guid to ldap searchable string
<#
$guid_ps1_ScriptBlock = {
	param (
		[Parameter()]
		[Switch]
		$FullLoad
	)

	if ($FullLoad) {
		#helper to convert Guid to ldap searchable string
		add-type -TypeDefinition @'
		using System;
		using System.Text;

		public static class GuidExtensions
		{
			public static string ToLdapSearchableString(this Guid guid)
			{
				StringBuilder sb = new StringBuilder();
				foreach(var v in guid.ToByteArray())
				{
					sb.Append("\\");
					sb.Append(v.ToString("X2"));
				}
				return sb.ToString();
			}
		}
'@
	}
	$codeBlock_guid_ps1 = New-LdapAttributeTransformDefinition -SupportedAttributes @('appliesTo','attributeSecurityGUID','objectGuid','mS-DS-ConsistencyGuid','msExchMailboxGuid','schemaIDGUID','msExchArchiveGUID') -BinaryInput
	$codeBlock_guid_ps1.OnLoad = {
		param(
		[byte[][]]$Values
		)
		Process
		{
			foreach($Value in $Values)
			{
				New-Object System.Guid(,$Value)
			}
		}
	}
	$codeBlock_guid_ps1.OnSave = {
		param(
		[Guid[]]$Values
		)

		Process
		{
			foreach($value in $values)
			{
				,($value.ToByteArray())
			}
		}
	}
	$codeBlock_guid_ps1
}
$guid_ps1_attributes = $(Invoke-Command -ArgumentList $false -ScriptBlock $guid_ps1_ScriptBlock).SupportedAttributes
$guid_ps1_attributes | ForEach-Object {
	$attributeToProcess = $_
	$guid_ps1_transform = Invoke-Command -ArgumentList $true -ScriptBlock $guid_ps1_ScriptBlock
	$script:RegisteredTransforms[$attributeToProcess] = $guid_ps1_transform | Add-Member -MemberType NoteProperty -Name "Name" -Value $attributeToProcess -PassThru
}
#>
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

# vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# File In Repo: https://github.com/jformacek/S.DS.P/blob/master/Module/S.DS.P/Transforms/unicodePwd.ps1 (https://github.com/jformacek/S.DS.P/tree/master/Module/S.DS.P/Transforms)
$unicodePwd_ps1_ScriptBlock = {
	$codeBlock_unicodePwd_ps1 = New-LdapAttributeTransformDefinition -SupportedAttributes @('unicodePwd') -BinaryInput
	$codeBlock_unicodePwd_ps1.OnSave = {
		param(
			[string[]]$Values
		)

		Process {
			foreach ($Value in $Values) {
				, ([System.Text.Encoding]::Unicode.GetBytes("`"$Value`"") -as [byte[]])
			}
		}
	}
	$codeBlock_unicodePwd_ps1
}
$unicodePwd_ps1_attributes = $(Invoke-Command -ScriptBlock $unicodePwd_ps1_ScriptBlock).SupportedAttributes
$unicodePwd_ps1_attributes | ForEach-Object {
	$attributeToProcess = $_
	$unicodePwd_ps1_transform = Invoke-Command -ScriptBlock $unicodePwd_ps1_ScriptBlock
	$script:RegisteredTransforms[$attributeToProcess] = $unicodePwd_ps1_transform | Add-Member -MemberType NoteProperty -Name "Name" -Value $attributeToProcess -PassThru
}
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

################# S.DS.P PowerShell Module TRANSFORMS v2.3.0 (2025-08-05): https://github.com/jformacek/S.DS.P ###################

###
# Functions Used In Script
###

### FUNCTION: Logging Data To The Log File
Function writeLog {
	Param(
		[string]$dataToLog,
		[string]$lineType,
		[bool]$logFileOnly,
		[bool]$noDateTimeInLogLine,
		[bool]$ignoreRemote
	)

	$dateTime = Get-Date
	$datetimeLocal = $(Get-Date $dateTime -format "yyyy-MM-dd HH:mm:ss")							# Local Time
	$datetimeUniversal = $(Get-Date $dateTime.ToUniversalTime() -format "yyyy-MM-dd HH:mm:ss")		# Universal Time
	$datetimeLogLine = "[UT:" + $datetimeUniversal + " | LT:" + $datetimeLocal + "] : "
	If ($ignoreRemote -ne $true) {
		If ($noDateTimeInLogLine -eq $true) {
			Out-File -filepath "$logFilePath" -append -inputObject "$dataToLog"
		}
		If ($noDateTimeInLogLine -eq $false) {
			Out-File -filepath "$logFilePath" -append -inputObject "$datetimeLogLine$dataToLog"
		}
	}
	If ($logFileOnly -eq $false) {
		If ($([string]::IsNullOrEmpty($lineType))) {
			Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Yellow
		}
		If ($lineType -eq "SUCCESS") {
			Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Green
		}
		If ($lineType -eq "ERROR") {
			Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Red
		}
		If ($lineType -eq "WARNING") {
			Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Red
		}
		If ($lineType -eq "MAINHEADER") {
			Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Magenta
		}
		If ($lineType -eq "HEADER") {
			Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor DarkCyan
		}
		If ($lineType -eq "REMARK") {
			Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Cyan
		}
		If ($lineType -eq "REMARK-NO-NEW-LINE") {
			Write-Host "`r$datetimeLogLine$dataToLog" -NoNewline -ForeGroundColor Cyan
		}
		If ($lineType -eq "DEFAULT") {
			Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Yellow
		}
		If ($lineType -eq "REMARK-IMPORTANT") {
			Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Green
		}
		If ($lineType -eq "REMARK-MORE-IMPORTANT") {
			Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Yellow
		}
		If ($lineType -eq "REMARK-MOST-IMPORTANT") {
			Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Red
		}
		If ($lineType -eq "ACTION") {
			Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor White
		}
		If ($lineType -eq "ACTION-NO-NEW-LINE") {
			Write-Host "$datetimeLogLine$dataToLog" -NoNewline -ForeGroundColor White
		}
	}
}
$loggingDef = "function Logging{${function:Logging}}"

### FUNCTION: Logging Data To The Log File
Function cleanUpOldLogs {
	Param(
		[string]$folder,
		[string]$filterName,
		[int]$numDaysToKeep,
		[string]$fileType
	)

	$filesToDelete = Get-ChildItem -Path $folder -Filter $filterName | Where-Object { $_.CreationTime -lt ([DateTime]::Now).AddDays(-$numDaysToKeep) }

	If (($filesToDelete | Measure-Object).Count -gt 0) {
		$filesToDelete | ForEach-Object {
			Try {
				Remove-Item -Path $($_.FullName) -Force -ErrorAction STOP
				writeLog -dataToLog "$fileType File Deleted......................: '$($_.FullName)'"
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Failed To Delete The $fileType File '$($_.FullName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
	} Else {
		writeLog -dataToLog "NO $fileType Files To Deleted..."
	}
}

### FUNCTION: Test Resolving The Server Name And Connectivity Over The Specified TCP Port
Function portConnectionCheck {
	<#
		.SYNOPSIS
			This Code Checks If A Specific TCP Port Is Open/Reachable For The Defined Server

		.DESCRIPTION
			This Code Checks If A Specific TCP Port Is Open/Reachable For The Defined Server

		.PARAMETER serverIPOrFQDN
			The IP Address Or FQDN Of The Server To Check Against.

		.PARAMETER port
			The Numeric Value For A Specific Port That Needs To Be Checked

		.PARAMETER timeOut
			The Number Of Milliseconds For The Time Out
	#>

	[cmdletbinding()]
	Param(
		[Parameter(Mandatory = $TRUE)]
		[string]$serverIPOrFQDN,

		[Parameter(Mandatory = $TRUE)]
		[int]$port,

		[Parameter(Mandatory = $FALSE)]
		[int]$timeOut
	)

	Begin {
		If ([int]$timeOut -eq 0) {
			[int]$timeOut = 1000
		}
	}

	Process {
		# Validate If An IP Address Has Been Provided, And If NOT Try To Resolve The FQDN
		$regexIPv4 = "^(?:(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)\.){3}(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)$"
		If ($serverIPOrFQDN -notmatch $regexIPv4) {
			# Test To See If The HostName Is Resolvable At All
			Try {
				[System.Net.Dns]::GetHostEntry($serverIPOrFQDN) > $null
			} Catch {
				Return "ERROR"
			}
		}

		# Test If The Server Is Reachable Over The Specified TCP Port
		$tcpPortSocket = $null
		$tcpPortSocket = New-Object System.Net.Sockets.TcpClient

		$portConnect = $null
		$portConnect = $tcpPortSocket.BeginConnect($serverIPOrFQDN, $port, $null, $null)

		$tcpPortWait = $null
		$tcpPortWait = $portConnect.AsyncWaitHandle.WaitOne($timeOut, $false)

		If (!$tcpPortWait) {
			$tcpPortSocket.Close()

			Return "ERROR"
		} Else {
			$ErrorActionPreference = "SilentlyContinue"

			$tcpPortSocket.EndConnect($portConnect) > $null
			If (!$?) {
				Return "ERROR"
			} Else {
				Return "SUCCESS"
			}

			$tcpPortSocket.Close()

			$ErrorActionPreference = "Continue"
		}
	}
}

### FUNCTION: Load Required PowerShell Modules
Function loadPoSHModules {
	Param (
		[string]$poshModule,
		[bool]$ignoreRemote
	)
	$retValue = $null
	If ($(@(Get-Module | Where-Object { $_.Name -eq $poshModule }) | Measure-Object).Count -eq 0) {
		If ($(@(Get-Module -ListAvailable -All | Where-Object { $_.Name -eq $poshModule }) | Measure-Object).Count -ne 0) {
			If ($script:poshVersion -ge [version]"7.0") {
				Import-Module -Name $poshModule -SkipEditionCheck
			} Else {
				Import-Module -Name $poshModule
			}
			writeLog -dataToLog "PoSH Module '$poshModule' Has Been Loaded..." -lineType "SUCCESS" -logFileOnly $false -ignoreRemote $ignoreRemote
			$retValue = "HasBeenLoaded"
		} Else {
			writeLog -dataToLog "PoSH Module '$poshModule' Is Not Available To Load..." -lineType "ERROR" -logFileOnly $false -ignoreRemote $ignoreRemote
			writeLog -dataToLog "The PoSH Module '$poshModule' Is Required For This Script To Work..." -lineType "REMARK" -logFileOnly $false -ignoreRemote $ignoreRemote
			$confirmInstallPoshModuleYESNO = $null
			$confirmInstallPoshModuleYESNO = Read-Host "Would You Like To Install The PoSH Module '$poshModule' NOW? [Yes|No]"
			If ($confirmInstallPoshModuleYESNO.ToUpper() -eq "YES" -Or $confirmInstallPoshModuleYESNO.ToUpper() -eq "Y") {
				If ($poshModule -eq "GroupPolicy") {
					writeLog -dataToLog "Installing The Windows Feature 'GPMC' For The PoSH Module '$poshModule'..." -lineType "REMARK" -logFileOnly $false -ignoreRemote $ignoreRemote
					Add-WindowsFeature -Name "GPMC" -IncludeAllSubFeature > $null
				}
				If ($(@(Get-Module -ListAvailable | Where-Object { $_.Name -eq $poshModule }) | Measure-Object).Count -ne 0) {
					Import-Module $poshModule
					writeLog -dataToLog "PoSH Module '$poshModule' Has Been Loaded..." -lineType "SUCCESS" -logFileOnly $false -ignoreRemote $ignoreRemote
					$retValue = "HasBeenLoaded"
				} Else {
					writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -ignoreRemote $ignoreRemote
					$retValue = "NotAvailable"
				}
			} Else {
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -ignoreRemote $ignoreRemote
				$retValue = "NotAvailable"
			}
		}
	} Else {
		writeLog -dataToLog "PoSH Module '$poshModule' Already Loaded..." -lineType "SUCCESS" -logFileOnly $false -ignoreRemote $ignoreRemote
		$retValue = "AlreadyLoaded"
	}
	Return $retValue
}
$loadPoSHModulesDef = "function loadPoSHModules{${function:loadPoSHModules}}"

### FUNCTION: Check To See If The Script Is Executed Through An Elevated PowerShell Command Prompt Or Not
Function checkLocalElevationStatus {
	# Determine Current User
	$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()

	# Check The Process Owner SID And The User SID And Compare
	$processOwnerSid = $currentUser.Owner.Value
	$processUserSid = $currentUser.User.Value

	# When Equal, Not Elevated. When Different Elevated
	If ($processOwnerSid -eq $processUserSid) {
		Return "NOT-ELEVATED"
	} Else {
		Return "ELEVATED"
	}
}

### FUNCTION: Set Window Position And Size.
# Source: https://github.com/proxb/PowerShell_Scripts/blob/master/Set-Window.ps1
Function Set-Window {
	<#
		.SYNOPSIS
			Sets the window size (height,width) and coordinates (x,y) of a process window.

		.DESCRIPTION
			Sets the window size (height,width) and coordinates (x,y) of a process window.

		.PARAMETER ProcessName
			Name of the process to determine the window characteristics

		.PARAMETER X
			Set the position of the window in pixels from the top.

		.PARAMETER Y
			Set the position of the window in pixels from the left.

		.PARAMETER Width
			Set the width of the window.

		.PARAMETER Height
			Set the height of the window.

		.PARAMETER Passthru
			Display the output object of the window.

		.NOTES
			Name: Set-Window
			Author: Boe Prox
			Version History
				1.0//Boe Prox - 11/24/2015
					- Initial build

		.OUTPUT
			System.Automation.WindowInfo

		.EXAMPLE
			Get-Process powershell | Set-Window -X 2040 -Y 142 -Passthru

			ProcessName Size	 TopLeft  BottomRight
			----------- ----	 -------  -----------
			powershell  1262,642 2040,142 3302,784

			Description
			-----------
			Set the coordinates on the window for the process PowerShell.exe

	#>
	[OutputType('System.Automation.WindowInfo')]
	[cmdletbinding()]
	Param (
		[parameter(ValueFromPipelineByPropertyName = $True)]
		$ProcessName,
		[int]$X,
		[int]$Y,
		[int]$Width,
		[int]$Height,
		[switch]$Passthru
	)
	Begin {
		Try {
			[void][Window]
		} Catch {
			Add-Type @"
			using System;
			using System.Runtime.InteropServices;
			public class Window {
				[DllImport("user32.dll")]
				[return: MarshalAs(UnmanagedType.Bool)]
				public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

				[DllImport("User32.dll")]
				public extern static bool MoveWindow(IntPtr handle, int x, int y, int width, int height, bool redraw);
			}
			public struct RECT
			{
				public int Left;	// x position of upper-left corner
				public int Top;		// y position of upper-left corner
				public int Right;	// x position of lower-right corner
				public int Bottom;	// y position of lower-right corner
			}
"@
		}
	}
	Process {
		$Rectangle = New-Object RECT
		$Handle = (Get-Process -Name $ProcessName).MainWindowHandle
		$Return = [Window]::GetWindowRect($Handle, [ref]$Rectangle)
		If (-NOT $PSBoundParameters.ContainsKey('Width')) {
			$Width = $Rectangle.Right - $Rectangle.Left
		}
		If (-NOT $PSBoundParameters.ContainsKey('Height')) {
			$Height = $Rectangle.Bottom - $Rectangle.Top
		}
		If ($Return) {
			$Return = [Window]::MoveWindow($Handle, $x, $y, $Width, $Height, $True)
		}
		If ($PSBoundParameters.ContainsKey('Passthru')) {
			$Rectangle = New-Object RECT
			$Return = [Window]::GetWindowRect($Handle, [ref]$Rectangle)
			If ($Return) {
				$Height = $Rectangle.Bottom - $Rectangle.Top
				$Width = $Rectangle.Right - $Rectangle.Left
				$Size = New-Object System.Management.Automation.Host.Size -ArgumentList $Width, $Height
				$TopLeft = New-Object System.Management.Automation.Host.Coordinates -ArgumentList $Rectangle.Left, $Rectangle.Top
				$BottomRight = New-Object System.Management.Automation.Host.Coordinates -ArgumentList $Rectangle.Right, $Rectangle.Bottom
				If ($Rectangle.Top -lt 0 -AND $Rectangle.LEft -lt 0) {
					Write-Warning "Window is minimized! Coordinates will not be accurate."
				}
				$Object = [pscustomobject]@{
					ProcessName = $ProcessName
					Size        = $Size
					TopLeft     = $TopLeft
					BottomRight = $BottomRight
				}
				$Object.PSTypeNames.insert(0, 'System.Automation.WindowInfo')
				$Object
			}
		}
	}
}

### FUNCTION: Test Account Is "NT AUTHORITY\SYSTEM" (SID: S-1-5-18)
Function testAccountIsSystemOnRWDC {
	# Determine Current User
	$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()

	# Check The Current User Is "NT AUTHORITY\SYSTEM"
	If ($currentUser.User.Value -eq "S-1-5-18") {
		$isNTAuthSystem = $true
	} Else {
		$isNTAuthSystem = $false
	}

	# Determine Current domainRole And DC Type
	$domainRole = Get-CimInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty DomainRole
	If (($domainRole -eq 4 -Or $domainRole -eq 5) -And $isNTAuthSystem -eq $true) {
		$dcType = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "DsaOptions").DsaOptions
		If ($dcType -eq 1) { # 1 = RWDC
			$isRWDC = $true
		} Else { # 5 = RODC
			$isRWDC = $false
		}
	} Else {
		$isRWDC = $false
	}

	Return $isRWDC, $isNTAuthSystem, $($currentUser.Name)
}

### FUNCTION: Test Credentials For Specific Admin Role
Function testAdminRole {
	Param (
		[string]$adminRole
	)

	# Determine Current User
	$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()

	# Check The Current User Is In The Specified Admin Role
	Return (New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole($adminRole)
}

### FUNCTION: Request For Admin Credentials
Function requestForAdminCreds {
	# Ask For The Remote Credentials
	$adminUserAccount = $null
	Do {
		writeLog -dataToLog "Please provide an account (<DOMAIN FQDN>\<ACCOUNT>) that is a member of the 'Administrators' group in every AD domain of the specified AD forest: " -lineType "ACTION-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false
		$adminUserAccount = Read-Host
	} Until (-not [string]::IsNullOrEmpty($adminUserAccount) -And $adminUserAccount -match "^[a-zA-Z0-9_.-]*\\[a-zA-Z0-9_.-]*$")

	# Ask For The Corresponding Password
	$adminUserPasswordString = $null
	Do {
		writeLog -dataToLog "Please provide the corresponding password of that admin account: " -lineType "ACTION-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false
		[System.Security.SecureString]$adminUserPasswordSecureString = Read-Host -AsSecureString -ErrorAction SilentlyContinue
	} Until ($adminUserPasswordSecureString.Length -gt 0)
	[string]$adminUserPasswordString = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminUserPasswordSecureString))
	$secureAdminUserPassword = ConvertTo-SecureString $adminUserPasswordString -AsPlainText -Force
	$adminCrds = $null
	$adminCrds = New-Object System.Management.Automation.PSCredential $adminUserAccount, $secureAdminUserPassword

	Return $adminCrds
}

### FUNCTION: Create Temporary Canary Object
Function createTempCanaryObject {
	Param (
		[string]$targetedADdomainRWDCFQDN,
		[string]$krbTgtSamAccountName,
		[string]$execDateTimeCustom1,
		[bool]$localADforest,
		[PSCredential]$adminCrds
	)
	# Determine The DN Of The Users Container Of The Targeted Domain
	$containerForTempCanaryObject = $null
	$containerForTempCanaryObject = "CN=Users," + $($script:targetedADdomainDefaultNCDN)

	# Generate The Name Of The Temporary Canary Object
	$targetObjectToCheckName = $null
	$targetObjectToCheckName = "_adReplTempObject_" + $krbTgtSamAccountName + "_" + $execDateTimeCustom1

	# Specify The Description Of The Temporary Canary Object
	$targetObjectToCheckDescription = "...!!!.TEMP OBJECT TO CHECK AD REPLICATION IMPACT.!!!..."

	# Generate The DN Of The Temporary Canary Object
	$targetObjectToCheckDN = $null
	$targetObjectToCheckDN = "CN=" + $targetObjectToCheckName + "," + $containerForTempCanaryObject
	writeLog -dataToLog "  --> RWDC To Create Object On..............: '$targetedADdomainRWDCFQDN'"
	writeLog -dataToLog "  --> Full Name Temp Canary Object..........: '$targetObjectToCheckName'"
	writeLog -dataToLog "  --> Description...........................: '$targetObjectToCheckDescription'"
	writeLog -dataToLog "  --> Container For Temp Canary Object......: '$containerForTempCanaryObject'"
	writeLog -dataToLog ""

	# Try To Create The Canary Object In The AD Domain And If Not Successful Throw Error
	Try {
		$contactObject = [PSCustomObject]@{distinguishedName = $null; objectClass = $null; displayName = $null; description = $null }
		$contactObject.DistinguishedName = "CN=$targetObjectToCheckName,$containerForTempCanaryObject"
		$contactObject.objectClass = "contact"
		$contactObject.displayName = $targetObjectToCheckName
		$contactObject.description = $targetObjectToCheckDescription
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
			Add-LdapObject -LdapConnection $ldapConnection -Object $contactObject
			$ldapConnection.Dispose()
		}
		If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
			Add-LdapObject -LdapConnection $ldapConnection -Object $contactObject
			$ldapConnection.Dispose()
		}
	} Catch {
		writeLog -dataToLog "  --> Temp Canary Object [$targetObjectToCheckDN] FAILED TO BE CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	}

	# Check The Temporary Canary Object Exists And Was created In AD
	$targetObjectToCheck = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
			$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectClass=contact)(name=$targetObjectToCheckName))"
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Contact Object With 'name=$targetObjectToCheckName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
			$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectClass=contact)(name=$targetObjectToCheckName))"
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Contact Object With 'name=$targetObjectToCheckName' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ($(-not [string]::IsNullOrEmpty($targetObjectToCheck))) {
		$targetObjectToCheckDN = $null
		$targetObjectToCheckDN = $targetObjectToCheck.DistinguishedName
		writeLog -dataToLog "  --> Temp Canary Object [$targetObjectToCheckDN] CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	}

	Return $targetObjectToCheckDN
}

### FUNCTION: Confirm Generated Password Meets Complexity Requirements
# Source: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements
Function confirmPasswordIsComplex {
	Param (
		[string]$passwd
	)

	Process {
		$criteriaMet = 0

		# Upper Case Characters (A through Z, with diacritic marks, Greek and Cyrillic characters)
		If ($passwd -cmatch '[A-Z]') { $criteriaMet++ }

		# Lower Case Characters (a through z, sharp-s, with diacritic marks, Greek and Cyrillic characters)
		If ($passwd -cmatch '[a-z]') { $criteriaMet++ }

		# Numeric Characters (0 through 9)
		If ($passwd -match '\d') { $criteriaMet++ }

		# Special Characters (Non-alphanumeric characters, currency symbols such as the Euro or British Pound are not counted as special characters for this policy setting)
		If ($passwd -match '[\^~!@#$%^&*_+=`|\\(){}\[\]:;"''<>,.?/]') { $criteriaMet++ }

		# Check If It Matches Default Windows Complexity Requirements
		If ($criteriaMet -lt 3) {
			Return $false
		} ElseIf ($passwd.Length -lt 8) {
			Return $false
		} Else {
			Return $true
		}
	}
}

### FUNCTION: Generate New Complex Password
Function generateNewComplexPassword {
	Param (
		[int]$passwdNrChars
	)

	Process {
		$iterations = 0
		Do {
			If ($iterations -ge 20) {
				writeLog -dataToLog "  --> Complex password generation failed after '$iterations' iterations..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				EXIT
			}
			$iterations++
			$passwdBytes = [System.Collections.Generic.List[Object]]::New()
			$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
			Do {
				[byte[]]$byte = [byte]1
				$rng.GetBytes($byte)
				If ($byte[0] -lt 33 -or $byte[0] -gt 126) {
					CONTINUE
				}
				$passwdBytes.Add($byte[0])
			}
			While ($($passwdBytes | Measure-Object).Count -lt $passwdNrChars)
			$passwd = ([char[]]$passwdBytes) -join ''
		}
		Until (confirmPasswordIsComplex -passwd $passwd)

		Return $passwd
	}
}

### FUNCTION: Retrieve The Metadata Of An Object
Function retrieveObjectMetadata {
	Param (
		[string]$targetedADdomainRWDCFQDN,
		[string]$ObjectDN,
		[bool]$localADforest,
		[PSCredential]$adminCrds
	)
	# Get The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object BEFORE THE PASSWORD SET
	$objectMetadata = $null
	$targetedADdomainRWDCContext = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
		$targetedADdomainRWDCContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer", $targetedADdomainRWDCFQDN)
	}
	If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
		$targetedADdomainRWDCContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer", $targetedADdomainRWDCFQDN, $($adminCrds.UserName), $($adminCrds.GetNetworkCredential().Password))
	}
	$targetedADdomainRWDCObject = $null
	Try {
		$targetedADdomainRWDCObject = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($targetedADdomainRWDCContext)
		$objectMetadata = $targetedADdomainRWDCObject.GetReplicationMetadata($ObjectDN)
	} Catch {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
			writeLog -dataToLog "Error Getting Metadata From '$targetedADdomainRWDCFQDN' For Object '$krbTgtObjectBeforeDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
		If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
			writeLog -dataToLog "Error Getting Metadata From '$targetedADdomainRWDCFQDN' For Object '$krbTgtObjectBeforeDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	}

	If ($objectMetadata) {
		Return $($objectMetadata.Values)
	}
}

### FUNCTION: Edit The AD Account And/Or Reset The Password
Function editADAccount {
	Param (
		[string]$targetedADdomainRWDCFQDN,
		[string]$krbTgtSamAccountName,
		[bool]$localADforest,
		[PSCredential]$adminCrds,
		[Hashtable]$listOfEdits
	)

	# Retrieve The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
	$krbTgtObjectBefore = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
			$krbTgtObjectBefore = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
			$krbTgtObjectBefore = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Contact Object With 'sAMAccountName=$krbTgtSamAccountName' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}

	# Get The DN Of The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
	$krbTgtObjectBeforeDN = $null
	$krbTgtObjectBeforeDN = $krbTgtObjectBefore.DistinguishedName

	# Get The Password Last Set Value From The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
	$krbTgtObjectBeforePwdLastSet = $null
	$krbTgtObjectBeforePwdLastSet = Get-Date $([datetime]::fromfiletime($krbTgtObjectBefore.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"

	# Get The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object BEFORE THE PASSWORD SET
	$objectMetadataBefore = $null
	$objectMetadataBefore = retrieveObjectMetadata -targetedADdomainRWDCFQDN $targetedADdomainRWDCFQDN -ObjectDN $krbTgtObjectBeforeDN -localADforest $localADforest -adminCrds $adminCrds
	$objectMetadataBeforeAttribPwdLastSet = $null
	$objectMetadataBeforeAttribPwdLastSet = $objectMetadataBefore | Where-Object { $_.Name -eq "pwdLastSet" }
	$objectMetadataBeforeAttribPwdLastSetOrgRWDCFQDN = $null
	$objectMetadataBeforeAttribPwdLastSetOrgRWDCFQDN = If ($objectMetadataBeforeAttribPwdLastSet.OriginatingServer) { $objectMetadataBeforeAttribPwdLastSet.OriginatingServer } Else { "RWDC Demoted" }
	$objectMetadataBeforeAttribPwdLastSetOrgTime = $null
	$objectMetadataBeforeAttribPwdLastSetOrgTime = Get-Date $($objectMetadataBeforeAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
	$objectMetadataBeforeAttribPwdLastSetVersion = $null
	$objectMetadataBeforeAttribPwdLastSetVersion = $objectMetadataBeforeAttribPwdLastSet.Version

	writeLog -dataToLog "  --> RWDC To Reset Password On.............: '$targetedADdomainRWDCFQDN'"
	writeLog -dataToLog "  --> sAMAccountName Of KrbTgt Account......: '$krbTgtSamAccountName'"
	writeLog -dataToLog "  --> Distinguished Name Of KrbTgt Account..: '$krbTgtObjectBeforeDN'"

	# Specify The Number Of Characters The Generate Password Should Contain
	$passwdNrChars = 64
	writeLog -dataToLog "  --> Number Of Chars For Pwd Generation....: '$passwdNrChars'"

	# Generate A New Password With The Specified Length (Text)
	$newKrbTgtPassword = $null
	$newKrbTgtPassword = (generateNewComplexPassword -passwdNrChars $passwdNrChars).ToString()

	# Try To Set The New Password On The Targeted KrbTgt Account And If Not Successful Throw Error
	Try {
		$krbTgtObj = [PSCustomObject]@{
			distinguishedName = $krbTgtObjectBeforeDN
		}
		If ("ResetPassword" -in $listOfEdits.Keys -And $listOfEdits["ResetPassword"] -eq $true) {
			$krbTgtObj | Add-Member -MemberType NoteProperty -Name unicodePwd -Value $newKrbTgtPassword
		}
		If ($execResetRoutine -And $($script:resetRoutineEnabled).ToUpper() -eq "TRUE") {
			If ($($script:resetRoutineAttributeForResetDateAction1) -in $listOfEdits.Keys) {
				$krbTgtObj | Add-Member -MemberType NoteProperty -Name $($script:resetRoutineAttributeForResetDateAction1) -Value $listOfEdits[$($script:resetRoutineAttributeForResetDateAction1)]
			}
			If ($($script:resetRoutineAttributeForResetDateAction2) -in $listOfEdits.Keys) {
				$krbTgtObj | Add-Member -MemberType NoteProperty -Name $($script:resetRoutineAttributeForResetDateAction2) -Value $listOfEdits[$($script:resetRoutineAttributeForResetDateAction2)]
			}
			If ($($script:resetRoutineAttributeForResetState) -in $listOfEdits.Keys) {
				$krbTgtObj | Add-Member -MemberType NoteProperty -Name $($script:resetRoutineAttributeForResetState) -Value $listOfEdits[$($script:resetRoutineAttributeForResetState)]
			}
		}

		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
			If ("ResetPassword" -in $listOfEdits.Keys -And $listOfEdits["ResetPassword"] -eq $true) {
				Edit-LdapObject -LdapConnection $ldapConnection -Mode Replace -Object $krbTgtObj -BinaryProps unicodePwd
				$script:numAccntsResetSUCCESS += 1
			} Else {
				Edit-LdapObject -LdapConnection $ldapConnection -Mode Replace -Object $krbTgtObj
			}
			$ldapConnection.Dispose()
		}
		If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
			If ("ResetPassword" -in $listOfEdits.Keys -And $listOfEdits["ResetPassword"] -eq $true) {
				Edit-LdapObject -LdapConnection $ldapConnection -Mode Replace -Object $krbTgtObj -BinaryProps unicodePwd
				$script:numAccntsResetSUCCESS += 1
			} Else {
				Edit-LdapObject -LdapConnection $ldapConnection -Mode Replace -Object $krbTgtObj
			}
			$ldapConnection.Dispose()
		}
	} Catch {
		writeLog -dataToLog ""
		writeLog -dataToLog "  --> Editing and/or setting the new password for [$krbTgtObjectBeforeDN] FAILED on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		$script:numAccntsResetFAIL += 1
	}

	# Retrieve The KrgTgt Object In The AD Domain AFTER THE PASSWORD SET
	$krbTgtObjectAfter = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
			If (($listOfEdits.Keys | Measure-Object).Count -gt 1) {
				$krbTgtObjectAfter = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset", $($script:resetRoutineAttributeForResetDateAction1), $($script:resetRoutineAttributeForResetDateAction2), $($script:resetRoutineAttributeForResetState))
			} Else {
				$krbTgtObjectAfter = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
			}
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
			If (($listOfEdits.Keys | Measure-Object).Count -gt 1) {
				$krbTgtObjectAfter = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset", $($script:resetRoutineAttributeForResetDateAction1), $($script:resetRoutineAttributeForResetDateAction2), $($script:resetRoutineAttributeForResetState))
			} Else {
				$krbTgtObjectAfter = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
			}
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}

	# Get The DN Of The KrgTgt Object In The AD Domain AFTER THE PASSWORD SET
	$krbTgtObjectAfterDN = $null
	$krbTgtObjectAfterDN = $krbTgtObjectAfter.DistinguishedName

	# Get The Password Last Set Value From The KrgTgt Object In The AD Domain AFTER THE PASSWORD SET
	$krbTgtObjectAfterPwdLastSet = $null
	$krbTgtObjectAfterPwdLastSet = Get-Date $([datetime]::fromfiletime($krbTgtObjectAfter.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"

	# Get The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object AFTER THE PASSWORD SET
	$objectMetadataAfter = $null
	$objectMetadataAfter = retrieveObjectMetadata -targetedADdomainRWDCFQDN $targetedADdomainRWDCFQDN -ObjectDN $krbTgtObjectAfterDN -localADforest $localADforest -adminCrds $adminCrds
	$objectMetadataAfterAttribPwdLastSet = $null
	$objectMetadataAfterAttribPwdLastSet = $objectMetadataAfter | Where-Object { $_.Name -eq "pwdLastSet" }
	$objectMetadataAfterAttribPwdLastSetOrgRWDCFQDN = $null
	$objectMetadataAfterAttribPwdLastSetOrgRWDCFQDN = If ($objectMetadataAfterAttribPwdLastSet.OriginatingServer) { $objectMetadataAfterAttribPwdLastSet.OriginatingServer } Else { "RWDC Demoted" }
	$objectMetadataAfterAttribPwdLastSetOrgTime = $null
	$objectMetadataAfterAttribPwdLastSetOrgTime = Get-Date $($objectMetadataAfterAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
	$objectMetadataAfterAttribPwdLastSetVersion = $null
	$objectMetadataAfterAttribPwdLastSetVersion = $objectMetadataAfterAttribPwdLastSet.Version

	writeLog -dataToLog ""
	writeLog -dataToLog "  --> Previous Password Set Date/Time.......: '$krbTgtObjectBeforePwdLastSet'"
	writeLog -dataToLog "  --> Max TGT Lifetime (Hours)..............: '$($script:targetedADdomainMaxTgtLifetimeHrs)'"
	writeLog -dataToLog "  --> Max TGT Lifetime Sourced From.........: '$($script:targetedADdomainMaxTgtLifetimeHrsSourceGPO)'"
	writeLog -dataToLog "  --> Max Clock Skew (Minutes)..............: '$($script:targetedADdomainMaxClockSkewMins)'"	
	writeLog -dataToLog "  --> Max Clock Skew Sourced From...........: '$($script:targetedADdomainMaxClockSkewMinsSourceGPO)'"
	writeLog -dataToLog "  --> Date/Time N-1 Kerberos Tickets........: '$(Get-Date $expirationTimeForNMinusOneKerbTickets -f 'yyyy-MM-dd HH:mm:ss')'"
	writeLog -dataToLog "  --> Date/Time Now (When Script Started)...: '$(Get-Date $execDateTime -f 'yyyy-MM-dd HH:mm:ss')'"

	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		writeLog -dataToLog "  --> New Password Set Date/Time............: '$krbTgtObjectAfterPwdLastSet'"
	}
	writeLog -dataToLog ""
	writeLog -dataToLog "  --> Previous Originating RWDC.............: '$objectMetadataBeforeAttribPwdLastSetOrgRWDCFQDN'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		writeLog -dataToLog "  --> New Originating RWDC..................: '$objectMetadataAfterAttribPwdLastSetOrgRWDCFQDN'"
	}
	writeLog -dataToLog ""
	writeLog -dataToLog "  --> Previous Originating Time.............: '$objectMetadataBeforeAttribPwdLastSetOrgTime'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		writeLog -dataToLog "  --> New Originating Time..................: '$objectMetadataAfterAttribPwdLastSetOrgTime'"
	}
	writeLog -dataToLog ""
	writeLog -dataToLog "  --> Previous Version Of Attribute Value...: '$objectMetadataBeforeAttribPwdLastSetVersion'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		writeLog -dataToLog "  --> New Version Of Attribute Value........: '$objectMetadataAfterAttribPwdLastSetVersion'"
	}

	# Check And Confirm If The Password Value Has Been Updated By Comparing The Password Last Set Before And After The Reset
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		writeLog -dataToLog ""
		writeLog -dataToLog "  --> THE NEW PASSWORD FOR [$krbTgtObjectAfterDN] HAS BEEN SET on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	} Else {
		writeLog -dataToLog ""
		writeLog -dataToLog "  --> NO PASSWORD HAS BEEN SET FOR [$krbTgtObjectAfterDN]!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	}
}

### FUNCTION: Replicate Single AD Object
# INFO: https://msdn.microsoft.com/en-us/library/cc223306.aspx
Function replicateSingleADObject {
	Param (
		[string]$sourceDCNTDSSettingsObjectDN,
		[string]$targetDCFQDN,
		[string]$objectDN,
		[string]$contentScope,
		[bool]$localADforest,
		[PSCredential]$adminCrds
	)

	# Define And Target The root DSE Context
	$rootDSE = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$rootDSE = [ADSI]"LDAP://$targetDCFQDN/rootDSE"
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Connecting To '$targetDCFQDN' For 'rootDSE'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$rootDSE = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$targetDCFQDN/rootDSE"), $($adminCrds.UserName), $($adminCrds.GetNetworkCredential().password))
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Connecting To '$targetDCFQDN' For 'rootDSE' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}

	# Perform A Replicate Single Object For The Complete Object
	If ($contentScope -eq "Full") {
		Try {
			$rootDSE.Put("replicateSingleObject", $sourceDCNTDSSettingsObjectDN + ":" + $objectDN)
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Replicate Single Object (Full) Failed From '$sourceDCNTDSSettingsObjectDN' To '$targetDCFQDN' For Object '$objectDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}

	# Perform A Replicate Single Object For Only The Secrets Of The Object
	If ($contentScope -eq "Secrets") {
		Try {
			$rootDSE.Put("replicateSingleObject", $sourceDCNTDSSettingsObjectDN + ":" + $objectDN + ":SECRETS_ONLY")
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Replicate Single Object (Secrets Only) Failed From '$sourceDCNTDSSettingsObjectDN' To '$targetDCFQDN' For Object '$objectDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}

	# Commit The Change To The Operational Attribute
	Try {
		$rootDSE.SetInfo()
	} Catch {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Triggering Replicate Single Object On '$targetDCFQDN' From '$sourceDCNTDSSettingsObjectDN' Failed For Object '$objectDN' Using The '$contentScope' Scope..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	}
}

### FUNCTION: Delete/Cleanup Temporary Canary Object
Function deleteTempCanaryObject {
	Param (
		[string]$targetedADdomainRWDCFQDN,
		[string]$targetObjectToCheckDN,
		[bool]$localADforest,
		[PSCredential]$adminCrds
	)

	# Try To Delete The Canary Object In The AD Domain And If Not Successful Throw Error
	Try {
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
			Remove-LdapObject -LdapConnection $ldapConnection -Object $targetObjectToCheckDN
			$ldapConnection.Dispose()
		}
		If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
			Remove-LdapObject -LdapConnection $ldapConnection -Object $targetObjectToCheckDN
			$ldapConnection.Dispose()
		}
	} Catch {
		writeLog -dataToLog "  --> Temp Canary Object [$targetObjectToCheckDN] FAILED TO BE DELETED on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "  --> Manually delete the Temp Canary Object [$targetObjectToCheckDN] on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	}

	# Retrieve The Temporary Canary Object From The AD Domain And If It Does Not Exist It Was Deleted Successfully
	$targetObjectToCheck = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
			$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$targetObjectToCheckDN)"
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$targetObjectToCheckDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
			$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$targetObjectToCheckDN)"
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ([string]::IsNullOrEmpty($targetObjectToCheck)) {
		writeLog -dataToLog "  --> Temp Canary Object [$targetObjectToCheckDN] DELETED on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	}
}

### FUNCTION: Check AD Replication Convergence
Function checkADReplicationConvergence {
	Param (
		[string]$targetedADdomainFQDN,
		[string]$targetedADdomainSourceRWDCFQDN,
		[string]$targetObjectToCheckDN,
		[PSCustomObject]$listOfDCsToCheckObjectOnStart,
		[PSCustomObject]$listOfDCsToCheckObjectOnEnd,
		[int]$modeOfOperationNr,
		[bool]$localADforest,
		[PSCredential]$adminCrds
	)

	# Determine The Starting Time
	$startDateTime = Get-Date

	# Counter
	$c = 0

	# Boolean To Use In The While Condition
	$continue = $true

	# The Delay In Seconds Before The Next Check Iteration
	$delay = 0.1

	While ($continue) {
		$c++
		$oldpos = $host.UI.RawUI.CursorPosition
		writeLog -dataToLog ""
		writeLog -dataToLog "  =================================================================== CHECK $c ==================================================================="
		writeLog -dataToLog ""

		# Wait For The Duration Of The Configured Delay Before Trying Again
		Start-Sleep $delay

		# Variable Specifying The Object Is In Sync
		$replicated = $true

		# For Each DC To Check On The Starting List With All DCs To Check Execute The Following...
		ForEach ($dcToCheck in $listOfDCsToCheckObjectOnStart) {
			# HostName Of The DC To Check
			$dcToCheckHostName = $null
			$dcToCheckHostName = $dcToCheck."Host Name"

			# Is The DC To Check Also The PDC?
			$dcToCheckIsPDC = $null
			$dcToCheckIsPDC = $dcToCheck.PDC

			# Type (RWDC Or RODC) Of The DC To Check
			$dcToCheckDSType = $null
			$dcToCheckDSType = $dcToCheck."DS Type"

			# SiteName Of The DC To Check
			$dcToCheckSiteName = $null
			$dcToCheckSiteName = $dcToCheck."Site Name"

			# IP Address Of The DC To Check
			$dcToCheckIPAddress = $null
			$dcToCheckIPAddress = $dcToCheck."IP Address"

			# Reachability Of The DC To Check
			$dcToCheckReachability = $null
			$dcToCheckReachability = $dcToCheck.Reachable

			# DSA DN Of The Source RWDC Of The DC To Check
			$dcToCheckSourceRWDCNTDSSettingsObjectDN = $null
			$dcToCheckSourceRWDCNTDSSettingsObjectDN = $dcToCheck."Source RWDC DSA"

			# If Mode 3, Simulate Password Reset Of TEST/BOGUS KrbTgt Accounts (No Password Reset/WhatIf Mode)
			# If Mode 4, Do A Real Password Reset Of TEST/BOGUS KrbTgt Accounts (Password Reset!)
			# If Mode 5, Simulate Password Reset Of PROD/REAL KrbTgt Accounts (No Password Reset/WhatIf Mode)
			# If Mode 6, Do A Real Password Reset Of PROD/REAL KrbTgt Accounts (Password Reset!)
			If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
				# Retrieve The Object From The Source Originating RWDC
				$objectOnSourceOrgRWDC = $null
				If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
					Try {
						$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos
						$objectOnSourceOrgRWDC = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$targetObjectToCheckDN)" -PropertiesToLoad @("pwdlastset")
						$ldapConnection.Dispose()
					} Catch {
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For Object '$targetObjectToCheckDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					}
				}
				If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
					Try {
						$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
						$objectOnSourceOrgRWDC = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$targetObjectToCheckDN)" -PropertiesToLoad @("pwdlastset")
						$ldapConnection.Dispose()
					} Catch {
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For Object '$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					}
				}

				# Retrieve The Password Last Set Of The Object On The Source Originating RWDC
				$objectOnSourceOrgRWDCPwdLastSet = $null
				$objectOnSourceOrgRWDCPwdLastSet = Get-Date $([datetime]::fromfiletime($objectOnSourceOrgRWDC.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
			}

			# When The DC To Check Is Also The Source (Originating) RWDC
			If ($dcToCheckHostName -eq $targetedADdomainSourceRWDCFQDN) {
				writeLog -dataToLog "  - Contacting DC in AD domain ...[$($dcToCheckHostName.ToUpper())]...(SOURCE RWDC)"
				writeLog -dataToLog "     * DC is Reachable..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false

				# For Mode 2 Only
				If ($modeOfOperationNr -eq 2) {
					writeLog -dataToLog "     * Object [$targetObjectToCheckDN] exists in the AD database" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				}

				# For Mode 3 Or 4 Or 5 Or 6 Only
				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
					writeLog -dataToLog "     * The (new) password for Object [$targetObjectToCheckDN] exists in the AD database" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				}
				writeLog -dataToLog ""

				CONTINUE
			}

			writeLog -dataToLog "  - Contacting DC in AD domain ...[$($dcToCheckHostName.ToUpper())]..."
			If ($dcToCheckReachability -eq $true) {
				# When The DC To Check Is Reachable
				writeLog -dataToLog "     * DC is Reachable..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false

				# When The DC To Check Is Not The Source (Originating) RWDC
				If ($dcToCheckHostName -ne $targetedADdomainSourceRWDCFQDN) {
					# As The DSA DN Use The DSA DN Of The Source (Originating) RWDC Of The DC Being Checked
					$sourceDCNTDSSettingsObjectDN = $dcToCheckSourceRWDCNTDSSettingsObjectDN

					# For Mode 2 Perform A Full Replicate Single Object
					If ($modeOfOperationNr -eq 2) {
						$contentScope = "Full"
					}

					# For Mode 3 Or 4 Or 5 Or 6 Only
					If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
						# If The DC Being Checked Is An RWDC Perform A Full Replicate Single Object
						If ($dcToCheckDSType -eq "Read/Write") {
							$contentScope = "Full"
						}

						# If The DC Being Checked Is An RODC Perform A Partial Replicate Single Object (Secrets Only)
						If ($dcToCheckDSType -eq "Read-Only") {
							$contentScope = "Secrets"
						}
					}

					# Execute The Replicate Single Object Function For The Targeted Object To Check
					replicateSingleADObject -sourceDCNTDSSettingsObjectDN $sourceDCNTDSSettingsObjectDN -targetDCFQDN $dcToCheckHostName -objectDN $targetObjectToCheckDN -contentScope $contentScope -localADforest $localADforest -adminCrds $adminCrds
				}

				# For Mode 2 From The DC to Check Retrieve The AD Object Of The Temporary Canary Object That Was Created On The Source (Originating) RWDC
				If ($modeOfOperationNr -eq 2) {
					$targetObjectToCheck = $null
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
						Try {
							$ldapConnection = Get-LdapConnection -LdapServer:$dcToCheckHostName -EncryptionType Kerberos
							$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$targetObjectToCheckDN)"
							$ldapConnection.Dispose()
						} Catch {
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error Querying AD Against '$dcToCheckHostName' For Object With 'distinguishedName=$targetObjectToCheckDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						}
					}
					If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
						Try {
							$ldapConnection = Get-LdapConnection -LdapServer:$dcToCheckHostName -EncryptionType Kerberos -Credential $adminCrds
							$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$targetObjectToCheckDN)"
							$ldapConnection.Dispose()
						} Catch {
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error Querying AD Against '$dcToCheckHostName' For User Object With 'distinguishedName=$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						}
					}
				}

				# For Mode 3 Or 4 From The DC to Check Retrieve The AD Object Of The Targeted KrbTgt Account (And Its Password Last Set) That Had Its Password Reset On The Source (Originating) RWDC
				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
					# Retrieve The Object From The Target DC
					$objectOnTargetDC = $null
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
						Try {
							$ldapConnection = Get-LdapConnection -LdapServer:$dcToCheckHostName -EncryptionType Kerberos
							$objectOnTargetDC = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$targetObjectToCheckDN)" -PropertiesToLoad @("pwdlastset")
							$ldapConnection.Dispose()
						} Catch {
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error Querying AD Against '$dcToCheckHostName' For Object '$targetObjectToCheckDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						}
					}
					If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
						Try {
							$ldapConnection = Get-LdapConnection -LdapServer:$dcToCheckHostName -EncryptionType Kerberos -Credential $adminCrds
							$objectOnTargetDC = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$targetObjectToCheckDN)" -PropertiesToLoad @("pwdlastset")
							$ldapConnection.Dispose()
						} Catch {
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error Querying AD Against '$dcToCheckHostName' For Object '$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						}
					}

					# Retrieve The Password Last Set Of The Object On The Target DC
					$objectOnTargetDCPwdLastSet = $null
					$objectOnTargetDCPwdLastSet = Get-Date $([datetime]::fromfiletime($objectOnTargetDC.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
				}
			} Else {
				# When The DC To Check Is Not Reachable
				writeLog -dataToLog "     * DC is NOT reachable..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}

			If ($dcToCheckReachability -eq $true) {
				# When The DC To Check Is Reachable

				If ($(-not [string]::IsNullOrEmpty($targetObjectToCheck)) -Or $objectOnTargetDCPwdLastSet -eq $objectOnSourceOrgRWDCPwdLastSet) {
					# If The Target Object To Check Does Exist Or Its Password Last Set Does Match With The Password Last Set Of The Object On The Source (Originating) RWDC
					# For Mode 2 Only
					If ($modeOfOperationNr -eq 2) {
						writeLog -dataToLog "     * Object [$targetObjectToCheckDN] now does exist in the AD database" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					}

					# For Mode 3 Or 4 Or 5 Or 6 Only
					If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
						writeLog -dataToLog "     * The (new) password for Object [$targetObjectToCheckDN] now does exist in the AD database" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					}
					writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false

					# If The DC To Check Does Not Yet Exist On The Ending List With All DCs That Were Checked, Then Add It To The Ending List
					If (!($listOfDCsToCheckObjectOnEnd | Where-Object { $_."Host Name" -eq $dcToCheckHostName })) {
						$listOfDCsToCheckObjectOnEndObj = [PSCustomObject]@{
							"Host Name"        = $dcToCheckHostName
							"PDC"              = $dcToCheckIsPDC
							"Site Name"        = $dcToCheckSiteName
							"DS Type"          = $dcToCheckDSType
							"IP Address"       = $dcToCheckIPAddress
							"Reachable"        = $dcToCheckReachability
							"Source RWDC FQDN" = $targetedADdomainSourceRWDCFQDN
							"Time"             = $(("{0:n2}" -f ((Get-Date) - $startDateTime).TotalSeconds))
						}
						$listOfDCsToCheckObjectOnEnd.Add($listOfDCsToCheckObjectOnEndObj)
					}
				} Else {
					# If The Target Object To Check Does Not Exist Or Its Password Last Set Does Not Match (Yet) With The Password Last Set Of The Object On The Source (Originating) RWDC
					# For Mode 2 Only
					If ($modeOfOperationNr -eq 2) {
						writeLog -dataToLog "     * Object [$targetObjectToCheckDN] does NOT exist yet in the AD database" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
					}

					# For Mode 3 Or 4 Or 5 Or 6 Only
					If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
						writeLog -dataToLog "     * The (new) password for Object [$targetObjectToCheckDN] does NOT exist yet in the AD database" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
					}
					writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false

					# Variable Specifying The Object Is Not In Sync
					$replicated = $false
				}
			} Else {
				# When The DC To Check Is Not Reachable
				writeLog -dataToLog "     * Unable to connect to DC and check for Object [$targetObjectToCheckDN]..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false

				# If The DC To Check Does Not Yet Exist On The Ending List With All DCs That Were Checked, Then Add It To The Ending List
				If (!($listOfDCsToCheckObjectOnEnd | Where-Object { $_."Host Name" -eq $dcToCheckHostName })) {
					$listOfDCsToCheckObjectOnEndObj = [PSCustomObject]@{
						"Host Name"        = $dcToCheckHostName
						"PDC"              = $dcToCheckIsPDC
						"Site Name"        = $dcToCheckSiteName
						"DS Type"          = $dcToCheckDSType
						"IP Address"       = $dcToCheckIPAddress
						"Reachable"        = $dcToCheckReachability
						"Source RWDC FQDN" = $targetedADdomainSourceRWDCFQDN
						"Time"             = "<Fail>"
					}
					$listOfDCsToCheckObjectOnEnd.Add($listOfDCsToCheckObjectOnEndObj)
				}
			}
		}

		# If The Object Is In Sync
		If ($replicated) {
			# Do Not Continue For The DC That Is Being Checked
			$continue = $false
		} Else {
			# Do Continue For The DC That Is Being Checked And Move The Cursor Back To The Initial Position
			$host.UI.RawUI.CursorPosition = $oldpos
		}
	}

	# Determine The Ending Time
	$endDateTime = Get-Date

	# Calculate The Duration
	$duration = "{0:n2}" -f ($endDateTime.Subtract($startDateTime).TotalSeconds)
	writeLog -dataToLog ""
	writeLog -dataToLog "  --> Start Time......: $(Get-Date $startDateTime -format 'yyyy-MM-dd HH:mm:ss')"
	writeLog -dataToLog "  --> End Time........: $(Get-Date $endDateTime -format 'yyyy-MM-dd HH:mm:ss')"
	writeLog -dataToLog "  --> Duration........: $duration Seconds"
	writeLog -dataToLog ""

	# If Mode 2 Was Being Executed, Then Delete The Temp Canary Object On The Source (Originating) RWDC
	If ($modeOfOperationNr -eq 2) {
		# Retrieve The Temp Canary Object From The Source (Originating) RWDC
		$targetObjectToCheck = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos
				$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$targetObjectToCheckDN)"
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For Object '$targetObjectToCheckDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
				$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$targetObjectToCheckDN)"
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For Object '$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}

		# If The Temp Canary Object Exists On The Source (Originating) RWDC, Then Delete It
		If ($(-not [string]::IsNullOrEmpty($targetObjectToCheck))) {
			# Execute The Deletion Of The Temp Canary Object On The Source (Originating) RWDC. There Is No Need To Force Deletion Of The Object On All The Other DCs As In Time It Will Be Deleted
			deleteTempCanaryObject -targetedADdomainRWDCFQDN $targetedADdomainSourceRWDCFQDN -targetObjectToCheckDN $targetObjectToCheckDN -localADforest $localADforest -adminCrds $adminCrds
		}
	}

	# Sort The Ending List With All DCs That Were Checked
	$listOfDCsToCheckObjectOnEnd = $listOfDCsToCheckObjectOnEnd | Sort-Object -Property @{Expression = "Time"; Descending = $false } | Format-Table -Autosize
	writeLog -dataToLog ""
	writeLog -dataToLog "List Of DCs In AD Domain '$targetedADdomainFQDN' And Their Timing..."
	writeLog -dataToLog ""
	writeLog -dataToLog "$($listOfDCsToCheckObjectOnEnd | Out-String -Width 1024)"
	writeLog -dataToLog ""
}

### FUNCTION: Determine The User Account To Use For RSoP
Function determineUserAccountForRSoP {
	Param (
		[string]$targetedADdomainNearestRWDCFQDN,
		[string]$targetedADdomainDomainSID
	)

	# Get All User Profiles That Match The Targeted AD Domain Sid
	$sidOfProfilesOfTargetedDomainOnDC = Get-CimInstance Win32_UserProfile -ComputerName $targetedADdomainNearestRWDCFQDN | Where-Object { $_.SID -match $targetedADdomainDomainSID } | ForEach-Object { $_.SID }
	$sidCandidatesOnDC = @()
	
	# For Each Scoped User Profile Get The Object Class And The Constructed Attribute "tokenGroupsNoGCAcceptable"
	$sidOfProfilesOfTargetedDomainOnDC | ForEach-Object {
		$targetObjectToCheck = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos
				$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(objectSid=$_)"
				$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($targetObjectToCheck.distinguishedName) -searchFilter "(objectSid=$_)" -searchScope Base -PropertiesToLoad @("objectClass","tokenGroupsNoGCAcceptable") -BinaryProps @("tokenGroupsNoGCAcceptable")
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Object '$_' To Determine Its ObjectClass..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
				$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(objectSid=$_)"
				$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($targetObjectToCheck.distinguishedName) -searchFilter "(objectSid=$_)" -searchScope Base -PropertiesToLoad @("objectClass","tokenGroupsNoGCAcceptable") -BinaryProps @("tokenGroupsNoGCAcceptable")
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Object '$_' To Determine Its ObjectClass Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		
		# From The List With SIDs In Byte Format, Create A List Wth SIDs In String Format
		$groupSidsByteFormatForAccount = $targetObjectToCheck.tokenGroupsNoGCAcceptable
		$groupSidsStringFormatForAccount = @()
		$groupSidsByteFormatForAccount | ForEach-Object {
			$sidByteFormat = $_
			$sidStringFormat = (New-Object System.Security.Principal.SecurityIdentifier($sidByteFormat,0)).Value
			$groupSidsStringFormatForAccount += $sidStringFormat
		}

		# If The User Profile Belongs To An Account With Object Class USER And Which Is A Member Of Either Or Both "Administrators" And/Or "Domain Admins" Group, Add It As A Possible Candidate To Choose From
		If ($targetObjectToCheck.objectClass[-1] -eq "user" -And ($groupSidsStringFormatForAccount.Contains("S-1-5-32-544") -Or $groupSidsStringFormatForAccount.Contains("$targetedADdomainDomainSID-512"))) {
			$sidCandidatesOnDC += $_
		}
	}
	If ($sidCandidatesOnDC -contains ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value) {
		$sidToChoose = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
	} ElseIf ($($sidCandidatesOnDC | Measure-Object).Count -gt 0) {
		$sidToChoose = $sidCandidatesOnDC | Get-Random
	} Else {
		$sidToChoose = $sidOfProfilesOfTargetedDomainOnDC | Get-Random
	}
	$accountToChooseForRSoP = $(New-Object System.Security.Principal.SecurityIdentifier($sidToChoose)).Translate([System.Security.Principal.NTAccount]).Value

	Return $accountToChooseForRSoP
}
$determineUserAccountForRSoPDef = "function determineUserAccountForRSoP{${function:determineUserAccountForRSoP}}"

### FUNCTION: Determine Kerberos Policy Settings
Function determineKerberosPolicySettings {
	Param (
		[string]$targetedADdomainFQDN,
		[string]$targetedADdomainNearestRWDCFQDN,
		[string]$execDateTimeCustom,
		[Xml]$gpRSoPxml
	)

	$gpoList = @{}
	(Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop" }).Node.ComputerResults.GPO | ForEach-Object { $gpoList.Add($_.Path.Identifier."#text", $_.Name) }
	$rsopKerberosPolicy = (((Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop" }).Node.ComputerResults.ExtensionData.Extension | Where-Object { $_.type -like "*:SecuritySettings" }) | Where-Object { Get-Member -InputObject $_ -Name Account }).Account | Where-Object { $_.Type -eq "Kerberos" }
	$kerberosPolicyMaxTgtAgeObject = New-Object -TypeName PSObject -Property @{
		SettingName   = "MaxTicketAge";
		SettingValue  = ($rsopKerberosPolicy | Where-Object { $_.Name -eq "MaxTicketAge" }).SettingNumber;
		SourceGPOGuid = $(($rsopKerberosPolicy | Where-Object { $_.Name -eq "MaxTicketAge" }).GPO.Identifier.'#text');
		SourceGPOName = $gpoList[$(($rsopKerberosPolicy | Where-Object { $_.Name -eq "MaxTicketAge" }).GPO.Identifier.'#text')];
	}
	$kerberosPolicyMaxClockSkewObject = New-Object -TypeName PSObject -Property @{
		SettingName   = "MaxClockSkew";
		SettingValue  = ($rsopKerberosPolicy | Where-Object { $_.Name -eq "MaxClockSkew" }).SettingNumber;
		SourceGPOGuid = $(($rsopKerberosPolicy | Where-Object { $_.Name -eq "MaxClockSkew" }).GPO.Identifier.'#text');
		SourceGPOName = $gpoList[$(($rsopKerberosPolicy | Where-Object { $_.Name -eq "MaxClockSkew" }).GPO.Identifier.'#text')];
	}

	Return $kerberosPolicyMaxTgtAgeObject, $kerberosPolicyMaxClockSkewObject
}
$determineKerberosPolicySettingsDef = "function determineKerberosPolicySettings{${function:determineKerberosPolicySettings}}"

### FUNCTION: Create TEST/BOGUS KrbTgt Accounts
Function createTestKrbTgtADAccount {
	Param (
		[string]$targetedADdomainRWDCFQDN,
		[string]$krbTgtInUseByDCFQDN,
		[string]$krbTgtSamAccountName,
		[string]$krbTgtUse,
		[string]$targetedADdomainDomainSID,
		[bool]$localADforest,
		[PSCredential]$adminCrds
	)
	# Determine The DN Of The Users Container Of The Targeted Domain
	$containerForTestKrbTgtAccount = $null
	$containerForTestKrbTgtAccount = "CN=Users," + $($script:targetedADdomainDefaultNCDN)

	# Set The SamAccountName For The Test/Bogus KrbTgt Account
	$testKrbTgtObjectSamAccountName = $null
	$testKrbTgtObjectSamAccountName = $krbTgtSamAccountName

	# Set The Name For The Test/Bogus KrbTgt Account
	$testKrbTgtObjectName = $null
	$testKrbTgtObjectName = $testKrbTgtObjectSamAccountName

	# Set The Description For The Test/Bogus KrbTgt Account
	$testKrbTgtObjectDescription = $null

	# Set The Description For The Test/Bogus KrbTgt Account For RWDCs
	If ($krbTgtUse -eq "RWDC") {
		$testKrbTgtObjectDescription = "Test Copy Representing '$($krbTgtSamAccountName.SubString(0,$krbTgtSamAccountName.IndexOf('_TEST')))' - Key Distribution Center Service Account For RWDCs"
	}

	# Set The Description For The Test/Bogus KrbTgt Account For RODCs
	If ($krbTgtUse -eq "RODC") {
		$testKrbTgtObjectDescription = "Test Copy Representing '$($krbTgtSamAccountName.SubString(0,$krbTgtSamAccountName.IndexOf('_TEST')))' - Key Distribution Center Service Account For RODC '$krbTgtInUseByDCFQDN'"
	}

	# Generate The DN Of The TEST/BOGUS KrbTgt Object
	$testKrbTgtObjectDN = $null
	$testKrbTgtObjectDN = "CN=" + $testKrbTgtObjectName + "," + $containerForTestKrbTgtAccount

	# Display Information About The TEST/BOGUS KrbTgt To Be Created/Edited
	writeLog -dataToLog "  --> RWDC To Create/Update Object On.......: '$targetedADdomainRWDCFQDN'"
	writeLog -dataToLog "  --> Full Name TEST/BOGUS KrbTgt Account...: '$testKrbTgtObjectName'"
	writeLog -dataToLog "  --> Description...........................: '$testKrbTgtObjectDescription'"
	writeLog -dataToLog "  --> Container TEST/BOGUS KrbTgt Account...: '$containerForTestKrbTgtAccount'"
	If ($krbTgtUse -eq "RWDC") {
		writeLog -dataToLog "  --> To Be Used By DC(s)...................: 'All RWDCs'"
	}
	If ($krbTgtUse -eq "RODC") {
		writeLog -dataToLog "  --> To Be Used By RODC....................: '$krbTgtInUseByDCFQDN'"
	}

	# If The Test/Bogus KrbTgt Account Is Used By RWDCs
	If ($krbTgtUse -eq "RWDC") {
		$deniedRODCPwdReplGroupRID = "572"
		$deniedRODCPwdReplGroupObjectSID = $targetedADdomainDomainSID + "-" + $deniedRODCPwdReplGroupRID
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
				$deniedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(objectSID=$deniedRODCPwdReplGroupObjectSID)" -PropertiesToLoad @("name")
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Group Object With 'objectSID=$deniedRODCPwdReplGroupObjectSID'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
				$deniedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(objectSID=$deniedRODCPwdReplGroupObjectSID)" -PropertiesToLoad @("name")
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Group Object With 'objectSID=$deniedRODCPwdReplGroupObjectSID' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		$deniedRODCPwdReplGroupObjectDN = $deniedRODCPwdReplGroupObject.distinguishedName
		$deniedRODCPwdReplGroupObjectName = $deniedRODCPwdReplGroupObject.name
		writeLog -dataToLog "  --> Membership Of RODC PRP Group..........: '$deniedRODCPwdReplGroupObjectName' ('$deniedRODCPwdReplGroupObjectDN')"
	}

	# If The Test/Bogus KrbTgt Account Is Used By RODCs
	If ($krbTgtUse -eq "RODC") {
		$allowedRODCPwdReplGroupRID = "571"
		$allowedRODCPwdReplGroupObjectSID = $targetedADdomainDomainSID + "-" + $allowedRODCPwdReplGroupRID
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
				$allowedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(objectSID=$allowedRODCPwdReplGroupObjectSID)" -PropertiesToLoad @("name")
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Group Object With 'objectSID=$allowedRODCPwdReplGroupObjectSID'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
				$allowedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(objectSID=$allowedRODCPwdReplGroupObjectSID)" -PropertiesToLoad @("name")
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Group Object With 'objectSID=$allowedRODCPwdReplGroupObjectSID' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		$allowedRODCPwdReplGroupObjectDN = $allowedRODCPwdReplGroupObject.distinguishedName
		$allowedRODCPwdReplGroupObjectName = $allowedRODCPwdReplGroupObject.name
		writeLog -dataToLog "  --> Membership Of RODC PRP Group..........: '$allowedRODCPwdReplGroupObjectName' ('$allowedRODCPwdReplGroupObjectDN')"
	}
	writeLog -dataToLog ""

	# Check If The Test/Bogus KrbTgt Account Already Exists In AD
	$testKrbTgtObject = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
			$testKrbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$testKrbTgtObjectDN)" -PropertiesToLoad @("description")
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$testKrbTgtObjectDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
			$testKrbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$testKrbTgtObjectDN)" -PropertiesToLoad @("description")
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$testKrbTgtObjectDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ($testKrbTgtObject) {
		writeLog -dataToLog "  --> TEST/BOGUS KrbTgt Account [$testKrbTgtObjectDN] ALREADY EXISTS on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""
		# Update The Description For The TEST/BOGUS KrbTgt Account If There Is A Mismatch For Whatever Reason
		If ($testKrbTgtObject.Description -ne $testKrbTgtObjectDescription) {
			$testKrbTgtObj = [PSCustomObject]@{distinguishedName = $null; description = $null }
			$testKrbTgtObj.distinguishedName = $testKrbTgtObjectDN
			$testKrbTgtObj.description = $testKrbTgtObjectDescription
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
					Edit-LdapObject -LdapConnection $ldapConnection -Mode Replace -Object $testKrbTgtObj
					$ldapConnection.Dispose()
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Updating User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectSamAccountName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
			If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
					Edit-LdapObject -LdapConnection $ldapConnection -Mode Replace -Object $testKrbTgtObj
					$ldapConnection.Dispose()
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Updating User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectSamAccountName' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
			writeLog -dataToLog "  --> Updated Description For Existing TEST/BOGUS KrbTgt Account [$testKrbTgtObjectDN] on RWDC [$targetedADdomainRWDCFQDN] Due To Mismatch!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		}

		# Check The Membership Of The TEST/BOGUS KrbTgt Accounts And Update As Needed
		$updateMembership = $false
		If ($krbTgtUse -eq "RWDC") {
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
					If (!(Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$testKrbTgtObjectSamAccountName)(memberOf:1.2.840.113556.1.4.1941:=$deniedRODCPwdReplGroupObjectDN))")) {
						$updateMembership = $true
					}
					$ldapConnection.Dispose()
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Checking Membership On '$targetedADdomainRWDCFQDN' Of Object '$testKrbTgtObjectSamAccountName' For Object '$deniedRODCPwdReplGroupObjectName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
			If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
					If (!(Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$testKrbTgtObjectSamAccountName)(memberOf:1.2.840.113556.1.4.1941:=$deniedRODCPwdReplGroupObjectDN))")) {
						$updateMembership = $true
					}
					$ldapConnection.Dispose()
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Checking Membership On '$targetedADdomainRWDCFQDN' Of Object '$testKrbTgtObjectSamAccountName' For Object '$deniedRODCPwdReplGroupObjectName' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
		}
		If ($krbTgtUse -eq "RODC") {
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
					If (!(Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$testKrbTgtObjectSamAccountName)(memberOf:1.2.840.113556.1.4.1941:=$allowedRODCPwdReplGroupObjectDN))")) {
						$updateMembership = $true
					}
					$ldapConnection.Dispose()
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Checking Membership On '$targetedADdomainRWDCFQDN' Of Object '$testKrbTgtObjectSamAccountName' For Object '$allowedRODCPwdReplGroupObjectName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
			If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
					If (!(Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$testKrbTgtObjectSamAccountName)(memberOf:1.2.840.113556.1.4.1941:=$allowedRODCPwdReplGroupObjectDN))")) {
						$updateMembership = $true
					}
					$ldapConnection.Dispose()
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Checking Membership On '$targetedADdomainRWDCFQDN' Of Object '$testKrbTgtObjectSamAccountName' For Object '$allowedRODCPwdReplGroupObjectName' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
		}
	} Else {
		# If The Test/Bogus KrbTgt Account Does Not Exist Yet In AD
		# Specify The Number Of Characters The Generate Password Should Contain
		$passwdNrChars = 64

		# Generate A New Password With The Specified Length (Text)
		$krbTgtPassword = $null
		$krbTgtPassword = (generateNewComplexPassword -passwdNrChars $passwdNrChars).ToString()

		# Try To Create The Test/Bogus KrbTgt Account In The AD Domain And If Not Successful Throw Error
		Try {
			$testKrbTgtObj = [PSCustomObject]@{distinguishedName = $null; objectClass = $null; sAMAccountName = $null; displayName = $null; userAccountControl = 0; unicodePwd = $null; description = $null }
			$testKrbTgtObj.distinguishedName = $testKrbTgtObjectDN
			$testKrbTgtObj.objectClass = "user"
			$testKrbTgtObj.sAMAccountName = $testKrbTgtObjectSamAccountName
			$testKrbTgtObj.displayName = $testKrbTgtObjectName
			$testKrbTgtObj.userAccountControl = 514
			$testKrbTgtObj.unicodePwd = $krbTgtPassword
			$testKrbTgtObj.description = $testKrbTgtObjectDescription
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
					Add-LdapObject -LdapConnection $ldapConnection -Object $testKrbTgtObj -BinaryProps unicodePwd
					$ldapConnection.Dispose()
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Creating User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectSamAccountName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
			If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
					Add-LdapObject -LdapConnection $ldapConnection -Object $testKrbTgtObj -BinaryProps unicodePwd
					$ldapConnection.Dispose()
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Creating User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectSamAccountName' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  --> TEST/BOGUS KrbTgt Account [$testKrbTgtObjectDN] FAILED TO BE CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}

		# Check The The Test/Bogus KrbTgt Account Exists And Was created In AD
		$testKrbTgtObject = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
				$testKrbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectClass=user)(name=$testKrbTgtObjectName))"
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'name=$testKrbTgtObjectName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
				$testKrbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectClass=user)(name=$testKrbTgtObjectName))"
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'name=$testKrbTgtObjectName' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		If ($testKrbTgtObject) {
			$testKrbTgtObjectDN = $null
			$testKrbTgtObjectDN = $testKrbTgtObject.DistinguishedName
			writeLog -dataToLog "  --> New TEST/BOGUS KrbTgt Account [$testKrbTgtObjectDN] CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
			$updateMembership = $true
		} Else {
			$updateMembership = $false
		}
	}

	If ($testKrbTgtObject -And $updateMembership -eq $true) {
		# If The Test/Bogus KrbTgt Account Already Exists In AD
		# If The Test/Bogus KrbTgt Account Is Not Yet A Member Of The Specified AD Group, Then Add It As A Member
		If ($krbTgtUse -eq "RWDC") {
			# If The Test/Bogus KrbTgt Account Is Used By RWDCs
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
					$deniedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectClass=group)(sAMAccountName=$deniedRODCPwdReplGroupObjectName))" -AdditionalProperties @('member')
					$deniedRODCPwdReplGroupObject.member = $testKrbTgtObjectDN
					Edit-LdapObject -LdapConnection $ldapConnection -Object $deniedRODCPwdReplGroupObject -Mode Add
					$ldapConnection.Dispose()
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Adding Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$deniedRODCPwdReplGroupObjectName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
			If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
					$deniedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectClass=group)(sAMAccountName=$deniedRODCPwdReplGroupObjectName))" -AdditionalProperties @('member')
					$deniedRODCPwdReplGroupObject.member = $testKrbTgtObjectDN
					Edit-LdapObject -LdapConnection $ldapConnection -Object $deniedRODCPwdReplGroupObject -Mode Add
					$ldapConnection.Dispose()
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Retrieving Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$deniedRODCPwdReplGroupObjectName' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
			writeLog -dataToLog "  --> TEST/BOGUS KrbTgt Account [$testKrbTgtObjectDN] ADDED AS MEMBER OF [$deniedRODCPwdReplGroupObjectName]!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		}

		If ($krbTgtUse -eq "RODC") {
			# If The Test/Bogus KrbTgt Account Is Used By RODCs
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
					$allowedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectClass=group)(sAMAccountName=$allowedRODCPwdReplGroupObjectName))" -AdditionalProperties @('member')
					$allowedRODCPwdReplGroupObject.member = $testKrbTgtObjectDN
					Edit-LdapObject -LdapConnection $ldapConnection -Object $allowedRODCPwdReplGroupObject -Mode Add
					$ldapConnection.Dispose()
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Adding Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$allowedRODCPwdReplGroupObjectName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
			If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
					$allowedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectClass=group)(sAMAccountName=$allowedRODCPwdReplGroupObjectName))" -AdditionalProperties @('member')
					$allowedRODCPwdReplGroupObject.member = $testKrbTgtObjectDN
					Edit-LdapObject -LdapConnection $ldapConnection -Object $allowedRODCPwdReplGroupObject -Mode Add
					$ldapConnection.Dispose()
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Retrieving Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$allowedRODCPwdReplGroupObjectName' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
			writeLog -dataToLog "  --> TEST/BOGUS KrbTgt Account [$testKrbTgtObjectDN] ADDED AS MEMBER OF [$allowedRODCPwdReplGroupObjectName]!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		}
	} ElseIf ($testKrbTgtObject -And $updateMembership -eq $false) {
		# If The Test/Bogus KrbTgt Account Is Already A Member Of The Specified AD Group
		If ($krbTgtUse -eq "RWDC") {
			writeLog -dataToLog "  --> TEST/BOGUS KrbTgt Account [$testKrbTgtObjectDN] ALREADY MEMBER OF [$deniedRODCPwdReplGroupObjectName]!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		}
		If ($krbTgtUse -eq "RODC") {
			writeLog -dataToLog "  --> TEST/BOGUS KrbTgt Account [$testKrbTgtObjectDN] ALREADY MEMBER OF [$allowedRODCPwdReplGroupObjectName]!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		}
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	}
}

### FUNCTION: Delete TEST/BOGUS KrbTgt Accounts
Function deleteTestKrbTgtADAccount {
	Param (
		[string]$targetedADdomainRWDCFQDN,
		[string]$krbTgtSamAccountName,
		[bool]$localADforest,
		[PSCredential]$adminCrds
	)

	# Check If The Test/Bogus KrbTgt Account Exists In AD
	$testKrbTgtObject = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
			$testKrbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))"
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}

	}
	If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
			$testKrbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))"
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object 'sAMAccountName=$krbTgtSamAccountName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ($testKrbTgtObject) {
		# If It Does Exist In AD
		$testKrbTgtObjectDN = $null
		$testKrbTgtObjectDN = $testKrbTgtObject.DistinguishedName
		writeLog -dataToLog "  --> RWDC To Delete Object On..............: '$targetedADdomainRWDCFQDN'"
		writeLog -dataToLog "  --> TEST/BOGUS KrbTgt Account DN..........: '$testKrbTgtObjectDN'"
		writeLog -dataToLog ""
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
				Remove-LdapObject -LdapConnection $ldapConnection -Object $testKrbTgtObjectDN
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Deleting User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
				Remove-LdapObject -LdapConnection $ldapConnection -Object $testKrbTgtObjectDN
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Deleting User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		$testKrbTgtObject = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
				$testKrbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$testKrbTgtObjectDN)"
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$testKrbTgtObjectDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
				$testKrbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(distinguishedName=$testKrbTgtObjectDN)"
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$testKrbTgtObjectDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		If (!$testKrbTgtObject) {
			writeLog -dataToLog "  --> TEST/BOGUS KrbTgt Account [$testKrbTgtObjectDN] DELETED on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		} Else {
			writeLog -dataToLog "  --> TEST/BOGUS KrbTgt Account [$testKrbTgtObjectDN] FAILED TO BE DELETED on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  --> Manually delete the TEST/BOGUS KrbTgt Account [$testKrbTgtObjectDN] on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	} Else {
		# If It Does Not Exist In AD
		writeLog -dataToLog "  --> TEST/BOGUS KrbTgt Account [$krbTgtSamAccountName] DOES NOT EXIST on RWDC [$targetedADdomainRWDCFQDN]!..." -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	}
}

### FUNCTION: Start Countdown/Waiting Function With Message
Function startCountdown {
	Param (
		[Int32]$seconds,
		[string]$message = "Pausing For $seconds Seconds..."
	)

	1..$seconds | ForEach-Object {
		Write-Progress -Id 1 -Activity $message -Status "Waiting For $seconds Seconds, $($seconds - $_) Seconds Left" -PercentComplete (($_ / $seconds) * 100)
		Start-Sleep -s 1
	}
	Write-Progress -Id 1 -Activity $message -Status "Completed" -PercentComplete 100 -Completed
}

### FUNCTION: Send E-mail With Information
Function sendMailMessage {
	Param (
		[XML]$configResetKrbTgtPasswordSettings,
		[string[]]$mailAttachments,
		[string]$context

	)

	$smtpServer = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.smtpServer
	$smtpPort = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.smtpPort
	$smtpCredsType = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.smtpCredsType
	$mailSubject = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.mailSubject
	$mailPriority = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.mailPriority
	$mailBody = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.mailBody
	$mailBody = $mailBody.Replace("REPLACE_CONTEXT", $context)
	$mailBody = $mailBody.Replace("REPLACE_AD_FOREST_FQDN", $($script:targetedADforestFQDN))
	$mailBody = $mailBody.Replace("REPLACE_AD_DOMAIN_FQDN", $($script:targetedADdomainFQDN))
	$mailBody = $mailBody.Replace("REPLACE_NUM_KRBTGT_ACCNTS_PROCESSED_TOTAL", $($script:numAccntsProcessedTOTAL))
	$mailBody = $mailBody.Replace("REPLACE_NUM_KRBTGT_ACCNTS_RESET_CANDIDATE_YES", $($script:numAccntsResetCandidateYES))
	$mailBody = $mailBody.Replace("REPLACE_NUM_KRBTGT_ACCNTS_RESET_CANDIDATE_NO", $($script:numAccntsResetCandidateNO))
	$mailBody = $mailBody.Replace("REPLACE_NUM_KRBTGT_ACCNTS_RESET_SUCCESS", $($script:numAccntsResetSUCCESS))
	$mailBody = $mailBody.Replace("REPLACE_NUM_KRBTGT_ACCNTS_RESET_FAIL", $($script:numAccntsResetFAIL))
	$mailBody = $mailBody.Replace("REPLACE_NUM_KRBTGT_ACCNTS_RESET_SKIP", $($script:numAccntsResetSKIP))
	$mailBody = $mailBody.Replace("REPLACE_NUM_KRBTGT_ACCNTS_RESET_ANOMALY", $($script:numAccntsResetANOMALY))
	$mailFromSender = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.mailFromSender
	$mailToRecipients = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.mailToRecipients.mailToRecipient
	$mailCcRecipients = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.mailCcRecipients.mailCcRecipient

	If ($smtpCredsType.ToUpper() -eq "EIDAPPCLIENTID_SECRET" -Or $smtpCredsType.ToUpper() -eq "EIDAPPCLIENTID_CERTIFICATE") {
		$tenantFQDN = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.smtpCredsUserName.Split("\")[0]
		$appOrClientId = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.smtpCredsUserName.Split("\")[1]
		$scope = "https://graph.microsoft.com/.default"
		$endpointUrl = "https://login.microsoftonline.com/$tenantFQDN/oauth2/v2.0/token"

		If ($smtpCredsType.ToUpper() -eq "EIDAPPCLIENTID_SECRET") {
			$appOrClientSecret = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.smtpCredsPassword

			# Request Body Hash Table Parameters
			$requestBody = @{
				client_id     = $appOrClientId
				client_secret = $appOrClientSecret
				scope         = $scope
				grant_type    = "client_credentials"
			}

			# Splat The Parameters For Token Request
			$tokenRequestParameters = @{
				ContentType = "application/x-www-form-urlencoded"
				Method      = "POST"
				Body        = $requestBody
				Uri         = $endpointUrl
			}
		}

		If ($smtpCredsType.ToUpper() -eq "EIDAPPCLIENTID_CERTIFICATE") {
			$subjectName = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.smtpCredsPassword
			$authNcertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$subjectName" }
			If ([string]::IsNullOrEmpty($authNcertificate)) {
				Write-Error "Certificate 'CN=$subjectName' DOES NOT Exist!"
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Certificate 'CN=$subjectName' DOES NOT Exist!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

				BREAK
			}

			# Create BASE64 Hash Of Certificate
			$authNcertificateBase64Hash = [System.Convert]::ToBase64String($authNcertificate.GetCertHash())

			# Create JWT Header
			$jwtHeader = @{
				alg = "RS256"
				typ = "JWT"
				# Use the CertificateBase64Hash and replace/strip to match web encoding of base64
				x5t = $authNcertificateBase64Hash -replace '\+', '-' -replace '/', '_' -replace '='
			}

			# Create JWT Payload
			$jwtPayLoad = @{
				# What Endpoint Is Allowed To Use This JWT
				aud = "https://login.microsoftonline.com/$tenantFQDN/oauth2/token"

				# Issuer Is The Application (Client Id)
				iss = $appOrClientId

				# JWT Subject
				sub = $appOrClientId

				# JWT ID: Random Guid
				jti = [guid]::NewGuid()

				# Not To Be Used Before
				nbf = ([DateTimeOffset](Get-Date)).ToUnixTimeSeconds()

				# Not To Be Used After, i.e. Expiration Timestamp
				exp = ([DateTimeOffset](Get-Date).AddMinutes(5)).ToUnixTimeSeconds()
			}

			# Convert Header To Base64
			$jwtHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader | ConvertTo-Json))
			$encodedHeader = [System.Convert]::ToBase64String($jwtHeaderToByte)

			# Convert Payload To Base64
			$jwtPayLoadToByte = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayload | ConvertTo-Json))
			$encodedPayload = [System.Convert]::ToBase64String($jwtPayLoadToByte)

			# Join Base64 Header And Base64 Payload With "." To Create A Valid (Unsigned) JWT
			$jwt = $encodedHeader + "." + $encodedPayload

			# Get The Private Key Object Of The Certificate
			If ($authNcertificate.HasPrivateKey -eq $true) {
				$certPrivateKey = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($authNcertificate))
			} Else {
				Write-Error "Certificate 'CN=$subjectName' DOES NOT Have A Private Key!"
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Certificate 'CN=$subjectName' DOES NOT Have A Private Key!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

				BREAK
			}

			# Define RSA signature and hashing algorithm
			$rsaPadding = [Security.Cryptography.RSASignaturePadding]::PKCS1
			$hashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

			# Create A Signature Of The JWT
			$signature = [Convert]::ToBase64String(
				$certPrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($jwt), $hashAlgorithm, $rsaPadding)
			) -replace '\+', '-' -replace '/', '_' -replace '='

			# Join The Signature To The JWT With "."
			$jwt = $jwt + "." + $signature

			# Use The Self-Generated JWT As Authorization Request Header
			$jwtRequestHeader = @{
				Authorization = "Bearer $jwt"
			}

			# Use The Self-Generated JWT As Authorization Request Body
			$jwtRequestBody = @{
				client_id             = $appOrClientId
				client_assertion      = $jwt
				client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
				scope                 = $scope
				grant_type            = "client_credentials"
			}

			# Splat The Parameters For Token Request
			$tokenRequestParameters = @{
				Uri         = $endpointUrl
				Method      = "POST"
				Headers     = $jwtRequestHeader
				Body        = $jwtRequestBody
				ContentType = "application/x-www-form-urlencoded"
				ErrorAction = "Stop"
			}
		}

		# https://stackoverflow.com/questions/69080522/send-mail-via-microsoft-graph-as-application-any-user

		# Request The Token
		Try {
			$tokenRequest = Invoke-RestMethod @tokenRequestParameters
			$sendMailContinue = $true
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Requesting Tokens From Entra ID To Send Mail Through Exchange Online..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			$sendMailContinue = $false
		}

		If ($sendMailContinue -eq $true) {
			# Send Mail Endpoint URL
			$sendMailEndpointURL = "https://graph.microsoft.com/v1.0/users/$mailFromSender/sendMail"

			# Request Header For Sending The E-mail
			$requestHeader = @{
				Authorization = "$($tokenRequest.token_type) $($tokenRequest.access_token)"
			}

			# Request Body For Sending The E-mail
			$requestBody = @(
				[PSCustomObject]@{
					message         = [PSCustomObject]@{
						importance = $mailPriority
						subject    = $mailSubject
						body       = [PSCustomObject]@{
							contentType = "HTML"
							content     = $mailBody
						}
					}
					saveToSentItems = $true
				}
			)
			If (($mailToRecipients | Measure-Object).Count -gt 0) {
				$requestBody.message | Add-Member -MemberType NoteProperty -Name toRecipients -Value @()
				$mailToRecipients | ForEach-Object {
					$requestBody.message.toRecipients += $([PSCustomObject]@{emailAddress = [PSCustomObject]@{name = $_; address = $_ } })
				}
			}
			If (($mailCcRecipients | Measure-Object).Count -gt 0 -And -not [string]::IsNullOrEmpty($mailCcRecipients)) {
				$requestBody.message | Add-Member -MemberType NoteProperty -Name ccRecipients -Value @()
				$mailCcRecipients | ForEach-Object {
					$requestBody.message.ccRecipients += $([PSCustomObject]@{emailAddress = [PSCustomObject]@{name = $_; address = $_ } })
				}
			}
			If (($mailAttachments | Measure-Object).Count -gt 0) {
				$requestBody.message | Add-Member -MemberType NoteProperty -Name attachments -Value @()
				$mailAttachments | ForEach-Object {
					If ($script:poshVersion -lt [version]"7.0") {
						$requestBody.message.attachments += $([PSCustomObject]@{"@odata.type" = "#microsoft.graph.fileAttachment"; name = $(Split-Path $_ -leaf); contentType = "text/plain"; contentBytes = $([System.Convert]::ToBase64String($(Get-Content -Path $_ -Encoding Byte))) })
					} Else {
						$requestBody.message.attachments += $([PSCustomObject]@{"@odata.type" = "#microsoft.graph.fileAttachment"; name = $(Split-Path $_ -leaf); contentType = "text/plain"; contentBytes = $([System.Convert]::ToBase64String($(Get-Content -Path $_ -AsByteStream))) })
					}
				}
			}

			Try {
				Invoke-RestMethod -Headers $requestHeader -Uri $sendMailEndpointURL -Method POST -Body $($requestBody | ConvertTo-Json -Depth 99) -ContentType "application/json" -ErrorAction Stop
			} Catch {
				Write-Host ""
				Write-Host "Error Sending Mail Through Exchange Online..." -ForeGroundColor Red
				Write-Host ""
				Write-Host "Exception Type......: $($_.Exception.GetType().FullName)" -ForeGroundColor Red
				Write-Host ""
				Write-Host "Exception Message...: $($_.Exception.Message)" -ForeGroundColor Red
				Write-Host ""
				Write-Host "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -ForeGroundColor Red
				Write-Host ""
			}
		}
	}

	If ($smtpCredsType.ToUpper() -eq "USERNAME_PASSWORD") {
		$smtpCrdsUsrName = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.smtpCredsUserName
		$smtpCrdsPasswd = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.smtpCredsPassword

		# Create Mail Message Object
		$mail = New-Object System.Net.Mail.MailMessage
		$mail.From = $mailFromSender
		$mail.Sender = $mailFromSender
		If ($($mailToRecipients | Measure-Object).Count -gt 0) {
			$mailToRecipients | ForEach-Object {
				$mail.To.Add($_)
			}
		}
		If (($mailCcRecipients | Measure-Object).Count -gt 0 -And -not [string]::IsNullOrEmpty($mailCcRecipients)) {
			$mailCcRecipients | ForEach-Object {
				$mail.CC.Add($_)
			}
		}
		$mail.Subject = $mailSubject
		$mail.Priority = $mailPriority
		$mail.Body = $mailBody
		$mail.IsBodyHtml = $true
		If ($($mailAttachments | Measure-Object).Count -gt 0) {
			$mailAttachments | ForEach-Object {
				$mail.Attachments.Add($_)
			}
		}

		# Create SMTP-Client To Send Mail Message
		$smtp = New-Object System.Net.Mail.SmtpClient($smtpServer, $smtpPort)
		If ($smtpPort -eq 465 -Or $smtpPort -eq 587) {
			$smtp.EnableSsl = $true
		} Else {
			$smtp.EnableSsl = $false
		}
		$smtp.Credentials = New-Object System.Net.NetworkCredential($smtpCrdsUsrName, $(ConvertTo-SecureString $smtpCrdsPasswd -AsPlainText -Force))


		# Finally Send Mail
		Try {
			$smtp.Send($mail)
		} Catch {
			Write-Host ""
			Write-Host "Error Sending Mail Through Provider..." -ForeGroundColor Red
			Write-Host ""
			Write-Host "Exception Type......: $($_.Exception.GetType().FullName)" -ForeGroundColor Red
			Write-Host ""
			Write-Host "Exception Message...: $($_.Exception.Message)" -ForeGroundColor Red
			Write-Host ""
			Write-Host "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -ForeGroundColor Red
			Write-Host ""
		}
	}
}

### FUNCTION: Send Mail With Zip File As Attachment
Function sendMailWithAttachmentAndDisplayOutput  {
	Param (
		[string[]]$mailToRecipients,
		[string[]]$mailCcRecipients,
		[string]$logFilePath,
		[string]$zipFilePath,
		[string]$context
	)

	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	If ($($mailToRecipients | Measure-Object).Count -gt 0) {
		$mailToRecipients | ForEach-Object {
			writeLog -dataToLog "  - TO: '$($_)'..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If (($mailCcRecipients | Measure-Object).Count -gt 0 -And -not [string]::IsNullOrEmpty($mailCcRecipients)) {
		$mailCcRecipients | ForEach-Object {
			writeLog -dataToLog "  - CC: '$($_)'..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

	$compressionParameters = @{
		Path             = $logFilePath # Multiple Files/Folders/Wildcards Can Be Added Here In Comma-Separated List
		CompressionLevel = "Optimal"
		DestinationPath  = $zipFilePath
	}
	Compress-Archive @compressionParameters

	$mailAttachments = [System.Collections.Generic.List[Object]]::New()
	$mailAttachments.Add($zipFilePath)

	sendMailMessage -configResetKrbTgtPasswordSettings $script:configResetKrbTgtPasswordSettings -mailAttachments $mailAttachments -context $context
	Start-Sleep -s 3
	Try {
		Remove-Item $zipFilePath -Force -ErrorAction STOP
		writeLog -dataToLog "Zip File Deleted............................: '$zipFilePath'"
		writeLog -dataToLog ""
	} Catch {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Failed To Delete The File '$zipFilePath'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	}
}

### FUNCTION: Get Server Names
Function getServerNames {
	$localComputerName = $(Get-CimInstance -Class Win32_ComputerSystem).Name						# [0] NetBIOS Computer Name
	$fqdnADDomainOfComputer = $(Get-CimInstance -Class Win32_ComputerSystem).Domain					# [1] FQDN Of The AD Domain The Computer Is A Member Of
	$fqdnComputerInADDomain = $localComputerName + "." + $fqdnADDomainOfComputer					# [2] FQDN Of The Computer In The AD (!) Domain
	$fqdnComputerInDNS = [System.Net.Dns]::GetHostByName($localComputerName).HostName				# [3] FQDN Of The Computer In The DNS (!) Domain
	$fqdnDnsDomainOfComputer = $fqdnComputerInDNS.SubString($fqdnComputerInDNS.IndexOf(".") + 1)	# [4] FQDN Of The Dns Domain The Computer Is A Part Of

	Return $localComputerName, $fqdnADDomainOfComputer, $fqdnComputerInADDomain, $fqdnComputerInDNS, $fqdnDnsDomainOfComputer
}

### FUNCTION: BuildAttribute Schema Mapping Tables
Function buildAttributeSchemaMappingTables {
	Param (
		[string]$targetedADdomainRWDCFQDN,
		[bool]$localADforest,
		[PSCredential]$adminCrds
	)

	# Create Mapping HashTable Between lDAPDisplayName And schemaIDGUID, And back
	$script:mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT = @{}
	$script:mappingTable_SCHEMA_schemaIDGUID_lDAPDisplayNameHT = @{}
	$script:mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT["All"] = "00000000-0000-0000-0000-000000000000"
	$script:mappingTable_SCHEMA_schemaIDGUID_lDAPDisplayNameHT["00000000-0000-0000-0000-000000000000"] = "All"

	# Retrieve The Schema lDAPDisplayName And schemaIDGUID Of Each Attribute In The AD Schema
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos
			Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADforestSchemaNCDN) -searchFilter "(schemaIDGUID=*)" -PropertiesToLoad @("lDAPDisplayName", "schemaIDGUID") -BinaryProps:@("schemaIDGUID") | ForEach-Object {
				$script:mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT[$($_.lDAPDisplayName)] = $(([GUID]$_.schemaIDGUID).Guid)
				$script:mappingTable_SCHEMA_schemaIDGUID_lDAPDisplayNameHT[$(([GUID]$_.schemaIDGUID).Guid)] = $($_.lDAPDisplayName)
			}
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For attributeSchema Objects..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
			Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADforestSchemaNCDN) -searchFilter "(schemaIDGUID=*)" -PropertiesToLoad @("lDAPDisplayName", "schemaIDGUID") -BinaryProps:@("schemaIDGUID") | ForEach-Object {
				$script:mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT[$($_.lDAPDisplayName)] = $(([GUID]$_.schemaIDGUID).Guid)
				$script:mappingTable_SCHEMA_schemaIDGUID_lDAPDisplayNameHT[$(([GUID]$_.schemaIDGUID).Guid)] = $($_.lDAPDisplayName)
			}
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$targetedADdomainRWDCFQDN' For attributeSchema Objects Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
}

###
# Clear The Screen
###
Clear-Host
Set-StrictMode -Version Latest

###
# Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
###
$randomNr = Get-Random -Minimum 1000 -Maximum 9999
$windowTitle = "+++ RESET KRBTGT ACCOUNT PASSWORD FOR RWDCs/RODCs +++ ($randomNr)"
$uiConfig = (Get-Host).UI.RawUI
$host.UI.RawUI.WindowTitle = $windowTitle
Start-Sleep -s 1
$poshProcess = Get-Process | Where-Object { $_.MainWindowTitle -eq $windowTitle }
$poshProcessName = $poshProcess.ProcessName
$poshProcessId = $poshProcess.Id
If ($poshProcessName -eq "WindowsTerminal") {
	Get-Process -Id $poshProcessId | Set-Window -X 1 -Y 25 -Width 2000 -Height 800 # -Passthru
} ElseIf ($poshProcessName -like "*powershell_ise*") {
	Write-Host ""
	Write-Host "The Script Is Being Executed From A PowerShell_ISE Command Prompt Window, Which IS NOT Supported!..." -ForeGroundColor Red
	Write-Host "Please Rerun The Script From A PowerShell Command Prompt Window!..." -ForeGroundColor Red
	Write-Host ""
	Write-Host "Aborting Script..." -ForeGroundColor Red
	Write-Host ""

	BREAK
} Else {
	$uiConfig.ForegroundColor = "Yellow"
	$uiConfigBufferSize = $uiConfig.BufferSize
	$uiConfigBufferSize.Width = 400
	$uiConfigBufferSize.Height = 9999
	$uiConfigScreenSizeMax = $uiConfig.MaxPhysicalWindowSize
	$uiConfigScreenSizeMaxWidth = $uiConfigScreenSizeMax.Width
	$uiConfigScreenSizeMaxHeight = $uiConfigScreenSizeMax.Height
	$uiConfigScreenSize = $uiConfig.WindowSize
	If ($uiConfigScreenSizeMaxWidth -lt 240) {
		$uiConfigScreenSize.Width = $uiConfigScreenSizeMaxWidth
	} Else {
		$uiConfigScreenSize.Width = 240
	}
	If ($uiConfigScreenSizeMaxHeight -lt 75) {
		$uiConfigScreenSize.Height = $uiConfigScreenSizeMaxHeight - 5
	} Else {
		$uiConfigScreenSize.Height = 75
	}
	$uiConfig.BufferSize = $uiConfigBufferSize
	$uiConfig.WindowSize = $uiConfigScreenSize
}

###
# Definition Of Some Constants
###
$execDateTime = Get-Date
$execDateTimeYEAR = $execDateTime.Year
$execDateTimeMONTH = $execDateTime.Month
$execDateTimeDAY = $execDateTime.Day
$execDateTimeHOUR = $execDateTime.Hour
$execDateTimeMINUTE = $execDateTime.Minute
$execDateTimeSECOND = $execDateTime.Second
$execDateTimeCustom = [STRING]$execDateTimeYEAR + "-" + $("{0:D2}" -f $execDateTimeMONTH) + "-" + $("{0:D2}" -f $execDateTimeDAY) + "_" + $("{0:D2}" -f $execDateTimeHOUR) + "." + $("{0:D2}" -f $execDateTimeMINUTE) + "." + $("{0:D2}" -f $execDateTimeSECOND)
$execDateTimeCustom1 = [STRING]$execDateTimeYEAR + $("{0:D2}" -f $execDateTimeMONTH) + $("{0:D2}" -f $execDateTimeDAY) + $("{0:D2}" -f $execDateTimeHOUR) + $("{0:D2}" -f $execDateTimeMINUTE) + $("{0:D2}" -f $execDateTimeSECOND)
$adRunningUserAccount = $ENV:USERDOMAIN + "\" + $ENV:USERNAME
$scriptFullPath = $MyInvocation.MyCommand.Definition
$currentScriptCmdLineUsed = $MyInvocation.Line
$currentScriptFolderPath = Split-Path $scriptFullPath
$currentScriptFileName = Split-Path $scriptFullPath -Leaf
If ($currentScriptCmdLineUsed -match ".*\:\\.*") {
	$currentScriptCmdLineUsedElevated = $currentScriptCmdLineUsed
}
If ($currentScriptCmdLineUsed -match "\.\\.*") {
	$currentScriptCmdLineUsedElevated = Join-Path $currentScriptFolderPath $($currentScriptCmdLineUsed.Replace(".\", ""))
}
$getServerNames = getServerNames
$localComputerName = $getServerNames[0]			# [0] NetBIOS Computer Name
$fqdnADDomainOfComputer = $getServerNames[1]	# [1] FQDN Of The AD Domain The Computer Is A Member Of
$fqdnComputerInADDomain = $getServerNames[2]	# [2] FQDN Of The Computer In The AD (!) Domain
$fqdnComputerInDNS = $getServerNames[3]			# [3] FQDN Of The Computer In The DNS (!) Domain
$fqdnDnsDomainOfComputer = $getServerNames[4]	# [4] FQDN Of The Dns Domain The Computer Is A Part Of
$fqdnADDomainOfComputerContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $fqdnADDomainOfComputer)
$fqdnADForestOfComputer = ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($fqdnADDomainOfComputerContext)).Forest.Name
[string]$logFilePath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_" + $currentScriptFileName.Replace(".ps1", ".log"))
[string]$zipFilePath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_" + $currentScriptFileName.Replace(".ps1", ".zip"))
$argsCount = $PSBoundParameters.Count
[string]$scriptXMLConfigFilePath = Join-Path $currentScriptFolderPath $currentScriptFileName.Replace(".ps1", ".xml")
$script:poshVersion = $psVersionTable.PSVersion
$script:numAccntsProcessedTOTAL = 0							# Counter For TOTAL Accounts Processed
$script:numAccntsResetCandidateYES = 0						# Counter For CANDIDATE Accounts Processed For Password Reset
$script:numAccntsResetCandidateNO = 0						# Counter For CANDIDATE Accounts NOT Processed For Password Reset
$script:numAccntsResetSUCCESS = 0							# Counter For Accounts Processed For SUCCESSFUL Password Reset
$script:numAccntsResetFAIL = 0								# Counter For Accounts Processed For FAILED Password Reset
$script:numAccntsResetSKIP = 0								# Counter For Accounts Processed For SKIPPED Password Reset
$script:numAccntsResetANOMALY = 0							# Counter For Accounts Processed For Which An Anomaly Was Detected
$script:maxTgtLifetimeHrs = 10								# The Value For The Max Tgt Lifetime In Hours To Be Assumed As DEFAULT (Within An AD Domain This IS The Default!)
$script:maxClockSkewMins = 5								# The Value For The Max Clock Skew In Minutes To Be Assumed As DEFAULT (Within An AD Domain This IS The Default!)
$script:passwordResetRoutineOverlapPeriodInMinutes = 120	# The Value The Overlap Period When Executing The Password Reset Routine

### Read The XML Config File
If (Test-Path $scriptXMLConfigFilePath) {

	[XML]$script:configResetKrbTgtPasswordSettings = Get-Content $scriptXMLConfigFilePath

	$useXMLConfigFileSettings = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.useXMLConfigFileSettings
	$script:resetRoutineEnabled = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.resetRoutineEnabled
	$sendMailEnabled = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.sendMailEnabled

	If ($useXMLConfigFileSettings.ToUpper() -ne "TRUE" -And $execResetRoutine) {
		writeLog -dataToLog ""
		writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "  > 'useXMLConfigFileSettings'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""

		BREAK
	}

	If ($useXMLConfigFileSettings.ToUpper() -ne "TRUE" -And $sendMailWithLogFile) {
		writeLog -dataToLog ""
		writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "  > 'useXMLConfigFileSettings'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""

		BREAK
	}

	If ($useXMLConfigFileSettings.ToUpper() -eq "TRUE") {
		$connectionParametersSource = "XML Config File '$scriptXMLConfigFilePath'"

		$connectionTimeout = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.connectionTimeoutInMilliSeconds
		If ($connectionTimeout -notmatch "^\d+$") {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'connectionTimeoutInMilliSeconds'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}

		$goldenTicketMonitorWaitingIntervalBetweenRuns = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.goldenTicketMonitorWaitingIntervalBetweenRunsInSeconds
		If ($goldenTicketMonitorWaitingIntervalBetweenRuns -notmatch "^\d+$") {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'goldenTicketMonitorWaitingIntervalBetweenRunsInSeconds'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}

		$goldenTicketMonitoringPeriod = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.goldenTicketMonitoringPeriodInSeconds
		If ($goldenTicketMonitoringPeriod -notmatch "^\d+$") {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'goldenTicketMonitoringPeriodInSeconds'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}

		If ($($script:resetRoutineEnabled).ToUpper() -ne "TRUE" -And $execResetRoutine) {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'resetRoutineEnabled'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}

		If ($($script:resetRoutineEnabled).ToUpper() -eq "TRUE") {
			$resetRoutineFirstResetIntervalInDays = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.resetRoutineFirstResetIntervalInDays
			If ($resetRoutineFirstResetIntervalInDays -notmatch "^\d+$" -Or $resetRoutineFirstResetIntervalInDays -lt 3) {
				writeLog -dataToLog ""
				writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'resetRoutineFirstResetIntervalInDays'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""

				BREAK
			}

			$resetRoutineSecondResetIntervalInDays = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.resetRoutineSecondResetIntervalInDays
			If ($resetRoutineSecondResetIntervalInDays -notmatch "^\d+$" -Or $resetRoutineSecondResetIntervalInDays -lt 1) {
				writeLog -dataToLog ""
				writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'resetRoutineSecondResetIntervalInDays'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""

				BREAK
			}

			If ($resetRoutineFirstResetIntervalInDays -le $resetRoutineSecondResetIntervalInDays) {
				writeLog -dataToLog ""
				writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'resetRoutineFirstResetIntervalInDays'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'resetRoutineSecondResetIntervalInDays'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "The Value For 'resetRoutineFirstResetIntervalInDays' Must Be At Least 1 Day More Than 'resetRoutineSecondResetIntervalInDays'" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""

				BREAK
			}

			$script:resetRoutineAttributeForResetDateAction1 = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.resetRoutineAttributeForResetDateAction1
			If ($($script:resetRoutineAttributeForResetDateAction1) -notmatch "^[a-zA-Z0-9_-]{0,}$") {
				writeLog -dataToLog ""
				writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'resetRoutineAttributeForResetDateAction1'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""

				BREAK
			}

			$script:resetRoutineAttributeForResetDateAction2 = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.resetRoutineAttributeForResetDateAction2
			If ($($script:resetRoutineAttributeForResetDateAction2) -notmatch "^[a-zA-Z0-9_-]{0,}$") {
				writeLog -dataToLog ""
				writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'resetRoutineAttributeForResetDateAction2'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""

				BREAK
			}

			$script:resetRoutineAttributeForResetState = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.resetRoutineAttributeForResetState
			If ($($script:resetRoutineAttributeForResetState) -notmatch "^[a-zA-Z0-9_-]{0,}$") {
				writeLog -dataToLog ""
				writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'resetRoutineAttributeForResetState'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""

				BREAK
			}
		}

		If ($sendMailEnabled.ToUpper() -ne "TRUE" -And $sendMailWithLogFile) {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'sendMailEnabled'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}

		If ($sendMailEnabled.ToUpper() -eq "TRUE") {
			$smtpServer = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.smtpServer
			If ($smtpServer -notmatch "^(([a-z0-9][a-z0-9\-]*[a-z0-9])|[a-z0-9]+\.)*([a-z]+|xn\-\-[a-z0-9]+)\.?$") {
				writeLog -dataToLog ""
				writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'smtpServer'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""

				BREAK
			}

			$smtpPort = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.smtpPort
			If ($smtpPort -notmatch "^\d+$") {
				writeLog -dataToLog ""
				writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'smtpPort'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""

				BREAK
			}

			$smtpCredsType = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.smtpCredsType
			If ($smtpCredsType.ToUpper() -ne "EIDAPPCLIENTID_SECRET" -And $smtpCredsType.ToUpper() -ne "EIDAPPCLIENTID_CERTIFICATE" -And $smtpCredsType.ToUpper() -ne "USERNAME_PASSWORD") {
				writeLog -dataToLog ""
				writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'smtpCredsType'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""

				BREAK
			}

			$smtpCrdsUsrName = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.smtpCredsUserName
			If ($smtpCrdsUsrName.ToUpper() -eq "REPLACE_ME_SEE_EXAMPLES") {
				writeLog -dataToLog ""
				writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'smtpCredsUserName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""

				BREAK
			}

			$mailSubject = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.mailSubject
			If ($mailSubject.ToUpper() -eq "REPLACE_ME") {
				writeLog -dataToLog ""
				writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'mailSubject'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""

				BREAK
			}

			$mailPriority = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.mailPriority
			If ($mailPriority.ToUpper() -ne "LOW" -And $mailPriority.ToUpper() -ne "NORMAL" -And $mailPriority.ToUpper() -ne "HIGH") {
				writeLog -dataToLog ""
				writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'mailPriority'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""

				BREAK
			}

			$mailFromSender = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.mailFromSender
			If ($mailFromSender -notmatch "^[\w-\.]+@([\w-]+\.)+[\w-]{2,6}$") {
				writeLog -dataToLog ""
				writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  > 'mailFromSender'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""

				BREAK
			}

			$mailToRecipients = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.mailToRecipients.mailToRecipient
			$mailToRecipients | ForEach-Object {
				If ([string]::IsNullOrEmpty($_) -Or $_ -notmatch "^[\w-\.]+@([\w-]+\.)+[\w-]{2,6}$") {
					writeLog -dataToLog ""
					writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "  > 'mailToRecipients.mailToRecipient'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog ""
					writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog ""

					BREAK
				}
			}

			$mailCcRecipients = $configResetKrbTgtPasswordSettings.resetKrbTgtPassword.mailCcRecipients.mailCcRecipient
			$mailCcRecipients | ForEach-Object {
				If (-not [string]::IsNullOrEmpty($_) -And $_ -notmatch "^[\w-\.]+@([\w-]+\.)+[\w-]{2,6}$") {
					writeLog -dataToLog ""
					writeLog -dataToLog "The XML Config File '$scriptXMLConfigFilePath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "  > 'mailCcRecipients.mailCcRecipient'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog ""
					writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog ""

					BREAK
				}
			}
		}
	} Else {
		$connectionParametersSource = "Default Values In Script - XML Config File Found, But Disabled"

		# XML Config File Was Found, But Its Usage Is Disabled => Using Default Values In Script
		$connectionTimeout = 500										# When Checking If The Host Is Reachable Over Certain Port. This Is The Timeout In Milliseconds
		$goldenTicketMonitorWaitingIntervalBetweenRuns = 3600 # 1 Hour	# The Waiting Interval Between Each Run When Running Mode Of Operation 7. This Is The Interval In Seconds
		$goldenTicketMonitoringPeriod = 172800 # 2 Days					# The Duration The Script Monitors For Suspicious Kerberos Tickets Requests When Running Mode Of Operation 7. This Is The Duration In Seconds

		$script:resetRoutineEnabled = "FALSE"							# Because There IS NO XML Config File, There Are No Reset Routine Related Parameters To Use

		$sendMailEnabled = "FALSE"										# Because There IS NO XML Config File, There Are No Mail Related Parameters To Use
	}
} Else {
	$connectionParametersSource = "Default Values In Script - No XML Config File Found"

	# No XML Config File Was Found => Using Default Values In Script
	$connectionTimeout = 500										# When Checking If The Host Is Reachable Over Certain Port. This Is The Timeout In Milliseconds
	$goldenTicketMonitorWaitingIntervalBetweenRuns = 3600 # 1 Hour	# The Waiting Interval Between Each Run When Running Mode Of Operation 7. This Is The Interval In Seconds
	$goldenTicketMonitoringPeriod = 172800 # 2 Days					# The Duration The Script Monitors For Suspicious Kerberos Tickets Requests When Running Mode Of Operation 7. This Is The Duration In Seconds

	$script:resetRoutineEnabled = "FALSE"							# Because There IS NO XML Config File, There Are No Reset Routine Related Parameters To Use

	$sendMailEnabled = "FALSE"										# Because There IS NO XML Config File, There Are No Mail Related Parameters To Use
}

###
# Loading Any Applicable/Required Libraries
###
Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop

###
# Execute Any Additional Actions Required For The Script To Run Successfully
###
# N.A.

###
# Start Of Script
###
### Presentation Of Script Header
writeLog -dataToLog ""
writeLog -dataToLog "                                          **********************************************************" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *  --> Reset KrbTgt Account Password For RWDCs/RODCs <-- *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *     Re-Written By: Jorge de Almeida Pinto [MVP-EMS]    *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *            BLOG: Jorge's Quest For Knowledge           *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *   (URL: http://jorgequestforknowledge.wordpress.com/)  *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                    $version                    *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          **********************************************************" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

# SOURCE: http://patorjk.com/software/taag/#p=display&f=Graffiti&t=KrbTGT%20Password%20Reset
writeLog -dataToLog " ____  __.     ___. ______________________________ __________                                               .___ __________                      __" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "|    |/ _|_____\_ |_\__    ___/  _____/\__    ___/ \______   \_____    ______ ________  _  _____________  __| _/ \______   \ ____   ______ _____/  |" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "|      < \_  __ \ __ \|    | /   \  ___  |    |     |     ___/\__  \  /  ___//  ___/\ \/ \/ /  _ \_  __ \/ __ |   |       _// __ \ /  ___// __ \   __\" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "|    |  \ |  | \/ \_\ \    | \    \_\  \ |    |     |    |     / __ \_\___ \ \___ \  \     (  <_> )  | \/ /_/ |   |    |   \  ___/ \___ \\  ___/|  |" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "|____|__ \|__|  |___  /____|  \______  / |____|     |____|    (____  /____  >____  >  \/\_/ \____/|__|  \____ |   |____|_  /\___  >____  >\___  >__|" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "        \/          \/               \/                            \/     \/     \/                          \/          \/     \/     \/     \/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

# http://patorjk.com/software/taag/#p=display&f=Graffiti&t=Provided%20By%20IAMTEC
writeLog -dataToLog "           __________                    .__    .___         .___ __________         .___   _____      ____________________________________" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "           \______   \_______  _______  _|__| __| _/____   __| _/ \______   \___.__. |   | /  _  \    /     \__    ___/\_   _____/\_   ___ \" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "            |     ___/\_  __ \/  _ \  \/ /  |/ __ |/ __ \ / __ |   |    |  _<   |  | |   |/  /_\  \  /  \ /  \|    |    |    __)_ /    \  \/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "            |    |     |  | \(  <_> )   /|  / /_/ \  ___// /_/ |   |    |   \\___  | |   /    |    \/    Y    \    |    |        \\     \____" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "            |____|     |__|   \____/ \_/ |__\____ |\___  >____ |   |______  // ____| |___\____|__  /\____|__  /____|   /_______  / \______  /" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                                 \/    \/     \/          \/ \/                  \/         \/                 \/         \/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

###
# Script Details
###
### Logging Where The Script Is Being Executed From
writeLog -dataToLog ""
writeLog -dataToLog "Local Computer Name...................: $localComputerName"
writeLog -dataToLog "FQDN AD Domain Of Computer............: $fqdnADDomainOfComputer"
writeLog -dataToLog "FQDN Computer In AD Domain............: $fqdnComputerInADDomain"
writeLog -dataToLog "FQDN Computer In DNS..................: $fqdnComputerInDNS"
writeLog -dataToLog "FQDN DNS Domain Of Computer...........: $fqdnDnsDomainOfComputer"
writeLog -dataToLog "Running/Execution User Account........: $adRunningUserAccount"

writeLog -dataToLog ""
If ($argsCount -ge 1) {
	writeLog -dataToLog "Arguments Used........................:"
	$PSBoundParameters.Keys | ForEach-Object {
		writeLog -dataToLog " - Argument...........................: $($_.PadRight(35,' ')) = $($PSBoundParameters[$_])"
	}
	writeLog -dataToLog ""
}

writeLog -dataToLog "Source Of Connection Parameters.......: $connectionParametersSource"
writeLog -dataToLog ""
writeLog -dataToLog "Configuration XML.Options.............:"
writeLog -dataToLog " - Use XML Config Settings............: $useXMLConfigFileSettings"
writeLog -dataToLog " - Connection Timeout.................: $connectionTimeout Milliseconds"
writeLog -dataToLog " - Reset Routine Enabled..............: $($script:resetRoutineEnabled)"
If ($execResetRoutine -And $($script:resetRoutineEnabled).ToUpper() -eq "TRUE") {
	writeLog -dataToLog " - Reset Routine 1st Reset Interval...: $resetRoutineFirstResetIntervalInDays Days"
	writeLog -dataToLog " - Reset Routine 2nd Reset Interval...: $resetRoutineSecondResetIntervalInDays Days"
	writeLog -dataToLog " - Reset Routine Attribute Reset State: $($script:resetRoutineAttributeForResetState)"
	writeLog -dataToLog " - Reset Routine Attribute Action 1...: $($script:resetRoutineAttributeForResetDateAction1)"
	writeLog -dataToLog " - Reset Routine Attribute Action 2...: $($script:resetRoutineAttributeForResetDateAction2)"
}
writeLog -dataToLog " - Golden Ticket Monitor Wait Interval: $goldenTicketMonitorWaitingIntervalBetweenRuns Seconds"
writeLog -dataToLog " - Golden Ticket Monitor Period.......: $goldenTicketMonitoringPeriod Seconds"
writeLog -dataToLog " - Send Mail..........................: $sendMailEnabled"
If ($sendMailEnabled.ToUpper() -eq "TRUE") {
	writeLog -dataToLog " - smtpServer.........................: $smtpServer"
	writeLog -dataToLog " - smtpPort...........................: $smtpPort"
	writeLog -dataToLog " - smtpCredsType......................: $smtpCredsType"
	writeLog -dataToLog " - smtpCrdsUsrName....................: $smtpCrdsUsrName"
	writeLog -dataToLog " - mailSubject........................: $mailSubject"
	writeLog -dataToLog " - mailPriority.......................: $mailPriority"
	writeLog -dataToLog " - mailFromSender.....................: $mailFromSender"
	If ($($mailToRecipients | Measure-Object).Count -gt 0) {
		writeLog -dataToLog " - mailToRecipient(s).................:"
		$mailToRecipients | ForEach-Object {
			writeLog -dataToLog "                     .................: $($_)"
		}
	}
	If (($mailCcRecipients | Measure-Object).Count -gt 0 -And -not [string]::IsNullOrEmpty($mailCcRecipients)) {
		writeLog -dataToLog " - mailCcRecipient(s).................:"
		$mailCcRecipients | ForEach-Object {
			writeLog -dataToLog "                     .................: $($_)"
		}
	}
}
writeLog -dataToLog ""

###
# Cleaning Up Old Logs
###
### Checking Elevation Status Of Current Process
writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "CLEANING UP OLD LOGS..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""
cleanUpOldLogs -folder $currentScriptFolderPath -filterName "*$($currentScriptFileName.Replace(".ps1",".log"))" -numDaysToKeep 60 -fileType "LOG"
cleanUpOldLogs -folder $currentScriptFolderPath -filterName "*$($currentScriptFileName.Replace(".ps1",".zip"))" -numDaysToKeep 10 -fileType "ZIP"
writeLog -dataToLog ""

###
# Checking Requirements
###
### Checking PowerShell Version
writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "CHECKING POWERSHELL VERSION..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""
If ($script:poshVersion -lt [version]"5.1") {
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "This script only supports PowerShell version 5.1 and higher!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

	BREAK
} Else {
	writeLog -dataToLog "PowerShell Version....................: $(($script:poshVersion).ToString())" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
}

### Checking Elevation Status Of Current Process
$testAccountIsSystemOnRWDC = testAccountIsSystemOnRWDC
$userIsSystem = $testAccountIsSystemOnRWDC[1]
If ($skipElevationCheck -eq $false) {
	writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "CHECKING ELEVATION STATUS OF CURRENT PROCESS..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""

	$elevateProcess = $false

	If ($userIsSystem -eq $false) {
		$currentElevationStatus = checkLocalElevationStatus
	} Else {
		$currentElevationStatus = "ELEVATED"
	}
	writeLog -dataToLog "Current Elevation Status..............: $currentElevationStatus" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false

	If ($currentElevationStatus -eq "NOT-ELEVATED") {
		If (!(Test-Path $($currentScriptFolderPath + "\Reset-KrbTgt-Password-For-RWDCs-And-RODCs_ELEVATION.TXT"))) {
			(Get-Date).ToString() | Out-File $($currentScriptFolderPath + "\Reset-KrbTgt-Password-For-RWDCs-And-RODCs_ELEVATION.TXT") -Force
			$elevateProcess = $true
		} Else {
			If ($(Get-Date $(Get-Content $($currentScriptFolderPath + "\Reset-KrbTgt-Password-For-RWDCs-And-RODCs_ELEVATION.TXT"))).AddSeconds(30) -lt ([DateTime]::Now)) {
				Remove-Item $($currentScriptFolderPath + "\Reset-KrbTgt-Password-For-RWDCs-And-RODCs_ELEVATION.TXT") -Force
				(Get-Date).ToString() | Out-File $($currentScriptFolderPath + "\Reset-KrbTgt-Password-For-RWDCs-And-RODCs_ELEVATION.TXT") -Force
				$elevateProcess = $true
			} Else {
				Remove-Item $($currentScriptFolderPath + "\Reset-KrbTgt-Password-For-RWDCs-And-RODCs_ELEVATION.TXT") -Force

				If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
					$context = "SCRIPT ABORT - ERROR: The elevation of the PowerShell process failed. Check the permissions of the account and the configuration of User Account Control (UAC)!"

					sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
				}

				Stop-Process -Id $PID
			}
		}
	} Else {
		If (Test-Path $($currentScriptFolderPath + "\Reset-KrbTgt-Password-For-RWDCs-And-RODCs_ELEVATION.TXT")) {
			Remove-Item $($currentScriptFolderPath + "\Reset-KrbTgt-Password-For-RWDCs-And-RODCs_ELEVATION.TXT") -Force
		}
	}

	If ($elevateProcess -eq $true) {
		$sleepInSecs = 5
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Script IS NOT Running In An Elevated PowerShell Command Prompt..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Restarting The Script Through An Elevated Command Prompt In $sleepInSecs Seconds..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		$iTimer = 0
		Do {
			writeLog -dataToLog "  > $($sleepInSecs - $iTimer)..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
			Start-Sleep -s 1
			$iTimer++
		} Until ($iTimer -eq $sleepInSecs)
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		Start-Process Powershell -Wait -Verb runAs -ArgumentList "-NoExit -Command & {Set-Location $currentScriptFolderPath;`"$currentScriptCmdLineUsedElevated`"}"
		Stop-Process -Id $PID
	}
	writeLog -dataToLog ""
}

###
# Technical Information
###
### Providing Information About What The Script Is Capable Of And How The Script Works
writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "INFORMATION REGARDING KRBTGT ACCOUNTS AND PASSWORD RESETS..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""
If ($noInfo) {
	writeLog -dataToLog "Do you want to read information about the script, its functions, its behavior and the impact? [YES | NO]: NO" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$yesOrNo = "NO"
} Else {
	writeLog -dataToLog "Do you want to read information about the script, its functions, its behavior and the impact? [YES | NO]: " -lineType "ACTION-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false
	$yesOrNo = Read-Host
	If ($yesOrNo.ToUpper() -ne "NO" -And $yesOrNo.ToUpper() -ne "N") {
		$yesOrNo = "YES"
	}
}
writeLog -dataToLog ""
writeLog -dataToLog "  --> Chosen: $yesOrNo" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""
If ($yesOrNo.ToUpper() -ne "NO" -And $yesOrNo.ToUpper() -ne "N") {
	writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "INFORMATION ABOUT THE SCRIPT, ITS FUNCTIONS AND BEHAVIOR, AND IMPACT TO THE ENVIRONMENT - PLEASE READ CAREFULLY..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog "-----" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "This PoSH script provides the following functions:" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "-----" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " - Single Password Reset for the KrbTgt account in use by RWDCs in a specific AD domain, using either TEST/BOGUS or PROD/REAL KrbTgt accounts" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " - Single Password Reset for the KrbTgt account in use by an individual RODC in a specific AD domain, using either TEST or PROD/REAL KrbTgt accounts" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * A single RODC in a specific AD domain" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * A specific list of in a specific AD domain" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * All RODCs in a specific AD domain" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " - Resetting the password/keys of the KrbTgt Account can be done for multiple reasons such as for example:" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * From a security perspective as mentioned in:" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * From an AD recovery perspective as mentioned in:" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " - For all scenarios, an informational mode, which is mode 1 with no changes" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " - For all scenarios, a simulation mode, which is mode 2 where replication is tested through the replication of a temporary canary" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     object that is created and deleted afterwards" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " - For all scenarios, a simulation mode, which is mode 3 where the password reset of the chosen TEST/BOGUS KrbTgt account is actually executed" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     and replication of it is monitored through the environment for its duration" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " - For all scenarios, a real reset mode, which is mode 4 where the password reset of the chosen PROD/REAL KrbTgt account is actually executed" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     and replication of it is monitored through the environment for its duration" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " - The creation of TEST/BOGUS KrbTgt Accounts" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " - The cleanup of previously created TEST/BOGUS KrbTgt Accounts" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "-----" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "This PoSH script has the following behavior:" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "-----" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog " - Mode 1 is INFORMATIONAL MODE..." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Safe to run at any time as there are not changes in any way!" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Analyzes the environment and check for issues that may impact mode 2, 3 or 4!" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * For the targeted AD domain, it always retrieves all RWDCs, and all RODCs if applicable." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog " - Mode 2 is SIMULATION MODE USING A TEMPORARY CANARY OBJECT..." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Also executes everything from mode 1!" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Creates the temporary canary object and, depending on the scope, it will check if it exists in the AD database of the remote DC(s)" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       (RWDC/RODC)." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * When simulating the KrbTgt account for RWDCs, the creation of the object is against the RWDC with the PDC Emulator FSMO followed" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       by the 'replicate single object' operation against every available/reachable RWDC. This is a way to estimate the total replication" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       time for mode 4, but also to test replication between DCs." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * When simulating the KrbTgt account for RODCs, the creation of the object is against the RWDC the RODC is replicating from if" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       available. If not available the creation is against the RWDC with the PDC Emulator FSMO. Either way it is followed by the 'replicate" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       single object' operation against the RODC. This is a way to estimate the total replication time for mode 4." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       the change made reached it or not." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * When performing the 'replicate single object' operation, it will always be for the full object, no matter if the remote DC is an RWDC" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       or an RODC" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog " - Mode 3 is SIMULATION MODE USING TEST/BOGUS KRBTGT ACCOUNTS..." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Also executes everything from mode 1!" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Instead of using PROD/REAL KrbTgt Account(s), it uses pre-created TEST/BOGUS KrbTgt Accounts(s) for the password reset whatif!" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * For RWDCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_TEST' (All RWDCs) (= Created when running mode 8)" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * For RODCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' (RODC Specific) (= Created when running mode 8)" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * IT DOES NOT reset the password of the TEST/BOGUS KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       RWDC." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       the change made reached it or not." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog " - Mode 4 is REAL RESET MODE USING TEST/BOGUS KRBTGT ACCOUNTS..." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Also executes everything from mode 1!" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Instead of using PROD/REAL KrbTgt Account(s), it uses pre-created TEST/BOGUS KrbTgt Accounts(s) for the password reset!" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * For RWDCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_TEST' (All RWDCs) (= Created when running mode 8)" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * For RODCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' (RODC Specific) (= Created when running mode 8)" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Resets the password of the TEST/BOGUS KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       RWDC." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * When simulating the KrbTgt account for RWDCs, the password reset is done for the TEST/BOGUS KrbTgt Accounts(s) against the RWDC with" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       the PDC Emulator FSMO followed by the 'replicate single object' operation against every available/reachable RWDC. No RODCs are involved" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       as those do not use the KrbTgt account in use by the RWDCs and also do not store/cache its password. This is a way to estimate the" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       total replication time for mode 6." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * When simulating the KrbTgt account for RODCs, the password reset is done for the TEST/BOGUS KrbTgt Accounts(s) against the RWDC the" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       RODC is replicating from if available/reachable. If not available the password reset is against the RWDC with the PDC Emulator FSMO." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       Either way it is followed by the 'replicate single object' operation against the RODC that uses that KrbTgt account. Only the RODC" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       that uses the specific KrbTgt account is checked against to see if the change has reached it, but only if the RODC is available/reachable." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       This is a way to estimate the total replication time for mode 6." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       the change made reached it or not." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * When performing the 'replicate single object' operation, it will always be for the full object if the target DC is an RWDC. If the" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       target DC is an RODC, then it will be for the partial object (secrets only)." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog " - Mode 5 is SIMULATION MODE USING PROD/REAL KRBTGT ACCOUNTS..." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Also executes everything from mode 1!" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Now it does use the PROD/REAL KrbTgt Accounts(s) for the password reset whatif!" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * For RWDCs it uses the PROD/REAL KrbTgt account 'krbtgt' (All RWDCs) (= Created when running mode 8)" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * For RODCs it uses the PROD/REAL KrbTgt account 'krbtgt_<Numeric Value>' (RODC Specific) (= Created when running mode 8)" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * IT DOES NOT reset the password of the PROD/REAL KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       RWDC." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       the change made reached it or not." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog " - Mode 6 is REAL RESET MODE USING PROD/REAL KRBTGT ACCOUNTS..." -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Also executes everything from mode 1!" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Now it does use the PROD/REAL KrbTgt Accounts(s) for the password reset!" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * For RWDCs it uses the PROD/REAL KrbTgt account 'krbtgt' (All RWDCs)" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * For RODCs it uses the PROD/REAL KrbTgt account 'krbtgt_<Numeric Value>' (RODC Specific)" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Resets the password of the PROD/REAL KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       RWDC." -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * When simulating the KrbTgt account for RWDCs, the password reset is done for the PROD/REAL KrbTgt Accounts(s) against the RWDC with" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       the PDC Emulator FSMO followed by the 'replicate single object' operation against every available/reachable RWDC. No RODCs are involved" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       as those do not use the KrbTgt account in use by the RWDCs and also do not store/cache its password. Once the replication is" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       complete, the total impact time will be displayed." -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * When simulating the KrbTgt account for RODCs, the password reset is done for the PROD/REAL KrbTgt Accounts(s) against the RWDC the" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       RODC is replicating from if available/reachable. If not available the password reset is against the RWDC with the PDC Emulator FSMO." -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       Either way it is followed by the 'replicate single object' operation against the RODC that uses that KrbTgt account. Only the RODC" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       that uses the specific KrbTgt account is checked against to see if the change has reached it, but only if the RODC is available/reachable." -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       Once the replication is complete, the total impact time will be displayed." -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       the change made reached it or not." -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * When performing the 'replicate single object' operation, it will always be for the full object if the target DC is an RWDC. If the" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       target DC is an RODC, then it will be for the partial object (secrets only)." -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog " - Mode 7 is GOLDEN TICKET MONITOR MODE BY CHECKING DOMAIN CONTROLLERS FOR EVENT ID 4769 WITH SPECIFIC ERROR CODES!.." -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Checks all scoped DCs in the AD domain for event id 4769 (Kerberos Service Ticket Operations). For every event found it checks the" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       error code to see if matches either one of the following error codes:" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * 0x6 (= KDC_ERR_C_PRINCIPAL_UNKNOWN = Client not found in Kerberos database)" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * 0x1F (= KRB_AP_ERR_BAD_INTEGRITY = Integrity check on decrypted field failed)" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * 0x40  (= KDC_ERR_INVALID_SIG = The signature is invalid)" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       More information about this event: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * When the event id 4769 is discovered, it reports the number of events found. In addition, after processing the gathered events with" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       event id 4769, it will also report the number of events that have any of the previously mentioned error codes. In addition, it exports" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       the information of the matching events to a log file, and if mailing has been configured an enabled it will mail that log file" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       which is mailed" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * More information about Golden Tickets can be found through the following links:" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * https://www.semperis.com/blog/how-to-defend-against-golden-ticket-attacks/" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * https://www.semperis.com/blog/golden-ticket-attacks-active-directory/" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * https://www.sentinelone.com/blog/mitigation-strategy-kerberos-golden-ticket-attack/" -lineType "REMARK-MOST-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog " - Mode 8 is CREATE TEST/BOGUS KrbTgt ACCOUNTS MODE..." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Creates so called TEST/BOGUS KrbTgt Account(s) to simulate the password reset with." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Has no impact on the PROD/REAL KrbTgt Account(s)." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * For RWDCs it creates (in disabled state!) the TEST/BOGUS KrbTgt account 'krbtgt_TEST' and adds it to the AD group 'Denied RODC" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       Password Replication Group'." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * For RODCs, if any in the AD domain, it creates (in disabled state!) the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' and" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       adds it to the AD group 'Allowed RODC Password Replication Group'. To determine the specific KrbTgt account in use by an RODC, the" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       script reads the attribute 'msDS-KrbTgtLink' on the RODC computer account." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * It is recommended to create the TEST/BOGUS KrbTgt Account(s) and NOT cleanup afterwards. The main reason is that every time you create" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       the accounts and then test the reset, you will always receive the 'Major Impact' warning as the password was recently set. By keeping" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       the TEST/BOGUS KrbTgt Account(s) in place (remember: disabled, with lengthy strong unknown passwords, and not high privileges at all)" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       the behavior will be the similar to the PROD/REAL KrbTgt Account(s) which makes the test more representative." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog " - Mode 9 is CLEANUP TEST/BOGUS KrbTgt ACCOUNTS MODE..." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Cleanup (delete) the so called TEST/BOGUS KrbTgt Account(s) that were used to simulate the password reset with." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * For RWDCs it deletes the TEST/BOGUS KrbTgt account 'krbtgt_TEST' if it exists." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * For RODCs, if any in the AD domain, it deletes the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' if it exists. To determine" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       the specific KrbTgt account in use by an RODC, the script reads the attribute 'msDS-KrbTgtLink' on the RODC computer account." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog " - Password Reset Routine Logic And Behavior..." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * The use of the XML configuration file must be enabled for the script to consume any of its settings." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * The Password Reset Routine feature must be enabled within the XML configuration file." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * The number of days must be defined for the 1st interval in days. The lowest value possible for THIS interval is 3." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * The number of days must be defined for the 2nd interval in days. The lowest value possible for THIS interval is 1." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * The Password Reset Routine feature must have an attribute defined that exists in the schema for USER objects to store the numeric value of the date for the 1st reset" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * The Password Reset Routine feature must have an attribute defined that exists in the schema for USER objects to store the numeric value of the date for the 2nd reset" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * The Password Reset Routine feature must have an attribute defined that exists in the schema for USER objects to store the numeric value of the state of the process" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * For the numeric values of the dates for reset has the format yyyyMMddHHmmss (e.g. 20250119231123) and this format MUST NOT be changed in any way!" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * The Process Flow...(see for examples the NOTES in the script!)" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * 1st RUN: Script runs for PWD reset" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * lastResetDate = pwdLastSet" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * state = attribute_for_state" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * If state = EMPTY" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * 1stResetDate = lastResetDate + interval_1" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * 2ndResetDate = lastResetDate + interval_1 + interval_2" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * If 1stResetDate lower or equal than TODAY OR If 2ndResetDate lower or equal than TODAY" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "             * 1stResetDate = TODAY + interval_1" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "             * 2ndResetDate = TODAY + interval_1 + interval_2" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * state = 0" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * Write 1stResetDate to attribute_for_1stResetDate" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * Write 2ndResetDate to attribute_for_2ndResetDate" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * Write state to attribute_for_state" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * No PWD RESET!" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "       * 2nd RUN: Script runs for PWD reset" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * lastResetDate = pwdLastSet" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * state = attribute_for_state" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * If state = 0" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * 1stResetDate = attribute_for_1stResetDate" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * 2ndResetDate = attribute_for_2ndResetDate" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * If 1stResetDate not empty AND If 2ndResetDate not empty AND 1stResetDate lower than 2ndResetDate AND 1stResetDate lower or equal than TODAY AND lastResetDate + kerbTGTTicketLifeTime lower than TODAY" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "             * PWD RESET!" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "             * state = 1" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "             * Write state to attribute_for_state" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * OTHERWISE, skip" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * 3rd RUN: Script runs for PWD reset" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * lastResetDate = pwdLastSet" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * state = attribute_for_state" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * If state = 1" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * 1stResetDate = attribute_for_1stResetDate" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * 2ndResetDate = attribute_for_2ndResetDate" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * If 1stResetDate not empty AND If 2ndResetDate not empty AND 1stResetDate lower than 2ndResetDate AND 2ndResetDate lower or equal than TODAY AND lastResetDate + kerbTGTTicketLifeTime lower than TODAY" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "             * PWD RESET!" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "             * state = 2" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "             * Write state to attribute_for_state" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * OTHERWISE, skip" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * State changes use the following logic" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * State change From 'EMPTY' to '0' will occur any time the script runs and the state is 'EMPTY' without any additional conditions" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * State change From '0' to '1' will occur any time the script runs and the state is '0' and only when very specific conditions are met" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * State change From '1' to '2' will occur any time the script runs and the state is '1' and only when very specific conditions are met" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * State change From '2' To 'EMPTY' will occur any time the script runs and the state is '2' without any additional conditions" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "       * ANY RUN: Script runs for PWD reset" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * lastResetDate = pwdLastSet" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * state = attribute_for_state" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * 1stResetDate = attribute_for_1stResetDate" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * 2ndResetDate = attribute_for_2ndResetDate" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * (If state not empty AND (If 1stResetDate empty OR If 2ndResetDate empty))" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           OR (If 1stResetDate not empty AND (If state empty OR If 2ndResetDate empty))" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           OR (If 2ndResetDate not empty AND (If state empty OR If 1stResetDate empty))" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           OR (If 2ndResetDate lower or equal than 1stResetDate)" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           OR (If state = 0 AND If 1stResetDate lower than ScriptExecTime AND If 2ndResetDate lower or equal than ScriptExecTime)" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           OR (If state not empty AND state not equal 0 AND state not equal 1 AND state not equal 2)" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           OR ((If state = 0 OR If state = 1 OR If state = 2) AND (If 1stResetDate notmatch regex yyyyMMddHHmmss OR 2ndResetDate notmatch regex yyyyMMddHHmmss))" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * No PWD RESET!" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * state = EMPTY" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * 1stResetDate = EMPTY" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * 2ndResetDate = EMPTY" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * Write 1stResetDate to attribute_for_1stResetDate" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * Write 2ndResetDate to attribute_for_2ndResetDate" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "           * Write state to attribute_for_state" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         * OTHERWISE, skip" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog " - ADDITIONAL INFO - BEHAVIOR..." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * If the operating system attribute of an RODC computer account does not have a value, it is determined to be unknown (not a real RODC)," -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       and therefore something else. It could for example be a Riverbed appliance in 'RODC mode'." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * The only DC that knows what the real replication partner is of an RODC, is the RODC itself. Only the RODC manages a connection object" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       (CO) that only exists in the AD database of the RODC and does not replicate out to other DCs as RODCs do not support outbound replication." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       Therefore, assuming the RODC is available, the CO is looked up in the RODC AD database and from that CO, the 'source' server is" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       determined. In case the RODC is not available or its 'source' server is not available, the RWDC with the PDC FSMO is used to reset" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       the password of the krbtgt account in use by that RODC. If the RODC is available a check will be done against its database, and if" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       not available the check is skipped." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * When using a scheduled task running as NT AUTHORITY\SYSTEM, make sure to configure that scheduled task on the RWDC with the PDC FSMO role." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       The reason for this is that NT AUTHORITY\SYSTEM, although highly privileged when running on an RWDC can only make changes against its" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       own database instance and not against a remote database instance on another RWDC! When it concerns the KrbTgt account of RODCs, and" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       when running as NT AUTHORITY\SYSTEM, instead of using the real source RWDC of the RODC, the RWDC with the PDC FSMO will be used instead" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       for the previously mentioned reason. As an additional tip, make sure the scheduled task is configured in a GPO that follows the RWDC" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       with the PDC FSMO role." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog " - ADDITIONAL INFO - OBSERVED IMPACT..." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Within an AD domain, all RWDCs use the account 'krbtgt' to encrypt/sign Kerberos tickets trusted by all RWDCs" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Within an AD domain, every RODC uses its own 'krbtgt_<Numeric Value>' account to encrypt/sign Kerberos tickets trusted by only that RODC" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       and that account is specified in the attribute 'msDS-KrbTgtLink' on the RODC computer account." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * RODCs are cryptographically isolated from other RODCs and the RWDCs, whether these are in the same AD site or not. Any Kerberos TGT/Service" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       tickets issued by an RODC are only valid against that RODC and any resource that has a secure channel with that RODC. That's why when an" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       RODC is compromised the scope of impact is only for that RODC and any resource using it, and not the complete AD domain." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Kerberos PAC validation failures: Until the new KrbTgt account password is replicated to all DCs in the domain using that KrbTgt account," -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       applications which attempt KDC PAC validation may experience KDC PAC validation failures. This is possible  when a client in one AD site" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       is accessing an application leveraging the Kerberos Authentication protocol that is in a different AD site. If that application is not a" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       trusted part of the operating system, it may attempt to validate the PAC of the client's Kerberos Service Ticket against the KDC (DC) in" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       its AD site. If the DC in its site does not yet have the new KrbTgt account password, this KDC PAC validation will fail. This will likely" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       manifest itself to the client as authentication errors for that application. Once all DCs using a specific KrbTgt account have the new" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       password some affected clients may recover gracefully and resume functioning normally. If not, rebooting the affected client(s) will" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       resolve the issue. This issue may not occur if the replication of the new KrbTgt account password is timely and successful and no" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       applications attempt KDC PAC validation against an out of sync DC during that time." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Kerberos TGS request failures: Until the new KrbTgt account password is replicated to all DCs in the domain that use that KrbTgt account," -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       a client may experience Kerberos authentication failures. This is when a client in one AD site has obtained a Kerberos Ticket Granting" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       Ticket (TGT) from an RWDC that has the new KrbTgt account password, but then subsequently attempts to obtain a Kerberos Service Ticket" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       via a TGS request against an RWDC in a different AD site. If that RWDC does not also have the new KrbTgt account password, it will not" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       be able to decrypt the client''s TGT, which will result in a TGS request failure.  This will manifest itself to the client as authenticate" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       errors. However, it should be noted that this impact is very unlikely, because it is very unlikely that a client will attempt to obtain a" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       service ticket from a different RWDC than the one from which their TGT was obtained, especially during the relatively short impact" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       duration of Mode 4." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Resetting the password of account 'krbtgt' 2x very quickly in sequence will NEGATIVELY impact both DCs and server/apps/users." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Resetting the password of account 'krbtgt' 1x, allowing AD replication to occur end-to-end, and resetting it a second time WITHIN the max" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       ticket lifetime will NEGATIVELY impact server/apps/users only." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Resetting the password of account 'krbtgt' 1x, allowing AD replication to occur end-to-end, and resetting it a second time AFTER the max" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       ticket lifetime will not impact DCs nor server/apps/users only." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Resetting the password of account 'krbtgt' 2x very quickly in sequence should only be done during forest/domain recovery (isolation) and/or" -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       a ransomware attack (taking back control)." -lineType "REMARK-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog " - RECOMMENDATIONS:" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Reset password of ALL KrbTGT account(s) periodically at least every 3 months." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * Want to reset more frequently? Please pay attention to the max kerberos ticket lifetime configured for the AD domain! The script will warn" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     	about any possible impact. If you really want to continue and still reset you will have to explicitly tell the script to do so!" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     * To automate the reset of 1 or more KrbTGT account(s), the following options exist:" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * Use a scheduled task and run the script every X days, weeks or months at the same time. Consider this the simple automation." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       * Use a scheduled task, use the Password Reset Routine and run the script every day at the same time. Configure the interval for the 1st" -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "         reset and the 2nd reset. Consider for this the more advanced automation. See the script itself for more information and examples." -lineType "REMARK-MORE-IMPORTANT" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog ""
	writeLog -dataToLog "First, read the info above, then..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Press Any Key (TWICE!) To Continue..." -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") > $null
}

###
# Loading Required PowerShell Modules
###
writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "LOADING REQUIRED POWERSHELL MODULES..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

# Try To Load The Required PowerShell Module. Abort Script If Not Available
"GroupPolicy" | ForEach-Object {
	$poshModuleState = $null
	$poshModuleState = loadPoSHModules -poshModule $_ -ignoreRemote $false
	If ($poshModuleState -eq "NotAvailable") {
		writeLog -dataToLog ""

		EXIT
	}
	writeLog -dataToLog ""
}

###
# Display And Selecting The Mode Of Operation
###
writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "SELECT THE MODE OF OPERATION..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""
writeLog -dataToLog "Which mode of operation do you want to execute?"
writeLog -dataToLog ""
writeLog -dataToLog " - 1 - Informational Mode (No Changes At All)"
writeLog -dataToLog ""
writeLog -dataToLog " - 2 - Simulation Mode | Temporary Canary Object Created To Test Replication Convergence!"
writeLog -dataToLog ""
writeLog -dataToLog " - 3 - Simulation Mode | Use TEST/BOGUS KrbTgt Accounts - No Password Reset/WhatIf Mode!"
writeLog -dataToLog ""
writeLog -dataToLog " - 4 - Real Reset Mode | Use TEST/BOGUS KrbTgt Accounts - Password Will Be Reset Once!"
writeLog -dataToLog ""
writeLog -dataToLog " - 5 - Simulation Mode | Use PROD/REAL KrbTgt Accounts - No Password Reset/WhatIf Mode!"
writeLog -dataToLog ""
writeLog -dataToLog " - 6 - Real Reset Mode | Use PROD/REAL KrbTgt Accounts - Password Will Be Reset Once!"
writeLog -dataToLog ""
writeLog -dataToLog " - 7 - Golden Ticket Monitor Mode | Checking Domain Controllers For Event ID 4769 With Specific Error Codes (EXPERIMENTAL!)"
writeLog -dataToLog ""
writeLog -dataToLog ""
writeLog -dataToLog ""
writeLog -dataToLog " - 8 - Create TEST/BOGUS KrbTgt Accounts"
writeLog -dataToLog ""
writeLog -dataToLog " - 9 - Cleanup TEST/BOGUS KrbTgt Accounts"
writeLog -dataToLog ""
writeLog -dataToLog ""
writeLog -dataToLog ""
writeLog -dataToLog " - 0 - Exit Script"
writeLog -dataToLog ""
Switch ($modeOfOperation) {
	"infoMode" { $modeOfOperationNr = 1 }
	"simulModeCanaryObject" { $modeOfOperationNr = 2 }
	"simulModeKrbTgtTestAccountsWhatIf" { $modeOfOperationNr = 3 }
	"resetModeKrbTgtTestAccountsResetOnce"	{ $modeOfOperationNr = 4 }
	"simulModeKrbTgtProdAccountsWhatIf" { $modeOfOperationNr = 5 }
	"resetModeKrbTgtProdAccountsResetOnce" { $modeOfOperationNr = 6 }
	"monitorForGoldenTicket" { $modeOfOperationNr = 7 }
	Default { $modeOfOperationNr = $null }
}
If ([string]::IsNullOrEmpty($modeOfOperationNr)) {
	writeLog -dataToLog "Please specify the mode of operation: " -lineType "ACTION-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false
	$modeOfOperationNr = Read-Host
} Else {
	writeLog -dataToLog "Please specify the mode of operation: $modeOfOperationNr" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
}
writeLog -dataToLog ""

# If Anything Else Than The Allowed/Available Non-Zero Modes, Abort The Script
If (($modeOfOperationNr -ne 1 -And $modeOfOperationNr -ne 2 -And $modeOfOperationNr -ne 3 -And $modeOfOperationNr -ne 4 -And $modeOfOperationNr -ne 5 -And $modeOfOperationNr -ne 6 -And $modeOfOperationNr -ne 7 -And $modeOfOperationNr -ne 8 -And $modeOfOperationNr -ne 9) -Or $modeOfOperationNr -notmatch "^[\d\.]+$") {
	writeLog -dataToLog "  --> Chosen mode: Mode 0 - Exit Script..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""

	EXIT
}

# If Mode 1
If ($modeOfOperationNr -eq 1) {
	writeLog -dataToLog "  --> Chosen Mode: Mode 1 - Informational Mode (No Changes At All)..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
}

# If Mode 2
If ($modeOfOperationNr -eq 2) {
	writeLog -dataToLog "  --> Chosen Mode: Mode 2 - Simulation Mode | Temporary Canary Object Created To Test Replication Convergence..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
}

# If Mode 3
If ($modeOfOperationNr -eq 3) {
	writeLog -dataToLog "  --> Chosen Mode: Mode 3 - Simulation Mode | Use TEST/BOGUS KrbTgt Accounts - No Password Reset/WhatIf Mode!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
}

# If Mode 4
If ($modeOfOperationNr -eq 4) {
	writeLog -dataToLog "  --> Chosen Mode: Mode 4 - Real Reset Mode | Use TEST/BOGUS KrbTgt Accounts - Password Will Be Reset Once!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
}

# If Mode 5
If ($modeOfOperationNr -eq 5) {
	writeLog -dataToLog "  --> Chosen Mode: Mode 5 - Simulation Mode | Use PROD/REAL KrbTgt Accounts - No Password Reset/WhatIf Mode!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
}

# If Mode 6
If ($modeOfOperationNr -eq 6) {
	writeLog -dataToLog "  --> Chosen Mode: Mode 6 - Real Reset Mode | Use PROD/REAL KrbTgt Accounts - Password Will Be Reset Once!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
}

# If Mode 7
If ($modeOfOperationNr -eq 7) {
	writeLog -dataToLog "  --> Chosen Mode: Mode 7 - Golden Ticket Monitor Mode | Checking Domain Controllers For Event ID 4769 With Specific Error Codes..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
}

# If Mode 8
If ($modeOfOperationNr -eq 8) {
	writeLog -dataToLog "  --> Chosen Mode: Mode 8 - Create TEST/BOGUS KrbTgt Accounts..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
}

# If Mode 9
If ($modeOfOperationNr -eq 9) {
	writeLog -dataToLog "  --> Chosen Mode: Mode 9 - Cleanup TEST/BOGUS KrbTgt Accounts..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
}

###
# All Modes - Selecting The Target AD Forest
###
writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "SPECIFY THE TARGET AD FOREST..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

# Ask Which AD Forest To Target
$script:targetedADforestFQDN = $targetedADforestFQDN
If ($($script:targetedADforestFQDN) -eq "") {
	writeLog -dataToLog "For the AD forest to be targeted, please provide the FQDN or press [ENTER] for the current AD forest: " -lineType "ACTION-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false
	$script:targetedADforestFQDN = Read-Host
} Else {
	writeLog -dataToLog "For the AD forest to be targeted, please provide the FQDN or press [ENTER] for the current AD forest: $($script:targetedADforestFQDN)" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
}

# If No FQDN Of An AD Domain Is Specified, Then Use The AD Domain Of The Local Computer
If ([string]::IsNullOrEmpty($($script:targetedADforestFQDN))) {
	$script:targetedADforestFQDN = $fqdnADForestOfComputer
}
writeLog -dataToLog ""
writeLog -dataToLog "  --> Selected AD Forest: '$($script:targetedADforestFQDN)'..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

# Validate The Specified AD Forest And Check A (Forest) Trust Is In Place, If Applicable
$adForestValidity = $false

# Test To See If The Forest FQDN Exists At All
If ($($script:targetedADforestFQDN) -eq $fqdnADForestOfComputer) {
	$localADforest = $true
	$adForestLocation = "Local"
} Else {
	$localADforest = $false
	$adForestLocation = "Remote"
}

Try {
	# Checking Through DNS Resolution
	writeLog -dataToLog ""
	writeLog -dataToLog "Checking Resolvability of the specified $adForestLocation AD forest '$($script:targetedADforestFQDN)' through DNS..."
	[System.Net.Dns]::GetHostEntry($($script:targetedADforestFQDN)) > $null
	$adForestValidity = $true
} Catch {
	Try {
		# Checking Through RootDse Connection
		writeLog -dataToLog ""
		writeLog -dataToLog "Checking Reachability of the specified $adForestLocation AD forest '$($script:targetedADforestFQDN)' through RootDse..."
		$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADforestFQDN) -EncryptionType Kerberos
		Get-RootDSE -LdapConnection $ldapConnection -ErrorAction Stop > $null
		$ldapConnection.Dispose()
		$adForestValidity = $true
	} Catch [System.Security.Authentication.AuthenticationException] {
		# $Error[0].Exception.GetType().FullName
		$adForestValidity = $true
	} Catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
		# $Error[0].Exception.GetType().FullName
		$adForestValidity = $false
	} Catch {
		$adForestValidity = $false
	}
}

If ($adForestValidity -eq $true) {
	# If The AD Forest Is Resolvable/Reachable And Therefore Exists, Continue
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "The specified $adForestLocation AD forest '$($script:targetedADforestFQDN)' is resolvable through either DNS or reachable through RootDse!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
} Else {
	# If The AD Forest Is Not Resolvable And Not Reachable And Therefore Does Not Exists, Abort
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "The specified $adForestLocation AD forest '$($script:targetedADforestFQDN)' IS NOT resolvable through DNS and IS NOT reachable through RootDse!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Please re-run the script and provide the FQDN of an AD forest that exists..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

	# Mail The Log File With The Results
	If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
		$context = "SCRIPT ABORT - ERROR: The specified $adForestLocation AD forest '$($script:targetedADforestFQDN)' IS NOT resolvable through DNS and IS NOT reachable through RootDse!"
		
		sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
	}

	EXIT
}

# Validate The Specified AD Forest Is Accessible. If it is the local AD forest then it is accessible. If it is a remote AD forest and a (forest) trust is in place, then it is accessible. If it is a remote AD forest and a (forest) trust is NOT in place, then it is NOT accessible.
$adForestAccessibility = $false
# Test To See If The AD Forest Is Accessible
Try {
	# Retrieve Information About The AD Forest
	$adForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", $($script:targetedADforestFQDN))
	$thisADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($adForestContext)

	$adForestAccessibility = $true
} Catch {
	$adForestAccessibility = $false
}
writeLog -dataToLog ""
writeLog -dataToLog "Checking Accessibility of the specified AD forest '$($script:targetedADforestFQDN)' By Trying To Retrieve AD Forest Data..."
If ($adForestAccessibility -eq $true) {
	# If The AD Forest Is Accessible, Continue
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "The specified AD forest '$($script:targetedADforestFQDN)' is accessible!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false

	$adminCrds = $null
} Else {
	If ($PSBoundParameters.keys -notcontains "modeOfOperation" -And $PSBoundParameters.keys -notcontains "targetedADforestFQDN" -And $PSBoundParameters.keys -notcontains "targetedADdomainFQDN" -And $PSBoundParameters.keys -notcontains "targetKrbTgtAccountScope") {
		# If The AD Forest Is NOT Accessible, Ask For Credentials
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The specified AD forest '$($script:targetedADforestFQDN)' IS NOT accessible!" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Custom credentials are needed..." -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Continuing Script And Asking For Credentials..." -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""

		# Ask For The Remote Credentials
		$adminCrds = requestForAdminCreds
		writeLog -dataToLog ""

		# Test To See If The AD Forest Is Accessible
		Try {
			# Retrieve Information About The AD Forest
			$adForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", $($script:targetedADforestFQDN), $($adminCrds.UserName), $($adminCrds.GetNetworkCredential().Password))
			$thisADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($adForestContext)

			$adForestAccessibility = $true
		} Catch {
			$adForestAccessibility = $false
		}
		writeLog -dataToLog ""
		writeLog -dataToLog "Checking Accessibility of the specified AD forest '$($script:targetedADforestFQDN)' By Trying To Retrieve AD Forest Data..."
		If ($adForestAccessibility -eq $true) {
			# If The AD Forest Is Accessible, Continue
			writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "The specified AD forest '$($script:targetedADforestFQDN)' is accessible!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		} Else {
			# If The AD Forest Is NOT Accessible, Ask For Credentials
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "The specified AD forest '$($script:targetedADforestFQDN)' IS NOT accessible!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Please re-run the script and provide the correct credentials to connect to the remote AD forest..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

			# Mail The Log File With The Results
			If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
				$context = "SCRIPT ABORT - ERROR: The specified AD forest '$($script:targetedADforestFQDN)' IS NOT accessible!"

				sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
			}

			EXIT
		}
	} Else {
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The specified AD forest '$($script:targetedADforestFQDN)' IS NOT accessible!" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Custom credentials are needed..." -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Script is running in automated mode and because of that it cannot ask fo customer credentials..." -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Please re-run the script and run the script with the correct credentials to connect to the remote AD forest..." -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false

		# Mail The Log File With The Results
		If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
			$context = "SCRIPT ABORT - ERROR: The specified AD forest '$($script:targetedADforestFQDN)' IS NOT accessible!"

			sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
		}

		EXIT
	}
}

# Retrieve Root AD Domain Of The AD Forest
$script:targetedADforestFQDN = $thisADForest.RootDomain.Name

# Retrieve All The AD Domains In The AD Forest And Sort These In Some Way
$arrayOfADDomainFQDNsInADForest = $thisADForest.Domains.Name

# Retrieve The DN Of The Configuration NC In The AD Forest
$script:targetedADforestConfigNCDN = $($thisADForest.Schema.Name).Replace("CN=Schema,", "")

# Retrieve The DN Of The Schema NC In The AD Forest
$script:targetedADforestSchemaNCDN = $thisADForest.Schema.Name

# Retrieve The DN Of The Sites Container In The AD Forest
$script:targetedADforestSitesContainerDN = "CN=Sites," + $script:targetedADforestConfigNCDN

# Retrieve The DN Of The Partitions Container In The AD Forest
$script:targetedADforestPartitionsContainerDN = "CN=Partitions," + $script:targetedADforestConfigNCDN

# Retrieve The Mode/Functional Level Of The AD Forest + Fix For Bug In S.DS.P.
$script:targetedADforestForestFunctionalMode = $thisADForest.ForestMode
$script:targetedADforestForestFunctionalModeLevel = $thisADForest.ForestModeLevel

# Password Reset Routine - Build Attribute Schema Mapping Table And Check Specified Attributes Actually Exist
If ($execResetRoutine -And $($script:resetRoutineEnabled).ToUpper() -eq "TRUE") {
	### Checking Defined Attributes For The Reset Routine Exist In The Schema Of The Targeted AD Forest
	writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "CHECKING DEFINED ATTRIBUTES FOR THE RESET ROUTINE EXIST IN THE SCHEMA OF THE TARGETED AD FOREST..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""

	buildAttributeSchemaMappingTables -targetedADdomainRWDCFQDN $($thisADForest.SchemaRoleOwner.Name) -localADforest $localADforest -adminCrds $adminCrds

	If ($(($script:mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT.Keys | Measure-Object).Count -eq 1) -Or $(($script:mappingTable_SCHEMA_schemaIDGUID_lDAPDisplayNameHT.Keys | Measure-Object).Count -eq 1)) {
		writeLog -dataToLog ""
		writeLog -dataToLog "The Build Of The Attribute Schema Mapping Tables Failed" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""

		$context = "SCRIPT ABORT - ERROR: The Build Of The Attribute Schema Mapping Tables Failed"

		sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context

		BREAK
	} ElseIf ([string]::IsNullOrEmpty($($script:mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT[$($script:resetRoutineAttributeForResetState)]))) {
		writeLog -dataToLog ""
		writeLog -dataToLog "The Following Attribute DOES NOT Exist In The AD Schema:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "  > '$($script:resetRoutineAttributeForResetState)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""

		$context = "SCRIPT ABORT - ERROR: The Following Attribute DOES NOT Exist In The AD Schema: $($script:resetRoutineAttributeForResetState)"

		sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context

		BREAK
	} ElseIf ([string]::IsNullOrEmpty($($script:mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT[$($script:resetRoutineAttributeForResetDateAction1)]))) {
		writeLog -dataToLog ""
		writeLog -dataToLog "The Following Attribute DOES NOT Exist In The AD Schema:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "  > '$($script:resetRoutineAttributeForResetDateAction1)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""

		$context = "SCRIPT ABORT - ERROR: The Following Attribute DOES NOT Exist In The AD Schema: $($script:resetRoutineAttributeForResetDateAction1)"

		sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context

		BREAK
	} ElseIf ([string]::IsNullOrEmpty($($script:mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT[$($script:resetRoutineAttributeForResetDateAction2)]))) {
		writeLog -dataToLog ""
		writeLog -dataToLog "The Following Attribute DOES NOT Exist In The AD Schema:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "  > '$($script:resetRoutineAttributeForResetDateAction2)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""

		$context = "SCRIPT ABORT - ERROR: The Following Attribute DOES NOT Exist In The AD Schema: $($script:resetRoutineAttributeForResetDateAction2)"

		sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context

		BREAK
	} Else {
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "All The Defined Attributes For The Password Reset Routine Exist In The Schema Of The AD Forest '$($script:targetedADforestFQDN)'!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "  > '$($script:resetRoutineAttributeForResetState)'..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "  > '$($script:resetRoutineAttributeForResetDateAction1)'..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "  > '$($script:resetRoutineAttributeForResetDateAction2)'..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	}
}

###
# All Modes - Selecting The Target AD Domain
###
writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "SELECT THE TARGET AD DOMAIN..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

# Retrieve All The AD Domains In The AD Forest And Sort These In Some Way
$sortedListOfADDomainFQDNsInADForest = [System.Collections.Generic.List[Object]]::New()
($arrayOfADDomainFQDNsInADForest | Where-Object { $_ -like "*$($script:targetedADforestFQDN)" } | ForEach-Object { ([regex]::Matches($_, '.', 'RightToLeft') | ForEach-Object { $_.value }) -join '' }) | Sort-Object | ForEach-Object { $sortedListOfADDomainFQDNsInADForest.Add($(([regex]::Matches($_, '.', 'RightToLeft') | ForEach-Object { $_.value }) -join '')) }
(@($arrayOfADDomainFQDNsInADForest | Where-Object { $_ -notin $sortedListOfADDomainFQDNsInADForest }) | ForEach-Object { ([regex]::Matches($_, '.', 'RightToLeft') | ForEach-Object { $_.value }) -join '' }) | Sort-Object | ForEach-Object { $sortedListOfADDomainFQDNsInADForest.Add($(([regex]::Matches($_, '.', 'RightToLeft') | ForEach-Object { $_.value }) -join '')) }

# Retrieve The Mode/Functional Level Of The AD Forest + Fix For Bug In S.DS.P.
If ([int]$script:targetedADforestForestFunctionalModeLevel -eq 7 -And $script:targetedADforestForestFunctionalMode -eq "Unknown") {
	$script:targetedADforestForestFunctionalMode = "Windows2016Forest"
}
If ([int]$script:targetedADforestForestFunctionalModeLevel -eq 10 -And $script:targetedADforestForestFunctionalMode -eq "Unknown") {
	$script:targetedADforestForestFunctionalMode = "Windows2025Forest"
}

# Define An Empty List/Table That Will Contain All AD Domains In The AD Forest And Related Information
$tableOfADDomainsInADForest = [System.Collections.Generic.List[Object]]::New()
writeLog -dataToLog "Forest Mode/Level...: $($script:targetedADforestForestFunctionalMode) ($($script:targetedADforestForestFunctionalModeLevel))"

# Set The Counter To Zero
$nrOfDomainsInForest = 0

# Execute For All AD Domains In The AD Forest
$sortedListOfADDomainFQDNsInADForest | ForEach-Object {
	# Increase The Counter
	$nrOfDomainsInForest += 1

	# Get The FQDN Of The AD Domain
	$domainFQDN = $_

	# Retrieve The Object Of The AD Domain From AD And The Nearest RWDC
	$domainObj = $null
	$nearestRWDCInADDomain = $null
	Try {
		$dcLocatorFlag = [System.DirectoryServices.ActiveDirectory.LocatorOptions]::"ForceRediscovery", "WriteableRequired"
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
			$adDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $domainFQDN)
		}
		If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
			$adDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $domainFQDN, $($adminCrds.UserName), $($adminCrds.GetNetworkCredential().Password))
		}
		$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($adDomainContext)
		$nearestRWDCInADDomain = $domainObj.FindDomainController($dcLocatorFlag).Name
	} Catch {
		$domainObj = $null
	}

	# Populate The Table With Data From The Processed AD Domain + Bug Fix For DomainMode(Level) In S.DS.P. When FFL/DFL Is 2016
	$tableOfADDomainsInADForestObj = [PSCustomObject]@{
		"ListNr"          = $nrOfDomainsInForest
		"Name"            = $domainFQDN
		"NetBIOS"         = $(If ($domainObj) { $domainObj.GetDirectoryEntry().Properties["Name"].Value } Else { "AD Domain Is Not Available" })
		"DomainSID"       = $(If ($domainObj) { $objectSidBytes = $domainObj.GetDirectoryEntry().Properties["objectSid"].Value; (New-Object System.Security.Principal.SecurityIdentifier($objectSidBytes, 0)).Value } Else { "AD Domain Is Not Available" })
		"IsRootDomain"    = $(If ($($script:targetedADforestFQDN) -eq $domainFQDN) { $true } Else { $false })
		"DomainMode"      = $(If ($domainObj) { If ([int]$($domainObj.DomainModeLevel) -eq 7 -And $($domainObj.DomainMode) -eq "Unknown") { "Windows2016Domain" } ElseIf ([int]$($domainObj.DomainModeLevel) -eq 10 -And $($domainObj.DomainMode) -eq "Unknown") { "Windows2025Domain" } Else { $($domainObj.DomainMode) } } Else { "AD Domain Is Not Available" })
		"IsCurrentDomain" = $(If ($fqdnADDomainOfComputer -eq $domainFQDN) { $true } Else { $false })
		"IsAvailable"     = $(If ($domainObj) { $true } Else { $false })
		"PDCFsmoOwner"    = $(If ($domainObj) { $domainObj.PdcRoleOwner.Name } Else { "AD Domain Is Not Available" })
		"NearestRWDC"     = $(If ($domainObj) { $nearestRWDCInADDomain } Else { "AD Domain Is Not Available" })
	}
	$tableOfADDomainsInADForest.Add($tableOfADDomainsInADForestObj)
}

# Display The List And Amount Of AD Domains
writeLog -dataToLog ""
writeLog -dataToLog "List Of AD Domains In AD Forest '$($script:targetedADforestFQDN)'..."
writeLog -dataToLog ""
writeLog -dataToLog "$($tableOfADDomainsInADForest | Format-Table | Out-String -Width 1024)"
writeLog -dataToLog "  --> Found [$nrOfDomainsInForest] AD Domain(s) in the AD forest '$($script:targetedADforestFQDN)'..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

# Ask Which AD Domain To Target From The Previously Presented List
$script:targetedADdomainFQDN = $targetedADdomainFQDN
If ($($script:targetedADdomainFQDN) -eq "") {
	writeLog -dataToLog "For the AD domain to be targeted, please provide the list nr or the FQDN or press [ENTER] for the current AD domain: " -lineType "ACTION-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false
	$script:targetedADdomainFQDN = Read-Host
} Else {
	writeLog -dataToLog "For the AD domain to be targeted, please provide the list nr or the FQDN or press [ENTER] for the current AD domain: $($script:targetedADdomainFQDN)" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
}

# If A Numeric Value Was Entered Instead, Then Resolve That To An Actual FQDN
If ($($script:targetedADdomainFQDN) -match "^\d$" -And [int]$($script:targetedADdomainFQDN) -le $($tableOfADDomainsInADForest | Measure-Object).Count) {
	$script:targetedADdomainFQDN = ($tableOfADDomainsInADForest | Where-Object { $_.ListNr -eq $($script:targetedADdomainFQDN) }).Name
}

# If No FQDN Of An AD Domain Is Specified, Then Use The AD Domain Of The Local Computer
If ([string]::IsNullOrEmpty($($script:targetedADdomainFQDN))) {
	$script:targetedADdomainFQDN = $fqdnADDomainOfComputer
}
writeLog -dataToLog ""
writeLog -dataToLog "  --> Selected AD Domain: '$($script:targetedADdomainFQDN)'..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

# Validate The Chosen AD Domain Against The List Of Available AD Domains To See If It Does Exist In The AD Forest
$adDomainValidity = $false
$sortedListOfADDomainFQDNsInADForest | ForEach-Object {
	$domainFQDN = $null
	$domainFQDN = $_
	If ($($script:targetedADdomainFQDN) -eq $domainFQDN) {
		$script:adDomainValidity = $true
	}
}
writeLog -dataToLog ""
writeLog -dataToLog "Checking existence of the specified AD domain '$($script:targetedADdomainFQDN)' in the AD forest '$($script:targetedADforestFQDN)'..."
If ($adDomainValidity -eq $true) {
	# If The AD Domain Is Valid And Therefore Exists, Continue
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "The specified AD domain '$($script:targetedADdomainFQDN)' exists in the AD forest '$($script:targetedADforestFQDN)'!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
} Else {
	# If The AD Domain Is Not Valid And Therefore Does Not Exist, Abort
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "The specified AD domain '$($script:targetedADdomainFQDN)' DOES NOT exist in the AD forest '$($script:targetedADforestFQDN)'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Please re-run the script and provide the FQDN of an AD domain that does exist in the AD forest '$($script:targetedADforestFQDN)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

	# Mail The Log File With The Results
	If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
		$context = "SCRIPT ABORT - ERROR: The specified AD domain '$($script:targetedADdomainFQDN)' DOES NOT exist in the AD forest '$($script:targetedADforestFQDN)'!"

		sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
	}

	EXIT
}

###
# All Modes
###
# Target AD Domain Data
$targetedADdomainData = $tableOfADDomainsInADForest | Where-Object { $_.Name -eq $($script:targetedADdomainFQDN) }

# Retrieve The HostName Of Nearest RWDC In The AD Domain
$script:targetedADdomainNearestRWDCFQDN = $targetedADdomainData.NearestRWDC

###
# All Modes, Except MODE 1 - Testing If Required Permissions Are Available (Domain/Enterprise Admin Credentials)
###
If ($modeOfOperationNr -gt 1) {
	writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "TESTING IF REQUIRED PERMISSIONS ARE AVAILABLE (DOMAIN/ENTERPRISE ADMINS OR ADMINISTRATORS CREDENTIALS)..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""

	# Retrieve The ObjectSIDOf The Targeted AD Domain
	$targetedDomainObjectSID = $targetedADdomainData.DomainSID

	# If The AD Forest Is Local, Then We Can Test For Role Membership Of Either Domain Admins Or Enterprise Admins.
	If ($localADforest -eq $true) {
		# Validate The User Account Running This Script Is "NT AUTHORITY\SYSTEM" Or Not
		$testAccountIsSystemOnRWDC = testAccountIsSystemOnRWDC
		$systemIsRWDC = $testAccountIsSystemOnRWDC[0]
		$userIsSystem = $testAccountIsSystemOnRWDC[1]
		$userAccount = $testAccountIsSystemOnRWDC[2]

		If ($systemIsRWDC -eq $true -And $userIsSystem -eq $true) {
			# The User Account Running This Script Has Been Validated To Be "NT AUTHORITY\SYSTEM" On An RWDC
			writeLog -dataToLog "The user account '$userAccount' is the local SYSTEM account of the RWDC the script is being executed on!..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		} ElseIf ($systemIsRWDC -eq $false -And $userIsSystem -eq $true) {
			# The User Account Running This Script Has Been Validated To Be "NT AUTHORITY\SYSTEM" But It Is NOT Running On An RWDC
			writeLog -dataToLog "The user account '$userAccount' is the local SYSTEM account, but the script in this case is NOT being executed on an RWDC!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "For this script to run successfully as '$userAccount', it must be executed on an RWDC!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

			# Mail The Log File With The Results
			If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
				$context = "SCRIPT ABORT - ERROR: The user account '$userAccount' is the local SYSTEM account, but the script in this case is NOT being executed on an RWDC!..."

				sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
			}

			EXIT
		} Else {
			If ($skipDAMembershipCheck -eq $false) {
				# Validate The User Account Running This Script Is A Member Of The Domain Admins Group Of The Targeted AD Domain
				$domainAdminRID = "512"
				$domainAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($targetedDomainObjectSID + "-" + $domainAdminRID)).Translate([System.Security.Principal.NTAccount]).Value
				$userIsDomainAdmin = testAdminRole -adminRole $domainAdminRole
				If (!$userIsDomainAdmin) {
					# The User Account Running This Script Has Been Validated Not Being A Member Of The Domain Admins Group Of The Targeted AD Domain
					# Validate The User Account Running This Script Is A Member Of The Enterprise Admins Group Of The AD Forest
					$forestRootDomainObjectSID = ($tableOfADDomainsInADForest | Where-Object { $_.IsRootDomain -eq $true }).DomainSID
					$enterpriseAdminRID = "519"
					$enterpriseAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($forestRootDomainObjectSID + "-" + $enterpriseAdminRID)).Translate([System.Security.Principal.NTAccount]).Value
					$userIsEnterpriseAdmin = testAdminRole -adminRole $enterpriseAdminRole
					If (!$userIsEnterpriseAdmin) {
						# The User Account Running This Script Has Been Validated Not Being A Member Of The Enterprise Admins Group Of The AD Forest
						writeLog -dataToLog "The user account '$adRunningUserAccount' IS NOT running with Domain/Enterprise Administrator equivalent permissions in the AD Domain '$($script:targetedADdomainFQDN)'!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "The user account '$adRunningUserAccount' IS NOT a member of '$domainAdminRole' and NOT a member of '$enterpriseAdminRole'!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "For this script to run successfully, Domain/Enterprise Administrator equivalent permissions are required..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

						# Mail The Log File With The Results
						If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
							$context = "SCRIPT ABORT - ERROR: The user account '$adRunningUserAccount' IS NOT running with Domain/Enterprise Administrator equivalent permissions in the AD Domain '$($script:targetedADdomainFQDN)'!"
							
							sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
						}

						EXIT
					} Else {
						# The User Account Running This Script Has Been Validated To Be A Member Of The Enterprise Admins Group Of The AD Forest
						writeLog -dataToLog "The user account '$adRunningUserAccount' is running with Enterprise Administrator equivalent permissions in the AD Domain '$($script:targetedADdomainFQDN)'!..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "The user account '$adRunningUserAccount' is a member of '$enterpriseAdminRole'!..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					}
				} Else {
					# The User Account Running This Script Has Been Validated To Be A Member Of The Domain Admins Group Of The Targeted AD Domain
					writeLog -dataToLog "The user account '$adRunningUserAccount' is running with Domain Administrator equivalent permissions in the AD Domain '$($script:targetedADdomainFQDN)'!..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "The user account '$adRunningUserAccount' is a member of '$domainAdminRole'!..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				}
			} Else {
				# Validation Of The User Account Running This Script Has Been Disabled
				writeLog -dataToLog "Validation of the user account '$adRunningUserAccount' running with Domain Administrator equivalent permissions in the AD Domain '$($script:targetedADdomainFQDN)' has been disabled!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "It is unknown if the user account '$adRunningUserAccount' has the correct permissions or not. The required permissions will be assumed..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
	}
}

# If The AD Forest Is Remote Then We Cannot Test For Role Membership Of The Administrators Group. We Will Test Permissions By Copying The Value Of The Description Field Into The Title Field And Clearing It Again
If ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds))) {
	Try {
		$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos
		$krbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $("DC=" + $($script:targetedADdomainFQDN).Replace(".",",DC=")) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=KRBTGT))" -PropertiesToLoad @("description") -AdditionalProperties @('title')
		$krbTgtObject.title = $krbTgtObject.description
		Edit-LdapObject -LdapConnection $ldapConnection -Mode Replace -Object $krbTgtObject
		$krbTgtObject.title = $null
		Edit-LdapObject -LdapConnection $ldapConnection -Mode Replace -Object $krbTgtObject
		$ldapConnection.Dispose()
		writeLog -dataToLog "The user account '$adRunningUserAccount' is running with Administrators equivalent permissions in the AD Domain '$($script:targetedADdomainFQDN)'!..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	} Catch {
		writeLog -dataToLog "The user account '$adRunningUserAccount' IS NOT running with Administrators equivalent permissions in the AD Domain '$($script:targetedADdomainFQDN)'!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "For this script to run successfully, Administrators equivalent permissions are required in the AD Domain '$($script:targetedADdomainFQDN)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		If ($PSBoundParameters.keys -notcontains "modeOfOperation" -And $PSBoundParameters.keys -notcontains "targetedADforestFQDN" -And $PSBoundParameters.keys -notcontains "targetedADdomainFQDN" -And $PSBoundParameters.keys -notcontains "targetKrbTgtAccountScope") {
			writeLog -dataToLog "Custom credentials are needed..." -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Continuing Script And Asking For Credentials..." -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			# Ask For The Remote Credentials
			$adminCrds = requestForAdminCreds
			writeLog -dataToLog ""
		} Else {
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			# Mail The Log File With The Results
			If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
				$context = "SCRIPT ABORT - ERROR: The user account '$adRunningUserAccount' IS NOT running with Administrators equivalent permissions in the AD Domain '$($script:targetedADdomainFQDN)'!"

				sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
			}

			EXIT
		}
	}
}
If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
	Try {
		$adminUserAccountRemoteForest = $adminCrds.UserName
		$adminUserPasswordRemoteForest = $adminCrds.GetNetworkCredential().Password
		$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos -Credential $adminCrds
		$krbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $("DC=" + $($script:targetedADdomainFQDN).Replace(".",",DC=")) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=KRBTGT))" -PropertiesToLoad @("description") -AdditionalProperties @('title')
		$krbTgtObject.title = $krbTgtObject.description
		Edit-LdapObject -LdapConnection $ldapConnection -Mode Replace -Object $krbTgtObject
		$krbTgtObject.title = $null
		Edit-LdapObject -LdapConnection $ldapConnection -Mode Replace -Object $krbTgtObject
		$ldapConnection.Dispose()
		writeLog -dataToLog "The user account '$adminUserAccountRemoteForest' is running with Administrators equivalent permissions in the AD Domain '$($script:targetedADdomainFQDN)'!..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	} Catch {
		writeLog -dataToLog "The user account '$adminUserAccountRemoteForest' IS NOT running with Administrators equivalent permissions in the AD Domain '$($script:targetedADdomainFQDN)' OR username/password IS NOT correct!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "For this script to run successfully, Administrators equivalent permissions are required in the AD Domain '$($script:targetedADdomainFQDN)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		# Mail The Log File With The Results
		If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
			$context = "SCRIPT ABORT - ERROR: The user account '$adminUserAccountRemoteForest' IS NOT running with Administrators equivalent permissions in the AD Domain '$($script:targetedADdomainFQDN)' OR username/password IS NOT correct!"

			sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
		}

		EXIT
	}
}

###
# All Modes - Gathering AD Domain Information
###
writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "GATHERING TARGETED AD DOMAIN INFORMATION..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

# Retrieve Information For The AD Domain That Was Chosen
Try {
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
		$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos
		$adDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $($script:targetedADdomainFQDN))
		$targetSearchBase = "OU=Domain Controllers," + $("DC=" + $($script:targetedADdomainFQDN).Replace(".",",DC="))
		$dcsInADDomain = Find-LdapObject -LdapConnection $ldapConnection -searchBase $targetSearchBase -searchFilter "(&(objectClass=computer)(|(primaryGroupID=516)(primaryGroupID=521)))" -PropertiesToLoad @("dNSHostName", "msDS-isRODC", "msDS-KrbTgtLink", "OperatingSystem", "primaryGroupID", "rIDSetReferences", "serverReferenceBL")
		$ldapConnection.Dispose()
	}
	If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
		$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos -Credential $adminCrds
		$adDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $($script:targetedADdomainFQDN), $($adminCrds.UserName), $($adminCrds.GetNetworkCredential().Password))
		$targetSearchBase = "OU=Domain Controllers," + $("DC=" + $($script:targetedADdomainFQDN).Replace(".",",DC="))
		$dcsInADDomain = Find-LdapObject -LdapConnection $ldapConnection -searchBase $targetSearchBase -searchFilter "(&(objectClass=computer)(|(primaryGroupID=516)(primaryGroupID=521)))" -PropertiesToLoad @("dNSHostName", "msDS-isRODC", "msDS-KrbTgtLink", "OperatingSystem", "primaryGroupID", "rIDSetReferences", "serverReferenceBL")
		$ldapConnection.Dispose()
	}
	$thisADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($adDomainContext)
} Catch {
	$thisADDomain = $null
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' To Get List Of DCs In The Targeted AD '$($script:targetedADdomainFQDN)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
}

If ($thisADDomain) {
	# Retrieve The Domain NC DN
	$script:targetedADdomainDefaultNCDN = $thisADDomain.GetDirectoryEntry().Properties["distinguishedName"].Value
	
	# Retrieve The Domain SID
	$objectSidBytes = $thisADDomain.GetDirectoryEntry().Properties["objectSid"].Value
	$targetedADdomainDomainSID = (New-Object System.Security.Principal.SecurityIdentifier($objectSidBytes, 0)).Value

	# Retrieve The HostName Of RWDC In The AD Domain That Hosts The PDC FSMO Role
	$script:targetedADdomainRWDCFQDNWithPDCFSMOFQDN = $thisADDomain.PdcRoleOwner.Name

	# Retrieve The DSA DN Of RWDC In The AD Domain That Hosts The PDC FSMO Role
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos
			$script:targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADforestSitesContainerDN) -searchFilter "(&(objectClass=server)(dNSHostName=$($script:targetedADdomainRWDCFQDNWithPDCFSMOFQDN)))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' For Domain Controller With 'dNSHostName=$($script:targetedADdomainRWDCFQDNWithPDCFSMOFQDN)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos -Credential $adminCrds
			$script:targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADforestSitesContainerDN) -searchFilter "(&(objectClass=server)(dNSHostName=$($script:targetedADdomainRWDCFQDNWithPDCFSMOFQDN)))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' For Domain Controller With 'dNSHostName=$($script:targetedADdomainRWDCFQDNWithPDCFSMOFQDN)' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}

	# Retrieve Domain Functional Level/Mode Of The AD Domain
	$script:targetedADdomainDomainFunctionalMode = $thisADDomain.DomainMode
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos
			$script:targetedADdomainDomainFunctionalModeLevel = (Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADforestPartitionsContainerDN) -searchFilter "(&(objectClass=crossRef)(nCName=$('DC=' + $($script:targetedADdomainFQDN).replace('.',',DC='))))" -PropertiesToLoad @("msDS-Behavior-Version"))."msDS-Behavior-Version"
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' For Cross Reference Object With 'nCName=$('DC=' + $($script:targetedADdomainFQDN).replace('.',',DC='))'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
		Try {
			$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos -Credential $adminCrds
			$script:targetedADdomainDomainFunctionalModeLevel = (Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADforestPartitionsContainerDN) -searchFilter "(&(objectClass=crossRef)(nCName=$('DC=' + $($script:targetedADdomainFQDN).replace('.',',DC='))))" -PropertiesToLoad @("msDS-Behavior-Version"))."msDS-Behavior-Version"
			$ldapConnection.Dispose()
		} Catch {
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' For Cross Reference Object With 'nCName=$('DC=' + $($script:targetedADdomainFQDN).replace('.',',DC='))' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	If ($($script:targetedADdomainDomainFunctionalModeLevel) -eq 7 -And $targetedADdomainDomainFunctionalMode -eq "Unknown") {
		$script:targetedADdomainDomainFunctionalMode = "Windows2016Domain"
	}
	If ($($script:targetedADdomainDomainFunctionalModeLevel) -eq 10 -And $targetedADdomainDomainFunctionalMode -eq "Unknown") {
		$script:targetedADdomainDomainFunctionalMode = "Windows2025Domain"
	}

	Try {
		# Execute An RSoP Against The Nearest RWDC In The Targeted AD Domain To Determine The Result Settings And The GPO(s) That Provided The Final Setting
		# Get The List Of GPOs That Were Processed For RSoP So We Can Map The GUID Back To Show Which GPO Won
		# Determine The Max Tgt Lifetime In Hours From The Winning GPO And The Max Clock Skew In Minutes From The Winning GPO
		If ($localADforest -eq $true) {
			# Determine The User Account To Use During RSoP
			$accountToChooseForRSoP = determineUserAccountForRSoP -targetedADdomainNearestRWDCFQDN $($script:targetedADdomainNearestRWDCFQDN) -targetedADdomainDomainSID $targetedADdomainDomainSID

			# Run An RsOP To Determine In Which GPO, If Applicable, What The Kerberos Policy Settings Are And Export To XML File
			Get-GPResultantSetOfPolicy -Computer $($script:targetedADdomainNearestRWDCFQDN) -User $accountToChooseForRSoP -ReportType xml -Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_Kerberos_$($script:targetedADdomainFQDN)`_$($script:targetedADdomainNearestRWDCFQDN)`_$execDateTimeCustom.xml" -ErrorAction Stop > $null

			# Determine The Kerberos Policy Settings
			If (Test-Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_Kerberos_$($script:targetedADdomainFQDN)`_$($script:targetedADdomainNearestRWDCFQDN)`_$execDateTimeCustom.xml") {
				[xml]$gpRSoPxml = Get-Content "$($ENV:WINDIR + '\TEMP')\gpRSoP_Kerberos_$($script:targetedADdomainFQDN)`_$($script:targetedADdomainNearestRWDCFQDN)`_$execDateTimeCustom.xml"
				$kerberosPolicyMaxTgtAgeObject, $kerberosPolicyMaxClockSkewObject = determineKerberosPolicySettings -targetedADdomainFQDN $($script:targetedADdomainFQDN) -targetedADdomainNearestRWDCFQDN $($script:targetedADdomainNearestRWDCFQDN) -execDateTimeCustom $execDateTimeCustom -gpRSoPxml $gpRSoPxml

				Try {
					Remove-Item "$($ENV:WINDIR + '\TEMP')\gpRSoP_Kerberos_$($script:targetedADdomainFQDN)`_$($script:targetedADdomainNearestRWDCFQDN)`_$execDateTimeCustom.xml" -Force -ErrorAction Stop
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Removing The RSoP File '$($ENV:WINDIR + '\TEMP')\gpRSoP_Kerberos_$($script:targetedADdomainFQDN)`_$($script:targetedADdomainNearestRWDCFQDN)`_$execDateTimeCustom.xml'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			} Else {
				$kerberosPolicyMaxTgtAgeObject = New-Object -TypeName PSObject -Property @{
					SettingName   = "MaxTicketAge";
					SettingValue  = $script:maxTgtLifetimeHrs;
					SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
					SourceGPOName = "Default Value Assumed";
				}
				$kerberosPolicyMaxClockSkewObject = New-Object -TypeName PSObject -Property @{
					SettingName   = "MaxClockSkew";
					SettingValue  = $script:maxClockSkewMins;
					SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
					SourceGPOName = "Default Value Assumed";
				}
			}
		}
		If ($localADforest -eq $false) {
			If ([string]::IsNullOrEmpty($adminCrds)) {
				$targetedServerSession = New-PSSession -ComputerName $($script:targetedADdomainNearestRWDCFQDN) -ErrorAction Stop
			} Else {
				$targetedServerSession = New-PSSession -ComputerName $($script:targetedADdomainNearestRWDCFQDN) -Credential $adminCrds -ErrorAction Stop
			}
			$kerberosPolicyMaxTgtAgeObject, $kerberosPolicyMaxClockSkewObject, $accountToChooseForRSoP = Invoke-Command -Session $targetedServerSession -ArgumentList $($script:targetedADdomainFQDN), $targetedADdomainDomainSID, $($script:targetedADdomainNearestRWDCFQDN), $execDateTimeCustom, $loggingDef, $loadPoSHModulesDef, $determineUserAccountForRSoPDef, $determineKerberosPolicySettingsDef -ScriptBlock {
				Param (
					$targetedADdomainFQDN,
					$targetedADdomainDomainSID,
					$targetedADdomainNearestRWDCFQDN,
					$execDateTimeCustom,
					$loggingDef,
					$loadPoSHModulesDef,
					$determineUserAccountForRSoPDef,
					$determineKerberosPolicySettingsDef
				)

				. ([ScriptBlock]::Create($loggingDef))
				. ([ScriptBlock]::Create($loadPoSHModulesDef))
				. ([ScriptBlock]::Create($determineUserAccountForRSoPDef))
				. ([ScriptBlock]::Create($determineKerberosPolicySettingsDef))

				"GroupPolicy" | ForEach-Object {
					$poshModuleState = $null
					$poshModuleState = loadPoSHModules -poshModule $_ -ignoreRemote $true
					If ($poshModuleState -eq "NotAvailable") {
						BREAK
					}
				}

				If ($poshModuleState -eq "HasBeenLoaded" -Or $poshModuleState -eq "AlreadyLoaded") {
					# Determine The User Account To Use During RSoP
					$accountToChooseForRSoP = determineUserAccountForRSoP -targetedADdomainNearestRWDCFQDN $targetedADdomainNearestRWDCFQDN -targetedADdomainDomainSID $targetedADdomainDomainSID

					# Run An RsOP To Determine In Which GPO, If Applicable, What The Kerberos Policy Settings Are And Export To XML File
					Get-GPResultantSetOfPolicy -Computer $targetedADdomainNearestRWDCFQDN -User $accountToChooseForRSoP -ReportType xml -Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_Kerberos_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml" -ErrorAction Stop > $null

					# Determine The Kerberos Policy Settings
					If (Test-Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_Kerberos_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml") {
						[xml]$gpRSoPxml = Get-Content "$($ENV:WINDIR + '\TEMP')\gpRSoP_Kerberos_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml"
						$kerberosPolicyMaxTgtAgeObject, $kerberosPolicyMaxClockSkewObject = determineKerberosPolicySettings -targetedADdomainFQDN $targetedADdomainFQDN -targetedADdomainNearestRWDCFQDN $targetedADdomainNearestRWDCFQDN -execDateTimeCustom $execDateTimeCustom -gpRSoPxml $gpRSoPxml

						Try {
							Remove-Item "$($ENV:WINDIR + '\TEMP')\gpRSoP_Kerberos_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml" -Force -ErrorAction Stop
						} Catch {
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error Removing The RSoP File '$($ENV:WINDIR + '\TEMP')\gpRSoP_Kerberos_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						}
					} Else {
						$kerberosPolicyMaxTgtAgeObject = New-Object -TypeName PSObject -Property @{
							SettingName   = "MaxTicketAge";
							SettingValue  = $script:maxTgtLifetimeHrs;
							SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
							SourceGPOName = "Default Value Assumed (Reason: RsOP Failed)";
						}
						$kerberosPolicyMaxClockSkewObject = New-Object -TypeName PSObject -Property @{
							SettingName   = "MaxClockSkew";
							SettingValue  = $script:maxClockSkewMins;
							SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
							SourceGPOName = "Default Value Assumed (Reason: RsOP Failed)";
						}
						$accountToChooseForRSoP = $accountToChooseForRSoP + " (Reason: RsOP Failed)"
					}
				} Else {
					$kerberosPolicyMaxTgtAgeObject = New-Object -TypeName PSObject -Property @{
						SettingName   = "MaxTicketAge";
						SettingValue  = $script:maxTgtLifetimeHrs;
						SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
						SourceGPOName = "Default Value Assumed (Reason: PoSH Module Not Installed On Remote RWDC)";
					}
					$kerberosPolicyMaxClockSkewObject = New-Object -TypeName PSObject -Property @{
						SettingName   = "MaxClockSkew";
						SettingValue  = $script:maxClockSkewMins;
						SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
						SourceGPOName = "Default Value Assumed (Reason: PoSH Module Not Installed On Remote RWDC)";
					}
					$accountToChooseForRSoP = "Unused/Undetermined (Reason: PoSH Module Not Installed On Remote RWDC)"
				}
				Return $kerberosPolicyMaxTgtAgeObject, $kerberosPolicyMaxClockSkewObject, $accountToChooseForRSoP
			}
			Remove-PSSession $targetedServerSession
		}

		$script:targetedADdomainMaxTgtLifetimeHrs = $kerberosPolicyMaxTgtAgeObject.SettingValue
		$script:targetedADdomainMaxTgtLifetimeHrsSourceGPO = $kerberosPolicyMaxTgtAgeObject.SourceGPOName
		$script:targetedADdomainMaxClockSkewMins = $kerberosPolicyMaxClockSkewObject.SettingValue
		$script:targetedADdomainMaxClockSkewMinsSourceGPO = $kerberosPolicyMaxClockSkewObject.SourceGPOName
	} Catch {
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Could Not Lookup 'MaxTicketAge' (Default 10 Hours) And 'MaxClockSkew' (Default 5 minutes) From The Resultant GPO, So Default Values Will Be Assumed." -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		Get-ChildItem $(Join-Path $ENV:WINDIR "TEMP") -Filter "gpRSoP*" | ForEach-Object { Remove-Item $_.FullName -force }
		$script:targetedADdomainMaxTgtLifetimeHrs = $script:maxTgtLifetimeHrs
		$script:targetedADdomainMaxTgtLifetimeHrsSourceGPO = "Default Value Assumed"
		$script:targetedADdomainMaxClockSkewMins = $script:maxClockSkewMins
		$script:targetedADdomainMaxClockSkewMinsSourceGPO = "Default Value Assumed"
		$accountToChooseForRSoP = "Unused/Undetermined (Reason: Unknown Error/Issue)"
	}
} Else {
	$script:targetedADdomainRWDCFQDNWithPDCFSMOFQDN = "Unavailable"
	$script:targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN = "Unavailable"
	$script:targetedADdomainDomainFunctionalMode = "Unavailable"
	$script:targetedADdomainDomainFunctionalModeLevel = "Unavailable"
	$script:targetedADdomainMaxTgtLifetimeHrs = "Unavailable"
	$script:targetedADdomainMaxTgtLifetimeHrsSourceGPO = "Unavailable"
	$script:targetedADdomainMaxClockSkewMins = "Unavailable"
	$script:targetedADdomainMaxClockSkewMinsSourceGPO = "Unavailable"
}

# Present The Information
writeLog -dataToLog "Forest FQDN...........................: '$($script:targetedADforestFQDN)'"
writeLog -dataToLog "Forest Functional Mode................: '$($script:targetedADforestForestFunctionalMode)'"
writeLog -dataToLog "Forest Functional Mode Level..........: '$($script:targetedADforestForestFunctionalModeLevel)'"
writeLog -dataToLog "Forest Configuration NC DN............: '$($script:targetedADforestConfigNCDN)'"
writeLog -dataToLog "Forest Partitions Container DN........: '$($script:targetedADforestPartitionsContainerDN)'"
writeLog -dataToLog "Forest Sites Container DN.............: '$($script:targetedADforestSitesContainerDN)'"
writeLog -dataToLog "Domain FQDN...........................: '$($script:targetedADdomainFQDN)'"
writeLog -dataToLog "Domain NC DN..........................: '$($script:targetedADdomainDefaultNCDN)'"
writeLog -dataToLog "Domain Functional Mode................: '$($script:targetedADdomainDomainFunctionalMode)'"
writeLog -dataToLog "Domain Functional Mode Level..........: '$($script:targetedADdomainDomainFunctionalModeLevel)'"
writeLog -dataToLog "FQDN RWDC With PDC FSMO...............: '$($script:targetedADdomainRWDCFQDNWithPDCFSMOFQDN)'"
writeLog -dataToLog "FQDN Nearest RWDC.....................: '$($script:targetedADdomainNearestRWDCFQDN)'"
writeLog -dataToLog "DSA RWDC With PDC FSMO................: '$($script:targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN)'"
writeLog -dataToLog "Account Used For RSoP.................: '$accountToChooseForRSoP'"
writeLog -dataToLog "Max TGT Lifetime (Hours)..............: '$($script:targetedADdomainMaxTgtLifetimeHrs)'"
writeLog -dataToLog "Max TGT Lifetime Sourced From.........: '$($script:targetedADdomainMaxTgtLifetimeHrsSourceGPO)'"
writeLog -dataToLog "Max Clock Skew (Minutes)..............: '$($script:targetedADdomainMaxClockSkewMins)'"
writeLog -dataToLog "Max Clock Skew Sourced From...........: '$($script:targetedADdomainMaxClockSkewMinsSourceGPO)'"
writeLog -dataToLog ""
writeLog -dataToLog "Checking Domain Functional Mode of targeted AD domain '$($script:targetedADdomainFQDN)' is high enough..."

# Check If The Domain Functional Level/Mode Of The AD Domain Is High Enough To Continue
If ($($script:targetedADdomainDomainFunctionalModeLevel) -ne "Unavailable" -And [int]$($script:targetedADdomainDomainFunctionalModeLevel) -ge 3) {
	# If The Domain Functional Level/Mode Of The AD Domain Is Equal Or Higher Than Windows Server 2008 (3), Then Continue
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "The specified AD domain '$($script:targetedADdomainFQDN)' has a Domain Functional Mode of 'Windows2008Domain (3)' or higher!..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
} Else {
	# If The Domain Functional Level/Mode Of The AD Domain Is Lower Than Windows Server 2008 (3) Or It Cannot Be Determined, Then Abort
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "It CANNOT be determined the specified AD domain '$($script:targetedADdomainFQDN)' has a Domain Functional Mode of 'Windows2008Domain (3)' or higher!..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "AD domains with Windows Server 2000/2003 DCs CANNOT do KDC PAC validation using the previous (N-1) KrbTgt Account Password" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "like Windows Server 2008 and higher DCs are able to. Windows Server 2000/2003 DCs will only attempt it with the current (N)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "KrbTgt Account Password. That means that in the subset of KRB AP exchanges where KDC PAC validation is performed," -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "authentication issues could be experience because the target server gets a PAC validation error when asking the KDC (DC)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "to validate the KDC signature of the PAC that is inside the service ticket that was presented by the client to the server." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "This problem would potentially persist for the lifetime of the service ticket(s). And by the way... for Windows Server" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "2000/2003 support already ended years ago. Time to upgrade to higher version dude!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Be aware though, when increasing the DFL from Windows Server 2003 to any higher level, the password of the KrbTgt Account" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "will be reset automatically due to the introduction of AES encryption for Kerberos and the requirement to regenerate new" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "keys for DES, RC4, AES128, AES256!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

	# Mail The Log File With The Results
	If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
		$context = "SCRIPT ABORT - ERROR: It CANNOT be determined the specified AD domain '$($script:targetedADdomainFQDN)' has a Domain Functional Mode of 'Windows2008Domain (3)' or higher!"

		sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
	}

	EXIT
}

###
# All Modes - Gathering Domain Controller Information And Testing Connectivity
###
writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "GATHERING DOMAIN CONTROLLER INFORMATION AND TESTING CONNECTIVITY..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

# Define An Empty List/Table That Will Contain All DCs In The AD Domain And Related Information
$tableOfDCsInADDomain = [System.Collections.Generic.List[Object]]::New()

# Retrieve All The RWDCs In The AD Domain
$listOfRWDCsInADDomain = $dcsInADDomain | Where-Object { $_."msDS-isRODC" -eq $false -And $_.primaryGroupID -eq "516" -And $(-not [string]::IsNullOrEmpty($_.rIDSetReferences)) }

# Set The Counters To Zero
$nrOfRWDCs = 0
$nrOfReachableRWDCs = 0
$nrOfUnReachableRWDCs = 0

# Execute For All RWDCs In The AD Domain
writeLog -dataToLog "Processing Data Of All The Discovered Writable DCs (RWDCs) - NO CHANGES!!!..." -logFileOnly $false -noDateTimeInLogLine $false
$nrOfRWDCsToProcess = ($listOfRWDCsInADDomain | Measure-Object).Count
$nrOfRWDCsProcessed = 0

# For RWDCs, The KrbTgt Account Is The Same So Only Processing Once Is Enough
$rwdcKrbTgtSamAccountName = $null
If ($modeOfOperationNr -eq 1 -Or $modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6 -Or $modeOfOperationNr -eq 7) {
	# Use The PROD/REAL KrbTgt Account Of The RWDC
	$rwdcKrbTgtSamAccountName = "krbtgt"
}
If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {
	# Use The TEST/BOGUS KrbTgt Account Of The RWDC
	$rwdcKrbTgtSamAccountName = "krbtgt_TEST"
}
$rwdcKrbTgtObject = $null
If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
	Try {
		$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos
		$rwdcKrbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$rwdcKrbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
		$ldapConnection.Dispose()
	} Catch {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' For User Object With 'sAMAccountName=$rwdcKrbTgtSamAccountName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	}
}
If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
	Try {
		$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos -Credential $adminCrds
		$rwdcKrbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN)searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$rwdcKrbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
		$ldapConnection.Dispose()
	} Catch {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' For User Object With 'sAMAccountName=$rwdcKrbTgtSamAccountName' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	}
}
# Retrieve The Object Of The KrbTgt Account
$rwdcKrbTgtObjectDN = $null
$rwdcKrbTgtPwdLastSet = $null
$rwdcKrbTgtObjectMetadata = $null
$rwdcKrbTgtObjectMetadataAttribPwdLastSet = $null
$rwdcKrbTgtObjectMetadataAttribPwdLastSetOrgRWDCFQDN = $null
$rwdcKrbTgtObjectMetadataAttribPwdLastSetOrgTime = $null
$rwdcKrbTgtObjectMetadataAttribPwdLastSetVersion = $null
If ($rwdcKrbTgtObject) {
	# If The Object Of The KrbTgt Account Exists
	# Retrieve The DN OF The Object
	$rwdcKrbTgtObjectDN = $rwdcKrbTgtObject.DistinguishedName

	# Retrieve The Password Last Set Value Of The KrbTgt Account
	$rwdcKrbTgtPwdLastSet = Get-Date $([datetime]::fromfiletime($rwdcKrbTgtObject.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"

	# Retrieve The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object
	$rwdcKrbTgtObjectMetadata = retrieveObjectMetadata -targetedADdomainRWDCFQDN $($script:targetedADdomainNearestRWDCFQDN) -ObjectDN $rwdcKrbTgtObjectDN -localADforest $localADforest -adminCrds $adminCrds
	$rwdcKrbTgtObjectMetadataAttribPwdLastSet = $rwdcKrbTgtObjectMetadata | Where-Object { $_.Name -eq "pwdLastSet" }
	$rwdcKrbTgtObjectMetadataAttribPwdLastSetOrgRWDCFQDN = If ($rwdcKrbTgtObjectMetadataAttribPwdLastSet.OriginatingServer) { $rwdcKrbTgtObjectMetadataAttribPwdLastSet.OriginatingServer } Else { "RWDC Demoted" }
	$rwdcKrbTgtObjectMetadataAttribPwdLastSetOrgTime = Get-Date $($rwdcKrbTgtObjectMetadataAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
	$rwdcKrbTgtObjectMetadataAttribPwdLastSetVersion = $rwdcKrbTgtObjectMetadataAttribPwdLastSet.Version
} Else {
	# If The Object Of The KrbTgt Account Does Not Exist
	$rwdcKrbTgtPwdLastSet = "No Such Object"
	$rwdcKrbTgtObjectMetadataAttribPwdLastSet = "No Such Object"
	$rwdcKrbTgtObjectMetadataAttribPwdLastSetOrgRWDCFQDN = "No Such Object"
	$rwdcKrbTgtObjectMetadataAttribPwdLastSetOrgTime = "No Such Object"
	$rwdcKrbTgtObjectMetadataAttribPwdLastSetVersion = "No Such Object"
}
If ($listOfRWDCsInADDomain) {
	$listOfRWDCsInADDomain | ForEach-Object {
		$nrOfRWDCsProcessed += 1

		# Get The FQDN Of The RWDC
		$rwdcFQDN = $null
		$rwdcFQDN = $_.dNSHostName

		writeLog -dataToLog " > $($nrOfRWDCsProcessed.ToString().PadLeft($($nrOfRWDCsToProcess.ToString().Length), '0')) Of $nrOfRWDCsToProcess" -lineType "REMARK-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false

		# Define The Columns For The RWDCs In The AD Domain To Be Filled In
		$tableOfDCsInADDomainObj = [PSCustomObject]@{
			"Host Name" = $rwdcFQDN
			"PDC"       = $(If (($tableOfADDomainsInADForest | Where-Object { $_.Name -eq $($script:targetedADdomainFQDN) }).PDCFsmoOwner -eq $rwdcFQDN) { $true } Else { $false })
			#"Site Name" = $($rwdcObj.serverReferenceBL.Split(",")[2].Replace("CN=", ""))
			"Site Name" = $($_.serverReferenceBL.Split(",")[2].Replace("CN=", ""))
			"DS Type"   = "Read/Write"
		}
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Krb Tgt" -Value $rwdcKrbTgtSamAccountName
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Pwd Last Set" -Value $rwdcKrbTgtPwdLastSet
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Org RWDC" -Value $rwdcKrbTgtObjectMetadataAttribPwdLastSetOrgRWDCFQDN
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Org Time" -Value $rwdcKrbTgtObjectMetadataAttribPwdLastSetOrgTime
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Ver" -Value $rwdcKrbTgtObjectMetadataAttribPwdLastSetVersion
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $(Try { (([System.Net.Dns]::GetHostEntry($rwdcFQDN)).AddressList | Where-Object { $_.AddressFamily -eq "InterNetwork" }).IPAddressToString } Catch { "Unknown" })
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "OS Version" -Value $($_.OperatingSystem)

		# Define The Ports To Check Against
		$ports = 389 # LDAP

		# Define The Connection Check To Be True Initially
		$connectionCheckOK = $true

		# For Every Defined Port Check The Connection And Report
		$ports | ForEach-Object {
			# Set The Port To Check Against
			$port = $null
			$port = $_

			# Test The Connection To The Server Using The Port
			$connectionResult = $null
			$connectionResult = portConnectionCheck -serverIPOrFQDN $rwdcFQDN -port $port -timeOut $connectionTimeout
			If ($connectionResult -eq "ERROR") {
				$script:connectionCheckOK = $false
			}
		}
		If ($connectionCheckOK -eq $true) {
			# If The Connection Check Is OK
			# Connect To The RootDSE Of The RWDC
			$rwdcRootDSEObj = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$rwdcRootDSEObj = [ADSI]"LDAP://$rwdcFQDN/rootDSE"
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Connecting To '$rwdcFQDN' For 'rootDSE'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
			If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$rwdcRootDSEObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$rwdcFQDN/rootDSE"), $adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Connecting To '$rwdcFQDN' For 'rootDSE' Using '$adminUserAccountRemoteForest'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
			If ([string]::IsNullOrEmpty($rwdcRootDSEObj.Path)) {
				# If It Throws An Error Then The RWDC Is Not Available/Reachable And Increase The Counter Of Unreachable RWDCs
				$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $false
				$nrOfUnReachableRWDCs += 1

			} Else {
				# If It Does Not Throw An Error Then The RWDC Is Available/Reachable And Increase The Counter Of Reachable RWDCs
				$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $true
				$nrOfReachableRWDCs += 1
			}
		} Else {
			# If The Connection Check Is Not OK Then The RWDC Is Not Available/Reachable And Increase The Counter Of Unreachable RWDCs
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $false
			$nrOfUnReachableRWDCs += 1
		}

		If (($tableOfADDomainsInADForest | Where-Object { $_.Name -eq $($script:targetedADdomainFQDN) }).PDCFsmoOwner -eq $rwdcFQDN) {
			# If The RWDC Is The RWDC With The PDC FSMO, Then Do Not Specify A Source RWDC As The RWDC With The PDC FSMO Is The Source Originating RWDC
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC FQDN" -Value "N.A."
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC DSA" -Value "N.A."
		} Else {
			# If The RWDC Is Not The RWDC With The PDC FSMO, Then Specify A Source RWDC Being The RWDC With The PDC FSMO As The Source Originating RWDC
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC FQDN" -Value $($script:targetedADdomainRWDCFQDNWithPDCFSMOFQDN)
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC DSA" -Value $($script:targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN)
		}

		# Increase The Counter For The Number Of RWDCs
		$nrOfRWDCs += 1

		# Add The Row For The RWDC To The Table
		$tableOfDCsInADDomain.Add($tableOfDCsInADDomainObj)
	}
}

# Retrieve All The RODCs In The AD Domain
$listOfRODCsInADDomain = $dcsInADDomain | Where-Object { $_."msDS-isRODC" -eq $true -And $_.primaryGroupID -eq "521" -And $_."msDS-KrbTgtLink" -match "^CN=krbtgt_\d.*" }

# Set The Counters To Zero
$nrOfRODCs = 0
$nrOfReachableRODCs = 0
$nrOfUnReachableRODCs = 0
$nrOfUnDetermined = 0

# Execute For All RODCs In The AD Domain
Write-Host ""
writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "Processing Data Of All The Discovered Read-Only DCs (RODCs) - NO CHANGES!!!..." -logFileOnly $false -noDateTimeInLogLine $false
$nrOfRODCsToProcess = ($listOfRODCsInADDomain | Measure-Object).Count
$nrOfRODCsProcessed = 0
If ($listOfRODCsInADDomain) {
	$listOfRODCsInADDomain | ForEach-Object {
		$nrOfRODCsProcessed += 1

		# Get The FQDN Of The RODC
		$rodcFQDN = $null
		$rodcFQDN = $_.dNSHostName

		writeLog -dataToLog " > $($nrOfRODCsProcessed.ToString().PadLeft($($nrOfRODCsToProcess.ToString().Length), '0')) Of $nrOfRODCsToProcess" -lineType "REMARK-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false

		# Get The NTDS Settings Object Of THe RODC
		$rodcObjNTDSSettingsObjectDN = "CN=NTDS Settings," + $_.serverReferenceBL

		# Define The Columns For The RODCs In The AD Domain To Be Filled In
		$tableOfDCsInADDomainObj = [PSCustomObject]@{
			"Host Name" = $rodcFQDN
			"PDC"       = $false
			"Site Name" = $(If ($_.OperatingSystem) { $_.serverReferenceBL.Split(",")[2].Replace("CN=", "") } Else { "Unknown" })
			"DS Type"   = "Read-Only"
		}

		# Retrieve The Object Of The KrbTgt Account
		$rodcKrbTgtSamAccountName = $null
		$rodcKrbTgtObject = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos

				# Use The PROD/REAL KrbTgt Account Of The RODC, Or Use It As The Base For The TEST/BOGUS KrbTgt Account Of The RODC
				$rodcKrbTgtSamAccountName = (Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(sAMAccountName=krbtgt*)(msDS-KrbTgtLinkBl=$($_.distinguishedName)))" -PropertiesToLoad @("sAMAccountName")).sAMAccountName

				# The TEST/BOGUS KrbTgt Account Of The RODC
				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {
					$rodcKrbTgtSamAccountName = $rodcKrbTgtSamAccountName + "_TEST"
				}
				$rodcKrbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN)-searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$rodcKrbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

				# When Using The PROD/REAL KrbTgt Account Of The RODC
				If ($modeOfOperationNr -eq 1 -Or $modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6 -Or $modeOfOperationNr -eq 7) {
					writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' To Determine The PROD/REAL KrbTgt Account In Use By '$rodcFQDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}

				# When Using The PROD/REAL KrbTgt Account Of The RODC
				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {
					writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' To Determine The TEST/BOGUS KrbTgt Account In Use By '$rodcFQDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
			Try {
				$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos -Credential $adminCrds

				# Use The PROD/REAL KrbTgt Account Of The RODC, Or Use It As The Base For The TEST/BOGUS KrbTgt Account Of The RODC
				$rodcKrbTgtSamAccountName = (Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(sAMAccountName=krbtgt*)(msDS-KrbTgtLinkBl=$($_.distinguishedName)))" -PropertiesToLoad @("sAMAccountName")).sAMAccountName

				# The TEST/BOGUS KrbTgt Account Of The RODC
				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {
					$rodcKrbTgtSamAccountName = $rodcKrbTgtSamAccountName + "_TEST"
				}
				$rodcKrbTgtObject = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$rodcKrbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
				$ldapConnection.Dispose()
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' To Determine The KrbTgt Account In Use By '$rodcFQDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				# When Using The PROD/REAL KrbTgt Account Of The RODC
				If ($modeOfOperationNr -eq 1 -Or $modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6 -Or $modeOfOperationNr -eq 7) {
					writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' To Determine The PROD/REAL KrbTgt Account In Use By '$rodcFQDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
				# When Using The PROD/REAL KrbTgt Account Of The RODC
				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {
					writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' To Determine The TEST/BOGUS KrbTgt Account In Use By '$rodcFQDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Krb Tgt" -Value $rodcKrbTgtSamAccountName

		$rodcKrbTgtObjectDN = $null
		$rodcKrbTgtPwdLastSet = $null
		$rodcKrbTgtObjectMetadata = $null
		$rodcKrbTgtObjectMetadataAttribPwdLastSet = $null
		$rodcKrbTgtObjectMetadataAttribPwdLastSetOrgRWDCFQDN = $null
		$rodcKrbTgtObjectMetadataAttribPwdLastSetOrgTime = $null
		$rodcKrbTgtObjectMetadataAttribPwdLastSetVersion = $null
		If ($rodcKrbTgtObject) {
			# If The Object Of The KrbTgt Account Exists
			# Retrieve The DN OF The Object
			$rodcKrbTgtObjectDN = $rodcKrbTgtObject.DistinguishedName

			# Retrieve The Password Last Set Value Of The KrbTgt Account
			$rodcKrbTgtPwdLastSet = Get-Date $([datetime]::fromfiletime($rodcKrbTgtObject.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"

			# Retrieve The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object
			$rodcKrbTgtObjectMetadata = retrieveObjectMetadata -targetedADdomainRWDCFQDN $($script:targetedADdomainNearestRWDCFQDN) -ObjectDN $rodcKrbTgtObjectDN -localADforest $localADforest -adminCrds $adminCrds
			$rodcKrbTgtObjectMetadataAttribPwdLastSet = $rodcKrbTgtObjectMetadata | Where-Object { $_.Name -eq "pwdLastSet" }
			$rodcKrbTgtObjectMetadataAttribPwdLastSetOrgRWDCFQDN = If ($rodcKrbTgtObjectMetadataAttribPwdLastSet.OriginatingServer) { $rodcKrbTgtObjectMetadataAttribPwdLastSet.OriginatingServer } Else { "RWDC Demoted" }
			$rodcKrbTgtObjectMetadataAttribPwdLastSetOrgTime = Get-Date $($rodcKrbTgtObjectMetadataAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
			$rodcKrbTgtObjectMetadataAttribPwdLastSetVersion = $rodcKrbTgtObjectMetadataAttribPwdLastSet.Version
		} Else {
			# If The Object Of The KrbTgt Account Does Not Exist
			$rodcKrbTgtPwdLastSet = "No Such Object"
			$rodcKrbTgtObjectMetadataAttribPwdLastSet = "No Such Object"
			$rodcKrbTgtObjectMetadataAttribPwdLastSetOrgRWDCFQDN = "No Such Object"
			$rodcKrbTgtObjectMetadataAttribPwdLastSetOrgTime = "No Such Object"
			$rodcKrbTgtObjectMetadataAttribPwdLastSetVersion = "No Such Object"
		}
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Pwd Last Set" -Value $rodcKrbTgtPwdLastSet
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Org RWDC" -Value $rodcKrbTgtObjectMetadataAttribPwdLastSetOrgRWDCFQDN
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Org Time" -Value $rodcKrbTgtObjectMetadataAttribPwdLastSetOrgTime
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Ver" -Value $rodcKrbTgtObjectMetadataAttribPwdLastSetVersion
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $(Try { (([System.Net.Dns]::GetHostEntry($rodcFQDN)).AddressList | Where-Object { $_.AddressFamily -eq "InterNetwork" }).IPAddressToString } Catch { "Unknown" })
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "OS Version" -Value $($_.OperatingSystem)

		# Define The Ports To Check Against
		$ports = 389 # LDAP

		# Define The Connection Check To Be True Initially
		$connectionCheckOK = $true

		# For Every Defined Port Check The Connection And Report
		$failedPorts = [System.Collections.Generic.List[Object]]::New()
		$ports | ForEach-Object {
			# Set The Port To Check Against
			$port = $null
			$port = $_

			# Test The Connection To The Server Using The Port
			$connectionResult = $null
			$connectionResult = portConnectionCheck -serverIPOrFQDN $rodcFQDN -port $port -timeOut $connectionTimeout
			If ($connectionResult -eq "ERROR") {
				$failedPorts.Add($port)
				$script:connectionCheckOK = $false
			}
		}
		If ($connectionCheckOK -eq $true) {
			# If The Connection Check Is OK
			# Connect To The RootDSE Of The RODC
			$rodcRootDSEObj = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$rodcRootDSEObj = [ADSI]"LDAP://$rodcFQDN/rootDSE"
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Connecting To '$rodcFQDN' For 'rootDSE'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
			If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
				Try {
					$rodcRootDSEObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$rodcFQDN/rootDSE"), $adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error Connecting To '$rodcFQDN' For 'rootDSE' Using '$adminUserAccountRemoteForest'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
			}
			If ([string]::IsNullOrEmpty($rodcRootDSEObj.Path)) {
				# If It Throws An Error Then The RODC Is Not Available/Reachable And Increase The Counter Of Unreachable RODCs
				$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $false
				$nrOfUnReachableRODCs += 1
			} Else {
				# If It Does Not Throw An Error Then The RWDC Is Available/Reachable And Increase The Counter Of Reachable RODCs
				$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $true
				$nrOfReachableRODCs += 1
			}
		} Else {
			# If The Connection Check Is Not OK Then The RWDC Is Not Available/Reachable And Increase The Counter Of Unreachable RODCs
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $false
			$nrOfUnReachableRODCs += 1
		}

		If ($_.OperatingSystem) {
			# If The RODC Has An Operating System Specified, Then It Is Most Likely A Windows RODC
			If ($tableOfDCsInADDomainObj.Reachable -eq $true) {
				# If The RODC Is Available/Reachable
				# Define An LDAP Query With A Search Base And A Filter To Determine The DSA DN Of The Source RWDC Of The RODC
				$dsDirSearcher = $null
				$dsDirSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
				$dsDirSearcher.SearchRoot = $null
				If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
					$dsDirSearcher.SearchRoot = "LDAP://$rodcFQDN/$rodcObjNTDSSettingsObjectDN"
				}
				If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
					$dsDirSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$rodcFQDN/$rodcObjNTDSSettingsObjectDN"), $adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
				}
				$dsDirSearcher.Filter = $null
				$dsDirSearcher.Filter = "(&(objectClass=nTDSConnection)(options:1.2.840.113556.1.4.803:=64))" # Targeting The CO Called "CN=RODC Connection (SYSVOL),CN=NTDS Settings,CN=<RODC NAME>,CN=Servers,CN=<SITE>,CN=Sites,CN=Configuration,DC=<DOMAIN>,DC=<TLD>" ONLY
				$sourceRWDCsNTDSSettingsObjectDN = $null
				Try {
					$sourceRWDCsNTDSSettingsObjectDN = $dsDirSearcher.FindAll().Properties.fromserver
				} Catch {
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
						writeLog -dataToLog "Error Querying AD Against '$rodcFQDN' For Object '$rodcObjNTDSSettingsObjectDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					}
					If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
						writeLog -dataToLog "Error Querying AD Against '$rodcFQDN' For Object '$rodcObjNTDSSettingsObjectDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					}
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}

				# For Every DSA DN Of The Source RWDC Retrieved
				$sourceRWDCsNTDSSettingsObjectDN | ForEach-Object {
					$sourceRWDCNTDSSettingsObjectDN = $null
					$sourceRWDCNTDSSettingsObjectDN = $_

					# Strip "CN=NTDS Settings," To End Up With The Server Object DN
					$sourceRWDCServerObjectDN = $null
					$sourceRWDCServerObjectDN = $sourceRWDCNTDSSettingsObjectDN.SubString(("CN=NTDS Settings,").Length)

					# Connect To The Server Object DN
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
						Try {
							$sourceRWDCServerObjectObj = ([ADSI]"LDAP://$($script:targetedADdomainNearestRWDCFQDN)/$sourceRWDCServerObjectDN")
						} Catch {
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error Connecting To '$($script:targetedADdomainNearestRWDCFQDN)' For Object '$sourceRWDCServerObjectDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						}
					}
					If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
						Try {
							$sourceRWDCServerObjectObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$($script:targetedADdomainNearestRWDCFQDN)/$sourceRWDCServerObjectDN"), $adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
						} Catch {
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error Connecting To '$($script:targetedADdomainNearestRWDCFQDN)' For Object '$sourceRWDCServerObjectDN' Using '$adminUserAccountRemoteForest'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						}
					}

					If ($userIsSystem -eq $true) {
						# When The Script Runs As SYSTEM, The HostName Of Source RWDC To Be Used By The RODC, Being The RWDC With The PDC FSMO Role
						$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC FQDN" -Value $($script:targetedADdomainRWDCFQDNWithPDCFSMOFQDN)

						# When The Script Runs As SYSTEM, The DSA DN Of Source RWDC To Be Used By The RODC, Being The RWDC With The PDC FSMO Role
						$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC DSA" -Value $($script:targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN)
					} Else {
						# When The Script DOES NOT Run As SYSTEM, But Rather As A High-Privileged User Account, The HostName Of The Real Source RWDC To Be Used By The RODC
						$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC FQDN" -Value $sourceRWDCServerObjectObj.dnshostname[0]

						# When The Script DOES NOT Run As SYSTEM, But Rather As A High-Privileged User Account, The DSA DN Of The Real Source RWDC To Be Used By The RODC
						$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC DSA" -Value $sourceRWDCsNTDSSettingsObjectDN[0]
					}
				}
			} Else {
				# If The RODC Is Available/Reachable
				$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC FQDN" -Value "RODC Unreachable"
				$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC DSA" -Value "RODC Unreachable"
			}
		} Else {
			# If The RODC Does Not Have An Operating System Specified, Then It Is Most Likely Not A Windows RODC
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC FQDN" -Value "Unknown"
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC DSA" -Value "Unknown"
		}

		If ($_.OperatingSystem) {
			# If The RODC Has An Operating System Specified, Then It Is Most Likely A Windows RODC, Therefore Increase The Counter For Real RODCs
			$nrOfRODCs += 1
		} Else {
			# If The RODC Does Not Have An Operating System Specified, Then It Is Most Likely Not A Windows RODC, Therefore Increase The Counter For Unknown RODCs
			$nrOfUnDetermined += 1
		}
		# Add The Row For The RODC To The Table
		$tableOfDCsInADDomain.Add($tableOfDCsInADDomainObj)
	}
}

# Sort The Table With DCs In The AD Domain In The Order "DS Type" (Read/Write At The Top), Then If It Is The PDC Or Not (PDC At The Top), Then If It Is Reachable Or Not (Reachable At the Top)
$tableOfDCsInADDomain = $tableOfDCsInADDomain | Sort-Object -Property @{Expression = "DS Type"; Descending = $false }, @{Expression = "PDC"; Descending = $true }, @{Expression = "Reachable"; Descending = $true }

# Determine The Number Of DCs Based Upon The Number Of RWDCs And The Number Of RODCs
$nrOfDCs = $nrOfRWDCs + $nrOfRODCs

# Display The Information
Write-Host ""
writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "List Of Domain Controllers In AD Domain '$($script:targetedADdomainFQDN)'..."
writeLog -dataToLog "$($tableOfDCsInADDomain | Format-Table * -Autosize | Out-String -Width 1024)"
writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "REMARKS:" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog " - 'N.A.' in the columns 'Source RWDC FQDN' and 'Source RWDC DSA' means the RWDC is considered as the master for this script." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog " - 'RODC Unreachable' in the columns 'Source RWDC FQDN' and 'Source RWDC DSA' means the RODC cannot be reached to determine its replicating source" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "     RWDC/DSA. The unavailability can be due to firewalls/networking or the RODC actually being down." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog " - 'Unknown' in various columns means that an RODC was found that may not be a true Windows Server RODC. It may be an appliance acting as an RODC." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog " - 'RWDC Demoted' in the column 'Org RWDC' means the RWDC existed once, but it does not exist anymore as it has been decommissioned in the past." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "     This is normal." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog " - 'No Such Object' in the columns 'Pwd Last Set', 'Org RWDC', 'Org Time' or 'Ver' means the targeted object was not found in the AD domain." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "     Although this is possible for any targeted object, this is most likely the case when targeting the TEST/BOGUS KrbTgt Accounts and if those" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "     do not exist yet. This may also occur for an appliance acting as an RODC as in that case no KrbTgt TEST/BOGUS account is created." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
$krbTgtAADname = "krbtgt_AzureAD"
Try {
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
		$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos
		$krbTgtAAD = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(name=$krbTgtAADname))"
		$ldapConnection.Dispose()
	}
	If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
		$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos -Credential $adminCrds
		$krbTgtAAD = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(name=$krbTgtAADname))"
		$ldapConnection.Dispose()
	}
} Catch {
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' To Determine If An Azure AD KrbTgt Account Existed..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
}
If ($krbTgtAAD) {
	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "WARNING:" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " - This is a WARNING message for you to READ and ACT ON, and NOT an error. The script WILL NOT reset the password of the '$krbTgtAADname' account!" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " - In this AD domain '$($script:targetedADdomainFQDN)' the special purpose krbtgt account '$krbTgtAADname' for Azure AD was found (not listed in the table above though!)!" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " - DO NOT reset the password of this krbtgt account in any way except using the official method to reset the password and rotate the keys" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "     (See: - https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-passwordless-security-key-on-premises)" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " - To reset the password and rotate the keys of the krbtgt account '$krbTgtAADname' perform the following steps:" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "    * Go to an Azure AD Connect server (v1.4.32.0 or later)" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "    * Open a PowerShell Command Prompt window" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "    * In that window execute the following commands:" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       # Import The PowerShell Module For Azure AD Kerberos Server" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       Import-Module `"C:\Program Files\Microsoft Azure Active Directory Connect\AzureADKerberos\AzureAdKerberos.psd1`"" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       # AD Domain/Enterprise Admin Credentials" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       `$adDomainAdminAccount = Read-Host `"AD Admin Account`"" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       `$adDomainAdminPassword = Read-Host `"AD Admin Account Password`" -AsSecureString" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       `$secureAdDomainAdminPassword = ConvertTo-SecureString `$adDomainAdminPassword -AsPlainText -Force" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       `$adDomainAdminCreds = New-Object System.Management.Automation.PSCredential `$adDomainAdminAccount, `$secureAdDomainAdminPassword" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       # Azure AD Global Admin Credentials" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       `$aadDomainAdminAccount = Read-Host `"Azure AD Admin Account`"" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       `$aadDomainAdminPassword = Read-Host `"Azure AD Admin Account Password`" -AsSecureString" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       [string]`$aadDomainAdminPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR(`$aadDomainAdminPassword))" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       `$secureAadDomainAdminPassword = ConvertTo-SecureString `$aadDomainAdminPassword -AsPlainText -Force" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       `$aadDomainAdminCreds = New-Object System.Management.Automation.PSCredential `$aadDomainAdminAccount, `$secureAadDomainAdminPassword" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       # Check the CURRENT status of the Azure AD Kerberos Server object in Active Directory" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       Get-AzureADKerberosServer -Domain $($script:targetedADdomainFQDN) -DomainCredential `$adDomainAdminCreds -CloudCredential `$aadDomainAdminCreds" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       # Reset the password and rotate the keys" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       Set-AzureADKerberosServer -Domain $($script:targetedADdomainFQDN) -DomainCredential `$adDomainAdminCreds -CloudCredential `$aadDomainAdminCreds -RotateServerKey" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       # Check the NEW status of the Azure AD Kerberos Server object in Active Directory" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "       Get-AzureADKerberosServer -Domain $($script:targetedADdomainFQDN) -DomainCredential `$adDomainAdminCreds -CloudCredential `$aadDomainAdminCreds" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "    REMARK: Make sure the 'KeyVersion' value matches the 'CloudKeyVersion' value and the 'KeyUpdatedOn' value matches the 'CloudKeyUpdatedOn' value!" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
}
writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> Found [$nrOfDCs] Real DC(s) In AD Domain..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> Found [$nrOfRWDCs] RWDC(s) In AD Domain..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> Found [$nrOfReachableRWDCs] Reachable RWDC(s) In AD Domain..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> Found [$nrOfUnReachableRWDCs] UnReachable RWDC(s) In AD Domain..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> Found [$nrOfRODCs] RODC(s) In AD Domain..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> Found [$nrOfReachableRODCs] Reachable RODC(s) In AD Domain..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> Found [$nrOfUnReachableRODCs] UnReachable RODC(s) In AD Domain..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> Found [$nrOfUnDetermined] Undetermined RODC(s) In AD Domain..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

###
# Mode 2 And 3 And 4 and 5 And 6 And 8 And 9 Only - Making Sure The RWDC With The PDC FSMO And The Nearest RWDC Are Reachable/Available
###
If ($modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {
	$abortDueToUnreachable = $false

	If (($tableOfDCsInADDomain | Where-Object { $_.PDC -eq $true }).Reachable -eq $false) {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "  --> The RWDC With The PDC FSMO Role '$($script:targetedADdomainRWDCFQDNWithPDCFSMOFQDN)' IS NOT Reachable For The Ports '$($ports -join ', ')'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		$abortDueToUnreachable = $true
	}

	If (($tableOfDCsInADDomain | Where-Object { $_."Host Name" -eq $($script:targetedADdomainNearestRWDCFQDN) }).Reachable -eq $false) {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "  --> The Nearest RWDC '$($script:targetedADdomainNearestRWDCFQDN)' IS NOT Reachable For The Ports '$($ports -join ', ')'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		$abortDueToUnreachable = $true
	}

	If ($abortDueToUnreachable -eq $true) {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "  --> Due To Unavailability Issues Of The RWDC With The PDC FSMO Role And/Or The Nearest RWDC, The Script Cannot Continue ..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "  --> Both The RWDC With The PDC FSMO Role And The The Nearest RWDC MUST Be Available/Reachable..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		# Mail The Log File With The Results
		If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
			$context = "SCRIPT ABORT - ERROR: Due to unavailability issues of the RWDC with the PDC FSMO role and/or the nearest RWDC, the script cannot continue"

			sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
		}

		EXIT
	}
}

###
# Mode 2 And 3 And 4 and 5 And 6 Only - Selecting The KrbTgt Account To Target And Scope If Applicable (Only Applicable To RODCs)
###
If ($modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6 -Or $modeOfOperationNr -eq 7) {
	writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "SELECT THE SCOPE OF THE KRBTGT ACCOUNT(S) TO TARGET..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
	writeLog -dataToLog "Which KrbTgt account do you want to target?"
	writeLog -dataToLog ""
	writeLog -dataToLog " - 1 - Scope of KrbTgt in use by all RWDCs in the AD Domain"
	writeLog -dataToLog ""
	If ($nrOfRODCs -gt 0) {
		writeLog -dataToLog " - 2 - Scope of KrbTgt in use by specific RODC - Single/Multiple RODC(s) in the AD Domain"
		writeLog -dataToLog ""
		writeLog -dataToLog " - 3 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain"
		writeLog -dataToLog ""
		writeLog -dataToLog " - 4 - Scope of ANY KrbTgt in use by ANY DC - All RWDCs/RODCs in the AD Domain"
		writeLog -dataToLog ""
	}
	writeLog -dataToLog ""
	writeLog -dataToLog " - 0 - Exit Script"
	writeLog -dataToLog ""
	Switch ($targetKrbTgtAccountScope) {
		"allRWDCs" { $targetKrbTgtAccountNr = 1 }
		"specificRODCs"	{ $targetKrbTgtAccountNr = 2 }
		"allRODCs" { $targetKrbTgtAccountNr = 3 }
		"allRWDCsAndRODCs" { $targetKrbTgtAccountNr = 4 }
		Default { $targetKrbTgtAccountNr = $null }
	}
	If ([string]::IsNullOrEmpty($targetKrbTgtAccountNr)) {
		writeLog -dataToLog "Please specify the scope of KrbTgt Account to target: " -lineType "ACTION-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false
		$targetKrbTgtAccountNr = Read-Host
	} Else {
		writeLog -dataToLog "Please specify the scope of KrbTgt Account to target: $targetKrbTgtAccountNr" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	}
	writeLog -dataToLog ""

	# If Anything Else Than The Allowed/Available Non-Zero KrbTgt Accounts, Abort The Script
	If (($targetKrbTgtAccountNr -ne 1 -And $targetKrbTgtAccountNr -ne 2 -And $targetKrbTgtAccountNr -ne 3 -And $targetKrbTgtAccountNr -ne 4) -Or $targetKrbTgtAccountNr -notmatch "^[\d\.]+$") {
		writeLog -dataToLog "  --> Chosen Scope KrbTgt Account Target: 0 - Exit Script..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""

		If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
			$context = "SCRIPT ABORT - ERROR: A wrong/non-existent target KrbTgt scope was selected!"

			sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
		}

		EXIT
	}

	# If KrbTgt Account Scope 1
	If ($targetKrbTgtAccountNr -eq 1) {
		$targetKrbTgtAccountDescription = "1 - Scope of KrbTgt in use by all RWDCs in the AD Domain..."
	}

	# If KrbTgt Account Scope 2
	If ($targetKrbTgtAccountNr -eq 2) {
		$targetKrbTgtAccountDescription = "2 - Scope of KrbTgt in use by specific RODC - Single/Multiple RODC(s) in the AD Domain..."
	}

	# If KrbTgt Account Scope 3
	If ($targetKrbTgtAccountNr -eq 3) {
		$targetKrbTgtAccountDescription = "3 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain..."
	}
	# If KrbTgt Account Scope 4
	If ($targetKrbTgtAccountNr -eq 4) {
		$targetKrbTgtAccountDescription = "4 - Scope of ANY KrbTgt in use by ANY DC - All RWDCs/RODCs in the AD Domain..."
	}
	writeLog -dataToLog "  --> Chosen Scope KrbTgt Account Target: $targetKrbTgtAccountDescription" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""

	# Present List Of RODCs When Option 2 Or 3 Is Chosen To Make It Easier To Chose From
	# Specify A Comma Separated List Of FQDNs Of RODCs To Target (Single/Multiple)
	If ($targetKrbTgtAccountNr -eq 2) {
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "List Of Read-Only Domain Controllers In AD Domain '$($script:targetedADdomainFQDN)'..."
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "$($tableOfDCsInADDomain | Where-Object{$_.'DS Type' -eq 'Read-Only'} | Format-Table 'Host Name','DS Type','Krb Tgt','Pwd Last Set','Reachable' -Autosize | Out-String -Width 1024)"
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

		If ($($targetRODCFQDNList | Measure-Object).Count -eq 0) {
			writeLog -dataToLog "Specify a single, or comma-separated list of FQDNs of RODCs for which the KrbTgt Account Password must be reset: " -lineType "ACTION-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false
			$targetDCFQDNList = Read-Host
			$targetDCFQDNList = $targetDCFQDNList.Split(",")
		} Else {
			$targetDCFQDNList = $targetRODCFQDNList
		}
		writeLog -dataToLog ""
		writeLog -dataToLog "  --> Specified RODCs:" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		$targetDCFQDNList | ForEach-Object {
			writeLog -dataToLog "       * $($_)" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		}
		writeLog -dataToLog ""
	}
}

###
# Mode 2/3/5 - Simulation Mode
# Mode 4/6 - Real Reset Mode
# Mode 7 - Golden Ticket Monitoring
###
If ($modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6 -Or $modeOfOperationNr -eq 7) {
	# Mode 2 - Simulation Mode - TEMPORARY CANARY OBJECT
	If ($modeOfOperationNr -eq 2) {
		writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "SIMULATION MODE (MODE $modeOfOperationNr) - CREATING/REPLICATING TEMPORARY CANARY OBJECT TO TEST REPLICATION CONVERGENCE" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "SCOPE: $targetKrbTgtAccountDescription" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""
	}

	# Mode 3 - Simulation Mode - SCOPED TEST/BOGUS KRBTGT ACCOUNT(S)
	If ($modeOfOperationNr -eq 3) {
		writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "SIMULATION MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED TEST/BOGUS KRBTGT ACCOUNT(S) (WHAT IF MODE)" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "SCOPE: $targetKrbTgtAccountDescription" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""
	}

	# Mode 4 - Real Reset Mode - SCOPED TEST/BOGUS KRBTGT ACCOUNT(S)
	If ($modeOfOperationNr -eq 4) {
		writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "REAL RESET MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED TEST/BOGUS KRBTGT ACCOUNT(S)" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "SCOPE: $targetKrbTgtAccountDescription" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""
	}

	# Mode 5 - Simulation Mode - SCOPED PROD/REAL KRBTGT ACCOUNT(S)
	If ($modeOfOperationNr -eq 5) {
		writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "SIMULATION MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED PROD/REAL KRBTGT ACCOUNT(S) (WHAT IF MODE)" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "SCOPE: $targetKrbTgtAccountDescription" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""
	}

	# Mode 6 - Real Reset Mode - SCOPED PROD/REAL KRBTGT ACCOUNT(S)
	If ($modeOfOperationNr -eq 6) {
		writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "REAL RESET MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED PROD/REAL KRBTGT ACCOUNT(S)" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "SCOPE: $targetKrbTgtAccountDescription" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""
	}

	# Mode 7 - Golden Ticket Monitor Mode | Checking Domain Controllers For Event ID 4769 With Specific Error Codes
	If ($modeOfOperationNr -eq 7) {
		writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "GOLDEN TICKET MONITOR MODE (MODE $modeOfOperationNr) - GOLDEN TICKET MONITOR MODE | CHECKING DOMAIN CONTROLLERS FOR EVENT ID 4769 WITH SPECIFIC ERROR CODES" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "SCOPE: $targetKrbTgtAccountDescription" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog ""
	}

	# Asking Confirmation To Continue Or Not
	$continueOrStop = $null
	If ($argsCount -ge 1 -And $continueOps) {
		$continueOrStop = "CONTINUE"
		writeLog -dataToLog "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: $continueOrStop" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	} Else {
		writeLog -dataToLog "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: " -lineType "ACTION-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false
		$continueOrStop = Read-Host
	}

	# Any Confirmation Not Equal To CONTINUE Will Be Equal To STOP
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		$continueOrStop = "STOP"
	}
	writeLog -dataToLog ""
	writeLog -dataToLog "  --> Chosen: $continueOrStop" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""

	# Any Confirmation Not Equal To CONTINUE Will Abort The Script
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		# Mail The Log File With The Results
		If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
			$context = "SCRIPT - NORMAL OPS: The script was told to stop and not to continue!"

			sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
		}

		EXIT
	}

	$collectionOfDCsToProcess = [System.Collections.Generic.List[Object]]::New()
	$collectionOfDCsNotToProcess = [System.Collections.Generic.List[Object]]::New()
	# For The KrbTgt Account Scope Of All RWDCs
	If ($targetKrbTgtAccountNr -eq 1 -Or $targetKrbTgtAccountNr -eq 4) {
		# Collection Of DCs To Process
		If ($modeOfOperationNr -eq 7) {
			# Collection Of Reachable RWDCs
			$collectionOfRWDCsToProcessReachable = [System.Collections.Generic.List[Object]]::New()
			$tableOfDCsInADDomain | Where-Object { $_."DS Type" -eq "Read/Write" -And $_.Reachable -eq $true } | ForEach-Object {
				$collectionOfRWDCsToProcessReachable.Add($_)
			}

			# Collection Of UnReachable RWDCs
			$collectionOfRWDCsToProcessUnReachable = [System.Collections.Generic.List[Object]]::New()
			$tableOfDCsInADDomain | Where-Object { $_."DS Type" -eq "Read/Write" -And $_.Reachable -eq $false } | ForEach-Object {
				$collectionOfRWDCsToProcessUnReachable.Add($_)
			}

			# Collection Of DCs To Process
			$collectionOfRWDCsToProcessReachable | ForEach-Object {
				$collectionOfDCsToProcess.Add($_)
			}

			# Collection Of DCs NOT To Process
			$collectionOfRWDCsToProcessUnReachable | ForEach-Object {
				$collectionOfDCsNotToProcess.Add($_)
			}
		} Else {
			# RWDC With PDC FSMO Role Only
			$tableOfDCsInADDomain | Where-Object { $_.PDC -eq $true } | ForEach-Object {
				$collectionOfDCsToProcess.Add($_)
			}
		}
	}

	# For The KrbTgt Account Scope Of Specified, But Individual RODCs
	If ($targetKrbTgtAccountNr -eq 2) {
		# Collection Of Reachable RODCs
		$collectionOfRODCsToProcessReachable = [System.Collections.Generic.List[Object]]::New()
		$tableOfDCsInADDomain | Where-Object { $_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $true -And $_."Source RWDC FQDN" -ne "Unknown" -And $_."Source RWDC FQDN" -ne "RODC Unreachable" -And $targetDCFQDNList -contains $_."Host Name" } | ForEach-Object {
			$collectionOfRODCsToProcessReachable.Add($_)
		}

		# Collection Of UnReachable RODCs
		$collectionOfRODCsToProcessUnReachable = [System.Collections.Generic.List[Object]]::New()
		$tableOfDCsInADDomain | Where-Object { $_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $false -And $_."Source RWDC FQDN" -eq "RODC Unreachable" -And $targetDCFQDNList -contains $_."Host Name" } | ForEach-Object {
			$collectionOfRODCsToProcessUnReachable.Add($_)
		}

		# Collection Of Unknown RODCs
		$collectionOfRODCsToProcessUnknown = [System.Collections.Generic.List[Object]]::New()
		$tableOfDCsInADDomain | Where-Object { $_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $false -And $_."Source RWDC FQDN" -eq "Unknown" -And $targetDCFQDNList -contains $_."Host Name" } | ForEach-Object {
			$collectionOfRODCsToProcessUnknown.Add($_)
		}

		# Collection Of DCs To Process
		$collectionOfRODCsToProcessReachable | ForEach-Object {
			$collectionOfDCsToProcess.Add($_)
		}

		If ($modeOfOperationNr -eq 7) {
			# Collection Of DCs NOT To Process
			$collectionOfRODCsToProcessUnReachable | ForEach-Object {
				$collectionOfDCsNotToProcess.Add($_)
			}
			$collectionOfRODCsToProcessUnknown | ForEach-Object {
				$collectionOfDCsNotToProcess.Add($_)
			}
		} Else {
			# Collection Of DCs To Process
			$collectionOfRODCsToProcessUnReachable | ForEach-Object {
				$collectionOfDCsToProcess.Add($_)
			}

			# Collection Of DCs NOT To Process
			$collectionOfRODCsToProcessUnknown | ForEach-Object {
				$collectionOfDCsNotToProcess.Add($_)
			}
		}
	}

	# For The KrbTgt Account Scope Of Each Individual RODCs
	If ($targetKrbTgtAccountNr -eq 3 -Or $targetKrbTgtAccountNr -eq 4) {
		# Collection Of Reachable RODCs
		$collectionOfRODCsToProcessReachable = [System.Collections.Generic.List[Object]]::New()
		$tableOfDCsInADDomain | Where-Object { $_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $true -And $_."Source RWDC FQDN" -ne "Unknown" -And $_."Source RWDC FQDN" -ne "RODC Unreachable" } | ForEach-Object {
			$collectionOfRODCsToProcessReachable.Add($_)
		}

		# Collection Of UnReachable RODCs
		$collectionOfRODCsToProcessUnReachable = [System.Collections.Generic.List[Object]]::New()
		$tableOfDCsInADDomain | Where-Object { $_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $false -And $_."Source RWDC FQDN" -eq "RODC Unreachable" } | ForEach-Object {
			$collectionOfRODCsToProcessUnReachable.Add($_)
		}

		# Collection Of Unknown RODCs
		$collectionOfRODCsToProcessUnknown = [System.Collections.Generic.List[Object]]::New()
		$tableOfDCsInADDomain | Where-Object { $_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $false -And $_."Source RWDC FQDN" -eq "Unknown" } | ForEach-Object {
			$collectionOfRODCsToProcessUnknown.Add($_)
		}

		# Collection Of DCs To Process
		$collectionOfRODCsToProcessReachable | ForEach-Object {
			$collectionOfDCsToProcess.Add($_)
		}

		# Collection Of DCs To Process
		If ($modeOfOperationNr -eq 7) {
			# Collection Of DCs NOT To Process
			$collectionOfRODCsToProcessUnReachable | ForEach-Object {
				$collectionOfDCsNotToProcess.Add($_)
			}
			$collectionOfRODCsToProcessUnknown | ForEach-Object {
				$collectionOfDCsNotToProcess.Add($_)
			}
		} Else {
			# Collection Of DCs To Process
			$collectionOfRODCsToProcessUnReachable | ForEach-Object {
				$collectionOfDCsToProcess.Add($_)
			}

			# Collection Of DCs NOT To Process
			$collectionOfRODCsToProcessUnknown | ForEach-Object {
				$collectionOfDCsNotToProcess.Add($_)
			}
		}
	}

	# If Any DC Exists In The List, Process it
	If ($($collectionOfDCsToProcess | Measure-Object).Count -gt 0) {
		# Only For Mode 7 To Make Sure The Required Security Option And Audit Setting Are Configured
		If ($modeOfOperationNr -eq 7) {
			# Required Security Option
			$requiredSecurityOptionAdvAudit = "Audit: Force Audit Policy Subcategory Settings (Windows Vista Or Later) To Override Audit Policy Category Settings|MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy"

			# Required Advanced Auditing Settings
			$requiredAdvAuditSettings = "Audit Kerberos Service Ticket Operations|{0cce9240-69ae-11d9-bed3-505054503030}|Success|1"

			Try {
				writeLog -dataToLog ""
				writeLog -dataToLog "Checking If The Required Security Option And The Required Advanced Auditing Setting Are Being Used By DCs In The AD Domain '$($script:targetedADdomainFQDN)' By Executing A RSoP..."
				writeLog -dataToLog "  > Required Security Option..........: '$($requiredSecurityOptionAdvAudit.Split('|')[0])'"
				writeLog -dataToLog "  > Required Advanced Auditing Setting: '$($requiredAdvAuditSettings.Split('|')[0])'"

				# Execute An RSoP Against The Nearest RWDC In The Targeted AD Domain To Determine The Result Settings And The GPO(s) That Provided The Final Setting
				# Get The List Of GPOs That Were Processed For RSoP So We Can Map The GUID Back To Show Which GPO Won
				# Determine If The Required Security Option Is Already Being Used Or Not, And If The Required Advanced Audit Setting Is Already In Use For At Least Success
				If ($localADforest -eq $true) {
					# First Force A GP Update On The Local RWDC To Make Sure All Current Stuff Is Applied
					Invoke-GPUpdate -RandomDelayInMinutes 0 -Force
					Start-Sleep -s 10

					# Determine The User Account To Use During RSoP
					$accountToChooseForRSoP = determineUserAccountForRSoP -targetedADdomainNearestRWDCFQDN $($script:targetedADdomainNearestRWDCFQDN) -targetedADdomainDomainSID $targetedADdomainDomainSID

					# Run An RsOP To Determine In Which GPO, If Applicable, The Required Security Option And Audit Settings Have Been Configured And Which Should Be Used, And Export To XML File
					Get-GPResultantSetOfPolicy -Computer $($script:targetedADdomainNearestRWDCFQDN) -User $accountToChooseForRSoP -ReportType xml -Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_Audit_$($script:targetedADdomainFQDN)`_$($script:targetedADdomainNearestRWDCFQDN)`_$execDateTimeCustom.xml" -ErrorAction Stop > $null

					# Determine If The Required Security Option Is Configured And If The Required Advanced Auditing Setting Is Configured As Needed
					If (Test-Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_Audit_$($script:targetedADdomainFQDN)`_$($script:targetedADdomainNearestRWDCFQDN)`_$execDateTimeCustom.xml") {
						[xml]$gpRSoPxml = Get-Content "$($ENV:WINDIR + '\TEMP')\gpRSoP_Audit_$($script:targetedADdomainFQDN)`_$($script:targetedADdomainNearestRWDCFQDN)`_$execDateTimeCustom.xml"
						$gpoList = @{}
						$gpoList["NONE"] = "NONE_AVAILABLE"
						(Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop" }).Node.ComputerResults.GPO | ForEach-Object { $gpoList.Add($_.Path.Identifier."#text", $_.Name) }
						$rsopSecurityOptions = ((Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop" }).Node.ComputerResults.ExtensionData.Extension | Where-Object { Get-Member -InputObject $_ -Name SecurityOptions }).SecurityOptions | Where-Object { Get-Member -InputObject $_ -Name KeyName }
						$gpoWithRequiredSecurityOptionGpoGuid = $null
						If (-not ([string]::IsNullOrEmpty($($rsopSecurityOptions | Where-Object { $_.KeyName -eq $($requiredSecurityOptionAdvAudit.Split("|")[1]) })))) {
							$gpoWithRequiredSecurityOptionGpoGuid = ($rsopSecurityOptions | Where-Object { $_.KeyName -eq $($requiredSecurityOptionAdvAudit.Split("|")[1]) }).GPO.Identifier.'#text'
							$isRequiredSecurityOptionEnabled = $true
						} Else {
							$gpoWithRequiredSecurityOptionGpoGuid = "NONE"
							$isRequiredSecurityOptionEnabled = $false
						}
						writeLog -dataToLog "  --> Current GPO With Required Security Option: '$($gpoList[$gpoWithRequiredSecurityOptionGpoGuid])'..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog ""
						$rsopAdvancedAuditSettings = ((Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop" }).Node.ComputerResults.ExtensionData.Extension | Where-Object { Get-Member -InputObject $_ -Name AuditSetting }).AuditSetting
						$gpoWithRequiredAdvancedAuditSettingsGpoGuid = $null
						If (-not ([string]::IsNullOrEmpty($($rsopAdvancedAuditSettings | Where-Object { $_.SubcategoryName -eq $($requiredAdvAuditSettings.Split("|")[0]) })))) {
							If ($(($rsopAdvancedAuditSettings | Where-Object { $_.SubcategoryName -eq $($requiredAdvAuditSettings.Split("|")[0]) }).SettingValue -band $($requiredAdvAuditSettings.Split("|")[3])) -eq $($requiredAdvAuditSettings.Split("|")[3])) {
								$gpoWithRequiredAdvancedAuditSettingsGpoGuid = ($rsopAdvancedAuditSettings | Where-Object { $_.SubcategoryName -eq $($requiredAdvAuditSettings.Split("|")[0]) }).GPO.Identifier.'#text'
								$isRequiredAdvancedAuditSettingsEnabled = $true
							} Else {
								$gpoWithRequiredAdvancedAuditSettingsGpoGuid = "NONE"
								$isRequiredAdvancedAuditSettingsEnabled = $false
							}
						} Else {
							$gpoWithRequiredAdvancedAuditSettingsGpoGuid = "NONE"
							$isRequiredAdvancedAuditSettingsEnabled = $false
						}
						writeLog -dataToLog "  --> Current GPO With Required Advanced Auditing Setting: '$($gpoList[$gpoWithRequiredAdvancedAuditSettingsGpoGuid])'..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog ""
					} Else {
						$isRequiredSecurityOptionEnabled = $false
						$isRequiredAdvancedAuditSettingsEnabled = $false
						writeLog -dataToLog "  --> The Execution Of The RSoP Failed..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog ""
					}
				}
				If ($localADforest -eq $false) {
					If ([string]::IsNullOrEmpty($adminCrds)) {
						$targetedServerSession = New-PSSession -ComputerName $($script:targetedADdomainNearestRWDCFQDN) -ErrorAction Stop
					} Else {
						$targetedServerSession = New-PSSession -ComputerName $($script:targetedADdomainNearestRWDCFQDN) -Credential $adminCrds -ErrorAction Stop
					}
					$isRequiredSecurityOptionEnabled, $isRequiredAdvancedAuditSettingsEnabled = Invoke-Command -Session $targetedServerSession -ArgumentList $($script:targetedADdomainNearestRWDCFQDN), $($script:targetedADdomainFQDN), $targetedADdomainDomainSID, $execDateTimeCustom, $requiredSecurityOptionAdvAudit, $requiredAdvAuditSettings, $loggingDef, $loadPoSHModulesDef, $determineUserAccountForRSoPDef -ScriptBlock {
						Param (
							$targetedADdomainNearestRWDCFQDN,
							$targetedADdomainFQDN,
							$targetedADdomainDomainSID,
							$execDateTimeCustom,
							$requiredSecurityOptionAdvAudit,
							$requiredAdvAuditSettings,
							$loggingDef,
							$loadPoSHModulesDef,
							$determineUserAccountForRSoPDef
						)

						. ([ScriptBlock]::Create($loggingDef))
						. ([ScriptBlock]::Create($loadPoSHModulesDef))
						. ([ScriptBlock]::Create($determineUserAccountForRSoPDef))

						"GroupPolicy" | ForEach-Object {
							$poshModuleState = $null
							$poshModuleState = loadPoSHModules -poshModule $_ -ignoreRemote $true
							If ($poshModuleState -eq "NotAvailable") {
								BREAK
							}
						}

						If ($poshModuleState -eq "HasBeenLoaded" -Or $poshModuleState -eq "AlreadyLoaded") {
							# First Force A GP Update On The Local RWDC To Make Sure All Current Stuff Is Applied
							Invoke-GPUpdate -RandomDelayInMinutes 0 -Force
							Start-Sleep -s 10

							# Determine The User Account To Use During RSoP
							$accountToChooseForRSoP = determineUserAccountForRSoP -targetedADdomainNearestRWDCFQDN $targetedADdomainNearestRWDCFQDN -targetedADdomainDomainSID $targetedADdomainDomainSID

							# Run An RsOP To Determine In Which GPO, If Applicable, The Required Security Option And Audit Settings Have Been Configured And Which Should Be Used, And Export To XML File
							Get-GPResultantSetOfPolicy -Computer $targetedADdomainNearestRWDCFQDN -User $accountToChooseForRSoP -ReportType xml -Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_Audit_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml" -ErrorAction Stop > $null

							# Determine If The Required Security Option Is Configured And If The Required Advanced Auditing Setting Is Configured As Needed
							If (Test-Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_Audit_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml") {
								[xml]$gpRSoPxml = Get-Content "$($ENV:WINDIR + '\TEMP')\gpRSoP_Audit_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml"
								$gpoList = @{}
								$gpoList["NONE"] = "NONE_AVAILABLE"
								(Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop" }).Node.ComputerResults.GPO | ForEach-Object { $gpoList.Add($_.Path.Identifier."#text", $_.Name) }
								$rsopSecurityOptions = (Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop" }).Node.ComputerResults.ExtensionData.Extension.SecurityOptions
								$gpoWithRequiredSecurityOptionGpoGuid = $null
								If (-not ([string]::IsNullOrEmpty($($rsopSecurityOptions | Where-Object { $_.KeyName -eq $($requiredSecurityOptionAdvAudit.Split("|")[1]) })))) {
									$gpoWithRequiredSecurityOptionGpoGuid = ($rsopSecurityOptions | Where-Object { $_.KeyName -eq $($requiredSecurityOptionAdvAudit.Split("|")[1]) }).GPO.Identifier.'#text'
									$isRequiredSecurityOptionEnabled = $true
								} Else {
									$gpoWithRequiredSecurityOptionGpoGuid = "NONE"
									$isRequiredSecurityOptionEnabled = $false
								}
								writeLog -dataToLog "  --> Current GPO With Required Security Option: '$($gpoList[$gpoWithRequiredSecurityOptionGpoGuid])'..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog ""
								$rsopAdvancedAuditSettings = (Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop" }).Node.ComputerResults.ExtensionData.Extension.AuditSetting
								$gpoWithRequiredAdvancedAuditSettingsGpoGuid = $null
								If (-not ([string]::IsNullOrEmpty($($rsopAdvancedAuditSettings | Where-Object { $_.SubcategoryName -eq $($requiredAdvAuditSettings.Split("|")[0]) })))) {
									If ($(($rsopAdvancedAuditSettings | Where-Object { $_.SubcategoryName -eq $($requiredAdvAuditSettings.Split("|")[0]) }).SettingValue -band $($requiredAdvAuditSettings.Split("|")[3])) -eq $($requiredAdvAuditSettings.Split("|")[3])) {
										$gpoWithRequiredAdvancedAuditSettingsGpoGuid = ($rsopAdvancedAuditSettings | Where-Object { $_.SubcategoryName -eq $($requiredAdvAuditSettings.Split("|")[0]) }).GPO.Identifier.'#text'
										$isRequiredAdvancedAuditSettingsEnabled = $true
									} Else {
										$gpoWithRequiredAdvancedAuditSettingsGpoGuid = "NONE"
										$isRequiredAdvancedAuditSettingsEnabled = $false
									}
								} Else {
									$gpoWithRequiredAdvancedAuditSettingsGpoGuid = "NONE"
									$isRequiredAdvancedAuditSettingsEnabled = $false
								}
								writeLog -dataToLog "  --> Current GPO With Required Advanced Auditing Setting: '$($gpoList[$gpoWithRequiredAdvancedAuditSettingsGpoGuid])'..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog ""
							} Else {
								$isRequiredSecurityOptionEnabled = $false
								$isRequiredAdvancedAuditSettingsEnabled = $false
								writeLog -dataToLog "  --> The Execution Of The RSoP Failed..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog ""
							}
						} Else {
							$isRequiredSecurityOptionEnabled = $false
							$isRequiredAdvancedAuditSettingsEnabled = $false
							writeLog -dataToLog "  --> The Execution Of The RSoP Cannot Be Done Due To Missing GPO PowerShell Module..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							writeLog -dataToLog ""
						}
						Return $isRequiredSecurityOptionEnabled, $isRequiredAdvancedAuditSettingsEnabled
					}
					Remove-PSSession $targetedServerSession
				}
				If ($isRequiredSecurityOptionEnabled -eq $true -And $isRequiredAdvancedAuditSettingsEnabled -eq $true) {
					# If Both The Required Security Option And The Required Advanced Auditing Setting Are In Place, Continue
					writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Both The Required Security Option And The Required Advanced Auditing Setting Are In Use By DCs In The AD Domain '$($script:targetedADdomainFQDN)'!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				} Else {
					# If Both/Either The Required Security Option And/Or The Required Advanced Auditing Setting Are NOT In Place, Abort
					writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Both/Either The Required Security Option And/Or The Required Advanced Auditing Setting Are NOT In Use By DCs In The AD Domain '$($script:targetedADdomainFQDN)'!" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Please Re-Run The Script AFTER Configuring The Required Security Option And/Or The Required Advanced Auditing Setting In A GPO That Targets All DCs In The AD Domain '$($script:targetedADdomainFQDN)'..." -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "Aborting Script..." -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false

					EXIT
				}
			} Catch {
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error Checking If The Required Security Option And The Required Advanced Auditing Setting Are Being Used By DCs In The AD Domain '$($script:targetedADdomainFQDN)' Through Executing A RSoP..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

				EXIT
			}
		}

		# The DO/UNTIL Contains The Processing Of The DCs In The List For Every Mode Of Operation.
		# For Mode 2, 3, 4, 5 and 6 It Will Go Through Just Once
		# For Mode 7, It Will Go Through Until The Additional Conditions Have Been Met (Running Within A Specific Period, Using A Certain Interval)
		$runNr = 0
		Do {
			If ($modeOfOperationNr -eq 7 -And $isRequiredSecurityOptionEnabled -eq $true -And $isRequiredAdvancedAuditSettingsEnabled -eq $true) {
				$runNr++

				# Regular Expression For IPv4 Addresses
				$ipv4Regex = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

				# Define The Starting Time For The Run Of The Monitoring Of Golden Tickets Across All Contacted DCs
				$startDateTimeRunMonitorGoldenTickets = Get-Date

				# Define The File Containing All Suspicious Tickets CSV For This Run Of The Monitoring Of Golden Tickets Across All Contacted DCs
				$suspiciousTicketsFileMonitoringRunGoldenTickets = $logFilePath.Replace(".log", "_Monitor-Golden-Tickets_$(Get-Date $startDateTimeRunMonitorGoldenTickets -f 'yyyyMMddHHmmss').csv")

				# Filtered Security Events
				$filteredSecurityEventsKerbSvcTicketOps = [System.Collections.Generic.List[Object]]::New()

				writeLog -dataToLog ""
				writeLog -dataToLog "  ============= CURRENT Date/Time: ($(Get-Date -format 'yyyy-MM-dd HH:mm:ss')) ============= Run: '$runNr' ============= STOPS After: $(Get-Date $($execDateTime.AddSeconds($goldenTicketMonitoringPeriod)) -format 'yyyy-MM-dd HH:mm:ss') ============="
				writeLog -dataToLog ""
			}

			$numOfKrbTGTAccountsToProcess = ($collectionOfDCsToProcess | Measure-Object).Count
			$collectionOfDCsToProcess | ForEach-Object {
				# The DC Object In The List To Process
				$dcToProcess = $null
				$dcToProcess = $_

				# Retrieve The sAMAccountName Of The KrbTgt Account In Use By The DC(s)
				$krbTgtSamAccountName = $null
				$krbTgtSamAccountName = $dcToProcess."Krb Tgt"

				# The Target Object (DN) To Check For Existence
				$targetObjectToCheck = $null
				$targetObjectToCheckDN = $null

				# Retrieve The KrbTgt Account Object DN
				$krbTgtObjectDN = $null
				If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
					Try {
						$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos
						$krbTgtObjectDN = (Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))").DistinguishedName
						$ldapConnection.Dispose()
					} Catch {
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					}
				}
				If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
					Try {
						$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos -Credential $adminCrds
						$krbTgtObjectDN = (Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))").DistinguishedName
						$ldapConnection.Dispose()
					} Catch {
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' For User Object With 'sAMAccountName=$krbTgtSamAccountName' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					}
				}

				# Present The Information Of The KrbTgt Account Scope Being Processed
				writeLog -dataToLog "+++++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "+++ Processing KrbTgt Account....: '$krbTgtSamAccountName' | '$krbTgtObjectDN' +++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				If ($dcToProcess."DS Type" -eq "Read/Write") {
					writeLog -dataToLog "+++ Used By RWDC.................: 'All RWDCs' +++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				}
				If ($dcToProcess."DS Type" -eq "Read-Only") {
					writeLog -dataToLog "+++ Used By RODC.................: '$($dcToProcess."Host Name")' (Site: $($dcToProcess."Site Name")) +++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				}
				writeLog -dataToLog "+++++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

				If ($modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
					# Determine The HostName Of The Source RWDC
					If ($dcToProcess."DS Type" -eq "Read/Write") {
						$targetedADdomainSourceRWDCFQDN = $null
						$targetedADdomainSourceRWDCFQDN = $dcToProcess."Host Name"
					}
					If ($dcToProcess."DS Type" -eq "Read-Only") {
						$targetedADdomainDCToProcessReachability = $null
						$targetedADdomainDCToProcessReachability = $dcToProcess.Reachable

						$targetedADdomainSourceRWDCFQDN = $null
						$targetedADdomainSourceRWDCFQDN = $dcToProcess."Source RWDC FQDN"

						If ($targetedADdomainDCToProcessReachability -eq $false -Or $targetedADdomainSourceRWDCFQDN -eq "RODC Unreachable" -Or $targetedADdomainSourceRWDCFQDN -eq "Unknown") {
							Try {
								$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object { $_.PDC -eq $true })."Host Name"
								If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
									$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos
									$dcToProcess."Source RWDC DSA" = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADforestSitesContainerDN) -searchFilter "(&(objectClass=server)(dNSHostName=$targetedADdomainSourceRWDCFQDN))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
									$ldapConnection.Dispose()
								}
								If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
									$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
									$dcToProcess."Source RWDC DSA" = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADforestSitesContainerDN) -searchFilter "(&(objectClass=server)(dNSHostName=$targetedADdomainSourceRWDCFQDN))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
									$ldapConnection.Dispose()
								}
							} Catch {
								writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For The Source RWDC DSA 'dNSHostName=$targetedADdomainSourceRWDCFQDN'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							}
						} Else {
							Try {
								$targetedADdomainSourceRWDCReachability = $null
								$targetedADdomainSourceRWDCReachability = ($tableOfDCsInADDomain | Where-Object { $_."Host Name" -eq $targetedADdomainSourceRWDCFQDN }).Reachable
								If ($targetedADdomainSourceRWDCReachability -eq $false) {
									$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object { $_.PDC -eq $true })."Host Name"
									If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
										$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos
										$dcToProcess."Source RWDC DSA" = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADforestSitesContainerDN) -searchFilter "(&(objectClass=server)(dNSHostName=$targetedADdomainSourceRWDCFQDN))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
										$ldapConnection.Dispose()
									}
									If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
										$ldapConnection = Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds
										$dcToProcess."Source RWDC DSA" = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADforestSitesContainerDN) -searchFilter "(&(objectClass=server)(dNSHostName=$targetedADdomainSourceRWDCFQDN))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
										$ldapConnection.Dispose()
									}
								}
							} Catch {
								writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For The Source RWDC DSA 'dNSHostName=$targetedADdomainSourceRWDCFQDN' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
							}
						}
					}

					# Retrieve Details Of The Source RWDC
					$targetedADdomainSourceRWDCIsPDC = $null
					$targetedADdomainSourceRWDCIsPDC = ($tableOfDCsInADDomain | Where-Object { $_."Host Name" -eq $targetedADdomainSourceRWDCFQDN }).PDC
					$targetedADdomainSourceRWDCDSType = $null
					$targetedADdomainSourceRWDCDSType = ($tableOfDCsInADDomain | Where-Object { $_."Host Name" -eq $targetedADdomainSourceRWDCFQDN })."DS Type"
					$targetedADdomainSourceRWDCSiteName = $null
					$targetedADdomainSourceRWDCSiteName = ($tableOfDCsInADDomain | Where-Object { $_."Host Name" -eq $targetedADdomainSourceRWDCFQDN })."Site Name"
					$targetedADdomainSourceRWDCIPAddress = $null
					$targetedADdomainSourceRWDCIPAddress = ($tableOfDCsInADDomain | Where-Object { $_."Host Name" -eq $targetedADdomainSourceRWDCFQDN })."IP Address"
					$targetedADdomainSourceRWDCReachability = $null
					$targetedADdomainSourceRWDCReachability = ($tableOfDCsInADDomain | Where-Object { $_."Host Name" -eq $targetedADdomainSourceRWDCFQDN }).Reachable

					# Only Continue If The Source RWDC Is Available/Reachable To Process The Change
					If ($targetedADdomainSourceRWDCReachability -eq $true) {
						# If Mode 2, Execute The Creation Of the Temporary Canary Object, And Abort The Script If That Fails
						If ($modeOfOperationNr -eq 2) {
							$targetObjectToCheckDN = createTempCanaryObject -targetedADdomainRWDCFQDN $targetedADdomainSourceRWDCFQDN -krbTgtSamAccountName $krbTgtSamAccountName -execDateTimeCustom1 $execDateTimeCustom1 -localADforest $localADforest -adminCrds $adminCrds
							If ([string]::IsNullOrEmpty($targetObjectToCheckDN)) {
								# Mail The Log File With The Results
								If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
									$context = "SCRIPT ABORT - ERROR: Failed to create Temporary Canary Object!"

									sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
								}

								EXIT
							}
						}

						# If Mode 3, Simulate Password Reset Of TEST/BOGUS KrbTgt Accounts (No Password Reset/WhatIf Mode)
						# If Mode 4, Do A Real Password Reset Of TEST/BOGUS KrbTgt Accounts (Password Reset!)
						# If Mode 5, Simulate Password Reset Of PROD/REAL KrbTgt Accounts (No Password Reset/WhatIf Mode)
						# If Mode 6, Do A Real Password Reset Of PROD/REAL KrbTgt Accounts (Password Reset!)
						If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
							# Retrieve The KrbTgt Account Object
							If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
								Try {
									$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos
									If ($execResetRoutine -And $($script:resetRoutineEnabled).ToUpper() -eq "TRUE") {
										$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset", $($script:resetRoutineAttributeForResetDateAction1), $($script:resetRoutineAttributeForResetDateAction2), $($script:resetRoutineAttributeForResetState))
									} Else {
										$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $($script:targetedADdomainDefaultNCDN) -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
									}
									$ldapConnection.Dispose()
								} Catch {
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								}
							}
							If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
								Try {
									$ldapConnection = Get-LdapConnection -LdapServer:$($script:targetedADdomainNearestRWDCFQDN) -EncryptionType Kerberos -Credential $adminCrds
									$targetSearchBase = (Get-RootDSE -LdapConnection $ldapConnection).defaultNamingContext.distinguishedName
									If ($execResetRoutine -And $($script:resetRoutineEnabled).ToUpper() -eq "TRUE") {
										$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset", $($script:resetRoutineAttributeForResetDateAction1), $($script:resetRoutineAttributeForResetDateAction2), $($script:resetRoutineAttributeForResetState))
									} Else {
										$targetObjectToCheck = Find-LdapObject -LdapConnection $ldapConnection -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
									}
									$ldapConnection.Dispose()
								} Catch {
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Error Querying AD Against '$($script:targetedADdomainNearestRWDCFQDN)' For User Object With 'sAMAccountName=$krbTgtSamAccountName' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								}
							}

							# If The KrbTgt Account Object Was Found
							If ($(-not [string]::IsNullOrEmpty($targetObjectToCheck))) {
								# If The KrbTgt Account Object Exists (You're In Deep Sh!t If The Account Does Not Exist! :-))
								# Retrieve The DN Of The KrbTgt Account Object
								$targetObjectToCheckDN = $targetObjectToCheck.DistinguishedName

								# Retrieve The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object
								$objectMetadata = $null
								$objectMetadata = retrieveObjectMetadata -targetedADdomainRWDCFQDN $($script:targetedADdomainNearestRWDCFQDN) -ObjectDN $targetObjectToCheckDN -localADforest $localADforest -adminCrds $adminCrds
								$objectMetadataAttribPwdLastSet = $null
								$objectMetadataAttribPwdLastSet = $objectMetadata | Where-Object { $_.Name -eq "pwdLastSet" }
								$objectMetadataAttribPwdLastSetOrgRWDCFQDN = $null
								$objectMetadataAttribPwdLastSetOrgRWDCFQDN = If ($objectMetadataAttribPwdLastSet.OriginatingServer) { $objectMetadataAttribPwdLastSet.OriginatingServer } Else { "RWDC Demoted" }
								$objectMetadataAttribPwdLastSetOrgTime = $null
								$objectMetadataAttribPwdLastSetOrgTime = Get-Date $($objectMetadataAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
								$objectMetadataAttribPwdLastSetVersion = $null
								$objectMetadataAttribPwdLastSetVersion = $objectMetadataAttribPwdLastSet.Version

								# Retrieve The Password Last Set Of The KrbTgt Account Object And If Applicable Also The Password Reset Routine Data From The Account
								$targetObjectToCheckPwdLastSet = $null
								$targetObjectToCheckPwdLastSet = Get-Date $([datetime]::fromfiletime($targetObjectToCheck.pwdLastSet))

								If ($execResetRoutine -And $($script:resetRoutineEnabled).ToUpper() -eq "TRUE") {
									$targetObjectToCheckPwdResetRoutineStateFromAD = $null
									$targetObjectToCheckPwdResetRoutineStateFromAD = $targetObjectToCheck.$($script:resetRoutineAttributeForResetState)
									$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD = $null
									$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD = $targetObjectToCheck.$($script:resetRoutineAttributeForResetDateAction1)
									$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD = $null
									$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD = $targetObjectToCheck.$($script:resetRoutineAttributeForResetDateAction2)

									If ([string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutineStateFromAD)) {
										writeLog -dataToLog "  --> Reset Routine State (From AD).........: 'EMPTY'"
										writeLog -dataToLog "  --> Reset Routine PWD LAST DATE (From AD).: '$($targetObjectToCheckPwdLastSet.ToString("yyyyMMddHHmmss"))' ($($targetObjectToCheckPwdLastSet.ToString("yyyy-MM-dd HH:mm:ss")))"
										writeLog -dataToLog "  --> Max TGT Lifetime (Hours)..............: '$targetedADdomainMaxTgtLifetimeHrs'"
										#writeLog -dataToLog "  --> Reset Routine TODAY...................: '$(([DateTime]::Now).ToString("yyyyMMddHHmmss"))' ($(([DateTime]::Now).ToString("yyyy-MM-dd HH:mm:ss")))"
										writeLog -dataToLog "  --> Reset Routine TODAY...................: '$($execDateTime.ToString("yyyyMMddHHmmss"))' ($($execDateTime.ToString("yyyy-MM-dd HH:mm:ss")))"
										writeLog -dataToLog ""
									}
									If (-not [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutineStateFromAD) -And ($targetObjectToCheckPwdResetRoutineStateFromAD -eq 0 -Or $targetObjectToCheckPwdResetRoutineStateFromAD -eq 1 -Or $targetObjectToCheckPwdResetRoutineStateFromAD -eq 2)) {
										writeLog -dataToLog "  --> Reset Routine State (From AD).........: '$targetObjectToCheckPwdResetRoutineStateFromAD'"
										writeLog -dataToLog "  --> Reset Routine PWD LAST DATE (From AD).: '$($targetObjectToCheckPwdLastSet.ToString("yyyyMMddHHmmss"))' ($($targetObjectToCheckPwdLastSet.ToString("yyyy-MM-dd HH:mm:ss")))"
										writeLog -dataToLog "  --> Max TGT Lifetime (Hours)..............: '$targetedADdomainMaxTgtLifetimeHrs'"
										#writeLog -dataToLog "  --> Reset Routine TODAY...................: '$(([DateTime]::Now).ToString("yyyyMMddHHmmss"))' ($(([DateTime]::Now).ToString("yyyy-MM-dd HH:mm:ss")))"
										writeLog -dataToLog "  --> Reset Routine TODAY...................: '$($execDateTime.ToString("yyyyMMddHHmmss"))' ($($execDateTime.ToString("yyyy-MM-dd HH:mm:ss")))"
										If ($targetObjectToCheckPwdResetRoutineStateFromAD -eq 0 -Or $targetObjectToCheckPwdResetRoutineStateFromAD -eq 1) {
											writeLog -dataToLog "  --> Safe To Reset Password?...............: $(If ($targetObjectToCheckPwdLastSet.AddHours($([int]$targetedADdomainMaxTgtLifetimeHrs)) -lt $execDateTime) {"'YES' ('Reset Routine PWD LAST DATE (From AD)' and 'Reset Routine TODAY' ARE at least 'Max TGT Lifetime (Hours)' apart from each other!)"} Else {"'NO' ('Reset Routine PWD LAST DATE (From AD)' and 'Reset Routine TODAY' ARE NOT at least 'Max TGT Lifetime (Hours)' apart from each other!)"})"
										}
										If (-not [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD) -And $targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD -match "^(20)\d{2}(0[1-9]|1[0,1,2])(0[1-9]|[12][0-9]|3[01])([01][0-9]|[2][0-3])([012345][0-9])([012345][0-9])$") {
											writeLog -dataToLog "  --> Reset Routine Action 1 Date (From AD).: '$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD' ($([DateTime]::ParseExact($targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD, "yyyyMMddHHmmss", $null).ToString("yyyy-MM-dd HH:mm:ss")))"
										} Else {
											writeLog -dataToLog "  --> Reset Routine Action 1 Date (From AD).: '$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD'"
										}
										If (-not [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD) -And $targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD -match "^(20)\d{2}(0[1-9]|1[0,1,2])(0[1-9]|[12][0-9]|3[01])([01][0-9]|[2][0-3])([012345][0-9])([012345][0-9])$") {
											writeLog -dataToLog "  --> Reset Routine Action 2 Date (From AD).: '$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD' ($([DateTime]::ParseExact($targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD, "yyyyMMddHHmmss", $null).ToString("yyyy-MM-dd HH:mm:ss")))"
										} Else {
											writeLog -dataToLog "  --> Reset Routine Action 2 Date (From AD).: '$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD'"
										}
										writeLog -dataToLog ""
									}
								}

								# If Mode 3, Do A WHAT IF Password Reset Of TEST/BOGUS KrbTgt Accounts (No Password Reset!)
								# If Mode 5, Do A WHAT IF Password Reset Of PROD/REAL KrbTgt Accounts (No Password Reset!)
								If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 5) {
									writeLog -dataToLog "  --> According To RWDC.....................: '$($script:targetedADdomainNearestRWDCFQDN)'"
									writeLog -dataToLog "  --> Previous Password Set Date/Time.......: '$(Get-Date $targetObjectToCheckPwdLastSet -f 'yyyy-MM-dd HH:mm:ss')'"
									writeLog -dataToLog "  --> Originating RWDC Previous Change......: '$objectMetadataAttribPwdLastSetOrgRWDCFQDN'"
									writeLog -dataToLog "  --> Originating Time Previous Change......: '$objectMetadataAttribPwdLastSetOrgTime'"
									writeLog -dataToLog "  --> Current Version Of Attribute Value....: '$objectMetadataAttribPwdLastSetVersion'"
									writeLog -dataToLog ""
									writeLog -dataToLog "REMARK: What If Mode! NO PASSWORD RESET HAS OCCURED!" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog ""
								}

								# If Mode 4, Do A Real Password Reset Of TEST/BOGUS KrbTgt Accounts (Password Reset!)
								# If Mode 6, Do A Real Password Reset Of PROD/REAL KrbTgt Accounts (Password Reset!)
								If ($modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 6) {
									# Calculate The Expiration Date/Time Of N-1 Kerberos Tickets
									$expirationTimeForNMinusOneKerbTickets = $null
									$expirationTimeForNMinusOneKerbTickets = (($targetObjectToCheckPwdLastSet.AddHours($($script:targetedADdomainMaxTgtLifetimeHrs))).AddMinutes($($script:targetedADdomainMaxClockSkewMins))).AddMinutes($($script:targetedADdomainMaxClockSkewMins))

									# Check If It Advisable To Reset The Password Or Not.
									# If YES, Just Continue
									# If NO, Ask For Acknowledgement
									$okToReset = $null
									If ($expirationTimeForNMinusOneKerbTickets -lt $execDateTime -Or ($execResetRoutine -And $($script:resetRoutineEnabled).ToUpper() -eq "TRUE") -Or ($ignoreProtectionForTESTAccounts -And $modeOfOperationNr -eq 4)) {
										# Allow The Password Reset To Occur Without Questions If The Expiration Date/Time Of N-1 Kerberos Tickets Is Earlier Than The Current Time
										# If The Password Reset Routine Is Being Executed, It Will Act Based On State And Calculated Reset Dates
										# If Mode 4 (Do A Real Password Reset Of TEST/BOGUS KrbTgt Accounts) And The Parameter '-ignoreProtectionForTESTAccounts' Is Specifeid, Then Allow The Reset To Occur
										$okToReset = $true
									} Else {
										# Allow The Password Reset To Occur After Confirnation Only If The Expiration Date/Time Of N-1 Kerberos Tickets Is Equal Or Later Than The Current Time
										writeLog -dataToLog "  --> According To RWDC.....................: '$($script:targetedADdomainNearestRWDCFQDN)'"
										writeLog -dataToLog "  --> Previous Password Set Date/Time.......: '$(Get-Date $targetObjectToCheckPwdLastSet -f 'yyyy-MM-dd HH:mm:ss')'"
										writeLog -dataToLog "  --> Max TGT Lifetime (Hours)..............: '$($script:targetedADdomainMaxTgtLifetimeHrs)'"
										writeLog -dataToLog "  --> Max Clock Skew (Minutes)..............: '$($script:targetedADdomainMaxClockSkewMins)'"
										writeLog -dataToLog "  --> Date/Time N-1 Kerberos Tickets........: '$(Get-Date $expirationTimeForNMinusOneKerbTickets -f 'yyyy-MM-dd HH:mm:ss')'"
										writeLog -dataToLog "  --> Date/Time Now (When Script Started)...: '$(Get-Date $execDateTime -f 'yyyy-MM-dd HH:mm:ss')'"
										writeLog -dataToLog "  --> Originating RWDC Previous Change......: '$objectMetadataAttribPwdLastSetOrgRWDCFQDN'"
										writeLog -dataToLog "  --> Originating Time Previous Change......: '$objectMetadataAttribPwdLastSetOrgTime'"
										writeLog -dataToLog "  --> Current Version Of Attribute Value....: '$objectMetadataAttribPwdLastSetVersion'"
										writeLog -dataToLog ""
										$continueOrStop = $null
										If ($dcToProcess."DS Type" -eq "Read/Write") {
											If ($argsCount -ge 1 -And $PSBoundParameters.keys -contains "modeOfOperation" -And $PSBoundParameters.keys -contains "targetedADforestFQDN" -And $PSBoundParameters.keys -contains "targetedADdomainFQDN" -And $PSBoundParameters.keys -contains "targetKrbTgtAccountScope") {
												$continueOrStop = "SKIP"
												writeLog -dataToLog "  --> Resetting KrbTgt Accnt Password Means.: 'MAJOR DOMAIN WIDE IMPACT'" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
												writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
												writeLog -dataToLog "What do you want to do? [CONTINUE | SKIP | STOP]: $continueOrStop" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
											} Else {
												writeLog -dataToLog "  --> Resetting KrbTgt Accnt Password Means.: 'MAJOR DOMAIN WIDE IMPACT'" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
												writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
												writeLog -dataToLog "What do you want to do? [CONTINUE | SKIP | STOP]: " -lineType "ACTION-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false
												$continueOrStop = Read-Host
											}
										}
										If ($dcToProcess."DS Type" -eq "Read-Only") {
											If ($argsCount -ge 1 -And $PSBoundParameters.keys -contains "modeOfOperation" -And $PSBoundParameters.keys -contains "targetedADforestFQDN" -And $PSBoundParameters.keys -contains "targetedADdomainFQDN" -And $PSBoundParameters.keys -contains "targetKrbTgtAccountScope") {
												$continueOrStop = "SKIP"
												writeLog -dataToLog "  --> Resetting KrbTgt Accnt Password Means.: 'MAJOR IMPACT FOR RESOURCES SERVICED BY $($dcToProcess."Host Name")' (Site: $($dcToProcess."Site Name"))" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
												writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
												writeLog -dataToLog "What do you want to do? [CONTINUE | SKIP | STOP]: $continueOrStop" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
											} Else {
												writeLog -dataToLog "  --> Resetting KrbTgt Accnt Password Means.: 'MAJOR IMPACT FOR RESOURCES SERVICED BY $($dcToProcess."Host Name")' (Site: $($dcToProcess."Site Name"))" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
												writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
												writeLog -dataToLog "What do you want to do? [CONTINUE | SKIP | STOP]: " -lineType "ACTION-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false
												$continueOrStop = Read-Host
											}
										}

										If ($dcToProcess."DS Type" -eq "Read/Write") {
											# Any Confirmation Not Equal To CONTINUE And Not Equal To SKIP And Not Equal To STOP Will Be Equal To STOP
											If ($continueOrStop.ToUpper() -ne "CONTINUE" -And $continueOrStop.ToUpper() -ne "SKIP" -And $continueOrStop.ToUpper() -ne "STOP") {
												$continueOrStop = "STOP"
											}
										}
										If ($dcToProcess."DS Type" -eq "Read-Only") {
											# Any Confirmation Not Equal To CONTINUE And Not Equal To SKIP And Not Equal To STOP Will Be Equal To STOP
											If ($continueOrStop.ToUpper() -ne "CONTINUE" -And $continueOrStop.ToUpper() -ne "SKIP" -And $continueOrStop.ToUpper() -ne "STOP") {
												$continueOrStop = "STOP"
											}
										}

										writeLog -dataToLog ""
										If ($continueOrStop.ToUpper() -eq "CONTINUE") { # If The Confirmation Equals CONTINUE, Allow The Password Reset To Occur For This Account.
											$okToReset = $true
										} ElseIf ($continueOrStop.ToUpper() -eq "SKIP") { # If The Confirmation Equals SKIP, Do Not Allow The Password Reset To Occur For This Account. Continue With Next Account If Applicable
											$okToReset = $false
										} Else {
											$okToReset = $false
										}
										writeLog -dataToLog "  --> Chosen: $continueOrStop" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
										writeLog -dataToLog ""
										
										If ($continueOrStop.ToUpper() -eq "STOP") {
											BREAK
										}
									}

									$script:numAccntsProcessedTOTAL += 1
									writeLog -dataToLog "  --> KrbTGT Account Processed: $($($script:numAccntsProcessedTOTAL).ToString().PadLeft($($numOfKrbTGTAccountsToProcess.ToString().Length), '0')) Of $numOfKrbTGTAccountsToProcess"
									writeLog -dataToLog ""

									If ($okToReset -eq $true) {
										# Define The List Of Edits To Execute On The Account (A Hash Table)
										$listOfEdits = @{}

										If ($execResetRoutine -And $($script:resetRoutineEnabled).ToUpper() -eq "TRUE") {
											# If The KrbTGT Password Reset Routine Is Executed
											# If An Anomaly Is Detected, Then Reset The State And The Dates To Be EMPTY So That The Process Can Restart Again At A Later Moment - THIS IS/ARE PROTECTION MECHANISM(S)

											# ANOMALY - Password Reset Routine State IS NOT EMPTY, And Either/Both Password Reset Routine Action 1 Date And/or Password Reset Routine Action 2 Date IS/ARE EMPTY
											If (-not [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutineStateFromAD) -And ([string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD) -Or [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD))) {
												$anomaly = "State Has A Value ('$targetObjectToCheckPwdResetRoutineStateFromAD') While Either Or Both Action 1 Date ('$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD') And/Or Action 2 Date ('$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD') Has No Value!"
												$resetToInitialStateDueToAnomaly = $true

											# ANOMALY - Password Reset Routine Action 1 Date IS NOT EMPTY, And Either/Both Password Reset Routine State And/or Password Reset Routine Action 2 Date IS/ARE EMPTY
											} ElseIf (-not [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD) -And ([string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutineStateFromAD) -Or [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD))) {
												$anomaly = "Action 1 Date ('$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD') Has A Value, While Either Or Both State ('$targetObjectToCheckPwdResetRoutineStateFromAD') And/Or Action 2 Date ('$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD') Has No Value!"
												$resetToInitialStateDueToAnomaly = $true

											# ANOMALY - Password Reset Routine Action 2 Date IS NOT EMPTY, And Either/Both Password Reset Routine State And/or Password Reset Routine Action 1 Date IS/ARE EMPTY
											} ElseIf (-not [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD) -And ([string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutineStateFromAD) -Or [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD))) {
												$anomaly = "Action 2 Date ('$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD') Has A Value, While Either Or Both State ('$targetObjectToCheckPwdResetRoutineStateFromAD') And/Or Action 1 Date ('$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD') Has No Value!"
												$resetToInitialStateDueToAnomaly = $true

											# ANOMALY - Both Password Reset Routine Action 1 Date And Password Reset Routine Action 2 Date ARE NOT Empty, But Password Reset Routine Action 2 Date Is Before/Equal Password Reset Routine Action 1 Date
											} ElseIf (-not [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD) -And -not [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD) -And [int64]$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD -le [int64]$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD) {
												$anomaly = "Action 2 Date ('$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD') Is Before Action 1 Date ('$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD'), And Not After Action 1 Date!"
												$resetToInitialStateDueToAnomaly = $true

											# ANOMALY - Password Reset Routine State IS NOT EMPTY, And Password Reset Routine State DOES NOT Equal Either 0/1/2
											} ElseIf (-not [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutineStateFromAD) -And $targetObjectToCheckPwdResetRoutineStateFromAD -ne "0" -And $targetObjectToCheckPwdResetRoutineStateFromAD -ne "1" -And $targetObjectToCheckPwdResetRoutineStateFromAD -ne "2") {
												$anomaly = "State Has A Value ('$targetObjectToCheckPwdResetRoutineStateFromAD'), But The Value Is Invalid!"
												$resetToInitialStateDueToAnomaly = $true

											# ANOMALY - Password Reset Routine State Is Either 0/1/2, And Either/Both Password Reset Routine Action 1 Date And/Or Password Reset Routine Action 2 Date DOES NOT Match The Required Value Structure Of yyyyMMddHHmmss
											} ElseIf (($targetObjectToCheckPwdResetRoutineStateFromAD -eq "0" -Or $targetObjectToCheckPwdResetRoutineStateFromAD -eq "1" -Or $targetObjectToCheckPwdResetRoutineStateFromAD -eq "2") -And ($targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD -notmatch "^(20)\d{2}(0[1-9]|1[0,1,2])(0[1-9]|[12][0-9]|3[01])([01][0-9]|[2][0-3])([012345][0-9])([012345][0-9])$" -Or $targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD -notmatch "^(20)\d{2}(0[1-9]|1[0,1,2])(0[1-9]|[12][0-9]|3[01])([01][0-9]|[2][0-3])([012345][0-9])([012345][0-9])$")) {
												$anomaly = "Normal State Value ('$targetObjectToCheckPwdResetRoutineStateFromAD') While Either Or Both Action Dates ('$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD') ('$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD') Not Matching Required Structure!"
												$resetToInitialStateDueToAnomaly = $true

											# ANOMALY - Password Reset Routine State Is 0, And Execution Date/Time IS NOT Before Password Reset Routine Action 2 Date
											} ElseIf ($targetObjectToCheckPwdResetRoutineStateFromAD -eq "0" -And -not ([int64]$($execDateTime.ToString("yyyyMMddHHmmss")) -lt [int64]$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD)) {
												$anomaly = "State Value ('$targetObjectToCheckPwdResetRoutineStateFromAD') While Execution Date/time! ('$($execDateTime.ToString("yyyyMMddHHmmss"))') IS NOT Before Action 2 Date ('$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD')!"
												$resetToInitialStateDueToAnomaly = $true

											# ANOMALY - Password Reset Routine State Is 1, And Execution Date/Time IS NOT After Password Reset Routine Action 1 Date
											} ElseIf ($targetObjectToCheckPwdResetRoutineStateFromAD -eq "1" -And -not ([int64]$($execDateTime.ToString("yyyyMMddHHmmss")) -gt [int64]$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD)) {
												$anomaly = "State Value ('$targetObjectToCheckPwdResetRoutineStateFromAD') While Execution Date/time! ('$($execDateTime.ToString("yyyyMMddHHmmss"))') IS NOT After Action 1 Date ('$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD')!"
												$resetToInitialStateDueToAnomaly = $true

											# ANOMALY - Password Reset Routine State Is 2, And Execution Date/Time IS NOT After Password Reset Routine Action 2 Date
											} ElseIf ($targetObjectToCheckPwdResetRoutineStateFromAD -eq "2" -And -not ([int64]$($execDateTime.ToString("yyyyMMddHHmmss")) -gt [int64]$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD)) {
												$anomaly = "State Value ('$targetObjectToCheckPwdResetRoutineStateFromAD') While Execution Date/time! ('$($execDateTime.ToString("yyyyMMddHHmmss"))') IS NOT After Action 2 Date ('$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD')!"
												$resetToInitialStateDueToAnomaly = $true

											# When NO ANOMALY HAS BEEN BEEN DETECTED!
											} Else {
												$resetToInitialStateDueToAnomaly = $false

												# When The Password Reset Routine State Is EMPTY
												If ([string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutineStateFromAD)) {
													# When The Script Is Executed At A Specific Time A Comparison Is Made Between The ExecTime And Reset Routine Dates/Times. Because The Moment, Of When The Password Is Reset, Moves Forward,
													#	Due To The Fact The Script Has To Exceed That Last Moment For The Reset To Occur An Overlap Period Is Used. That Is Why That Value Is Subtracted To Compensate The
													#	Moment Of When The Password Is Reset Moving Forward
													$targetObjectToCheckPwdResetRoutine1stResetDateDecimalToAD = $targetObjectToCheckPwdLastSet.AddDays([int]$resetRoutineFirstResetIntervalInDays).AddMinutes(-$script:passwordResetRoutineOverlapPeriodInMinutes).ToString("yyyyMMddHHmmss")
													$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalToAD = $targetObjectToCheckPwdLastSet.AddDays([int]$resetRoutineFirstResetIntervalInDays + [int]$resetRoutineSecondResetIntervalInDays).AddMinutes(-$script:passwordResetRoutineOverlapPeriodInMinutes).ToString("yyyyMMddHHmmss")
													If ([int64]$targetObjectToCheckPwdResetRoutine1stResetDateDecimalToAD -le [int64]$($execDateTime.ToString("yyyyMMddHHmmss")) -Or [int64]$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalToAD -le [int64]$($execDateTime.ToString("yyyyMMddHHmmss"))) {
														$targetObjectToCheckPwdResetRoutine1stResetDateDecimalToAD = $execDateTime.AddDays([int]$resetRoutineFirstResetIntervalInDays).AddMinutes(-$script:passwordResetRoutineOverlapPeriodInMinutes).ToString("yyyyMMddHHmmss")
														$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalToAD = $execDateTime.AddDays([int]$resetRoutineFirstResetIntervalInDays + [int]$resetRoutineSecondResetIntervalInDays).AddMinutes(-$script:passwordResetRoutineOverlapPeriodInMinutes).ToString("yyyyMMddHHmmss")
													}
													$listOfEdits["ResetPassword"] = $false
													$listOfEdits[$($script:resetRoutineAttributeForResetDateAction1)] = $targetObjectToCheckPwdResetRoutine1stResetDateDecimalToAD
													$listOfEdits[$($script:resetRoutineAttributeForResetDateAction2)] = $targetObjectToCheckPwdResetRoutine2ndResetDateDecimalToAD
													$listOfEdits[$($script:resetRoutineAttributeForResetState)] = "0"
													writeLog -dataToLog "  --> State Change: 'EMPTY' --> '0' | Configuring Action Dates For THIS Account | NO Password Reset" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
													writeLog -dataToLog ""
													writeLog -dataToLog "  --> Reset Routine State (Set 2 AD)........: '0'"
													writeLog -dataToLog "  --> Reset Routine Action 1 Date (Set 2 AD): '$targetObjectToCheckPwdResetRoutine1stResetDateDecimalToAD' ($([DateTime]::ParseExact($targetObjectToCheckPwdResetRoutine1stResetDateDecimalToAD, "yyyyMMddHHmmss", $null).ToString("yyyy-MM-dd HH:mm:ss")))"
													writeLog -dataToLog "  --> Reset Routine Action 2 Date (Set 2 AD): '$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalToAD' ($([DateTime]::ParseExact($targetObjectToCheckPwdResetRoutine2ndResetDateDecimalToAD, "yyyyMMddHHmmss", $null).ToString("yyyy-MM-dd HH:mm:ss")))"
													writeLog -dataToLog "  --> Reset Routine Password Is Reset.......: 'FALSE'"													
													writeLog -dataToLog ""
													$script:numAccntsResetCandidateNO += 1
												}

												# When The Password Reset Routine State IS NOT EMPTY, And Password Reset Routine Action 1 Date IS NOT EMPTY, And Password Reset Routine Action 2 Date IS NOT EMPTY, And Password Reset Routine Action 1 Date Is Before Password Reset Routine Action 2 Date
												If (-not [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutineStateFromAD) -And -not [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD) -And -not [string]::IsNullOrEmpty($targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD) -And [int64]$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD -lt [int64]$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD) {
													# When The Password Reset Routine State Is 0
													If ($targetObjectToCheckPwdResetRoutineStateFromAD -eq "0") {
														# If The Execution Date/Time Is Between Password Reset Routine Action 1 Date And Password Reset Routine Action 2 Date And The Password Last Set Date/Time + Max KRBTGT Lifetime In Domain Is Before Execution Date/Time
														If ([int64]$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD -lt [int64]$($execDateTime.ToString("yyyyMMddHHmmss")) -And [int64]$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD -gt [int64]$($execDateTime.ToString("yyyyMMddHHmmss")) -And $targetObjectToCheckPwdLastSet.AddHours($([int]$targetedADdomainMaxTgtLifetimeHrs)) -lt $execDateTime) {
															$listOfEdits["ResetPassword"] = $true
															$listOfEdits[$($script:resetRoutineAttributeForResetState)] = "1"
															writeLog -dataToLog "  --> State Change: '0' --> '1' | Primary Password Reset For THIS Account" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
															writeLog -dataToLog ""
															writeLog -dataToLog "  --> Reset Routine State (Set 2 AD)........: '1'"
															writeLog -dataToLog "  --> Reset Routine Password Is Reset.......: 'TRUE'"
															writeLog -dataToLog ""
															$script:numAccntsResetCandidateYES += 1
														} Else {
															$script:numAccntsResetCandidateNO += 1
														}
													}

													# When The Password Reset Routine State Is 1
													If ($targetObjectToCheckPwdResetRoutineStateFromAD -eq "1") {
														# If The Execution Date/Time Is After Password Reset Routine Action 2 Date And The Password Last Set Date/Time + Max KRBTGT Lifetime In Domain Is Before Execution Date/Time
														If ([int64]$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD -lt [int64]$($execDateTime.ToString("yyyyMMddHHmmss")) -And [int64]$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD -lt [int64]$($execDateTime.ToString("yyyyMMddHHmmss")) -And $targetObjectToCheckPwdLastSet.AddHours($([int]$targetedADdomainMaxTgtLifetimeHrs)) -lt $execDateTime) {
															$listOfEdits["ResetPassword"] = $true
															$listOfEdits[$($script:resetRoutineAttributeForResetState)] = "2"
															writeLog -dataToLog "  --> State Change: '1' --> '2' | Secondary Password Reset For THIS Account" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
															writeLog -dataToLog ""
															writeLog -dataToLog "  --> Reset Routine State (Set 2 AD)........: '2'"
															writeLog -dataToLog "  --> Reset Routine Password Is Reset.......: 'TRUE'"
															writeLog -dataToLog ""
															$script:numAccntsResetCandidateYES += 1
														} Else {
															$script:numAccntsResetCandidateNO += 1
														}
													}

													# When The Password Reset Routine State Is 2
													If ($targetObjectToCheckPwdResetRoutineStateFromAD -eq "2") {
														# If The Execution Date/Time Is After Password Reset Routine Action 1 Date And After Password Reset Routine Action 2 Date
														If ([int64]$targetObjectToCheckPwdResetRoutine1stResetDateDecimalFromAD -lt [int64]$($execDateTime.ToString("yyyyMMddHHmmss")) -And [int64]$targetObjectToCheckPwdResetRoutine2ndResetDateDecimalFromAD -le [int64]$($execDateTime.ToString("yyyyMMddHHmmss"))) {
															$listOfEdits["ResetPassword"] = $false
															$listOfEdits[$($script:resetRoutineAttributeForResetDateAction1)] = $null
															$listOfEdits[$($script:resetRoutineAttributeForResetDateAction2)] = $null
															$listOfEdits[$($script:resetRoutineAttributeForResetState)] = $null
															writeLog -dataToLog "  --> State Change: '2' --> 'EMPTY' | Resetting Process To Initial State For Another Cycle For THIS Account" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
															writeLog -dataToLog ""
															writeLog -dataToLog "  --> Reset Routine State (Set 2 AD)........: 'EMPTY'"
															writeLog -dataToLog "  --> Reset Routine Action 1 Date (Set 2 AD): 'EMPTY'"
															writeLog -dataToLog "  --> Reset Routine Action 2 Date (Set 2 AD): 'EMPTY'"
															writeLog -dataToLog "  --> Reset Routine Password Is Reset.......: 'FALSE'"
															writeLog -dataToLog ""
															$script:numAccntsResetCandidateNO += 1
														}
													}
												}
											}

											If ($resetToInitialStateDueToAnomaly -eq $true) {
												$listOfEdits["ResetPassword"] = $false
												$listOfEdits[$($script:resetRoutineAttributeForResetDateAction1)] = $null
												$listOfEdits[$($script:resetRoutineAttributeForResetDateAction2)] = $null
												$listOfEdits[$($script:resetRoutineAttributeForResetState)] = $null
												writeLog -dataToLog "  --> !!! ANOMALY DETECTED !!! | Resetting Process To Initial State For THIS Account" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
												writeLog -dataToLog "  --> ANOMALY: $anomaly" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
												writeLog -dataToLog ""
												writeLog -dataToLog "  --> Reset Routine State (Set 2 AD)........: 'EMPTY'"
												writeLog -dataToLog "  --> Reset Routine Action 1 Date (Set 2 AD): 'EMPTY'"
												writeLog -dataToLog "  --> Reset Routine Action 2 Date (Set 2 AD): 'EMPTY'"
												writeLog -dataToLog "  --> Reset Routine Password Is Reset.......: 'FALSE'"
												writeLog -dataToLog ""
												$script:numAccntsResetCandidateNO += 1
												$script:numAccntsResetANOMALY += 1
											}
										} Else {
											# If The KrbTGT Password Reset Routine IS NOT Executed
											$listOfEdits["ResetPassword"] = $true
											$script:numAccntsResetCandidateYES += 1
										}
										# If OK To Reset Then Execute The Defined Changes Against The KrbTgt Account
										editADAccount -targetedADdomainRWDCFQDN $targetedADdomainSourceRWDCFQDN -krbTgtSamAccountName $krbTgtSamAccountName -localADforest $localADforest -adminCrds $adminCrds -listOfEdits $listOfEdits
									} Else {
										If ($execResetRoutine -And $($script:resetRoutineEnabled).ToUpper() -eq "TRUE") {
											writeLog -dataToLog "  --> Reset Routine State ..................: 'UNCHANGED'"
											writeLog -dataToLog "  --> Reset Routine Password Is Reset.......: 'FALSE' (REASON: NOT Allowed Due To Protection!)"
											writeLog -dataToLog ""
										}
										$script:numAccntsResetCandidateYES += 1
										$script:numAccntsResetSKIP += 1
									}
								}
								# If Mode 3, Do A WHAT IF Password Reset Of TEST/BOGUS KrbTgt Accounts (No Password Reset!)
								# If Mode 5, Do A WHAT IF Password Reset Of PROD/REAL KrbTgt Accounts (No Password Reset!)
								If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 5) {
									# PLACEHOLDER
								}
							} Else {
								# If The KrbTgt Account Object Does Not Exist (You're In Deep Sh!t If The Account Does Not Exist! :-))
								writeLog -dataToLog "  --> KrbTgt Account With sAMAccountName '$krbTgtSamAccountName' Does NOT Exist! Skipping..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								$targetObjectToCheckDN = $null
							}
						}
					} Else {
						# If The Source RWDC Is NOT Reachable
						writeLog -dataToLog ""
						writeLog -dataToLog "The RWDC '$targetedADdomainSourceRWDCFQDN' To Make The Change On Is Not Reachable/Available..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						writeLog -dataToLog ""
					}

					# If The DN Of The Target Object To Check (Temp Canary Object Or KrbTgt Account, Depends On The Mode Chosen) Was Determined/Found
					If ($(-not [string]::IsNullOrEmpty($targetObjectToCheckDN))) {
						# Retrieve/Define The Start List With RWDCs To Check
						If ($dcToProcess."DS Type" -eq "Read/Write") {
							$listOfDCsToCheckObjectOnStart = [System.Collections.Generic.List[Object]]::New()
							$tableOfDCsInADDomain | Where-Object { $_."DS Type" -eq "Read/Write" } | ForEach-Object { $listOfDCsToCheckObjectOnStart.Add($_) }
						}
						If ($dcToProcess."DS Type" -eq "Read-Only") {
							$listOfDCsToCheckObjectOnStart = [System.Collections.Generic.List[Object]]::New()
							$tableOfDCsInADDomain | Where-Object { $_."Host Name" -eq $targetedADdomainSourceRWDCFQDN } | ForEach-Object { $listOfDCsToCheckObjectOnStart.Add($_) }
							$listOfDCsToCheckObjectOnStart.Add($dcToProcess)
						}

						# Define The End List With RWDCs That Have Been Checked. Now Only Contains The Source RWDC. While Looping Through The Start List And Determing The Object Has Replicated, DCs Are Added To The End List
						$listOfDCsToCheckObjectOnEnd = [System.Collections.Generic.List[Object]]::New()

						$listOfDCsToCheckObjectOnEndSourceRWDCObj = [PSCustomObject]@{
							"Host Name"        = $targetedADdomainSourceRWDCFQDN
							"PDC"              = $targetedADdomainSourceRWDCIsPDC
							"Site Name"        = $targetedADdomainSourceRWDCSiteName
							"DS Type"          = $targetedADdomainSourceRWDCDSType
							"IP Address"       = $targetedADdomainSourceRWDCIPAddress
							"Reachable"        = $targetedADdomainSourceRWDCReachability
							"Source RWDC FQDN" = "N.A."
							"Time"             = 0.00
						}

						# Add The Row For The RWDC To The Table
						$listOfDCsToCheckObjectOnEnd.Add($listOfDCsToCheckObjectOnEndSourceRWDCObj)

						# Execute The Check AD Replication Convergence Function For The Targeted Object To Check
						checkADReplicationConvergence -targetedADdomainFQDN $($script:targetedADdomainFQDN) -targetedADdomainSourceRWDCFQDN $targetedADdomainSourceRWDCFQDN -targetObjectToCheckDN $targetObjectToCheckDN -listOfDCsToCheckObjectOnStart $listOfDCsToCheckObjectOnStart -listOfDCsToCheckObjectOnEnd $listOfDCsToCheckObjectOnEnd -modeOfOperationNr $modeOfOperationNr -localADforest $localADforest -adminCrds $adminCrds
					}
				}

				If ($modeOfOperationNr -eq 7 -And $isRequiredSecurityOptionEnabled -eq $true -And $isRequiredAdvancedAuditSettingsEnabled -eq $true) {
					$krbTgtPwdLastSet = $null
					$krbTgtPwdLastSet = $dcToProcess."Pwd Last Set"

					writeLog -dataToLog "  --> Previous Password Set Date/Time.......: '$krbTgtPwdLastSet'"
					writeLog -dataToLog ""

					# Determine The Starting Time For The Run Of The Monitoring Of Golden Tickets For This DC
					$startDateTimeDCMonitorGoldenTickets = Get-Date

					# Start Date/Time Event query
					If ($runNr -eq 1) {
						$collectionOfDCsToProcess | Where-Object { $_."Host Name" -eq $dcToProcess."Host Name" } | Add-Member -MemberType NoteProperty -Name "NextStartDateTimeEventQuery" -Value $(Get-Date $krbTgtPwdLastSet)
					}
					$startDateTimeEventQuery = ($collectionOfDCsToProcess | Where-Object { $_."Host Name" -eq $dcToProcess."Host Name" }).NextStartDateTimeEventQuery
					$startDateTimeEventQueryString = $(Get-Date $startDateTimeEventQuery -Format "yyyy-MM-dd HH:mm:ss")

					# Determine The FQDN Of The DC To Contact
					$fqdnDC = $dcToProcess."Host Name"

					writeLog -dataToLog "  --> DC '$fqdnDC': Retrieving 'Kerberos Service Ticket Operations' Events (ID 4769) After '$startDateTimeEventQueryString'..."
					Try {
						($collectionOfDCsToProcess | Where-Object { $_."Host Name" -eq $dcToProcess."Host Name" }).NextStartDateTimeEventQuery = $(Get-Date)
						# https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
						$securityEventsKerbSvcTicketOps = [System.Collections.Generic.List[Object]]::New()
						# Retrieve The Security Events With Event ID 4769
						If ($localADforest -eq $true -Or ($localADforest -eq $false -And $([string]::IsNullOrEmpty($adminCrds)))) {
							Try {
								Get-WinEvent -ComputerName $fqdnDC -FilterHashtable @{LogName = 'Security'; ID = 4769; StartTime = $startDateTimeEventQuery } -ErrorAction Stop | ForEach-Object {
									$securityEventsKerbSvcTicketOps.Add($_)
								}
							} Catch {
								If ($_.FullyQualifiedErrorId -match "NoMatchingEventsFound") {
									# PlaceHolder, Just For NO EVENTS!
								} Else {
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Error Retrieving The Security Events With Event ID 4769 From The DC '$($script:targetedADdomainNearestRWDCFQDN)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								}
							}
						}
						If ($localADforest -eq $false -And $(-not $([string]::IsNullOrEmpty($adminCrds)))) {
							Try {
								Get-WinEvent -ComputerName $fqdnDC -FilterHashtable @{LogName = 'Security'; ID = 4769; StartTime = $startDateTimeEventQuery } -Credential $adminCrds -ErrorAction Stop | ForEach-Object {
									$securityEventsKerbSvcTicketOps.Add($_)
								}
							} Catch {
								If ($_.FullyQualifiedErrorId -match "NoMatchingEventsFound") {
									# PlaceHolder, Just For NO EVENTS!
								} Else {
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Error Retrieving The Security Events With Event ID 4769 From The DC '$($script:targetedADdomainNearestRWDCFQDN)' Using '$($adminCrds.UserName)'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Exception Type......: $($_.Exception.GetType().FullName)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Exception Message...: $($_.Exception.Message)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
									writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
								}
							}
						}
						writeLog -dataToLog "    --> Found '$(($securityEventsKerbSvcTicketOps | Measure-Object).Count)' Security Events For ID 4769 On DC '$fqdnDC' Since Last Reset Date/Time" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
					} Catch {
						writeLog -dataToLog "    --> Found '$(($securityEventsKerbSvcTicketOps | Measure-Object).Count)' Security Events For ID 4769 On DC '$fqdnDC'" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
					}

					# The RecordID Is Basicly Used To NOT Retrieve Events That Were Already Retrieved In A Previous Run Against The Same DC. When It (The Variable) Does NOT Exist, It Is The First Query For That DC, Otherwise Subsequent Query
					If (($securityEventsKerbSvcTicketOps | Measure-Object).Count -gt 0) {
						Try {
							$lastRecordId = $null
							$lastRecordId = (Get-Variable $($fqdnDC + "_LastRecordId") -ErrorAction Stop).Value
							$securityEventsKerbSvcTicketOps | Where-Object { $_.RecordID -gt $lastRecordId } | ForEach-Object {
								$filteredSecurityEventsKerbSvcTicketOps.Add($_)
							}
						} Catch {
							New-Variable $($fqdnDC + "_LastRecordId")
							$securityEventsKerbSvcTicketOps | ForEach-Object {
								$filteredSecurityEventsKerbSvcTicketOps.Add($_)
							}
						}
						Set-Variable $($fqdnDC + "_LastRecordId") -Value $securityEventsKerbSvcTicketOps[0].RecordId
					}

					# Define The Ending Time For The Run Of The Monitoring Of Golden Tickets For This DC
					$endDateTimeDCMonitorGoldenTickets = Get-Date

					# Calculate The Duration
					$durationDCMonitorGoldenTickets = "{0:n2}" -f ($endDateTimeDCMonitorGoldenTickets.Subtract($startDateTimeDCMonitorGoldenTickets).TotalSeconds)

					writeLog -dataToLog ""
					writeLog -dataToLog "    --> Start Time......: $(Get-Date $startDateTimeDCMonitorGoldenTickets -format 'yyyy-MM-dd HH:mm:ss')" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "    --> End Time........: $(Get-Date $endDateTimeDCMonitorGoldenTickets -format 'yyyy-MM-dd HH:mm:ss')" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "    --> Duration........: $durationDCMonitorGoldenTickets Seconds" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog ""
				}
			}

			If ($modeOfOperationNr -eq 7 -And $isRequiredSecurityOptionEnabled -eq $true -And $isRequiredAdvancedAuditSettingsEnabled -eq $true) {
				# Get The Suspicious Kerberos Service Ticket Operations With Error:
				# * 0x6  | KDC_ERR_C_PRINCIPAL_UNKNOWN | Client not found in Kerberos database
				# * 0x1F | KRB_AP_ERR_BAD_INTEGRITY    | Integrity check on decrypted field failed
				# * 0x40 | KDC_ERR_INVALID_SIG         | The signature is invalid
				$suspiciousKerbSvcTicketOps = [System.Collections.Generic.List[Object]]::New()
				If (($filteredSecurityEventsKerbSvcTicketOps | Measure-Object).Count -gt 0) {
					$filteredSecurityEventsKerbSvcTicketOps | Where-Object { $_.KeywordsDisplayNames -eq "Audit Failure" -And ($(([xml]($_.ToXml())).Event.EventData.Data.'#text'[8]) -eq "0x6" -Or $(([xml]($_.ToXml())).Event.EventData.Data.'#text'[8]) -eq "0x1F" -Or $(([xml]($_.ToXml())).Event.EventData.Data.'#text'[8]) -eq "0x40") } | ForEach-Object {
						$suspiciousKerbSvcTicketOps.Add($_)
					}
				}

				# Report The Numbers Found
				writeLog -dataToLog ""
				writeLog -dataToLog ""
				writeLog -dataToLog "SUMMARY - THIS RUN ($runNr):"
				writeLog -dataToLog "  --> Found '$(($filteredSecurityEventsKerbSvcTicketOps | Measure-Object).Count)' Security Events For ID 4769 (Kerberos Service Ticket Operations) During THIS Run..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
				writeLog -dataToLog "  --> Found '$(($suspiciousKerbSvcTicketOps | Measure-Object).Count)' Suspicious TGS Requests With Error '0x6', '0x1F' or '0x40' During THIS Run..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "      '0x6' = KDC_ERR_C_PRINCIPAL_UNKNOWN = Client not found in Kerberos database" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "      '0x1F' = KRB_AP_ERR_BAD_INTEGRITY = Integrity check on decrypted field failed" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "      '0x40' = KDC_ERR_INVALID_SIG = The signature is invalid" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

				# Process Any Suspicious Kerberos Service Ticket Operations
				$suspiciousKerbSvcTicketOpsProcessed = [System.Collections.Generic.List[Object]]::New()
				If (($suspiciousKerbSvcTicketOps | Measure-Object).Count -gt 0) {
					$suspiciousKerbSvcTicketOps | ForEach-Object {
						$suspiciousKerbSvcTicketOpsEvent = $null
						$suspiciousKerbSvcTicketOpsEvent = $_

						$ipAddress = $null
						$ipAddress = $(([xml]($suspiciousKerbSvcTicketOpsEvent.ToXml())).Event.EventData.Data.'#text'[6]).Split(":")[-1]
						$hostName = $null
						If ($ipAddress -ne $null -And $ipAddress -match $ipv4Regex) {
							$hostName = $([System.Net.Dns]::GetHostEntry($ipAddress)).HostName
						}
						$suspiciousKerbSvcTicketOps = [PSCustomObject]@{
							"IP Address"             = $ipAddress
							"Host Name"              = $hostName
							"Time Created"           = $($suspiciousKerbSvcTicketOpsEvent.TimeCreated)
							"Target DomainName"      = $(([xml]($suspiciousKerbSvcTicketOpsEvent.ToXml())).Event.EventData.Data.'#text'[1])
							"Target UserName"        = $(([xml]($suspiciousKerbSvcTicketOpsEvent.ToXml())).Event.EventData.Data.'#text'[0])
							"Service Name"           = $(([xml]($suspiciousKerbSvcTicketOpsEvent.ToXml())).Event.EventData.Data.'#text'[2])
							"Service SID"            = $(([xml]($suspiciousKerbSvcTicketOpsEvent.ToXml())).Event.EventData.Data.'#text'[3])
							"Ticket Options"         = $(([xml]($suspiciousKerbSvcTicketOpsEvent.ToXml())).Event.EventData.Data.'#text'[4])
							"Ticket Encryption Type" = $(([xml]($suspiciousKerbSvcTicketOpsEvent.ToXml())).Event.EventData.Data.'#text'[5])
							"Port"                   = $(([xml]($suspiciousKerbSvcTicketOpsEvent.ToXml())).Event.EventData.Data.'#text'[7])
							"Status/Error Code"      = $(([xml]($suspiciousKerbSvcTicketOpsEvent.ToXml())).Event.EventData.Data.'#text'[8])
							"Logon GUID"             = $(([xml]($suspiciousKerbSvcTicketOpsEvent.ToXml())).Event.EventData.Data.'#text'[9])
							"Transmitted Services"   = $(([xml]($suspiciousKerbSvcTicketOpsEvent.ToXml())).Event.EventData.Data.'#text'[10])
						}
						$suspiciousKerbSvcTicketOpsProcessed.Add($suspiciousKerbSvcTicketOps)
					}
					If (($suspiciousKerbSvcTicketOpsProcessed | Measure-Object).Count -gt 0) {
						$suspiciousKerbSvcTicketOpsProcessed | Export-Csv -Path $suspiciousTicketsFileMonitoringRunGoldenTickets -Force -Encoding Unicode -NoTypeInformation
						writeLog -dataToLog ""
						writeLog -dataToLog "  --> Suspicious TGS Requests During THIS Run Exported To '$suspiciousTicketsFileMonitoringRunGoldenTickets' And Mailed If Configured..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

						If ($sendMailEnabled.ToUpper() -eq "TRUE") {
							$mailAttachments = [System.Collections.Generic.List[Object]]::New()
							$mailAttachments.Add($suspiciousTicketsFileMonitoringRunGoldenTickets)

							$context = "SCRIPT - NORMAL OPS: Suspicious TGS requests detected!"

							sendMailMessage -configResetKrbTgtPasswordSettings $script:configResetKrbTgtPasswordSettings -mailAttachments $mailAttachments -context $context
						}
					}
				}

				# Define The Ending Time For The Run Of The Monitoring Of Golden Tickets Across All Contacted DCs
				$endDateTimeRunMonitorGoldenTickets = Get-Date

				# Cleanup All The Variables
				Get-Variable "*_LastRecordId" | Remove-Variable

				# Calculate The Duration
				$durationRunMonitorGoldenTickets = "{0:n2}" -f ($endDateTimeRunMonitorGoldenTickets.Subtract($startDateTimeRunMonitorGoldenTickets).TotalSeconds)
				writeLog -dataToLog ""
				writeLog -dataToLog "  --> Start Time........: $(Get-Date $startDateTimeRunMonitorGoldenTickets -format 'yyyy-MM-dd HH:mm:ss')" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  --> End Time..........: $(Get-Date $endDateTimeRunMonitorGoldenTickets -format 'yyyy-MM-dd HH:mm:ss')" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  --> Duration..........: $durationRunMonitorGoldenTickets Seconds" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog ""
			}

			# If Any DC Object Exists In The Unknown DC List
			If ($($collectionOfDCsNotToProcess | Measure-Object).Count -gt 0) {
				writeLog -dataToLog "+++++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				If ($modeOfOperationNr -eq 7 -And $isRequiredSecurityOptionEnabled -eq $true -And $isRequiredAdvancedAuditSettingsEnabled -eq $true) {
					writeLog -dataToLog "+++ The Following DCs Were Not Contacted As Those Are Not Reachable..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				} Else {
					writeLog -dataToLog "+++ The Following Look Like DCs, But May Not Be Real DCs..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				}
				writeLog -dataToLog "+++++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

				# For Every Unknown DC
				$collectionOfDCsNotToProcess | ForEach-Object {
					$dcToProcess = $null
					$dcToProcess = $_
					writeLog -dataToLog "$($dcToProcess | Format-Table * | Out-String -Width 1024)"
					writeLog -dataToLog ""
				}
				writeLog -dataToLog ""
			}

			If ($modeOfOperationNr -eq 7 -And $isRequiredSecurityOptionEnabled -eq $true -And $isRequiredAdvancedAuditSettingsEnabled -eq $true) {
				writeLog -dataToLog ""
				writeLog -dataToLog "Waiting For $goldenTicketMonitorWaitingIntervalBetweenRuns Seconds Until Continuing With The Next Run..."
				writeLog -dataToLog ""
				startCountdown $goldenTicketMonitorWaitingIntervalBetweenRuns
			}
		} Until ($modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6 -Or ($modeOfOperationNr -eq 7 -And $(Get-Date) -gt $($execDateTime.AddSeconds($goldenTicketMonitoringPeriod))))
	}
}

###
# Mode 8 - Create TEST/BOGUS KrbTgt Accounts
###
If ($modeOfOperationNr -eq 8) {
	writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "CREATE TEST/BOGUS KrbTgt ACCOUNTS (MODE 8)..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""

	# Asking Confirmation To Continue Or Not
	writeLog -dataToLog "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: " -lineType "ACTION-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false
	$continueOrStop = Read-Host

	# Any Confirmation Not Equal To CONTINUE Will Be Equal To STOP
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		$continueOrStop = "STOP"
	}
	writeLog -dataToLog ""
	writeLog -dataToLog "  --> Chosen: $continueOrStop" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""

	# Any Confirmation Not Equal To CONTINUE Will Abort The Script
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		# Mail The Log File With The Results
		If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
			$context = "SCRIPT - NORMAL OPS: The script was told to stop and not to continue!"

			sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
		}

		EXIT
	}

	# Retrieve The FQDN Of The RWDC With The PDC FSMO To Create The TEST/BOGUS KrbTgt Account Objects
	$targetedADdomainSourceRWDCFQDN = $null
	$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object { $_.PDC -eq $true })."Host Name"

	# Determine The KrbTgt Account In Use By The RWDC with The PDC FSMO (Representative For All RWDCs In The AD Domain)
	$krbTgtSamAccountName = $null
	$krbTgtSamAccountName = ($tableOfDCsInADDomain | Where-Object { $_.PDC -eq $true })."Krb Tgt"
	writeLog -dataToLog "+++++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "+++ Create TEST/BOGUS KrbTgt Acct: '$krbTgtSamAccountName' +++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "+++ Used By RWDC.................: 'All RWDCs' +++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "+++++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

	# Execute The Creation TEST/BOGUS KrbTgt Accounts Function To Create The TEST/BOGUS KrbTgt Account For RWDCs
	createTestKrbTgtADAccount -targetedADdomainRWDCFQDN $targetedADdomainSourceRWDCFQDN -krbTgtInUseByDCFQDN $targetedADdomainSourceRWDCFQDN -krbTgtSamAccountName $krbTgtSamAccountName -krbTgtUse "RWDC" -targetedADdomainDomainSID $targetedADdomainDomainSID -localADforest $localADforest -adminCrds $adminCrds

	# For All RODCs In The AD Domain That Do Not Have An Unknown RWDC Specfied
	$tableOfDCsInADDomain | Where-Object { $_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -ne "Unknown" } | ForEach-Object {
		# Retrieve The RODC Object In The List
		$rodcToProcess = $null
		$rodcToProcess = $_

		# Retrieve The sAMAccountName Of The KrbTgt Account In Use By The RODC
		$krbTgtSamAccountName = $null
		$krbTgtSamAccountName = $rodcToProcess."Krb Tgt"

		# Retrieve The HostName Of The RODC
		$rodcFQDNTarget = $null
		$rodcFQDNTarget = $rodcToProcess."Host Name"

		# Retrieve The SiteName Of The RODC
		$rodcSiteTarget = $null
		$rodcSiteTarget = $rodcToProcess."Site Name"
		writeLog -dataToLog "+++++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "+++ Create TEST/BOGUS KrbTgt Account...: '$krbTgtSamAccountName' +++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "+++ Used By RODC.................: '$rodcFQDNTarget' (Site: $rodcSiteTarget) +++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "+++++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

		# Execute The Create TEST/BOGUS KrbTgt Accounts Function To Create The TEST/BOGUS KrbTgt Account For Each RODC
		createTestKrbTgtADAccount -targetedADdomainRWDCFQDN $targetedADdomainSourceRWDCFQDN -krbTgtInUseByDCFQDN $rodcFQDNTarget -krbTgtSamAccountName $krbTgtSamAccountName -krbTgtUse "RODC" -targetedADdomainDomainSID $targetedADdomainDomainSID -localADforest $localADforest -adminCrds $adminCrds
	}
}

###
# Mode 9 - Cleanup TEST/BOGUS KrbTgt Accounts
###
If ($modeOfOperationNr -eq 9) {
	writeLog -dataToLog "------------------------------------------------------------------------------------------------------------------------------------------------------" -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "CLEANUP TEST/BOGUS KrbTgt ACCOUNTS (MODE 9)..." -lineType "HEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""

	# Asking Confirmation To Continue Or Not
	writeLog -dataToLog "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: " -lineType "ACTION-NO-NEW-LINE" -logFileOnly $false -noDateTimeInLogLine $false
	$continueOrStop = Read-Host

	# Any Confirmation Not Equal To CONTINUE Will Be Equal To STOP
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		$continueOrStop = "STOP"
	}
	writeLog -dataToLog ""
	writeLog -dataToLog "  --> Chosen: $continueOrStop" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""

	# Any Confirmation Not Equal To CONTINUE Will Abort The Script
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		# Mail The Log File With The Results
		If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
			$context = "SCRIPT - NORMAL OPS: The script was told to stop and not to continue!"

			sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
		}

		EXIT
	}

	# Retrieve The FQDN Of The RWDC With The PDC FSMO To Delete The TEST/BOGUS KrbTgt Account Objects
	$targetedADdomainSourceRWDCFQDN = $null
	$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object { $_.PDC -eq $true })."Host Name"

	# Determine The KrbTgt Account In Use By The RWDC with The PDC FSMO (Representative For All RWDCs In The AD Domain)
	$krbTgtSamAccountName = $null
	$krbTgtSamAccountName = ($tableOfDCsInADDomain | Where-Object { $_.PDC -eq $true })."Krb Tgt"
	writeLog -dataToLog "+++++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "+++ Delete TEST/BOGUS KrbTgt Acct: '$krbTgtSamAccountName' +++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "+++ Used By RWDC.................: 'All RWDCs' +++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "+++++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

	# Execute The Delete TEST/BOGUS KrbTgt Accounts Function To Delete The TEST/BOGUS KrbTgt Account For RWDCs. There Is No Need To Force Deletion Of The Object On All The Other DCs As In Time It Will Be Deleted
	deleteTestKrbTgtADAccount -targetedADdomainRWDCFQDN $targetedADdomainSourceRWDCFQDN -krbTgtSamAccountName $krbTgtSamAccountName -localADforest $localADforest -adminCrds $adminCrds

	# For All RODCs In The AD Domain That Do Not Have An Unknown RWDC Specfied
	$tableOfDCsInADDomain | Where-Object { $_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -ne "Unknown" } | ForEach-Object {
		# Retrieve The RODC Object In The List
		$rodcToProcess = $null
		$rodcToProcess = $_

		# Retrieve The sAMAccountName Of The KrbTgt Account In Use By The RODC
		$krbTgtSamAccountName = $null
		$krbTgtSamAccountName = $rodcToProcess."Krb Tgt"

		# Retrieve The HostName Of The RODC
		$rodcFQDNTarget = $null
		$rodcFQDNTarget = $rodcToProcess."Host Name"

		# Retrieve The SiteName Of The RODC
		$rodcSiteTarget = $null
		$rodcSiteTarget = $rodcToProcess."Site Name"
		writeLog -dataToLog "+++++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "+++ Delete TEST/BOGUS KrbTgt Account...: '$krbTgtSamAccountName' +++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "+++ Used By RODC.................: '$rodcFQDNTarget' (Site: $rodcSiteTarget) +++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "+++++" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

		# Execute The Delete TEST/BOGUS KrbTgt Accounts Function To Delete The TEST/BOGUS KrbTgt Account For Each RODC. There Is No Need To Force Deletion Of The Object On All The Other DCs As In Time It Will Be Deleted
		deleteTestKrbTgtADAccount -targetedADdomainRWDCFQDN $targetedADdomainSourceRWDCFQDN -krbTgtSamAccountName $krbTgtSamAccountName -localADforest $localADforest -adminCrds $adminCrds
	}
}

# Display The Number Of Totally Processed, Candidate For Reset, NOT Candidate For Reset, With SUCCESSFUL Reset, With FAILED Reset
If ($modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 6) {
	writeLog -dataToLog "Nr Of KrbTGT Account(s) Processed In TOTAL..........: $($script:numAccntsProcessedTOTAL)"
	writeLog -dataToLog "Nr Of KrbTGT Account(s) Candidate For Reset.........: $($script:numAccntsResetCandidateYES)"
	writeLog -dataToLog "Nr Of KrbTGT Account(s) NOT Candidate For Reset.....: $($script:numAccntsResetCandidateNO)"
	writeLog -dataToLog "Nr Of KrbTGT Account(s) With SUCCESSFUL Reset.......: $($script:numAccntsResetSUCCESS)"
	writeLog -dataToLog "Nr Of KrbTGT Account(s) With FAILED Reset...........: $($script:numAccntsResetFAIL)"
	writeLog -dataToLog "Nr Of KrbTGT Account(s) With SKIPPED Reset..........: $($script:numAccntsResetSKIP)"
	writeLog -dataToLog "Nr Of KrbTGT Account(s) With ANOMALY DETECTED.......: $($script:numAccntsResetANOMALY)"
}

# Display The Full Path To The Log File
writeLog -dataToLog ""
writeLog -dataToLog "Log File Path...: $logFilePath" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

# Mail The Log File With The Results
If ($sendMailWithLogFile -And $sendMailEnabled.ToUpper() -eq "TRUE") {
	If ($script:numAccntsResetANOMALY -eq 0) {
		$context = "SCRIPT - NORMAL OPS: Script completed successfully!"
	} Else {
		$context = "SCRIPT - NORMAL OPS: Script completed successfully, but ANOMALIES were detected (see table below and log file for details)!"
	}

	sendMailWithAttachmentAndDisplayOutput -mailToRecipients $mailToRecipients -mailCcRecipients $mailCcRecipients -logFilePath $logFilePath -zipFilePath $zipFilePath -context $context
}