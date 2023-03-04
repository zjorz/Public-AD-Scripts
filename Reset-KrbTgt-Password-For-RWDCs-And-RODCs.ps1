###
# Parameters Used By Script
###
Param (
	[switch]$noInfo,
	[ValidateSet("infoMode", "simulModeCanaryObject", "simulModeKrbTgtTestAccountsWhatIf", "resetModeKrbTgtTestAccountsResetOnce", "simulModeKrbTgtProdAccountsWhatIf", "resetModeKrbTgtProdAccountsResetOnce")]
	[string]$modeOfOperation,
	[string]$targetedADforestFQDN,
	[string]$targetedADdomainFQDN,
	[ValidateSet("allRWDCs", "allRODCs", "specificRODCs")]
	[string]$targetKrbTgtAccountScope,
	[string[]]$targetRODCFQDNList,
	[switch]$continueOps,
	[switch]$sendMailWithLogFile
)

###
# Version Of Script
###
$version = "v3.4, 2023-03-04"

<#
	AUTHOR
		Written By....................: Jorge de Almeida Pinto [MVP Enterprise Mobility And Security, EMS / Lead Identity/Security Architect]
		Re-Written By.................: N.A.
		Company.......................: IAMTEC >> Identity | Security | Recovery [https://www.iamtec.eu/]
		Blog..........................: Jorge's Quest For Knowledge [http://jorgequestforknowledge.wordpress.com/]
		For Feedback/Questions........: scripts.gallery@iamtec.eu
			--> Please Describe Your Scenario As Best As Possible With As Much Detail As Possible.
			--> If Applicable Describe What Does and/Or Does Not Work.
			--> If Applicable Describe What Should Be/Work Different And Explain Why/How.
			--> Please Add Screendumps.

	ORIGINAL SOURCES
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

	RELEASE NOTES
		v3.4, 2023-03-04, Jorge de Almeida Pinto [MVP-EMS]:
			- Bug Fix: The PowerShell CMDlets from the ActiveDirectory module DO recognize the 2016 FFL and DFL. The script DOES NOT use those anymore, but instead uses S.DS.P.. The issue appears to be that MSFT did update the
				ActiveDirectory module to recognize the 2016 FFL/DFl, but they apparently did not update the S.DS.P. DLLs to do the same. The script itself now detects this and reports the correct FFL/DFL when it is 2016

		v3.3, 2022-12-20, Jorge de Almeida Pinto [MVP-EMS]:
			- Bug Fix: updated the attribute type when specifying the number of the AD domain instead of the actual FQDN of the AD domain

		v3.2, 2022-11-05, Jorge de Almeida Pinto [MVP-EMS]:
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

		v3.1, 2022-06-06, Jorge de Almeida Pinto [MVP-EMS]:
			- Improved User Experience: The S.DS.P PowerShell Module v2.1.4 has been included into this script (with permission and under GPL license) to remove the dependency of the AD PowerShell Module when querying objects in AD. The
				ActiveDirectory PowerShell module is still used to get forest, domain, and domaincontroller information.
			- Improved User Experience: Removed dependency for port 135 (RPC Endpoint Mapper) and 9389 (AD Web Service)
			- Bug Fix: Getting the description of the Test KrbTgt accounts in remote AD forest with explicit credentials to compare and fix later
			- Code Improvement: In addition to check for the correct description, also check if the test KrbTgt accounts are member of the correct groups
			- Code Improvement: Updated function createTestKrbTgtADAccount
			- Bug Fix: Minor textual fixes

		v3.0, 2022-05-27, Jorge de Almeida Pinto [MVP-EMS]:
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

		v2.9, 2021-05-04, Jorge de Almeida Pinto [MVP-EMS]:
			- Improved User Experience: Added additional info and recommendations
			- New Feature: Added function to check UAC elevation status, and if not elevated to start the script automatically using an elevated PowerShell Command Prompt

		v2.8, 2020-04-02, Jorge de Almeida Pinto [MVP-EMS]:
			- Bug fix: Fixed an issue when the RODC itself is not reachable/available, whereas in that case, the source should be the RWDC with the PDC FSMO
			- Improved User Experience: Checks to make sure both the RWDC with the PDC FSMO role and the nearest RWDC are available. If either one is not available, the script will abort

		v2.7, 2020-04-02, Jorge de Almeida Pinto [MVP-EMS]:
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
				- 3 - Simulation Mode | Use KrbTgt TEST/BOGUS Accounts - No Password Reset/WhatIf Mode!
				- 4 - Real Reset Mode | Use KrbTgt TEST/BOGUS Accounts - Password Will Be Reset Once!
				- 5 - Simulation Mode | Use KrbTgt PROD/REAL Accounts - No Password Reset/WhatIf Mode!
				- 6 - Real Reset Mode | Use KrbTgt PROD/REAL Accounts - Password Will Be Reset Once!
			- Improved User Experience: When choosing RODC Krb Tgt Account scope the following will now occur:
				- If the RODC is not reachable, the real source RWDC of the RODC cannot be determined. In that case, the RWDC with the PDC FSMO role is used as the source for the change and replication
				- If the RODC is reachable, but the real source RWDC of the RODC is not reachable it cannot be used as the source for the change and replication. In that case, the RWDC with the PDC FSMO role is used as the source for the change and replication

		v2.6, 2020-02-25, Jorge de Almeida Pinto [MVP-EMS]:
			- Code Improvement: Removed code that was commented out
			- Code Improvement: In addition to the port 135 (RPC Endpoint Mapper) and 389 (LDAP), the script will also check for port 9389 (AD Web Service) which is used by the ADDS PoSH CMDlets
			- Code Improvement: Updated script to included more 'try/catch' and more (error) logging, incl. line where it fails, when things go wrong to make troubleshooting easier
			- Improved User Experience: Logging where the script is being executed from
			- Improved User Experience: Updated the function 'createTestKrbTgtADAccount' to also include the FQDN of the RODC for which the Test KrbTgt account is created for better recognition

		v2.5, 2020-02-17, Jorge de Almeida Pinto [MVP-EMS]:
			- Code Improvement: To improve performance, for some actions the nearest RWDC is discovered instead of using the RWDC with the PDC FSMO Role

		v2.4, 2020-02-10, Jorge de Almeida Pinto [MVP-EMS]:
			- Bug Fix: Fixed language specific issue with the groups 'Allowed RODC Password Replication Group' and 'Denied RODC Password Replication Group'
			- Code Improvement: Checked script with Visual Studio Code and fixed all "problems" identified by Visual Studio Code
				- Variable "$remoteCredsUsed" is ignored by me, as the problem is due to the part 'Creds' in the variable name
				- Variable "$adminCreds" is ignored by me, as the problem is due to the part 'Creds' in the variable name
			- New Feature: Added support to execute this script against a remote AD forest, either with or without a trust

		v2.3, 2019-02-25, Jorge de Almeida Pinto [MVP-EMS]:
			- Code Improvement: Removed the language specific error checking. Has been replaced with another check. This solution also resolved another
				issue when checking if a (RW/RO)DC was available or not

		v2.2, 2019-02-12, Jorge de Almeida Pinto [MVP-EMS]:
			- Code Improvement: Instead of searching for "Domain Admins" or "Enterprise Admins" membership, it resolves the default RIDs of those
				groups, combined with the corresponding domain SID, to the actual name of those domain groups. This helps in supporting non-english
				names of those domain groups

		v2.1, 2019-02-11, Jorge de Almeida Pinto [MVP-EMS]:
			- Code Improvement: Added a try catch when enumerating details about a specific AD domain that appears not to be available
			- New Feature: Read and display metadata of the KrbTgt accounts before and after to assure it was only updated once!

		v2.0, 2018-12-30, Jorge de Almeida Pinto [MVP-EMS]:
			- Code Improvement: Full rewrite and major release
			- New Feature: Added possibility to also reset KrbTgt account in use by RODCs
			- New Feature: Added possibility to try this procedure using a temp canary object (contact object)
			- New Feature: Added possibility to try this procedure using a TEST krbtgt accounts and perform password reset on those TEST krbtgt accounts
			- New Feature: Added possibility to create TEST krbtgt accounts if required
			- New Feature: Added possibility to delete TEST krbtgt accounts if required
			- New Feature: Check if an RODC account is indeed in use by a Windows RODC and not something simulating an RODC (e.g. Riverbed)
			- New Feature: Removed dependency for REPADMIN.EXE
			- New Feature: Removed dependency for RPCPING.EXE
			- New Feature: Extensive logging to both screen and file
			- New Feature: Added more checks, such as permissions check, etc.
			- Script Improvement: Renamed script to Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1

		v1.7, Jared Poeppelman, Microsoft
			- Code Improvement: Modified rpcping.exe call to use "-u 9 -a connect" parameters to accomodate tighter RPC security settings as specified in
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
	- Single Password Reset for the KrbTgt account in use by RWDCs in a specific AD domain, using either TEST or PROD KrbTgt accounts
	- Single Password Reset for the KrbTgt account in use by an individual RODC in a specific AD domain, using either TEST or PROD KrbTgt accounts
		* A single RODC in a specific AD domain
		* A specific list of RODCs in a specific AD domain
		* All RODCs in a specific AD domain
	- Resetting the password/keys of the KrbTgt Account can be done for multiple reasons such as for example:
		* From a security perspective as mentioned in https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/
		* From an AD recovery perspective as mentioned in https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password
	- For all scenarios, an informational mode, which is mode 1 with no changes
	- For all scenarios, a simulation mode, which is mode 2 where replication is tested through the replication of a temporary canary
		object that is created and deleted afterwards. No Password Resets involved here as the temporary canary object is a contact object
	- For all scenarios, a simulation mode, which is mode 3 where NO password reset of the chosen TEST KrbTgt account occurs. Basically this
		just checks the status of the objects on scoped DCs. NOTHING is changed. Can be scoped for RWDCs and RODCs (single, multiple, all)
	- For all scenarios, a real reset mode, which is mode 4 where the password reset of the chosen TEST KrbTgt account is actually executed
		and replication of it is monitored through the environment for its duration. Can be scoped for RWDCs and RODCs (single, multiple, all)
	- For all scenarios, a simulation mode, which is mode 5 where NO password reset of the chosen PROD KrbTgt account occurs. Basically this
		just checks the status of the objects on scoped DCs. NOTHING is changed. Can be scoped for RWDCs and RODCs (single, multiple, all)
	- For all scenarios, a real reset mode, which is mode 6 where the password reset of the chosen PROD KrbTgt account is actually executed
		and replication of it is monitored through the environment for its duration
	- The creation of Test KrbTgt Accounts, which is mode 8
	- The deletion of Test KrbTgt Accounts, which is mode 9
	- It is possible to run the script in a scheduled and automated manner by specifying the correct parameters and the correct information
	- When running in a scheduled and automated manner, it is possible to have the log file mailed to some defined mailbox
	- When mailing it is possible to sign and/or encrypt the mail message, provided the correct certificates are available for signing and/or
		encryption
	- Certificates can either be in the User Store or in a PFX file with the password available (Signing and Encryption) or in a CER file
		(Encryption Only)
	- When mailing of the log file is needed in ANY way, a configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml" is needed
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
	- In mode 8, for RWDCs it creates (in disabled state!) the TEST/BOGUS krbtgt account "krbtgt_TEST" and adds it to the AD group
		"Denied RODC Password Replication Group". If any RODC exists in the targeted AD domain, it reads the attribute "msDS-KrbTgtLink" of
		each RODC computer account to determine the RODC specific krbtgt account and creates (in disabled state!) the TEST/BOGUS krbtgt
		account "krbtgt_<Numeric Value>_TEST" and adds it to the AD group "Allowed RODC Password Replication Group"
	- In mode 9, for RWDCs it deletes the TEST/BOGUS krbtgt account "krbtgt_TEST" if it exists. If any RODC exists in the targeted AD domain,
		it reads the attribute "msDS-KrbTgtLink" of each RODC computer account to determine the RODC specific krbtgt account and deletes the
		TEST/BOGUS krbtgt account "krbtgt_<Numeric Value>_TEST" if it exists.
	- In mode 2, 3, 4, 5 or 6, if a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database
		to determine if the change made reached it or not.
	- In mode 2 when performing the "replicate single object" operation, it will always be for the full object, no matter if the remote DC
		is an RWDC or an RODC
	- In mode 3, 4, 5 or 6 when performing the "replicate single object" operation, it will always be for the full object, if the remote DC is an
		RWDC. If the remote DC is an RODC it will always be for the partial object and more specifically "secrets only"
	- When targeting the krbtgt account (TEST/BOGUS or PROD/REAL) in use by all the RWDCs, the originating RWDC is the RWDC with the PDC FSMO
		and all other available/reachable RWDCs will be checked against to see if the change has reached them. No RODCs are involved as those
		do not use the krbtg account in use by the RWDCs and also do not store/cache its password.
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
						"simulModeKrbTgtProdAccountsWhatIf", "resetModeKrbTgtProdAccountsResetOnce"

.PARAMETER targetedADforestFQDN
	With this parameter it is possible to specify the FQDN of an AD forest that will be targeted. This should only be used in an automated manner
	such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

.PARAMETER targetedADdomainFQDN
	With this parameter it is possible to specify the FQDN of an AD domain that will be targeted within the specified AD forest. This should only
	be used in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

.PARAMETER targetKrbTgtAccountScope
	With this parameter it is possible to specify the scope of the targeted KrbTgt account. This should only be used in an automated manner such
	as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!
	Accepted values are: "allRWDCs", "allRODCs", "specificRODCs"

.PARAMETER targetRODCFQDNList
	With this parameter it is possible to specify one or more RODCs through a comma-separated list. This parameter is ONLY needed when the
	targetKrbTgtAccountScope is set to specificRODCs. This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY after
	testing an getting confidence of what will happen!

.PARAMETER continueOps
	With this parameter it is possible to specify the script should continue where it is needed to confirm the operation depending of whether there
	is impact or not. If the script determines there is impact, the script will abort to prevent impact. Only when running ON-DEMAND without any
	parameters will it be possible to continue and still have domain wide impact, in other words ignore there is impact. This should only be used
	in an automated manner such as in a Scheduled Task, BUT ONLY after testing an getting confidence of what will happen!

.PARAMETER sendMailWithLogFile
	With this parameter it is possible to specify the script should mail the LOG file at any moment when the script stops running, whether it
	finished succesfully or due to encountered issue(s). This should only be used in an automated manner such as in a Scheduled Task, BUT ONLY
	after testing an getting confidence of what will happen!

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
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 3 With All RWDCs As Scope

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeKrbTgtTestAccountsWhatIf -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 4 With All RWDCs As Scope

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtTestAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 5 With All RWDCs As Scope

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeKrbTgtProdAccountsWhatIf -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 6 With All RWDCs As Scope

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRWDCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 3 With All RODCs As Scope

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeKrbTgtTestAccountsWhatIf -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRODCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 4 With All RODCs As Scope

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtTestAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRODCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 5 With All RODCs As Scope

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation simulModeKrbTgtProdAccountsWhatIf -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRODCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 6 With All RODCs As Scope

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope allRODCs -continueOps -sendMailWithLogFile

.EXAMPLE
	Execute The Script - Automated And Sending The Log File Through Mail - Mode 6 With Specific RODCs (But Not All) As Scope

	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1 -noInfo -modeOfOperation resetModeKrbTgtProdAccountsResetOnce -targetedADforestFQDN DOMAIN.COM -targetedADdomainFQDN CHILD.DOMAIN.COM -targetKrbTgtAccountScope specificRODCs -targetRODCFQDNList "RODC1.DOMAIN.COM","RODC2.DOMAIN.COM","RODC3.DOMAIN.COM" -continueOps -sendMailWithLogFile

.NOTES
	- Required PoSH CMDlets: GPMC PoSH CMDlets on all targeted RWDCs!!! (and the S.DS.P Posh CMDlets are INCLUDED in this script!)
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
	- If User Account Control (UAC) is in effect (i.e. enabled) the script MUST be executed in an elevated Powershell Command Prompt Window!
	- When running the script on-demand with an account that does have the correct permissions, the script will ask for credentials with the
		correct permissions
	- When running the script automated with an account that does have the correct permissions, the script will NOT ask for credentials with the
		correct permissions. It will just stop. Therefore in an automated manner, the running account MUST have the correct permissions!
	- When mailing of the log file is needed and the mail message must be signed and/or encrypted, then an external DLL is needed to
		provide such functionality. The source code can be download from https://www.codeproject.com/Articles/41727/An-S-MIME-Library-for-Sending-Signed-and-Encrypted
		and you must compile it yourself! I have NOT reviewed that source code in any way. You MUST review that source code yourself and
		determine if you use it or not!. The path of the DLL must be specified in the configuration XML file so that the script can find
		it and load it
	- When there is a need to SIGN the mail message, then a certificate with a private key (PFX file or in the User Store) is needed for
		the sender
	- When there is a need to ENCRYPT the mail message, then a certificate (CER file or in the User Store) is needed for EVERY recipient!
		In turn, every recipient must have the corresponding certificate with a private key (in the User Store) to be able to decrypt the mail
	- When there is a need to SIGN and ENCRYPT the mail message, both of the previous requirements must be met
	- To SIGN and/or ENCRYPT the mail message, the correct certificate must be issued and used, such as one with EKU "Secure Email (1.3.6.1.5.5.7.3.4)"
	- Configuration XML file "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml" structure
============ Configuration XML file ============
<?xml version="1.0" encoding="utf-8"?>
<resetKrbTgtPassword xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<!-- FQDN Of The Mail Server Or Mail Relay -->
	<smtpServer>REPLACE_WITH_MAIL_SERVER_FQDN</smtpServer>

	<!-- SMTP Port To Use -->
	<smtpPort>REPLACE_WITH_MAIL_SERVER_SMTP_PORT_NUMERIC_VALUE</smtpPort>

	<!-- SSL FOR SMTP - TRUE OR FALSE -->
	<useSSLForSMTP>TRUE_OR_FALSE</useSSLForSMTP>

	<!-- SMTP Credentials To Use - UserName/Password -->
	<smtpCredsUserName>LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_REPLACE_WITH_USERNAME_IF_USED</smtpCredsUserName>
	<smtpCredsPassword>LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_REPLACE_WITH_PASSWORD_IF_USED</smtpCredsPassword>

	<!-- Mail Subject To Use -->
	<mailSubject>KrbTgt Password Reset Result</mailSubject>

	<!-- The Priority Of The Message: Low, Normal, High -->
	<mailPriority>High</mailPriority>

	<!-- Mail Body To Use -->
	<mailBody>
&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;head&gt;
&lt;title&gt;KrbTgt_Password_Reset&lt;/title&gt;
&lt;style type="text/css"&gt;
&lt;/style&gt;
&lt;/head&gt;
&lt;body&gt;
&lt;B&gt;&lt;P align="center" style="font-size: 24pt; font-family: Arial Narrow, sans-serif; color: red"&gt;!!! ATTENTION | FYI - ACTION REQUIRED !!!&lt;/P&gt;&lt;/B&gt;
&lt;hr size=2 width="95%" align=center&gt;
&lt;BR&gt;
&lt;P style="font-size: 12pt; font-family: Arial Narrow, sans-serif;"&gt;Hello,&lt;/P&gt;
&lt;BR&gt;
&lt;P style="font-size: 12pt; font-family: Arial Narrow, sans-serif;"&gt;Please review the attached log file.&lt;/P&gt;
&lt;BR&gt;
&lt;P style="font-size: 12pt; font-family: Arial Narrow, sans-serif;"&gt;Best regards&lt;/P&gt;
&lt;/body&gt;
&lt;/html&gt;</mailBody>

	<!-- The SMTP Address Used In The FROM Field -->
	<mailFromSender>sender_Mail_Address@company.com</mailFromSender>

	<!-- The SMTP Address Used In The TO Field -->
	<mailToRecipient>recipient_To_MailAddress@company.com</mailToRecipient>

	<!-- The SMTP Address Used In The CC Field -->
	<mailCcRecipients>
			<!-- For Every Recipient To Be Added In The CC Add A New Line -->
			<mailCcRecipient>recipient_Cc_MailAddress_1@company.com</mailCcRecipient>
			<mailCcRecipient>recipient_Cc_MailAddress_2@company.com</mailCcRecipient>
	</mailCcRecipients>

	<!-- Enable/Disable SMIME signing and encryptionof emails: ON or OFF -->
	<mailSign>OFF</mailSign>
	<mailEncrypt>OFF</mailEncrypt>

	<!-- Full path of Cpi.Net.SecureMail.dll -->
	<!-- Dll Source Code: https://www.codeproject.com/Articles/41727/An-S-MIME-Library-for-Sending-Signed-and-Encrypted -->
	<mailSignAndEncryptDllFile>REPLACE_WITH_FULL_FOLDER_PATH_TO_COMPILED_DLL_FILE\Cpi.Net.SecureMail.dll</mailSignAndEncryptDllFile>

	<!-- Location Of Cert To Sign/Encrypt The Mail -->
	<mailSignAndEncryptCertLocation>STORE_OR_PFX</mailSignAndEncryptCertLocation>	<!-- Location Of Cert To Sign/Encrypt The Mail - Options Are: PFX or STORE -->
	<mailEncryptCertLocation>STORE_OR_CER</mailEncryptCertLocation>					<!-- Location Of Cert To Encrypt The Mail - Options Are: CER or STORE -->

	<!-- Thumbprint Of Certificate To Sign/Encrypt Mail With - Only Used When Corresponding Value For Location Is STORE -->
	<mailSignAndEncryptCertThumbprint>LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_REPLACE_WITH_THUMBPRINT_IF_USED</mailSignAndEncryptCertThumbprint>	<!-- Thumbprint Of Cert To Sign/Encrypt The Mail By Sender -->
	<mailEncryptCertThumbprint>LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_REPLACE_WITH_THUMBPRINT_IF_USED</mailEncryptCertThumbprint>				<!-- Thumbprint Of Cert To Encrypt The Mail For Recipient -->

	<!-- Full path of a .pfx/.cer certificate file used to sign/encrypt the email message - Only Used When Corresponding Value For Location Is PFX/CER -->
	<mailSignAndEncryptCertPFXFile>REPLACE_WITH_FULL_FOLDER_PATH_TO_PFX_FILE\cert.pfx</mailSignAndEncryptCertPFXFile>	<!-- PFX File Of Cert/Private Key To Sign/Encrypt The Mail By Sender -->
	<mailEncryptCertCERFile>REPLACE_WITH_FULL_FOLDER_PATH_TO_CER_FILE\cert.cer</mailEncryptCertCERFile>					<!-- CER File Of Cert To Encrypt The Mail For Recipient -->

	<!-- The password for the .pfx certificate file - Only Used When Corresponding Value For Location Is PFX -->
	<mailSignAndEncryptCertPFXPassword>LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_REPLACE_WITH_PFX_PASSWORD_IF_USED</mailSignAndEncryptCertPFXPassword>	<!-- Password Of PFX File Of Cert/Private Key To Sign/Encrypt The Mail By Sender -->
</resetKrbTgtPassword>
============ Configuration XML file ============
#>

###
# External S.DS.P. PowerShell Module INCLUDED In This Script
###
######################### S.DS.P PowerShell Module v2.1.5 (2022-09-20): https://github.com/jformacek/S.DS.P #########################
# vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# Github Repo:  https://github.com/jformacek/S.DS.P
# Applicable License: https://github.com/jformacek/S.DS.P/blob/master/LICENSE.TXT
# Owner: Jiri Formacek
Function Find-LdapObject {
    <#
.SYNOPSIS
    Searches LDAP server in given search root and using given search filter

.DESCRIPTION
    Searches LDAP server identified by LDAP connection passed as parameter.
    Attributes of returned objects are retrieved via ranged attribute retrieval by default. This allows to retrieve all attributes, including computed ones, but has impact on performace as each attribute generated own LDAP server query. Tu turn ranged attribute retrieval off, set parameter RangeSize to zero.
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
Get-LdapConnection -LdapServer "mydc.mydomain.com" | Out-Null

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
Get-LdapConnection -LdapServer dc.mydomain.com -Port 636 -AuthType Basic -Credential $creds | Out-Null
$dse = Get-RootDSE

Description
-----------
This command connects to given LDAP server with simple bind over TLS (TLS needed for basic authentication), storing the connection in session variable.
Next command uses connection from session variable to get Root DSE object.
Usage of Basic authentication is typically way to go on client platforms that do not support other authentication schemes, such as Negotiate

.EXAMPLE
Get-LdapConnection -LdapServer dc.mydomain.com | Out-Null
$dse = Get-RootDSE
#obtain initial sync cookie valid from now on
Find-LdapObject -searchBase $dse.defaultNamingContext -searchFilter '(objectClass=domainDns)' -PropertiesToLoad 'name' -DirSync Standard | Out-Null
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
            #When we perform many searches, it is more effective to use the same conbnection rather than create new connection for each search request.
        $LdapConnection = $script:LdapConnection,

        [parameter(Mandatory = $true)]
        [String]
            #Search filter in LDAP syntax
        $searchFilter,

        [parameter(Mandatory = $false, ValueFromPipeline=$true)]
        [Object]
            #DN of container where to search
        $searchBase,

        [parameter(Mandatory = $false)]
        [System.DirectoryServices.Protocols.SearchScope]
            #Search scope
            #Ignored for DirSync searches
            #Default: Subtree
        $searchScope='Subtree',

        [parameter(Mandatory = $false)]
        [String[]]
            #List of properties we want to return for objects we find.
            #Default: empty array, meaning no properties are returned
        $PropertiesToLoad=@(),

        [parameter(Mandatory = $false)]
        [String]
            #Name of attribute for ASQ search.
            #Ignored for DirSync searches
            #Note: searchScope must be set to Base for this type of seach
            #Default: empty string
        $ASQ,

        [parameter(Mandatory = $false)]
        [UInt32]
            #Page size for paged search. Zero means that paging is disabled
            #Ignored for DirSync searches
            #Default: 500
        $PageSize=500,

        [parameter(Mandatory = $false)]
        [Int32]
            # Specification of attribute value retrieval mode
            # Negative value means that attribute values are loaded directly with list of objects
            # Zero means that ranged attribute value retrieval is disabled and attribute values are returned in single request.
            # Positive value  means that each attribute value is loaded in dedicated requests in batches of given size. Usable for loading of group members
            # Ignored for DirSync searches
            # Note: Default in query policy in AD is 1500; make sure that you do not use here higher value than allowed by LDAP server
            # Default: -1 (means that ranged attribute retrieval is not used by default)
            # IMPORTANT: default changed in v2.1.1 - previously it was 1000. Changed because it typically caused large perforrmance impact when using -PropsToLoad '*'
        $RangeSize=-1,

        [parameter(Mandatory=$false)]
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
        $BinaryProps=@(),

        [parameter(Mandatory = $false)]
        [String[]]
            <#
            List of properties that we want to be defined on output object, but we do not want to load them from AD.
            Properties listed here must NOT occur in propertiesToLoad list
            Command defines properties on output objects and sets the value to $null
            Good for having output object with all props that we need for further processing, so we do not need to add them ourselves
            Default: empty list, which means that we don't want any additional propertis defined on output object
            #>
        $AdditionalProperties=@(),

        [parameter(Mandatory = $false)]
        [System.DirectoryServices.Protocols.DirectoryControl[]]
            #additional controls that caller may need to add to request
        $AdditionalControls=@(),

        [parameter(Mandatory = $false)]
        [Timespan]
            #Number of seconds before request times out.
            #Default: [TimeSpan]::Zero, which means that no specific timeout provided
        $Timeout = [TimeSpan]::Zero,

        [Parameter(Mandatory=$false)]
        [ValidateSet('None','Standard','ObjectSecurity','StandardIncremental','ObjectSecurityIncremental')]
        [string]
            #whether to issue search with DirSync. Allowed options:
            #None: Standard searxh without DirSync
            #Standard: Dirsync search using standard permisions of caller. Requires Replicate Directory Changes permission
            #ObjectSecurity: DirSync search using Replicate Direcory Changes permission that reveals object that caller normally does not have permission to see. Requires Requires Replicate Directory Changes All permission
            #Note: When Standard or ObjectSecurity specified, searchBase must be set to root of directory partition
            #For specs, see https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-ADTS/2213a7f2-0a36-483c-b2a4-8574d53aa1e3
            #Default: None, which means search without DirSync
        $DirSync = 'None',

        [Switch]
            #Whether to alphabetically sort attributes on returned objects
        $SortAttributes
    )

    Begin
    {
        EnsureLdapConnection -LdapConnection $LdapConnection
        Function PostProcess {
            param
            (
                [Parameter(ValueFromPipeline)]
                [System.Collections.Hashtable]$data,
                [bool]$Sort
            )
    
            process
            {
                #Flatten
                $coll=@($data.Keys)
                foreach($prop in $coll) {
                    $data[$prop] = [Flattener]::FlattenArray($data[$prop])
                    <#
                    #support for DirSync struct for Add/Remove values of multival props
                    if($data[$prop] -is [System.Collections.Hashtable])
                    {
                        $data[$prop] = [pscustomobject]$data[$prop]
                    }
                    #>
                }
                if($Sort)
                {
                    #flatten and sort attributes
                    $coll=@($coll | Sort-Object)
                    $sortedData=[ordered]@{}
                    foreach($prop in $coll) {$sortedData[$prop] = $data[$prop]}
                    #return result to pipeline
                    [PSCustomObject]$sortedData
                }
                else {
                    [PSCustomObject]$data
                }
            }
        }
    
        #remove unwanted props
        $PropertiesToLoad=@($propertiesToLoad | where-object {$_ -notin @('distinguishedName','1.1')})
        #if asterisk in list of props to load, load all props available on object despite of  required list
        if($propertiesToLoad.Count -eq 0) {$NoAttributes=$true} else {$NoAttributes=$false}
        if('*' -in $PropertiesToLoad) {$PropertiesToLoad=@()}

        #configure LDAP connection
        #preserve original value of referral chasing
        $referralChasing = $LdapConnection.SessionOptions.ReferralChasing
        if($pageSize -gt 0) {
            #paged search silently fails in AD when chasing referrals
            $LdapConnection.SessionOptions.ReferralChasing="None"
        }
    }

    Process {
        #build request
        $rq=new-object System.DirectoryServices.Protocols.SearchRequest

        #search base
        #we support passing $null as SearchBase - used for Global Catalog searches
        if($null -ne $searchBase)
        {
            #we support pipelining of strings, or objects containing distinguishedName property
            switch($searchBase.GetType().Name) {
                "String"
                {
                    $rq.DistinguishedName=$searchBase
                }
                default
                {
                    if($null -ne $searchBase.distinguishedName)
                    {
                        $rq.DistinguishedName=$searchBase.distinguishedName
                    }
                }
            }
        }

        #search filter in LDAP syntax
        $rq.Filter=$searchFilter


        if($DirSync -eq 'None')
        {
            #paged search control for paged search
            #for DirSync searches, paging is not used
            if($pageSize -gt 0) {
                [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($pageSize)
                #asking server for best effort with paging
                $pagedRqc.IsCritical=$false
                $rq.Controls.Add($pagedRqc) | Out-Null
            }

            #Attribute scoped query
            #Not supported for DirSync
            if(-not [String]::IsNullOrEmpty($asq)) {
                [System.DirectoryServices.Protocols.AsqRequestControl]$asqRqc=new-object System.DirectoryServices.Protocols.AsqRequestControl($ASQ)
                $rq.Controls.Add($asqRqc) | Out-Null
            }

            #search scope
            $rq.Scope=$searchScope

            #size limit
            if($SizeLimit -gt 0)
            {
                $rq.SizeLimit = $SizeLimit
            }
        }
        else {
            #specifics for DirSync searches

            #only supported scope is subtree
            $rq.Scope = 'Subtree'

            #Windows AD/LDS server always returns objectGuid for DirSync.
            #We do not want to hide it, we just make sure it is returned in proper format
            if('objectGuid' -notin $BinaryProps)
            {
                $BinaryProps+='objectGuid'
            }
        }

        #add additional controls that caller may have passed
        foreach($ctrl in $AdditionalControls) {$rq.Controls.Add($ctrl) | Out-Null}

        if($Timeout -ne [timespan]::Zero)
        {
            #server side timeout
            $rq.TimeLimit=$Timeout
        }

        switch($DirSync)
        {
            'None' {
                #standard search
                if($NoAttributes)
                {
                    #just run as fast as possible when not loading any attribs
                    GetResultsDirectlyInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -BinaryProperties $BinaryProps -Timeout $Timeout -NoAttributes | PostProcess
                }
                else {
                    #load attributes according to desired strategy
                    switch($RangeSize)
                    {
                        {$_ -lt 0} {
                            #directly via single ldap call
                            #some attribs may not be loaded (e.g. computed)
                            GetResultsDirectlyInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -BinaryProperties $BinaryProps -Timeout $Timeout | PostProcess -Sort $SortAttributes
                            break
                        }
                        0 {
                            #query attributes for each object returned using base search
                            #but not using ranged retrieval, so multivalued attributes with many values may not be returned completely
                            GetResultsIndirectlyInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -AdditionalControls $AdditionalControls -BinaryProperties $BinaryProps -Timeout $Timeout | PostProcess -Sort $SortAttributes
                            break
                        }
                        {$_ -gt 0} {
                            #query attributes for each object returned using base search and each attribute value with ranged retrieval
                            #so even multivalued attributes with many values are returned completely
                            GetResultsIndirectlyRangedInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -AdditionalControls $AdditionalControls -BinaryProperties $BinaryProps -Timeout $Timeout -RangeSize $RangeSize | PostProcess -Sort $SortAttributes
                            break
                        }
                    }
                }
                break;
            }
            'Standard' {
                GetResultsDirSyncInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -BinaryProperties $BinaryProps -Timeout $Timeout | PostProcess -Sort $SortAttributes
                break;
            }
            'ObjectSecurity' {
                GetResultsDirSyncInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -BinaryProperties $BinaryProps -Timeout $Timeout -ObjectSecurity | PostProcess -Sort $SortAttributes
                break;
            }
            'StandardIncremental' {
                GetResultsDirSyncInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -BinaryProperties $BinaryProps -Timeout $Timeout -Incremental | PostProcess -Sort $SortAttributes
                break;
            }
            'ObjectSecurityIncremental' {
                GetResultsDirSyncInternal -rq $rq -conn $LdapConnection -PropertiesToLoad $PropertiesToLoad -AdditionalProperties $AdditionalProperties -BinaryProperties $BinaryProps -Timeout $Timeout -ObjectSecurity -Incremental | PostProcess -Sort $SortAttributes
                break;
            }
        }
    }

    End
    {
        if(($pageSize -gt 0) -and ($null -ne $ReferralChasing)) {
            #revert to original value of referral chasing on connection
            $LdapConnection.SessionOptions.ReferralChasing=$ReferralChasing
        }
    }
}

Function Get-RootDSE {
<#
.SYNOPSIS
    Connects to LDAP server and retrieves metadata

.DESCRIPTION
    Retrieves LDAP server metadata from Root DSE object
    Current implementation is specialized to metadata foung on Windows LDAP server, so on other platforms, some metadata may be empty.
    Or other platforms may publish interesting metadata not available on Windwos LDAP - feel free to add here

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
    Begin
    {
        EnsureLdapConnection -LdapConnection $LdapConnection

		#initialize output objects via hashtable --> faster than add-member
        #create default initializer beforehand
        $propDef=[ordered]@{`
            rootDomainNamingContext=$null; configurationNamingContext=$null; schemaNamingContext=$null; `
            'defaultNamingContext'=$null; 'namingContexts'=$null; `
            'dnsHostName'=$null; 'ldapServiceName'=$null; 'dsServiceName'=$null; 'serverName'=$null;`
            'supportedLdapPolicies'=$null; 'supportedSASLMechanisms'=$null; 'supportedControl'=$null; 'supportedConfigurableSettings'=$null; `
            'currentTime'=$null; 'highestCommittedUSN' = $null; 'approximateHighestInternalObjectID'=$null; `
            'dsSchemaAttrCount'=$null; 'dsSchemaClassCount'=$null; 'dsSchemaPrefixCount'=$null; `
            'isGlobalCatalogReady'=$null; 'isSynchronized'=$null; 'pendingPropagations'=$null; `
            'domainControllerFunctionality' = $null; 'domainFunctionality'=$null; 'forestFunctionality'=$null; `
            'subSchemaSubEntry'=$null; `
            'msDS-ReplAllInboundNeighbors'=$null; 'msDS-ReplConnectionFailures'=$null; 'msDS-ReplLinkFailures'=$null; 'msDS-ReplPendingOps'=$null; `
            'dsaVersionString'=$null; 'serviceAccountInfo'=$null; 'LDAPPoliciesEffective'=$null `
        }
    }
    Process {

        #build request
        $rq=new-object System.DirectoryServices.Protocols.SearchRequest
        $rq.Scope =  [System.DirectoryServices.Protocols.SearchScope]::Base
        $rq.Attributes.AddRange($propDef.Keys) | Out-Null

        #try to get extra information with ExtendedDNControl
        #RFC4511: Server MUST ignore unsupported controls marked as not critical
        [System.DirectoryServices.Protocols.ExtendedDNControl]$exRqc = new-object System.DirectoryServices.Protocols.ExtendedDNControl('StandardString')
        $exRqc.IsCritical=$false
        $rq.Controls.Add($exRqc) | Out-Null

        try {
            $rsp=$LdapConnection.SendRequest($rq)
        }
        catch {
           throw $_.Exception
           return
        }
        #if there was error, let the exception go to caller and do not continue

        #sometimes server does not return anything if we ask for property that is not supported by protocol
        if($rsp.Entries.Count -eq 0) {
            return;
        }

        $data=[PSCustomObject]$propDef

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
        if($null -ne $rsp.Entries[0].Attributes['approximateHighestInternalObjectID']) {
            try {
                $data.approximateHighestInternalObjectID=[long]::Parse($rsp.Entries[0].Attributes['approximateHighestInternalObjectID'].GetValues([string]))
            }
            catch {
                #it isn't a numeric, just return what's stored without parsing
                $data.approximateHighestInternalObjectID=$rsp.Entries[0].Attributes['approximateHighestInternalObjectID'].GetValues([string])
            }
        }
        if($null -ne $rsp.Entries[0].Attributes['highestCommittedUSN']) {
            try {
                $data.highestCommittedUSN=[long]::Parse($rsp.Entries[0].Attributes['highestCommittedUSN'].GetValues([string]))
            }
            catch {
                #it isn't a numeric, just return what's stored without parsing
                $data.highestCommittedUSN=$rsp.Entries[0].Attributes['highestCommittedUSN'].GetValues([string])
            }
        }
        if($null -ne $rsp.Entries[0].Attributes['currentTime']) {
            $val = ($rsp.Entries[0].Attributes['currentTime'].GetValues([string]))[0]
            try {
                $data.currentTime = [DateTime]::ParseExact($val,'yyyyMMddHHmmss.fZ',[CultureInfo]::InvariantCulture,[System.Globalization.DateTimeStyles]::None)
            }
            catch {
                $data.currentTime=$val
            }
        }
        if($null -ne $rsp.Entries[0].Attributes['dnsHostName']) {
            $data.dnsHostName = ($rsp.Entries[0].Attributes['dnsHostName'].GetValues([string]))[0]
        }
        if($null -ne $rsp.Entries[0].Attributes['ldapServiceName']) {
            $data.ldapServiceName = ($rsp.Entries[0].Attributes['ldapServiceName'].GetValues([string]))[0]
        }
        if($null -ne $rsp.Entries[0].Attributes['dsServiceName']) {
            $val = ($rsp.Entries[0].Attributes['dsServiceName'].GetValues([string]))[0]
            if($val.Contains(';'))
            {
                $data.dsServiceName = $val.Split(';')
            }
            else {
                $data.dsServiceName=$val
            }
        }
        if($null -ne $rsp.Entries[0].Attributes['serverName']) {
            $val = ($rsp.Entries[0].Attributes['serverName'].GetValues([string]))[0]
            if($val.Contains(';'))
            {
                $data.serverName = $val.Split(';')
            }
            else {
                $data.serverName=$val
            }
        }
        if($null -ne $rsp.Entries[0].Attributes['supportedControl']) {
            $data.supportedControl = ( ($rsp.Entries[0].Attributes['supportedControl'].GetValues([string])) | Sort-Object )
        }
        if($null -ne $rsp.Entries[0].Attributes['supportedLdapPolicies']) {
            $data.supportedLdapPolicies = ( ($rsp.Entries[0].Attributes['supportedLdapPolicies'].GetValues([string])) | Sort-Object )
        }
        if($null -ne $rsp.Entries[0].Attributes['supportedSASLMechanisms']) {
            $data.supportedSASLMechanisms = ( ($rsp.Entries[0].Attributes['supportedSASLMechanisms'].GetValues([string])) | Sort-Object )
        }
        if($null -ne $rsp.Entries[0].Attributes['supportedConfigurableSettings']) {
            $data.supportedConfigurableSettings = ( ($rsp.Entries[0].Attributes['supportedConfigurableSettings'].GetValues([string])) | Sort-Object )
        }
        if($null -ne $rsp.Entries[0].Attributes['namingContexts']) {
            $data.namingContexts = @()
            foreach($ctxDef in ($rsp.Entries[0].Attributes['namingContexts'].GetValues([string]))) {
                $data.namingContexts+=[NamingContext]::Parse($ctxDef)
            }
        }
        if($null -ne $rsp.Entries[0].Attributes['dsSchemaAttrCount']) {
            [long]$outVal=-1
            [long]::TryParse($rsp.Entries[0].Attributes['dsSchemaAttrCount'].GetValues([string]),[ref]$outVal) | Out-Null
            $data.dsSchemaAttrCount=$outVal
        }
        if($null -ne $rsp.Entries[0].Attributes['dsSchemaClassCount']) {
            [long]$outVal=-1
            [long]::TryParse($rsp.Entries[0].Attributes['dsSchemaClassCount'].GetValues([string]),[ref]$outVal) | Out-Null
            $data.dsSchemaClassCount=$outVal
        }
        if($null -ne $rsp.Entries[0].Attributes['dsSchemaPrefixCount']) {
            [long]$outVal=-1
            [long]::TryParse($rsp.Entries[0].Attributes['dsSchemaPrefixCount'].GetValues([string]),[ref]$outVal) | Out-Null
            $data.dsSchemaPrefixCount=$outVal
        }
        if($null -ne $rsp.Entries[0].Attributes['isGlobalCatalogReady']) {
            $data.isGlobalCatalogReady=[bool]$rsp.Entries[0].Attributes['isGlobalCatalogReady'].GetValues([string])
        }
        if($null -ne $rsp.Entries[0].Attributes['isSynchronized']) {
            $data.isSynchronized=[bool]$rsp.Entries[0].Attributes['isSynchronized'].GetValues([string])
        }
        if($null -ne $rsp.Entries[0].Attributes['pendingPropagations']) {
            $data.pendingPropagations=$rsp.Entries[0].Attributes['pendingPropagations'].GetValues([string])
        }
        if($null -ne $rsp.Entries[0].Attributes['subSchemaSubEntry']) {
            $data.subSchemaSubEntry=$rsp.Entries[0].Attributes['subSchemaSubEntry'].GetValues([string])[0]
        }
         if($null -ne $rsp.Entries[0].Attributes['domainControllerFunctionality']) {
            $data.domainControllerFunctionality=[int]$rsp.Entries[0].Attributes['domainControllerFunctionality'].GetValues([string])[0]
        }
        if($null -ne $rsp.Entries[0].Attributes['domainFunctionality']) {
            $data.domainFunctionality=[int]$rsp.Entries[0].Attributes['domainFunctionality'].GetValues([string])[0]
        }
        if($null -ne $rsp.Entries[0].Attributes['forestFunctionality']) {
            $data.forestFunctionality=[int]$rsp.Entries[0].Attributes['forestFunctionality'].GetValues([string])[0]
        }
        if($null -ne $rsp.Entries[0].Attributes['msDS-ReplAllInboundNeighbors']) {
            $data.'msDS-ReplAllInboundNeighbors'=@()
            foreach($val in $rsp.Entries[0].Attributes['msDS-ReplAllInboundNeighbors'].GetValues([string])) {
                $data.'msDS-ReplAllInboundNeighbors'+=[xml]$Val.SubString(0,$Val.Length-2)
            }
        }
        if($null -ne $rsp.Entries[0].Attributes['msDS-ReplConnectionFailures']) {
            $data.'msDS-ReplConnectionFailures'=@()
            foreach($val in $rsp.Entries[0].Attributes['msDS-ReplConnectionFailures'].GetValues([string])) {
                $data.'msDS-ReplConnectionFailures'+=[xml]$Val.SubString(0,$Val.Length-2)
            }
        }
        if($null -ne $rsp.Entries[0].Attributes['msDS-ReplLinkFailures']) {
            $data.'msDS-ReplLinkFailures'=@()
            foreach($val in $rsp.Entries[0].Attributes['msDS-ReplLinkFailures'].GetValues([string])) {
                $data.'msDS-ReplLinkFailures'+=[xml]$Val.SubString(0,$Val.Length-2)
            }
        }
        if($null -ne $rsp.Entries[0].Attributes['msDS-ReplPendingOps']) {
            $data.'msDS-ReplPendingOps'=@()
            foreach($val in $rsp.Entries[0].Attributes['msDS-ReplPendingOps'].GetValues([string])) {
                $data.'msDS-ReplPendingOps'+=[xml]$Val.SubString(0,$Val.Length-2)
            }
        }
        if($null -ne $rsp.Entries[0].Attributes['dsaVersionString']) {
            $data.dsaVersionString=$rsp.Entries[0].Attributes['dsaVersionString'].GetValues([string])[0]
        }
        if($null -ne $rsp.Entries[0].Attributes['serviceAccountInfo']) {
            $data.serviceAccountInfo=$rsp.Entries[0].Attributes['serviceAccountInfo'].GetValues([string])
        }
        if($null -ne $rsp.Entries[0].Attributes['LDAPPoliciesEffective']) {
            $data.LDAPPoliciesEffective=@{}
            foreach($val in $rsp.Entries[0].Attributes['LDAPPoliciesEffective'].GetValues([string]))
            {
                $vals=$val.Split(':')
                if($vals.Length -gt 1) {
                    $data.LDAPPoliciesEffective[$vals[0]]=$vals[1]
                }
            }
        }
        $data
    }
}

Function Get-LdapConnection
{
<#
.SYNOPSIS
    Connects to LDAP server and returns LdapConnection object

.DESCRIPTION
    Creates connection to LDAP server according to parameters passed.
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
        $LdapServer=[String]::Empty,

        [parameter(Mandatory = $false)]
        [Int32]
            #LDAP server port
            #Default: 389
        $Port=389,

        [parameter(Mandatory = $false)]
        [PSCredential]
            #Use different credentials when connecting
        $Credential=$null,

        [parameter(Mandatory = $false)]
        [ValidateSet('None','TLS','SSL','Kerberos')]
        [string]
            #Type of encryption to use.
        $EncryptionType='None',

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
            #Client certificate used for authenticcation instead of credentials
            #See https://docs.microsoft.com/en-us/windows/win32/api/winldap/nc-winldap-queryclientcert
        $ClientCertificate
    )

    Begin
    {
        if($null -eq $script:ConnectionParams)
        {
            $script:ConnectionParams=@{}
        }
    }
    Process
    {

        $FullyQualifiedDomainName=$false;
        [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]$di=new-object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $Port, $FullyQualifiedDomainName, $ConnectionLess)

        if($null -ne $Credential)
        {
            $LdapConnection=new-object System.DirectoryServices.Protocols.LdapConnection($di, $Credential.GetNetworkCredential())
        }
        else 
        {
            $LdapConnection=new-object System.DirectoryServices.Protocols.LdapConnection($di)
        }
        $LdapConnection.SessionOptions.ProtocolVersion=$ProtocolVersion

        
        #store connection params for each server in global variable, so as it is reachable from callback scriptblocks
        $connectionParams=@{}
        foreach($server in $LdapServer) {$script:ConnectionParams[$server]=$connectionParams}
        if($CertificateValidationFlags -ne 'NoFlag')
        {
            $connectionParams['ServerCertificateValidationFlags'] = $CertificateValidationFlags
            #server certificate validation callback
            $LdapConnection.SessionOptions.VerifyServerCertificate = { 
                param(
                    [Parameter(Mandatory)][DirectoryServices.Protocols.LdapConnection]$LdapConnection,
                    [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
                )
                [System.Security.Cryptography.X509Certificates.X509Chain] $chain = new-object System.Security.Cryptography.X509Certificates.X509Chain
                foreach($server in $LdapConnection.Directory.Servers)
                {
                    if($server -in $script:ConnectionParams.Keys)
                    {
                        $connectionParam=$script:ConnectionParams[$server]
                        if($null -ne $connectionParam['ServerCertificateValidationFlags'])
                        {
                            $chain.ChainPolicy.VerificationFlags = $connectionParam['ServerCertificateValidationFlags']
                            break;
                        }
                    }
                }
                $result = $chain.Build($Certificate)
                return $result
            }
        }
        
        if($null -ne $ClientCertificate)
        {
            $connectionParams['ClientCertificate'] = $ClientCertificate
            #client certificate retrieval callback
            #we just support explicit certificate now
            $LdapConnection.SessionOptions.QueryClientCertificate = { param(
                [Parameter(Mandatory)][DirectoryServices.Protocols.LdapConnection]$LdapConnection,
                [Parameter(Mandatory)][byte[][]]$TrustedCAs
            )
                $clientCert = $null
                foreach($server in $LdapConnection.Directory.Servers)
                {
                    if($server -in $script:ConnectionParams.Keys)
                    {
                        $connectionParam=$script:ConnectionParams[$server]
                        if($null -ne $connectionParam['ClientCertificate'])
                        {
                            $clientCert = $connectionParam['ClientCertificate']
                            break;
                        }
                    }
                }
                return $clientCert
            }
        }

        if ($null -ne $AuthType) {
            $LdapConnection.AuthType = $AuthType
        }


        switch($EncryptionType) {
            'None' {break}
            'TLS' {
                $LdapConnection.SessionOptions.StartTransportLayerSecurity($null)
                break
            }
            'Kerberos' {
                $LdapConnection.SessionOptions.Sealing=$true
                $LdapConnection.SessionOptions.Signing=$true
                break
            }
            'SSL' {
                $LdapConnection.SessionOptions.SecureSocketLayer=$true
                break
            }
        }
        if($Timeout -ne [TimeSpan]::Zero)
        {
            $LdapConnection.Timeout = $Timeout
        }

        if($FastConcurrentBind) {
            $LdapConnection.SessionOptions.FastConcurrentBind()
        }
        $script:LdapConnection = $LdapConnection
        $LdapConnection
     }
}


Function Add-LdapObject
{
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
        [parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [PSObject]
            #Source object to copy properties from
        $Object,

        [parameter()]
        [String[]]
            #Properties to ignore on source object
        $IgnoredProps=@(),

        [parameter(Mandatory = $false)]
        [String[]]
            #List of properties that we want to handle as byte stream.
            #Note: Properties not listed here are handled as strings
            #Default: empty list, which means that all properties are handled as strings
        $BinaryProps=@(),

        [parameter()]
        [System.DirectoryServices.Protocols.LdapConnection]
            #Existing LDAPConnection object.
        $LdapConnection = $script:LdapConnection,

        [parameter(Mandatory = $false)]
        [System.DirectoryServices.Protocols.DirectoryControl[]]
            #Additional controls that caller may need to add to request
        $AdditionalControls=@(),

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

    begin
    {
        EnsureLdapConnection -LdapConnection $LdapConnection
    }

    Process
    {
        if([string]::IsNullOrEmpty($Object.DistinguishedName)) {
            throw (new-object System.ArgumentException("Input object missing DistinguishedName property"))
        }
        [System.DirectoryServices.Protocols.AddRequest]$rqAdd=new-object System.DirectoryServices.Protocols.AddRequest
        $rqAdd.DistinguishedName=$Object.DistinguishedName

        #add additional controls that caller may have passed
        foreach($ctrl in $AdditionalControls) {$rqAdd.Controls.Add($ctrl) | Out-Null}

        foreach($prop in (Get-Member -InputObject $Object -MemberType NoteProperty)) {
            if($prop.Name -eq "distinguishedName") {continue}
            if($IgnoredProps -contains $prop.Name) {continue}
            [System.DirectoryServices.Protocols.DirectoryAttribute]$propAdd=new-object System.DirectoryServices.Protocols.DirectoryAttribute
            $transform = $script:RegisteredTransforms[$prop.Name]
            $binaryInput = ($null -ne $transform -and $transform.BinaryInput -eq $true) -or ($prop.Name -in $BinaryProps)
            $propAdd.Name=$prop.Name
            
            if($null -ne $transform -and $null -ne $transform.OnSave) {
                #transform defined -> transform to form accepted by directory
                $attrVal = @(& $transform.OnSave -Values $Object.($prop.Name))
            }
            else {
                #no transform defined - take value as-is
                $attrVal = $Object.($prop.Name)
            }

            if($null -ne $attrVal)  #ignore empty props
            {
                if($binaryInput) {
                    foreach($val in $attrVal) {
                        $propAdd.Add([byte[]]$val) | Out-Null
                    }
                } else {
                    $propAdd.AddRange([string[]]($attrVal))
                }

                if($propAdd.Count -gt 0) {
                    $rqAdd.Attributes.Add($propAdd) | Out-Null
                }
            }
        }
        if($rqAdd.Attributes.Count -gt 0) {
            if($Timeout -ne [TimeSpan]::Zero)
            {
                $LdapConnection.SendRequest($rqAdd, $Timeout) -as [System.DirectoryServices.Protocols.AddResponse] | Out-Null
            }
            else {
                $LdapConnection.SendRequest($rqAdd) -as [System.DirectoryServices.Protocols.AddResponse] | Out-Null
            }
        }
        if($Passthrough)
        {
            $Object
        }
    }
}

Function Edit-LdapObject
{
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
    -searchFilter '(&(objeectClass=user)(objectCategory=organizationalPerson)(l=Prague))' `
    -searchBase $dse.defaultNamingContext `
    -PropertiesToLoad 'adminDescription' `
| foreach-object{$_.adminDescription = 'Praguer'; $_} `
| Edit-LdapObject -IncludedProps 'adminDescription' -Passthrough `
| Find-LdapObject -searchFilter '(objectClass=*)' -searchScope Base -PropertiesToLoad 'adminDescription'

Description
-----------
This sample demontrates pipeline capabilities of various commands by updating an attribute value on many objects and reading updated objects from server

.LINK
More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx

#>
    Param (
        [parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [PSObject]
            #Source object to copy properties from
        $Object,

        [parameter()]
        [String[]]
            #Properties to ignore on source object. If not specified, no props are ignored
        $IgnoredProps=@(),

        [parameter()]
        [String[]]
            #Properties to include on source object. If not specified, all props are included
        $IncludedProps=@(),

        [parameter(Mandatory = $false)]
        [String[]]
            #List of properties that we want to handle as byte stream.
            #Note: Those properties must also be present in IncludedProps parameter. Properties not listed here are handled as strings
            #Default: empty list, which means that all properties are handled as strings
        $BinaryProps=@(),

        [parameter()]
        [System.DirectoryServices.Protocols.LdapConnection]
            #Existing LDAPConnection object.
        $LdapConnection = $script:LdapConnection,

        [parameter(Mandatory=$false)]
        [System.DirectoryServices.Protocols.DirectoryAttributeOperation]
            #Mode of operation
            #Replace: Replaces attribute values on target
            #Add: Adds attribute values to existing values on target
            #Delete: Removes atribute values from existing values on target
        $Mode=[System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,

        [parameter(Mandatory = $false)]
        [System.DirectoryServices.Protocols.DirectoryControl[]]
            #Additional controls that caller may need to add to request
        $AdditionalControls=@(),

        [parameter(Mandatory = $false)]
        [timespan]
            #Time before request times out.
            #Default: [TimeSpan]::Zero, which means that no specific timeout provided
        $Timeout = [TimeSpan]::Zero,

        [Switch]
            #When turned on, command returns modified object to pipeline
            #This is useful when different types of modifications need to be done on single object
        $Passthrough
    )

    begin
    {
        EnsureLdapConnection -LdapConnection $LdapConnection
    }

    Process
    {
        if([string]::IsNullOrEmpty($Object.DistinguishedName)) {
            throw (new-object System.ArgumentException("Input object missing DistinguishedName property"))
        }

        [System.DirectoryServices.Protocols.ModifyRequest]$rqMod=new-object System.DirectoryServices.Protocols.ModifyRequest
        $rqMod.DistinguishedName=$Object.DistinguishedName
        $permissiveModifyRqc = new-object System.DirectoryServices.Protocols.PermissiveModifyControl
        $permissiveModifyRqc.IsCritical = $false
        $rqMod.Controls.Add($permissiveModifyRqc) | Out-Null

        #add additional controls that caller may have passed
        foreach($ctrl in $AdditionalControls) {$rqMod.Controls.Add($ctrl) | Out-Null}

        foreach($prop in (Get-Member -InputObject $Object -MemberType NoteProperty)) {
            if($prop.Name -eq "distinguishedName") {continue} #Dn is always ignored
            if($IgnoredProps -contains $prop.Name) {continue}
            if(($IncludedProps.Count -gt 0) -and ($IncludedProps -notcontains $prop.Name)) {continue}
            [System.DirectoryServices.Protocols.DirectoryAttribute]$propMod=new-object System.DirectoryServices.Protocols.DirectoryAttributeModification
            $transform = $script:RegisteredTransforms[$prop.Name]
            $binaryInput = ($null -ne $transform -and $transform.BinaryInput -eq $true) -or ($prop.Name -in $BinaryProps)
            $propMod.Name=$prop.Name

            if($null -ne $transform -and $null -ne $transform.OnSave) {
                #transform defined -> transform to form accepted by directory
                $attrVal = @(& $transform.OnSave -Values $Object.($prop.Name))
            }
            else {
                #no transform defined - take value as-is
                $attrVal = $Object.($prop.Name)
            }

            if($null -ne $attrVal) {
                #we're modifying property
                if($attrVal.Count -gt 0) {
                    $propMod.Operation=$Mode
                    if($binaryInput)  {
                        foreach($val in $attrVal) {
                            $propMod.Add([byte[]]$val) | Out-Null
                        }
                    } else {
                        $propMod.AddRange([string[]]($attrVal))
                    }
                    $rqMod.Modifications.Add($propMod) | Out-Null
                }
            } else {
                #source object has no value for property - we're removing value on target
                $propMod.Operation=[System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
                $rqMod.Modifications.Add($propMod) | Out-Null
            }
        }
        if($rqMod.Modifications.Count -gt 0) {
            if($Timeout -ne [TimeSpan]::Zero)
            {
                $LdapConnection.SendRequest($rqMod, $Timeout) -as [System.DirectoryServices.Protocols.ModifyResponse] | Out-Null
            }
            else
            {
                $LdapConnection.SendRequest($rqMod) -as [System.DirectoryServices.Protocols.ModifyResponse] | Out-Null
            }
        }
        #if requested, pass the objeect to pipeline for further processing
        if($Passthrough) {$Object}
    }
}

Function Remove-LdapObject
{
<#
.SYNOPSIS
    Removes existing object from LDAP server

.DESCRIPTION
    Removes an object from LDAP server.
    All proprties of object are ignored and no transforms are performed; only distinguishedName property is used to locate the object.

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
Find-LdapObject -LdapConnection (Get-LdapConnection) -SearchFilter:"(&(objectClass=organitationalUnit)(adminDescription=ToDelete))" -SearchBase:"dc=myDomain,dc=com" | Remove-LdapObject -UseTreeDelete

Description
-----------
Removes existing subtree using TreeDeleteControl

.LINK
More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx

#>
    Param (
        [parameter(Mandatory = $true, ValueFromPipeline=$true)]
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
        $AdditionalControls=@(),

        [parameter(Mandatory = $false)]
        [Switch]
            #Whether or not to use TreeDeleteControl.
        $UseTreeDelete
    )

    begin
    {
        EnsureLdapConnection -LdapConnection $LdapConnection
    }

    Process
    {
        [System.DirectoryServices.Protocols.DeleteRequest]$rqDel=new-object System.DirectoryServices.Protocols.DeleteRequest
        #add additional controls that caller may have passed
        foreach($ctrl in $AdditionalControls) {$rqDel.Controls.Add($ctrl) | Out-Null}

        switch($Object.GetType().Name)
        {
            "String"
            {
                $rqDel.DistinguishedName=$Object
            }
            default
            {
                if($null -ne $Object.distinguishedName)
                {
                    $rqDel.DistinguishedName=$Object.distinguishedName
                }
                else
                {
                    throw (new-object System.ArgumentException("DistinguishedName must be passed"))
                }
            }
        }
        if($UseTreeDelete) {
            $rqDel.Controls.Add((new-object System.DirectoryServices.Protocols.TreeDeleteControl)) | Out-Null
        }
        $LdapConnection.SendRequest($rqDel) -as [System.DirectoryServices.Protocols.DeleteResponse] | Out-Null
    }
}

Function Rename-LdapObject
{
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

Decription
----------
This command changes CN of User1 object to User2. Notice that 'cn=' is part of new name. This is required by protocol, when you do not provide it, you will receive NamingViolation error.

.EXAMPLE
$Ldap = Get-LdapConnection
Rename-LdapObject -LdapConnection $Ldap -Object "cn=User1,cn=Users,dc=mydomain,dc=com" -NewName "cn=User1" -NewParent "ou=CompanyUsers,dc=mydomain,dc=com"

Description
-----------
This command Moves the User1 object to different OU. Notice the newName parameter - it's the same as old name as we do not rename the object a new name is required parameter for protocol.

.LINK
More about System.DirectoryServices.Protocols: http://msdn.microsoft.com/en-us/library/bb332056.aspx

#>

    Param (
        [parameter(Mandatory = $true, ValueFromPipeline=$true)]
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
        $AdditionalControls=@()
    )

    begin
    {
        EnsureLdapConnection -LdapConnection $LdapConnection
    }
    Process
    {
        [System.DirectoryServices.Protocols.ModifyDNRequest]$rqModDN=new-object System.DirectoryServices.Protocols.ModifyDNRequest
        switch($Object.GetType().Name)
        {
            "String"
            {
                $rqModDN.DistinguishedName=$Object
            }
            default
            {
                if($Object.distinguishedName)
                {
                    $rqModDN.DistinguishedName=$Object.distinguishedName
                }
                else
                {
                    throw (new-object System.ArgumentException("DistinguishedName must be passed"))
                }
            }
        }
        $rqModDn.NewName = $NewName
        if(-not [string]::IsNullOrEmpty($NewParent)) {$rqModDN.NewParentDistinguishedName = $NewParent}
        $rqModDN.DeleteOldRdn = (-not $KeepOldRdn)
        $LdapConnection.SendRequest($rqModDN) -as [System.DirectoryServices.Protocols.ModifyDNResponse] | Out-Null
    }
}

#Transform registration handling support

# Internal holder of registered transforms
$script:RegisteredTransforms = @{}

Function Register-LdapAttributeTransform
{
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

Decription
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
        [Parameter(Mandatory,ParameterSetName='Name', Position=0)]
        [string]
            #Name of the transform
        $Name,
        [Parameter()]
        [string]
            #Name of the attribute that will be processed by transform
            #If not specified, transform will be registered on all supported attributes
        $AttributeName,
        [Parameter(Mandatory,ValueFromPipeline,ParameterSetName='TransformObject', Position=0)]
        [PSCustomObject]
            #Transform object produced by Get-LdapAttributeTRansform
        $Transform
    )

    Process
    {
        switch($PSCmdlet.ParameterSetName)
        {
            'TransformObject' {
                $Name = $transform.TransformName
                break;
            }
        }

        if(-not (Test-Path -Path "$PSScriptRoot\Transforms\$Name.ps1") )
        {
            throw new-object System.ArgumentException "Transform $Name not found"
        }

        $SupportedAttributes = (& "$PSScriptRoot\Transforms\$Name.ps1").SupportedAttributes
        switch($PSCmdlet.ParameterSetName)
        {
            'Name' {
                if([string]::IsNullOrEmpty($AttributeName))
                {
                    $attribs = $SupportedAttributes
                }
                else
                {
                    if($supportedAttributes -contains $AttributeName)
                    {
                        $attribs = @($AttributeName)
                    }
                    else {
                        throw new-object System.ArgumentException "Transform $Name does not support attribute $AttributeName"
                    }
                }
                break;
            }
            'TransformObject' {
                $attribs = $SupportedAttributes
                break;
            }
        }
        foreach($attr in $attribs)
        {
            $t = (. "$PSScriptRoot\Transforms\$Name.ps1" -FullLoad)
            $t = $t | Add-Member -MemberType NoteProperty -Name 'Name' -Value $Name -PassThru
            $script:RegisteredTransforms[$attr]= $t
        }
    }
}

Function Unregister-LdapAttributeTransform
{
<#
.SYNOPSIS

    Unregisters previously registered attribute transform logic

.DESCRIPTION

    Unregisters attribute transform. Attribute transforms transform attributes from simple types provided by LDAP server to more complex types. Transforms work on attribute level and do not have acces to values of other attributes.
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
More about attribute transforms and how to create them: https://github.com/jformacek/S.DS.P/tree/master/Transforms

#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, Position=0)]
        [string]
            #Name of the attribute to unregister transform from
        $AttributeName
    )

    Process
    {
        if($script:RegisteredTransforms.Keys -contains $AttributeName)
        {
            $script:RegisteredTransforms.Remove($AttributeName)
        }
    }
}

Function Get-LdapAttributeTransform
{
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
            #Lists all tranforms available
        $ListAvailable
    )
    if($ListAvailable)
    {
        $TransformList = Get-ChildItem -Path "$PSScriptRoot\Transforms\*.ps1" -ErrorAction SilentlyContinue
        foreach($transformFile in $TransformList)
        {
            $transform = (& $transformFile.FullName)
            $transform = $transform | Add-Member -MemberType NoteProperty -Name 'TransformName' -Value ([System.IO.Path]::GetFileNameWithoutExtension($transformFile.FullName)) -PassThru
            $transform | Select-Object TransformName,SupportedAttributes
        }
    }
    else {
        foreach($attrName in ($script:RegisteredTransforms.Keys | Sort-object))
        {
            [PSCustomObject]([Ordered]@{
                AttributeName = $attrName
                TransformName = $script:RegisteredTransforms[$attrName].Name
            })
        }
    }
}

function New-LdapAttributeTransformDefinition
{
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
        [Parameter(Mandatory, Position=0)]
        [string[]]$SupportedAttributes,
        [switch]
            #Whether supported attributes need to be loaded from/saved to LDAP as binary stream
        $BinaryInput
    )

    process
    {
        [PSCustomObject][Ordered]@{
            BinaryInput=$BinaryInput
            SupportedAttributes=$SupportedAttributes
            OnLoad = $null
            OnSave = $null
        }
    }
}

#region DirSync support
Function Get-LdapDirSyncCookie
{
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
Get-LdapConnection -LdapServer dc.mydomain.com | Out-Null
$dse = Get-RootDSE
#obtain initial sync cookie valid from now on
Find-LdapObject -searchBase $dse.defaultNamingContext -searchFilter '(objectClass=domainDns)' -PropertiesToLoad 'name' -DirSync Standard | Out-Null
$show the cookie
Get-LdapDirSyncCookie

Description
-----------
This example connects to given LDAP server and obtains initial cookie that represents current time - output does not contain full sync data.


.LINK
More about DirSync: https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-ADTS/2213a7f2-0a36-483c-b2a4-8574d53aa1e3

#>
param()

    process
    {
        if($null -ne $script:DirSyncCookie)
        {
            [Convert]::ToBase64String($script:DirSyncCookie)
        }
    }
}

Function Set-LdapDirSyncCookie
{
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
        [Parameter(Mandatory,ValueFromPipeline)]
        [string]$Cookie
    )

    process
    {
        [byte[]]$script:DirSyncCookie = [System.Convert]::FromBase64String($Cookie)
    }
}
#endregion

#region Helpers
Add-Type @'
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
'@

$referencedAssemblies=@()
if($PSVersionTable.PSEdition -eq 'Core') {$referencedAssemblies+='System.Security.Principal.Windows'}
Add-Type @'
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
'@ -ReferencedAssemblies $referencedAssemblies

<#
    Helper that makes sure that LdapConnection is initialized in commands that need it
#>
Function EnsureLdapConnection
{
    param
    (
        [parameter()]
        [System.DirectoryServices.Protocols.LdapConnection]
        $LdapConnection
    )

    process
    {
        if($null -eq $LdapConnection)
        {
            throw (new-object System.ArgumentException("LdapConnection parameter not provided and not found in session variable. Call Get-LdapConnection first"))
        }
    }
}
<#
    Helper that creates output object template used by Find-LdapObject command, based on required properties to be returned
#>
Function InitializeItemTemplateInternal
{
    param
    (
        [string[]]$props,
        [string[]]$additionalProps
    )

    process
    {
        $template=@{}
        foreach($prop in $additionalProps) {$template[$prop]= $null}
        foreach($prop in $props) {$template[$prop]=$null}
        $template
    }
}

<#
    Process ragnged retrieval hints
#>
function GetTargetAttr
{
    param
    (
        [Parameter(Mandatory)]
        [string]$attr
    )

    process
    {
        $targetAttr = $attr
        $m = [System.Text.RegularExpressions.Regex]::Match($attr,';range=.+');  #this is to skip range hints provided by DC
        if($m.Success)
        {
            $targetAttr = $($attr.Substring(0,$m.Index))
        }
        $targetAttr
    }
}

<#
    Retrieves search results as single search request
    Total # of search requests produced is 1
#>
function GetResultsDirectlyInternal
{
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
        $BinaryProperties=@(),
        [parameter()]
        [Timespan]
        $Timeout,
        [switch]$NoAttributes
    )
    begin
    {
        $template=InitializeItemTemplateInternal -props $PropertiesToLoad -additionalProps $AdditionalProperties
    }
    process
    {
        $pagedRqc=$rq.Controls | Where-Object{$_ -is [System.DirectoryServices.Protocols.PageResultRequestControl]}
        if($NoAttributes) {
            $rq.Attributes.Add('1.1') | Out-Null
        } else {
            $rq.Attributes.AddRange($propertiesToLoad) | Out-Null
        }
        while($true)
        {
            try
            {
                if($Timeout -ne [timespan]::Zero)
                {
                    $rsp = $conn.SendRequest($rq, $Timeout) -as [System.DirectoryServices.Protocols.SearchResponse]
                }
                else
                {
                    $rsp = $conn.SendRequest($rq) -as [System.DirectoryServices.Protocols.SearchResponse]
                }
            }
            catch [System.DirectoryServices.Protocols.DirectoryOperationException]
            {
                if($null -ne $_.Exception.Response -and $_.Exception.Response.ResultCode -eq 'SizeLimitExceeded')
                {
                    #size limit exceeded
                    $rsp = $_.Exception.Response
                }
                else
                {
                    throw $_.Exception
                }
            }

            foreach ($sr in $rsp.Entries)
            {
                $data=$template.Clone()
                
                foreach($attrName in $sr.Attributes.AttributeNames) {
                    $targetAttrName = GetTargetAttr -attr $attrName
                    if($targetAttrName -ne $attrName)
                    {
                        Write-Warning "Value of attribute $targetAttrName not completely retrieved as it exceeds query policy. Use ranged retrieval. Range hint: $attrName"
                    }
                    else
                    {
                        if($data[$attrName].Count -gt 0)
                        {
                            #we may have already loaded partial results from ranged hint
                            continue
                        }
                    }
                    
                    $transform = $script:RegisteredTransforms[$targetAttrName]
                    $BinaryInput = ($null -ne $transform -and $transform.BinaryInput -eq $true) -or ($targetAttrName -in $BinaryProperties)
                    if($null -ne $transform -and $null -ne $transform.OnLoad)
                    {
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
                }
                
                if($data['distinguishedName'].Count -eq 0) {
                    #dn has to be present on all objects
                    #having DN processed at the end gives chance to possible transforms on this attribute
                    $data['distinguishedName']=$sr.DistinguishedName
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
    Retrieves search results as dirsync request
#>
function GetResultsDirSyncInternal
{
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
        $BinaryProperties=@(),
        [parameter()]
        [Timespan]
        $Timeout,
        [Switch]$ObjectSecurity,
        [switch]$Incremental
    )
    begin
    {
        $template=InitializeItemTemplateInternal -props $PropertiesToLoad -additionalProps $AdditionalProperties
    }
    process
    {
        $DirSyncRqc= new-object System.DirectoryServices.Protocols.DirSyncRequestControl(,$script:DirSyncCookie)
        $DirSyncRqc.Option = [System.DirectoryServices.Protocols.DirectorySynchronizationOptions]::ParentsFirst
        if($ObjectSecurity)
        {
            $DirSyncRqc.Option = $DirSyncRqc.Option -bor [System.DirectoryServices.Protocols.DirectorySynchronizationOptions]::ObjectSecurity
        }
        if($Incremental)
        {
            $DirSyncRqc.Option = $DirSyncRqc.Option -bor [System.DirectoryServices.Protocols.DirectorySynchronizationOptions]::IncrementalValues
        }
        $rq.Controls.Add($DirSyncRqc) | Out-Null
        $rq.Attributes.AddRange($propertiesToLoad) | Out-Null
        
        while($true)
        {
            try
            {
                if($Timeout -ne [timespan]::Zero)
                {
                    $rsp = $conn.SendRequest($rq, $Timeout) -as [System.DirectoryServices.Protocols.SearchResponse]
                }
                else
                {
                    $rsp = $conn.SendRequest($rq) -as [System.DirectoryServices.Protocols.SearchResponse]
                }
            }
            catch [System.DirectoryServices.Protocols.DirectoryOperationException]
            {
                #just throw as we do not have need case for special handling now
                throw $_.Exception
            }

            foreach ($sr in $rsp.Entries)
            {
                $data=$template.Clone()
                
                foreach($attrName in $sr.Attributes.AttributeNames) {
                    $targetAttrName = GetTargetAttr -attr $attrName
                    if($attrName -ne $targetAttrName)
                    {
                        if($null -eq $data[$targetAttrName])
                        {
                            $data[$targetAttrName] = [PSCustomObject]@{
                                Add=@()
                                Remove=@()
                            }
                        }
                        #we have multival prop chnage --> need special handling
                        #Windows AD/LDS server returns attribute name as '<attr>;range=1-1' for added values and '<attr>;range=0-0' for removed values on forward-linked attributes
                        if($attrName -like '*;range=1-1')
                        {
                            $attributeContainer = {param($val) $data[$targetAttrName].Add=$val}
                        }
                        else {
                            $attributeContainer = {param($val) $data[$targetAttrName].Remove=$val}
                        }
                    }
                    else
                    {
                        $attributeContainer = {param($val) $data[$targetAttrName]=$val}
                    }
                    
                    $transform = $script:RegisteredTransforms[$targetAttrName]
                    $BinaryInput = ($null -ne $transform -and $transform.BinaryInput -eq $true) -or ($targetAttrName -in $BinaryProperties)
                    if($null -ne $transform -and $null -ne $transform.OnLoad)
                    {
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
                }
                
                if($data['distinguishedName'].Count -eq 0) {
                    #dn has to be present on all objects
                    #having DN processed at the end gives chance to possible transforms on this attribute
                    $data['distinguishedName']=$sr.DistinguishedName
                }
                $data
            }
            #the response may contain dirsync response. If so, we will need a cookie from it
            [System.DirectoryServices.Protocols.DirSyncResponseControl] $dsrc=$rsp.Controls | Where-Object{$_ -is [System.DirectoryServices.Protocols.DirSyncResponseControl]}
            if($null -ne $dsrc -and $dsrc.Cookie.Length -ne 0 -and $null -ne $DirSyncRqc) {
                #pass the search cookie back to server in next paged request
                $DirSyncRqc.Cookie = $dsrc.Cookie;
                $script:DirSyncCookie = $dsrc.Cookie
                if(-not $dsrc.MoreData)
                {
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

function GetResultsIndirectlyInternal
{
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
    begin
    {
        $template=InitializeItemTemplateInternal -props $PropertiesToLoad -additionalProps $AdditionalProperties
    }
    process
    {
        $pagedRqc=$rq.Controls | Where-Object{$_ -is [System.DirectoryServices.Protocols.PageResultRequestControl]}
        $rq.Attributes.AddRange($propertiesToLoad) | Out-Null
        #load only attribute names now and attribute values later
        $rq.TypesOnly=$true
        while ($true)
        {
            try
            {
                if($Timeout -ne [timespan]::Zero)
                {
                    $rsp = $conn.SendRequest($rq, $Timeout) -as [System.DirectoryServices.Protocols.SearchResponse]
                }
                else
                {
                    $rsp = $conn.SendRequest($rq) -as [System.DirectoryServices.Protocols.SearchResponse]
                }
            }
            catch [System.DirectoryServices.Protocols.DirectoryOperationException]
            {
                if($null -ne $_.Exception.Response -and $_.Exception.Response.ResultCode -eq 'SizeLimitExceeded')
                {
                    #size limit exceeded
                    $rsp = $_.Exception.Response
                }
                else
                {
                    throw $_.Exception
                }
            }

            #now process the returned list of distinguishedNames and fetch required properties directly from returned objects
            foreach ($sr in $rsp.Entries)
            {
                $data=$template.Clone()

                $rqAttr=new-object System.DirectoryServices.Protocols.SearchRequest
                $rqAttr.DistinguishedName=$sr.DistinguishedName
                $rqAttr.Scope="Base"
                $rqAttr.Controls.AddRange($AdditionalControls)

                #loading just attributes indicated as present in first search
                $rqAttr.Attributes.AddRange($sr.Attributes.AttributeNames) | Out-Null
                $rspAttr = $LdapConnection.SendRequest($rqAttr)
                foreach ($srAttr in $rspAttr.Entries) {
                    foreach($attrName in $srAttr.Attributes.AttributeNames) {
                        $targetAttrName = GetTargetAttr -attr $attrName
                        if($targetAttrName -ne $attrName)
                        {
                            Write-Warning "Value of attribute $targetAttrName not completely retrieved as it exceeds query policy. Use ranged retrieval. Range hint: $attrName"
                        }
                        else
                        {
                            if($data[$attrName].Count -gt 0)
                            {
                                #we may have already loaded partial results from ranged hint
                                continue
                            }
                        }

                        $transform = $script:RegisteredTransforms[$targetAttrName]
                        $BinaryInput = ($null -ne $transform -and $transform.BinaryInput -eq $true) -or ($attrName -in $BinaryProperties)
                        #protecting against LDAP servers who don't understand '1.1' prop
                        if($null -ne $transform -and $null -ne $transform.OnLoad)
                        {
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
                    }
                }
                if($data['distinguishedName'].Count -eq 0) {
                    #dn has to be present on all objects
                    $data['distinguishedName']=$sr.DistinguishedName
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
function GetResultsIndirectlyRangedInternal
{
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
        $BinaryProperties=@(),

        [parameter()]
        [Timespan]
        $Timeout,

        [parameter()]
        [Int32]
        $RangeSize
    )
    begin
    {
        $template=InitializeItemTemplateInternal -props $PropertiesToLoad -additionalProps $AdditionalProperties
    }
    process
    {
        $pagedRqc=$rq.Controls | Where-Object{$_ -is [System.DirectoryServices.Protocols.PageResultRequestControl]}
        $rq.Attributes.AddRange($PropertiesToLoad)
        #load only attribute names now and attribute values later
        $rq.TypesOnly=$true
        while ($true)
        {
            try
            {
                if($Timeout -ne [timespan]::Zero)
                {
                    $rsp = $conn.SendRequest($rq, $Timeout) -as [System.DirectoryServices.Protocols.SearchResponse]
                }
                else
                {
                    $rsp = $conn.SendRequest($rq) -as [System.DirectoryServices.Protocols.SearchResponse]
                }
            }
            catch [System.DirectoryServices.Protocols.DirectoryOperationException]
            {
                if($null -ne $_.Exception.Response -and $_.Exception.Response.ResultCode -eq 'SizeLimitExceeded')
                {
                    #size limit exceeded
                    $rsp = $_.Exception.Response
                }
                else
                {
                    throw $_.Exception
                }
            }

            #now process the returned list of distinguishedNames and fetch required properties directly from returned objects
            foreach ($sr in $rsp.Entries)
            {
                $data=$template.Clone()

                $rqAttr=new-object System.DirectoryServices.Protocols.SearchRequest
                $rqAttr.DistinguishedName=$sr.DistinguishedName
                $rqAttr.Scope="Base"
                $rqAttr.Controls.AddRange($AdditionalControls)

                #loading just attributes indicated as present in first search
                foreach($attrName in $sr.Attributes.AttributeNames) {
                    $transform = $script:RegisteredTransforms[$attrName]
                    $BinaryInput = ($null -ne $transform -and $transform.BinaryInput -eq $true) -or ($attrName -in $BinaryProperties)
                    $start=-$rangeSize
                    $lastRange=$false
                    while ($lastRange -eq $false) {
                        $start += $rangeSize
                        $rng = "$($attrName.ToLower());range=$start`-$($start+$rangeSize-1)"
                        $rqAttr.Attributes.Clear() | Out-Null
                        $rqAttr.Attributes.Add($rng) | Out-Null
                        $rspAttr = $LdapConnection.SendRequest($rqAttr)
                        foreach ($srAttr in $rspAttr.Entries) {
                            #LDAP server changes upper bound to * on last chunk
                            $returnedAttrName=$($srAttr.Attributes.AttributeNames)
                            #load binary properties as byte stream, other properties as strings
                            if($BinaryInput) {
                                $data[$attrName]+=$srAttr.Attributes[$returnedAttrName].GetValues([byte[]])
                            } else {
                                $data[$attrName] += $srAttr.Attributes[$returnedAttrName].GetValues([string])
                            }
                            if($returnedAttrName.EndsWith("-*") -or $returnedAttrName -eq $attrName) {
                                #last chunk arrived
                                $lastRange = $true
                            }
                        }
                    }

                    #perform transform if registered
                    if($null -ne $transform -and $null -ne $transform.OnLoad)
                    {
                        $data[$attrName] = (& $transform.OnLoad -Values $data[$attrName])
                    }
                }
                if($data['distinguishedName'].Count -eq 0) {
                    #dn has to be present on all objects
                    $data['distinguishedName']=$sr.DistinguishedName
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
#endregion
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
######################### S.DS.P PowerShell Module v2.1.5 (2022-09-20): https://github.com/jformacek/S.DS.P #########################

################### S.DS.P PowerShell Module TRANSFORMS v2.1.5: https://github.com/jformacek/S.DS.P ####################
$script:RegisteredTransforms = @{}
# vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
# unicodePwd.ps1
$codeBlock = New-LdapAttributeTransformDefinition -SupportedAttributes @('unicodePwd') -BinaryInput
$codeBlock.OnSave = {
	param(
		[string[]]$Values
	)

	Process {
		foreach ($Value in $Values) {
			, ([System.Text.Encoding]::Unicode.GetBytes("`"$Value`"") -as [byte[]])
		}
	}
}
$codeBlock.SupportedAttributes | ForEach-Object {
	$attributeToProcess = $_
	$codeBlock = $codeBlock | Add-Member -MemberType NoteProperty -Name 'Name' -Value $attributeToProcess -PassThru
	$script:RegisteredTransforms[$attributeToProcess] = $codeBlock
}
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
################### S.DS.P PowerShell Module TRANSFORMS v2.1.4: https://github.com/jformacek/S.DS.P ####################

###
# Functions Used In Script
###
### FUNCTION: Logging Data To The Log File
Function Logging($dataToLog, $lineType, $ignoreRemote) {
	$datetimeLogLine = "[" + $(Get-Date -format "yyyy-MM-dd HH:mm:ss") + "] : "
	If ($ignoreRemote -ne $true) {
		Out-File -filepath "$logFilePath" -append -inputObject "$datetimeLogLine$dataToLog"
	}
	If ($null -eq $lineType) {
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
$LoggingDef = "function Logging{${function:Logging}}"

### FUNCTION: Test The Port Connection
Function portConnectionCheck($fqdnServer, $port, $timeOut) {
	# Test To See If The HostName Is Resolvable At All
	Try {
		[System.Net.Dns]::GetHostEntry($fqdnServer) | Out-Null
	} Catch {
		Return "ERROR"
	}

	$tcpPortSocket = $null
	$portConnect = $null
	$tcpPortWait = $null
	$tcpPortSocket = New-Object System.Net.Sockets.TcpClient
	$portConnect = $tcpPortSocket.BeginConnect($fqdnServer, $port, $null, $null)
	$tcpPortWait = $portConnect.AsyncWaitHandle.WaitOne($timeOut, $false)
	If (!$tcpPortWait) {
		$tcpPortSocket.Close()
		Return "ERROR"
	} Else {
		$ErrorActionPreference = "SilentlyContinue"
		$tcpPortSocket.EndConnect($portConnect) | Out-Null
		If (!$?) {
			Return "ERROR"
		} Else {
			Return "SUCCESS"
		}
		$tcpPortSocket.Close()
		$ErrorActionPreference = "Continue"
	}
}

### FUNCTION: Load Required PowerShell Modules
Function loadPoSHModules($poshModule, $ignoreRemote) {
	$retValue = $null
	If (@(Get-Module | Where-Object{$_.Name -eq $poshModule}).count -eq 0) {
		If (@(Get-Module -ListAvailable | Where-Object{$_.Name -eq $poshModule}).count -ne 0) {
			Import-Module $poshModule
			Logging "PoSH Module '$poshModule' Has Been Loaded..." "SUCCESS" $ignoreRemote
			$retValue = "HasBeenLoaded"
		} Else {
			Logging "PoSH Module '$poshModule' Is Not Available To Load..." "ERROR" $ignoreRemote
			Logging "The PoSH Module '$poshModule' Is Required For This Script To Work..." "REMARK" $ignoreRemote
			$confirmInstallPoshModuleYESNO = $null
			$confirmInstallPoshModuleYESNO = Read-Host "Would You Like To Install The PoSH Module '$poshModule' NOW? [Yes|No]"
			If ($confirmInstallPoshModuleYESNO.ToUpper() -eq "YES" -Or $confirmInstallPoshModuleYESNO.ToUpper() -eq "Y") {
				If ($poshModule -eq "GroupPolicy") {
					Logging "Installing The Windows Feature 'GPMC' For The PoSH Module '$poshModule'..." "REMARK" $ignoreRemote
					Add-WindowsFeature -Name "GPMC" -IncludeAllSubFeature | Out-Null
				}
				If (@(Get-Module -ListAvailable | Where-Object{$_.Name -eq $poshModule}).count -ne 0) {
					Import-Module $poshModule
					Logging "PoSH Module '$poshModule' Has Been Loaded..." "SUCCESS" $ignoreRemote
					$retValue = "HasBeenLoaded"
				} Else {
					Logging "Aborting Script..." "ERROR" $ignoreRemote
					$retValue = "NotAvailable"
				}
			} Else {
				Logging "Aborting Script..." "ERROR" $ignoreRemote
				$retValue = "NotAvailable"
			}
		}
	} Else {
		Logging "PoSH Module '$poshModule' Already Loaded..." "SUCCESS" $ignoreRemote
		$retValue = "AlreadyLoaded"
	}
	Return $retValue
}
$loadPoSHModulesDef = "function loadPoSHModules{${function:loadPoSHModules}}"

### FUNCTION: Check To See If The Script Is Executed Through An Elevated PowerShell Command Prompt Or Not
Function checkLocalElevationStatus() {
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

### FUNCTION: Test Credentials For Specific Admin Role
Function testAdminRole($adminRole) {
	# Determine Current User
	$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()

	# Check The Current User Is In The Specified Admin Role
	(New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole($adminRole)
}

### FUNCTION: Request For Admin Credentials
Function requestForAdminCreds() {
	# Ask For The Remote Credentials
	$adminUserAccount = $null
	Do {
		Logging "Please provide an account (<DOMAIN FQDN>\<ACCOUNT>) that is a member of the 'Administrators' group in every AD domain of the specified AD forest: " "ACTION-NO-NEW-LINE"
		$adminUserAccount = Read-Host
	} Until ($adminUserAccount -ne "" -And $null -ne $adminUserAccount)

	# Ask For The Corresponding Password
	$adminUserPasswordString = $null
	Do {
		Logging "Please provide the corresponding password of that admin account: " "ACTION-NO-NEW-LINE"
		[System.Security.SecureString]$adminUserPasswordSecureString = Read-Host -AsSecureString -ErrorAction SilentlyContinue
	} Until ($adminUserPasswordSecureString.Length -gt 0)
	[string]$adminUserPasswordString = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminUserPasswordSecureString))
	$secureAdminUserPassword = ConvertTo-SecureString $adminUserPasswordString -AsPlainText -Force
	$adminCrds = $null
	$adminCrds = New-Object System.Management.Automation.PSCredential $adminUserAccount, $secureAdminUserPassword

	Return $adminCrds
}

### FUNCTION: Create Temporary Canary Object
Function createTempCanaryObject($targetedADdomainRWDCFQDN, $krbTgtSamAccountName, $execDateTimeCustom1, $localADforest, $adminCrds) {
	# Determine The DN Of The Default NC Of The Targeted Domain
	$targetedADdomainDefaultNC = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			#$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDCFQDN).defaultNamingContext
			$targetedADdomainDefaultNC = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetedADdomainRWDCFQDN' For 'rootDSE'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			#$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDCFQDN -Credential $adminCrds).defaultNamingContext
			$targetedADdomainDefaultNC = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetedADdomainRWDCFQDN' For 'rootDSE' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}

	# Determine The DN Of The Users Container Of The Targeted Domain
	$containerForTempCanaryObject = $null
	$containerForTempCanaryObject = "CN=Users," + $targetedADdomainDefaultNC

	# Generate The Name Of The Temporary Canary Object
	$targetObjectToCheckName = $null
	$targetObjectToCheckName = "_adReplTempObject_" + $krbTgtSamAccountName + "_" + $execDateTimeCustom1

	# Specify The Description Of The Temporary Canary Object
	$targetObjectToCheckDescription = "...!!!.TEMP OBJECT TO CHECK AD REPLICATION IMPACT.!!!..."

	# Generate The DN Of The Temporary Canary Object
	$targetObjectToCheckDN = $null
	$targetObjectToCheckDN = "CN=" + $targetObjectToCheckName + "," + $containerForTempCanaryObject
	Logging "  --> RWDC To Create Object On..............: '$targetedADdomainRWDCFQDN'"
	Logging "  --> Full Name Temp Canary Object..........: '$targetObjectToCheckName'"
	Logging "  --> Description...........................: '$targetObjectToCheckDescription'"
	Logging "  --> Container For Temp Canary Object......: '$containerForTempCanaryObject'"
	Logging ""

	# Try To Create The Canary Object In The AD Domain And If Not Successfull Throw Error
	Try {
		$contactObject = [PSCustomObject]@{distinguishedName = $null; objectClass = $null; displayName = $null; description = $null}
		$contactObject.DistinguishedName = "CN=$targetObjectToCheckName,$containerForTempCanaryObject"
		$contactObject.objectClass = "contact"
		$contactObject.displayName = $targetObjectToCheckName
		$contactObject.description = $targetObjectToCheckDescription
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			#New-ADObject -Type contact -Name $targetObjectToCheckName -Path $containerForTempCanaryObject -DisplayName $targetObjectToCheckName -Description $targetObjectToCheckDescription -Server $targetedADdomainRWDCFQDN
			Add-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -Object $contactObject
		}
		If ($localADforest -eq $false -And $adminCrds) {
			#New-ADObject -Type contact -Name $targetObjectToCheckName -Path $containerForTempCanaryObject -DisplayName $targetObjectToCheckName -Description $targetObjectToCheckDescription -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
			Add-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -Object $contactObject
		}
	} Catch {
		Logging "  --> Temp Canary Object [$targetObjectToCheckDN] FAILED TO BE CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
		Logging "" "ERROR"
		Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
		Logging "" "ERROR"
		Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
		Logging "" "ERROR"
		Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
		Logging "" "ERROR"
	}

	# Check The Temporary Canary Object Exists And Was created In AD
	$targetObjectToCheck = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			#$targetObjectToCheck = Get-ADObject -LDAPFilter "(&(objectClass=contact)(name=$targetObjectToCheckName))" -Server $targetedADdomainRWDCFQDN
			$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
			$targetObjectToCheck = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectClass=contact)(name=$targetObjectToCheckName))"
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Contact Object With 'name=$targetObjectToCheckName'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			#$targetObjectToCheck = Get-ADObject -LDAPFilter "(&(objectClass=contact)(name=$targetObjectToCheckName))" -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
			$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
			$targetObjectToCheck = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectClass=contact)(name=$targetObjectToCheckName))"
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Contact Object With 'name=$targetObjectToCheckName' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($targetObjectToCheck) {
		$targetObjectToCheckDN = $null
		$targetObjectToCheckDN = $targetObjectToCheck.DistinguishedName
		Logging "  --> Temp Canary Object [$targetObjectToCheckDN] CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." "REMARK"
		Logging "" "REMARK"
	}
	Return $targetObjectToCheckDN
}

### FUNCTION: Confirm Generated Password Meets Complexity Requirements
# Source: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements
Function confirmPasswordIsComplex($passwd) {
	Process {
		$criteriaMet = 0

		# Upper Case Characters (A through Z, with diacritic marks, Greek and Cyrillic characters)
		If ($passwd -cmatch '[A-Z]') {$criteriaMet++}

		# Lower Case Characters (a through z, sharp-s, with diacritic marks, Greek and Cyrillic characters)
		If ($passwd -cmatch '[a-z]') {$criteriaMet++}

		# Numeric Characters (0 through 9)
		If ($passwd -match '\d') {$criteriaMet++}

		# Special Chracters (Non-alphanumeric characters, currency symbols such as the Euro or British Pound are not counted as special characters for this policy setting)
		If ($passwd -match '[\^~!@#$%^&*_+=`|\\(){}\[\]:;"''<>,.?/]') {$criteriaMet++}

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
Function generateNewComplexPassword([int]$passwdNrChars) {
	Process {
		$iterations = 0
		Do {
			If ($iterations -ge 20) {
				Logging "  --> Complex password generation failed after '$iterations' iterations..." "ERROR"
				Logging "" "ERROR"
				EXIT
			}
			$iterations++
			$passwdBytes = @()
			$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
			Do {
				[byte[]]$byte = [byte]1
				$rng.GetBytes($byte)
				If ($byte[0] -lt 33 -or $byte[0] -gt 126) {
					CONTINUE
				}
				$passwdBytes += $byte[0]
			}
			While ($passwdBytes.Count -lt $passwdNrChars)
			$passwd = ([char[]]$passwdBytes) -join ''
		}
		Until (confirmPasswordIsComplex $passwd)
		Return $passwd
	}
}

### FUNCTION: Retrieve The Metadata Of An Object
Function retrieveObjectMetadata($targetedADdomainRWDCFQDN, $ObjectDN, $localADforest, $adminCrds) {
	# Get The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object BEFORE THE PASSWORD SET
	$objectMetadata = $null
	$targetedADdomainRWDCContext = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		$targetedADdomainRWDCContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer", $targetedADdomainRWDCFQDN)
	}
	If ($localADforest -eq $false -And $adminCrds) {
		$targetedADdomainRWDCContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer", $targetedADdomainRWDCFQDN, $($adminCrds.UserName), $($adminCrds.GetNetworkCredential().Password))
	}
	$targetedADdomainRWDCObject = $null
	Try {
		$targetedADdomainRWDCObject = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($targetedADdomainRWDCContext)
		$objectMetadata = $targetedADdomainRWDCObject.GetReplicationMetadata($ObjectDN)
	} Catch {
		Logging "" "ERROR"
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Logging "Error Getting Metadata From '$targetedADdomainRWDCFQDN' For Object '$krbTgtObjectBeforeDN'..." "ERROR"
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Logging "Error Getting Metadata From '$targetedADdomainRWDCFQDN' For Object '$krbTgtObjectBeforeDN' Using '$($adminCrds.UserName)'..." "ERROR"
		}
		Logging "" "ERROR"
		Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
		Logging "" "ERROR"
		Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
		Logging "" "ERROR"
		Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
		Logging "" "ERROR"
	}

	If ($objectMetadata) {
		Return $($objectMetadata.Values)
	}
}

### FUNCTION: Reset Password Of AD Account
Function setPasswordOfADAccount($targetedADdomainRWDCFQDN, $krbTgtSamAccountName, $localADforest, $adminCrds) {
	# Retrieve The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
	$krbTgtObjectBefore = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			#$krbTgtObjectBefore = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCFQDN
			$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
			$krbTgtObjectBefore = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			#$krbTgtObjectBefore = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
			$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
			$krbTgtObjectBefore = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Contact Object With 'sAMAccountName=$krbTgtSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
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
	$objectMetadataBefore = retrieveObjectMetadata $targetedADdomainRWDCFQDN $krbTgtObjectBeforeDN $localADforest $adminCrds
	$objectMetadataBeforeAttribPwdLastSet = $null
	$objectMetadataBeforeAttribPwdLastSet = $objectMetadataBefore | Where-Object{$_.Name -eq "pwdLastSet"}
	$objectMetadataBeforeAttribPwdLastSetOrgRWDCFQDN = $null
	$objectMetadataBeforeAttribPwdLastSetOrgRWDCFQDN = If ($objectMetadataBeforeAttribPwdLastSet.OriginatingServer) {$objectMetadataBeforeAttribPwdLastSet.OriginatingServer} Else {"RWDC Demoted"}
	$objectMetadataBeforeAttribPwdLastSetOrgTime = $null
	$objectMetadataBeforeAttribPwdLastSetOrgTime = Get-Date $($objectMetadataBeforeAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
	$objectMetadataBeforeAttribPwdLastSetVersion = $null
	$objectMetadataBeforeAttribPwdLastSetVersion = $objectMetadataBeforeAttribPwdLastSet.Version

	Logging "  --> RWDC To Reset Password On.............: '$targetedADdomainRWDCFQDN'"
	Logging "  --> sAMAccountName Of KrbTgt Account......: '$krbTgtSamAccountName'"
	Logging "  --> Distinguished Name Of KrbTgt Account..: '$krbTgtObjectBeforeDN'"

	# Specify The Number Of Characters The Generate Password Should Contain
	$passwdNrChars = 64
	Logging "  --> Number Of Chars For Pwd Generation....: '$passwdNrChars'"

	# Generate A New Password With The Specified Length (Text)
	$newKrbTgtPassword = $null
	$newKrbTgtPassword = (generateNewComplexPassword $passwdNrChars).ToString()

	# Convert The Text Based Version Of The New Password To A Secure String
	#$newKrbTgtPasswordSecure = $null
	#$newKrbTgtPasswordSecure = ConvertTo-SecureString $newKrbTgtPassword -AsPlainText -Force

	# Try To Set The New Password On The Targeted KrbTgt Account And If Not Successfull Throw Error
	Try {
		$krbTgtObj = [PSCustomObject]@{distinguishedName = $null; unicodePwd = $null}
		$krbTgtObj.distinguishedName = $krbTgtObjectBeforeDN
		$krbTgtObj.unicodePwd = $newKrbTgtPassword
		#Register-LdapAttributeTransform -name unicodePwd -AttributeName unicodePwd
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			#Set-ADAccountPassword -Identity $krbTgtObjectBeforeDN -Server $targetedADdomainRWDCFQDN -Reset -NewPassword $newKrbTgtPasswordSecure
			Edit-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -Mode Replace -Object $krbTgtObj -BinaryProps unicodePwd
		}
		If ($localADforest -eq $false -And $adminCrds) {
			#Set-ADAccountPassword -Identity $krbTgtObjectBeforeDN -Server $targetedADdomainRWDCFQDN -Reset -NewPassword $newKrbTgtPasswordSecure -Credential $adminCrds
			Edit-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -Mode Replace -Object $krbTgtObj -BinaryProps unicodePwd
		}
	} Catch {
		Logging ""
		Logging "  --> Setting the new password for [$krbTgtObjectBeforeDN] FAILED on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
		Logging "" "ERROR"
		Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
		Logging "" "ERROR"
		Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
		Logging "" "ERROR"
		Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
		Logging "" "ERROR"
	}

	# Retrieve The KrgTgt Object In The AD Domain AFTER THE PASSWORD SET
	$krbTgtObjectAfter = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			#$krbTgtObjectAfter = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCFQDN
			$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
			$krbTgtObjectAfter = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			#$krbTgtObjectAfter = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
			$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
			$krbTgtObjectAfter = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
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
	$objectMetadataAfter = retrieveObjectMetadata $targetedADdomainRWDCFQDN $krbTgtObjectAfterDN $localADforest $adminCrds
	$objectMetadataAfterAttribPwdLastSet = $null
	$objectMetadataAfterAttribPwdLastSet = $objectMetadataAfter | Where-Object{$_.Name -eq "pwdLastSet"}
	$objectMetadataAfterAttribPwdLastSetOrgRWDCFQDN = $null
	$objectMetadataAfterAttribPwdLastSetOrgRWDCFQDN = If ($objectMetadataAfterAttribPwdLastSet.OriginatingServer) {$objectMetadataAfterAttribPwdLastSet.OriginatingServer} Else {"RWDC Demoted"}
	$objectMetadataAfterAttribPwdLastSetOrgTime = $null
	$objectMetadataAfterAttribPwdLastSetOrgTime = Get-Date $($objectMetadataAfterAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
	$objectMetadataAfterAttribPwdLastSetVersion = $null
	$objectMetadataAfterAttribPwdLastSetVersion = $objectMetadataAfterAttribPwdLastSet.Version

	Logging ""
	Logging "  --> Previous Password Set Date/Time.......: '$krbTgtObjectBeforePwdLastSet'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging "  --> New Password Set Date/Time............: '$krbTgtObjectAfterPwdLastSet'"
	}
	Logging ""
	Logging "  --> Previous Originating RWDC.............: '$objectMetadataBeforeAttribPwdLastSetOrgRWDCFQDN'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging "  --> New Originating RWDC..................: '$objectMetadataAfterAttribPwdLastSetOrgRWDCFQDN'"
	}
	Logging ""
	Logging "  --> Previous Originating Time.............: '$objectMetadataBeforeAttribPwdLastSetOrgTime'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging "  --> New Originating Time..................: '$objectMetadataAfterAttribPwdLastSetOrgTime'"
	}
	Logging ""
	Logging "  --> Previous Version Of Attribute Value...: '$objectMetadataBeforeAttribPwdLastSetVersion'"
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging "  --> New Version Of Attribute Value........: '$objectMetadataAfterAttribPwdLastSetVersion'"
	}

	# Check And Confirm If The Password Value Has Been Updated By Comparing The Password Last Set Before And After The Reset
	If ($krbTgtObjectAfterPwdLastSet -ne $krbTgtObjectBeforePwdLastSet) {
		Logging ""
		Logging "  --> The new password for [$krbTgtObjectAfterDN] HAS BEEN SET on RWDC [$targetedADdomainRWDCFQDN]!..." "REMARK"
		Logging "" "REMARK"
	}
}

### FUNCTION: Replicate Single AD Object
# INFO: https://msdn.microsoft.com/en-us/library/cc223306.aspx
Function replicateSingleADObject($sourceDCNTDSSettingsObjectDN, $targetDCFQDN, $objectDN, $contentScope, $localADforest, $adminCrds) {
	# Define And Target The root DSE Context
	$rootDSE = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$rootDSE = [ADSI]"LDAP://$targetDCFQDN/rootDSE"
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetDCFQDN' For 'rootDSE'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$rootDSE = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$targetDCFQDN/rootDSE"), $($adminCrds.UserName), $($adminCrds.GetNetworkCredential().password))
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetDCFQDN' For 'rootDSE' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}

	# Perform A Replicate Single Object For The Complete Object
	If ($contentScope -eq "Full") {
		Try {
			$rootDSE.Put("replicateSingleObject", $sourceDCNTDSSettingsObjectDN + ":" + $objectDN)
		} Catch {
			Logging "" "ERROR"
			Logging "Replicate Single Object (Full) Failed From '$sourceDCNTDSSettingsObjectDN' To '$targetDCFQDN' For Object '$objectDN'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}

	# Perform A Replicate Single Object For Obnly The Secrets Of The Object
	If ($contentScope -eq "Secrets") {
		Try {
			$rootDSE.Put("replicateSingleObject", $sourceDCNTDSSettingsObjectDN + ":" + $objectDN + ":SECRETS_ONLY")
		} Catch {
			Logging "" "ERROR"
			Logging "Replicate Single Object (Secrets Only) Failed From '$sourceDCNTDSSettingsObjectDN' To '$targetDCFQDN' For Object '$objectDN'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}

	# Commit The Change To The Operational Attribute
	Try {
		$rootDSE.SetInfo()
	} Catch {
		Logging "" "ERROR"
		Logging "Triggering Replicate Single Object On '$targetDCFQDN' From '$sourceDCNTDSSettingsObjectDN' Failed For Object '$objectDN' Using The '$contentScope' Scope..." "ERROR"
		Logging "" "ERROR"
		Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
		Logging "" "ERROR"
		Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
		Logging "" "ERROR"
		Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
		Logging "" "ERROR"
	}
}

### FUNCTION: Delete/Cleanup Temporary Canary Object
Function deleteTempCanaryObject($targetedADdomainRWDCFQDN, $targetObjectToCheckDN, $localADforest, $adminCrds) {
	# Try To Delete The Canary Object In The AD Domain And If Not Successfull Throw Error
	Try {
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			#Remove-ADObject -Identity $targetObjectToCheckDN -Server $targetedADdomainRWDCFQDN -Confirm:$false
			Remove-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -Object $targetObjectToCheckDN
		}
		If ($localADforest -eq $false -And $adminCrds) {
			#Remove-ADObject -Identity $targetObjectToCheckDN -Server $targetedADdomainRWDCFQDN -Credential $adminCrds -Confirm:$false
			Remove-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -Object $targetObjectToCheckDN
		}
	} Catch {
		Logging "  --> Temp Canary Object [$targetObjectToCheckDN] FAILED TO BE DELETED on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
		Logging "  --> Manually delete the Temp Canary Object [$targetObjectToCheckDN] on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
		Logging "" "ERROR"
		Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
		Logging "" "ERROR"
		Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
		Logging "" "ERROR"
		Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
		Logging "" "ERROR"
	}

	# Retrieve The Temporary Canary Object From The AD Domain And If It Does Not Exist It Was Deleted Successfully
	$targetObjectToCheck = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			#$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $targetedADdomainRWDCFQDN
			$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
			$targetObjectToCheck = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$targetObjectToCheckDN)"
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$targetObjectToCheckDN'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			#$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
			$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
			$targetObjectToCheck = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$targetObjectToCheckDN)"
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If (!$targetObjectToCheck) {
		Logging "  --> Temp Canary Object [$targetObjectToCheckDN] DELETED on RWDC [$targetedADdomainRWDCFQDN]!..." "REMARK"
		Logging "" "REMARK"
	}
}

### FUNCTION: Check AD Replication Convergence
Function checkADReplicationConvergence($targetedADdomainFQDN, $targetedADdomainSourceRWDCFQDN, $targetObjectToCheckDN, $listOfDCsToCheckObjectOnStart, $listOfDCsToCheckObjectOnEnd, $modeOfOperationNr, $localADforest, $adminCrds) {
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
		Logging ""
		Logging "  =================================================================== CHECK $c ==================================================================="
		Logging ""

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

			# HostName Of The Source RWDC Of The DC To Check
			#$dcToCheckSourceRWDCFQDN = $null
			#$dcToCheckSourceRWDCFQDN = $dcToCheck."Source RWDC FQDN"

			# DSA DN Of The Source RWDC Of The DC To Check
			$dcToCheckSourceRWDCNTDSSettingsObjectDN = $null
			$dcToCheckSourceRWDCNTDSSettingsObjectDN = $dcToCheck."Source RWDC DSA"

			# If Mode 3, Simulate Password Reset Of KrbTgt TEST/BOGUS Accounts (No Password Reset/WhatIf Mode)
			# If Mode 4, Do A Real Password Reset Of KrbTgt TEST/BOGUS Accounts (Password Reset!)
			# If Mode 5, Simulate Password Reset Of KrbTgt PROD/REAL Accounts (No Password Reset/WhatIf Mode)
			# If Mode 6, Do A Real Password Reset Of KrbTgt PROD/REAL Accounts (Password Reset!)
			If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
				# Retrieve The Object From The Source Originating RWDC
				$objectOnSourceOrgRWDC = $null
				If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
					Try {
						#$objectOnSourceOrgRWDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $targetedADdomainSourceRWDCFQDN
						$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
						$objectOnSourceOrgRWDC = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$targetObjectToCheckDN)" -PropertiesToLoad @("pwdlastset")
					} Catch {
						Logging "" "ERROR"
						Logging "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For Object '$targetObjectToCheckDN'..." "ERROR"
						Logging "" "ERROR"
						Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
						Logging "" "ERROR"
						Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
						Logging "" "ERROR"
						Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
						Logging "" "ERROR"
					}
				}
				If ($localADforest -eq $false -And $adminCrds) {
					Try {
						#$objectOnSourceOrgRWDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $targetedADdomainSourceRWDCFQDN -Credential $adminCrds
						$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
						$objectOnSourceOrgRWDC = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$targetObjectToCheckDN)" -PropertiesToLoad @("pwdlastset")
					} Catch {
						Logging "" "ERROR"
						Logging "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For Object '$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." "ERROR"
						Logging "" "ERROR"
						Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
						Logging "" "ERROR"
						Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
						Logging "" "ERROR"
						Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
						Logging "" "ERROR"
					}
				}

				# Retrieve The Password Last Set Of The Object On The Source Originating RWDC
				$objectOnSourceOrgRWDCPwdLastSet = $null
				$objectOnSourceOrgRWDCPwdLastSet = Get-Date $([datetime]::fromfiletime($objectOnSourceOrgRWDC.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
			}

			# When The DC To Check Is Also The Source (Originating) RWDC
			If ($dcToCheckHostName -eq $targetedADdomainSourceRWDCFQDN) {
				Logging "  - Contacting DC in AD domain ...[$($dcToCheckHostName.ToUpper())]...(SOURCE RWDC)"
				Logging "     * DC is Reachable..." "SUCCESS"

				# For Mode 2 Only
				If ($modeOfOperationNr -eq 2) {
					Logging "     * Object [$targetObjectToCheckDN] exists in the AD database" "SUCCESS"
				}

				# For Mode 3 Or 4 Or 5 Or 6 Only
				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
					Logging "     * The (new) password for Object [$targetObjectToCheckDN] exists in the AD database" "SUCCESS"
				}
				Logging ""
				CONTINUE
			}

			Logging "  - Contacting DC in AD domain ...[$($dcToCheckHostName.ToUpper())]..."
			If ($dcToCheckReachability -eq $true) {
				# When The DC To Check Is Reachable
				Logging "     * DC is Reachable..." "SUCCESS"

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
					replicateSingleADObject $sourceDCNTDSSettingsObjectDN $dcToCheckHostName $targetObjectToCheckDN $contentScope $localADforest $adminCrds
				}

				# For Mode 2 From The DC to Check Retrieve The AD Object Of The Temporary Canary Object That Was Created On The Source (Originating) RWDC
				If ($modeOfOperationNr -eq 2) {
					$targetObjectToCheck = $null
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
						Try {
							#$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $dcToCheckHostName
							$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$dcToCheckHostName -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
							$targetObjectToCheck = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$dcToCheckHostName -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$targetObjectToCheckDN)"
						} Catch {
							Logging "" "ERROR"
							Logging "Error Querying AD Against '$dcToCheckHostName' For Object With 'distinguishedName=$targetObjectToCheckDN'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}
					If ($localADforest -eq $false -And $adminCrds) {
						Try {
							#$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $dcToCheckHostName -Credential $adminCrds
							$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$dcToCheckHostName -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
							$targetObjectToCheck = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$dcToCheckHostName -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$targetObjectToCheckDN)"
						} Catch {
							Logging "" "ERROR"
							Logging "Error Querying AD Against '$dcToCheckHostName' For User Object With 'distinguishedName=$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}
				}

				# For Mode 3 Or 4 From The DC to Check Retrieve The AD Object Of The Targeted KrbTgt Account (And Its Password Last Set) That Had Its Password Reset On The Source (Originating) RWDC
				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
					# Retrieve The Object From The Target DC
					$objectOnTargetDC = $null
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
						Try {
							#$objectOnTargetDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $dcToCheckHostName
							$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$dcToCheckHostName -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
							$objectOnTargetDC = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$dcToCheckHostName -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$targetObjectToCheckDN)" -PropertiesToLoad @("pwdlastset")
						} Catch {
							Logging "" "ERROR"
							Logging "Error Querying AD Against '$dcToCheckHostName' For Object '$targetObjectToCheckDN'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}
					If ($localADforest -eq $false -And $adminCrds) {
						Try {
							#$objectOnTargetDC = Get-ADObject -Identity $targetObjectToCheckDN -Properties * -Server $dcToCheckHostName -Credential $adminCrds
							$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$dcToCheckHostName -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
							$objectOnTargetDC = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$dcToCheckHostName -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$targetObjectToCheckDN)" -PropertiesToLoad @("pwdlastset")
						} Catch {
							Logging "" "ERROR"
							Logging "Error Querying AD Against '$dcToCheckHostName' For Object '$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}

					# Retrieve The Password Last Set Of The Object On The Target DC
					$objectOnTargetDCPwdLastSet = $null
					$objectOnTargetDCPwdLastSet = Get-Date $([datetime]::fromfiletime($objectOnTargetDC.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
				}
			} Else {
				# When The DC To Check Is Not Reachable
				Logging "     * DC is NOT reachable..." "ERROR"
			}

			If ($dcToCheckReachability -eq $true) {
				# When The DC To Check Is Reachable

				If ($targetObjectToCheck -Or $objectOnTargetDCPwdLastSet -eq $objectOnSourceOrgRWDCPwdLastSet) {
					# If The Target Object To Check Does Exist Or Its Password Last Set Does Match With The Password Last Set Of The Object On The Source (Originating) RWDC
					# For Mode 2 Only
					If ($modeOfOperationNr -eq 2) {
						Logging "     * Object [$targetObjectToCheckDN] now does exist in the AD database" "SUCCESS"
					}

					# For Mode 3 Or 4 Or 5 Or 6 Only
					If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
						Logging "     * The (new) password for Object [$targetObjectToCheckDN] now does exist in the AD database" "SUCCESS"
					}
					Logging "" "SUCCESS"

					# If The DC To Check Does Not Yet Exist On The Ending List With All DCs That Were Checked, Then Add It To The Ending List
					If (!($listOfDCsToCheckObjectOnEnd | Where-Object{$_."Host Name" -eq $dcToCheckHostName})) {
						$listOfDCsToCheckObjectOnEndObj = New-Object -TypeName System.Object
						$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "Host Name" -Value $dcToCheckHostName
						$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "PDC" -Value $dcToCheckIsPDC
						$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $dcToCheckSiteName
						$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "DS Type" -Value $dcToCheckDSType
						$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $dcToCheckIPAddress
						$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $dcToCheckReachability
						$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "Source RWDC FQDN" -Value $targetedADdomainSourceRWDCFQDN
						$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "Time" -Value $(("{0:n2}" -f ((Get-Date) - $startDateTime).TotalSeconds))
						$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndObj
					}
				} Else {
					# If The Target Object To Check Does Not Exist Or Its Password Last Set Does Not Match (Yet) With The Password Last Set Of The Object On The Source (Originating) RWDC
					# For Mode 2 Only
					If ($modeOfOperationNr -eq 2) {
						Logging "     * Object [$targetObjectToCheckDN] does NOT exist yet in the AD database" "WARNING"
					}

					# For Mode 3 Or 4 Or 5 Or 6 Only
					If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
						Logging "     * The (new) password for Object [$targetObjectToCheckDN] does NOT exist yet in the AD database" "WARNING"
					}
					Logging "" "WARNING"

					# Variable Specifying The Object Is Not In Sync
					$replicated = $false
				}
			} Else {
				# When The DC To Check Is Not Reachable
				Logging "     * Unable to connect to DC and check for Object [$targetObjectToCheckDN]..." "ERROR"
				Logging "" "WARNING"

				# If The DC To Check Does Not Yet Exist On The Ending List With All DCs That Were Checked, Then Add It To The Ending List
				If (!($listOfDCsToCheckObjectOnEnd | Where-Object{$_."Host Name" -eq $dcToCheckHostName})) {
					$listOfDCsToCheckObjectOnEndObj = New-Object -TypeName System.Object
					$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "Host Name" -Value $dcToCheckHostName
					$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "PDC" -Value $dcToCheckIsPDC
					$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $dcToCheckSiteName
					$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "DS Type" -Value $dcToCheckDSType
					$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $dcToCheckIPAddress
					$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $dcToCheckReachability
					$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "Source RWDC FQDN" -Value $targetedADdomainSourceRWDCFQDN
					$listOfDCsToCheckObjectOnEndObj | Add-Member -MemberType NoteProperty -Name "Time" -Value "<Fail>"
					$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndObj
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
	Logging ""
	Logging "  --> Start Time......: $(Get-Date $startDateTime -format 'yyyy-MM-dd HH:mm:ss')"
	Logging "  --> End Time........: $(Get-Date $endDateTime -format 'yyyy-MM-dd HH:mm:ss')"
	Logging "  --> Duration........: $duration Seconds"
	Logging ""

	# If Mode 2 Was Being Executed, Then Delete The Temp Canary Object On The Source (Originating) RWDC
	If ($modeOfOperationNr -eq 2) {
		# Retrieve The Temp Canary Object From The Source (Originating) RWDC
		$targetObjectToCheck = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				#$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $targetedADdomainSourceRWDCFQDN
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
				$targetObjectToCheck = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$targetObjectToCheckDN)"
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For Object '$targetObjectToCheckDN'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				#$targetObjectToCheck = Get-ADObject -LDAPFilter "(distinguishedName=$targetObjectToCheckDN)" -Server $targetedADdomainSourceRWDCFQDN -Credential $adminCrds
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
				$targetObjectToCheck = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$targetObjectToCheckDN)"
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainSourceRWDCFQDN' For Object '$targetObjectToCheckDN' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}

		# If The Temp Canary Object Exists On The Source (Originating) RWDC, Then Delete It
		If ($targetObjectToCheck) {
			# Execute The Deletion Of The Temp Canary Object On The Source (Originating) RWDC. There Is No Need To Force Deletion Of The Object On All The Other DCs As In Time It Will Be Deleted
			deleteTempCanaryObject $targetedADdomainSourceRWDCFQDN $targetObjectToCheckDN $localADforest $adminCrds
		}
	}

	# Sort The Ending List With All DCs That Were Checked
	$listOfDCsToCheckObjectOnEnd = $listOfDCsToCheckObjectOnEnd | Sort-Object -Property @{Expression = "Time"; Descending = $False} | Format-Table -Autosize
	Logging ""
	Logging "List Of DCs In AD Domain '$targetedADdomainFQDN' And Their Timing..."
	Logging ""
	Logging "$($listOfDCsToCheckObjectOnEnd | Out-String)"
	Logging ""
}

### FUNCTION: Create Test Krbtgt Accounts
Function createTestKrbTgtADAccount($targetedADdomainRWDCFQDN, $krbTgtInUseByDCFQDN, $krbTgtSamAccountName, $krbTgtUse, $targetedADdomainDomainSID, $localADforest, $adminCrds) {
	# Determine The DN Of The Default NC Of The Targeted Domain
	$targetedADdomainDefaultNC = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			#$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDCFQDN).defaultNamingContext
			$targetedADdomainDefaultNC = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetedADdomainRWDCFQDN' For 'rootDSE'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			#$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDCFQDN -Credential $adminCrds).defaultNamingContext
			$targetedADdomainDefaultNC = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetedADdomainRWDCFQDN' For 'rootDSE' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}

	# Determine The DN Of The Users Container Of The Targeted Domain
	$containerForTestKrbTgtAccount = $null
	$containerForTestKrbTgtAccount = "CN=Users," + $targetedADdomainDefaultNC

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

	# Generate The DN Of The Test KrbTgt Object
	$testKrbTgtObjectDN = $null
	$testKrbTgtObjectDN = "CN=" + $testKrbTgtObjectName + "," + $containerForTestKrbTgtAccount

	# Display Information About The Test KrbTgt To Be Created/Edited
	Logging "  --> RWDC To Create/Update Object On.......: '$targetedADdomainRWDCFQDN'"
	Logging "  --> Full Name Test KrbTgt Account.........: '$testKrbTgtObjectName'"
	Logging "  --> Description...........................: '$testKrbTgtObjectDescription'"
	Logging "  --> Container Test KrbTgt Account.........: '$containerForTestKrbTgtAccount'"
	If ($krbTgtUse -eq "RWDC") {
		Logging "  --> To Be Used By DC(s)...................: 'All RWDCs'"
	}
	If ($krbTgtUse -eq "RODC") {
		Logging "  --> To Be Used By RODC....................: '$krbTgtInUseByDCFQDN'"
	}

	# If The Test/Bogus KrbTgt Account Is Used By RWDCs
	If ($krbTgtUse -eq "RWDC") {
		$deniedRODCPwdReplGroupRID = "572"
		$deniedRODCPwdReplGroupObjectSID = $targetedADdomainDomainSID + "-" + $deniedRODCPwdReplGroupRID
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				#$deniedRODCPwdReplGroupObjectName = (Get-ADGroup -Identity $deniedRODCPwdReplGroupObjectSID -Server $targetedADdomainRWDCFQDN).Name
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
				$deniedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(objectSID=$deniedRODCPwdReplGroupObjectSID)" -PropertiesToLoad @("name")
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Group Object With 'objectSID=$deniedRODCPwdReplGroupObjectSID'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				#$deniedRODCPwdReplGroupObjectName = (Get-ADGroup -Identity $deniedRODCPwdReplGroupObjectSID -Server $targetedADdomainRWDCFQDN -Credential $adminCrds).Name
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
				$deniedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(objectSID=$deniedRODCPwdReplGroupObjectSID)" -PropertiesToLoad @("name")
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Group Object With 'objectSID=$deniedRODCPwdReplGroupObjectSID' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		$deniedRODCPwdReplGroupObjectDN = $deniedRODCPwdReplGroupObject.distinguishedName
		$deniedRODCPwdReplGroupObjectName = $deniedRODCPwdReplGroupObject.name
		Logging "  --> Membership Of RODC PRP Group..........: '$deniedRODCPwdReplGroupObjectName' ('$deniedRODCPwdReplGroupObjectDN')"
	}

	# If The Test/Bogus KrbTgt Account Is Used By RODCs
	If ($krbTgtUse -eq "RODC") {
		$allowedRODCPwdReplGroupRID = "571"
		$allowedRODCPwdReplGroupObjectSID = $targetedADdomainDomainSID + "-" + $allowedRODCPwdReplGroupRID
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				#$allowedRODCPwdReplGroupObjectName = (Get-ADGroup -Identity $allowedRODCPwdReplGroupObjectSID -Server $targetedADdomainRWDCFQDN).Name
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
				$allowedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(objectSID=$allowedRODCPwdReplGroupObjectSID)" -PropertiesToLoad @("name")
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Group Object With 'objectSID=$allowedRODCPwdReplGroupObjectSIDD'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				#$allowedRODCPwdReplGroupObjectName = (Get-ADGroup -Identity $allowedRODCPwdReplGroupObjectSID -Server $targetedADdomainRWDCFQDN -Credential $adminCrds).Name
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
				$allowedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(objectSID=$allowedRODCPwdReplGroupObjectSID)" -PropertiesToLoad @("name")
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Group Object With 'objectSID=$allowedRODCPwdReplGroupObjectSID' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		$allowedRODCPwdReplGroupObjectDN = $allowedRODCPwdReplGroupObject.distinguishedName
		$allowedRODCPwdReplGroupObjectName = $allowedRODCPwdReplGroupObject.name
		Logging "  --> Membership Of RODC PRP Group..........: '$allowedRODCPwdReplGroupObjectName' ('$allowedRODCPwdReplGroupObjectDN')"
	}
	Logging ""

	# Check If The Test/Bogus KrbTgt Account Already Exists In AD
	$testKrbTgtObject = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			#$testKrbTgtObject = Get-ADUser -LDAPFilter "(distinguishedName=$testKrbTgtObjectDN)" -Properties Description -Server $targetedADdomainRWDCFQDN
			$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
			$testKrbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$testKrbTgtObjectDN)" -PropertiesToLoad @("description")
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$testKrbTgtObjectDN'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			#$testKrbTgtObject = Get-ADUser -LDAPFilter "(distinguishedName=$testKrbTgtObjectDN)" -Properties Description -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
			$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
			$testKrbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$testKrbTgtObjectDN)" -PropertiesToLoad @("description")
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$testKrbTgtObjectDN' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($testKrbTgtObject) {
		Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ALREADY EXISTS on RWDC [$targetedADdomainRWDCFQDN]!..." "REMARK"
		Logging ""
		# Update The Description For The Test KrbTgt Account If There Is A Mismatch For Whatever Reason
		If ($testKrbTgtObject.Description -ne $testKrbTgtObjectDescription) {
			$testKrbTgtObj = [PSCustomObject]@{distinguishedName = $null; description = $null}
			$testKrbTgtObj.distinguishedName = $testKrbTgtObjectDN
			$testKrbTgtObj.description = $testKrbTgtObjectDescription
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					#Set-ADUser -Identity $testKrbTgtObjectSamAccountName -description $testKrbTgtObjectDescription -Server $targetedADdomainRWDCFQDN
					Edit-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -Mode Replace -Object $testKrbTgtObj
				} Catch {
					Logging "" "ERROR"
					Logging "Error Updating User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectSamAccountName'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					#Set-ADUser -Identity $testKrbTgtObjectSamAccountName -description $testKrbTgtObjectDescription -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
					Edit-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -Mode Replace -Object $testKrbTgtObj
				} Catch {
					Logging "" "ERROR"
					Logging "Error Updating User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			Logging "  --> Updated Description For Existing Test KrbTgt Account [$testKrbTgtObjectDN] on RWDC [$targetedADdomainRWDCFQDN] Due To Mismatch!..." "REMARK"
		}

		# Check The Membership Of The Test KrbTgt Accounts And Update As Needed
		$updateMembership = $false
		If ($krbTgtUse -eq "RWDC") {
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
					If (!(Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$testKrbTgtObjectSamAccountName)(memberOf:1.2.840.113556.1.4.1941:=$deniedRODCPwdReplGroupObjectDN))")) {
						$updateMembership = $true
					}
				} Catch {
					Logging "" "ERROR"
					Logging "Error Checking Membership On '$targetedADdomainRWDCFQDN' Of Object '$testKrbTgtObjectSamAccountName' For Object '$deniedRODCPwdReplGroupObjectName'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
					If (!(Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$testKrbTgtObjectSamAccountName)(memberOf:1.2.840.113556.1.4.1941:=$deniedRODCPwdReplGroupObjectDN))")) {
						$updateMembership = $true
					}
				} Catch {
					Logging "" "ERROR"
					Logging "Error Checking Membership On '$targetedADdomainRWDCFQDN' Of Object '$testKrbTgtObjectSamAccountName' For Object '$deniedRODCPwdReplGroupObjectName' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
		}
		If ($krbTgtUse -eq "RODC") {
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
					If (!(Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$testKrbTgtObjectSamAccountName)(memberOf:1.2.840.113556.1.4.1941:=$allowedRODCPwdReplGroupObjectDN))")) {
						$updateMembership = $true
					}
				} Catch {
					Logging "" "ERROR"
					Logging "Error Checking Membership On '$targetedADdomainRWDCFQDN' Of Object '$testKrbTgtObjectSamAccountName' For Object '$allowedRODCPwdReplGroupObjectName'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
					If (!(Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$testKrbTgtObjectSamAccountName)(memberOf:1.2.840.113556.1.4.1941:=$allowedRODCPwdReplGroupObjectDN))")) {
						$updateMembership = $true
					}
				} Catch {
					Logging "" "ERROR"
					Logging "Error Checking Membership On '$targetedADdomainRWDCFQDN' Of Object '$testKrbTgtObjectSamAccountName' For Object '$allowedRODCPwdReplGroupObjectName' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
		}
	} Else {
		# If The Test/Bogus KrbTgt Account Does Not Exist Yet In AD
		# Specify The Number Of Characters The Generate Password Should Contain
		$passwdNrChars = 64

		# Generate A New Password With The Specified Length (Text)
		$krbTgtPassword = $null
		$krbTgtPassword = (generateNewComplexPassword $passwdNrChars).ToString()

		# Convert The Text Based Version Of The New Password To A Secure String
		#$krbTgtPasswordSecure = $null
		#$krbTgtPasswordSecure = ConvertTo-SecureString $krbTgtPassword -AsPlainText -Force

		# Try To Create The Test/Bogus KrbTgt Account In The AD Domain And If Not Successfull Throw Error
		Try {
			$testKrbTgtObj = [PSCustomObject]@{distinguishedName = $null; objectClass = $null; sAMAccountName = $null; displayName = $null; userAccountControl = 0; unicodePwd = $null; description = $null}
			$testKrbTgtObj.distinguishedName = $testKrbTgtObjectDN
			$testKrbTgtObj.objectClass = "user"
			$testKrbTgtObj.sAMAccountName = $testKrbTgtObjectSamAccountName
			$testKrbTgtObj.displayName = $testKrbTgtObjectName
			$testKrbTgtObj.userAccountControl = 514
			$testKrbTgtObj.unicodePwd = $krbTgtPassword
			$testKrbTgtObj.description = $testKrbTgtObjectDescription
			#Register-LdapAttributeTransform -name unicodePwd -AttributeName unicodePwd
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					#New-ADUser -SamAccountName $testKrbTgtObjectSamAccountName -Name $testKrbTgtObjectName -DisplayName $testKrbTgtObjectName -Path $containerForTestKrbTgtAccount -AccountPassword $krbTgtPasswordSecure -Enabled $False -description $testKrbTgtObjectDescription -Server $targetedADdomainRWDCFQDN
					Add-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -Object $testKrbTgtObj -BinaryProps unicodePwd
				} Catch {
					Logging "" "ERROR"
					Logging "Error Creating User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectSamAccountName'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					#New-ADUser -SamAccountName $testKrbTgtObjectSamAccountName -Name $testKrbTgtObjectName -DisplayName $testKrbTgtObjectName -Path $containerForTestKrbTgtAccount -AccountPassword $krbTgtPasswordSecure -Enabled $False -description $testKrbTgtObjectDescription -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
					Add-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -Object $testKrbTgtObj -BinaryProps unicodePwd
				} Catch {
					Logging "" "ERROR"
					Logging "Error Creating User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
		} Catch {
			#Logging "" "ERROR"
			Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] FAILED TO BE CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
			Logging "" "ERROR"
			#Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			#Logging "" "ERROR"
			#Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			#Logging "" "ERROR"
			#Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			#Logging "" "ERROR"
		}

		# Check The The Test/Bogus KrbTgt Account Exists And Was created In AD
		$testKrbTgtObject = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				#$testKrbTgtObject = Get-ADObject -LDAPFilter "(&(objectClass=user)(name=$testKrbTgtObjectName))" -Server $targetedADdomainRWDCFQDN
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
				$testKrbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectClass=user)(name=$testKrbTgtObjectName))"
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'name=$testKrbTgtObjectName'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				#$testKrbTgtObject = Get-ADObject -LDAPFilter "(&(objectClass=user)(name=$testKrbTgtObjectName))" -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
				$testKrbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectClass=user)(name=$testKrbTgtObjectName))"
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'name=$testKrbTgtObjectName' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($testKrbTgtObject) {
			$testKrbTgtObjectDN = $null
			$testKrbTgtObjectDN = $testKrbTgtObject.DistinguishedName
			Logging "  --> New Test KrbTgt Account [$testKrbTgtObjectDN] CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." "REMARK"
			Logging "" "REMARK"
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
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					#Add-ADGroupMember -Identity $deniedRODCPwdReplGroupObjectName -Members $testKrbTgtObjectDN -Server $targetedADdomainRWDCFQDN
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
					$deniedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectClass=group)(sAMAccountName=$deniedRODCPwdReplGroupObjectName))" -AdditionalProperties @('member')
					$deniedRODCPwdReplGroupObject.member = $testKrbTgtObjectDN
					Edit-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -Object $deniedRODCPwdReplGroupObject -Mode Add
				} Catch {
					Logging "" "ERROR"
					Logging "Error Adding Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$deniedRODCPwdReplGroupObjectName'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					#Add-ADGroupMember -Identity $deniedRODCPwdReplGroupObjectName -Members $testKrbTgtObjectDN -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
					$deniedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectClass=group)(sAMAccountName=$deniedRODCPwdReplGroupObjectName))" -AdditionalProperties @('member')
					$deniedRODCPwdReplGroupObject.member = $testKrbTgtObjectDN
					Edit-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -Object $deniedRODCPwdReplGroupObject -Mode Add
				} Catch {
					Logging "" "ERROR"
					Logging "Error Retrieving Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$deniedRODCPwdReplGroupObjectName' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ADDED AS MEMBER OF [$deniedRODCPwdReplGroupObjectName]!..." "REMARK"
			Logging "" "REMARK"
		}

		If ($krbTgtUse -eq "RODC") {
			# If The Test/Bogus KrbTgt Account Is Used By RODCs
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					#Add-ADGroupMember -Identity $allowedRODCPwdReplGroupObjectName -Members $testKrbTgtObjectDN -Server $targetedADdomainRWDCFQDN
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
					$allowedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectClass=group)(sAMAccountName=$allowedRODCPwdReplGroupObjectName))" -AdditionalProperties @('member')
					$allowedRODCPwdReplGroupObject.member = $testKrbTgtObjectDN
					Edit-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -Object $allowedRODCPwdReplGroupObject -Mode Add
				} Catch {
					Logging "" "ERROR"
					Logging "Error Adding Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$allowedRODCPwdReplGroupObjectName'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					#Add-ADGroupMember -Identity $allowedRODCPwdReplGroupObjectName -Members $testKrbTgtObjectDN -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
					$allowedRODCPwdReplGroupObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectClass=group)(sAMAccountName=$allowedRODCPwdReplGroupObjectName))" -AdditionalProperties @('member')
					$allowedRODCPwdReplGroupObject.member = $testKrbTgtObjectDN
					Edit-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -Object $allowedRODCPwdReplGroupObject -Mode Add
				} Catch {
					Logging "" "ERROR"
					Logging "Error Retrieving Members On '$targetedADdomainRWDCFQDN' For Group Object With 'name=$allowedRODCPwdReplGroupObjectName' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ADDED AS MEMBER OF [$allowedRODCPwdReplGroupObjectName]!..." "REMARK"
			Logging "" "REMARK"
		}
	} ElseIf ($testKrbTgtObject -And $updateMembership -eq $false) {
		# If The Test/Bogus KrbTgt Account Is Already A Member Of The Specified AD Group
		If ($krbTgtUse -eq "RWDC") {
			Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ALREADY MEMBER OF [$deniedRODCPwdReplGroupObjectName]!..." "REMARK"
		}
		If ($krbTgtUse -eq "RODC") {
			Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] ALREADY MEMBER OF [$allowedRODCPwdReplGroupObjectName]!..." "REMARK"
		}
		Logging "" "REMARK"
	}
}

### FUNCTION: Delete Test Krbtgt Accounts
Function deleteTestKrbTgtADAccount($targetedADdomainRWDCFQDN, $krbTgtSamAccountName) {
	# Check If The Test/Bogus KrbTgt Account Exists In AD
	$testKrbTgtObject = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			#$testKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainRWDCFQDN
			$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
			$testKrbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))"
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}

	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			#$testKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
			$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
			$testKrbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))"
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object 'sAMAccountName=$krbTgtSamAccountName'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($testKrbTgtObject) {
		# If It Does Exist In AD
		$testKrbTgtObjectDN = $null
		$testKrbTgtObjectDN = $testKrbTgtObject.DistinguishedName
		Logging "  --> RWDC To Delete Object On..............: '$targetedADdomainRWDCFQDN'"
		Logging "  --> Test KrbTgt Account DN................: '$testKrbTgtObjectDN'"
		Logging ""
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				#Remove-ADUser -Identity $testKrbTgtObjectDN -Server $targetedADdomainRWDCFQDN -Confirm:$false
				Remove-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -Object $testKrbTgtObjectDN
			} Catch {
				Logging "" "ERROR"
				Logging "Error Deleting User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectDN'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				#Remove-ADUser -Identity $testKrbTgtObjectDN -Server $targetedADdomainRWDCFQDN -Credential $adminCrds -Confirm:$false
				Remove-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -Object $testKrbTgtObjectDN
			} Catch {
				Logging "" "ERROR"
				Logging "Error Deleting User On '$targetedADdomainRWDCFQDN' For Object '$testKrbTgtObjectDN' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		$testKrbTgtObject = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				#$testKrbTgtObject = Get-ADUser -LDAPFilter "(distinguishedName=$testKrbTgtObjectDN)" -Server $targetedADdomainRWDCFQDN
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
				$testKrbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$testKrbTgtObjectDN)"
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$testKrbTgtObjectDN'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				#$testKrbTgtObject = Get-ADUser -LDAPFilter "(distinguishedName=$testKrbTgtObjectDN)" -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
				$testKrbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$testKrbTgtObjectDN)"
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'distinguishedName=$testKrbTgtObjectDN' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If (!$testKrbTgtObject) {
			Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] DELETED on RWDC [$targetedADdomainRWDCFQDN]!..." "REMARK"
			Logging "" "REMARK"
		} Else {
			Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] FAILED TO BE DELETED on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
			Logging "  --> Manually delete the Test KrbTgt Account [$testKrbTgtObjectDN] on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
			Logging "" "ERROR"
		}
	} Else {
		# If It Does Not Exist In AD
		Logging "  --> Test KrbTgt Account [$testKrbTgtObjectDN] DOES NOT EXIST on RWDC [$targetedADdomainRWDCFQDN]!..." "WARNING"
		Logging "" "WARNING"
	}
}

### FUNCTION: Send E-mail With Information
Function sendMailMessage($smtpServer, $smtpPort, $smtpCredsUserName, $smtpCredsPassword, $mailFromSender, $mailToRecipient, $mailCcRecipients, $mailPriority, $mailSubject, $mailBody, $mailAttachments, $mailSignAndEncryptDllFile, $mailSign, $mailSignAndEncryptCertLocation, $mailSignAndEncryptCertThumbprint, $mailSignAndEncryptCertPFXFile, $mailSignAndEncryptCertPFXPassword, $mailEncrypt, $mailEncryptCertLocation, $mailEncryptCertThumbprint, $mailEncryptCertCERFile) {
	If ($mailSign.ToUpper() -eq "ON" -Or $mailEncrypt.ToUpper() -eq "ON") {
		# Load Cpi.Net.SecureMail.dll
		Add-Type -Path $mailSignAndEncryptDllFile

		# Create Cryptocertificate Object
		If ($mailSign.ToUpper() -eq "ON" -Or $mailEncrypt.ToUpper() -eq "ON") {
			If ($mailSignAndEncryptCertLocation.ToUpper() -eq "PFX") {
				$mailSignAndEncryptCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($mailSignAndEncryptCertPFXFile, $mailSignAndEncryptCertPFXPassword) # Cert From The Sender If Applicable!
			}
			If ($mailSignAndEncryptCertLocation.ToUpper() -eq "STORE") {
				$certStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("My", "CurrentUser")
				$certStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
				$mailSignAndEncryptCert = $($certStore.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $mailSignAndEncryptCertThumbprint, $true))[0] # Cert From The Sender If Applicable!
				$certStore.Close()
			}
		} Else {
			$mailSignCert = $null
		}
		If ($mailEncrypt.ToUpper() -eq "ON") {
			If ($mailEncryptCertLocation.ToUpper() -eq "CER") {
				$mailEncryptCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($mailEncryptCertCERFile) # Cert From The Recipient(s) If Applicable!
			}
			If ($mailEncryptCertLocation.ToUpper() -eq "STORE") {
				$certStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("My", "CurrentUser")
				$certStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
				$mailEncryptCert = $($certStore.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $mailEncryptCertThumbprint, $true))[0] # Cert From The Recipient(s) If Applicable!
				$certStore.Close()
			}
		} Else {
			$mailEncryptCert = $null
		}

		# Split Sender E-mail Adress To Get Sender Name
		$mailFromSenderName = $mailFromSender -split '@'

		# Split Recipient E-mail Adress To Get Sender Name
		$mailToRecipientName = $mailToRecipient -split '@'

		# Create Secure Mail Message Object
		$mail = New-Object Cpi.Net.SecureMail.SecureMailMessage
		$mail.From = New-Object Cpi.Net.SecureMail.SecureMailAddress($mailFromSender, $mailFromSenderName[0], $mailSignAndEncryptCert, $mailSignAndEncryptCert)
		$mail.To.Add((New-Object Cpi.Net.SecureMail.SecureMailAddress($mailToRecipient, $mailToRecipientName[0], $mailEncryptCert)))
		If ($mailCcRecipients.Length -gt 0) {
			$mailCcRecipients | ForEach-Object {
				$mail.CC.Add((New-Object Cpi.Net.SecureMail.SecureMailAddress($_)))
			}
		}
		$mail.Subject = $mailSubject
		$mail.Priority = $mailPriority
		$mail.Body = $mailBody
		$mail.IsBodyHtml = $true
		If ($mailAttachments.Length -gt 0) {
			$mailAttachments | ForEach-Object {
				$mail.Attachments.Add((New-Object Cpi.Net.SecureMail.SecureAttachment($_)))
			}
		}
		# Set Mail Properties For Signing And Encryption
		If ($mailSign.ToUpper() -eq "ON") {
			$mail.IsSigned = $true
		} Else {
			$mail.IsSigned = $false
		}
		If ($mailEncrypt.ToUpper() -eq "ON") {
			$mail.IsEncrypted = $true
		} Else {
			$mail.IsEncrypted = $false
		}

		# Create SMTP-Client To Send Mail Message
		$smtp = New-Object System.Net.Mail.SmtpClient($smtpServer, $smtpPort)
		If ($useSSLForSMTP -eq "TRUE") {
			$smtp.EnableSsl = $true
		} Else {
			$smtp.EnableSsl = $false
		}
		If ($null -ne $smtpCredsUserName -And $smtpCredsUserName -ne "LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_SPECIFY" -And $null -ne $smtpCredsPassword -And $smtpCredsPassword -ne "LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_SPECIFY") {
			$smtp.Credentials = New-Object System.Net.NetworkCredential($smtpCredsUserName, $(ConvertTo-SecureString $smtpCredsPassword -AsPlainText -Force))
		}

		# Finally Send Mail
		Try {
			$smtp.Send($mail)
		} Catch {
			Write-Host ""
			Write-Host "Error Sending Mail..." -ForeGroundColor Red
			Write-Host ""
			Write-Host "Exception Type......: $($_.Exception.GetType().FullName)" -ForeGroundColor Red
			Write-Host ""
			Write-Host "Exception Message...: $($_.Exception.Message)" -ForeGroundColor Red
			Write-Host ""
			Write-Host "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -ForeGroundColor Red
			Write-Host ""
		}
	} Else {
		If ($sslType.ToUpper() -eq "IMPLICIT") {
			# SOURCE: https://nicholasarmstrong.com/2009/12/sending-email-with-powershell-implicit-and-explicit-ssl/
			# Load System.Web assembly
			[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

			# Create Mail Message Object
			$mail = New-Object System.Web.Mail.MailMessage
			$mail.Fields.Add("http://schemas.microsoft.com/cdo/configuration/smtpserver", $smtpServer)
			$mail.Fields.Add("http://schemas.microsoft.com/cdo/configuration/smtpserverport", $smtpPort)
			$mail.Fields.Add("http://schemas.microsoft.com/cdo/configuration/smtpusessl", $true)
			$mail.Fields.Add("http://schemas.microsoft.com/cdo/configuration/sendusername", $smtpCredsUserName)
			$mail.Fields.Add("http://schemas.microsoft.com/cdo/configuration/sendpassword", $smtpCredsPassword)
			#$mail.Fields.Add("http://schemas.microsoft.com/cdo/configuration/smtpconnectiontimeout", 30000/1000)
			# Use Network SMTP server...
			$mail.Fields.Add("http://schemas.microsoft.com/cdo/configuration/sendusing", 2)
			# ... and basic authentication
			$mail.Fields.Add("http://schemas.microsoft.com/cdo/configuration/smtpauthenticate", 1)
			$mail.From = $mailFromSender
			$mail.To = $mailToRecipient
			If ($mailCcRecipients.Length -gt 0) {
				$mail.CC = $($mailCcRecipients -join ";")
			}
			$mail.Subject = $mailSubject
			$mail.Priority = $mailPriority
			$mail.Body = $mailBody
			$mail.BodyFormat = "Html"
			If ($mailAttachments.Length -gt 0) {
				$mailAttachments | ForEach-Object {
					$mail.Attachments.Add($(New-Object System.Web.Mail.MailAttachment $_))
				}
			}

			# Finally Send Mail
			Try {
				[System.Web.Mail.SmtpMail]::Send($mail)
			} Catch {
				Write-Host ""
				Write-Host "Error Sending Mail..." -ForeGroundColor Red
				Write-Host ""
				Write-Host "Exception Type......: $($_.Exception.GetType().FullName)" -ForeGroundColor Red
				Write-Host ""
				Write-Host "Exception Message...: $($_.Exception.Message)" -ForeGroundColor Red
				Write-Host ""
				Write-Host "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -ForeGroundColor Red
				Write-Host ""
			}
		}
		If ($sslType.ToUpper() -eq "EXPLICIT") {
			# Create Mail Message Object
			$mail = New-Object System.Net.Mail.MailMessage
			$mail.From = $mailFromSender
			$mail.To.Add($mailToRecipient)
			If ($mailCcRecipients.Length -gt 0) {
				$mailCcRecipients | ForEach-Object {
					$mail.CC.Add($_)
				}
			}
			$mail.Subject = $mailSubject
			$mail.Priority = $mailPriority
			$mail.Body = $mailBody
			$mail.IsBodyHtml = $true
			If ($mailAttachments.Length -gt 0) {
				$mailAttachments | ForEach-Object {
					$mail.Attachments.Add($_)
				}
			}

			# Create SMTP-Client To Send Mail Message
			$smtp = New-Object System.Net.Mail.SmtpClient($smtpServer, $smtpPort)
			If ($useSSLForSMTP -eq "TRUE") {
				$smtp.EnableSsl = $true
			} Else {
				$smtp.EnableSsl = $false
			}
			If ($null -ne $smtpCredsUserName -And $smtpCredsUserName -ne "LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_SPECIFY" -And $null -ne $smtpCredsPassword -And $smtpCredsPassword -ne "LEAVE_EMPTY_OR_LEAVE_AS_IS_OR_SPECIFY") {
				$smtp.Credentials = New-Object System.Net.NetworkCredential($smtpCredsUserName, $(ConvertTo-SecureString $smtpCredsPassword -AsPlainText -Force))
			}

			# Finally Send Mail
			Try {
				$smtp.Send($mail)
			} Catch {
				Write-Host ""
				Write-Host "Error Sending Mail..." -ForeGroundColor Red
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
}

### FUNCTION: Get Server Names
Function getServerNames {
	$localComputerName = $(Get-WmiObject -Class Win32_ComputerSystem).Name							# [0] NetBIOS Computer Name
	$fqdnADDomainOfComputer = $(Get-WmiObject -Class Win32_ComputerSystem).Domain					# [1] FQDN Of The AD Domain The Computer Is A Member Of
	$fqdnComputerInADDomain = $localComputerName + "." + $fqdnADDomainOfComputer					# [2] FQDN Of The Computer In The AD (!) Domain
	$fqdnComputerInDNS = [System.Net.Dns]::GetHostByName($localComputerName).HostName				# [3] FQDN Of The Computer In The DNS (!) Domain
	$fqdnDnsDomainOfComputer = $fqdnComputerInDNS.SubString($fqdnComputerInDNS.IndexOf(".") + 1)	# [4] FQDN Of The Dns Domain The Computer Is A Part Of

	Return $localComputerName, $fqdnADDomainOfComputer, $fqdnComputerInADDomain, $fqdnComputerInDNS, $fqdnDnsDomainOfComputer
}

###
# Clear The Screen
###
Clear-Host

###
# Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
###
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ RESET KRBTGT ACCOUNT PASSWORD FOR RWDCs/RODCs +++"
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
$getServerNames = getServerNames
$localComputerName = $getServerNames[0]			# [0] NetBIOS Computer Name
$fqdnADDomainOfComputer = $getServerNames[1]	# [1] FQDN Of The AD Domain The Computer Is A Member Of
$fqdnComputerInADDomain = $getServerNames[2]	# [2] FQDN Of The Computer In The AD (!) Domain
$fqdnComputerInDNS = $getServerNames[3]			# [3] FQDN Of The Computer In The DNS (!) Domain
$fqdnDnsDomainOfComputer = $getServerNames[4]	# [4] FQDN Of The Dns Domain The Computer Is A Part Of
$fqdnADDomainOfComputerContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $fqdnADDomainOfComputer)
$fqdnADForestOfComputer = ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($fqdnADDomainOfComputerContext)).Forest.Name
[string]$logFilePath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_Reset-KrbTgt-Password-For-RWDCs-And-RODCs.log")
$connectionTimeout = 2000
$argsCount = $PSBoundParameters.Count
If ($argsCount -gt 0 -And $sendMailWithLogFile) {
	[string]$scriptXMLConfigFilePath = Join-Path $currentScriptFolderPath "Reset-KrbTgt-Password-For-RWDCs-And-RODCs.xml"

	### Read The XML Config File
	If (!(Test-Path $scriptXMLConfigFilePath)) {
		Write-Host ""
		Write-Host "The XML Config File '$scriptXMLConfigFilePath' CANNOT Be Found!..." -ForeGroundColor Red
		Write-Host "Aborting Script..." -ForeGroundColor Red
		Write-Host ""
		
		BREAK
	} Else {
		[XML]$script:configResetKrbTgtPasswordNotify = Get-Content $scriptXMLConfigFilePath

		### Read The Properties From The XML Config File
		$script:smtpServer = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.smtpServer
		$script:smtpPort = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.smtpPort
		$script:useSSLForSMTP = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.useSSLForSMTP
		$script:sslType = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.sslType
		$script:smtpCredsUserName = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.smtpCredsUserName
		$script:smtpCredsPassword = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.smtpCredsPassword
		$script:mailSubject = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailSubject
		$script:mailPriority = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailPriority
		$script:mailBody = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailBody
		$script:mailFromSender = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailFromSender
		$script:mailToRecipient = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailToRecipient
		$script:mailCcRecipients = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailCcRecipients.mailCcRecipient
		$script:mailSign = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailSign
		$script:mailEncrypt = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailEncrypt
		$script:mailSignAndEncryptDllFile = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailSignAndEncryptDllFile
		If ($mailSign.ToUpper() -eq "ON") {
			$script:mailSignAndEncryptCertLocation = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailSignAndEncryptCertLocation
			If ($mailSignAndEncryptCertLocation.ToUpper() -eq "PFX") {
				$script:mailSignAndEncryptCertPFXFile = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailSignAndEncryptCertPFXFile
				$script:mailSignAndEncryptCertPFXPassword = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailSignAndEncryptCertPFXPassword
			}
			If ($mailSignAndEncryptCertLocation.ToUpper() -eq "STORE") {
				$script:mailSignAndEncryptCertThumbprint = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailSignAndEncryptCertThumbprint
			}
		}
		If ($mailEncrypt.ToUpper() -eq "ON") {
			$script:mailEncryptCertLocation = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailEncryptCertLocation
			If ($mailEncryptCertLocation.ToUpper() -eq "CER") {
				$script:mailEncryptCertCERFile = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailEncryptCertCERFile
			}
			If ($mailEncryptCertLocation.ToUpper() -eq "STORE") {
				$script:mailEncryptCertThumbprint = $configResetKrbTgtPasswordNotify.resetKrbTgtPassword.mailEncryptCertThumbprint
			}
		}
	}
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
Logging ""
Logging "                                          **********************************************************" "MAINHEADER"
Logging "                                          *                                                        *" "MAINHEADER"
Logging "                                          *  --> Reset KrbTgt Account Password For RWDCs/RODCs <-- *" "MAINHEADER"
Logging "                                          *                                                        *" "MAINHEADER"
Logging "                                          *     Re-Written By: Jorge de Almeida Pinto [MVP-EMS]    *" "MAINHEADER"
Logging "                                          *                                                        *" "MAINHEADER"
Logging "                                          *            BLOG: Jorge's Quest For Knowledge           *" "MAINHEADER"
Logging "                                          *   (URL: http://jorgequestforknowledge.wordpress.com/)  *" "MAINHEADER"
Logging "                                          *                                                        *" "MAINHEADER"
Logging "                                          *                    $version                    *" "MAINHEADER"
Logging "                                          *                                                        *" "MAINHEADER"
Logging "                                          **********************************************************" "MAINHEADER"
Logging ""

###
# Script Details
###
### Logging Where The Script Is Being Executed From
Logging ""
Logging "Local Computer Name...................: $localComputerName"
Logging "FQDN AD Domain Of Computer............: $fqdnADDomainOfComputer"
Logging "FQDN Computer In AD Domain............: $fqdnComputerInADDomain"
Logging "FQDN Computer In DNS..................: $fqdnComputerInDNS"
Logging "FQDN DNS Domain Of Computer...........: $fqdnDnsDomainOfComputer"
Logging "Execution Mode........................: $(If ($argsCount -eq 0) {'ON-DEMAND'} Else {'AUTOMATED'})"
If ($argsCount -gt 0 -And $sendMailWithLogFile) {
	Logging "Arguments Used........................:"
	$PSBoundParameters.Keys | ForEach-Object {
		Logging " - Argument...........................: $($_.PadRight(25,' ')) = $($PSBoundParameters[$_])"
	}
	Logging "XML Config Options....................:"
	Logging " - smtpServer.........................: $smtpServer"
	Logging " - smtpPort...........................: $smtpPort"
	Logging " - useSSLForSMTP......................: $useSSLForSMTP"
	If ($useSSLForSMTP.ToUpper() -eq "TRUE") {
		Logging " - sslType............................: $sslType"
	}
	Logging " - smtpCredsUserName..................: $smtpCredsUserName"
	Logging " - smtpCredsPassword..................: ******************"
	Logging " - mailSubject........................: $mailSubject"
	Logging " - mailPriority.......................: $mailPriority"
	Logging " - mailBody...........................: `<Some HTML Body`>"
	Logging " - mailFromSender.....................: $mailFromSender"
	Logging " - mailToRecipient....................: $mailToRecipient"
	If ($mailCcRecipients.count -gt 0) {
		$mailCcRecipients | ForEach-Object {
			Logging " - mailCcRecipient....................: $($_)"
		}
	}
	Logging " - mailSign...........................: $mailSign"
	Logging " - mailEncrypt........................: $mailEncrypt"
	Logging " - mailSignAndEncryptDllFile..........: $mailSignAndEncryptDllFile"
	Logging " - mailSignAndEncryptCertLocation.....: $mailSignAndEncryptCertLocation"
	Logging " - mailSignAndEncryptCertPFXFile......: $mailSignAndEncryptCertPFXFile"
	Logging " - mailSignAndEncryptCertThumbprint...: $mailSignAndEncryptCertThumbprint"
	Logging " - mailEncryptCertLocation............: $mailEncryptCertLocation"
	Logging " - mailEncryptCertCERFile.............: $mailEncryptCertCERFile"
	Logging " - mailEncryptCertThumbprint..........: $mailEncryptCertThumbprint"
}
Logging ""

###
# Checking Requirements
###
### Checking Elevation Status Of Current Process
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "CHECKING ELEVATION STATUS OF CURRENT PROCESS..." "HEADER"
Logging ""

$currentElevationStatus = checkLocalElevationStatus
Logging "Current Elevation Status...: $currentElevationStatus"
If ($currentElevationStatus -eq "NOT-ELEVATED") {
	$sleepInSecs = 5
	Logging "" "REMARK"
	Logging "The Script IS NOT Running In An Elevated PowerShell Command Prompt..." "REMARK"
	Logging "Restarting The Script Through An Elevated Command Prompt In $sleepInSecs Seconds..." "REMARK"
	$iTimer = 0
	Do {
		Logging " > $($sleepInSecs - $iTimer)..." "REMARK"
		Start-Sleep -s 1
		$iTimer++
	} Until ($iTimer -eq $sleepInSecs)
	Logging "" "REMARK"
	Start-Process Powershell -Wait -Verb runAs -ArgumentList "-NoExit -Command `"$currentScriptCmdLineUsed`""
	Stop-Process -Id $PID
}

<#
### Loading The DLL Required For System.DirectoryServices.Protocols (S.DS.P.)
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "LOADING THE DLL REQUIRED FOR SYSTEM.DIRECTORYSERVICES.PROTOCOLS (S.DS.P.)..." "HEADER"
Logging ""

If ([Environment]::Is64BitProcess) {
	$processArchitecture = "64-Bit"
	$dotNetMainFolderPath = "$ENV:WINDIR\Microsoft.NET\Framework64"
} Else {
	$processArchitecture = "32-Bit"
	$dotNetMainFolderPath = "$ENV:WINDIR\Microsoft.NET\Framework"
}
$sdspDLLPath = Get-ChildItem -Path $dotNetMainFolderPath -Recurse -Filter "System.DirectoryServices.Protocols.dll"
Logging "Process Architecture..................: $processArchitecture"
Logging "S.DS.P. DLL Path......................: $(($sdspDLLPath | Sort-Object -Property ProductVersion)[0].FullName)"
Add-Type -Path $(($sdspDLLPath | Sort-Object -Property ProductVersion)[0].FullName)
#>

###
# Technical Information
###
### Providing Information About What The Script Is Capable Of And How The Script Works
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "INFORMATION REGARDING KRBTGT ACCOUNTS AND PASSWORD RESETS..." "HEADER"
Logging ""
If ($noInfo) {
	Logging "Do you want to read information about the script, its functions, its behavior and the impact? [YES | NO]: NO" "ACTION"
	$yesOrNo = "NO"
} Else {
	Logging "Do you want to read information about the script, its functions, its behavior and the impact? [YES | NO]: " "ACTION-NO-NEW-LINE"
	$yesOrNo = Read-Host
	If ($yesOrNo.ToUpper() -ne "NO" -And $yesOrNo.ToUpper() -ne "N") {
		$yesOrNo = "YES"
	}
}
Logging ""
Logging "  --> Chosen: $yesOrNo" "REMARK"
Logging ""
If ($yesOrNo.ToUpper() -ne "NO" -And $yesOrNo.ToUpper() -ne "N") {
	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "INFORMATION ABOUT THE SCRIPT, ITS FUNCTIONS AND BEHAVIOR, AND IMPACT TO THE ENVIRONMENT - PLEASE READ CAREFULLY..." "HEADER"
	Logging ""
	Logging "-----" "REMARK"
	Logging "This PoSH script provides the following functions:" "REMARK"
	Logging "-----" "REMARK"
	Logging " - Single Password Reset for the KrbTgt account in use by RWDCs in a specific AD domain, using either TEST or PROD KrbTgt accounts" "REMARK"
	Logging " - Single Password Reset for the KrbTgt account in use by an individual RODC in a specific AD domain, using either TEST or PROD KrbTgt accounts" "REMARK"
	Logging "     * A single RODC in a specific AD domain" "REMARK"
	Logging "     * A specific list of in a specific AD domain" "REMARK"
	Logging "     * All RODCs in a specific AD domain" "REMARK"
	Logging " - Resetting the password/keys of the KrbTgt Account can be done for multiple reasons such as for example:" "REMARK"
	Logging "     * From a security perspective as mentioned in:" "REMARK"
	Logging "       https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/" "REMARK"
	Logging "     * From an AD recovery perspective as mentioned in:" "REMARK"
	Logging "       https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password" "REMARK"
	Logging " - For all scenarios, an informational mode, which is mode 1 with no changes" "REMARK"
	Logging " - For all scenarios, a simulation mode, which is mode 2 where replication is tested through the replication of a temporary canary" "REMARK"
	Logging "     object that is created and deleted afterwards" "REMARK"
	Logging " - For all scenarios, a simulation mode, which is mode 3 where the password reset of the chosen TEST KrbTgt account is actually executed" "REMARK"
	Logging "     and replication of it is monitored through the environment for its duration" "REMARK"
	Logging " - For all scenarios, a real reset mode, which is mode 4 where the password reset of the chosen PROD KrbTgt account is actually executed" "REMARK"
	Logging "     and replication of it is monitored through the environment for its duration" "REMARK"
	Logging " - The creation of Test KrbTgt Accounts" "REMARK"
	Logging " - The cleanup of previously created Test KrbTgt Accounts" "REMARK"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging "-----" "REMARK"
	Logging "This PoSH script has the following behavior:" "REMARK"
	Logging "-----" "REMARK"
	Logging ""
	Logging " - Mode 1 is INFORMATIONAL MODE..." "REMARK-IMPORTANT"
	Logging "     * Safe to run at any time as there are not changes in any way!" "REMARK-IMPORTANT"
	Logging "     * Analyzes the environment and check for issues that may impact mode 2, 3 or 4!" "REMARK-IMPORTANT"
	Logging "     * For the targeted AD domain, it always retrieves all RWDCs, and all RODCs if applicable." "REMARK-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 2 is SIMULATION MODE USING A TEMPORARY CANARY OBJECT..." "REMARK-MORE-IMPORTANT"
	Logging "     * Also executes everything from mode 1!" "REMARK-MORE-IMPORTANT"
	Logging "     * Creates the temporary canary object and, depending on the scope, it will check if it exists in the AD database of the remote DC(s)" "REMARK-MORE-IMPORTANT"
	Logging "       (RWDC/RODC)." "REMARK-MORE-IMPORTANT"
	Logging "     * When simulating the KrbTgt account for RWDCs, the creation of the object is against the RWDC with the PDC Emulator FSMO followed" "REMARK-MORE-IMPORTANT"
	Logging "       by the 'replicate single object' operation against every available/reachable RWDC. This is a way to estimate the total replication" "REMARK-MORE-IMPORTANT"
	Logging "       time for mode 4." "REMARK-MORE-IMPORTANT"
	Logging "     * When simulating the KrbTgt account for RODCs, the creation of the object is against the RWDC the RODC is replicating from if" "REMARK-MORE-IMPORTANT"
	Logging "       available. If not available the creation is against the RWDC with the PDC Emulator FSMO. Either way it is followed by the 'replicate" "REMARK-MORE-IMPORTANT"
	Logging "       single object' operation against the RODC. This is a way to estimate the total replication time for mode 4." "REMARK-MORE-IMPORTANT"
	Logging "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" "REMARK-MORE-IMPORTANT"
	Logging "       the change made reached it or not." "REMARK-MORE-IMPORTANT"
	Logging "     * When performing the 'replicate single object' operation, it will always be for the full object, no matter if the remote DC is an RWDC" "REMARK-MORE-IMPORTANT"
	Logging "       or an RODC" "REMARK-MORE-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 3 is SIMULATION MODE USING TEST/BOGUS KRBTGT ACCOUNTS..." "REMARK-MORE-IMPORTANT"
	Logging "     * Also executes everything from mode 1!" "REMARK-MORE-IMPORTANT"
	Logging "     * Instead of using PROD/REAL KrbTgt Account(s), it uses pre-created TEST/BOGUS KrbTgt Accounts(s) for the password reset whatif!" "REMARK-MORE-IMPORTANT"
	Logging "       * For RWDCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_TEST' (All RWDCs) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
	Logging "       * For RODCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' (RODC Specific) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
	Logging "     * IT DOES NOT reset the password of the TEST/BOGUS KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" "REMARK-MORE-IMPORTANT"
	Logging "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" "REMARK-MORE-IMPORTANT"
	Logging "       RWDC." "REMARK-MORE-IMPORTANT"
	Logging "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" "REMARK-MORE-IMPORTANT"
	Logging "       the change made reached it or not." "REMARK-MORE-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 4 is REAL RESET MODE USING TEST/BOGUS KRBTGT ACCOUNTS..." "REMARK-MORE-IMPORTANT"
	Logging "     * Also executes everything from mode 1!" "REMARK-MORE-IMPORTANT"
	Logging "     * Instead of using PROD/REAL KrbTgt Account(s), it uses pre-created TEST/BOGUS KrbTgt Accounts(s) for the password reset!" "REMARK-MORE-IMPORTANT"
	Logging "       * For RWDCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_TEST' (All RWDCs) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
	Logging "       * For RODCs it uses the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' (RODC Specific) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
	Logging "     * Resets the password of the TEST/BOGUS KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" "REMARK-MORE-IMPORTANT"
	Logging "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" "REMARK-MORE-IMPORTANT"
	Logging "       RWDC." "REMARK-MORE-IMPORTANT"
	Logging "     * When simulating the KrbTgt account for RWDCs, the password reset is done for the TEST/BOGUS KrbTgt Accounts(s) against the RWDC with" "REMARK-MORE-IMPORTANT"
	Logging "       the PDC Emulator FSMO followed by the 'replicate single object' operation against every available/reachable RWDC. No RODCs are involved" "REMARK-MORE-IMPORTANT"
	Logging "       as those do not use the KrbTgt account in use by the RWDCs and also do not store/cache its password. This is a way to estimate the" "REMARK-MORE-IMPORTANT"
	Logging "       total replication time for mode 6." "REMARK-MORE-IMPORTANT"
	Logging "     * When simulating the KrbTgt account for RODCs, the password reset is done for the TEST/BOGUS KrbTgt Accounts(s) against the RWDC the" "REMARK-MORE-IMPORTANT"
	Logging "       RODC is replicating from if available/reachable. If not available the password reset is against the RWDC with the PDC Emulator FSMO." "REMARK-MORE-IMPORTANT"
	Logging "       Either way it is followed by the 'replicate single object' operation against the RODC that uses that KrbTgt account. Only the RODC" "REMARK-MORE-IMPORTANT"
	Logging "       that uses the specific KrbTgt account is checked against to see if the change has reached it, but only if the RODC is available/reachable." "REMARK-MORE-IMPORTANT"
	Logging "       This is a way to estimate the total replication time for mode 6." "REMARK-MORE-IMPORTANT"
	Logging "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" "REMARK-MORE-IMPORTANT"
	Logging "       the change made reached it or not." "REMARK-MORE-IMPORTANT"
	Logging "     * When performing the 'replicate single object' operation, it will always be for the full object if the target DC is an RWDC. If the" "REMARK-MORE-IMPORTANT"
	Logging "       target DC is an RODC, then it will be for the partial object (secrets only)." "REMARK-MORE-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 5 is SIMULATION MODE USING PROD/REAL KRBTGT ACCOUNTS..." "REMARK-MORE-IMPORTANT"
	Logging "     * Also executes everything from mode 1!" "REMARK-MORE-IMPORTANT"
	Logging "     * Now it does use the PROD/REAL KrbTgt Accounts(s) for the password reset whatif!" "REMARK-MORE-IMPORTANT"
	Logging "       * For RWDCs it uses the PROD/REAL KrbTgt account 'krbtgt' (All RWDCs) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
	Logging "       * For RODCs it uses the PROD/REAL KrbTgt account 'krbtgt_<Numeric Value>' (RODC Specific) (= Created when running mode 8)" "REMARK-MORE-IMPORTANT"
	Logging "     * IT DOES NOT reset the password of the PROD/REAL KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" "REMARK-MORE-IMPORTANT"
	Logging "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" "REMARK-MORE-IMPORTANT"
	Logging "       RWDC." "REMARK-MORE-IMPORTANT"
	Logging "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" "REMARK-MORE-IMPORTANT"
	Logging "       the change made reached it or not." "REMARK-MORE-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 6 is REAL RESET MODE USING PROD/REAL KRBTGT ACCOUNTS..." "REMARK-MOST-IMPORTANT"
	Logging "     * Also executes everything from mode 1!" "REMARK-MOST-IMPORTANT"
	Logging "     * Now it does use the PROD/REAL KrbTgt Accounts(s) for the password reset!" "REMARK-MOST-IMPORTANT"
	Logging "       * For RWDCs it uses the PROD/REAL KrbTgt account 'krbtgt' (All RWDCs)" "REMARK-MOST-IMPORTANT"
	Logging "       * For RODCs it uses the PROD/REAL KrbTgt account 'krbtgt_<Numeric Value>' (RODC Specific)" "REMARK-MOST-IMPORTANT"
	Logging "     * Resets the password of the PROD/REAL KrbTgt Accounts(s) and, depending on the scope, it will check if the Password Last Set value" "REMARK-MOST-IMPORTANT"
	Logging "       in the AD database of the remote DC(s) (RWDC/RODC) matches the Password Last Set value in the AD database of the source originating" "REMARK-MOST-IMPORTANT"
	Logging "       RWDC." "REMARK-MOST-IMPORTANT"
	Logging "     * When simulating the KrbTgt account for RWDCs, the password reset is done for the PROD/REAL KrbTgt Accounts(s) against the RWDC with" "REMARK-MOST-IMPORTANT"
	Logging "       the PDC Emulator FSMO followed by the 'replicate single object' operation against every available/reachable RWDC. No RODCs are involved" "REMARK-MOST-IMPORTANT"
	Logging "       as those do not use the KrbTgt account in use by the RWDCs and also do not store/cache its password. Once the replication is" "REMARK-MOST-IMPORTANT"
	Logging "       complete, the total impact time will be displayed." "REMARK-MOST-IMPORTANT"
	Logging "     * When simulating the KrbTgt account for RODCs, the password reset is done for the PROD/REAL KrbTgt Accounts(s) against the RWDC the" "REMARK-MOST-IMPORTANT"
	Logging "       RODC is replicating from if available/reachable. If not available the password reset is against the RWDC with the PDC Emulator FSMO." "REMARK-MOST-IMPORTANT"
	Logging "       Either way it is followed by the 'replicate single object' operation against the RODC that uses that KrbTgt account. Only the RODC" "REMARK-MOST-IMPORTANT"
	Logging "       that uses the specific KrbTgt account is checked against to see if the change has reached it, but only if the RODC is available/reachable." "REMARK-MOST-IMPORTANT"
	Logging "       Once the replication is complete, the total impact time will be displayed." "REMARK-MOST-IMPORTANT"
	Logging "     * If a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database to determine if" "REMARK-MOST-IMPORTANT"
	Logging "       the change made reached it or not." "REMARK-MOST-IMPORTANT"
	Logging "     * When performing the 'replicate single object' operation, it will always be for the full object if the target DC is an RWDC. If the" "REMARK-MOST-IMPORTANT"
	Logging "       target DC is an RODC, then it will be for the partial object (secrets only)." "REMARK-MOST-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 8 is CREATE TEST KRBTGT ACCOUNTS MODE..." "REMARK-IMPORTANT"
	Logging "     * Creates so called TEST/BOGUS KrbTgt Account(s) to simulate the password reset with." "REMARK-IMPORTANT"
	Logging "     * Has no impact on the PROD/REAL KrbTgt Account(s)." "REMARK-IMPORTANT"
	Logging "     * For RWDCs it creates (in disabled state!) the TEST/BOGUS KrbTgt account 'krbtgt_TEST' and adds it to the AD group 'Denied RODC" "REMARK-IMPORTANT"
	Logging "       Password Replication Group'." "REMARK-IMPORTANT"
	Logging "     * For RODCs, if any in the AD domain, it creates (in disabled state!) the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' and" "REMARK-IMPORTANT"
	Logging "       adds it to the AD group 'Allowed RODC Password Replication Group'. To determine the specific KrbTgt account in use by an RODC, the" "REMARK-IMPORTANT"
	Logging "       script reads the attribute 'msDS-KrbTgtLink' on the RODC computer account." "REMARK-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - Mode 9 is CLEANUP TEST KRBTGT ACCOUNTS MODE..." "REMARK-IMPORTANT"
	Logging "     * Cleanup (delete) the so called TEST/BOGUS KrbTgt Account(s) that were used to simulate the password reset with." "REMARK-IMPORTANT"
	Logging "     * For RWDCs it deletes the TEST/BOGUS KrbTgt account 'krbtgt_TEST' if it exists." "REMARK-IMPORTANT"
	Logging "     * For RODCs, if any in the AD domain, it deletes the TEST/BOGUS KrbTgt account 'krbtgt_<Numeric Value>_TEST' if it exists. To determine" "REMARK-IMPORTANT"
	Logging "       the specific KrbTgt account in use by an RODC, the script reads the attribute 'msDS-KrbTgtLink' on the RODC computer account." "REMARK-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - ADDITIONAL INFO - BEHAVIOR..." "REMARK-IMPORTANT"
	Logging "     * If the operating system attribute of an RODC computer account does not have a value, it is determined to be unknown (not a real RODC)," "REMARK-IMPORTANT"
	Logging "       and therefore something else. It could for example be a Riverbed appliance in 'RODC mode'." "REMARK-IMPORTANT"
	Logging "     * The only DC that knows what the real replication partner is of an RODC, is the RODC itself. Only the RODC manages a connection object" "REMARK-IMPORTANT"
	Logging "       (CO) that only exists in the AD database of the RODC and does not replicate out to other DCs as RODCs do not support outbound replication." "REMARK-IMPORTANT"
	Logging "       Therefore, assuming the RODC is available, the CO is looked up in the RODC AD database and from that CO, the 'source' server is" "REMARK-IMPORTANT"
	Logging "       determined. In case the RODC is not available or its 'source' server is not available, the RWDC with the PDC FSMO is used to reset" "REMARK-IMPORTANT"
	Logging "       the password of the krbtgt account in use by that RODC. If the RODC is available a check will be done against its database, and if" "REMARK-IMPORTANT"
	Logging "       not available the check is skipped." "REMARK-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging " - ADDITIONAL INFO - OBSERVED IMPACT..." "REMARK-IMPORTANT"
	Logging "     * Within an AD domain, all RWDCs use the account 'krbtgt' to encrypt/sign Kerberos tickets trusted by all RWDCs" "REMARK-IMPORTANT"
	Logging "     * Within an AD domain, every RODC uses its own 'krbtgt_<Numeric Value>' account to encrypt/sign Kerberos tickets trusted by only that RODC" "REMARK-IMPORTANT"
	Logging "       and that account is specified in the attribute 'msDS-KrbTgtLink' on the RODC computer account." "REMARK-IMPORTANT"
	Logging "     * RODCs are cryptographically isolated from other RODCs and the RWDCs, whether these are in the same AD site or not. Any Kerberos TGT/Service" "REMARK-IMPORTANT"
	Logging "       tickets issued by an RODC are only valid against that RODC and any resource that has a secure channel with that RODC. That's why when an" "REMARK-IMPORTANT"
	Logging "       RODC is compromised the scope of impact is only for that RODC and any resource using it, and not the complete AD domain." "REMARK-IMPORTANT"
	Logging "     * Kerberos PAC validation failures: Until the new KrbTgt account password is replicated to all DCs in the domain using that KrbTgt account," "REMARK-IMPORTANT"
	Logging "       applications which attempt KDC PAC validation may experience KDC PAC validation failures. This is possible  when a client in one AD site" "REMARK-IMPORTANT"
	Logging "       is accessing an application leveraging the Kerberos Authentication protocol that is in a different AD site. If that application is not a" "REMARK-IMPORTANT"
	Logging "       trusted part of the operating system, it may attempt to validate the PAC of the client's Kerberos Service Ticket against the KDC (DC) in" "REMARK-IMPORTANT"
	Logging "       its AD site. If the DC in its site does not yet have the new KrbTgt account password, this KDC PAC validation will fail. This will likely" "REMARK-IMPORTANT"
	Logging "       manifest itself to the client as authentication errors for that application. Once all DCs using a specific KrbTgt account have the new" "REMARK-IMPORTANT"
	Logging "       password some affected clients may recover gracefully and resume functioning normally. If not, rebooting the affected client(s) will" "REMARK-IMPORTANT"
	Logging "       resolve the issue. This issue may not occur if the replication of the new KrbTgt account password is timely and successful and no" "REMARK-IMPORTANT"
	Logging "       applications attempt KDC PAC validation against an out of sync DC during that time." "REMARK-IMPORTANT"
	Logging "     * Kerberos TGS request failures: Until the new KrbTgt account password is replicated to all DCs in the domain that use that KrbTgt account," "REMARK-IMPORTANT"
	Logging "       a client may experience Kerberos authentication failures. This is when a client in one AD site has obtained a Kerberos Ticket Granting" "REMARK-IMPORTANT"
	Logging "       Ticket (TGT) from an RWDC that has the new KrbTgt account password, but then subsequently attempts to obtain a Kerberos Service Ticket" "REMARK-IMPORTANT"
	Logging "       via a TGS request against an RWDC in a different AD site. If that RWDC does not also have the new KrbTgt account password, it will not" "REMARK-IMPORTANT"
	Logging "       be able to decrypt the client''s TGT, which will result in a TGS request failure.  This will manifest itself to the client as authenticate" "REMARK-IMPORTANT"
	Logging "       errors. However, it should be noted that this impact is very unlikely, because it is very unlikely that a client will attempt to obtain a" "REMARK-IMPORTANT"
	Logging "       service ticket from a different RWDC than the one from which their TGT was obtained, especially during the relatively short impact" "REMARK-IMPORTANT"
	Logging "       duration of Mode 4." "REMARK-IMPORTANT"
	Logging "     * Resetting the password of account 'krbtgt' 2x very quickly in sequence will NEGATIVELY impact both DCs and server/apps/users." "REMARK-IMPORTANT"
	Logging "     * Resetting the password of account 'krbtgt' 1x, allowing AD replication to occur end-to-end, and resetting it a second time WITHIN the max" "REMARK-IMPORTANT"
	Logging "       ticket lifetime will NEGATIVELY impact server/apps/users only." "REMARK-IMPORTANT"
	Logging "     * Resetting the password of account 'krbtgt' 1x, allowing AD replication to occur end-to-end, and resetting it a second time AFTER the max" "REMARK-IMPORTANT"
	Logging "       ticket lifetime will not impact DCs nor server/apps/users only." "REMARK-IMPORTANT"
	Logging "     * Resetting the password of account 'krbtgt' 2x very quickly in sequence should only be done during forest/domain recovery (isolation) and/or" "REMARK-IMPORTANT"
	Logging "       a ransomware attack (taking back control)." "REMARK-IMPORTANT"
	Logging ""
	Logging ""
	Logging "First, read the info above, then..." "ACTION"
	Logging "Press Any Key (TWICE!) To Continue..." "ACTION"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
	Logging ""
	Logging ""
	Logging "    !!! It is highly recommended to use the following order of execution: !!!" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 1 - Informational Mode (No Changes At All)" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 8 - Create TEST KrbTgt Accounts" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 2 - Simulation Mode (Temporary Canary Object Created, No Password Reset!)" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 3 - Simulation Mode - Use KrbTgt TEST/BOGUS Accounts (No Password Reset, Check Only!)" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 4 - Real Reset Mode - Use KrbTgt TEST/BOGUS Accounts (Password Will Be Reset Once!)" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 5 - Simulation Mode - Use KrbTgt PROD/REAL Accounts (No Password Reset, Check Only!)" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 6 - Real Reset Mode - Use KrbTgt PROD/REAL Accounts (Password Will Be Reset Once!)" "REMARK-MORE-IMPORTANT"
	Logging "     - Mode 9 - Cleanup TEST KrbTgt Accounts (Could be skipped to reuse accounts the next time!)" "REMARK-MORE-IMPORTANT"
	Logging ""
	Logging ""
	Logging " - RECOMMENDATIONS:" "REMARK-MORE-IMPORTANT"
	Logging "     * Reset password of ALL krbtgt accounts periodically every 3 or 6 months. Whatever is comfortable for you." "REMARK-MORE-IMPORTANT"
	Logging "     * Want to reset more frequently? Please pay attention to the max kerberos ticket lifetime configured for the AD domain!" "REMARK-MORE-IMPORTANT"
	Logging "     * Normally 6 months is a good balance between security and management overhead!" "REMARK-MORE-IMPORTANT"
	Logging ""
	Logging ""
}

###
# Loading Required PowerShell Modules
###
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "LOADING REQUIRED POWERSHELL MODULES..." "HEADER"
Logging ""

# Try To Load The Required PowerShell Module. Abort Script If Not Available
#"S.DS.P", "ActiveDirectory", "GroupPolicy" | ForEach-Object {
#"ActiveDirectory", "GroupPolicy" | ForEach-Object {
"GroupPolicy" | ForEach-Object {
	$poshModuleState = $null
	$poshModuleState = loadPoSHModules $_
	If ($poshModuleState -eq "NotAvailable") {
		Logging ""

		EXIT
	}
	Logging ""
}

###
# Display And Selecting The Mode Of Operation
###
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "SELECT THE MODE OF OPERATION..." "HEADER"
Logging ""
Logging "Which mode of operation do you want to execute?"
Logging ""
Logging " - 1 - Informational Mode (No Changes At All)"
Logging ""
Logging " - 2 - Simulation Mode | Temporary Canary Object Created To Test Replication Convergence!"
Logging ""
Logging " - 3 - Simulation Mode | Use KrbTgt TEST/BOGUS Accounts - No Password Reset/WhatIf Mode!"
Logging ""
Logging " - 4 - Real Reset Mode | Use KrbTgt TEST/BOGUS Accounts - Password Will Be Reset Once!"
Logging ""
Logging " - 5 - Simulation Mode | Use KrbTgt PROD/REAL Accounts - No Password Reset/WhatIf Mode!"
Logging ""
Logging " - 6 - Real Reset Mode | Use KrbTgt PROD/REAL Accounts - Password Will Be Reset Once!"
Logging ""
Logging ""
Logging " - 8 - Create TEST KrbTgt Accounts"
Logging " - 9 - Cleanup TEST KrbTgt Accounts"
Logging ""
Logging ""
Logging " - 0 - Exit Script"
Logging ""
Switch ($modeOfOperation) {
	"infoMode" {$modeOfOperationNr = 1}
	"simulModeCanaryObject" {$modeOfOperationNr = 2}
	"simulModeKrbTgtTestAccountsWhatIf" {$modeOfOperationNr = 3}
	"resetModeKrbTgtTestAccountsResetOnce"	{ $modeOfOperationNr = 4}
	"simulModeKrbTgtProdAccountsWhatIf" {$modeOfOperationNr = 5}
	"resetModeKrbTgtProdAccountsResetOnce" {$modeOfOperationNr = 6}
	Default {$modeOfOperationNr = $null}
}
If ($null -eq $modeOfOperationNr) {
	Logging "Please specify the mode of operation: " "ACTION-NO-NEW-LINE"
	$modeOfOperationNr = Read-Host
} Else {
	Logging "Please specify the mode of operation: $modeOfOperationNr" "ACTION"
}
Logging ""

# If Anything Else Than The Allowed/Available Non-Zero Modes, Abort The Script
If (($modeOfOperationNr -ne 1 -And $modeOfOperationNr -ne 2 -And $modeOfOperationNr -ne 3 -And $modeOfOperationNr -ne 4 -And $modeOfOperationNr -ne 5 -And $modeOfOperationNr -ne 6 -And $modeOfOperationNr -ne 8 -And $modeOfOperationNr -ne 9) -Or $modeOfOperationNr -notmatch "^[\d\.]+$") {
	Logging "  --> Chosen mode: Mode 0 - Exit Script..." "REMARK"
	Logging ""

	EXIT
}

# If Mode 1
If ($modeOfOperationNr -eq 1) {
	Logging "  --> Chosen Mode: Mode 1 - Informational Mode (No Changes At All)..." "REMARK"
	Logging ""
}

# If Mode 2
If ($modeOfOperationNr -eq 2) {
	Logging "  --> Chosen Mode: Mode 2 - Simulation Mode | Temporary Canary Object Created To Test Replication Convergence..." "REMARK"
	Logging ""
}

# If Mode 3
If ($modeOfOperationNr -eq 3) {
	Logging "  --> Chosen Mode: Mode 3 - Simulation Mode | Use KrbTgt TEST/BOGUS Accounts - No Password Reset/WhatIf Mode!..." "REMARK"
	Logging ""
}

# If Mode 4
If ($modeOfOperationNr -eq 4) {
	Logging "  --> Chosen Mode: Mode 4 - Real Reset Mode | Use KrbTgt TEST/BOGUS Accounts - Password Will Be Reset Once!..." "REMARK"
	Logging ""
}

# If Mode 5
If ($modeOfOperationNr -eq 5) {
	Logging "  --> Chosen Mode: Mode 5 - Simulation Mode | Use KrbTgt PROD/REAL Accounts - No Password Reset/WhatIf Mode!..." "REMARK"
	Logging ""
}

# If Mode 6
If ($modeOfOperationNr -eq 6) {
	Logging "  --> Chosen Mode: Mode 6 - Real Reset Mode | Use KrbTgt PROD/REAL Accounts - Password Will Be Reset Once!..." "REMARK"
	Logging ""
}

# If Mode 8
If ($modeOfOperationNr -eq 8) {
	Logging "  --> Chosen Mode: Mode 8 - Create TEST KrbTgt Accounts..." "REMARK"
	Logging ""
}

# If Mode 9
If ($modeOfOperationNr -eq 9) {
	Logging "  --> Chosen Mode: Mode 9 - Cleanup TEST KrbTgt Accounts..." "REMARK"
	Logging ""
}

###
# All Modes - Selecting The Target AD Forest
###
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "SPECIFY THE TARGET AD FOREST..." "HEADER"
Logging ""

# Retrieve The AD Domain And AD Forest Of The Computer Where The Script Is Executed
#$currentADDomainOfLocalComputer = $(Get-WmiObject -Class Win32_ComputerSystem).Domain
#$currentADForestOfLocalComputer = (Get-ADDomain $currentADDomainOfLocalComputer).Forest
#$currentADDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $fqdnADDomainOfComputer)
#$currentADForestOfLocalComputer = ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($currentADDomainContext)).Forest.Name

# Ask Which AD Forest To Target
If ($targetedADforestFQDN -eq "") {
	Logging "For the AD forest to be targeted, please provide the FQDN or press [ENTER] for the current AD forest: " "ACTION-NO-NEW-LINE"
	$targetedADforestFQDN = Read-Host
} Else {
	Logging "For the AD forest to be targeted, please provide the FQDN or press [ENTER] for the current AD forest: $targetedADforestFQDN" "ACTION"
}

# If No FQDN Of An AD Domain Is Specified, Then Use The AD Domain Of The Local Computer
If ($targetedADforestFQDN -eq "" -Or $null -eq $targetedADforestFQDN) {
	$targetedADforestFQDN = $fqdnADForestOfComputer
}
Logging ""
Logging "  --> Selected AD Forest: '$targetedADforestFQDN'..." "REMARK"

# Validate The Specified AD Forest And Check A (Forest) Trust Is In Place, If Applicable
$adForestValidity = $false

# Test To See If The Forest FQDN Exists At All
If ($targetedADforestFQDN -eq $fqdnADForestOfComputer) {
	$localADforest = $true
	$adForestLocation = "Local"
} Else {
	$localADforest = $false
	$adForestLocation = "Remote"
}

Try {
	# Checking Through DNS Resolution
	Logging ""
	Logging "Checking Resolvability of the specified $adForestLocation AD forest '$targetedADforestFQDN' through DNS..."
	[System.Net.Dns]::GetHostEntry($targetedADforestFQDN) | Out-Null
	$adForestValidity = $true
} Catch {
	Try {
		# Checking Through RootDse Connection
		Logging ""
		Logging "Checking Reachability of the specified $adForestLocation AD forest '$targetedADforestFQDN' through RootDse..."
		#Get-ADRootDSE -Server $targetedADforestFQDN -ErrorAction Stop | Out-Null
		Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADforestFQDN -EncryptionType Kerberos) -ErrorAction Stop | Out-Null
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
	Logging "" "SUCCESS"
	Logging "The specified $adForestLocation AD forest '$targetedADforestFQDN' is either resolvable through DNS or reachable through RootDse!" "SUCCESS"
	Logging "" "SUCCESS"
	Logging "Continuing Script..." "SUCCESS"
	Logging "" "SUCCESS"
} Else {
	# If The AD Forest Is Not Resolvable And Not Reachable And Therefore Does Not Exists, Abort
	Logging "" "ERROR"
	Logging "The specified $adForestLocation AD forest '$targetedADforestFQDN' IS NOT resolvable through DNS and IS NOT reachable through RootDse!" "ERROR"
	Logging "" "ERROR"
	Logging "Please re-run the script and provide the FQDN of an AD forest that exists..." "ERROR"
	Logging "" "ERROR"
	Logging "Aborting Script..." "ERROR"
	Logging "" "ERROR"

	# Mail The Log File With The Results
	If ($argsCount -gt 0 -And $sendMailWithLogFile) {
		Logging "" "ERROR"
		Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "ERROR"
		Logging "  - TO: '$mailToRecipient'..." "ERROR"
		If ($mailCcRecipients.Length -gt 0) {
			$mailCcRecipients | ForEach-Object {
				Logging "  - CC: '$($_)'..." "ERROR"
			}
		}
		Logging "" "ERROR"

		$mailAttachments = @()
		$mailAttachments += $logFilePath
		sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
	}

	EXIT
}

# Validate The Specified AD Forest Is Accessible. If it is the local AD forest then it is accessible. If it is a remote AD forest and a (forest) trust is in place, then it is accessible. If it is a remote AD forest and a (forest) trust is NOT in place, then it is NOT accessible.
$adForestAccessibility = $false
# Test To See If The AD Forest Is Accessible
Try {
	# Retrieve The Nearest RWDC In The Forest Root AD Domain
	#$nearestRWDCInForestRootADDomain = (Get-ADDomainController -DomainName $targetedADforestFQDN -Discover -ErrorAction Stop).HostName[0]
	#$dcLocatorFlag = [System.DirectoryServices.ActiveDirectory.LocatorOptions]::"ForceRediscovery","WriteableRequired"
	#$adDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $targetedADforestFQDN)
	#$thisADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($adDomainContext)
	#$nearestRWDCInForestRootADDomain = $thisADDomain.FindDomainController($dcLocatorFlag)

	# Retrieve Information About The AD Forest
	#$thisADForest = Get-ADForest -Identity $targetedADforestFQDN -Server $nearestRWDCInForestRootADDomain -ErrorAction Stop
	$adForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", $targetedADforestFQDN)
	$thisADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($adForestContext)

	$adForestAccessibility = $true
} Catch {
	$adForestAccessibility = $false
}
Logging ""
Logging "Checking Accessibility of the specified AD forest '$targetedADforestFQDN' By Trying To Retrieve AD Forest Data..."
If ($adForestAccessibility -eq $true) {
	# If The AD Forest Is Accessible, Continue
	Logging "" "SUCCESS"
	Logging "The specified AD forest '$targetedADforestFQDN' is accessible!" "SUCCESS"
	Logging "" "SUCCESS"
	Logging "Continuing Script..." "SUCCESS"
	Logging "" "SUCCESS"
} Else {
	If ($argsCount -eq 0) {
		# If The AD Forest Is NOT Accessible, Ask For Credentials
		Logging "" "WARNING"
		Logging "The specified AD forest '$targetedADforestFQDN' IS NOT accessible!" "WARNING"
		Logging "" "WARNING"
		Logging "Custom credentials are needed..." "WARNING"
		Logging "" "WARNING"
		Logging "Continuing Script And Asking For Credentials..." "WARNING"
		Logging "" "WARNING"
		Logging ""

		# Ask For The Remote Credentials
		$adminCrds = requestForAdminCreds

		# Test To See If The AD Forest Is Accessible
		Try {
			# Retrieve The Nearest RWDC In The Forest Root AD Domain: ADDED CREDS To Get A DC. It Was Not Here Before! Why?
			#$nearestRWDCInForestRootADDomain = (Get-ADDomainController -DomainName $targetedADforestFQDN -Discover -Credential $adminCrds -ErrorAction Stop).HostName[0]
			#$dcLocatorFlag = [System.DirectoryServices.ActiveDirectory.LocatorOptions]::"ForceRediscovery","WriteableRequired"
			#$adDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $targetedADforestFQDN, $($adminCrds.UserName), $($adminCrds.GetNetworkCredential().Password))
			#$thisADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($adDomainContext)
			#$nearestRWDCInForestRootADDomain = $thisADDomain.FindDomainController($dcLocatorFlag)

			# Retrieve Information About The AD Forest
			#$thisADForest = Get-ADForest -Identity $targetedADforestFQDN -Server $nearestRWDCInForestRootADDomain -Credential $adminCrds -ErrorAction Stop
			$adForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", $targetedADforestFQDN, $($adminCrds.UserName), $($adminCrds.GetNetworkCredential().Password))
			$thisADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($adForestContext)

			$adForestAccessibility = $true
		} Catch {
			$adForestAccessibility = $false
		}
		Logging ""
		Logging "Checking Accessibility of the specified AD forest '$targetedADforestFQDN' By Trying To Retrieve AD Forest Data..."
		If ($adForestAccessibility -eq $true) {
			# If The AD Forest Is Accessible, Continue
			Logging "" "SUCCESS"
			Logging "The specified AD forest '$targetedADforestFQDN' is accessible!" "SUCCESS"
			Logging "" "SUCCESS"
			Logging "Continuing Script..." "SUCCESS"
			Logging "" "SUCCESS"
		} Else {
			# If The AD Forest Is NOT Accessible, Ask For Credentials
			Logging "" "ERROR"
			Logging "The specified AD forest '$targetedADforestFQDN' IS NOT accessible!" "ERROR"
			Logging "" "ERROR"
			Logging "Please re-run the script and provide the correct credentials to connect to the remote AD forest..." "ERROR"
			Logging "" "ERROR"
			Logging "Aborting Script..." "ERROR"
			Logging "" "ERROR"

			# Mail The Log File With The Results
			If ($argsCount -gt 0 -And $sendMailWithLogFile) {
				Logging "" "ERROR"
				Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "ERROR"
				Logging "  - TO: '$mailToRecipient'..." "ERROR"
				If ($mailCcRecipients.Length -gt 0) {
					$mailCcRecipients | ForEach-Object {
						Logging "  - CC: '$($_)'..." "ERROR"
					}
				}
				Logging "" "ERROR"

				$mailAttachments = @()
				$mailAttachments += $logFilePath
				sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
			}

			EXIT
		}
	} Else {
		Logging "" "WARNING"
		Logging "The specified AD forest '$targetedADforestFQDN' IS NOT accessible!" "WARNING"
		Logging "" "WARNING"
		Logging "Custom credentials are needed..." "WARNING"
		Logging "" "WARNING"
		Logging "Script is running in automated mode and because of that it cannot ask fo customer credentials..." "WARNING"
		Logging "" "WARNING"
		Logging "Please re-run the script and run the script with the correct credentials to connect to the remote AD forest..." "WARNING"
		Logging "" "WARNING"

		# Mail The Log File With The Results
		If ($argsCount -gt 0 -And $sendMailWithLogFile) {
			Logging "" "ERROR"
			Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "ERROR"
			Logging "  - TO: '$mailToRecipient'..." "ERROR"
			If ($mailCcRecipients.Length -gt 0) {
				$mailCcRecipients | ForEach-Object {
					Logging "  - CC: '$($_)'..." "ERROR"
				}
			}
			Logging "" "ERROR"

			$mailAttachments = @()
			$mailAttachments += $logFilePath
			sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
		}

		EXIT
	}
}

###
# All Modes - Selecting The Target AD Domain
###
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "SELECT THE TARGET AD DOMAIN..." "HEADER"
Logging ""

# Retrieve Root AD Domain Of The AD Forest
#$rootADDomainInADForest = $thisADForest.RootDomain
$rootADDomainInADForest = $thisADForest.RootDomain.Name

# Retrieve All The AD Domains In The AD Forest And Sort These In Some Way
$arrayOfADDomainFQDNsInADForest = $thisADForest.Domains.Name
$sortedListOfADDomainFQDNsInADForest = @()
($arrayOfADDomainFQDNsInADForest | ?{$_ -like "*$rootDomain"} | %{([regex]::Matches($_, '.', 'RightToLeft') | %{$_.value}) -join ''}) | Sort-Object | %{$sortedListOfADDomainFQDNsInADForest += $(([regex]::Matches($_, '.', 'RightToLeft') | %{$_.value}) -join '')}
(@($arrayOfADDomainFQDNsInADForest | ?{$_ -notin $sortedListOfADDomainFQDNsInADForest}) | %{([regex]::Matches($_, '.', 'RightToLeft') | %{$_.value}) -join ''}) | Sort-Object | %{$sortedListOfADDomainFQDNsInADForest += $(([regex]::Matches($_, '.', 'RightToLeft') | %{$_.value}) -join '')}

# Retrieve The DN Of The Partitions Container In The AD Forest
#$partitionsContainerDN = $thisADForest.PartitionsContainer
$partitionsContainerDN = $($thisADForest.Schema.Name).Replace("CN=Schema", "CN=Partitions")

# Retrieve The Mode/Functional Level Of The AD Forest + Fix For Buf In S.DS.P.
$targetedADforestForestFunctionalMode = $thisADForest.ForestMode
$targetedADforestForestFunctionalModeLevel = $thisADForest.ForestModeLevel
If ([int]$targetedADforestForestFunctionalModeLevel -eq 7 -And $targetedADforestForestFunctionalMode -eq "Unknown") {
	$targetedADforestForestFunctionalMode = "Windows2016Forest"
}

# Define An Empty List/Table That Will Contain All AD Domains In The AD Forest And Related Information
$tableOfADDomainsInADForest = @()
Logging "Forest Mode/Level...: $targetedADforestForestFunctionalMode"

# Set The Counter To Zero
$nrOfDomainsInForest = 0

# Execute For All AD Domains In The AD Forest
$sortedListOfADDomainFQDNsInADForest | ForEach-Object {
	# Increase The Counter
	$nrOfDomainsInForest += 1

	# Get The FQDN Of The AD Domain
	$domainFQDN = $_

	<#
	# Retrieve The Nearest RWDC In The AD Domain
	$nearestRWDCInADDomain = $null
	$nearestRWDCInADDomain = (Get-ADDomainController -DomainName $domainFQDN -Discover).HostName[0]

	# Retrieve The Object Of The AD Domain From AD
	$domainObj = $null
	Try {
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			$domainObj = Get-ADDomain $domainFQDN -Server $nearestRWDCInADDomain
		}
		If ($localADforest -eq $false -And $adminCrds) {
			$domainObj = Get-ADDomain $domainFQDN -Server $nearestRWDCInADDomain -Credential $adminCrds
		}
	} Catch {
		$domainObj = $null
	}
	#>

	# Retrieve The Object Of The AD Domain From AD And The Nearest RWDC
	$domainObj = $null
	$nearestRWDCInADDomain = $null
	Try {
		$dcLocatorFlag = [System.DirectoryServices.ActiveDirectory.LocatorOptions]::"ForceRediscovery", "WriteableRequired"
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			$adDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $domainFQDN)
		}
		If ($localADforest -eq $false -And $adminCrds) {
			$adDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $domainFQDN, $($adminCrds.UserName), $($adminCrds.GetNetworkCredential().Password))
		}
		$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($adDomainContext)
		$nearestRWDCInADDomain = $domainObj.FindDomainController($dcLocatorFlag).Name
	} Catch {
		$domainObj = $null
	}

	# Populate The Table With Data From The Processed AD Domain + Bug Fix For DomainMode(Level) In S.DS.P. When FFL/DFL Is 2016
	$tableOfADDomainsInADForestObj = New-Object -TypeName System.Object
	$tableOfADDomainsInADForestObj | Add-Member -MemberType NoteProperty -Name "ListNr" -Value $nrOfDomainsInForest
	$tableOfADDomainsInADForestObj | Add-Member -MemberType NoteProperty -Name "Name" -Value $domainFQDN
	$tableOfADDomainsInADForestObj | Add-Member -MemberType NoteProperty -Name "NetBIOS" -Value $(If ($domainObj) {$domainObj.GetDirectoryEntry().Properties["Name"].Value} Else {"AD Domain Is Not Available"})
	$tableOfADDomainsInADForestObj | Add-Member -MemberType NoteProperty -Name "DomainSID" -Value $(If ($domainObj) {$objectSidBytes = $domainObj.GetDirectoryEntry().Properties["objectSid"].Value; (New-Object System.Security.Principal.SecurityIdentifier($objectSidBytes, 0)).Value} Else {"AD Domain Is Not Available"})
	$tableOfADDomainsInADForestObj | Add-Member -MemberType NoteProperty -Name "IsRootDomain" -Value $(If ($rootADDomainInADForest -eq $domainFQDN) {$true} Else {$false})
	$tableOfADDomainsInADForestObj | Add-Member -MemberType NoteProperty -Name "DomainMode" -Value $(If ($domainObj) {If ([int]$($domainObj.DomainModeLevel) -eq 7 -And $($domainObj.DomainMode) -eq "Unknown") {"Windows2016Domain"} Else {$($domainObj.DomainMode)}} Else {"AD Domain Is Not Available"})
	$tableOfADDomainsInADForestObj | Add-Member -MemberType NoteProperty -Name "IsCurrentDomain" -Value $(If ($fqdnADDomainOfComputer -eq $domainFQDN) {$true} Else {$false})
	$tableOfADDomainsInADForestObj | Add-Member -MemberType NoteProperty -Name "IsAvailable" -Value $(If ($domainObj) {$true} Else {$false})
	$tableOfADDomainsInADForestObj | Add-Member -MemberType NoteProperty -Name "PDCFsmoOwner" -Value $(If ($domainObj) {$domainObj.PdcRoleOwner.Name} Else {"AD Domain Is Not Available"})
	$tableOfADDomainsInADForestObj | Add-Member -MemberType NoteProperty -Name "NearestRWDC" -Value $(If ($domainObj) {$nearestRWDCInADDomain} Else {"AD Domain Is Not Available"})
	$tableOfADDomainsInADForest += $tableOfADDomainsInADForestObj
}

# Display The List And Amount Of AD Domains
Logging ""
Logging "List Of AD Domains In AD Forest '$rootADDomainInADForest'..."
Logging ""
Logging "$($tableOfADDomainsInADForest | Format-Table | Out-String)"
Logging "  --> Found [$nrOfDomainsInForest] AD Domain(s) in the AD forest '$rootADDomainInADForest'..." "REMARK"
Logging ""

# Ask Which AD Domain To Target From The Previously Presented List
If ($targetedADdomainFQDN -eq "") {
	Logging "For the AD domain to be targeted, please provide the list nr or the FQDN or press [ENTER] for the current AD domain: " "ACTION-NO-NEW-LINE"
	$targetedADdomainFQDN = Read-Host
} Else {
	Logging "For the AD domain to be targeted, please provide the list nr or the FQDN or press [ENTER] for the current AD domain: $targetedADdomainFQDN" "ACTION"
}

# If A Numeric Value Was Entered Instead, Then Resolve That To An Actual FQDN
If ($targetedADdomainFQDN -match "^\d$" -And [int]$targetedADdomainFQDN -le $tableOfADDomainsInADForest.Count) {
	$targetedADdomainFQDN = ($tableOfADDomainsInADForest | Where-Object{$_.ListNr -eq $targetedADdomainFQDN}).Name
}

# If No FQDN Of An AD Domain Is Specified, Then Use The AD Domain Of The Local Computer
If ($targetedADdomainFQDN -eq "" -Or $null -eq $targetedADdomainFQDN) {
	$targetedADdomainFQDN = $fqdnADDomainOfComputer
}
Logging ""
Logging "  --> Selected AD Domain: '$targetedADdomainFQDN'..." "REMARK"

# Validate The Chosen AD Domain Against The List Of Available AD Domains To See If It Does Exist In The AD Forest
$adDomainValidity = $false
$sortedListOfADDomainFQDNsInADForest | ForEach-Object {
	$domainFQDN = $null
	$domainFQDN = $_
	If ($targetedADdomainFQDN -eq $domainFQDN) {
		$adDomainValidity = $true
	}
}
Logging ""
Logging "Checking existence of the specified AD domain '$targetedADdomainFQDN' in the AD forest '$rootADDomainInADForest'..."
If ($adDomainValidity -eq $true) {
	# If The AD Domain Is Valid And Therefore Exists, Continue
	Logging "" "SUCCESS"
	Logging "The specified AD domain '$targetedADdomainFQDN' exists in the AD forest '$rootADDomainInADForest'!" "SUCCESS"
	Logging "" "SUCCESS"
	Logging "Continuing Script..." "SUCCESS"
	Logging "" "SUCCESS"
} Else {
	# If The AD Domain Is Not Valid And Therefore Does Not Exist, Abort
	Logging "" "ERROR"
	Logging "The specified AD domain '$targetedADdomainFQDN' DOES NOT exist in the AD forest '$rootADDomainInADForest'!" "ERROR"
	Logging "" "ERROR"
	Logging "Please re-run the script and provide the FQDN of an AD domain that does exist in the AD forest '$rootADDomainInADForest'..." "ERROR"
	Logging "" "ERROR"
	Logging "Aborting Script..." "ERROR"
	Logging "" "ERROR"

	# Mail The Log File With The Results
	If ($argsCount -gt 0 -And $sendMailWithLogFile) {
		Logging "" "ERROR"
		Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "ERROR"
		Logging "  - TO: '$mailToRecipient'..." "ERROR"
		If ($mailCcRecipients.Length -gt 0) {
			$mailCcRecipients | ForEach-Object {
				Logging "  - CC: '$($_)'..." "ERROR"
			}
		}
		Logging "" "ERROR"

		$mailAttachments = @()
		$mailAttachments += $logFilePath
		sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
	}

	EXIT
}

###
# All Modes - Testing If Required Permissions Are Available (Domain/Enterprise Admin Credentials)
###
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "TESTING IF REQUIRED PERMISSIONS ARE AVAILABLE (DOMAIN/ENTERPRISE ADMINS OR ADMINISTRATORS CREDENTIALS)..." "HEADER"
Logging ""

# Target AD Domain Data
$targetedADdomainData = $tableOfADDomainsInADForest | Where-Object{$_.Name -eq $targetedADdomainFQDN}

# Retrieve The HostName Of Nearest RWDC In The AD Domain
$targetedADdomainNearestRWDCFQDN = $targetedADdomainData.NearestRWDC

# Retrieve The ObjectSIDOf The Targeted AD Domain
$targetedDomainObjectSID = $targetedADdomainData.DomainSID

# If The AD Forest Is Local, Then We Can Test For Role Membership Of Either Domain Admins Or Enterprise Admins.
If ($localADforest -eq $true) {
	# Validate The User Account Running This Script Is A Member Of The Domain Admins Group Of The Targeted AD Domain
	$domainAdminRID = "512"
	$domainAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($targetedDomainObjectSID + "-" + $domainAdminRID)).Translate([System.Security.Principal.NTAccount]).Value
	$userIsDomainAdmin = testAdminRole $domainAdminRole
	If (!$userIsDomainAdmin) {
		# The User Account Running This Script Has Been Validated Not Being A Member Of The Domain Admins Group Of The Targeted AD Domain
		# Validate The User Account Running This Script Is A Member Of The Enterprise Admins Group Of The AD Forest
		$forestRootDomainObjectSID = ($tableOfADDomainsInADForest | Where-Object{$_.IsRootDomain -eq $true}).DomainSID
		$enterpriseAdminRID = "519"
		$enterpriseAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($forestRootDomainObjectSID + "-" + $enterpriseAdminRID)).Translate([System.Security.Principal.NTAccount]).Value
		$userIsEnterpriseAdmin = testAdminRole $enterpriseAdminRole
		If (!$userIsEnterpriseAdmin) {
			# The User Account Running This Script Has Been Validated Not Being A Member Of The Enterprise Admins Group Of The AD Forest
			Logging "The user account '$adRunningUserAccount' IS NOT running with Domain/Enterprise Administrator equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "ERROR"
			Logging "The user account '$adRunningUserAccount' IS NOT a member of '$domainAdminRole' and NOT a member of '$enterpriseAdminRole'!..." "ERROR"
			Logging "" "ERROR"
			Logging "For this script to run successfully, Domain/Enterprise Administrator equivalent permissions are required..." "ERROR"
			Logging "" "ERROR"
			Logging "Aborting Script..." "ERROR"
			Logging "" "ERROR"

			# Mail The Log File With The Results
			If ($argsCount -gt 0 -And $sendMailWithLogFile) {
				Logging "" "ERROR"
				Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "ERROR"
				Logging "  - TO: '$mailToRecipient'..." "ERROR"
				If ($mailCcRecipients.Length -gt 0) {
					$mailCcRecipients | ForEach-Object {
						Logging "  - CC: '$($_)'..." "ERROR"
					}
				}
				Logging "" "ERROR"

				$mailAttachments = @()
				$mailAttachments += $logFilePath
				sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
			}

			EXIT
		} Else {
			# The User Account Running This Script Has Been Validated To Be A Member Of The Enterprise Admins Group Of The AD Forest
			Logging "The user account '$adRunningUserAccount' is running with Enterprise Administrator equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "SUCCESS"
			Logging "The user account '$adRunningUserAccount' is a member of '$enterpriseAdminRole'!..." "SUCCESS"
			Logging "" "SUCCESS"
			Logging "Continuing Script..." "SUCCESS"
			Logging "" "SUCCESS"
		}
	} Else {
		# The User Account Running This Script Has Been Validated To Be A Member Of The Domain Admins Group Of The Targeted AD Domain
		Logging "The user account '$adRunningUserAccount' is running with Domain Administrator equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "SUCCESS"
		Logging "The user account '$adRunningUserAccount' is a member of '$domainAdminRole'!..." "SUCCESS"
		Logging "" "SUCCESS"
		Logging "Continuing Script..." "SUCCESS"
		Logging "" "SUCCESS"
	}
}

# If The AD Forest Is Remote Then We Cannot Test For Role Membership Of The Administrators Group. We Will Test Permissions By Copying The Value Of The Description Field Into The Title Field And Clearing It Again
If ($localADforest -eq $false -And !$adminCrds) {
	Try {
		#Set-ADUser -Identity KRBTGT -Title $((Get-ADUser -Identity KRBTGT -Properties Description -Server $targetedADdomainFQDN).Description) -Server $targetedADdomainFQDN
		#Set-ADUser -Identity KRBTGT -Clear Title -Server $targetedADdomainFQDN
		$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
		$krbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=KRBTGT))" -PropertiesToLoad @("description") -AdditionalProperties @('title')
		$krbTgtObject.title = $krbTgtObject.description
		Edit-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -Mode Replace -Object $krbTgtObject
		$krbTgtObject.title = $null
		Edit-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -Mode Replace -Object $krbTgtObject
		Logging "The user account '$adRunningUserAccount' is running with Administrators equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "SUCCESS"
		Logging "" "SUCCESS"
		Logging "Continuing Script..." "SUCCESS"
		Logging "" "SUCCESS"
	} Catch {
		Logging "The user account '$adRunningUserAccount' IS NOT running with Administrators equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "ERROR"
		Logging "" "ERROR"
		Logging "For this script to run successfully, Administrators equivalent permissions are required in the AD Domain '$targetedADdomainFQDN'..." "ERROR"
		Logging "" "ERROR"

		If ($argsCount -gt 0) {
			Logging "Aborting Script..." "ERROR"
			Logging "" "ERROR"
			# Mail The Log File With The Results
			If ($sendMailWithLogFile) {
				Logging "" "ERROR"
				Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "ERROR"
				Logging "  - TO: '$mailToRecipient'..." "ERROR"
				If ($mailCcRecipients.Length -gt 0) {
					$mailCcRecipients | ForEach-Object {
						Logging "  - CC: '$($_)'..." "ERROR"
					}
				}
				Logging "" "ERROR"

				$mailAttachments = @()
				$mailAttachments += $logFilePath
				sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
			}

			EXIT
		} Else {
			Logging "Continuing Script..." "ERROR"
			Logging "" "ERROR"
			# Ask For The Remote Credentials
			$adminCrds = requestForAdminCreds
			Logging ""
		}
	}
}
If ($localADforest -eq $false -And $adminCrds) {
	Try {
		$adminUserAccountRemoteForest = $adminCrds.UserName
		$adminUserPasswordRemoteForest = $adminCrds.GetNetworkCredential().Password
		#Set-ADUser -Identity KRBTGT -Title $((Get-ADUser -Identity KRBTGT -Properties Description -Server $targetedADdomainFQDN -Credential $adminCrds).Description) -Server $targetedADdomainFQDN -Credential $adminCrds
		#Set-ADUser -Identity KRBTGT -Clear Title -Server $targetedADdomainFQDN -Credential $adminCrds
		$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
		$krbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=KRBTGT))" -PropertiesToLoad @("description") -AdditionalProperties @('title')
		$krbTgtObject.title = $krbTgtObject.description
		Edit-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -Mode Replace -Object $krbTgtObject
		$krbTgtObject.title = $null
		Edit-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -Mode Replace -Object $krbTgtObject
		Logging "The user account '$adminUserAccountRemoteForest' is running with Administrators equivalent permissions in the AD Domain '$targetedADdomainFQDN'!..." "SUCCESS"
		Logging "" "SUCCESS"
		Logging "Continuing Script..." "SUCCESS"
		Logging "" "SUCCESS"
	} Catch {
		Logging "The user account '$adminUserAccountRemoteForest' IS NOT running with Administrators equivalent permissions in the AD Domain '$targetedADdomainFQDN' OR username/password IS NOT correct!..." "ERROR"
		Logging "" "ERROR"
		Logging "For this script to run successfully, Administrators equivalent permissions are required in the AD Domain '$targetedADdomainFQDN'..." "ERROR"
		Logging "" "ERROR"
		Logging "Aborting Script..." "ERROR"
		Logging "" "ERROR"

		# Mail The Log File With The Results
		If ($argsCount -gt 0 -And $sendMailWithLogFile) {
			Logging "" "ERROR"
			Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "ERROR"
			Logging "  - TO: '$mailToRecipient'..." "ERROR"
			If ($mailCcRecipients.Length -gt 0) {
				$mailCcRecipients | ForEach-Object {
					Logging "  - CC: '$($_)'..." "ERROR"
				}
			}
			Logging "" "ERROR"

			$mailAttachments = @()
			$mailAttachments += $logFilePath
			sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
		}

		EXIT
	}
}

###
# All Modes - Gathering AD Domain Information
###
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "GATHERING TARGETED AD DOMAIN INFORMATION..." "HEADER"
Logging ""

# Retrieve Information For The AD Domain That Was Chosen
Try {
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		#$thisADDomain = Get-ADDomain $targetedADdomainFQDN -Server $targetedADdomainNearestRWDCFQDN
		$adDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $targetedADdomainFQDN)

		$targetSearchBase = "OU=Domain Controllers," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName)
		$dcsInADDomain = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectClass=computer)(|(primaryGroupID=516)(primaryGroupID=521)))" -PropertiesToLoad @("dNSHostName", "msDS-isRODC", "primaryGroupID")
	}
	If ($localADforest -eq $false -And $adminCrds) {
		#$thisADDomain = Get-ADDomain $targetedADdomainFQDN -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds
		$adDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $targetedADdomainFQDN, $($adminCrds.UserName), $($adminCrds.GetNetworkCredential().Password))
		
		$targetSearchBase = "OU=Domain Controllers," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName)
		$dcsInADDomain = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectClass=computer)(|(primaryGroupID=516)(primaryGroupID=521)))" -PropertiesToLoad @("dNSHostName", "msDS-isRODC", "primaryGroupID")
	}
	$thisADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($adDomainContext)
} Catch {
	$thisADDomain = $null
}

If ($thisADDomain) {
	# Retrieve The Domain SID
	#$targetedADdomainDomainSID = $thisADDomain.DomainSID.Value
	$objectSidBytes = $thisADDomain.GetDirectoryEntry().Properties["objectSid"].Value
	$targetedADdomainDomainSID = (New-Object System.Security.Principal.SecurityIdentifier($objectSidBytes, 0)).Value

	# Retrieve The HostName Of RWDC In The AD Domain That Hosts The PDC FSMO Role
	#$targetedADdomainRWDCFQDNWithPDCFSMOFQDN = $thisADDomain.PDCEmulator
	$targetedADdomainRWDCFQDNWithPDCFSMOFQDN = $thisADDomain.PdcRoleOwner.Name

	# Retrieve The DSA DN Of RWDC In The AD Domain That Hosts The PDC FSMO Role
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			#$targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN = (Get-ADDomainController $targetedADdomainRWDCFQDNWithPDCFSMOFQDN -Server $targetedADdomainNearestRWDCFQDN).NTDSSettingsObjectDN
			$targetSearchBase = "CN=Sites," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos)).configurationNamingContext.distinguishedName)
			$targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectClass=server)(dNSHostName=$targetedADdomainRWDCFQDNWithPDCFSMOFQDN))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Domain Controller With 'dNSHostName=$targetedADdomainRWDCFQDNWithPDCFSMOFQDN'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			#$targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN = (Get-ADDomainController $targetedADdomainRWDCFQDNWithPDCFSMOFQDN -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds).NTDSSettingsObjectDN
			$targetSearchBase = "CN=Sites," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).configurationNamingContext.distinguishedName)
			$targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectClass=server)(dNSHostName=$targetedADdomainRWDCFQDNWithPDCFSMOFQDN))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Domain Controller With 'dNSHostName=$targetedADdomainRWDCFQDNWithPDCFSMOFQDN' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}

	# Retrieve Domain Functional Level/Mode Of The AD Domain
	$targetedADdomainDomainFunctionalMode = $thisADDomain.DomainMode
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			#$targetedADdomainDomainFunctionalModeLevel = (Get-ADObject -LDAPFilter "(&(objectClass=crossRef)(nCName=$('DC=' + $targetedADdomainFQDN.replace('.',',DC='))))" -SearchBase $partitionsContainerDN -Properties "msDS-Behavior-Version" -Server $targetedADdomainNearestRWDCFQDN)."msDS-Behavior-Version"
			$targetedADdomainDomainFunctionalModeLevel = (Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $partitionsContainerDN -searchFilter "(&(objectClass=crossRef)(nCName=$('DC=' + $targetedADdomainFQDN.replace('.',',DC='))))" -PropertiesToLoad @("msDS-Behavior-Version"))."msDS-Behavior-Version"
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Cross Reference Object With 'nCName=$('DC=' + $targetedADdomainFQDN.replace('.',',DC='))'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			#$targetedADdomainDomainFunctionalModeLevel = (Get-ADObject -LDAPFilter "(&(objectClass=crossRef)(nCName=$('DC=' + $targetedADdomainFQDN.replace('.',',DC='))))" -SearchBase $partitionsContainerDN -Properties "msDS-Behavior-Version" -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds)."msDS-Behavior-Version"
			$targetedADdomainDomainFunctionalModeLevel = (Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $partitionsContainerDN -searchFilter "(&(objectClass=crossRef)(nCName=$('DC=' + $targetedADdomainFQDN.replace('.',',DC='))))" -PropertiesToLoad @("msDS-Behavior-Version"))."msDS-Behavior-Version"
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Cross Reference Object With 'nCName=$('DC=' + $targetedADdomainFQDN.replace('.',',DC='))' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($targetedADdomainDomainFunctionalModeLevel -eq 7 -And $targetedADdomainDomainFunctionalMode -eq "Unknown") {
		$targetedADdomainDomainFunctionalMode = "Windows2016Domain"
	}

	Try {
		# Execute An RSoP Against The Nearest RWDC In The Targeted AD Domain To Determine The Result Settings And The GPO(s) That Provided The Final Setting
		# Get The List Of GPOs That Were Processed For RSoP So We Can Map The GUID Back To Show Which GPO Won
		# Determine The Max Tgt Lifetime In Hours From The Winning GPO And The Max Clock Skew In Minutes From The Winning GPO
		If ($localADforest -eq $true) {
			$sidOfProfilesOnDC = (Get-WmiObject Win32_UserProfile -ComputerName $targetedADdomainNearestRWDCFQDN).SID | Where-Object{$_ -match $targetedADdomainDomainSID}
			If ($($sidOfProfilesOnDC | Measure-Object).Count -eq 1) {
				$sidToChoose = $sidOfProfilesOnDC
			} ElseIf ($($sidOfProfilesOnDC | Measure-Object).Count -gt 1) {
				$sidToChoose = $sidOfProfilesOnDC[0]
			} Else {
				$sidToChoose = [Security.Principal.WindowsIdentity]::GetCurrent().User
			}
			$accountToChoose = $(New-Object System.Security.Principal.SecurityIdentifier($sidToChoose)).Translate([System.Security.Principal.NTAccount]).Value
			Get-GPResultantSetOfPolicy -Computer $targetedADdomainNearestRWDCFQDN -User $accountToChoose -ReportType xml -Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml" -ErrorAction Stop | Out-Null
			If (Test-Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml") {
				[xml]$gpRSoPxml = Get-Content "$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml"
				$gpoList = @{}
				(Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop"}).Node.ComputerResults.GPO | ForEach-Object{$gpoList.Add($_.Path.Identifier."#text", $_.Name)}
				$rsopKerberosPolicy = (Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop"}).Node.ComputerResults.ExtensionData.Extension.Account | Where-Object{$_.Type -eq "Kerberos"}
				$kerberosPolicyMaxTgtAgeObject = New-Object -TypeName PSObject -Property @{
					SettingName   = "MaxTicketAge";
					SettingValue  = ($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxTicketAge"}).SettingNumber;
					SourceGPOGuid = $(($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxTicketAge"}).GPO.Identifier.'#text');
					SourceGPOName = $gpoList[$(($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxTicketAge"}).GPO.Identifier.'#text')];
				}
				$kerberosPolicyMaxClockSkewObject = New-Object -TypeName PSObject -Property @{
					SettingName   = "MaxClockSkew";
					SettingValue  = ($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxClockSkew"}).SettingNumber;
					SourceGPOGuid = $(($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxClockSkew"}).GPO.Identifier.'#text');
					SourceGPOName = $gpoList[$(($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxClockSkew"}).GPO.Identifier.'#text')];
				}
				Try {
					Remove-Item "$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml" -Force -ErrorAction Stop
				} Catch {
					Logging "" "ERROR"
					Logging "Error Removing The RSoP File '$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			} Else {
				$kerberosPolicyMaxTgtAgeObject = New-Object -TypeName PSObject -Property @{
					SettingName   = "MaxTicketAge";
					SettingValue  = 10;
					SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
					SourceGPOName = "Default Value Assumed";
				}
				$kerberosPolicyMaxClockSkewObject = New-Object -TypeName PSObject -Property @{
					SettingName   = "MaxClockSkew";
					SettingValue  = 5;
					SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
					SourceGPOName = "Default Value Assumed";
				}
			}
		}
		If ($localADforest -eq $false -And !$adminCrds) {
			$targetedServerSession = New-PSSession -ComputerName $targetedADdomainNearestRWDCFQDN -ErrorAction Stop
			$kerberosPolicyMaxTgtAgeObject, $kerberosPolicyMaxClockSkewObject = Invoke-Command -Session $targetedServerSession -ArgumentList $targetedADdomainFQDN, $targetedADdomainDomainSID, $targetedADdomainNearestRWDCFQDN, $execDateTimeCustom, $loadPoSHModulesDef, $LoggingDef -ScriptBlock {
				Param (
					$targetedADdomainFQDN,
					$targetedADdomainDomainSID,
					$targetedADdomainNearestRWDCFQDN,
					$execDateTimeCustom,
					$loadPoSHModulesDef,
					$LoggingDef
				)

				. ([ScriptBlock]::Create($loadPoSHModulesDef))
				. ([ScriptBlock]::Create($LoggingDef))

				"GroupPolicy" | ForEach-Object {
					$poshModuleState = $null
					$poshModuleState = loadPoSHModules $_ $true
					If ($poshModuleState -eq "NotAvailable") {
						BREAK
					}
				}

				If ($poshModuleState -eq "HasBeenLoaded" -Or $poshModuleState -eq "AlreadyLoaded") {
					$sidOfProfilesOnDC = (Get-WmiObject Win32_UserProfile -ComputerName $targetedADdomainNearestRWDCFQDN).SID | Where-Object{$_ -match $targetedADdomainDomainSID}
					If ($($sidOfProfilesOnDC | Measure-Object).Count -eq 1) {
						$sidToChoose = $sidOfProfilesOnDC
					} ElseIf ($($sidOfProfilesOnDC | Measure-Object).Count -gt 1) {
						$sidToChoose = $sidOfProfilesOnDC[0]
					} Else {
						$sidToChoose = [Security.Principal.WindowsIdentity]::GetCurrent().User
					}
					$accountToChoose = $(New-Object System.Security.Principal.SecurityIdentifier($sidToChoose)).Translate([System.Security.Principal.NTAccount]).Value
					Get-GPResultantSetOfPolicy -Computer $targetedADdomainNearestRWDCFQDN -User $accountToChoose -ReportType xml -Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml" -ErrorAction Stop | Out-Null
					If (Test-Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml") {
						[xml]$gpRSoPxml = Get-Content "$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml"
						$gpoList = @{}
						(Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop"}).Node.ComputerResults.GPO | ForEach-Object{$gpoList.Add($_.Path.Identifier."#text", $_.Name)}
						$rsopKerberosPolicy = (Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop"}).Node.ComputerResults.ExtensionData.Extension.Account | Where-Object{$_.Type -eq "Kerberos"}
						$kerberosPolicyMaxTgtAgeObject = New-Object -TypeName PSObject -Property @{
							SettingName   = "MaxTicketAge";
							SettingValue  = ($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxTicketAge"}).SettingNumber;
							SourceGPOGuid = $(($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxTicketAge"}).GPO.Identifier.'#text');
							SourceGPOName = $gpoList[$(($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxTicketAge"}).GPO.Identifier.'#text')];
						}
						$kerberosPolicyMaxClockSkewObject = New-Object -TypeName PSObject -Property @{
							SettingName   = "MaxClockSkew";
							SettingValue  = ($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxClockSkew"}).SettingNumber;
							SourceGPOGuid = $(($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxClockSkew"}).GPO.Identifier.'#text');
							SourceGPOName = $gpoList[$(($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxClockSkew"}).GPO.Identifier.'#text')];
						}
						Try {
							Remove-Item "$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml" -Force -ErrorAction Stop
						} Catch {
							Logging "" "ERROR"
							Logging "Error Removing The RSoP File '$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					} Else {
						$kerberosPolicyMaxTgtAgeObject = New-Object -TypeName PSObject -Property @{
							SettingName   = "MaxTicketAge";
							SettingValue  = 10;
							SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
							SourceGPOName = "Default Value Assumed (Reason: RsOP Failed)";
						}
						$kerberosPolicyMaxClockSkewObject = New-Object -TypeName PSObject -Property @{
							SettingName   = "MaxClockSkew";
							SettingValue  = 5;
							SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
							SourceGPOName = "Default Value Assumed (Reason: RsOP Failed)";
						}
					}
				} Else {
					$kerberosPolicyMaxTgtAgeObject = New-Object -TypeName PSObject -Property @{
						SettingName   = "MaxTicketAge";
						SettingValue  = 10;
						SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
						SourceGPOName = "Default Value Assumed (Reason: PoSH Module Not Installed On Remote RWDC)";
					}
					$kerberosPolicyMaxClockSkewObject = New-Object -TypeName PSObject -Property @{
						SettingName   = "MaxClockSkew";
						SettingValue  = 5;
						SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
						SourceGPOName = "Default Value Assumed (Reason: PoSH Module Not Installed On Remote RWDC)";
					}
				}
				Return $kerberosPolicyMaxTgtAgeObject, $kerberosPolicyMaxClockSkewObject
			}
			Remove-PSSession $targetedServerSession
		}
		If ($localADforest -eq $false -And $adminCrds) {
			$targetedServerSession = New-PSSession -ComputerName $targetedADdomainNearestRWDCFQDN -Credential $adminCrds -ErrorAction Stop
			$kerberosPolicyMaxTgtAgeObject, $kerberosPolicyMaxClockSkewObject = Invoke-Command -Session $targetedServerSession -ArgumentList $targetedADdomainFQDN, $targetedADdomainDomainSID, $targetedADdomainNearestRWDCFQDN, $execDateTimeCustom, $loadPoSHModulesDef, $LoggingDef -ScriptBlock {
				Param (
					$targetedADdomainFQDN,
					$targetedADdomainDomainSID,
					$targetedADdomainNearestRWDCFQDN,
					$execDateTimeCustom,
					$loadPoSHModulesDef,
					$LoggingDef
				)

				. ([ScriptBlock]::Create($loadPoSHModulesDef))
				. ([ScriptBlock]::Create($LoggingDef))

				"GroupPolicy" | ForEach-Object {
					$poshModuleState = $null
					$poshModuleState = loadPoSHModules $_ $true
					If ($poshModuleState -eq "NotAvailable") {
						BREAK
					}
				}

				If ($poshModuleState -eq "HasBeenLoaded" -Or $poshModuleState -eq "AlreadyLoaded") {
					$sidOfProfilesOnDC = (Get-WmiObject Win32_UserProfile -ComputerName $targetedADdomainNearestRWDCFQDN).SID | Where-Object{$_ -match $targetedADdomainDomainSID}
					If ($($sidOfProfilesOnDC | Measure-Object).Count -eq 1) {
						$sidToChoose = $sidOfProfilesOnDC
					} ElseIf ($($sidOfProfilesOnDC | Measure-Object).Count -gt 1) {
						$sidToChoose = $sidOfProfilesOnDC[0]
					} Else {
						$sidToChoose = [Security.Principal.WindowsIdentity]::GetCurrent().User
					}
					$accountToChoose = $(New-Object System.Security.Principal.SecurityIdentifier($sidToChoose)).Translate([System.Security.Principal.NTAccount]).Value
					Get-GPResultantSetOfPolicy -Computer $targetedADdomainNearestRWDCFQDN -User $accountToChoose -ReportType xml -Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml" -ErrorAction Stop | Out-Null
					If (Test-Path "$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml") {
						[xml]$gpRSoPxml = Get-Content "$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml"
						$gpoList = @{}
						(Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop"}).Node.ComputerResults.GPO | ForEach-Object{$gpoList.Add($_.Path.Identifier."#text", $_.Name)}
						$rsopKerberosPolicy = (Select-Xml -xml $gpRSoPxml -XPath '/rsop:Rsop' -Namespace @{rsop = "http://www.microsoft.com/GroupPolicy/Rsop"}).Node.ComputerResults.ExtensionData.Extension.Account | Where-Object{$_.Type -eq "Kerberos"}
						$kerberosPolicyMaxTgtAgeObject = New-Object -TypeName PSObject -Property @{
							SettingName   = "MaxTicketAge";
							SettingValue  = ($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxTicketAge"}).SettingNumber;
							SourceGPOGuid = $(($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxTicketAge"}).GPO.Identifier.'#text');
							SourceGPOName = $gpoList[$(($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxTicketAge"}).GPO.Identifier.'#text')];
						}
						$kerberosPolicyMaxClockSkewObject = New-Object -TypeName PSObject -Property @{
							SettingName   = "MaxClockSkew";
							SettingValue  = ($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxClockSkew"}).SettingNumber;
							SourceGPOGuid = $(($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxClockSkew"}).GPO.Identifier.'#text');
							SourceGPOName = $gpoList[$(($rsopKerberosPolicy | Where-Object{$_.Name -eq "MaxClockSkew"}).GPO.Identifier.'#text')];
						}
						Try {
							Remove-Item "$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml" -Force -ErrorAction Stop
						} Catch {
							Logging "" "ERROR"
							Logging "Error Removing The RSoP File '$($ENV:WINDIR + '\TEMP')\gpRSoP_$targetedADdomainFQDN`_$targetedADdomainNearestRWDCFQDN`_$execDateTimeCustom.xml'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					} Else {
						$kerberosPolicyMaxTgtAgeObject = New-Object -TypeName PSObject -Property @{
							SettingName   = "MaxTicketAge";
							SettingValue  = 10;
							SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
							SourceGPOName = "Default Value Assumed";
						}
						$kerberosPolicyMaxClockSkewObject = New-Object -TypeName PSObject -Property @{
							SettingName   = "MaxClockSkew";
							SettingValue  = 5;
							SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
							SourceGPOName = "Default Value Assumed";
						}
					}
				} Else {
					$kerberosPolicyMaxTgtAgeObject = New-Object -TypeName PSObject -Property @{
						SettingName   = "MaxTicketAge";
						SettingValue  = 10;
						SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
						SourceGPOName = "Default Value Assumed (Reason: PoSH Module Not Installed On Remote RWDC)";
					}
					$kerberosPolicyMaxClockSkewObject = New-Object -TypeName PSObject -Property @{
						SettingName   = "MaxClockSkew";
						SettingValue  = 5;
						SourceGPOGuid = "00000000-0000-0000-0000-000000000000";
						SourceGPOName = "Default Value Assumed (Reason: PoSH Module Not Installed On Remote RWDC)";
					}
				}
				Return $kerberosPolicyMaxTgtAgeObject, $kerberosPolicyMaxClockSkewObject
			}
			Remove-PSSession $targetedServerSession
		}
		$targetedADdomainMaxTgtLifetimeHrs = $kerberosPolicyMaxTgtAgeObject.SettingValue
		$targetedADdomainMaxTgtLifetimeHrsSourceGPO = $kerberosPolicyMaxTgtAgeObject.SourceGPOName
		$targetedADdomainMaxClockSkewMins = $kerberosPolicyMaxClockSkewObject.SettingValue
		$targetedADdomainMaxClockSkewMinsSourceGPO = $kerberosPolicyMaxClockSkewObject.SourceGPOName
	} Catch {
		Logging "Could not lookup 'MaxTicketAge' (default 10 hours) and 'MaxClockSkew' (default 5 minutes) from the resultant GPO, so default values will be assumed." "WARNING"
		Logging ""
		$targetedADdomainMaxTgtLifetimeHrs = 10
		$targetedADdomainMaxTgtLifetimeHrsSourceGPO = "Default Value Assumed"
		$targetedADdomainMaxClockSkewMins = 5
		$targetedADdomainMaxClockSkewMinsSourceGPO = "Default Value Assumed"
	}
} Else {
	$targetedADdomainRWDCFQDNWithPDCFSMOFQDN = "Unavailable"
	$targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN = "Unavailable"
	$targetedADdomainDomainFunctionalMode = "Unavailable"
	$targetedADdomainDomainFunctionalModeLevel = "Unavailable"
	$targetedADdomainMaxTgtLifetimeHrs = "Unavailable"
	$targetedADdomainMaxTgtLifetimeHrsSourceGPO = "Unavailable"
	$targetedADdomainMaxClockSkewMins = "Unavailable"
	$targetedADdomainMaxClockSkewMinsSourceGPO = "Unavailable"
}

# Present The Information
Logging ""
Logging "Domain FQDN...........................: '$targetedADdomainFQDN'"
Logging "Domain Functional Mode................: '$targetedADdomainDomainFunctionalMode'"
Logging "Domain Functional Mode Level..........: '$targetedADdomainDomainFunctionalModeLevel'"
Logging "FQDN RWDC With PDC FSMO...............: '$targetedADdomainRWDCFQDNWithPDCFSMOFQDN'"
Logging "DSA RWDC With PDC FSMO................: '$targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN'"
Logging "Max TGT Lifetime (Hours)..............: '$targetedADdomainMaxTgtLifetimeHrs'"
Logging "Max TGT Lifetime Sourced From.........: '$targetedADdomainMaxTgtLifetimeHrsSourceGPO'"
Logging "Max Clock Skew (Minutes)..............: '$targetedADdomainMaxClockSkewMins'"
Logging "Max Clock Skew Sourced From...........: '$targetedADdomainMaxClockSkewMinsSourceGPO'"
Logging ""
Logging "Checking Domain Functional Mode of targeted AD domain '$targetedADdomainFQDN' is high enough..."

# Check If The Domain Functional Level/Mode Of The AD Domain Is High Enough To Continue
If ($targetedADdomainDomainFunctionalModeLevel -ne "Unavailable" -And $targetedADdomainDomainFunctionalModeLevel -ge 3) {
	# If The Domain Functional Level/Mode Of The AD Domain Is Equal Or Higher Than Windows Server 2008 (3), Then Continue
	Logging "" "SUCCESS"
	Logging "The specified AD domain '$targetedADdomainFQDN' has a Domain Functional Mode of 'Windows2008Domain (3)' or higher!..." "SUCCESS"
	Logging "" "SUCCESS"
	Logging "Continuing Script..." "SUCCESS"
	Logging "" "SUCCESS"
} Else {
	# If The Domain Functional Level/Mode Of The AD Domain Is Lower Than Windows Server 2008 (3) Or It Cannot Be Determined, Then Abort
	Logging "" "ERROR"
	Logging "It CANNOT be determined the specified AD domain '$targetedADdomainFQDN' has a Domain Functional Mode of 'Windows2008Domain (3)' or higher!..." "ERROR"
	Logging "" "ERROR"
	Logging "AD domains with Windows Server 2000/2003 DCs CANNOT do KDC PAC validation using the previous (N-1) KrbTgt Account Password" "ERROR"
	Logging "like Windows Server 2008 and higher DCs are able to. Windows Server 2000/2003 DCs will only attempt it with the current (N)" "ERROR"
	Logging "KrbTgt Account Password. That means that in the subset of KRB AP exchanges where KDC PAC validation is performed," "ERROR"
	Logging "authentication issues could be experience because the target server gets a PAC validation error when asking the KDC (DC)" "ERROR"
	Logging "to validate the KDC signature of the PAC that is inside the service ticket that was presented by the client to the server." "ERROR"
	Logging "This problem would potentially persist for the lifetime of the service ticket(s). And by the way... for Windows Server" "ERROR"
	Logging "2000/2003 support already ended years ago. Time to upgrade to higher version dude!" "ERROR"
	Logging "Be aware though, when increasing the DFL from Windows Server 2003 to any higher level, the password of the KrbTgt Account" "ERROR"
	Logging "will be reset automatically due to the introduction of AES encryption for Kerberos and the requirement to regenerate new" "ERROR"
	Logging "keys for DES, RC4, AES128, AES256!" "ERROR"
	Logging "" "ERROR"
	Logging "Aborting Script..." "ERROR"
	Logging "" "ERROR"

	# Mail The Log File With The Results
	If ($argsCount -gt 0 -And $sendMailWithLogFile) {
		Logging "" "ERROR"
		Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "ERROR"
		Logging "  - TO: '$mailToRecipient'..." "ERROR"
		If ($mailCcRecipients.Length -gt 0) {
			$mailCcRecipients | ForEach-Object {
				Logging "  - CC: '$($_)'..." "ERROR"
			}
		}
		Logging "" "ERROR"

		$mailAttachments = @()
		$mailAttachments += $logFilePath
		sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
	}

	EXIT
}

###
# All Modes - Gathering Domain Controller Information And Testing Connectivity
###
Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
Logging "GATHERING DOMAIN CONTROLLER INFORMATION AND TESTING CONNECTIVITY..." "HEADER"
Logging ""

# Define An Empty List/Table That Will Contain All DCs In The AD Domain And Related Information
$tableOfDCsInADDomain = @()

# Retrieve All The RWDCs In The AD Domain
#$listOfRWDCsInADDomain = $thisADDomain.ReplicaDirectoryServers
$listOfRWDCsInADDomain = $dcsInADDomain | Where-Object{$_."msDS-isRODC" -eq $false -Or $_.primaryGroupID -eq "516"} | ForEach-Object{$_.dnsHostName}

# Set The Counters To Zero
$nrOfRWDCs = 0
$nrOfReachableRWDCs = 0
$nrOfUnReachableRWDCs = 0

# Execute For All RWDCs In The AD Domain If Any
If ($listOfRWDCsInADDomain) {
	$listOfRWDCsInADDomain | ForEach-Object {
		# Get The FQDN Of The RWDC
		$rwdcFQDN = $null
		$rwdcFQDN = $_

		# Retrieve The Object Of The RWDC From AD
		$rwdcObj = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				#$rwdcObj = Get-ADDomainController $rwdcFQDN -Server $targetedADdomainNearestRWDCFQDN
				$targetSearchBase = "OU=Domain Controllers," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName)
				$rwdcObj = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectClass=computer)(dNSHostName=$rwdcFQDN))" -PropertiesToLoad @("OperatingSystem", "serverReferenceBL")
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Domain Controller With 'dNSHostName=$rwdcFQDN'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				#$rwdcObj = Get-ADDomainController $rwdcFQDN -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds
				$targetSearchBase = "OU=Domain Controllers," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName)
				$rwdcObj = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectClass=computer)(dNSHostName=$rwdcFQDN))" -PropertiesToLoad @("OperatingSystem", "serverReferenceBL")
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Domain Controller With 'dNSHostName=$rwdcFQDN' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}

		# Define The Columns For The RWDCs In The AD Domain To Be Filled In
		$tableOfDCsInADDomainObj = New-Object -TypeName System.Object
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Host Name" -Value $rwdcFQDN
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "PDC" -Value $(If (($tableOfADDomainsInADForest | Where-Object{$_.Name -eq $targetedADdomainFQDN}).PDCFsmoOwner -eq $rwdcFQDN) {$true} Else {$false})
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($rwdcObj.serverReferenceBL.Split(",")[2].Replace("CN=", ""))
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "DS Type" -Value "Read/Write"
		$rwdcKrbTgtSamAccountName = $null
		If ($modeOfOperationNr -eq 1 -Or $modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
			# Use The PROD/REAL KrbTgt Account Of The RWDC
			$rwdcKrbTgtSamAccountName = "krbtgt"
		}
		If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {
			# Use The TEST/BOGUS KrbTgt Account Of The RWDC
			$rwdcKrbTgtSamAccountName = "krbtgt_TEST"
		}
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Krb Tgt" -Value $rwdcKrbTgtSamAccountName
		$rwdcKrbTgtObject = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				#$rwdcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rwdcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainNearestRWDCFQDN
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
				$rwdcKrbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$rwdcKrbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$rwdcKrbTgtSamAccountName'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				#$rwdcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rwdcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
				$rwdcKrbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$rwdcKrbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$rwdcKrbTgtSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		# Retrieve The Object Of The KrbTgt Account
		If ($rwdcKrbTgtObject) {
			# If The Object Of The KrbTgt Account Exists
			# Retrieve The DN OF The Object
			$rwdcKrbTgtObjectDN = $null
			$rwdcKrbTgtObjectDN = $rwdcKrbTgtObject.DistinguishedName

			# Retrieve The Password Last Set Value Of The KrbTgt Account
			$rwdcKrbTgtPwdLastSet = $null
			$rwdcKrbTgtPwdLastSet = Get-Date $([datetime]::fromfiletime($rwdcKrbTgtObject.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"

			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Pwd Last Set" -Value $rwdcKrbTgtPwdLastSet

			# Retrieve The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object
			$objectMetadata = $null
			$objectMetadata = retrieveObjectMetadata $targetedADdomainNearestRWDCFQDN $rwdcKrbTgtObjectDN $localADforest $adminCrds
			$objectMetadataAttribPwdLastSet = $null
			$objectMetadataAttribPwdLastSet = $objectMetadata | Where-Object{$_.Name -eq "pwdLastSet"}
			$objectMetadataAttribPwdLastSetOrgRWDCFQDN = $null
			$objectMetadataAttribPwdLastSetOrgRWDCFQDN = If ($objectMetadataAttribPwdLastSet.OriginatingServer) {$objectMetadataAttribPwdLastSet.OriginatingServer} Else {"RWDC Demoted"}
			$objectMetadataAttribPwdLastSetOrgTime = $null
			$objectMetadataAttribPwdLastSetOrgTime = Get-Date $($objectMetadataAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
			$objectMetadataAttribPwdLastSetVersion = $null
			$objectMetadataAttribPwdLastSetVersion = $objectMetadataAttribPwdLastSet.Version

			# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Org RWDC" -Value $objectMetadataAttribPwdLastSetOrgRWDCFQDN
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Org Time" -Value $objectMetadataAttribPwdLastSetOrgTime
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Ver" -Value $objectMetadataAttribPwdLastSetVersion
		} Else {
			# If The Object Of The KrbTgt Account Does Not Exist
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Pwd Last Set" -Value "No Such Object"
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Org RWDC" -Value "No Such Object"
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Org Time" -Value "No Such Object"
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Ver" -Value "No Such Object"
		}
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $(Try{(([System.Net.Dns]::GetHostEntry($rwdcfqdn)).AddressList | Where-Object{$_.AddressFamily -eq "InterNetwork"}).IPAddressToString} Catch {"Unknown"})
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "OS Version" -Value $($rwdcObj.OperatingSystem)
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
			$connectionResult = portConnectionCheck $rwdcFQDN $port $connectionTimeout
			If ($connectionResult -eq "ERROR") {
				$connectionCheckOK = $false
			}
		}
		If ($connectionCheckOK -eq $true) {
			# If The Connection Check Is OK
			# Connect To The RootDSE Of The RWDC
			$rwdcRootDSEObj = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					$rwdcRootDSEObj = [ADSI]"LDAP://$rwdcFQDN/rootDSE"
				} Catch {
					Logging "" "ERROR"
					Logging "Error Connecting To '$rwdcFQDN' For 'rootDSE'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					$rwdcRootDSEObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$rwdcFQDN/rootDSE"), $adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
				} Catch {
					Logging "" "ERROR"
					Logging "Error Connecting To '$rwdcFQDN' For 'rootDSE' Using '$adminUserAccountRemoteForest'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($rwdcRootDSEObj.Path -eq $null) {
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
		#If ($rwdcObj.OperationMasterRoles -contains "PDCEmulator") {
		If (($tableOfADDomainsInADForest | Where-Object{$_.Name -eq $targetedADdomainFQDN}).PDCFsmoOwner -eq $rwdcFQDN) {
			# If The RWDC Is The RWDC With The PDC FSMO, Then Do Not Specify A Source RWDC As The RWDC With The PDC FSMO Is The Source Originating RWDC
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC FQDN" -Value "N.A."
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC DSA" -Value "N.A."
		} Else {
			# If The RWDC Is Not The RWDC With The PDC FSMO, Then Specify A Source RWDC Being The RWDC With The PDC FSMO As The Source Originating RWDC
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC FQDN" -Value $targetedADdomainRWDCFQDNWithPDCFSMOFQDN
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC DSA" -Value $targetedADdomainRWDCFQDNWithPDCFSMONTDSSettingsObjectDN
		}

		# Increase The Counter For The Number Of RWDCs
		$nrOfRWDCs += 1

		# Add The Row For The RWDC To The Table
		$tableOfDCsInADDomain += $tableOfDCsInADDomainObj
	}
}

# Retrieve All The RODCs In The AD Domain
#$listOfRODCsInADDomain = $thisADDomain.ReadOnlyReplicaDirectoryServers
$listOfRODCsInADDomain = $dcsInADDomain | Where-Object{$_."msDS-isRODC" -eq $true -Or $_.primaryGroupID -eq "521"} | ForEach-Object{$_.dnsHostName}

# Set The Counters To Zero
$nrOfRODCs = 0
$nrOfReachableRODCs = 0
$nrOfUnReachableRODCs = 0
$nrOfUnDetermined = 0

# Execute For All RODCs In The AD Domain
If ($listOfRODCsInADDomain) {
	$listOfRODCsInADDomain | ForEach-Object {
		# Get The FQDN Of The RODC
		$rodcFQDN = $null
		$rodcFQDN = $_

		# Get The FQDN Of The RODC
		$rodcObj = $null
		$rodcObjACC = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				#$rodcObj = Get-ADDomainController $rodcFQDN -Server $targetedADdomainNearestRWDCFQDN
				$targetSearchBaseACC = "OU=Domain Controllers," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName)
				$rodcObjACC = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBaseACC -searchFilter "(&(objectClass=computer)(dNSHostName=$rodcFQDN))" -PropertiesToLoad @("OperatingSystem", "serverReferenceBL")
				$targetSearchBaseDSA = "CN=Sites," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos)).configurationNamingContext.distinguishedName)
				$rodcObjNTDSSettingsObjectDN = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBaseDSA -searchFilter "(&(objectClass=server)(dNSHostName=$rodcFQDN))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Domain Controller With 'dNSHostName=$rodcFQDN'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				#$rodcObj = Get-ADDomainController $rodcFQDN -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds
				$targetSearchBaseACC = "OU=Domain Controllers," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName)
				$rodcObjACC = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBaseACC -searchFilter "(&(objectClass=computer)(dNSHostName=$rodcFQDN))" -PropertiesToLoad @("OperatingSystem", "serverReferenceBL")
				$targetSearchBaseDSA = "CN=Sites," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).configurationNamingContext.distinguishedName)
				$rodcObjNTDSSettingsObjectDN = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBaseDSA -searchFilter "(&(objectClass=server)(dNSHostName=$rodcFQDN))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For Domain Controller With 'dNSHostName=$rodcFQDN' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}

		# Define The Columns For The RODCs In The AD Domain To Be Filled In
		$tableOfDCsInADDomainObj = New-Object -TypeName System.Object
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Host Name" -Value $rodcFQDN
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "PDC" -Value $false
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $(If ($rodcObjACC.OperatingSystem) {$rodcObjACC.serverReferenceBL.Split(",")[2].Replace("CN=", "")} Else {"Unknown"})
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "DS Type" -Value "Read-Only"
		$rodcKrbTgtSamAccountName = $null
		If ($modeOfOperationNr -eq 1 -Or $modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
			# Use The PROD/REAL KrbTgt Account Of The RODC
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					#$rodcKrbTgtSamAccountName = ((Get-ADObject $($rodcObj.ComputerObjectDN) -properties msDS-KrbTgtLink -Server $targetedADdomainNearestRWDCFQDN)."msDS-KrbTgtLink" | Get-ADObject -Server $targetedADdomainNearestRWDCFQDN).Name
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
					$rodcKrbTgtSamAccountName = (Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$($rodcObjACC.distinguishedName))" -PropertiesToLoad @("msDS-KrbTgtLink"))."msDS-KrbTgtLink"))" -PropertiesToLoad @("name"))."name"
				} Catch {
					Logging "" "ERROR"
					Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' To Determine The KrbTgt Account In Use By '$rodcFQDN'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					#$rodcKrbTgtSamAccountName = ((Get-ADObject $($rodcObj.ComputerObjectDN) -properties msDS-KrbTgtLink -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds)."msDS-KrbTgtLink" | Get-ADObject -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds).Name
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
					$rodcKrbTgtSamAccountName = (Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$($rodcObjACC.distinguishedName))" -PropertiesToLoad @("msDS-KrbTgtLink"))."msDS-KrbTgtLink"))" -PropertiesToLoad @("name"))."name"
				} Catch {
					Logging "" "ERROR"
					Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' To Determine The KrbTgt Account In Use By '$rodcFQDN' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
		}
		If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {
			# Use The TEST/BOGUS KrbTgt Account Of The RODC
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					#$rodcKrbTgtSamAccountName = $(((Get-ADObject $($rodcObj.ComputerObjectDN) -properties msDS-KrbTgtLink -Server $targetedADdomainNearestRWDCFQDN)."msDS-KrbTgtLink" | Get-ADObject -Server $targetedADdomainNearestRWDCFQDN).Name) + "_TEST"
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
					$rodcKrbTgtSamAccountName = $((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$($rodcObjACC.distinguishedName))" -PropertiesToLoad @("msDS-KrbTgtLink"))."msDS-KrbTgtLink"))" -PropertiesToLoad @("name"))."name") + "_TEST"
				} Catch {
					Logging "" "ERROR"
					Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' To Determine The TEST KrbTgt Account In Use By '$rodcFQDN'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					#$rodcKrbTgtSamAccountName = $(((Get-ADObject $($rodcObj.ComputerObjectDN) -properties msDS-KrbTgtLink -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds)."msDS-KrbTgtLink" | Get-ADObject -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds).Name) + "_TEST"
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
					$rodcKrbTgtSamAccountName = $((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(distinguishedName=$($rodcObjACC.distinguishedName))" -PropertiesToLoad @("msDS-KrbTgtLink"))."msDS-KrbTgtLink"))" -PropertiesToLoad @("name"))."name") + "_TEST"
				} Catch {
					Logging "" "ERROR"
					Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' To Determine The TEST KrbTgt Account In Use By '$rodcFQDN' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
		}
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Krb Tgt" -Value $rodcKrbTgtSamAccountName
		# Retrieve The Object Of The KrbTgt Account
		$rodcKrbTgtObject = $null
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Try {
				#$rodcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rodcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainNearestRWDCFQDN
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
				$rodcKrbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$rodcKrbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$rodcKrbTgtSamAccountName'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Try {
				#$rodcKrbTgtObject = Get-ADUser -LDAPFilter "(sAMAccountName=$rodcKrbTgtSamAccountName)" -Properties * -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds
				$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
				$rodcKrbTgtObject = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$rodcKrbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
			} Catch {
				Logging "" "ERROR"
				Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$rodcKrbTgtSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
				Logging "" "ERROR"
				Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
				Logging "" "ERROR"
				Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
				Logging "" "ERROR"
				Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
				Logging "" "ERROR"
			}
		}
		If ($rodcKrbTgtObject) {
			# If The Object Of The KrbTgt Account Exists
			# Retrieve The DN OF The Object
			$rodcKrbTgtObjectDN = $null
			$rodcKrbTgtObjectDN = $rodcKrbTgtObject.DistinguishedName

			# Retrieve The Password Last Set Value Of The KrbTgt Account
			$rodcKrbTgtPwdLastSet = $null
			$rodcKrbTgtPwdLastSet = Get-Date $([datetime]::fromfiletime($rodcKrbTgtObject.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"

			# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Pwd Last Set" -Value $rodcKrbTgtPwdLastSet

			# Retrieve The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object
			$objectMetadata = $null
			$objectMetadata = retrieveObjectMetadata $targetedADdomainNearestRWDCFQDN $rodcKrbTgtObjectDN $localADforest $adminCrds
			$objectMetadataAttribPwdLastSet = $null
			$objectMetadataAttribPwdLastSet = $objectMetadata | Where-Object{$_.Name -eq "pwdLastSet"}
			$objectMetadataAttribPwdLastSetOrgRWDCFQDN = $null
			$objectMetadataAttribPwdLastSetOrgRWDCFQDN = If ($objectMetadataAttribPwdLastSet.OriginatingServer) {$objectMetadataAttribPwdLastSet.OriginatingServer} Else {"RWDC Demoted"}
			$objectMetadataAttribPwdLastSetOrgTime = $null
			$objectMetadataAttribPwdLastSetOrgTime = Get-Date $($objectMetadataAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
			$objectMetadataAttribPwdLastSetVersion = $null
			$objectMetadataAttribPwdLastSetVersion = $objectMetadataAttribPwdLastSet.Version

			# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Org RWDC" -Value $objectMetadataAttribPwdLastSetOrgRWDCFQDN
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Org Time" -Value $objectMetadataAttribPwdLastSetOrgTime
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Ver" -Value $objectMetadataAttribPwdLastSetVersion
		} Else {
			# If The Object Of The KrbTgt Account Does Not Exist
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Pwd Last Set" -Value "No Such Object"
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Org RWDC" -Value "No Such Object"
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Org Time" -Value "No Such Object"
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Ver" -Value "No Such Object"
		}
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $(Try{(([System.Net.Dns]::GetHostEntry($rodcfqdn)).AddressList | Where-Object{$_.AddressFamily -eq "InterNetwork"}).IPAddressToString} Catch {"Unknown"})
		$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "OS Version" -Value $($rodcObjACC.OperatingSystem)
		# Define The Ports To Check Against
		$ports = 389 # LDAP

		# Define The Connection Check To Be True Initially
		$connectionCheckOK = $true

		# For Every Defined Port Check The Connection And Report
		$failedPorts = @()
		$ports | ForEach-Object {
			# Set The Port To Check Against
			$port = $null
			$port = $_

			# Test The Connection To The Server Using The Port
			$connectionResult = $null
			$connectionResult = portConnectionCheck $rodcFQDN $port $connectionTimeout
			If ($connectionResult -eq "ERROR") {
				$failedPorts += $port
				$connectionCheckOK = $false
			}
		}
		If ($connectionCheckOK -eq $true) {
			# If The Connection Check Is OK
			# Connect To The RootDSE Of The RODC
			$rodcRootDSEObj = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					$rodcRootDSEObj = [ADSI]"LDAP://$rodcFQDN/rootDSE"
				} Catch {
					Logging "" "ERROR"
					Logging "Error Connecting To '$rodcFQDN' For 'rootDSE'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					$rodcRootDSEObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$rodcFQDN/rootDSE"), $adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
				} Catch {
					Logging "" "ERROR"
					Logging "Error Connecting To '$rodcFQDN' For 'rootDSE' Using '$adminUserAccountRemoteForest'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($rodcRootDSEObj.Path -eq $null) {
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
		If ($rodcObjACC.OperatingSystem) {
			# If The RODC Has An Operating System Specified, Then It Is Most Likely A Windows RODC
			If ($tableOfDCsInADDomainObj.Reachable -eq $true) {
				# If The RODC Is Available/Reachable
				# Define An LDAP Query With A Search Base And A Filter To Determine The DSA DN Of The Source RWDC Of The RODC
				$dsDirSearcher = $null
				$dsDirSearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
				$dsDirSearcher.SearchRoot = $null
				If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
					$dsDirSearcher.SearchRoot = "LDAP://$rodcFQDN/$rodcObjNTDSSettingsObjectDN"
				}
				If ($localADforest -eq $false -And $adminCrds) {
					$dsDirSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$rodcFQDN/$rodcObjNTDSSettingsObjectDN"), $adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
				}
				$dsDirSearcher.Filter = $null
				#$dsDirSearcher.Filter = "(&(objectClass=nTDSConnection)(ms-DS-ReplicatesNCReason=*))"
				$dsDirSearcher.Filter = "(&(objectClass=nTDSConnection)(options:1.2.840.113556.1.4.803:=64))" # Targeting The CO Called "CN=RODC Connection (SYSVOL),CN=NTDS Settings,CN=<RODC NAME>,CN=Servers,CN=<SITE>,CN=Sites,CN=Configuration,DC=<DOMAIN>,DC=<TLD>" ONLY
				$sourceRWDCsNTDSSettingsObjectDN = $null
				Try {
					$sourceRWDCsNTDSSettingsObjectDN = $dsDirSearcher.FindAll().Properties.fromserver
				} Catch {
					Logging "" "ERROR"
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
						Logging "Error Querying AD Against '$rodcFQDN' For Object '$rodcObjNTDSSettingsObjectDN'..." "ERROR"
					}
					If ($localADforest -eq $false -And $adminCrds) {
						Logging "Error Querying AD Against '$rodcFQDN' For Object '$rodcObjNTDSSettingsObjectDN' Using '$($adminCrds.UserName)'..." "ERROR"
					}
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}

				# For Every DSA DN Of The Source RWDC Retrieved
				$sourceRWDCsNTDSSettingsObjectDN | ForEach-Object {
					$sourceRWDCNTDSSettingsObjectDN = $null
					$sourceRWDCNTDSSettingsObjectDN = $_

					# Strip "CN=NTDS Settings," To End Up With The Server Object DN
					$sourceRWDCServerObjectDN = $null
					$sourceRWDCServerObjectDN = $sourceRWDCNTDSSettingsObjectDN.SubString(("CN=NTDS Settings,").Length)

					# Connect To The Server Object DN
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
						Try {
							$sourceRWDCServerObjectObj = ([ADSI]"LDAP://$targetedADdomainNearestRWDCFQDN/$sourceRWDCServerObjectDN")
						} Catch {
							Logging "" "ERROR"
							Logging "Error Connecting To '$targetedADdomainNearestRWDCFQDN' For Object '$sourceRWDCServerObjectDN'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}
					If ($localADforest -eq $false -And $adminCrds) {
						Try {
							$sourceRWDCServerObjectObj = New-Object System.DirectoryServices.DirectoryEntry(("LDAP://$targetedADdomainNearestRWDCFQDN/$sourceRWDCServerObjectDN"), $adminUserAccountRemoteForest, $adminUserPasswordRemoteForest)
						} Catch {
							Logging "" "ERROR"
							Logging "Error Connecting To '$targetedADdomainNearestRWDCFQDN' For Object '$sourceRWDCServerObjectDN' Using '$adminUserAccountRemoteForest'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}

					# The HostName Of Source RWDC Used By The RODC - Set The Corresponding Value Of The RODC In The Correct Column Of The Table
					$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC FQDN" -Value $sourceRWDCServerObjectObj.dnshostname[0]

					# The DSA DN Of Source RWDC Used By The RODC - Set The Corresponding Value Of The RODC In The Correct Column Of The Table
					$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC DSA" -Value $sourceRWDCsNTDSSettingsObjectDN[0]
				}
			} Else {
				# If The RODC Is Available/Reachable
				# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
				$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC FQDN" -Value "RODC Unreachable"
				$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC DSA" -Value "RODC Unreachable"
			}
		} Else {
			# If The RODC Does Not Have An Operating System Specified, Then It Is Most Likely Not A Windows RODC
			# Set The Corresponding Value Of The RODC In The Correct Column Of The Table
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC FQDN" -Value "Unknown"
			$tableOfDCsInADDomainObj | Add-Member -MemberType NoteProperty -Name "Source RWDC DSA" -Value "Unknown"
		}
		If ($rodcObjACC.OperatingSystem) {
			# If The RODC Has An Operating System Specified, Then It Is Most Likely A Windows RODC, Therefore Increase The Counter For Real RODCs
			$nrOfRODCs += 1
		} Else {
			# If The RODC Does Not Have An Operating System Specified, Then It Is Most Likely Not A Windows RODC, Therefore Increase The Counter For Unknown RODCs
			$nrOfUnDetermined += 1
		}
		# Add The Row For The RODC To The Table
		$tableOfDCsInADDomain += $tableOfDCsInADDomainObj
	}
}

# Sort The Table With DCs In The AD Domain In The Order "DS Type" (Read/Write At The Top), Then If It Is The PDC Or Not (PDC At The Top), Then If It Is Reachable Or Not (Reachable At the Top)
$tableOfDCsInADDomain = $tableOfDCsInADDomain | Sort-Object -Property @{Expression = "DS Type"; Descending = $False}, @{Expression = "PDC"; Descending = $True}, @{Expression = "Reachable"; Descending = $True}

# Determine The Number Of DCs Based Upon The Number Of RWDCs And The Number Of RODCs
$nrOfDCs = $nrOfRWDCs + $nrOfRODCs

# Display The Information
Logging "" "REMARK"
Logging "List Of Domain Controllers In AD Domain '$targetedADdomainFQDN'..."
Logging "" "REMARK"
Logging "$($tableOfDCsInADDomain | Format-Table * -Autosize | Out-String)"
Logging "" "REMARK"
Logging "REMARKS:" "REMARK"
Logging " - 'N.A.' in the columns 'Source RWDC FQDN' and 'Source RWDC DSA' means the RWDC is considered as the master for this script." "REMARK"
Logging " - 'RODC Unreachable' in the columns 'Source RWDC FQDN' and 'Source RWDC DSA' means the RODC cannot be reached to determine its replicating source" "REMARK"
Logging "     RWDC/DSA. The unavailability can be due to firewalls/networking or the RODC actually being down." "REMARK"
Logging " - 'Unknown' in various columns means that an RODC was found that may not be a true Windows Server RODC. It may be an appliance acting as an RODC." "REMARK"
Logging " - 'RWDC Demoted' in the column 'Org RWDC' means the RWDC existed once, but it does not exist anymore as it has been decommissioned in the past." "REMARK"
Logging "     This is normal." "REMARK"
Logging " - 'No Such Object' in the columns 'Pwd Last Set', 'Org RWDC', 'Org Time' or 'Ver' means the targeted object was not found in the AD domain." "REMARK"
Logging "     Although this is possible for any targeted object, this is most likely the case when targeting the KrbTgt TEST/BOGUS accounts and if those" "REMARK"
Logging "     do not exist yet. This may also occur for an appliance acting as an RODC as in that case no KrbTgt TEST/BOGUS account is created." "REMARK"
$krbTgtAADname = "krbtgt_AzureAD"
Try {
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		#$krbTgtAAD = Get-ADUser -Filter "name -eq '$krbTgtAADname'" -SearchBase $("DC=" + $targetedADdomainFQDN.Replace(".",",DC=")) -Server $targetedADdomainNearestRWDCFQDN
		$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
		$krbTgtAAD = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(name=$krbTgtAADname))"
	}
	If ($localADforest -eq $false -And $adminCrds) {
		#$krbTgtAAD = Get-ADUser -Filter "name -eq '$krbTgtAADname'" -SearchBase $("DC=" + $targetedADdomainFQDN.Replace(".",",DC=")) -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds
		$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
		$krbTgtAAD = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(name=$krbTgtAADname))"
	}
} Catch {
	Logging "" "ERROR"
	Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' To Determine If An Azure AD KrbTgt Account Existed..." "ERROR"
	Logging "" "ERROR"
	Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
	Logging "" "ERROR"
	Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
	Logging "" "ERROR"
	Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
	Logging "" "ERROR"
}
If ($krbTgtAAD) {
	Logging "" "REMARK"
	Logging "WARNING:" "WARNING"
	Logging " - In this AD domain '$targetedADdomainFQDN' the special purpose krbtgt account '$krbTgtAADname' for Azure AD was found (not listed in the table above though!)!" "WARNING"
	Logging " - DO NOT reset the password of this krbtgt account in any way except using the official method to reset the password and rotate the keys" "WARNING"
	Logging "     (See: - https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-passwordless-security-key-on-premises)" "WARNING"
	Logging " - To reset the password and rotate the keys of the krbtgt account '$krbTgtAADname' perform the following steps:" "WARNING"
	Logging "    * Go to an Azure AD Connect server (v1.4.32.0 or later)" "WARNING"
	Logging "    * Open a PowerShell Command Prompt window" "WARNING"
	Logging "    * In that window execute the following commands:" "WARNING"
	Logging "" "WARNING"
	Logging "       # Import The PowerShell Module For Azure AD Kerberos Server" "WARNING"
	Logging "       Import-Module `"C:\Program Files\Microsoft Azure Active Directory Connect\AzureADKerberos\AzureAdKerberos.psd1`"" "WARNING"
	Logging "" "WARNING"
	Logging "       # AD Domain/Enterprise Admin Credentials" "WARNING"
	Logging "       `$adDomainAdminAccount = Read-Host `"AD Admin Account`"" "WARNING"
	Logging "       `$adDomainAdminPassword = Read-Host `"AD Admin Account Password`" -AsSecureString" "WARNING"
	Logging "       `$secureAdDomainAdminPassword = ConvertTo-SecureString `$adDomainAdminPassword -AsPlainText -Force" "WARNING"
	Logging "       `$adDomainAdminCreds = New-Object System.Management.Automation.PSCredential `$adDomainAdminAccount, `$secureAdDomainAdminPassword" "WARNING"
	Logging "" "WARNING"
	Logging "       # Azure AD Global Admin Credentials" "WARNING"
	Logging "       `$aadDomainAdminAccount = Read-Host `"Azure AD Admin Account`"" "WARNING"
	Logging "       `$aadDomainAdminPassword = Read-Host `"Azure AD Admin Account Password`" -AsSecureString" "WARNING"
	Logging "       [string]`$aadDomainAdminPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR(`$aadDomainAdminPassword))" "WARNING"
	Logging "       `$secureAadDomainAdminPassword = ConvertTo-SecureString `$aadDomainAdminPassword -AsPlainText -Force" "WARNING"
	Logging "       `$aadDomainAdminCreds = New-Object System.Management.Automation.PSCredential `$aadDomainAdminAccount, `$secureAadDomainAdminPassword" "WARNING"
	Logging "" "WARNING"
	Logging "       # Check the CURRENT status of the Azure AD Kerberos Server object in Active Directory" "WARNING"
	Logging "       Get-AzureADKerberosServer -Domain $targetedADdomainFQDN -DomainCredential `$adDomainAdminCreds -CloudCredential `$aadDomainAdminCreds" "WARNING"
	Logging "" "WARNING"
	Logging "       # Reset the password and rotate the keys" "WARNING"
	Logging "       Set-AzureADKerberosServer -Domain $targetedADdomainFQDN -DomainCredential `$adDomainAdminCreds -CloudCredential `$aadDomainAdminCreds -RotateServerKey" "WARNING"
	Logging "" "WARNING"
	Logging "       # Check the NEW status of the Azure AD Kerberos Server object in Active Directory" "WARNING"
	Logging "       Get-AzureADKerberosServer -Domain $targetedADdomainFQDN -DomainCredential `$adDomainAdminCreds -CloudCredential `$aadDomainAdminCreds" "WARNING"
	Logging "" "WARNING"
	Logging "    REMARK: Make sure the 'KeyVersion' value matches the 'CloudKeyVersion' value and the 'KeyUpdatedOn' value matches the 'CloudKeyUpdatedOn' value!" "WARNING"
}
Logging "" "REMARK"
Logging "" "REMARK"
Logging "" "REMARK"
Logging "  --> Found [$nrOfDCs] Real DC(s) In AD Domain..." "REMARK"
Logging "" "REMARK"
Logging "  --> Found [$nrOfRWDCs] RWDC(s) In AD Domain..." "REMARK"
Logging "  --> Found [$nrOfReachableRWDCs] Reachable RWDC(s) In AD Domain..." "REMARK"
Logging "  --> Found [$nrOfUnReachableRWDCs] UnReachable RWDC(s) In AD Domain..." "REMARK"
Logging "" "REMARK"
Logging "  --> Found [$nrOfRODCs] RODC(s) In AD Domain..." "REMARK"
Logging "  --> Found [$nrOfReachableRODCs] Reachable RODC(s) In AD Domain..." "REMARK"
Logging "  --> Found [$nrOfUnReachableRODCs] UnReachable RODC(s) In AD Domain..." "REMARK"
Logging "  --> Found [$nrOfUnDetermined] Undetermined RODC(s) In AD Domain..." "REMARK"
Logging "" "REMARK"

###
# Mode 2 And 3 And 4 and 5 And 6 And 8 And 9 Only - Making Sure The RWDC With The PDC FSMO And The Nearest RWDC Are Reachable/Available
###
If ($modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6 -Or $modeOfOperationNr -eq 8 -Or $modeOfOperationNr -eq 9) {
	If (($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $true}).Reachable -eq $false) {
		Logging "" "ERROR"
		Logging "  --> The RWDC With The PDC FSMO Role '$targetedADdomainRWDCFQDNWithPDCFSMOFQDN' IS NOT Reachable For The Ports '$($ports -join ', ')'..." "ERROR"
		Logging "" "ERROR"

		$abortDueToUnreachable = $true
	}

	If (($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainNearestRWDCFQDN}).Reachable -eq $false) {
		Logging "" "ERROR"
		Logging "  --> The Nearest RWDC '$targetedADdomainNearestRWDCFQDN' IS NOT Reachable For The Ports '$($ports -join ', ')'..." "ERROR"
		Logging "" "ERROR"

		$abortDueToUnreachable = $true
	}

	If ($abortDueToUnreachable -eq $true) {
		Logging "" "ERROR"
		Logging "  --> Due To Unavailability Issues Of The RWDC With The PDC FSMO Role And/Or The Nearest RWDC, The Script Cannot Continue ..." "ERROR"
		Logging "  --> Both The RWDC With The PDC FSMO Role And The The Nearest RWDC MUST Be Available/Reachable..." "ERROR"
		Logging "" "ERROR"
		Logging "Aborting Script..." "ERROR"
		Logging "" "ERROR"

		# Mail The Log File With The Results
		If ($argsCount -gt 0 -And $sendMailWithLogFile) {
			Logging "" "ERROR"
			Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "ERROR"
			Logging "  - TO: '$mailToRecipient'..." "ERROR"
			If ($mailCcRecipients.Length -gt 0) {
				$mailCcRecipients | ForEach-Object {
					Logging "  - CC: '$($_)'..." "ERROR"
				}
			}
			Logging "" "ERROR"

			$mailAttachments = @()
			$mailAttachments += $logFilePath
			sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
		}

		EXIT
	}
}

###
# Mode 2 And 3 And 4 and 5 And 6 Only - Selecting The KrbTgt Account To Target And Scope If Applicable (Only Applicable To RODCs)
###
If ($modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "SELECT THE SCOPE OF THE KRBTGT ACCOUNT(S) TO TARGET..." "HEADER"
	Logging ""
	Logging "Which KrbTgt account do you want to target?"
	Logging ""
	Logging " - 1 - Scope of KrbTgt in use by all RWDCs in the AD Domain"
	Logging ""
	If ($nrOfRODCs -gt 0) {
		Logging " - 2 - Scope of KrbTgt in use by specific RODC - Single/Multiple RODC(s) in the AD Domain"
		Logging ""
		Logging " - 3 - Scope of KrbTgt in use by specific RODC - All RODCs in the AD Domain"
		Logging ""
	}
	Logging ""
	Logging " - 0 - Exit Script"
	Logging ""
	Switch ($targetKrbTgtAccountScope) {
		"allRWDCs" {$targetKrbTgtAccountNr = 1}
		"specificRODCs"	{ $targetKrbTgtAccountNr = 2}
		"allRODCs" {$targetKrbTgtAccountNr = 3}
		Default {$targetKrbTgtAccountNr = $null}
	}
	If ($null -eq $targetKrbTgtAccountNr) {
		Logging "Please specify the scope of KrbTgt Account to target: " "ACTION-NO-NEW-LINE"
		$targetKrbTgtAccountNr = Read-Host
	} Else {
		Logging "Please specify the scope of KrbTgt Account to target: $targetKrbTgtAccountNr" "ACTION"
	}
	Logging ""

	# If Anything Else Than The Allowed/Available Non-Zero KrbTgt Accounts, Abort The Script
	If (($targetKrbTgtAccountNr -ne 1 -And $targetKrbTgtAccountNr -ne 2 -And $targetKrbTgtAccountNr -ne 3) -Or $targetKrbTgtAccountNr -notmatch "^[\d\.]+$") {
		Logging "  --> Chosen Scope KrbTgt Account Target: 0 - Exit Script..." "REMARK"
		Logging ""

		If ($argsCount -gt 0 -And $sendMailWithLogFile) {
			# Mail The Log File With The Results
			Logging "" "WARNING"
			Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "WARNING"
			Logging "  - TO: '$mailToRecipient'..." "WARNING"
			If ($mailCcRecipients.Length -gt 0) {
				$mailCcRecipients | ForEach-Object {
					Logging "  - CC: '$($_)'..." "WARNING"
				}
			}
			Logging "" "WARNING"

			$mailAttachments = @()
			$mailAttachments += $logFilePath
			sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
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
	Logging "  --> Chosen Scope KrbTgt Account Target: $targetKrbTgtAccountDescription" "REMARK"
	Logging ""

	# Use The RWDC With The PDC FSMO Role To Represent All RWDCs In The AD Domain
	If ($targetKrbTgtAccountNr -eq 1) {
		$targetDCFQDNList = $tableOfDCsInADDomain | Where-Object{$_.PDC -eq $true}
	}

	# Present List Of RODCs When Option 2 Or 3 Is Chosen To Make It Easier To Chose From
	# Specify A Comma Separated List Of FQDNs Of RODCs To Target (Single/Multiple)
	If ($targetKrbTgtAccountNr -eq 2) {
		Logging "" "REMARK"
		Logging "List Of Read-Only Domain Controllers In AD Domain '$targetedADdomainFQDN'..."
		Logging "" "REMARK"
		Logging "$($tableOfDCsInADDomain | Where-Object{$_.'DS Type' -eq 'Read-Only'} | Format-Table 'Host Name','DS Type','Krb Tgt','Pwd Last Set','Reachable' -Autosize | Out-String)"
		Logging "" "REMARK"

		If ($targetRODCFQDNList.Length -eq 0) {
			Logging "Specify a single, or comma-separated list of FQDNs of RODCs for which the KrbTgt Account Password must be reset: " "ACTION-NO-NEW-LINE"
			$targetDCFQDNList = Read-Host
			$targetDCFQDNList = $targetDCFQDNList.Split(",")
		} Else {
			$targetDCFQDNList = $targetRODCFQDNList
		}
		Logging ""
		Logging "  --> Specified RODCs:" "REMARK"
		$targetDCFQDNList | ForEach-Object {
			Logging "       * $($_)" "REMARK"
		}
		Logging ""
	}
}

###
# Mode 2/3/5 - Simulation Mode AND Mode 4/6 - Real Reset Mode
###
If ($modeOfOperationNr -eq 2 -Or $modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
	# Mode 2 - Simulation Mode - TEMPORARY CANARY OBJECT
	If ($modeOfOperationNr -eq 2) {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "SIMULATION MODE (MODE $modeOfOperationNr) - CREATING/REPLICATING TEMPORARY CANARY OBJECT TO TEST REPLICATION CONVERGENCE" "HEADER"
		Logging "SCOPE: $targetKrbTgtAccountDescription" "HEADER"
		Logging ""
	}

	# Mode 3 - Simulation Mode - SCOPED TEST/BOGUS KRBTGT ACCOUNT(S)
	If ($modeOfOperationNr -eq 3) {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "SIMULATION MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED TEST/BOGUS KRBTGT ACCOUNT(S) (WHAT IF MODE)" "HEADER"
		Logging "SCOPE: $targetKrbTgtAccountDescription" "HEADER"
		Logging ""
	}

	# Mode 4 - Real Reset Mode - SCOPED TEST/BOGUS KRBTGT ACCOUNT(S)
	If ($modeOfOperationNr -eq 4) {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "REAL RESET MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED TEST/BOGUS KRBTGT ACCOUNT(S)" "HEADER"
		Logging "SCOPE: $targetKrbTgtAccountDescription" "HEADER"
		Logging ""
	}

	# Mode 5 - Simulation Mode - SCOPED PROD/REAL KRBTGT ACCOUNT(S)
	If ($modeOfOperationNr -eq 5) {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "SIMULATION MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED PROD/REAL KRBTGT ACCOUNT(S) (WHAT IF MODE)" "HEADER"
		Logging "SCOPE: $targetKrbTgtAccountDescription" "HEADER"
		Logging ""
	}

	# Mode 6 - Real Reset Mode - SCOPED PROD/REAL KRBTGT ACCOUNT(S)
	If ($modeOfOperationNr -eq 6) {
		Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
		Logging "REAL RESET MODE (MODE $modeOfOperationNr) - RESETTING PASSWORD OF SCOPED PROD/REAL KRBTGT ACCOUNT(S)" "HEADER"
		Logging "SCOPE: $targetKrbTgtAccountDescription" "HEADER"
		Logging ""
	}

	# Asking Confirmation To Continue Or Not
	$continueOrStop = $null
	If ($argsCount -gt 0 -And $continueOps) {
		$continueOrStop = "CONTINUE"
		Logging "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: $continueOrStop" "ACTION"
	} Else {
		Logging "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: " "ACTION-NO-NEW-LINE"
		$continueOrStop = Read-Host
	}

	# Any Confirmation Not Equal To CONTINUE Will Be Equal To STOP
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		$continueOrStop = "STOP"
	}
	Logging ""
	Logging "  --> Chosen: $continueOrStop" "REMARK"
	Logging ""

	# Any Confirmation Not Equal To CONTINUE Will Abort The Script
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		# Mail The Log File With The Results
		If ($argsCount -gt 0 -And $sendMailWithLogFile) {
			Logging "" "WARNING"
			Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "WARNING"
			Logging "  - TO: '$mailToRecipient'..." "WARNING"
			If ($mailCcRecipients.Length -gt 0) {
				$mailCcRecipients | ForEach-Object {
					Logging "  - CC: '$($_)'..." "WARNING"
				}
			}
			Logging "" "WARNING"

			$mailAttachments = @()
			$mailAttachments += $logFilePath
			sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
		}

		EXIT
	}

	# For The KrbTgt Account Scope Of All RWDCs
	If ($targetKrbTgtAccountNr -eq 1) {
		# Collection Of DCs To Process
		$collectionOfDCsToProcess = @()
		$collectionOfDCsToProcess += $targetDCFQDNList
	}

	# For The KrbTgt Account Scope Of Specified, But Individual RODCs
	If ($targetKrbTgtAccountNr -eq 2) {
		# Collection Of Reachable RODCs
		$collectionOfRODCsToProcessReachable = @()
		$collectionOfRODCsToProcessReachable += $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $true -And $_."Source RWDC FQDN" -ne "Unknown" -And $_."Source RWDC FQDN" -ne "RODC Unreachable" -And $targetDCFQDNList -contains $_."Host Name"}

		# Collection Of UnReachable RODCs
		$collectionOfRODCsToProcessUnReachable = @()
		$collectionOfRODCsToProcessUnReachable += $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $false -And $_."Source RWDC FQDN" -eq "RODC Unreachable" -And $targetDCFQDNList -contains $_."Host Name"}

		# Collection Of Unknown RODCs
		[string[]]$collectionOfRODCsToProcessUnknown = @()
		$collectionOfRODCsToProcessUnknown += $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $false -And $_."Source RWDC FQDN" -eq "Unknown" -And $targetDCFQDNList -contains $_."Host Name"}

		# Collection Of DCs To Process
		$collectionOfDCsToProcess = @()
		$collectionOfDCsToProcess += $collectionOfRODCsToProcessReachable
		$collectionOfDCsToProcess += $collectionOfRODCsToProcessUnReachable

		# Collection Of DCs NOT To Process
		$collectionOfDCsNotToProcess = @()
		$collectionOfDCsNotToProcess += $collectionOfRODCsToProcessUnknown
	}

	# For The KrbTgt Account Scope Of Each Individual RODCs
	If ($targetKrbTgtAccountNr -eq 3) {
		# Collection Of Reachable RODCs
		$collectionOfRODCsToProcessReachable = @()
		$collectionOfRODCsToProcessReachable += $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $true -And $_."Source RWDC FQDN" -ne "Unknown" -And $_."Source RWDC FQDN" -ne "RODC Unreachable"}

		# Collection Of UnReachable RODCs
		$collectionOfRODCsToProcessUnReachable = @()
		$collectionOfRODCsToProcessUnReachable += $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $false -And $_."Source RWDC FQDN" -eq "RODC Unreachable"}

		# Collection Of Unknown RODCs
		$collectionOfRODCsToProcessUnknown = @()
		$collectionOfRODCsToProcessUnknown += $tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_.Reachable -eq $false -And $_."Source RWDC FQDN" -eq "Unknown"}

		# Collection Of DCs To Process
		$collectionOfDCsToProcess = @()
		$collectionOfDCsToProcess += $collectionOfRODCsToProcessReachable
		$collectionOfDCsToProcess += $collectionOfRODCsToProcessUnReachable

		# Collection Of DCs NOT To Process
		$collectionOfDCsNotToProcess = @()
		$collectionOfDCsNotToProcess += $collectionOfRODCsToProcessUnknown
	}

	# If Any DC Exists In The List, Process it
	If ($collectionOfDCsToProcess.Length -gt 0) {
		$collectionOfDCsToProcess | ForEach-Object {
			# The DC Object In The List To Process
			$dcToProcess = $null
			$dcToProcess = $_

			# Retrieve The sAMAccountName Of The KrbTgt Account In Use By The DC(s)
			$krbTgtSamAccountName = $null
			$krbTgtSamAccountName = $dcToProcess."Krb Tgt"

			# Retrieve The KrbTgt Account Object DN
			$krbTgtObjectDN = $null
			If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
				Try {
					#$krbTgtObjectDN = (Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainNearestRWDCFQDN).DistinguishedName
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
					$krbTgtObjectDN = (Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))").DistinguishedName
				} Catch {
					Logging "" "ERROR"
					Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}
			If ($localADforest -eq $false -And $adminCrds) {
				Try {
					#$krbTgtObjectDN = (Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds).DistinguishedName
					$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
					$krbTgtObjectDN = (Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))").DistinguishedName
				} Catch {
					Logging "" "ERROR"
					Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
					Logging "" "ERROR"
					Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
					Logging "" "ERROR"
					Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
					Logging "" "ERROR"
					Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
					Logging "" "ERROR"
				}
			}

			# Present The Information Of The KrbTgt Account Scope Being Processed
			Logging "+++++" "REMARK"
			Logging "+++ Processing KrbTgt Account....: '$krbTgtSamAccountName' | '$krbTgtObjectDN' +++" "REMARK"
			If ($targetKrbTgtAccountNr -eq 1) {
				Logging "+++ Used By RWDC.................: 'All RWDCs' +++" "REMARK"
			}
			If ($targetKrbTgtAccountNr -eq 2 -Or $targetKrbTgtAccountNr -eq 3) {
				Logging "+++ Used By RODC.................: '$($dcToProcess."Host Name")' (Site: $($dcToProcess."Site Name")) +++" "REMARK"
			}
			Logging "+++++" "REMARK"
			Logging "" "REMARK"

			# Determine The HostName Of The Source RWDC
			If ($targetKrbTgtAccountNr -eq 1) {
				$targetedADdomainSourceRWDCFQDN = $null
				$targetedADdomainSourceRWDCFQDN = $dcToProcess."Host Name"
			}
			If ($targetKrbTgtAccountNr -eq 2 -Or $targetKrbTgtAccountNr -eq 3) {
				$targetedADdomainDCToProcessReachability = $null
				$targetedADdomainDCToProcessReachability = $dcToProcess.Reachable

				$targetedADdomainSourceRWDCFQDN = $null
				$targetedADdomainSourceRWDCFQDN = $dcToProcess."Source RWDC FQDN"

				If ($targetedADdomainDCToProcessReachability -eq $false -Or $targetedADdomainSourceRWDCFQDN -eq "RODC Unreachable" -Or $targetedADdomainSourceRWDCFQDN -eq "Unknown") {
					$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Host Name"
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
						#$dcToProcess."Source RWDC DSA" = (Get-ADDomainController $targetedADdomainSourceRWDCFQDN -Server $targetedADdomainSourceRWDCFQDN).NTDSSettingsObjectDN
						$targetSearchBase = "CN=Sites," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName)
						$dcToProcess."Source RWDC DSA" = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectClass=server)(dNSHostName=$targetedADdomainSourceRWDCFQDN))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
					}
					If ($localADforest -eq $false -And $adminCrds) {
						#$dcToProcess."Source RWDC DSA" = (Get-ADDomainController $targetedADdomainSourceRWDCFQDN -Server $targetedADdomainSourceRWDCFQDN -Credential $adminCrds).NTDSSettingsObjectDN
						$targetSearchBase = "CN=Sites," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName)
						$dcToProcess."Source RWDC DSA" = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectClass=server)(dNSHostName=$targetedADdomainSourceRWDCFQDN))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
					}
				} Else {
					$targetedADdomainSourceRWDCReachability = $null
					$targetedADdomainSourceRWDCReachability = ($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN}).Reachable
					If ($targetedADdomainSourceRWDCReachability -eq $false) {
						$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Host Name"
						If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
							#$dcToProcess."Source RWDC DSA" = (Get-ADDomainController $targetedADdomainSourceRWDCFQDN -Server $targetedADdomainSourceRWDCFQDN).NTDSSettingsObjectDN
							$targetSearchBase = "CN=Sites," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName)
							$dcToProcess."Source RWDC DSA" = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectClass=server)(dNSHostName=$targetedADdomainSourceRWDCFQDN))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
						}
						If ($localADforest -eq $false -And $adminCrds) {
							#$dcToProcess."Source RWDC DSA" = (Get-ADDomainController $targetedADdomainSourceRWDCFQDN -Server $targetedADdomainSourceRWDCFQDN -Credential $adminCrds).NTDSSettingsObjectDN
							$targetSearchBase = "CN=Sites," + $((Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName)
							$dcToProcess."Source RWDC DSA" = "CN=NTDS Settings," + $((Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainSourceRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectClass=server)(dNSHostName=$targetedADdomainSourceRWDCFQDN))" -PropertiesToLoad @("distinguishedName")).distinguishedName)
						}
					}
				}
			}

			# Retrieve Details Of The Source RWDC
			$targetedADdomainSourceRWDCIsPDC = $null
			$targetedADdomainSourceRWDCIsPDC = ($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN}).PDC
			$targetedADdomainSourceRWDCDSType = $null
			$targetedADdomainSourceRWDCDSType = ($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN})."DS Type"
			$targetedADdomainSourceRWDCSiteName = $null
			$targetedADdomainSourceRWDCSiteName = ($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN})."Site Name"
			$targetedADdomainSourceRWDCIPAddress = $null
			$targetedADdomainSourceRWDCIPAddress = ($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN})."IP Address"
			$targetedADdomainSourceRWDCReachability = $null
			$targetedADdomainSourceRWDCReachability = ($tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN}).Reachable

			# Only Continue If The Source RWDC Is Available/Reachable To Process The Change
			If ($targetedADdomainSourceRWDCReachability -eq $true) {
				# If Mode 2, Execute The Creation Of the Temporary Canary Object, And Abort The Script If That Fails
				If ($modeOfOperationNr -eq 2) {
					$targetObjectToCheckDN = $null
					$targetObjectToCheckDN = createTempCanaryObject $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $execDateTimeCustom1 $localADforest $adminCrds
					If (!$targetObjectToCheckDN) {
						# Mail The Log File With The Results
						If ($argsCount -gt 0 -And $sendMailWithLogFile) {
							Logging "" "WARNING"
							Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "WARNING"
							Logging "  - TO: '$mailToRecipient'..." "WARNING"
							If ($mailCcRecipients.Length -gt 0) {
								$mailCcRecipients | ForEach-Object {
									Logging "  - CC: '$($_)'..." "WARNING"
								}
							}
							Logging "" "WARNING"

							$mailAttachments = @()
							$mailAttachments += $logFilePath
							sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
						}

						EXIT
					}
				}

				# If Mode 3, Simulate Password Reset Of KrbTgt TEST/BOGUS Accounts (No Password Reset/WhatIf Mode)
				# If Mode 4, Do A Real Password Reset Of KrbTgt TEST/BOGUS Accounts (Password Reset!)
				# If Mode 5, Simulate Password Reset Of KrbTgt PROD/REAL Accounts (No Password Reset/WhatIf Mode)
				# If Mode 6, Do A Real Password Reset Of KrbTgt PROD/REAL Accounts (Password Reset!)
				If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 5 -Or $modeOfOperationNr -eq 6) {
					# Retrieve The KrbTgt Account Object
					$targetObjectToCheck = $null
					If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
						Try {
							#$targetObjectToCheck = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainNearestRWDCFQDN
							$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos)).defaultNamingContext.distinguishedName
							$targetObjectToCheck = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
						} Catch {
							Logging "" "ERROR"
							Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}
					If ($localADforest -eq $false -And $adminCrds) {
						Try {
							#$targetObjectToCheck = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainNearestRWDCFQDN -Credential $adminCrds
							$targetSearchBase = (Get-RootDSE -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds)).defaultNamingContext.distinguishedName
							$targetObjectToCheck = Find-LdapObject -LdapConnection $(Get-LdapConnection -LdapServer:$targetedADdomainNearestRWDCFQDN -EncryptionType Kerberos -Credential $adminCrds) -searchBase $targetSearchBase -searchFilter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$krbTgtSamAccountName))" -PropertiesToLoad @("pwdlastset")
						} Catch {
							Logging "" "ERROR"
							Logging "Error Querying AD Against '$targetedADdomainNearestRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
							Logging "" "ERROR"
							Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
							Logging "" "ERROR"
							Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
							Logging "" "ERROR"
							Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
							Logging "" "ERROR"
						}
					}

					# If The KrbTgt Account Object Was Found
					If ($targetObjectToCheck) {
						# If The KrbTgt Account Object Exists (You're In Deep Sh!t If The Account Does Not Exist! :-))
						# Retrieve The DN Of The KrbTgt Account Object
						$targetObjectToCheckDN = $null
						$targetObjectToCheckDN = $targetObjectToCheck.DistinguishedName

						# Retrieve The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object
						$objectMetadata = $null
						$objectMetadata = retrieveObjectMetadata $targetedADdomainNearestRWDCFQDN $targetObjectToCheckDN $localADforest $adminCrds
						$objectMetadataAttribPwdLastSet = $null
						$objectMetadataAttribPwdLastSet = $objectMetadata | Where-Object{$_.Name -eq "pwdLastSet"}
						$objectMetadataAttribPwdLastSetOrgRWDCFQDN = $null
						$objectMetadataAttribPwdLastSetOrgRWDCFQDN = If ($objectMetadataAttribPwdLastSet.OriginatingServer) {$objectMetadataAttribPwdLastSet.OriginatingServer} Else {"RWDC Demoted"}
						$objectMetadataAttribPwdLastSetOrgTime = $null
						$objectMetadataAttribPwdLastSetOrgTime = Get-Date $($objectMetadataAttribPwdLastSet.LastOriginatingChangeTime) -f "yyyy-MM-dd HH:mm:ss"
						$objectMetadataAttribPwdLastSetVersion = $null
						$objectMetadataAttribPwdLastSetVersion = $objectMetadataAttribPwdLastSet.Version

						# Retrieve The Password Last Set Of The KrbTgt Account Object
						$targetObjectToCheckPwdLastSet = $null
						$targetObjectToCheckPwdLastSet = Get-Date $([datetime]::fromfiletime($targetObjectToCheck.pwdLastSet))

						# If Mode 3, Do A WHAT IF Password Reset Of KrbTgt TEST/BOGUS Accounts (No Password Reset!)
						# If Mode 5, Do A WHAT IF Password Reset Of KrbTgt PROD/REAL Accounts (No Password Reset!)
						If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 5) {
							Logging "  --> According To RWDC.....................: '$targetedADdomainNearestRWDCFQDN'"
							Logging "  --> Previous Password Set Date/Time.......: '$(Get-Date $targetObjectToCheckPwdLastSet -f 'yyyy-MM-dd HH:mm:ss')'"
							Logging "  --> Originating RWDC Previous Change......: '$objectMetadataAttribPwdLastSetOrgRWDCFQDN'"
							Logging "  --> Originating Time Previous Change......: '$objectMetadataAttribPwdLastSetOrgTime'"
							Logging "  --> Current Version Of Attribute Value....: '$objectMetadataAttribPwdLastSetVersion'"
							Logging ""
							Logging "REMARK: What If Mode! NO PASSWORD RESET HAS OCCURED!" "REMARK"
							Logging ""
						}

						# If Mode 4, Do A Real Password Reset Of KrbTgt TEST/BOGUS Accounts (Password Reset!)
						# If Mode 6, Do A Real Password Reset Of KrbTgt PROD/REAL Accounts (Password Reset!)
						If ($modeOfOperationNr -eq 4 -Or $modeOfOperationNr -eq 6) {
							# Calculate The Expiration Date/Time Of N-1 Kerberos Tickets
							$expirationTimeForNMinusOneKerbTickets = $null
							$expirationTimeForNMinusOneKerbTickets = (($targetObjectToCheckPwdLastSet.AddHours($targetedADdomainMaxTgtLifetimeHrs)).AddMinutes($targetedADdomainMaxClockSkewMins)).AddMinutes($targetedADdomainMaxClockSkewMins)

							# Check If It Advisable To Reset The Password Or Not.
							# If YES, Just Continue
							# If NO, Ask For Acknowledgement
							$okToReset = $null
							If ($expirationTimeForNMinusOneKerbTickets -lt [DateTime]::Now) {
								# Allow The Password Reset To Occur Without Questions If The Expiration Date/Time Of N-1 Kerberos Tickets Is Earlier Than The Current Time
								$okToReset = $True
							} Else {
								# Allow The Password Reset To Occur After Confirnation Only If The Expiration Date/Time Of N-1 Kerberos Tickets Is Equal Or Later Than The Current Time
								Logging "  --> According To RWDC.....................: '$targetedADdomainNearestRWDCFQDN'"
								Logging "  --> Previous Password Set Date/Time.......: '$(Get-Date $targetObjectToCheckPwdLastSet -f 'yyyy-MM-dd HH:mm:ss')'"
								Logging "  --> Date/Time N-1 Kerberos Tickets........: '$(Get-Date $expirationTimeForNMinusOneKerbTickets -f 'yyyy-MM-dd HH:mm:ss')'"
								Logging "  --> Date/Time Now.........................: '$(Get-Date $([DateTime]::Now) -f 'yyyy-MM-dd HH:mm:ss')'"
								Logging "  --> Max TGT Lifetime (Hours)..............: '$targetedADdomainMaxTgtLifetimeHrs'"
								Logging "  --> Max Clock Skew (Minutes)..............: '$targetedADdomainMaxClockSkewMins'"
								Logging "  --> Originating RWDC Previous Change......: '$objectMetadataAttribPwdLastSetOrgRWDCFQDN'"
								Logging "  --> Originating Time Previous Change......: '$objectMetadataAttribPwdLastSetOrgTime'"
								Logging "  --> Current Version Of Attribute Value....: '$objectMetadataAttribPwdLastSetVersion'"
								Logging ""
								$continueOrStop = $null
								If ($targetKrbTgtAccountNr -eq 1) {
									If ($argsCount -gt 0) {
										$continueOrStop = "STOP"
										Logging "  --> Resetting KrbTgt Accnt Password Means.: 'MAJOR DOMAIN WIDE IMPACT'" "WARNING"
										Logging "" "WARNING"
										Logging "What do you want to do? [CONTINUE | STOP]: $continueOrStop" "ACTION"
									} Else {
										Logging "  --> Resetting KrbTgt Accnt Password Means.: 'MAJOR DOMAIN WIDE IMPACT'" "WARNING"
										Logging "" "WARNING"
										Logging "What do you want to do? [CONTINUE | STOP]: " "ACTION-NO-NEW-LINE"
										$continueOrStop = Read-Host
									}
								}
								If ($targetKrbTgtAccountNr -eq 2 -Or $targetKrbTgtAccountNr -eq 3) {
									If ($argsCount -gt 0) {
										$continueOrStop = "STOP"
										Logging "  --> Resetting KrbTgt Accnt Password Means.: 'MAJOR IMPACT FOR RESOURCES SERVICED BY $($dcToProcess."Host Name")' (Site: $($dcToProcess."Site Name"))" "WARNING"
										Logging "" "WARNING"
										Logging "What do you want to do? [CONTINUE | SKIP | STOP]: $continueOrStop" "ACTION"
									} Else {
										Logging "  --> Resetting KrbTgt Accnt Password Means.: 'MAJOR IMPACT FOR RESOURCES SERVICED BY $($dcToProcess."Host Name")' (Site: $($dcToProcess."Site Name"))" "WARNING"
										Logging "" "WARNING"
										Logging "What do you want to do? [CONTINUE | SKIP | STOP]: " "ACTION-NO-NEW-LINE"
										$continueOrStop = Read-Host
									}
								}

								If ($targetKrbTgtAccountNr -eq 1) {
									# Any Confirmation Not Equal To CONTINUE Will Be Equal To STOP
									If ($continueOrStop.ToUpper() -ne "CONTINUE") {
										$continueOrStop = "STOP"
									}
								}
								If ($targetKrbTgtAccountNr -eq 2 -Or $targetKrbTgtAccountNr -eq 3) {
									# Any Confirmation Not Equal To CONTINUE And Not Equal To SKIP And Not Equal To STOP Will Be Equal To STOP
									If ($continueOrStop.ToUpper() -ne "CONTINUE" -And $continueOrStop.ToUpper() -ne "SKIP" -And $continueOrStop.ToUpper() -ne "STOP") {
										$continueOrStop = "STOP"
									}
								}

								Logging ""
								If ($continueOrStop.ToUpper() -eq "CONTINUE") {
									# If The Confirmation Equals CONTINUE Allow The Password Reset To Continue
									$okToReset = $True
								} Else {
									# If The Confirmation Does Not Equal CONTINUE Do Not Allow The Password Reset To Continue. Abort
									$okToReset = $False
								}
								Logging "  --> Chosen: $continueOrStop" "REMARK"
								Logging ""
							}
							If ($okToReset -eq $true) {
								# If OK To Reset Then Execute The Password Reset Of The KrbTgt Account
								setPasswordOfADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $localADforest $adminCrds
							} Else {
								# If Not OK To Reset Then Abort
								# Mail The Log File With The Results
								If ($argsCount -gt 0 -And $sendMailWithLogFile) {
									Logging "" "WARNING"
									Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "WARNING"
									Logging "  - TO: '$mailToRecipient'..." "WARNING"
									If ($mailCcRecipients.Length -gt 0) {
										$mailCcRecipients | ForEach-Object {
											Logging "  - CC: '$($_)'..." "WARNING"
										}
									}
									Logging "" "WARNING"

									$mailAttachments = @()
									$mailAttachments += $logFilePath
									sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
								}

								EXIT
							}
						}
						# If Mode 3, Do A WHAT IF Password Reset Of KrbTgt TEST/BOGUS Accounts (No Password Reset!)
						# If Mode 5, Do A WHAT IF Password Reset Of KrbTgt PROD/REAL Accounts (No Password Reset!)
						If ($modeOfOperationNr -eq 3 -Or $modeOfOperationNr -eq 5) {

						}
					} Else {
						# If The KrbTgt Account Object Does Not Exist (You're In Deep Sh!t If The Account Does Not Exist! :-))
						Logging "  --> KrbTgt Account With sAMAccountName '$krbTgtSamAccountName' Does NOT Exist! Skipping..." "ERROR"
						Logging "" "ERROR"
					}
				}
			} Else {
				# If The Source RWDC Is NOT Reachable
				Logging ""
				Logging "The RWDC '$targetedADdomainSourceRWDCFQDN' To Make The Change On Is Not Reachable/Available..." "ERROR"
				Logging ""
			}

			# If The DN Of The Target Object To Check (Temp Canary Object Or KrbTgt Account, Depends On The Mode Chosen) Was Determined/Found
			If ($targetObjectToCheckDN) {
				# Retrieve/Define The Start List With RWDCs To Check
				If ($targetKrbTgtAccountNr -eq 1) {
					$listOfDCsToCheckObjectOnStart = $null
					$listOfDCsToCheckObjectOnStart = ($tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read/Write"})
				}
				If ($targetKrbTgtAccountNr -eq 2 -Or $targetKrbTgtAccountNr -eq 3) {
					$listOfDCsToCheckObjectOnStart = @()
					$listOfDCsToCheckObjectOnStart += $tableOfDCsInADDomain | Where-Object{$_."Host Name" -eq $targetedADdomainSourceRWDCFQDN}
					$listOfDCsToCheckObjectOnStart += $dcToProcess
				}

				# Define The End List With RWDCs That Have Been Checked. Now Only Contains The Source RWDC. While Looping Through The Start List And Determing The Object Has Replicated, DCs Are Added To The End List
				$listOfDCsToCheckObjectOnEnd = @()

				# Define The Columns For The RWDCs In The AD Domain To Be Filled In
				$listOfDCsToCheckObjectOnEndSourceRWDCObj = "" | Select-Object "Host Name", PDC, "Site Name", "DS Type", "IP Address", Reachable, "Source RWDC FQDN", Time

				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."Host Name" = $null
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."Host Name" = $targetedADdomainSourceRWDCFQDN

				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj.PDC = $null
				$listOfDCsToCheckObjectOnEndSourceRWDCObj.PDC = $targetedADdomainSourceRWDCIsPDC

				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."DS Type" = $null
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."DS Type" = $targetedADdomainSourceRWDCDSType

				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."Site Name" = $null
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."Site Name" = $targetedADdomainSourceRWDCSiteName

				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."IP Address" = $null
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."IP Address" = $targetedADdomainSourceRWDCIPAddress

				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj.Reachable = $null
				$listOfDCsToCheckObjectOnEndSourceRWDCObj.Reachable = $targetedADdomainSourceRWDCReachability

				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj."Source RWDC FQDN" = "N.A."

				# Set The Corresponding Value Of The RWDC In The Correct Column Of The Table
				$listOfDCsToCheckObjectOnEndSourceRWDCObj.Time = 0.00

				# Add The Row For The RWDC To The Table
				$listOfDCsToCheckObjectOnEnd += $listOfDCsToCheckObjectOnEndSourceRWDCObj

				# Execute The Check AD Replication Convergence Function For The Targeted Object To Check
				checkADReplicationConvergence $targetedADdomainFQDN $targetedADdomainSourceRWDCFQDN $targetObjectToCheckDN $listOfDCsToCheckObjectOnStart $listOfDCsToCheckObjectOnEnd $modeOfOperationNr $localADforest $adminCrds
			}
		}

		# If Any DC Object Exists In The Unknown DC List
		If ($collectionOfDCsNotToProcess) {
			Logging "+++++" "REMARK"
			Logging "+++ The Following Look Like DCs, But May Not Be Real DCs..." "REMARK"
			Logging "+++++" "REMARK"
			Logging "" "REMARK"

			# For Every Unknown DC
			$collectionOfDCsNotToProcess | ForEach-Object {
				$dcToProcess = $null
				$dcToProcess = $_
				Logging "$($dcToProcess | Format-Table * | Out-String)"
				Logging ""
			}
			Logging ""
		}
	}
}
 
###
# Mode 8 - Create TEST KrbTgt Accounts
###
If ($modeOfOperationNr -eq 8) {
	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "CREATE TEST KRBTGT ACCOUNTS (MODE 8)..." "HEADER"
	Logging ""

	# Asking Confirmation To Continue Or Not
	Logging "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: " "ACTION-NO-NEW-LINE"
	$continueOrStop = Read-Host

	# Any Confirmation Not Equal To CONTINUE Will Be Equal To STOP
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		$continueOrStop = "STOP"
	}
	Logging ""
	Logging "  --> Chosen: $continueOrStop" "REMARK"
	Logging ""

	# Any Confirmation Not Equal To CONTINUE Will Abort The Script
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		# Mail The Log File With The Results
		If ($argsCount -gt 0 -And $sendMailWithLogFile) {
			Logging "" "WARNING"
			Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "WARNING"
			Logging "  - TO: '$mailToRecipient'..." "WARNING"
			If ($mailCcRecipients.Length -gt 0) {
				$mailCcRecipients | ForEach-Object {
					Logging "  - CC: '$($_)'..." "WARNING"
				}
			}
			Logging "" "WARNING"

			$mailAttachments = @()
			$mailAttachments += $logFilePath
			sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
		}

		EXIT
	}

	# Retrieve The FQDN Of The RWDC With The PDC FSMO To Create The TEST/BOGUS KrbTgt Account Objects
	$targetedADdomainSourceRWDCFQDN = $null
	$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Host Name"

	# Determine The KrbTgt Account In Use By The RWDC with The PDC FSMO (Representative For All RWDCs In The AD Domain)
	$krbTgtSamAccountName = $null
	$krbTgtSamAccountName = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Krb Tgt"
	Logging "+++++" "REMARK"
	Logging "+++ Create Test KrbTgt Account...: '$krbTgtSamAccountName' +++" "REMARK"
	Logging "+++ Used By RWDC.................: 'All RWDCs' +++" "REMARK"
	Logging "+++++" "REMARK"
	Logging "" "REMARK"

	# Execute The Creation Test KrbTgt Accounts Function To Create The TEST/BOGUS KrbTgt Account For RWDCs
	createTestKrbTgtADAccount $targetedADdomainSourceRWDCFQDN $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName "RWDC" $targetedADdomainDomainSID $localADforest $adminCrds

	# For All RODCs In The AD Domain That Do Not Have An Unknown RWDC Specfied
	$tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -ne "Unknown"} | ForEach-Object {
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
		Logging "+++++" "REMARK"
		Logging "+++ Create Test KrbTgt Account...: '$krbTgtSamAccountName' +++" "REMARK"
		Logging "+++ Used By RODC.................: '$rodcFQDNTarget' (Site: $rodcSiteTarget) +++" "REMARK"
		Logging "+++++" "REMARK"
		Logging "" "REMARK"

		# Execute The Create Test KrbTgt Accounts Function To Create The TEST/BOGUS KrbTgt Account For Each RODC
		createTestKrbTgtADAccount $targetedADdomainSourceRWDCFQDN $rodcFQDNTarget $krbTgtSamAccountName "RODC" $targetedADdomainDomainSID $localADforest $adminCrds
	}
}

###
# Mode 9 - Cleanup TEST KrbTgt Accounts
###
If ($modeOfOperationNr -eq 9) {
	Logging "------------------------------------------------------------------------------------------------------------------------------------------------------" "HEADER"
	Logging "CLEANUP TEST KRBTGT ACCOUNTS (MODE 9)..." "HEADER"
	Logging ""

	# Asking Confirmation To Continue Or Not
	Logging "Do you really want to continue and execute 'Mode $modeOfOperationNr'? [CONTINUE | STOP]: " "ACTION-NO-NEW-LINE"
	$continueOrStop = Read-Host

	# Any Confirmation Not Equal To CONTINUE Will Be Equal To STOP
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		$continueOrStop = "STOP"
	}
	Logging ""
	Logging "  --> Chosen: $continueOrStop" "REMARK"
	Logging ""

	# Any Confirmation Not Equal To CONTINUE Will Abort The Script
	If ($continueOrStop.ToUpper() -ne "CONTINUE") {
		# Mail The Log File With The Results
		If ($argsCount -gt 0 -And $sendMailWithLogFile) {
			Logging "" "WARNING"
			Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "WARNING"
			Logging "  - TO: '$mailToRecipient'..." "WARNING"
			If ($mailCcRecipients.Length -gt 0) {
				$mailCcRecipients | ForEach-Object {
					Logging "  - CC: '$($_)'..." "WARNING"
				}
			}
			Logging "" "WARNING"

			$mailAttachments = @()
			$mailAttachments += $logFilePath
			sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
		}

		EXIT
	}

	# Retrieve The FQDN Of The RWDC With The PDC FSMO To Delete The TEST/BOGUS KrbTgt Account Objects
	$targetedADdomainSourceRWDCFQDN = $null
	$targetedADdomainSourceRWDCFQDN = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Host Name"

	# Determine The KrbTgt Account In Use By The RWDC with The PDC FSMO (Representative For All RWDCs In The AD Domain)
	$krbTgtSamAccountName = $null
	$krbTgtSamAccountName = ($tableOfDCsInADDomain | Where-Object{$_.PDC -eq $True})."Krb Tgt"
	Logging "+++++" "REMARK"
	Logging "+++ Delete Test KrbTgt Account...: '$krbTgtSamAccountName' +++" "REMARK"
	Logging "+++ Used By RWDC.................: 'All RWDCs' +++" "REMARK"
	Logging "+++++" "REMARK"
	Logging "" "REMARK"

	# Execute The Delete Test KrbTgt Accounts Function To Delete The TEST/BOGUS KrbTgt Account For RWDCs. There Is No Need To Force Deletion Of The Object On All The Other DCs As In Time It Will Be Deleted
	deleteTestKrbTgtADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $localADforest $adminCrds

	# For All RODCs In The AD Domain That Do Not Have An Unknown RWDC Specfied
	$tableOfDCsInADDomain | Where-Object{$_."DS Type" -eq "Read-Only" -And $_."Source RWDC FQDN" -ne "Unknown"} | ForEach-Object {
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
		Logging "+++++" "REMARK"
		Logging "+++ Delete Test KrbTgt Account...: '$krbTgtSamAccountName' +++" "REMARK"
		Logging "+++ Used By RODC.................: '$rodcFQDNTarget' (Site: $rodcSiteTarget) +++" "REMARK"
		Logging "+++++" "REMARK"
		Logging "" "REMARK"

		# Execute The Delete Test KrbTgt Accounts Function To Delete The TEST/BOGUS KrbTgt Account For Each RODC. There Is No Need To Force Deletion Of The Object On All The Other DCs As In Time It Will Be Deleted
		deleteTestKrbTgtADAccount $targetedADdomainSourceRWDCFQDN $krbTgtSamAccountName $localADforest $adminCrds
	}
}

# Display The Full Path To The Log File
Logging ""
Logging "Log File Path...: $logFilePath" "REMARK"
Logging ""

# Mail The Log File With The Results
If ($argsCount -gt 0 -And $sendMailWithLogFile) {
	Logging "" "REMARK"
	Logging "The Log File '$logFilePath' Has Been Mailed To The Following Recipients..." "REMARK"
	Logging "  - TO: '$mailToRecipient'..." "REMARK"
	If ($mailCcRecipients.Length -gt 0) {
		$mailCcRecipients | ForEach-Object {
			Logging "  - CC: '$($_)'..." "REMARK"
		}
	}
	Logging "" "REMARK"

	$mailAttachments = @()
	$mailAttachments += $logFilePath
	sendMailMessage $smtpServer $smtpPort $smtpCredsUserName $smtpCredsPassword $mailFromSender $mailToRecipient $mailCcRecipients $mailPriority $mailSubject $mailBody $mailAttachments $mailSignAndEncryptDllFile $mailSign $mailSignAndEncryptCertLocation $mailSignAndEncryptCertThumbprint $mailSignAndEncryptCertPFXFile $mailSignAndEncryptCertPFXPassword $mailEncrypt $mailEncryptCertLocation $mailEncryptCertThumbprint $mailEncryptCertCERFile
}