###
# Parameters Used By Script
###
Param (
	[Parameter(Mandatory=$False)]
	[switch]$skipFileCount,

	[Parameter(Mandatory=$False)]
	[string]$targetDomainFQDN,

	[Parameter(Mandatory=$False)]
	[string]$targetReplFolder,

	[Parameter(Mandatory=$False)]
	[ValidatePattern("^(Fsmo|Discover|(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]*?\.[\d]+?)(?<=[\w\-]{2,})(?<![\w\-]{25}))$")]
	[string]$targetReplMember
)

###
# Version Of Script
###
$version = "v0.7, 2024-07-30"

<#
	AUTHOR
		Written By....................: Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]
		Re-Written By.................: N.A.
		Company.......................: IAMTEC >> Identity | Security | Recovery [https://www.iamtec.eu/]
		Blog..........................: Jorge's Quest For Knowledge [http://jorgequestforknowledge.wordpress.com/]
		For Feedback/Questions........: scripts.gallery@iamtec.eu
			--> Please Describe Your Scenario As Best As Possible With As Much Detail As Possible.
			--> If Applicable Describe What Does and/Or Does Not Work.
			--> If Applicable Describe What Should Be/Work Different And Explain Why/How.
			--> Please Add Screendumps.

	ORIGINAL SOURCE(S)
		- https://github.com/zjorz/Public-AD-Scripts/blob/master/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1

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
		- N.A.

	RELEASE NOTES
		v0.7, 2024-07-30, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Bug Fix: Fixed case sensitivity bug when specifying a DFR Replicated Folder Name through the command line
			- Bug Fix: Fixed case sensitivity bug when specifying a Domain FQDN through the command line

		v0.6, 2024-02-06, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Code Improvement: Changed the function "getDFSRReplGroupMembers" to not use a GC, but instead use a RWDC from the respective AD domain of the object that is being looked for
			- Code Improvement: When discovering a member, added a check to choose a member with a writable copy of the replicated folder
			- Improved User Experience: Added a check to determine if there are Temporary Canary Object leftovers from previous executions of the script that were not cleaned up because the script was aborted or it crashed
			- Improved User Experience: Changed the timing column from "Time" to "TimeDiscvrd" (Time Discovered) which specifies how much time it took to find/see the file on the member of the replicated folder
			- Improved User Experience: The AD domain list presented is now consistently presented in the same order
			- Bug Fix: Fixed the unc path for the folder when SYSVOL is still using NTFRS. Temporary Canary File is now created in the Scripts folder (SYSVOL only!)
			- Bug Fix: When not using SYSVOL as replicated folder, fixed the Member to target for checking the existence of the Temporary Canary File
			- Bug Fix: Changed the variable name of the unc path for the folder on the source from $uncPathFolder to $uncPathFolderSource, to also target the correct (source) Member for cleanup of the file

		v0.5, 2024-01-31, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Script Improvement: Complete rewrite of the script
			- New Feature: Parameters added to support automation
			- New Feature: Logging Function
			- New Feature: Support for all replicated folders (SYSVOL and Custom), replicated either through NTFRS or DFSR
			- New Feature: File count across each member (enabled by default), can be disabled with parameter
			- Code Improvement: As target member use specific role owner hosting the PDC FSMO (SYSVOL only!), disccovered member, specific member

		v0.4, 2014-02-11, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Code Improvement: Added additional logic to determine if a DC is either an RWDC or RODC when it fails using the first logic and changed the layout a little bit

		v0.3, 2014-02-09, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Bug Fix: Solved a bug with regards to the detection/location of RWDCs and RODCs

		v0.2, 2014-02-01, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- New Feature: Updated to also work on W2K3
			- New Feature: Added STOP option
			- Code Improvement: Added few extra columns to output extra info of DCs,
			- Code Improvement: Better detection of unavailable DCs/GCs
			- Code Improvement: Added screen adjustment section

		v0.1, 2013-03-02, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Initial version of the script
#>

<#
.SYNOPSIS
	This PoSH Script Checks The File Replication Latency/Convergence For Replicated Folders (SYSVOL And Custom) Using Either NTFRS Or DFSR.

.DESCRIPTION
    This PoSH Script Checks The File Replication Latency/Convergence For Replicated Folders (SYSVOL And Custom) Using Either NTFRS Or DFSR.
	This PoSH script provides the following functions:
	- It executes on a per replicated folder basis. For multiple replicated folder use automation with parameters.
	- For automation, it is possible to define the FQDN of the AD Domain to target, the name of the replica set (NTFRS) or the name of the replicated folder (DFSR) within that AD domain, and the member to use as the source member to create the temoporary canary file on.
	- It supports non-interacive mode through automation with parameters, or interactive mode.
	- It supports file replication convergence check for any replica set (NTFRS) or replicated folder (DFSR) within an AD forest.
	- As the source member, it is possible to:
		- Use the FSMO of the AD Domain, when it concerns the SYSVOL only.
		- Use a discovered member (best effort).
		- Specify the FQDN of a member that hosts the replica set (NTFRS) or the replicated folder (DFSR).
	- For the temporary canary file:
		- Initially created on the source member and deleted from the source member at the end
		- Name            = _fileReplConvergenceCheckTempFile_yyyyMMddHHmmss (e.g. _fileReplConvergenceCheckTempFile_20240102030405)
		- Content         = ...!!!...TEMP FILE TO TEST REPLICATION LATENCY/CONVERGENCE FOR REPLICATED FOLDER <REPLICA SET NAME (NTFRS) OR REPLICATED FOLDER NAME (DFSR)> IN AD DOMAIN <AD DOMAIN FQDN> USING MEMBER <SOURCE MEMBER> AS THE SOURCE MEMBER...!!!...
		- Folder:
			- For custom replicated folders    => Folder = At the root of the folder
			- For SYSVOL                       => Folder = "<SYSVOL LOCAL PATH>\Scripts"
	- All is displayed on screen using different colors depending on what is occuring. The same thing is also logged to a log file without colors.
	- It checks if specified replica set (NTFRS) or replicated folder (DFSR) exists. If not, the script aborts.
	- It checks if specified member exists. If not, the script aborts.
	- At the end it checks if any Temporary Canary Files exist from previous execution of the script and offers to clean up (In the chosen Replicated Folder only!).
	- Disjoint namespaces and discontiguous namespaces are supported.
	- During interactive mode, after specifying the source member, it will count the files in the replicated folder on every member by default. This can be disabled through a parameter.

.PARAMETER skipFileCount
	With this parameter it is possible not count files in the replicated folder on every member

.PARAMETER targetDomainFQDN
	With this parameter it is possible to specify the FQDN of an AD domain to target for File Replication Convergence/Latency check against a chosen replica set (NTFRS) or the replicated folder (DFSR) within that AD domain

.PARAMETER targetReplFolder
	With this parameter it is possible to specify the name of the replica set (NTFRS) or the replicated folder (DFSR) within the chosen AD domain to target for the File Replication Convergence/Latency check

.PARAMETER targetReplMember
	With this parameter it is possible to specify the member to use to create the temporary canary file on. Options that are available for this are "Fsmo" (SYSVOL only!), "Discover" or the FQDN of a member

.EXAMPLE
	Check The File Replication Convergence/Latency Using Interactive Mode (Including File Count)

	.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1

.EXAMPLE
	Check The File Replication Convergence/Latency Using Interactive Mode (Excluding File Count)

	.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -skipFileCount

.EXAMPLE
	Check The File Replication Convergence/Latency Using Automated Mode For The SYSVOL Replicated Through NTFRS Using The Fsmo Role Owner As The Source Member To Create The Temporary Canary File On (Including File Count)

	.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "Domain System Volume (SYSVOL share)" -targetReplMember Fsmo

.EXAMPLE
	Check The File Replication Convergence/Latency Using Automated Mode For The SYSVOL Replicated Through DFSR Using The Fsmo Role Owner As The Source Member To Create The Temporary Canary File On (Including File Count)

	.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "SYSVOL Share" -targetReplMember Fsmo

.EXAMPLE
	Check The File Replication Convergence/Latency Using Automated Mode For The Replicated Folder "LPPStoreForAD" Using A Discovered Member As The Source Member To Create The Temporary Canary File On (Including File Count)

	.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "LPPStoreForAD" -targetRWDC Discover

.EXAMPLE
	Check The File Replication Convergence/Latency Using Automated Mode For The Replicated Folder "LPPStoreForAD" Using A Specific Member As The Source Member To Create The Temporary Canary File On (Including File Count)

	.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "LPPStoreForAD" -targetRWDC "R1FSRWDC1.IAMTEC.NET"

.EXAMPLE
	Check The File Replication Convergence/Latency Using Automated Mode For The SYSVOL Replicated Through NTFRS Using The Fsmo Role Owner As The Source Member To Create The Temporary Canary File On (Excluding File Count)

	.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "Domain System Volume (SYSVOL share)" -targetReplMember Fsmo -skipFileCount

.EXAMPLE
	Check The File Replication Convergence/Latency Using Automated Mode For The SYSVOL Replicated Through DFSR Using The Fsmo Role Owner As The Source Member To Create The Temporary Canary File On (Excluding File Count)

	.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "SYSVOL Share" -targetReplMember Fsmo -skipFileCount

.EXAMPLE
	Check The File Replication Convergence/Latency Using Automated Mode For The Replicated Folder "LPPStoreForAD" Using A Discovered Member As The Source Member To Create The Temporary Canary File On (Excluding File Count)

	.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "LPPStoreForAD" -targetRWDC Discover -skipFileCount

.EXAMPLE
	Check The File Replication Convergence/Latency Using Automated Mode For The Replicated Folder "LPPStoreForAD" Using A Specific Member As The Source Member To Create The Temporary Canary File On (Excluding File Count)

	.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "LPPStoreForAD" -targetRWDC "R1FSRWDC1.IAMTEC.NET" -skipFileCount

.NOTES
	- To execute this script, the account running the script MUST have the permissions to create and delete the file in the local folder of the source member through the drive share (C$, D$, etc). Being a local admin on all
		the member allows, the creation, deletion and monitoring of the file
	- The credentials used are the credentials of the logged on account. It is not possible to provided other credentials. Other credentials could maybe be used through RUNAS /NETONLY /USER
	- No check is done for the required permissions
	- No PowerShell modules are needed to use this script
	- For the SYSVOL, it only works correctly when either using NTFRS, or DFSR in a completed state!
	- Admin shares must be enabled
	- For File Count, WinRM must be possible against the remote machines
	- Yes, I'm aware, there is duplicate code to support both NTFRS and DFSR. This was the easiest way to support both without too much complexity. It also allows to remove it easily when NTFRS cannot be used anymore
#>

###
# Functions Used In Script
###
### FUNCTION: Logging Data To The Log File
Function writeLog {
	Param(
		[string]$dataToLog,
		[string]$lineType,
		[bool]$logFileOnly,
		[bool]$noDateTimeInLogLine
	)

	$dateTime = Get-Date
	$datetimeLocal = $(Get-Date $dateTime -format "yyyy-MM-dd HH:mm:ss")							# Local Time
	$datetimeUniversal = $(Get-Date $dateTime.ToUniversalTime() -format "yyyy-MM-dd HH:mm:ss")		# Universal Time
	$datetimeLogLine = "[UT:" + $datetimeUniversal + " | LT:" + $datetimeLocal + "] : "
	If ($noDateTimeInLogLine -eq $true) {
		Out-File -filepath "$scriptLogFullPath" -append -inputObject "$dataToLog"
	}
	If ($noDateTimeInLogLine -eq $false) {
		Out-File -filepath "$scriptLogFullPath" -append -inputObject "$datetimeLogLine$dataToLog"
	}
	If ($logFileOnly -eq $false) {
		If ($lineType -eq "") {
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

### FUNCTION: Test The Port Connection
Function portConnectionCheck {
	Param (
		$fqdnServer,
		$port,
		$timeOut
	)

	# Test To See If The HostName Is Resolvable At All
	$status = "OK"
	Try {
		[System.Net.Dns]::GetHostEntry($fqdnServer) | Out-Null
	} Catch {
		$status = "NOK"
	}

	If ($status -eq "OK") {
		$tcpPortSocket = $null
		$tcpPortSocket = New-Object System.Net.Sockets.TcpClient
		$portConnect = $null
		$portConnect = $tcpPortSocket.BeginConnect($fqdnServer, $port, $null, $null)
		$tcpPortWait = $null
		$tcpPortWait = $portConnect.AsyncWaitHandle.WaitOne($timeOut, $false)
		If (!$tcpPortWait) {
			$tcpPortSocket.Close()
			$returnStatus = "ERROR"
		} Else {
			$ErrorActionPreference = "SilentlyContinue"
			$tcpPortSocket.EndConnect($portConnect) | Out-Null
			If (!$?) {
				$returnStatus = "ERROR"
			} Else {
				$returnStatus = "SUCCESS"
			}
			$tcpPortSocket.Close()
			$ErrorActionPreference = "Continue"
		}
	} Else {
		$returnStatus = "ERROR"
	}
	Return $returnStatus
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

### FUNCTION: Locate An RWDC
Function locateRWDC {
	Param (
		$fqdnADdomain
	)

	# Locate An RWDC In The Specified AD Domain
	$dcLocatorFlag = [System.DirectoryServices.ActiveDirectory.LocatorOptions]::"ForceRediscovery", "WriteableRequired"
	$adDomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $fqdnADdomain)
	$adDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($adDomainContext)
	$rwdcFQDN = $adDomain.FindDomainController($dcLocatorFlag).Name

	Return $rwdcFQDN
}

### FUNCTION: Convert NTDS Settings Object DN Of A DC To An FQDN Of A DC
Function convertNTDSSettingsObjectDNToFQDN {
	Param (
		$rwdcFQDN,
		$ntdsSettingsObjectDN
	)

	$serverObjectDN = $ntdsSettingsObjectDN.Replace("CN=NTDS Settings,","")

	Try {
		$searchRootServerObject = [ADSI]"LDAP://$rwdcFQDN/$serverObjectDN"
		$searcherServerObject = New-Object System.DirectoryServices.DirectorySearcher($searchRootServerObject)
		$serverObject = $searcherServerObject.FindOne()
		$dNSHost = $serverObject.Properties.dnshostname[0]
	} Catch {
		$dNSHost = "FAIL - NOT VALID"
	}

	Return $dNSHost
}

### FUNCTION: Retrieve The DFS-R Replication Group In The AD Domain
Function getDFSRReplGroupsAndFoldersInADDomain {
	Param (
		$adDomainDN,
		$rwdcFQDN
	)

	$dfsrReplContentSetList = @()

	$searchbase = "CN=DFSR-GlobalSettings,CN=System,$adDomainDN"
	$searchRootReplContentSets = [ADSI]"LDAP://$rwdcFQDN/$searchbase"
	$searcherReplContentSets = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplContentSets)
	$searcherReplContentSets.Filter = "(objectClass=msDFSR-ContentSet)"
	$searcherReplContentSets.PropertiesToLoad.Add("distinguishedName") | Out-Null
	$searcherReplContentSets.PropertiesToLoad.Add("name") | Out-Null
	$searcherReplContentSets.PropertiesToLoad.Add("objectGuid") | Out-Null
	$dfsrReplContentSets = $searcherReplContentSets.FindAll()

	$dfsrReplContentSets | ForEach-Object{
		$dfsrReplContentSetReplgroupName = $($_.Properties.distinguishedname[0]).Replace($searchbase,"").Trim(",").Split(",")[-1].Replace("CN=","")

		$dfsrReplContentSetName = $($_.Properties.name[0])

		If ($dfsrReplContentSetReplgroupName -eq "Domain System Volume") {
			$dfsrReplContentSetGuid = "SYSVOL Subscription"
		} Else {
			$dfsrReplContentSetGuid = $((New-Object Guid @(,$($_.Properties.objectguid))).Guid)
		}

		$dfsrReplContentSetEntry = New-Object -TypeName System.Object
		$dfsrReplContentSetEntry | Add-Member -MemberType NoteProperty -Name "Domain DN" -Value $adDomainDN
		$dfsrReplContentSetEntry | Add-Member -MemberType NoteProperty -Name "Repl Group Name" -Value $dfsrReplContentSetReplgroupName
		$dfsrReplContentSetEntry | Add-Member -MemberType NoteProperty -Name "Repl Folder Name" -Value $dfsrReplContentSetName
		$dfsrReplContentSetEntry | Add-Member -MemberType NoteProperty -Name "Repl Folder Guid" -Value $dfsrReplContentSetGuid
		$dfsrReplContentSetEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value "DFSR"
		$dfsrReplContentSetList += $dfsrReplContentSetEntry
	}

	Return $dfsrReplContentSetList
}

### FUNCTION: Retrieve The DFS-R Replication Group Members
Function getDFSRReplGroupMembers {
	Param (
		$adDomainDN,
		$rwdcFQDN,
		$dfsrReplGroupName,
		$domainsAndDCsHT
	)

	$dfsrReplGroupMemberList = @()

	$searchRootReplGroupMemberRefs = [ADSI]"LDAP://$rwdcFQDN/CN=Topology,CN=$dfsrReplGroupName,CN=DFSR-GlobalSettings,CN=System,$adDomainDN"
	$searcherReplGroupMemberRefs = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplGroupMemberRefs)
	$searcherReplGroupMemberRefs.Filter = "(objectClass=msDFSR-Member)"
	$searcherReplGroupMemberRefs.PropertiesToLoad.Add("distinguishedName") | Out-Null
	$searcherReplGroupMemberRefs.PropertiesToLoad.Add("msDFSR-ComputerReference") | Out-Null
	$searcherReplGroupMemberRefs.PropertiesToLoad.Add("name") | Out-Null
	$dfsrReplGroupMemberRefs = $searcherReplGroupMemberRefs.FindAll()

	$dfsrReplGroupMemberRefs | ForEach-Object{
		$dfsrReplGroupMemberRefDN = $_.Properties."msdfsr-computerreference"[0]

		$dfsrReplGroupMemberRefComputerName = $dfsrReplGroupMemberRefDN.Substring(3, $dfsrReplGroupMemberRefDN.IndexOf(",") - 3)

		# Only In The Case Of SYSVOL DFS-R Replication Group
		If ($_.Properties.name[0] -eq $dfsrReplGroupMemberRefComputerName){
			$dfsrReplGroupMemberNameGuid = "$dfsrReplGroupMemberRefComputerName|Domain System Volume"
		} Else {
			$dfsrReplGroupMemberNameGuid = $_.Properties.name[0]
		}

		$searchRootReplGroupMemberCompAccount = [ADSI]"LDAP://$($domainsAndDCsHT[$($dfsrReplGroupMemberRefDN.SubString($dfsrReplGroupMemberRefDN.IndexOf("DC=")))])/$dfsrReplGroupMemberRefDN"
		$searcherReplGroupMemberCompAccount = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplGroupMemberCompAccount)
		$searcherReplGroupMemberCompAccount.PropertiesToLoad.Add("dNSHostName") | Out-Null
		$replGroupMemberCompAccount = $searcherReplGroupMemberCompAccount.FindOne()
		$dfsrReplGroupMemberRefFQDN = $replGroupMemberCompAccount.Properties.dnshostname[0]

		$dfsrReplGroupMemberEntry = New-Object -TypeName System.Object
		$dfsrReplGroupMemberEntry | Add-Member -MemberType NoteProperty -Name "MemberGuidName" -Value $dfsrReplGroupMemberNameGuid
		$dfsrReplGroupMemberEntry | Add-Member -MemberType NoteProperty -Name "ComputerReferenceDN" -Value $dfsrReplGroupMemberRefDN
		$dfsrReplGroupMemberEntry | Add-Member -MemberType NoteProperty -Name "DNSHostName" -Value $dfsrReplGroupMemberRefFQDN
		$dfsrReplGroupMemberList += $dfsrReplGroupMemberEntry
	}

	Return $dfsrReplGroupMemberList
}

### FUNCTION: Retrieve The DFS-R Replicated Folder Config And State
Function getDFSRReplFolderConfigAndState {
	Param (
		$dfsrReplGroupName,
		$dfsrReplGroupMemberList,
		$dfsrReplGroupContentSetName,
		$dfsrReplGroupContentSetGuid,
		$domainsAndDCsHT
	)

	$dfsrReplFolderConfigAndStateList = @()

	$dfsrReplGroupMemberList | ForEach-Object{
		$dfsrReplGroupMemberFQDN = $_.DNSHostName

		$dfsrReplGroupMemberRefDN = $_.ComputerReferenceDN

		$dfsrReplGroupMemberGuidName = $_.MemberGuidName

		$dfsrReplGroupMemberRefADDomainRWDC = $($domainsAndDCsHT[$($dfsrReplGroupMemberRefDN.SubString($dfsrReplGroupMemberRefDN.IndexOf("DC=")))])

		Try {
			$dfsrReplGroupMemberIPv4 = ([System.Net.Dns]::GetHostEntry($dfsrReplGroupMemberFQDN).AddressList | Where-Object{$_.AddressFamily -eq "InterNetwork"}).IPAddressToString
		} Catch {
			$dfsrReplGroupMemberIPv4 = "<FAIL>"
		}

		$dfsrReplGroupMemberSiteNLTEST = NLTEST.EXE /DSGETSITE /SERVER:$dfsrReplGroupMemberFQDN 2>$null
		If (-not [String]::IsNullOrEmpty($dfsrReplGroupMemberSiteNLTEST)) {
			$dfsrReplGroupMemberSite = $dfsrReplGroupMemberSiteNLTEST[0]
		} Else {
			$dfsrReplGroupMemberSite = "<FAIL>"
		}

		$searchRootReplGroupMember = [ADSI]"LDAP://$dfsrReplGroupMemberRefADDomainRWDC/$dfsrReplGroupMemberRefDN"
		$searcherReplGroupMember = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplGroupMember)
		$searcherReplGroupMember.PropertiesToLoad.Add("operatingSystem") | Out-Null
		$searcherReplGroupMember.PropertiesToLoad.Add("operatingSystemVersion") | Out-Null
		$replGroupMemberObject = $searcherReplGroupMember.FindOne()
		If (-not [String]::IsNullOrEmpty($replGroupMemberObject.Properties.operatingsystem)) {
			$dfsrReplGroupMemberOS = $replGroupMemberObject.Properties.operatingsystem[0]
		} Else {
			$dfsrReplGroupMemberOS = "<UNKNOWN>"
		}
		If (-not [String]::IsNullOrEmpty($replGroupMemberObject.Properties.operatingsystemversion)) {
			$dfsrReplGroupMemberOSVersion = $replGroupMemberObject.Properties.operatingsystemversion[0]
		} Else {
			$dfsrReplGroupMemberOSVersion = "<UNKNOWN>"
		}

		$dfsrReplGroupMemberReachable = $(If ($(portConnectionCheck -fqdnServer $dfsrReplGroupMemberFQDN -port $smbPort -timeOut $connectionTimeout) -eq "SUCCESS") {$true} Else {$false})

		If ($dfsrReplGroupMemberGuidName -like "*Domain System Volume") {
			$dfsrReplGroupMemberGuidName = $dfsrReplGroupMemberGuidName.Split("|")[1]
		}

		If ($(-not [String]::IsNullOrEmpty($dfsrReplGroupMemberRefDN)) -And $(-not [String]::IsNullOrEmpty($dfsrReplGroupMemberGuidName)) -And $(-not [String]::IsNullOrEmpty($dfsrReplGroupContentSetGuid))) {
			$dfsrReplGroupMemberSubscriptionDN = "CN=" + $dfsrReplGroupContentSetGuid + ",CN=" + $dfsrReplGroupMemberGuidName + ",CN=DFSR-LocalSettings," + $($dfsrReplGroupMemberRefDN)
		} Else {
			$dfsrReplGroupMemberSubscriptionDN = $null
		}

		$searchRootReplFolderSubscription = [ADSI]"LDAP://$dfsrReplGroupMemberRefADDomainRWDC/$dfsrReplGroupMemberSubscriptionDN"
		$searcherReplFolderSubscription = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplFolderSubscription)
		$searcherReplFolderSubscription.PropertiesToLoad.Add("msDFSR-Enabled") | Out-Null
		$searcherReplFolderSubscription.PropertiesToLoad.Add("msDFSR-RootPath") | Out-Null
		$searcherReplFolderSubscription.PropertiesToLoad.Add("msDFSR-ReadOnly") | Out-Null
		Try {
			$replFolderSubscriptionObject = $searcherReplFolderSubscription.FindOne()
		} Catch {
			$replFolderSubscriptionObject = $null
		}

		If (-not [String]::IsNullOrEmpty($replFolderSubscriptionObject.Properties."msdfsr-rootpath")) {
			$dfsrReplGroupMemberFolderPath = $($replFolderSubscriptionObject.Properties."msdfsr-rootpath"[0])
		} Else {
			$dfsrReplGroupMemberFolderPath = "<UNKNOWN>"
		}

		If (-not [String]::IsNullOrEmpty($replFolderSubscriptionObject.Properties."msdfsr-enabled") -And $($replFolderSubscriptionObject.Properties."msdfsr-enabled"[0]) -eq $true) {
			$dfsrReplGroupMemberFolderState = "Enabled"
		} ElseIf (-not [String]::IsNullOrEmpty($replFolderSubscriptionObject.Properties."msdfsr-enabled") -And $($replFolderSubscriptionObject.Properties."msdfsr-enabled"[0]) -eq $false) {
			$dfsrReplGroupMemberFolderState = "Disabled"
		} Else {
			$dfsrReplGroupMemberFolderState = "<UNKNOWN>"
		}

		If (-not [String]::IsNullOrEmpty($replFolderSubscriptionObject.Properties."msdfsr-readonly") -And $($replFolderSubscriptionObject.Properties."msdfsr-readonly"[0]) -eq $true) {
			$dfsrReplGroupMemberFolderType = "RO"
		} ElseIf (-not [String]::IsNullOrEmpty($replFolderSubscriptionObject.Properties."msdfsr-readonly") -And $($replFolderSubscriptionObject.Properties."msdfsr-readonly"[0]) -eq $false) {
			$dfsrReplGroupMemberFolderType = "RW"
		} Else {
			$dfsrReplGroupMemberFolderType = "<UNKNOWN>"
		}

		$dfsrReplFolderConfigAndStateEntry = New-Object -TypeName System.Object
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Repl Group Name" -Value $dfsrReplGroupName
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Repl Folder Name" -Value $dfsrReplGroupContentSetName
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Member FQDN" -Value $dfsrReplGroupMemberFQDN
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Member IPv4" -Value $dfsrReplGroupMemberIPv4
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $dfsrReplGroupMemberSite
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Member OS" -Value $($dfsrReplGroupMemberOS + "|" + $dfsrReplGroupMemberOSVersion)
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $dfsrReplGroupMemberReachable
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Repl Folder Path" -Value $dfsrReplGroupMemberFolderPath
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "State" -Value $dfsrReplGroupMemberFolderState
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $dfsrReplGroupMemberFolderType
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "File Count" -Value $null
		$dfsrReplFolderConfigAndStateList += $dfsrReplFolderConfigAndStateEntry
	}

	Return $dfsrReplFolderConfigAndStateList
}

### FUNCTION: Retrieve The NTFRS Replica Sets In The AD Domain
Function getNTFRSReplicaSetsInADDomain {
	Param (
		$adDomainDN,
		$rwdcFQDN
	)

	$ntfrsReplicaSetList = @()

	$searchbase = "CN=File Replication Service,CN=System,$adDomainDN"
	$searchRootReplicaSets = [ADSI]"LDAP://$rwdcFQDN/$searchbase"
	$searcherReplicaSets = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplicaSets)
	$searcherReplicaSets.Filter = "(objectClass=nTFRSReplicaSet)"
	$searcherReplicaSets.PropertiesToLoad.Add("distinguishedName") | Out-Null
	$searcherReplicaSets.PropertiesToLoad.Add("name") | Out-Null
	$searcherReplicaSets.PropertiesToLoad.Add("msDS-Approx-Immed-Subordinates") | Out-Null	# In Some Environments The Replica Set "Domain System Volume (SYSVOL share)" Might Still Exist While DFSR Is Already Being Used. If The Replica Set DOES NOT Contain Subobjects, Then DFSR Is Assumed To Be Used
	#$searcherReplicaSets.PropertiesToLoad.Add("fRSReplicaSetGUID") | Out-Null
	$ntfrsReplicaSets = $searcherReplicaSets.FindAll()

	$ntfrsReplicaSets | Where-Object {$_.Properties."msds-approx-immed-subordinates"[0] -gt 0} | ForEach-Object{
		$ntfrsReplicaSetName = $($_.Properties.name[0])

		#$ntfrsReplicaSetGuid = $((New-Object Guid @(,$($_.Properties.frsreplicasetguid))).Guid)

		$ntfrsReplicaSetEntry = New-Object -TypeName System.Object
		$ntfrsReplicaSetEntry | Add-Member -MemberType NoteProperty -Name "Domain DN" -Value $adDomainDN
		$ntfrsReplicaSetEntry | Add-Member -MemberType NoteProperty -Name "Repl Set Name" -Value $ntfrsReplicaSetName
		#$ntfrsReplicaSetEntry | Add-Member -MemberType NoteProperty -Name "Repl Set Guid" -Value $ntfrsReplicaSetGuid
		$ntfrsReplicaSetEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value "NTFRS"
		$ntfrsReplicaSetList += $ntfrsReplicaSetEntry
	}

	Return $ntfrsReplicaSetList
}

### FUNCTION: Retrieve The NTFRS ReplicaSet Members
Function getNTFRSReplSetMembers {
	Param (
		$adDomainDN,
		$rwdcFQDN,
		$ntfrsReplicaSetName
	)

	$ntfrsReplSetMemberList = @()

	$searchRootReplSetMemberRefs = [ADSI]"LDAP://$rwdcFQDN/CN=$ntfrsReplicaSetName,CN=File Replication Service,CN=System,$adDomainDN"
	$searcherReplSetMemberRefs = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplSetMemberRefs)
	$searcherReplSetMemberRefs.Filter = "(objectClass=nTFRSMember)"
	$searcherReplSetMemberRefs.PropertiesToLoad.Add("distinguishedName") | Out-Null
	$searcherReplSetMemberRefs.PropertiesToLoad.Add("frsComputerReference") | Out-Null
	$searcherReplSetMemberRefs.PropertiesToLoad.Add("name") | Out-Null
	$ntfrsReplSetMemberRefs = $searcherReplSetMemberRefs.FindAll()

	$ntfrsReplSetMemberRefs | ForEach-Object{
		$ntfrsReplSetMemberRefDN = $_.Properties.frscomputerreference[0]

		$searchRootReplSetMemberCompAccount = [ADSI]"LDAP://$rwdcFQDN/$ntfrsReplSetMemberRefDN"
		$searcherReplSetMemberCompAccount = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplSetMemberCompAccount)
		$searcherReplSetMemberCompAccount.PropertiesToLoad.Add("dNSHostName") | Out-Null
		$searcherReplSetMemberCompAccount.PropertiesToLoad.Add("msDS-isRODC") | Out-Null
		$replSetMemberCompAccount = $searcherReplSetMemberCompAccount.FindOne()
		$ntfrsReplSetMemberRefFQDN = $replSetMemberCompAccount.Properties.dnshostname[0]
		$ntfrsReplSetMemberRefIsRODC = $replSetMemberCompAccount.Properties."msds-isrodc"[0]

		$ntfrsReplSetMemberEntry = New-Object -TypeName System.Object
		$ntfrsReplSetMemberEntry | Add-Member -MemberType NoteProperty -Name "ComputerReferenceDN" -Value $ntfrsReplSetMemberRefDN
		$ntfrsReplSetMemberEntry | Add-Member -MemberType NoteProperty -Name "DNSHostName" -Value $ntfrsReplSetMemberRefFQDN
		$ntfrsReplSetMemberEntry | Add-Member -MemberType NoteProperty -Name "IsRODC" -Value $$ntfrsReplSetMemberRefIsRODC
		$ntfrsReplSetMemberList += $ntfrsReplSetMemberEntry
	}

	Return $ntfrsReplSetMemberList
}

### FUNCTION: Retrieve The NTFRS Replicated Set Config And State
Function getNTFRSReplSetConfigAndState {
	Param (
		$ntfrsReplSetMemberList,
		$ntfrsReplSetName,
		$rwdcFQDN
	)

	$ntfrsReplSetConfigAndStateList = @()

	$ntfrsReplSetMemberList | ForEach-Object{
		$ntfrsReplSetMemberFQDN = $_.DNSHostName

		$ntfrsReplSetMemberRefDN = $_.ComputerReferenceDN

		Try {
			$ntfrsReplSetMemberIPv4 = ([System.Net.Dns]::GetHostEntry($ntfrsReplSetMemberFQDN).AddressList | Where-Object{$_.AddressFamily -eq "InterNetwork"}).IPAddressToString
		} Catch {
			$ntfrsReplSetMemberIPv4 = "<FAIL>"
		}

		$ntfrsReplSetMemberSiteNLTEST = NLTEST.EXE /DSGETSITE /SERVER:$ntfrsReplSetMemberFQDN 2>$null
		If (-not [String]::IsNullOrEmpty($ntfrsReplSetMemberSiteNLTEST)) {
			$ntfrsReplSetMemberSite = $ntfrsReplSetMemberSiteNLTEST[0]
		} Else {
			$ntfrsReplSetMemberSite = "<FAIL>"
		}

		$searchRootReplSetMember = [ADSI]"LDAP://$rwdcFQDN/$ntfrsReplSetMemberRefDN"
		$searcherReplSetMember = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplSetMember)
		$searcherReplSetMember.PropertiesToLoad.Add("operatingSystem") | Out-Null
		$searcherReplSetMember.PropertiesToLoad.Add("operatingSystemVersion") | Out-Null
		$searcherReplSetMember.PropertiesToLoad.Add("msDS-isRODC") | Out-Null
		$replSetMemberObject = $searcherReplSetMember.FindOne()
		If (-not [String]::IsNullOrEmpty($replSetMemberObject.Properties.operatingsystem)) {
			$ntfrsReplSetMemberOS = $replSetMemberObject.Properties.operatingsystem[0]
		} Else {
			$ntfrsReplSetMemberOS = "<UNKNOWN>"
		}
		If (-not [String]::IsNullOrEmpty($replSetMemberObject.Properties.operatingsystemversion)) {
			$ntfrsReplSetMemberOSVersion = $replSetMemberObject.Properties.operatingsystemversion[0]
		} Else {
			$ntfrsReplSetMemberOSVersion = "<UNKNOWN>"
		}
		If (-not [String]::IsNullOrEmpty($replSetMemberObject.Properties."msds-isrodc")) {
			$ntfrsReplSetMemberIsRODC = $replSetMemberObject.Properties."msds-isrodc"[0]
		} Else {
			$ntfrsReplSetMemberIsRODC = "<UNKNOWN>"
		}

		$ntfrsReplSetMemberReachable = $(If ($(portConnectionCheck -fqdnServer $ntfrsReplSetMemberFQDN -port $smbPort -timeOut $connectionTimeout) -eq "SUCCESS") {$true} Else {$false})

		If ($(-not [String]::IsNullOrEmpty($ntfrsReplSetName)) -And $(-not [String]::IsNullOrEmpty($ntfrsReplSetMemberRefDN))) {
			$ntfrsReplSetMemberSubscriberDN = "CN=" + $ntfrsReplSetName + ",CN=NTFRS Subscriptions," + $ntfrsReplSetMemberRefDN
		} Else {
			$ntfrsReplSetMemberSubscriberDN = $null
		}

		$searchRootReplSetSubscriber = [ADSI]"LDAP://$rwdcFQDN/$ntfrsReplSetMemberSubscriberDN"
		$searcherReplSetSubscriber = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplSetSubscriber)
		$searcherReplSetSubscriber.PropertiesToLoad.Add("fRSRootPath") | Out-Null
		Try {
			$replSetSubscriberObject = $searcherReplSetSubscriber.FindOne()
		} Catch {
			$replSetSubscriberObject = $null
		}

		If (-not [String]::IsNullOrEmpty($replSetSubscriberObject.Properties.frsrootpath)) {
			$ntfrsReplSetMemberFolderPath = $($replSetSubscriberObject.Properties.frsrootpath[0])
		} Else {
			$ntfrsReplSetMemberFolderPath = "<UNKNOWN>"
		}

		If ($ntfrsReplSetMemberIsRODC -eq $true) {
			$ntfrsReplSetMemberFolderType = "RO"
		} ElseIf ($ntfrsReplSetMemberIsRODC -eq $false) {
			$ntfrsReplSetMemberFolderType = "RW"
		} Else {
			$ntfrsReplSetMemberFolderType = "<UNKNOWN>"
		}

		$ntfrsReplSetConfigAndStateEntry = New-Object -TypeName System.Object
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Repl Set Name" -Value $ntfrsReplSetName
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Member FQDN" -Value $ntfrsReplSetMemberFQDN
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Member IPv4" -Value $ntfrsReplSetMemberIPv4
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $ntfrsReplSetMemberSite
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Member OS" -Value $($ntfrsReplSetMemberOS + "|" + $ntfrsReplSetMemberOSVersion)
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $ntfrsReplSetMemberReachable
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Repl Folder Path" -Value $ntfrsReplSetMemberFolderPath
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $ntfrsReplSetMemberFolderType
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "File Count" -Value $null
		$ntfrsReplSetConfigAndStateList += $ntfrsReplSetConfigAndStateEntry
	}

	Return $ntfrsReplSetConfigAndStateList
}

###
# Clear The Screen
###
Clear-Host

###
# Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
###
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ CHECKING SYSVOL, DFSR FOLDERS, NTFRS FOLDERS REPLICATION LATENCY/CONVERGENCE +++"
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
$scriptFullPath = $MyInvocation.MyCommand.Definition
$currentScriptFolderPath = Split-Path $scriptFullPath
$getServerNames = getServerNames
$localComputerName = $getServerNames[0]			                            # [0] NetBIOS Computer Name
$fqdnADDomainOfComputer = $getServerNames[1]	                            # [1] FQDN Of The AD Domain The Computer Is A Member Of
$fqdnComputerInADDomain = $getServerNames[2]	                            # [2] FQDN Of The Computer In The AD (!) Domain
$fqdnComputerInDNS = $getServerNames[3]			                            # [3] FQDN Of The Computer In The DNS (!) Domain
$fqdnDnsDomainOfComputer = $getServerNames[4]	                            # [4] FQDN Of The Dns Domain The Computer Is A Part Of
$localComputerSiteName = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
$fqdnADDomainOfComputerContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $fqdnADDomainOfComputer)
$fqdnADForestOfComputer = ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($fqdnADDomainOfComputerContext)).Forest.Name
[string]$scriptLogFullPath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_Check-AD-Replication-Latency-Convergence.log")
$connectionTimeout = 500
$smbPort = 445
$continue = $true

###
# Loading Any Applicable/Required Libraries
###
# N.A.

###
# Execute Any Additional Actions Required For The Script To Run Successfully
###
# N.A.

###
# Start Of Script
###
### Presentation Of Script Header
writeLog -dataToLog ""
writeLog -dataToLog "                                   ************************************************************************" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                   *                                                                      *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                   *    --> Test SYSVOL/DFSR/NTFRS Replication Latency/Convergence <--    *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                   *                                                                      *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                   *                   BLOG: Jorge's Quest For Knowledge                  *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                   *          (URL: http://jorgequestforknowledge.wordpress.com/)         *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                   *                                                                      *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                   *                           $version                           *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                   *                                                                      *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                   ************************************************************************" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

# SOURCE: https://patorjk.com/software/taag/#p=display&f=Graffiti&t=Test%0ASYSVOL%2FFILE%0AReplication%0AConvergence
writeLog -dataToLog "                                                         ___________              __" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                                         \__    ___/___   _______/  |_" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                                           |    |_/ __ \ /  ___/\   __\" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                                           |    |\  ___/ \___ \  |  |" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                                           |____| \___  >____  > |__|" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                                                      \/     \/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                    ______________.___. _____________   ____________  .____          /\ ___________.___.____     ___________" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                   /   _____/\__  |   |/   _____/\   \ /   /\_____  \ |    |        / / \_   _____/|   |    |    \_   _____/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                   \_____  \  /   |   |\_____  \  \   Y   /  /   |   \|    |       / /   |    __)  |   |    |     |    __)_" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                   /        \ \____   |/        \  \     /  /    |    \    |___   / /    |     \   |   |    |___  |        \" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                  /_______  / / ______/_______  /   \___/   \_______  /_______ \ / /     \___  /   |___|_______ \/_______  /" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                          \/  \/              \/                    \/        \/ \/          \/                \/        \/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                    __________              .__  .__               __  .__" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                    \______   \ ____ ______ |  | |__| ____ _____ _/  |_|__| ____   ____" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                     |       _// __ \\____ \|  | |  |/ ___\\__  \\   __\  |/  _ \ /    \" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                     |    |   \  ___/|  |_> >  |_|  \  \___ / __ \|  | |  (  <_> )   |  \" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                     |____|_  /\___  >   __/|____/__|\___  >____  /__| |__|\____/|___|  /" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                            \/     \/|__|                \/     \/                    \/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                 _________" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                 \_   ___ \  ____   _______  __ ___________  ____   ____   ____   ____  ____" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                 /    \  \/ /  _ \ /    \  \/ // __ \_  __ \/ ___\_/ __ \ /    \_/ ___\/ __ \" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                 \     \___(  <_> )   |  \   /\  ___/|  | \/ /_/  >  ___/|   |  \  \__\  ___/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                  \______  /\____/|___|  /\_/  \___  >__|  \___  / \___  >___|  /\___  >___  >" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                         \/            \/          \/     /_____/      \/     \/     \/    \/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

# http://patorjk.com/software/taag/#p=display&f=Graffiti&t=Provided%20By%20IAMTEC
writeLog -dataToLog "        __________                    .__    .___         .___ __________         .___   _____      ____________________________________" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "        \______   \_______  _______  _|__| __| _/____   __| _/ \______   \___.__. |   | /  _  \    /     \__    ___/\_   _____/\_   ___ \" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "         |     ___/\_  __ \/  _ \  \/ /  |/ __ |/ __ \ / __ |   |    |  _<   |  | |   |/  /_\  \  /  \ /  \|    |    |    __)_ /    \  \/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "         |    |     |  | \(  <_> )   /|  / /_/ \  ___// /_/ |   |    |   \\___  | |   /    |    \/    Y    \    |    |        \\     \____" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "         |____|     |__|   \____/ \_/ |__\____ |\___  >____ |   |______  // ____| |___\____|__  /\____|__  /____|   /_______  / \______  /" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                              \/    \/     \/          \/ \/                  \/         \/                 \/         \/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
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
writeLog -dataToLog ""

###
# Checking Requirements
###
# N.A.

###
# Technical Information
###
# N.A.

###
# Getting AD Forest Details
###
$thisADForest = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$schemaNCDN = $thisADForest.schema.Name                                     # Schema NC DN
$configNCDN = $schemaNCDN.Substring(("CN=Schema,").Length)                  # Config NC DN
$adForestModeLevel = $thisADForest.ForestModeLevel                          # Forest Level
$adForestMode = $thisADForest.ForestMode                                    # Forest Mode
If ([int]$adForestModeLevel -eq 7 -And $adForestMode -eq "Unknown") {		# Fix To Correct Bug In S.DS.P. With Forest Mode When Its Is Windows2016Forest
	$adForestMode = "Windows2016Forest"
}
$adForestRootDomainObject = $thisADForest.RootDomain                        # Forest Root Domain Object
writeLog -dataToLog "Forest Mode (Level)...................: $adForestMode ($adForestModeLevel)"
writeLog -dataToLog ""

###
# Discover An RWDC/GC For AD Queries
###
$rwdcFQDN = locateRWDC -fqdnADdomain $fqdnADDomainOfComputer                # Discovered RWDC Based On The Domain Membership Of the Computer Where This Script Is Running
#$gcFQDN = $thisADForest.FindGlobalCatalog().Name                            # Discovered GC

###
# Get All Domains From The AD Forest, Create A Table, And Display That Table
###
$searchRootADDomains = [ADSI]"LDAP://$rwdcFQDN/CN=Partitions,$configNCDN"
$searcherADDomains = New-Object System.DirectoryServices.DirectorySearcher($searchRootADDomains)
$searcherADDomains.Filter = "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))"
$adDomainObjects = $searcherADDomains.FindAll()
$tableOfDomainsInADForest = @()
$adDomainObjects | %{
	$tableOfDomainsInADForestEntry = New-Object -TypeName System.Object
	$tableOfDomainsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Domain DN" -Value $($_.Properties.ncname[0])
	$tableOfDomainsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Domain FQDN" -Value $($_.Properties.dnsroot[0])
	$tableOfDomainsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Domain Name" -Value $($_.Properties.name[0])
	$tableOfDomainsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Domain Type" -Value $(If ([String]::IsNullOrEmpty($_.Properties.roottrust) -And [String]::IsNullOrEmpty($_.Properties.trustparent)) {"Root Domain"} ElseIf (-not [String]::IsNullOrEmpty($_.Properties.trustparent)) {"Child Domain"} ElseIf (-not [String]::IsNullOrEmpty($_.Properties.roottrust)) {"Tree Root Domain"})
	$tableOfDomainsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Current" -Value $(If ($fqdnADDomainOfComputer -eq $($_.Properties.dnsroot[0])) {$true} Else {$false})
	$tableOfDomainsInADForest += $tableOfDomainsInADForestEntry
}

writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "+++ LIST OF DOMAINS WITHIN THE AD FOREST '$($thisADForest.Name)' - PLEASE CHOOSE A DOMAIN TO TARGET +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
$domainSpecificOption = 0
$defaultDomainSpecificNumericOption = $null
$domainNumericSelection = $null
ForEach ($domainOption in $($tableOfDomainsInADForest | Sort-Object -Property "Domain Type","Domain DN" -Descending)) {
	$domainSpecificOption++
	If ($domainOption."Domain Type" -eq "Root Domain") {
		writeLog -dataToLog "[$domainSpecificOption] Domain DN: $($domainOption.'Domain DN'.PadRight(50, " ")) | FQDN: $($domainOption.'Domain FQDN'.PadRight(45, " ")) | Domain Type: $($domainOption.'Domain Type'.PadRight(25, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
		$defaultDomainSpecificNumericOption = $domainSpecificOption
	} Else {
		writeLog -dataToLog "[$domainSpecificOption] Domain DN: $($domainOption.'Domain DN'.PadRight(50, " ")) | FQDN: $($domainOption.'Domain FQDN'.PadRight(45, " ")) | Domain Type: $($domainOption.'Domain Type')" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	}
}
writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "REMARK: Specify A Number Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
Write-Host ""
If ([String]::IsNullOrEmpty($targetDomainFQDN)) {
	Do {
		$domainNumericSelection = Read-Host "Please Choose The Domain To Target.................."
	} Until (([int]$domainNumericSelection -gt 0 -And [int]$domainNumericSelection -le ($tableOfDomainsInADForest | Measure-Object).Count) -Or $([string]::IsNullOrEmpty($domainNumericSelection)))
	If ([string]::IsNullOrEmpty($domainNumericSelection)) {
		$domainNumericSelection = $defaultDomainSpecificNumericOption
	}
} Else {
	$domainNumericSelection = ($($tableOfDomainsInADForest | Sort-Object -Property "Domain Type","Domain DN" -Descending)."Domain FQDN").ToUpper().IndexOf($targetDomainFQDN.ToUpper()) + 1
	If ($domainNumericSelection -eq 0) {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Specified Domain '$targetDomainFQDN' DOES NOT Exist In The List Of Domains In The AD Forest '$($thisADForest.Name)'" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Please Re-Run The Script And Make Sure To Specify A Correct Domain That Does Exist In The The AD Forest '$($thisADForest.Name)'" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		BREAK
	}
}
$domainOptionChosen = $($tableOfDomainsInADForest | Sort-Object -Property "Domain Type","Domain DN" -Descending)[$domainNumericSelection - 1]
writeLog -dataToLog " > Option Chosen: [$domainNumericSelection] Domain DN: $($domainOptionChosen.'Domain DN') | FQDN: $($domainOptionChosen.'Domain FQDN') | Domain Type: $($domainOptionChosen.'Domain Type')" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
$rwdcADDomainFQDN = locateRWDC -fqdnADdomain $($domainOptionChosen.'Domain FQDN')
$searchRootFSMORoleOwner = [ADSI]"LDAP://$rwdcADDomainFQDN/$($domainOptionChosen.'Domain DN')"
$searcherFSMORoleOwner = New-Object System.DirectoryServices.DirectorySearcher($searchRootFSMORoleOwner)
$fsmoRoleOwnerObject = $searcherFSMORoleOwner.FindOne()
$ntdsSettingsObjectFsmoRoleOwnerDN = $fsmoRoleOwnerObject.Properties.fsmoroleowner[0]
If ([String]::IsNullOrEmpty($ntdsSettingsObjectFsmoRoleOwnerDN) -Or $ntdsSettingsObjectFsmoRoleOwnerDN -match "0ADEL:") {
	$fsmoRoleOwnerFQDN = "UNDEFINED / INVALID"
} Else {
	$fsmoRoleOwnerFQDN = convertNTDSSettingsObjectDNToFQDN -rwdcFQDN $rwdcADDomainFQDN -ntdsSettingsObjectDN $ntdsSettingsObjectFsmoRoleOwnerDN
}

###
# For Each AD Domain Discover An RWDC And Build A Hash Table Containing An RWDC For Every AD Domain
###
# This Is Needed As A Member Of A DFSR Replication Group, Can Be Part Of Any AD Domain In The AD Forest
$domainsAndDCsHT = @{}
$tableOfDomainsInADForest | ForEach-Object{
	$adDomainRWDCFQDN = locateRWDC -fqdnADdomain $($_.'Domain FQDN')
	$domainsAndDCsHT[$($_.'Domain DN')] = $adDomainRWDCFQDN
	$domainsAndDCsHT[$($_.'Domain FQDN')] = $adDomainRWDCFQDN
	$domainsAndDCsHT[$($_.'Domain Name')] = $adDomainRWDCFQDN
}

###
# Get All DFSR Replicated Folders, Create A Table, And Display That Table
###
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "+++ LIST OF REPLICATED FOLDERS WITHIN THE AD DOMAIN '$($domainOptionChosen.'Domain DN') ($($domainOptionChosen.'Domain FQDN'))' - PLEASE CHOOSE A DFSR REPLICATED FOLDER TO TARGET +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
$ntfrsReplSetsList = getNTFRSReplicaSetsInADDomain -adDomainDN $($domainOptionChosen.'Domain DN') -rwdcFQDN $rwdcADDomainFQDN
$dfsrReplFoldersList = getDFSRReplGroupsAndFoldersInADDomain -adDomainDN $($domainOptionChosen.'Domain DN') -rwdcFQDN $rwdcADDomainFQDN  | Sort-Object -Property "Repl Folder Guid" -Descending
$replFolderList = @()
# If Any NTFRS Replica Set Exists, Them Process It
If ($ntfrsReplSetsList) {
	$ntfrsReplSetsList | ForEach-Object {
		$replFolderListEntry = New-Object -TypeName System.Object
		$replFolderListEntry | Add-Member -MemberType NoteProperty -Name "Repl Folder Name" -Value $($_."Repl Set Name")
		$replFolderListEntry | Add-Member -MemberType NoteProperty -Name "Repl Group Name" -Value "N.A."
		$replFolderListEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $($_.Type)
		$replFolderList += $replFolderListEntry
	}
}
# If Any NTFRS Replica Set Exists, Them Process It
If ($dfsrReplFoldersList) {
	$dfsrReplFoldersList | ForEach-Object {
		$replFolderListEntry = New-Object -TypeName System.Object
		$replFolderListEntry | Add-Member -MemberType NoteProperty -Name "Repl Folder Name" -Value $($_."Repl Folder Name")
		$replFolderListEntry | Add-Member -MemberType NoteProperty -Name "Repl Group Name" -Value $($_."Repl Group Name")
		$replFolderListEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $($_.Type)
		$replFolderList += $replFolderListEntry
	}
}

$dfsrReplFolderSpecificOption = 0
$defaultDfsrReplFolderSpecificNumericOption = $null
$dfsrReplFolderNumericSelection = $null
ForEach ($dfsrReplFolderOption in $replFolderList) {
	$dfsrReplFolderSpecificOption++
	If ($dfsrReplFolderOption."Repl Folder Name" -eq "SYSVOL Share" -Or $dfsrReplFolderOption."Repl Folder Name" -eq "Domain System Volume (SYSVOL share)") {
		writeLog -dataToLog "[$dfsrReplFolderSpecificOption] Repl Folder Name: $($dfsrReplFolderOption.'Repl Folder Name'.PadRight(43, " ")) | Repl Group Name: $($dfsrReplFolderOption.'Repl Group Name'.PadRight(34, " ")) | Type: $($dfsrReplFolderOption.'Type'.PadRight(32, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
		$defaultDfsrReplFolderSpecificNumericOption = $dfsrReplFolderSpecificOption
	} Else {
		writeLog -dataToLog "[$dfsrReplFolderSpecificOption] Repl Folder Name: $($dfsrReplFolderOption.'Repl Folder Name'.PadRight(43, " ")) | Repl Group Name: $($dfsrReplFolderOption.'Repl Group Name'.PadRight(34, " ")) | Type: $($dfsrReplFolderOption.'Type'.PadRight(32, " "))" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	}
}
writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "REMARK: Specify A Number Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
Write-Host ""
If ([String]::IsNullOrEmpty($targetReplFolder)) {
	Do {
		$dfsrReplFolderNumericSelection = Read-Host "Please Choose The Repl Folder To Target............."
	} Until (([int]$dfsrReplFolderNumericSelection -gt 0 -And [int]$dfsrReplFolderNumericSelection -le ($replFolderList | Measure-Object).Count) -Or $([string]::IsNullOrEmpty($dfsrReplFolderNumericSelection)))
	If ([string]::IsNullOrEmpty($dfsrReplFolderNumericSelection)) {
		$dfsrReplFolderNumericSelection = $defaultDfsrReplFolderSpecificNumericOption
	}
} Else {
	$dfsrReplFolderNumericSelection = ($replFolderList."Repl Folder Name").ToUpper().IndexOf($targetReplFolder.ToUpper()) + 1
	If ($dfsrReplFolderNumericSelection -eq 0) {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Specified Replicated Folder '$targetReplFolder' DOES NOT Exist In The List Of Replicated Folders In The AD Domain '$($domainOptionChosen.'Domain FQDN')'" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Please Re-Run The Script And Make Sure To Specify A Correct Replicated Folder That Does Exist In The The AD Domain '$($domainOptionChosen.'Domain FQDN')'" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		BREAK
	}
}
$replFolderOptionChosen = $replFolderList[$dfsrReplFolderNumericSelection - 1]
writeLog -dataToLog " > Option Chosen: [$dfsrReplFolderNumericSelection] Repl Folder Name: $($replFolderOptionChosen.'Repl Folder Name') | Repl Group Name: $($replFolderOptionChosen.'Repl Group Name') | Type: $($replFolderOptionChosen.Type)" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

###
# For The Replicated Folder Chosen, Build A List Of Members Supporting That Replicated Folder, And Finally Display That List
###
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -eq "NTFRS") {
	$ntfrsReplFolderOptionChosen = $ntfrsReplSetsList | Where-Object {$_."Repl Set Name" -eq $($replFolderOptionChosen."Repl Folder Name")}
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "+++ LIST MEMBERS SUPPORTING THE REPLICATED FOLDER '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	$ntfrsReplSetMemberList = getNTFRSReplSetMembers -adDomainDN $($domainOptionChosen.'Domain DN') -rwdcFQDN $($domainsAndDCsHT[$($domainOptionChosen.'Domain FQDN')]) -ntfrsReplicaSetName $($ntfrsReplFolderOptionChosen."Repl Set Name")
	$ntfrsReplFolderConfigAndState = getNTFRSReplSetConfigAndState -ntfrsReplSetMemberList $ntfrsReplSetMemberList -ntfrsReplSetName $($ntfrsReplFolderOptionChosen."Repl Set Name") -rwdcFQDN $($domainsAndDCsHT[$($domainOptionChosen.'Domain FQDN')])
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "`n$($ntfrsReplFolderConfigAndState | Format-Table * -Wrap -Autosize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " --> Found [$((($ntfrsReplFolderConfigAndState | Where-Object {$_.Reachable -eq $true}) | Measure-Object).count)] DFS-R Members That Are REACHABLE..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " --> Found [$((($ntfrsReplFolderConfigAndState | Where-Object {$_.Reachable -eq $false}) | Measure-Object).count)] DFS-R Members That Are NOT REACHABLE..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	If ($($ntfrsReplFolderConfigAndState | Where-Object {$_."Site Name" -eq $localComputerSiteName -And $_.Reachable -eq $true})) {
		$discoveredMemberFQDN = $($ntfrsReplFolderConfigAndState | Where-Object {$_."Site Name" -eq $localComputerSiteName -And $_.Reachable -eq $true})[0]."Member FQDN"
	} Else {
		$discoveredMemberFQDN = $($ntfrsReplFolderConfigAndState | Where-Object {$_.Reachable -eq $true})[0]."Member FQDN"
	}
}

# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -eq "DFSR") {
	$dfsrReplFolderOptionChosen = $dfsrReplFoldersList | Where-Object {$_."Repl Folder Name" -eq $($replFolderOptionChosen."Repl Folder Name")}
	$dfsrReplFolderOptionChosenGuid = ($dfsrReplFoldersList | Where-Object {$_."Repl Folder Name" -eq $($dfsrReplFolderOptionChosen."Repl Folder Name")})."Repl Folder Guid"
	$dfsrReplFolderOptionChosenGroupName = ($dfsrReplFoldersList | Where-Object {$_."Repl Folder Name" -eq $($dfsrReplFolderOptionChosen."Repl Folder Name")})."Repl Group Name"
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "+++ LIST MEMBERS SUPPORTING THE REPLICATED FOLDER '$($dfsrReplFolderOptionChosen.'Repl Folder Name') ($dfsrReplFolderOptionChosenGroupName)' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	$dfsrReplGroupMemberList = getDFSRReplGroupMembers -adDomainDN $($domainOptionChosen.'Domain DN') -rwdcFQDN $($domainsAndDCsHT[$($domainOptionChosen.'Domain FQDN')]) -dfsrReplGroupName $dfsrReplFolderOptionChosenGroupName -domainsAndDCsHT $domainsAndDCsHT
	$dfsrReplFolderConfigAndState = getDFSRReplFolderConfigAndState -dfsrReplGroupName $dfsrReplFolderOptionChosenGroupName -dfsrReplGroupMemberList $dfsrReplGroupMemberList -dfsrReplGroupContentSetName $($dfsrReplFolderOptionChosen."Repl Folder Name") -dfsrReplGroupContentSetGuid $dfsrReplFolderOptionChosenGuid -domainsAndDCsHT $domainsAndDCsHT
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "`n$($dfsrReplFolderConfigAndState | Format-Table * -Wrap -Autosize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.Reachable -eq $true}) | Measure-Object).count)] DFS-R Members That Are REACHABLE..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.Reachable -eq $false}) | Measure-Object).count)] DFS-R Members That Are NOT REACHABLE..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.Reachable -eq $true -And $_.State -eq 'Enabled'}) | Measure-Object).count)] DFS-R Members With ENABLED DFS-R Replication State For The DFR-R Replicated Folder '$($dfsrReplFolderOptionChosen."Repl Folder Name")' (REACHABLE)..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.Reachable -eq $false -And $_.State -eq 'Enabled'}) | Measure-Object).count)] DFS-R Members With ENABLED DFS-R Replication State For The DFR-R Replicated Folder '$($dfsrReplFolderOptionChosen."Repl Folder Name")' (NOT REACHABLE)..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.Reachable -eq $true -And $_.State -eq 'Disabled'}) | Measure-Object).count)] DFS-R Members With DISABLED DFS-R Replication State For The DFR-R Replicated Folder '$($dfsrReplFolderOptionChosen."Repl Folder Name")' (REACHABLE)..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.Reachable -eq $false -And $_.State -eq 'Disabled'}) | Measure-Object).count)] DFS-R Members With DISABLED DFS-R Replication State For The DFR-R Replicated Folder '$($dfsrReplFolderOptionChosen."Repl Folder Name")' (NOT REACHABLE)..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.Reachable -eq $true -And $_.State -eq '<UNKNOWN>'}) | Measure-Object).count)] DFS-R Members With UNKNOWN DFS-R Replication State For The DFR-R Replicated Folder '$($dfsrReplFolderOptionChosen."Repl Folder Name")' (REACHABLE)..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.Reachable -eq $false -And $_.State -eq '<UNKNOWN>'}) | Measure-Object).count)] DFS-R Members With UNKNOWN DFS-R Replication State For The DFR-R Replicated Folder '$($dfsrReplFolderOptionChosen."Repl Folder Name")' (NOT REACHABLE)..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	If ($($dfsrReplFolderConfigAndState | Where-Object {$_."Site Name" -eq $localComputerSiteName -And $_.Reachable -eq $true -And $_.State -eq "Enabled"})) {
		$discoveredMemberFQDN = $($dfsrReplFolderConfigAndState | Where-Object {$_."Site Name" -eq $localComputerSiteName -And $_.Reachable -eq $true -And $_.State -eq "Enabled" -And $_.Type -eq "RW"})[0]."Member FQDN"
	} Else {
		$discoveredMemberFQDN = $($dfsrReplFolderConfigAndState | Where-Object {$_.Reachable -eq $true -And $_.State -eq "Enabled" -And $_.Type -eq "RW"})[0]."Member FQDN"
	}
}

###
# Specify A DFS-R Member For The Specified/Chosen DFS-R Replicated Folder
###
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "+++ SOURCE REPLICATION FOLDER MEMBER OPTIONS FOR THE REPLICATED FOLDER '$($replFolderOptionChosen."Repl Folder Name")' - PLEASE CHOOSE A MEMBER TO BE THE SOURCE MEMBER +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
$sourceMemberOptions = @()
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -eq "NTFRS") {
	If ($($ntfrsReplFolderOptionChosen.'Repl Set Name') -eq "Domain System Volume (SYSVOL share)") {
		$sourceMemberOptions += "FSMO [$fsmoRoleOwnerFQDN] (PDC Emulator FSMO)"
	}
	$sourceMemberOptions += "Discovered Member [$discoveredMemberFQDN]"
	$sourceMemberOptions += "Specify Member FQDN"
	$sourceMemberSpecificOption = 0
	$defaultSourceRWDCSpecificNumericOption = $null
	$sourceMemberNumericSelection = $null
	ForEach ($sourceMemberOption in $sourceMemberOptions) {
		$sourceMemberSpecificOption++
		If ($($ntfrsReplFolderOptionChosen.'Repl Set Name') -eq "Domain System Volume (SYSVOL share)") {
			If ($fsmoRoleOwnerFQDN -ne "UNDEFINED / INVALID" -And $sourceMemberOption -eq $sourceMemberOptions[0]) {
				writeLog -dataToLog "[$sourceMemberSpecificOption] $($sourceMemberOption.PadRight(75, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
				$defaultSourceRWDCSpecificNumericOption = $sourceMemberSpecificOption
			} ElseIf ($fsmoRoleOwnerFQDN -eq "UNDEFINED / INVALID" -And $sourceMemberOption -eq $sourceMemberOptions[1]) {
				writeLog -dataToLog "[$sourceMemberSpecificOption] $($sourceMemberOption.PadRight(75, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
				$defaultSourceRWDCSpecificNumericOption = $sourceMemberSpecificOption
			} Else {
				writeLog -dataToLog "[$sourceMemberSpecificOption] $sourceMemberOption" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
			}
		} Else {
			If ($sourceMemberOption -eq $sourceMemberOptions[0]) {
				writeLog -dataToLog "[$sourceMemberSpecificOption] $($sourceMemberOption.PadRight(75, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
				$defaultSourceRWDCSpecificNumericOption = $sourceMemberSpecificOption
			} Else {
				writeLog -dataToLog "[$sourceMemberSpecificOption] $sourceMemberOption" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
	}
	writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "REMARK: Specify A Number Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	Write-Host ""
	If ([String]::IsNullOrEmpty($targetReplMember)) {
		Do {
			$sourceMemberNumericSelection = Read-Host "Please Choose Source Member To Use For The File....."
		} Until (([int]$sourceMemberNumericSelection -gt 0 -And [int]$sourceMemberNumericSelection -le ($sourceMemberOptions | Measure-Object).Count) -Or $([string]::IsNullOrEmpty($sourceMemberNumericSelection)))
		If ([string]::IsNullOrEmpty($sourceMemberNumericSelection)) {
			$sourceMemberNumericSelection = $defaultSourceRWDCSpecificNumericOption
		}
	} Else {
		$sourceMemberOptionsHT = @{}
		$sourceMemberOptionsHT["Fsmo"] = $sourceMemberOptions[0]
		$sourceMemberOptionsHT["Discover"] = $sourceMemberOptions[1]
		If ($targetReplMember -match "(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]*?\.[\d]+?)(?<=[\w\-]{2,})(?<![\w\-]{25})") {
			If ($($dfsrReplFolderOptionChosen.'Repl Folder Name') -eq "SYSVOL Share") {
				$sourceMemberOptionsHT[$targetReplMember] = $sourceMemberOptions[2]
			} Else {
				$sourceMemberOptionsHT[$targetReplMember] = $sourceMemberOptions[1]
			}
		}
		$sourceMemberNumericSelection = $sourceMemberOptions.IndexOf($sourceMemberOptionsHT[$targetReplMember]) + 1
	}
	$sourceMemberOptionChosen = $sourceMemberOptions[$sourceMemberNumericSelection - 1]
	writeLog -dataToLog " > Option Chosen: [$sourceMemberNumericSelection] $sourceMemberOptionChosen" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	If ($sourceMemberOptionChosen -eq "FSMO [$fsmoRoleOwnerFQDN] (PDC Emulator FSMO)") {
		$sourceMemberFQDN = $fsmoRoleOwnerFQDN
	}
	If ($sourceMemberOptionChosen -eq "Discovered Member [$discoveredMemberFQDN]") {
		$sourceMemberFQDN = $discoveredMemberFQDN
	}
	If ($sourceMemberOptionChosen -eq "Specify Member FQDN") {
		If ([String]::IsNullOrEmpty($targetReplMember)) {
			$sourceMemberFQDN = Read-Host "Please Specify A Member Supporting The Repl Folder.."
		} Else {
			$sourceMemberFQDN = $targetReplMember
		}
		writeLog -dataToLog " > Member Specified: $sourceMemberFQDN" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	}
}

# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -eq "DFSR") {
	If ($($dfsrReplFolderOptionChosen.'Repl Folder Name') -eq "SYSVOL Share") {
		$sourceMemberOptions += "FSMO [$fsmoRoleOwnerFQDN] (PDC Emulator FSMO)"
	}
	$sourceMemberOptions += "Discovered Member [$discoveredMemberFQDN]"
	$sourceMemberOptions += "Specify Member FQDN"
	$sourceMemberSpecificOption = 0
	$defaultSourceRWDCSpecificNumericOption = $null
	$sourceMemberNumericSelection = $null
	ForEach ($sourceMemberOption in $sourceMemberOptions) {
		$sourceMemberSpecificOption++
		If ($($dfsrReplFolderOptionChosen.'Repl Folder Name') -eq "SYSVOL Share") {
			If ($fsmoRoleOwnerFQDN -ne "UNDEFINED / INVALID" -And $sourceMemberOption -eq $sourceMemberOptions[0]) {
				writeLog -dataToLog "[$sourceMemberSpecificOption] $($sourceMemberOption.PadRight(75, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
				$defaultSourceRWDCSpecificNumericOption = $sourceMemberSpecificOption
			} ElseIf ($fsmoRoleOwnerFQDN -eq "UNDEFINED / INVALID" -And $sourceMemberOption -eq $sourceMemberOptions[1]) {
				writeLog -dataToLog "[$sourceMemberSpecificOption] $($sourceMemberOption.PadRight(75, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
				$defaultSourceRWDCSpecificNumericOption = $sourceMemberSpecificOption
			} Else {
				writeLog -dataToLog "[$sourceMemberSpecificOption] $sourceMemberOption" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
			}
		} Else {
			If ($sourceMemberOption -eq $sourceMemberOptions[0]) {
				writeLog -dataToLog "[$sourceMemberSpecificOption] $($sourceMemberOption.PadRight(75, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
				$defaultSourceRWDCSpecificNumericOption = $sourceMemberSpecificOption
			} Else {
				writeLog -dataToLog "[$sourceMemberSpecificOption] $sourceMemberOption" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
	}
	writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "REMARK: Specify A Number Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	Write-Host ""
	If ([String]::IsNullOrEmpty($targetReplMember)) {
		Do {
			$sourceMemberNumericSelection = Read-Host "Please Choose Source Member To Use For The File....."
		} Until (([int]$sourceMemberNumericSelection -gt 0 -And [int]$sourceMemberNumericSelection -le ($sourceMemberOptions | Measure-Object).Count) -Or $([string]::IsNullOrEmpty($sourceMemberNumericSelection)))
		If ([string]::IsNullOrEmpty($sourceMemberNumericSelection)) {
			$sourceMemberNumericSelection = $defaultSourceRWDCSpecificNumericOption
		}
	} Else {
		$sourceMemberOptionsHT = @{}
		$sourceMemberOptionsHT["Fsmo"] = $sourceMemberOptions[0]
		$sourceMemberOptionsHT["Discover"] = $sourceMemberOptions[1]
		If ($targetReplMember -match "(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]*?\.[\d]+?)(?<=[\w\-]{2,})(?<![\w\-]{25})") {
			If ($($dfsrReplFolderOptionChosen.'Repl Folder Name') -eq "SYSVOL Share") {
				$sourceMemberOptionsHT[$targetReplMember] = $sourceMemberOptions[2]
			} Else {
				$sourceMemberOptionsHT[$targetReplMember] = $sourceMemberOptions[1]
			}
		}
		$sourceMemberNumericSelection = $sourceMemberOptions.IndexOf($sourceMemberOptionsHT[$targetReplMember]) + 1
	}
	$sourceMemberOptionChosen = $sourceMemberOptions[$sourceMemberNumericSelection - 1]
	writeLog -dataToLog " > Option Chosen: [$sourceMemberNumericSelection] $sourceMemberOptionChosen" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	If ($sourceMemberOptionChosen -eq "FSMO [$fsmoRoleOwnerFQDN] (PDC Emulator FSMO)") {
		$sourceMemberFQDN = $fsmoRoleOwnerFQDN
	}
	If ($sourceMemberOptionChosen -eq "Discovered Member [$discoveredMemberFQDN]") {
		$sourceMemberFQDN = $discoveredMemberFQDN
	}
	If ($sourceMemberOptionChosen -eq "Specify Member FQDN") {
		If ([String]::IsNullOrEmpty($targetReplMember)) {
			$sourceMemberFQDN = Read-Host "Please Specify A Member Supporting The Repl Folder.."
		} Else {
			$sourceMemberFQDN = $targetReplMember
		}
		writeLog -dataToLog " > Member Specified: $sourceMemberFQDN" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	}
}

###
# Validate The Member Exists, Is Available And Can Be Used, And Has A Replication State Of Enabled. Update The Table Of DCs To Process If It Can Be Used!
###
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -eq "NTFRS") {
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Checking Existence And Connectivity Of The Specified Member '$sourceMemberFQDN' For The Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')'..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	If ($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $sourceMemberFQDN -And $_.Reachable -eq $true -And $_.Type -eq "RW"}) {
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Specified Member '$sourceMemberFQDN':" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Exists, And" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Is Available/Reachable, And" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Supports/Hosts A Writable Copy Of The Chosen Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')'!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false

		($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $sourceMemberFQDN})."Source" = $true
		($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -ne $sourceMemberFQDN}) | ForEach-Object {$_."Source" = $false}
		($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $sourceMemberFQDN})."Member FQDN" = "$($sourceMemberFQDN + " [SOURCE MEMBER]")"
		$ntfrsReplFolderConfigAndState = $ntfrsReplFolderConfigAndState | Sort-Object -Property Source -Descending
	} Else {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Specified Member '$sourceMemberFQDN':" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > DOES NOT Exist, And/Or" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > IS NOT Available/Reachable, And/Or" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > DOES NOT Support/Host A Writable Copy Of The Chosen Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Please Re-Run The Script And Make Sure To Use A Member That Is Available/Reachable And Supports/Hosts A Writable Copy Of The Chosen Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Make Sure To Review The List Of Members Supporting The Replicated Folder, And Pay Special Attention To The Columns 'Member FQDN', 'Reachable' and 'Type'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		BREAK
	}
}

# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -eq "DFSR") {
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Checking Existence And Connectivity Of The Specified Member '$sourceMemberFQDN' For The Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	If ($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $sourceMemberFQDN -And $_.Reachable -eq $true -And $_.State -eq "Enabled" -And $_.Type -eq "RW"}) {
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Specified Member '$sourceMemberFQDN':" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Exists, And" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Is Available/Reachable, And" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Has An Enabled Replication State, And" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Supports/Hosts A Writable Copy Of The Chosen Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false

		($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $sourceMemberFQDN})."Source" = $true
		($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -ne $sourceMemberFQDN}) | ForEach-Object {$_."Source" = $false}
		($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $sourceMemberFQDN})."Member FQDN" = "$($sourceMemberFQDN + " [SOURCE MEMBER]")"
		$dfsrReplFolderConfigAndState = $dfsrReplFolderConfigAndState | Sort-Object -Property Source -Descending
	} Else {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Specified Member '$sourceMemberFQDN':" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > DOES NOT Exist, And/Or" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > IS NOT Available/Reachable, And/Or" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > DOES NOT Have An Enabled Replication State, And/Or" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > DOES NOT Support/Host A Writable Copy Of The Chosen Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Please Re-Run The Script And Make Sure To Use A Member That Is Available/Reachable, Has An Enabled Replication State And Supports/Hosts A Writable Copy Of The Chosen Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Make Sure To Review The List Of Members Supporting The Replicated Folder, And Pay Special Attention To The Columns 'Member FQDN', 'Reachable', 'State' and 'Type'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		BREAK
	}
}

If (-not $skipFileCount) {
	###
	# For The Replicated Folder Chosen, Count The Files On All Members. If There Is A Difference, Then Something Is Wrong!
	###
	# If The Replicated Folder Is Using NTFRS
	If ($replFolderOptionChosen.Type -eq "NTFRS") {
		writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "+++ COUNTING THE FILES IN THE REPLICATED FOLDER '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		# For Each Member In The List/Table With Members To Process '$ntfrsReplFolderConfigAndState' Perform A Number Of Steps
		ForEach ($replMember in $ntfrsReplFolderConfigAndState) {
			# Only For The Replication Member Used As The Source Member
			If ($replMember.Reachable -eq $true) {
				writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  * Contacting Member For Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' ...[$($replMember."Member FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Member Is Reachable..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Counting Files..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				$ntfrsReplFolderPath = $replMember."Repl Folder Path"

				If ($replMember."Member FQDN" -match $sourceMemberFQDN) {
					$ntfrsReplMember = $sourceMemberFQDN
				} Else {
					$ntfrsReplMember = $replMember."Member FQDN"
				}

				$fileCountInReplFolder = $null
				$fileCountInReplFolder = Invoke-Command -ComputerName $ntfrsReplMember -ArgumentList $($replMember."Repl Folder Path") -ScriptBlock {
					Param (
						$localReplFolderPathOnMember
					)
					$fileCountInReplFolder = $null
					$fileCountInReplFolder = (Get-ChildItem $localReplFolderPathOnMember -Recurse | Measure-Object).Count

					Return $fileCountInReplFolder
				}
				($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $($replMember."Member FQDN")})."File Count" = $fileCountInReplFolder
			}
			If ($replMember.Reachable -eq $false) {
				writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  * Contacting Member For Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' ...[$($replMember."Member FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Member IS NOT Reachable..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Skipping Counting Files..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $($replMember."Member FQDN")})."File Count" = "<SKIP>"
			}
		}
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "`n$($ntfrsReplFolderConfigAndState | Format-Table * -Wrap -Autosize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	}

	# If The Replicated Folder Is Using DFSR
	If ($replFolderOptionChosen.Type -eq "DFSR") {
		writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "+++ COUNTING THE FILES IN THE REPLICATED FOLDER '$($dfsrReplFolderOptionChosen.'Repl Folder Name') ($dfsrReplFolderOptionChosenGroupName)' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		# For Each Member In The List/Table With Members To Process '$dfsrReplFolderConfigAndState' Perform A Number Of Steps
		ForEach ($replMember in $dfsrReplFolderConfigAndState) {
			# Only For The Replication Member Used As The Source Member
			If ($replMember.Reachable -eq $true) {
				writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  * Contacting Member For Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')' ...[$($replMember."Member FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Member Is Reachable..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Counting Files..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				$dfsrReplFolderPath = $replMember."Repl Folder Path"

				If ($replMember."Member FQDN" -match $sourceMemberFQDN) {
					$dfsrReplMember = $sourceMemberFQDN
				} Else {
					$dfsrReplMember = $replMember."Member FQDN"
				}

				$fileCountInReplFolder = $null
				$fileCountInReplFolder = Invoke-Command -ComputerName $dfsrReplMember -ArgumentList $($replMember."Repl Folder Path") -ScriptBlock {
					Param (
						$localReplFolderPathOnMember
					)
					$fileCountInReplFolder = $null
					$fileCountInReplFolder = (Get-ChildItem $localReplFolderPathOnMember -Recurse | Measure-Object).Count

					Return $fileCountInReplFolder
				}
				($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $($replMember."Member FQDN")})."File Count" = $fileCountInReplFolder
			}
			If ($replMember.Reachable -eq $false) {
				writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  * Contacting Member For Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')' ...[$($replMember."Member FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Member IS NOT Reachable..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Skipping Counting Files..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $($replMember."Member FQDN")})."File Count" = "<SKIP>"
			}
		}
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "`n$($dfsrReplFolderConfigAndState | Format-Table * -Wrap -Autosize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	}
}

###
# Define And Create The TEMP File On The Chosen Source Member
###
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "+++ CREATING TEMPORARY CANARY FILE IN REPLICATED FOLDER +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -eq "NTFRS") {
	$replFolderPath = ($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Repl Folder Path"
	If ($($ntfrsReplFolderOptionChosen.'Repl Set Name') -eq "Domain System Volume (SYSVOL share)") {
		$uncPathFolderSource = "\\" + $sourceMemberFQDN + "\" + $($replFolderPath.Replace(":","$")) + "\Scripts"
	} Else {
		$uncPathFolderSource = "\\" + $sourceMemberFQDN + "\" + $($replFolderPath.Replace(":","$"))
	}	
}
# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -eq "DFSR") {
	$replFolderPath = ($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Repl Folder Path"
	If ($($dfsrReplFolderOptionChosen.'Repl Folder Name') -eq "SYSVOL Share") {
		$uncPathFolderSource = "\\" + $sourceMemberFQDN + "\" + $($replFolderPath.Replace(":","$")) + "\Scripts"
	} Else {
		$uncPathFolderSource = "\\" + $sourceMemberFQDN + "\" + $($replFolderPath.Replace(":","$"))
	}
}
$tempCanaryFileBaseName = "_fileReplConvergenceCheckTempFile_"
$tempCanaryFileName = $tempCanaryFileBaseName + (Get-Date -f yyyyMMddHHmmss)
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -eq "NTFRS") {
	$tempCanaryFileContent = "...!!!...TEMP FILE TO TEST REPLICATION LATENCY/CONVERGENCE FOR REPLICATED FOLDER $($ntfrsReplFolderOptionChosen.'Repl Set Name'.ToUpper()) IN AD DOMAIN $($domainOptionChosen.'Domain FQDN') USING MEMBER $($sourceMemberFQDN.ToUpper()) AS THE SOURCE MEMBER...!!!..."
}
# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -eq "DFSR") {
	$tempCanaryFileContent = "...!!!...TEMP FILE TO TEST REPLICATION LATENCY/CONVERGENCE FOR REPLICATED FOLDER $($dfsrReplFolderOptionChosen.'Repl Folder Name'.ToUpper()) IN AD DOMAIN $($domainOptionChosen.'Domain FQDN') USING MEMBER $($sourceMemberFQDN.ToUpper()) AS THE SOURCE MEMBER...!!!..."
}
writeLog -dataToLog "  --> AD Domain FQDN......: $($domainOptionChosen.'Domain FQDN')" -logFileOnly $false -noDateTimeInLogLine $false
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -eq "NTFRS") {
	writeLog -dataToLog "  --> In Replicated Folder: $($ntfrsReplFolderOptionChosen.'Repl Set Name')" -logFileOnly $false -noDateTimeInLogLine $false
}
# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -eq "DFSR") {
	writeLog -dataToLog "  --> In Replicated Folder: $($dfsrReplFolderOptionChosen.'Repl Folder Name')" -logFileOnly $false -noDateTimeInLogLine $false
}
writeLog -dataToLog "  --> On Source Member....: $sourceMemberFQDN" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> In Folder (UNC Path): $uncPathFolderSource" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> With Full Name......: $tempCanaryFileName" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> With Content........: $tempCanaryFileContent" -logFileOnly $false -noDateTimeInLogLine $false
$uncPathCanaryFileSource = $uncPathFolderSource + "\" + $tempCanaryFileName + ".txt"
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -eq "NTFRS") {
	Try {
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " Creating The Temporary Canary File..." -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		$tempCanaryFileContent | Out-File -FilePath $uncPathCanaryFileSource -ErrorAction Stop
		writeLog -dataToLog " Temporary Canary File [$uncPathCanaryFileSource] Has Been Created On Member [$sourceMemberFQDN] In Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')'!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	} Catch {
		writeLog -dataToLog " Temporary Canary File [$uncPathCanaryFileSource] Could Not Be Created On Member [$sourceMemberFQDN] In Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		BREAK
	}
}
# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -eq "DFSR") {
	Try {
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " Creating The Temporary Canary File..." -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		$tempCanaryFileContent | Out-File -FilePath $uncPathCanaryFileSource -ErrorAction Stop
		writeLog -dataToLog " Temporary Canary File [$uncPathCanaryFileSource] Has Been Created On The Source Member [$sourceMemberFQDN] In Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	} Catch {
		writeLog -dataToLog " Temporary Canary File [$uncPathCanaryFileSource] Could Not Be Created On The Source Member [$sourceMemberFQDN] In Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		BREAK
	}
}

###
# Create The Results Table And Already Insert The Source RWDC As The First RWDC
###
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -eq "NTFRS") {
	$resultsTableOfProcessedMembers = @()
	$resultsTableOfProcessedMemberEntry = New-Object -TypeName System.Object
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member FQDN" -Value $(($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Member FQDN")
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member IPv4" -Value $(($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Member IPv4")
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $(($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Site Name")
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $(($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Reachable")
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $(($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Type")
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $(($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Source")
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "TimeDiscvrd" -Value $([decimal]$('{0:N2}' -f "0.00"))
	$resultsTableOfProcessedMembers += $resultsTableOfProcessedMemberEntry
}
# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -eq "DFSR") {
	$resultsTableOfProcessedMembers = @()
	$resultsTableOfProcessedMemberEntry = New-Object -TypeName System.Object
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member FQDN" -Value $(($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Member FQDN")
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member IPv4" -Value $(($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Member IPv4")
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $(($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Site Name")
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $(($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Reachable")
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "State" -Value $(($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."State")
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $(($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Type")
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $(($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Source")
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "TimeDiscvrd" -Value $([decimal]$('{0:N2}' -f "0.00"))
	$resultsTableOfProcessedMembers += $resultsTableOfProcessedMemberEntry
}

###
# Go Through The Process Of Checking Each Member To See If The Temporary Canary File Already Has Replicated To It
###
$startDateTime = Get-Date
$i = 0
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -eq "NTFRS") {
	writeLog -dataToLog "  --> Found [$($($ntfrsReplFolderConfigAndState | Measure-Object).Count)] Member(s) Supporting/Hosting The Chosen Replicated Folder..." -logFileOnly $false -noDateTimeInLogLine $false
}
# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -eq "DFSR") {
	writeLog -dataToLog "  --> Found [$($($dfsrReplFolderConfigAndState | Measure-Object).Count)] Member(s) Supporting/Hosting The Chosen Replicated Folder..." -logFileOnly $false -noDateTimeInLogLine $false
}
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

While($continue) {
    $i++
    $oldpos = $host.UI.RawUI.CursorPosition
	writeLog -dataToLog "  =============================== CHECK $i ===============================" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "  REMARK: Each Member In The List Below Must Be At Least Accessible Through SMB Over TCP ($smbPort)" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	Start-Sleep 1
    $replicated = $true

	# If The Replicated Folder Is Using NTFRS
	If ($replFolderOptionChosen.Type -eq "NTFRS") {
		# For Each Member In The List/Table With Members To Process '$ntfrsReplFolderConfigAndState' Perform A Number Of Steps
		ForEach ($replMember in $ntfrsReplFolderConfigAndState) {
			# Only For The Replication Member Used As The Source Member
			If ($replMember."Member FQDN" -match $sourceMemberFQDN) {
				writeLog -dataToLog "  * Contacting Member For Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' ...[$($replMember."Member FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Member Is Reachable..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Temporary Canary File [$uncPathCanaryFileSource] Exists In The Replicated Folder" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false

				CONTINUE
			}

			# For The Other Replication Members, Connect To The Member Through SMB (TCP:445)
		   If ($replMember."Member FQDN" -notmatch $sourceMemberFQDN) {
				writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  * Contacting Member For Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' ...[$($replMember."Member FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
				$connectionResult = $null
				If ($replMember.Reachable -eq $true) {
					writeLog -dataToLog "     - Member Is Reachable..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					$replFolderPath = $replMember."Repl Folder Path"
					If ($($ntfrsReplFolderOptionChosen.'Repl Set Name') -eq "Domain System Volume (SYSVOL share)") {
						$uncPathFolder = "\\" + $($replMember."Member FQDN") + "\" + $($replFolderPath.Replace(":","$")) + "\Scripts"
					} Else {
						$uncPathFolder = "\\" + $($replMember."Member FQDN") + "\" + $($replFolderPath.Replace(":","$"))
					}
					$uncPathCanaryFile = $uncPathFolder + "\" + $tempCanaryFileName + ".txt"
					$connectionResult = "SUCCESS"
				}
				If ($replMember.Reachable -eq $false) {
					writeLog -dataToLog "     - Member IS NOT Reachable..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					$connectionResult = "FAILURE"
				}
			}

			# If The Connection To The Member Is Successful
			If ($connectionResult -eq "SUCCESS") {
				Try {
					# If The Temporary Canary File Already Exists (Assumption Is The Correct Permissions To Access The Temporary Canary File Are In Place!)
					If (Test-Path -Path $uncPathCanaryFile) {
						writeLog -dataToLog "     - Temporary Canary File [$uncPathCanaryFile] Now Does Exist In The Replicated Folder                               " -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
						If ([string]::IsNullOrEmpty($($resultsTableOfProcessedMembers | Where-Object {$_."Member FQDN" -match $replMember."Member FQDN"}))) {
							$resultsTableOfProcessedMemberEntry = New-Object -TypeName System.Object
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member FQDN" -Value $($replMember."Member FQDN")
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member IPv4" -Value $($replMember."Member IPv4")
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($replMember."Site Name")
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $($replMember."Reachable")
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $($replMember."Type")
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $($replMember."Source")
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "TimeDiscvrd" -Value $([decimal]$("{0:n2}" -f ((Get-Date) - $startDateTime).TotalSeconds))
							$resultsTableOfProcessedMembers += $resultsTableOfProcessedMemberEntry
						}
					} Else {
						# If The Temporary Canary File Does Not Yet Exist
						writeLog -dataToLog "     - Temporary Canary File [$uncPathCanaryFile] Does NOT Exist (Yet) In The Replicated Folder" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						$replicated = $false
					}
				} Catch [UnauthorizedAccessException] {
					# If An Access Denied Occurs For Whatever Reason
					writeLog -dataToLog "     - Temporary Canary File [$uncPathCanaryFile] Appears NOT To Be Accessible In The Replicated Folder (Access Denied)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					$connectionResult = "ACCESS_DENIED"
				} Catch {
					# Something Else Happened....
					writeLog -dataToLog "     - Temporary Canary File [$uncPathCanaryFile] Appears NOT To Be Accessible In The Replicated Folder (Error: $($_.Exception.Message))" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					$connectionResult = "UNKNOWN"
				}
			}

			# If The Connection To The Member Is Unsuccessful Or An Access Denied Occurred
			If ($connectionResult -eq "FAILURE" -Or $connectionResult -eq "ACCESS_DENIED" -Or $connectionResult -eq "UNKNOWN") {
				If ($connectionResult -eq "FAILURE") {
					writeLog -dataToLog "     - Unable To Contact The Member For Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' (Not Reachable Or Folder Disabled) ...[$($replMember."Member FQDN".ToUpper())]..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
				If ($connectionResult -eq "ACCESS_DENIED") {
					writeLog -dataToLog "     - Unable To Contact The Member For Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' (Access Denied) ...[$($replMember."Member FQDN".ToUpper())]..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
				If ($connectionResult -eq "UNKNOWN") {
					writeLog -dataToLog "     - Unable To Contact The Member For Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' (Unknown Error) ...[$($replMember."Member FQDN".ToUpper())]..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
				If ([string]::IsNullOrEmpty($($resultsTableOfProcessedMembers | Where-Object {$_."Member FQDN" -match $replMember."Member FQDN"}))) {
					$resultsTableOfProcessedMemberEntry = New-Object -TypeName System.Object
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member FQDN" -Value $($replMember."Member FQDN")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member IPv4" -Value $($replMember."Member IPv4")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($replMember."Site Name")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $($replMember."Reachable")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "State" -Value $($replMember."State")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $($replMember."Type")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $($replMember."Source")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "TimeDiscvrd" -Value $([string]"<$connectionResult>")
					$resultsTableOfProcessedMembers += $resultsTableOfProcessedMemberEntry
				}
			}
		}
	}

	# If The Replicated Folder Is Using DFSR
	If ($replFolderOptionChosen.Type -eq "DFSR") {
		# For Each Member In The List/Table With Members To Process '$dfsrReplFolderConfigAndState' Perform A Number Of Steps
		ForEach ($replMember in $dfsrReplFolderConfigAndState) {
			# Only For The Replication Member Used As The Source Member
			If ($replMember."Member FQDN" -match $sourceMemberFQDN) {
				writeLog -dataToLog "  * Contacting Member For Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')' ...[$($replMember."Member FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Member Is Reachable..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Replication Folder Is Enabled..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Temporary Canary File [$uncPathCanaryFileSource] Exists In The Replicated Folder" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false

				CONTINUE
			}

			# For The Other Replication Members, Connect To The Member Through SMB (TCP:445)
		   If ($replMember."Member FQDN" -notmatch $sourceMemberFQDN) {
				writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  * Contacting Member For Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')' ...[$($replMember."Member FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
				$connectionResult = $null
				If ($replMember.Reachable -eq $true -And $replMember.State -eq "Enabled") {
					writeLog -dataToLog "     - Member Is Reachable..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "     - Replication Folder Is Enabled..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
					$replFolderPath = $replMember."Repl Folder Path"
					If ($($dfsrReplFolderOptionChosen.'Repl Folder Name') -eq "SYSVOL Share") {
						$uncPathFolder = "\\" + $($replMember."Member FQDN") + "\" + $($replFolderPath.Replace(":","$")) + "\Scripts"
					} Else {
						$uncPathFolder = "\\" + $($replMember."Member FQDN") + "\" + $($replFolderPath.Replace(":","$"))
					}
					$uncPathCanaryFile = $uncPathFolder + "\" + $tempCanaryFileName + ".txt"
					$connectionResult = "SUCCESS"
				}
				If ($replMember.Reachable -eq $true -And $replMember.State -eq "Disabled") {
					writeLog -dataToLog "     - Member Is Reachable..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					writeLog -dataToLog "     - Replication Folder Is Disabled..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					$connectionResult = "SKIPPED"
				}
				If ($replMember.Reachable -eq $false) {
					writeLog -dataToLog "     - Member IS NOT Reachable..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					If ($replMember.State -eq "Enabled") {
						writeLog -dataToLog "     - Replication Folder Is Enabled..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					}
					If ($replMember.State -eq "Disabled") {
						writeLog -dataToLog "     - Replication Folder Is Disabled..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					}
					$connectionResult = "FAILURE"
				}
			}

			# If The Connection To The Member Is Successful
			If ($connectionResult -eq "SUCCESS") {
				Try {
					# If The Temporary Canary File Already Exists (Assumption Is The Correct Permissions To Access The Temporary Canary File Are In Place!)
					If (Test-Path -Path $uncPathCanaryFile) {
						writeLog -dataToLog "     - Temporary Canary File [$uncPathCanaryFile] Now Does Exist In The Replicated Folder                               " -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
						If ([string]::IsNullOrEmpty($($resultsTableOfProcessedMembers | Where-Object {$_."Member FQDN" -match $replMember."Member FQDN"}))) {
							$resultsTableOfProcessedMemberEntry = New-Object -TypeName System.Object
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member FQDN" -Value $($replMember."Member FQDN")
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member IPv4" -Value $($replMember."Member IPv4")
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($replMember."Site Name")
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $($replMember."Reachable")
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "State" -Value $($replMember."State")
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $($replMember."Type")
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $($replMember."Source")
							$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "TimeDiscvrd" -Value $([decimal]$("{0:n2}" -f ((Get-Date) - $startDateTime).TotalSeconds))
							$resultsTableOfProcessedMembers += $resultsTableOfProcessedMemberEntry
						}
					} Else {
						# If The Temporary Canary File Does Not Yet Exist
						writeLog -dataToLog "     - Temporary Canary File [$uncPathCanaryFile] Does NOT Exist (Yet) In The Replicated Folder" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
						$replicated = $false
					}
				} Catch [UnauthorizedAccessException] {
					# If An Access Denied Occurs For Whatever Reason
					writeLog -dataToLog "     - Temporary Canary File [$uncPathCanaryFile] Appears NOT To Be Accessible In The Replicated Folder (Access Denied)" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					$connectionResult = "ACCESS_DENIED"
				} Catch {
					# Something Else Happened....
					writeLog -dataToLog "     - Temporary Canary File [$uncPathCanaryFile] Appears NOT To Be Accessible In The Replicated Folder (Error: $($_.Exception.Message))" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
					$connectionResult = "UNKNOWN"
				}
			}

			# If The Connection To The Member Is Unsuccessful Or An Access Denied Occurred
			If ($connectionResult -eq "FAILURE" -Or $connectionResult -eq "ACCESS_DENIED" -Or $connectionResult -eq "SKIPPED" -Or $connectionResult -eq "UNKNOWN") {
				If ($connectionResult -eq "FAILURE") {
					writeLog -dataToLog "     - Unable To Contact The Member For Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')' (Not Reachable Or Folder Disabled) ...[$($replMember."Member FQDN".ToUpper())]..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
				If ($connectionResult -eq "ACCESS_DENIED") {
					writeLog -dataToLog "     - Unable To Contact The Member For Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')' (Access Denied) ...[$($replMember."Member FQDN".ToUpper())]..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
				If ($connectionResult -eq "SKIPPED") {
					writeLog -dataToLog "     - Unable To Contact The Member For Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')' (Disabled - Skipped) ...[$($replMember."Member FQDN".ToUpper())]..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
				If ($connectionResult -eq "UNKNOWN") {
					writeLog -dataToLog "     - Unable To Contact The Member For Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')' (Unknown Error) ...[$($replMember."Member FQDN".ToUpper())]..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				}
				If ([string]::IsNullOrEmpty($($resultsTableOfProcessedMembers | Where-Object {$_."Member FQDN" -match $replMember."Member FQDN"}))) {
					$resultsTableOfProcessedMemberEntry = New-Object -TypeName System.Object
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member FQDN" -Value $($replMember."Member FQDN")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member IPv4" -Value $($replMember."Member IPv4")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($replMember."Site Name")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $($replMember."Reachable")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "State" -Value $($replMember."State")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $($replMember."Type")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $($replMember."Source")
					$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "TimeDiscvrd" -Value $([string]"<$connectionResult>")
					$resultsTableOfProcessedMembers += $resultsTableOfProcessedMemberEntry
				}
			}
		}
	}
    If ($replicated) {
		$continue = $false
	} Else {
		$host.UI.RawUI.CursorPosition = $oldpos
	}
}

###
# Show The Start Time, The End Time And The Duration Of The Replication
###
$endDateTime = Get-Date
$duration = "{0:n2}" -f ($endDateTime.Subtract($startDateTime).TotalSeconds)
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  Start Time......: $(Get-Date $startDateTime -format "yyyy-MM-dd HH:mm:ss")" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  End Time........: $(Get-Date $endDateTime -format "yyyy-MM-dd HH:mm:ss")" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  Duration........: $duration Seconds" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

###
# Delete The Temporary Canary File On The Source Member, Which Will Replicate To The Other Members
###
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  Deleting Temporary Canary File... " -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
Remove-Item $uncPathCanaryFileSource -Force
writeLog -dataToLog "  Temporary Canary File [$uncPathCanaryFileSource] Has Been Deleted On The Source Member [$sourceMemberFQDN]!" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

###
# Output The Results Table Containing The Information Of Each Domain Controller And How Long It Took To Reach That Domain Controllerr After The Creation On The Source RWDC
###
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "`n$($resultsTableOfProcessedMembers | Sort-Object -Property TimeDiscvrd | Format-Table * -Wrap -AutoSize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

###
# Checking If There Are Temporary Canary Files Left Over From Previous Executions Of The Script
###
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -eq "NTFRS") {
	writeLog -dataToLog "+++ TEMPORARY CANARY FILES FROM PREVIOUS EXECUTIONS EXIST IN THE REPLICATED FOLDER '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
}
# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -eq "DFSR") {
	writeLog -dataToLog "+++ TEMPORARY CANARY FILES FROM PREVIOUS EXECUTIONS EXIST IN THE REPLICATED FOLDER '$($dfsrReplFolderOptionChosen.'Repl Folder Name') ($dfsrReplFolderOptionChosenGroupName)' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
}
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "Checking Existence Of Temporary Canary Files From Previous Executions Of The Script Within The Folder '$uncPathFolderSource'..." -logFileOnly $false -noDateTimeInLogLine $false
$prevTempCanaryFiles = Get-ChildItem $uncPathFolderSource -Filter "$tempCanaryFileBaseName*.txt"
If (($prevTempCanaryFiles | Measure-Object).Count -gt 0) {
	writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "The Following Temporary Canary Files From Previous Executions Of The Script Were Found:" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	$prevTempCanaryFiles | ForEach-Object {
		writeLog -dataToLog "  $($_.FullName)" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	}
	writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
	$tempCanaryFileConfirmationOptions = @()
	$tempCanaryFileConfirmationOptions += "No"
	$tempCanaryFileConfirmationOptions += "Yes"
	$tempCanaryFileConfirmationSpecificOption = 0
	$defaultTempCanaryFileConfirmationSpecificNumericOption = $null
	$tempCanaryFileConfirmationNumericSelection = $null
	ForEach ($tempCanaryFileConfirmationOption in $tempCanaryFileConfirmationOptions) {
		$tempCanaryFileConfirmationSpecificOption++
		If ($tempCanaryFileConfirmationOption -eq $tempCanaryFileConfirmationOptions[0]) {
			writeLog -dataToLog "[$tempCanaryFileConfirmationSpecificOption] $($tempCanaryFileConfirmationOption.PadRight(75, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
			$defaultTempCanaryFileConfirmationSpecificNumericOption = $tempCanaryFileConfirmationSpecificOption
		} Else {
			writeLog -dataToLog "[$tempCanaryFileConfirmationSpecificOption] $tempCanaryFileConfirmationOption" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "REMARK: Specify A Number Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	Write-Host ""
	Do {
		$tempCanaryFileConfirmationNumericSelection = Read-Host "Cleanup Temp Canary Files Previous Executions?...."
	} Until (([int]$tempCanaryFileConfirmationNumericSelection -gt 0 -And [int]$tempCanaryFileConfirmationNumericSelection -le ($tempCanaryFileConfirmationOptions | Measure-Object).Count) -Or $([string]::IsNullOrEmpty($tempCanaryFileConfirmationNumericSelection)))
	If ([string]::IsNullOrEmpty($tempCanaryFileConfirmationNumericSelection)) {
		$tempCanaryFileConfirmationNumericSelection = $defaultTempCanaryFileConfirmationSpecificNumericOption
	}
	$tempCanaryFileConfirmationOptionChosen = $tempCanaryFileConfirmationOptions[$tempCanaryFileConfirmationNumericSelection - 1]
	writeLog -dataToLog " > Option Chosen: [$tempCanaryFileConfirmationNumericSelection] $tempCanaryFileConfirmationOptionChosen" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	If ($tempCanaryFileConfirmationOptionChosen -eq "Yes") {
		$prevTempCanaryFiles | ForEach-Object {
			writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  Deleting Temporary Canary File From Previous Execution Of The Script... " -logFileOnly $false -noDateTimeInLogLine $false
			Remove-Item $($_.FullName) -Force
			writeLog -dataToLog "  Temporary Canary File [$($_.FullName)] Has Been Deleted On The Source Member [$sourceMemberFQDN]!" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false			
		}
	}
} Else {
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "No Temporary Canary Files From Previous Executions Of The Script Were NOT Found" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
}