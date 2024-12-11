###
# Parameters Used By Script
###
Param (
	[Parameter(Mandatory=$False)]
	[switch]$cleanupOrhanedCanaryObjects,

	[Parameter(Mandatory=$False)]
	[switch]$exportResultsToCSV,

	[Parameter(Mandatory=$False)]
	[switch]$skipOpenHTMLFileInBrowser,

	[Parameter(Mandatory=$False)]
	[switch]$skipCheckForOrphanedCanaryObjects,

	[Parameter(Mandatory=$False)]
	[ValidateSet("DomainAndGCs","DomainOnly")]
	[string]$targetedReplScope,

	[Parameter(Mandatory=$False)]
	[string]$targetNCDN,

	[Parameter(Mandatory=$False)]
	[ValidatePattern("^(Fsmo|Discover|(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]*?\.[\d]+?)(?<=[\w\-]{2,})(?<![\w\-]{25}))$")]
	[string]$targetRWDC
)

###
# Version Of Script
###
$version = "v1.0, 2024-12-11"

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
		- Documentation: https://github.com/zjorz/Public-AD-Scripts/blob/master/Check-AD-Replication-Latency-Convergence.md
		- Script: https://github.com/zjorz/Public-AD-Scripts/blob/master/Check-AD-Replication-Latency-Convergence.ps1

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
		- The content of the HTML file in the browser might suddenly appear to be blank. This might resolve by itself during the refresh or when the admin refreshes manually
		- Reachability of a certain DC depends on the required port being open, AND the speed a DC responds back. If the configured timeout is too low while a high latency is experienced, increase the configured timeout by using the XML configuration file

	RELEASE NOTES
		v1.0, 2024-12-11, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Improved User Experience: Changed the layout of the output on screen to display a summary of the progress.
			- Improved User Experience: Added URL for documentation to the ORIGINAL SOURCE(S) section above
			- Improved User Experience: Support for an XML file to specify environment specific connection parameters. At the same time this also allows upgrades/updates of the script without loosing those specify environment specific connection parameters
			- Improved User Experience: For a more detailed view of the progress, that information will automatically be displayed through an HTML file in a browser and refreshed every 5 seconds to display any changes.
			- Code Improvement: Implemented StrictMode Latest Version (Tested On PoSH 5.x And 7.x)
			- Code Improvement: Replaced "Get-WmiObject" with "Get-CimInstance" to also support PowerShell 7.x
			- New Feature: Added the function "showProgress" to display the progress of an action
			- New Feature: Added parameter to skip opening the HTML in a browser to support automation

		v0.9, 2024-09-03, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Improved User Experience: Added at the beginning the output of the command line and all parameters used
			- Improved User Experience: Faster processing due to paralellel processing through RunSpaces. (MAJOR CHANGE and WILL IMPACT CPU/RAM usage when checking against many members!)
				To configure the behavior of the processing in the Runspaces, review and update as needed the variables "$runspacePoolMinThreads", "$runspacePoolMaxThreads" And "$delayInMilliSecondsBetweenChecks"
				Inspired by:
				https://blog.netnerds.net/2016/12/runspaces-simplified/
				https://blog.netnerds.net/2016/12/immediately-output-runspace-results-to-the-pipeline/
				https://github.com/EliteLoser/misc/blob/master/PowerShell/PowerShell%20Runspace%20Example%20Template%20Code.ps1
				https://devblogs.microsoft.com/scripting/beginning-use-of-powershell-runspaces-part-1/
				https://devblogs.microsoft.com/scripting/beginning-use-of-powershell-runspaces-part-2/
				https://devblogs.microsoft.com/scripting/beginning-use-of-powershell-runspaces-part-3/
				https://devblogs.microsoft.com/scripting/weekend-scripter-a-look-at-the-poshrsjob-module/
			- Bug Fix: Added forgotten parameter to automatically cleanup orphaned canary objects when found
			- New Feature: Added parameter to skip cleaning of orphaned canary objects when found
			- New Feature: Added variable that specifies the delay in milliseconds between the checks for each DC/GC. The default is 0, which means NO DELAY and go for it!
			- New Feature: Added a parameter to allow the export of the results into a CSV

		v0.8, 2024-07-30, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Bug Fix: Fixed case sensitivity bug when specifying a Naming Context DN through the command line

		v0.7, 2024-02-06, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Improved User Experience: Added a check to determine if there are Temporary Canary Object leftovers from previous executions of the script that were not cleaned up because the script was aborted or it crashed
			- Improved User Experience: Previous the delta time was calculated when the object was found by the script and compare it to the start time. Now it provided 2 different timings:
				- The "TimeDiscvrd" (Time Discovered) specifies how much time it took to find/see the object on a DC
				- The "TimeReplctd" (Time Replicated) specifies how much time it took to reach the DC
			- Bug Fix: Fixed issue when the fsmoroleowner property did not contain a value
			- Improved User Experience: The naming context list presented is now consistently presented in the same order

		v0.6, 2024-01-31, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Code Improvement: Added additional information, minor changes

		v0.5, 2024-01-28, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Script Improvement: Complete rewrite of the script
			- New Feature: Parameters added to support automation
			- New Feature: Logging Function
			- New Feature: Support for all NCs (Configuration Partition As The Forest NC, Domain NCs With Domain Only Or Also Including GCs In Other AD Domains, And App NCs)
			- Code Improvement: As target RWDC use specific role owner, disccovered RWDC, specific RWDC

		v0.4, 2014-02-11, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Code Improvement: Added additional logic to determine if a DC is either an RWDC or RODC when it fails using the first logic and changed the layout a little bit

		v0.3, 2014-02-09, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Bug Fix: Solved a bug with regards to the detection/location of RWDCs and RODCs

		v0.2, 2014-02-01, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- New Feature: Added STOP option
			- Code Improvement: Added few extra columns to output extra info of DCs,
			- Code Improvement: Better detection of unavailable DCs/GCs
			- Code Improvement: Added screen adjustment section

		v0.1, 2013-03-02, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Initial version of the script
#>

<#
.SYNOPSIS
	This PoSH Script Checks The AD Replication Latency/Convergence Across Specified NC And Replication Scope

.DESCRIPTION
	This PoSH Script Checks The AD Replication Latency/Convergence Across Specified NC And Replication Scope

	This PoSH script provides the following functions:
	- It executes all checks in parallel at the same time against all DCs/GCs in scope.
	- It executes on a per specified NC basis. For multiple NCs use automation with parameters
	- For automation, it is possible to define the DN of an naming context, the replication scope (only applicable for domain NCs), and the RWDC to use as the source RWDC to create the temporary canary object on
	- It supports non-interacive mode through automation with parameters, or interactive mode
	- It supports AD replication convergence check for any NC within an AD forest.
		- Configuration Partition As The Forest NC to test AD replication convergence/latency across the AD forest. Connectivity check to DCs through TCP:LDAP/389 for the purpose of checking the existance of the canary object
		- Domain NCs with domain only scope to test AD replication convergence/latency across the AD domain. Connectivity check to DCs through TCP:LDAP/389
		- Domain NCs with domain and GCs scope to test AD replication convergence/latency across the AD domain and the GCs in other AD domains. Connectivity check to DCs through TCP:LDAP/389, and GCs through TCP:LDAP-GC/3268
		- App NCs to test AD replication convergence/latency across the application partition. Connectivity check to DCs through TCP:LDAP/389
	- As the source RWDC, it is possible to:
		- Use the FSMO of the naming context
			- For the Configuration Partition  => FSMO = RWDC with Domain Naming Master FSMO Role (Partitions (Container) Object, Attribute fSMORoleOwner has NTDS Settings Object DN of RWDC)
			- For the Domain Partition         => FSMO = RWDC with PDC Emulator FSMO Role (Domain NC Object, Attribute fSMORoleOwner Has NTDS Settings Object DN of RWDC)
			- For the Application Partition    => FSMO = RWDC with Infrastructure Master FSMO Role (Infrastructure Object, Attribute fSMORoleOwner has NTDS Settings Object DN of RWDC)
		- Use a discovered RWDC (best effort, especially with application partitions)
		- Specified the FQDN of a RWDC that hosts the naming context
	- For the temporary canary object:
		- Initially created on the source RWDC and deleted from the source RWDC at the end
		- ObjectClass     = contact
		- Name            = _adReplConvergenceCheckTempObject_yyyyMMddHHmmss (e.g. _adReplConvergenceCheckTempObject_20240102030405)
		- Description     = ...!!!...TEMP OBJECT TO TEST AD REPLICATION LATENCY/CONVERGENCE THROUGH THE '<NC TYPE>'...!!!...
		- Container:
			- For the Configuration Partition  => Container = "CN=Services,CN=Configuration,DC=<ROOT DOMAIN>,DC=<TLD>"
			- For the Domain Partition         => Container = "CN=Users,DC=<DOMAIN>,DC=<TLD>"
			- For the Application Partition    => Container = "<DN Of App Partition, e.g. DC=CustomAppNC OR DC=DomainDnsZones,DC=<DOMAIN>,DC=<TLD>"
		- Distinguished Name
			- For the Configuration Partition  => DN = "CN=_adReplConvergenceCheckTempObject_yyyyMMddHHmmss,CN=Services,CN=Configuration,DC=<ROOT DOMAIN>,DC=<TLD>"
			- For the Domain Partition         => DN = "CN=_adReplConvergenceCheckTempObject_yyyyMMddHHmmss,CN=Users,DC=<DOMAIN>,DC=<TLD>"
			- For the Application Partition    => DN = "CN=_adReplConvergenceCheckTempObject_yyyyMMddHHmmss,<DN Of App Partition, e.g. DC=CustomAppNC OR DC=DomainDnsZones,DC=<DOMAIN>,DC=<TLD>"
	- In the PowerShell command prompt window the global progress is displayed. The same thing is also logged to a log file
	- When a default browser is available/configured, the generated HTML file will be opened and automatically refreshed every 5 seconds as the script progresses. This HTML file displays the DC specific state/result
	- It checks if specified NC exists. If not, the script aborts.
	- It checks if specified RWDC exists. If not, the script aborts.
	- At the end it checks if any Temporary Canary Objects exist from previous execution of the script and offers to clean up (In the chosen NC only!).
	- Disjoint namespaces and discontiguous namespaces are supported
	- The script DOES NOT allow or support the schema partition to be targeted!
	- The script uses default values for specific connection parameters. If those do not meet expectation, an XML configuration file can be used with custom values.
	- For the specific NC, the script also checks if any remaining canary objects exists from previous script executions that either failed or were aborted. It provides the option to also clean those or not. Through a parameter
		it allows to default to always clean previous canary objects when found. This behavior is ignored when the parameter to skip the check of previous canary objects is used
	- In addition to displaying the end results on screen, it is also possible to export those end results to a CSV file
	- Through a parameter it is possible to not open the generated HTML in the default browser
	- Through a parameter it is possible to skip the check of previous canary objects
	- The script supports automation by using parameters with pre-specified details of the targeted Naming Context, if applicable the targeted Replication Scope and the targeted source RWDC

.PARAMETER cleanupOrhanedCanaryObjects
	With this parameter it is possible to automatically cleanup orphaned canary objects when found

.PARAMETER exportResultsToCSV
	With this parameter it is possible to export the results to a CSV file in addition of displaying it on screen on in the log file

.PARAMETER skipOpenHTMLFileInBrowser
	With this parameter it is possible to not open the HTML file in the default browser

.PARAMETER skipCheckForOrphanedCanaryObjects
	With this parameter it is possible to not check for orphaned canary objects

.PARAMETER targetedReplScope
	With this parameter it is possible to specify the replication scope when targeting a domain NC, being "Domain Only" (DomainOnly) or "Domain And GCs" (DomainAndGCs)

.PARAMETER targetNCDN
	With this parameter it is possible to specify the DN of a naming Context to target for AD Replication Convergence/Latency check

.PARAMETER targetRWDC
	With this parameter it is possible to specify the RWDC to use to create the temporary canary object on. Options that are available for this are "Fsmo", "Discover" or the FQDN of an RWDC

.EXAMPLE
	Check The AD Replication Convergence/Latency Using Interactive Mode

	.\Check-AD-Replication-Latency-Convergence.ps1

.EXAMPLE
	Check The AD Replication Convergence/Latency Using Automated Mode For The NC "DC=CustomAppNC1" Using The Fsmo Role Owner As The Source RWDC To Create The Temporary Canary Object On

	.\Check-AD-Replication-Latency-Convergence.ps1 -targetNCDN "DC=CustomAppNC1" -targetRWDC Fsmo

.EXAMPLE
	Check The AD Replication Convergence/Latency Using Automated Mode For The NC "CN=Configuration,DC=IAMTEC,DC=NET" Using The Fsmo Role Owner As The Source RWDC To Create The Temporary Canary Object On

	.\Check-AD-Replication-Latency-Convergence.ps1 -targetNCDN "CN=Configuration,DC=IAMTEC,DC=NET" -targetRWDC Discover

.EXAMPLE
	Check The AD Replication Convergence/Latency Using Automated Mode For The NC "DC=IAMTEC,DC=NET" Using A Specific RWDC As The Source RWDC To Create The Temporary Canary Object On, And Only Check Within The Domain Itself

	.\Check-AD-Replication-Latency-Convergence.ps1 -targetNCDN "DC=IAMTEC,DC=NET" -targetedReplScope DomainOnly -targetRWDC "R1FSRWDC1.IAMTEC.NET"

.EXAMPLE
	Check The AD Replication Convergence/Latency Using Automated Mode For The NC "DC=IAMTEC,DC=NET" Using A Specific RWDC As The Source RWDC To Create The Temporary Canary Object On, And Check Within The Domain And GCs

	.\Check-AD-Replication-Latency-Convergence.ps1 -targetNCDN "DC=IAMTEC,DC=NET" -targetedReplScope DomainAndGCs -targetRWDC "R1FSRWDC1.IAMTEC.NET"

.NOTES
	- To execute this script, the account running the script MUST have the permissions to create and delete the object type in the container used of the specified naming context. Being a member of the Enterprise Admins group
		in general allows the usage of the script against any naming context
	- The credentials used are the credentials of the logged on account. It is not possible to provided other credentials. Other credentials could maybe be used through RUNAS /NETONLY /USER
	- No check is done for the required permissions. The script simply assumes the required permissions are available. If not, errors will occur
	- The script DOES NOT allow or support the schema partition to be targeted!
	- No PowerShell modules are needed to use this script
	- Script Has StrictMode Enabled For Latest Version - Tested With PowerShell 7.4.6
	- Reachbility is determined by checking against the required ports (TCP:LDAP/389 for DCs, and where applicable TCP:LDAP-GC/3268) and if the DC/GC responds fast enough before the defined connection timeout
	- The XML file for the environment specific oonnection parameters should have the exact same name as the script and must be in the same folder as the script. If the script is renamed, the XML should be renamed accordingly.
		For example, if the script is called "Check-AD-Replication-Latency-Convergence_v10.ps1", the XML file should be called "Check-AD-Replication-Latency-Convergence_v10.xml". When a decision is made to use the XML
		Configuration File, then ALL connection parameters MUST be defined in it. It is an all or nothing thing. The structure of the XML file is:
============ Configuration XML file ============
<?xml version="1.0" encoding="utf-8"?>
<checkADReplConvergence xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<!-- Use The Connection Parameters In The XML Config File -->
	<useXMLConfigFileSettings>TRUE_OR_FALSE</useXMLConfigFileSettings>

	<!-- Default In Script = 500 | When Checking If The Host Is Reachable Over Certain Port, This Is The Timeout In Milliseconds -->
	<connectionTimeoutInMilliSeconds>REPLACE_WITH_NUMERIC_VALUE</connectionTimeoutInMilliSeconds>

	<!-- Default In Script = 30 | When Checking The Canary Object Against A Certain DC/GC, And The DC/GC Is Reachable, This Is The Amount Of Minutes, When Exceeded, It Stops Checking That DC/GC (This Could Be The Case When AD Replication Is Broken Somehow Or The DC/GC Is In A Unhealthy State) -->
	<timeoutInMinutes>REPLACE_WITH_NUMERIC_VALUE</timeoutInMinutes>

	<!-- Default In Script = 1 | Minimum Amount Of Threads Per Runspace Pool -->
	<runspacePoolMinThreads>REPLACE_WITH_NUMERIC_VALUE</runspacePoolMinThreads>

	<!-- Default In Script = 2048 | Minimum Amount Of Threads Per Runspace Pool -->
	<runspacePoolMaxThreads>REPLACE_WITH_NUMERIC_VALUE</runspacePoolMaxThreads>

	<!-- Default In Script = 500 | The Check Delay In Milliseconds Between Checks Against Each Individual DC/GC -->
	<delayInMilliSecondsBetweenChecks>REPLACE_WITH_NUMERIC_VALUE</delayInMilliSecondsBetweenChecks>
</checkADReplConvergence>
============ Configuration XML file ============
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
		[void]$([System.Net.Dns]::GetHostEntry($fqdnServer))
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
			[void]$($tcpPortSocket.EndConnect($portConnect))
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

### FUNCTION: Show Progress Of Operation
Function showProgress {
	Param(
		[int]$itemNr,
		[int]$totalItems,
		[string]$activityMessage
	)

	$progress = [int]((($itemNr - 1) / $totalItems) * 100)
	Write-Progress -Activity "Running $activityMessage" -status "Completed $progress %" -PercentComplete $progress
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

###
# Clear The Screen
###
Clear-Host
Set-StrictMode -Version Latest

###
# Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
###
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ CHECKING AD REPLICATION LATENCY/CONVERGENCE +++"
$uiConfig.ForegroundColor = "Yellow"
$uiConfigBufferSize = $uiConfig.BufferSize
$uiConfigBufferSize.Width = 500
$uiConfigBufferSize.Height = 9999
$uiConfigScreenSizeMax = $uiConfig.MaxPhysicalWindowSize
$uiConfigScreenSizeMaxWidth = $uiConfigScreenSizeMax.Width
$uiConfigScreenSizeMaxHeight = $uiConfigScreenSizeMax.Height
$uiConfigScreenSize = $uiConfig.WindowSize
If ($uiConfigScreenSizeMaxWidth -lt 220) {
	$uiConfigScreenSize.Width = $uiConfigScreenSizeMaxWidth
} Else {
	$uiConfigScreenSize.Width = 220
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
$currentScriptCmdLineUsed = $MyInvocation.Line
$currentScriptFolderPath = Split-Path $scriptFullPath -Parent
$currentScriptName = Split-Path $scriptFullPath -Leaf
$currentScriptConfigName = $currentScriptName.Replace("ps1","xml")
$scriptConfigFullPath = $currentScriptFolderPath + "\" + $currentScriptConfigName
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
[string]$replResultsExportCsvFullPath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_Check-AD-Replication-Latency-Convergence_ReplResults.csv")
[string]$htmlFullPath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_Check-AD-Replication-Latency-Convergence.html")
$ldapPort = 389                                 # LDAP Port
$gcPort = 3268                                  # LDAP-GC Port
If (Test-Path $scriptConfigFullPath) {
	[XML]$scriptConfig = Get-Content $scriptConfigFullPath

	$useXMLConfigFileSettings = $scriptConfig.checkADReplConvergence.useXMLConfigFileSettings
	If ($useXMLConfigFileSettings.ToUpper() -eq "TRUE") {
		$connectionParametersSource = "XML Config File '$scriptConfigFullPath'"

		$connectionTimeout = $scriptConfig.checkADReplConvergence.connectionTimeoutInMilliSeconds
		If ($connectionTimeout -notmatch "^\d+$") {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptConfigFullPath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'connectionTimeoutInMilliSeconds'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}

		$timeoutInMinutes = $scriptConfig.checkADReplConvergence.timeoutInMinutes
		If ($timeoutInMinutes -notmatch "^\d+$") {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptConfigFullPath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'timeoutInMinutes'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}

		$runspacePoolMinThreads = $scriptConfig.checkADReplConvergence.runspacePoolMinThreads
		If ($runspacePoolMinThreads -notmatch "^\d+$") {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptConfigFullPath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'runspacePoolMinThreads'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}

		$runspacePoolMaxThreads = $scriptConfig.checkADReplConvergence.runspacePoolMaxThreads
		If ($runspacePoolMaxThreads -notmatch "^\d+$") {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptConfigFullPath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'runspacePoolMaxThreads'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}

		$delayInMilliSecondsBetweenChecks = $scriptConfig.checkADReplConvergence.delayInMilliSecondsBetweenChecks
		If ($delayInMilliSecondsBetweenChecks -notmatch "^\d+$") {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptConfigFullPath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'delayInMilliSecondsBetweenChecks'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}
	} Else {
		$connectionParametersSource = "Default Values In Script - XML Config File Found, But Disabled"

		# XML Config File Was Found, But Its Usage Is Disabled => Using Default Values In Script
		$connectionTimeout = 500                        # When Checking If The Host Is Reachable Over Certain Port, This Is The Timeout In Milliseconds
		$timeoutInMinutes = 30                          # When Checking The Canary Object Against A Certain DC/GC, And The DC/GC Is Reachable, This Is The Amount Of Minutes, When Exceeded, It Stops Checking That DC/GC (This Could Be The Case When AD Replication Is Broken Somehow Or The DC/GC Is In A Unhealthy State)
		$runspacePoolMinThreads = 1                     # Minimum Amount Of Threads Per Runspace Pool
		$runspacePoolMaxThreads = 2048                  # Maximum Amount Of Threads Per Runspace Pool # [int]$env:NUMBER_OF_PROCESSORS + 1
		$delayInMilliSecondsBetweenChecks = 500         # The Check Delay In Milliseconds Between Checks Against Each Individual DC/GC.
	}
} Else {
	$connectionParametersSource = "Default Values In Script - No XML Config File Found"

	# No XML Config File Was Found => Using Default Values In Script
	$connectionTimeout = 500                        # When Checking If The Host Is Reachable Over Certain Port, This Is The Timeout In Milliseconds
	$timeoutInMinutes = 30                          # When Checking The Canary Object Against A Certain DC/GC, And The DC/GC Is Reachable, This Is The Amount Of Minutes, When Exceeded, It Stops Checking That DC/GC (This Could Be The Case When AD Replication Is Broken Somehow Or The DC/GC Is In A Unhealthy State)
	$runspacePoolMinThreads = 1                     # Minimum Amount Of Threads Per Runspace Pool
	$runspacePoolMaxThreads = 2048                  # Maximum Amount Of Threads Per Runspace Pool # [int]$env:NUMBER_OF_PROCESSORS + 1
	$delayInMilliSecondsBetweenChecks = 500         # The Check Delay In Milliseconds Between Checks Against Each Individual DC/GC.
}

$htmlBaseContent = @"
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<HTML xmlns="http://www.w3.org/1999/xhtml">
	<HEAD>
		<TITLE>AD REPLICATION LATENCY TEST</TITLE>
		<META HTTP-EQUIV="refresh" CONTENT="5">
		<STYLE>
			BODY {
				TEXT-ALIGN: CENTER;
				BACKGROUND-COLOR: #EBEBEB;
				FONT-FAMILY:VERDANA;
			}

			TABLE, TH, TD {
				BORDER-COLLAPSE: COLLAPSE;
				TEXT-ALIGN: CENTER;
			}

			TH {
				BACKGROUND-COLOR: #000000;
				COLOR: #FFFF00;
			}

			H1 {
				COLOR: RED;
			}

			.evenRow {
				BACKGROUND-COLOR: #E1D5E7;
			}

			.oddRow {
				BACKGROUND-COLOR: #D5E8D4;
			}

			[data-val="OK"] {
				COLOR: #008500;
			}

			[data-val="NOK"] {
				COLOR: #FF0000;
			}

			[data-val="NOTSET"] {
				COLOR: #FF8000;
			}
		</STYLE>
	</HEAD>

	<BODY>
		<H1>AD REPLICATION LATENCY/CONVERGENCE TEST</H1>
		<H3>(Provided By: IAMTEC)</H3>
		<P><img src="data:image/png;base64,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" alt="IAMTEC - Identity | Security | Recovery" /></P>
		<H3>REPLACEME_VERSION_DATE_TIME</H3>
		<H3>Execution: REPLACEME_EXECUTION_DATE_TIME</H3>
		<BR>
		<TABLE align="center" border="1">
			<TR><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #000000; COLOR: #FFFF00"><B>SOURCE RWDC FQDN:</B></TD><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #D4E1F5">REPLACEME_SOURCERWDC</TD></TR>
			<TR><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #000000; COLOR: #FFFF00"><B>OBJECT NAME:</B></TD><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #D4E1F5">REPLACEME_OBJNAME</TD></TR>
			<TR><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #000000; COLOR: #FFFF00"><B>OBJECT DESCRIPTION:</B></TD><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #D4E1F5">REPLACEME_OBJDESCRIPTION</TD></TR>
			<TR><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #000000; COLOR: #FFFF00"><B>NAMING CONTEXT DN:</B></TD><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #D4E1F5">REPLACEME_NCDN</TD></TR>
			<TR><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #000000; COLOR: #FFFF00"><B>CONTAINER DN:</B></TD><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #D4E1F5">REPLACEME_CONTAINERDN</TD></TR>
		</TABLE>
		<BR>
		<BR>
        
		<TABLE align="center" border="1">
			<TR><TH style = "width: 40px;">NR</TH><TH style = "width: 500px;">DC INSTANCE FQDN</TH><TH style = "width: 100px;">SOURCE</TH><TH style = "width: 150px;">PORT</TH><TH style = "width: 125px;">REACHABLE</TH><TH style = "width: 525px;">TEMPORARY CANARY OBJECT STATE IN DB OF INSTANCE</TH></TR>
			<!-- INSERT ROWS AFTER THIS LINE -->
			<!-- REPLACEME_DCLIST -->
			<!-- INSERT ROWS BEFORE THIS LINE -->
		</TABLE>
	</BODY>
</HTML>
"@

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
writeLog -dataToLog "                                          **********************************************************" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *     --> Test AD Replication Latency/Convergence <--    *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *            BLOG: Jorge's Quest For Knowledge           *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *   (URL: http://jorgequestforknowledge.wordpress.com/)  *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                    $version                    *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          **********************************************************" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

# SOURCE: https://patorjk.com/software/taag/#p=display&f=Graffiti&t=Test%0AAD%20Replication%0AConvergence
writeLog -dataToLog "                                                         ___________              __" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                                         \__    ___/___   _______/  |_" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                                           |    |_/ __ \ /  ___/\   __\" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                                           |    |\  ___/ \___ \  |  |" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                                           |____| \___  >____  > |__|" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                                                      \/     \/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                             _____  ________    __________              .__  .__               __  .__" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                            /  _  \ \______ \   \______   \ ____ ______ |  | |__| ____ _____ _/  |_|__| ____   ____" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                           /  /_\  \ |    |  \   |       _// __ \\____ \|  | |  |/ ___\\__  \\   __\  |/  _ \ /    \" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                          /    |    \|        \  |    |   \  ___/|  |_> >  |_|  \  \___ / __ \|  | |  (  <_> )   |  \" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                          \____|__  /_______  /  |____|_  /\___  >   __/|____/__|\___  >____  /__| |__|\____/|___|  /" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                  \/        \/          \/     \/|__|                \/     \/                    \/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
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

writeLog -dataToLog "Source Of Connection Parameters.......: $connectionParametersSource"
writeLog -dataToLog "Connection Timeout....................: $connectionTimeout Milliseconds"					# When Checking If The Host Is Reachable Over Certain Port, This Is The Timeout In Milliseconds
writeLog -dataToLog "Timeout In Minutes....................: $timeoutInMinutes Minutes"							# When Checking The Canary Object Against A Certain DC/GC, And The DC/GC Is Reachable, This Is The Amount Of Minutes, When Exceeded, It Stops Checking That DC/GC (This Could Be The Case When AD Replication Is Broken Somehow Or The DC/GC Is In A Unhealthy State)
writeLog -dataToLog "Runspace Minimum Threads..............: $runspacePoolMinThreads"							# Minimum Amount Of Threads Per Runspace Pool
writeLog -dataToLog "Runspace Maximum Threads..............: $runspacePoolMaxThreads"							# Maximum Amount Of Threads Per Runspace Pool # [int]$env:NUMBER_OF_PROCESSORS + 1
writeLog -dataToLog "Delay In Milliseconds Between Checks..: $delayInMilliSecondsBetweenChecks Milliseconds"	# The Check Delay In Milliseconds Between Checks Against Each Individual DC/GC.

If ($connectionParametersSource -eq "Default Values In Script - XML Config File Found, But Disabled") {
	# XML Config File Was Found, But Its Usage Is Disabled => Using Default Values In Script
	writeLog -dataToLog ""
	writeLog -dataToLog "The XML Config File '$scriptConfigFullPath' Was Found, But Its Usage Is Disabled..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Using The Default Values For The Connection Parameters As Defined In The Script!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
}

If ($connectionParametersSource -eq "Default Values In Script - No XML Config File Found") {
	# No XML Config File Was Found => Using Default Values In Script
	writeLog -dataToLog ""
	writeLog -dataToLog "The XML Config File '$scriptConfigFullPath' CANNOT Be Found!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Using The Default Values For The Connection Parameters As Defined In The Script!..." -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog ""
}

writeLog -dataToLog ""
writeLog -dataToLog "Command Line Used.....................: $currentScriptCmdLineUsed"
writeLog -dataToLog ""
writeLog -dataToLog "Log File Full Path....................: $scriptLogFullPath"
writeLog -dataToLog ""
writeLog -dataToLog "HTML File Full Path...................: $htmlFullPath"
writeLog -dataToLog ""
If ($exportResultsToCSV) {
	writeLog -dataToLog "Repl Results Export CSV Full Path.....: $replResultsExportCsvFullPath"
	writeLog -dataToLog ""
}

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
$domainNamingFSMORWDCObject = $thisADForest.NamingRoleOwner                 # Domain Naming FSMO Role Owner Object
writeLog -dataToLog "Forest Mode (Level)...................: $adForestMode ($adForestModeLevel)"
writeLog -dataToLog "Configuration Partition DN............: $configNCDN"
writeLog -dataToLog ""

###
# Discover An RWDC/GC For AD Queries
###
$rwdcFQDN = locateRWDC -fqdnADdomain $fqdnADDomainOfComputer                # Discovered RWDC Based On The Domain Membership Of the Computer Where This Script Is Running
$gcFQDN = $thisADForest.FindGlobalCatalog().Name                            # Discovered GC

###
# Get All NCs From The AD Forest, Create A Table, And Display That Table
###
$searchRootADNCs = [ADSI]"LDAP://$rwdcFQDN/CN=Partitions,$configNCDN"
$searcherADNCs = New-Object System.DirectoryServices.DirectorySearcher($searchRootADNCs)
$searcherADNCs.Filter = "(&(objectClass=crossRef)(systemFlags=*)(!(name=Enterprise Schema)))"
$adNCObjects = $searcherADNCs.FindAll()
$tableOfNCsInADForest = @()
$adNCObjects | %{
	$tableOfNCsInADForestEntry = New-Object -TypeName System.Object
	$tableOfNCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "NC DN" -Value $($_.Properties.ncname[0])
	$tableOfNCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Name/FQDN" -Value $(If ($_.Properties.systemflags[0] -eq 1) {$($_.Properties.name[0])} ElseIf (($_.Properties.systemflags[0] -band 2) -eq 2) {$($_.Properties.dnsroot[0])} Else {"N.A."})
	$tableOfNCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "NC Type" -Value $(If ($_.Properties.systemflags[0] -eq 1) {"Forest NC"} ElseIf (($_.Properties.systemflags[0] -band 2) -eq 2) {"Domain NC"} Else {"App NC"})
	$tableOfNCsInADForest += $tableOfNCsInADForestEntry
}

writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "+++ LIST OF NAMING CONTEXTS WITHIN THE AD FOREST '$($thisADForest.Name)' - PLEASE CHOOSE A NAMING CONTEXT TO TARGET +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
$ncSpecificOption = 0
$defaultNCSpecificNumericOption = $null
$ncNumericSelection = $null
ForEach ($ncOption in $($tableOfNCsInADForest | Sort-Object -Property "NC Type","NC DN" -Descending)) {
	$ncSpecificOption++
	If ($ncOption."Name/FQDN" -eq "Enterprise Configuration") {
		writeLog -dataToLog "[$ncSpecificOption] NC DN: $($ncOption.'NC DN'.PadRight(50, " ")) | Name/FQDN: $($ncOption.'Name/FQDN'.PadRight(35, " ")) | NC Type: $($ncOption.'NC Type'.PadRight(10, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
		$defaultNCSpecificNumericOption = $ncSpecificOption
	} Else {
		writeLog -dataToLog "[$ncSpecificOption] NC DN: $($ncOption.'NC DN'.PadRight(50, " ")) | Name/FQDN: $($ncOption.'Name/FQDN'.PadRight(35, " ")) | NC Type: $($ncOption.'NC Type')" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	}
}
writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "REMARK: Specify A Number Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
If ([String]::IsNullOrEmpty($targetNCDN)) {
	Do {
		$ncNumericSelection = Read-Host "Please Choose The Naming Context To Target.........."
	} Until (([int]$ncNumericSelection -gt 0 -And [int]$ncNumericSelection -le ($tableOfNCsInADForest | Measure-Object).Count) -Or $([string]::IsNullOrEmpty($ncNumericSelection)))
	If ([string]::IsNullOrEmpty($ncNumericSelection)) {
		$ncNumericSelection = $defaultNCSpecificNumericOption
	}
} Else {
	If ($targetNCDN -eq $schemaNCDN) {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Specified Naming Context '$schemaNCDN' IS NOT ALLOWED To Be Used With This Script And Also NOT Supported!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "To Check The Replication Convergence/Latency Throughout The AD Forest, Please Re-Run The Script And Use The Naming Context '$configNCDN' Instead!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		BREAK
	}
	$ncNumericSelection = ($($tableOfNCsInADForest | Sort-Object -Property "NC Type","NC DN" -Descending)."NC DN").ToUpper().IndexOf($targetNCDN.ToUpper()) + 1
	If ($ncNumericSelection -eq 0) {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Specified Naming Context '$targetNCDN' DOES NOT Exist In The List Of Naming Contexts In The AD Forest '$($thisADForest.Name)'" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Please Re-Run The Script And Make Sure To Specify A Correct Naming Context That Does Exist In The The AD Forest '$($thisADForest.Name)'" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		BREAK
	}
}
$ncOptionChosen = $($tableOfNCsInADForest | Sort-Object -Property "NC Type","NC DN" -Descending)[$ncNumericSelection - 1]
writeLog -dataToLog " > Option Chosen: [$ncNumericSelection] NC DN: $($ncOptionChosen.'NC DN') | Name/FQDN: $($ncOptionChosen.'Name/FQDN') | NC Type: $($ncOptionChosen.'NC Type')" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false

###
# If A Domain NC Is Chosen Ask What The Scope Of Replication Is, Domain Only Of Domain And GCs
###
If ($ncOptionChosen."NC Type" -eq "Domain NC") {
	$domainReplicationScopeToCheck = @()
	$domainReplicationScopeToCheck += "Domain And All GCs"
	$domainReplicationScopeToCheck += "Domain Only"

	writeLog -dataToLog "+++ SPECIFY THE REPLICATION SCOPE TO CHECK FOR THE DOMAIN NC '$($ncOptionChosen.'Name/FQDN')' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	$domainNCReplicationScopeSpecificOption = 0
	$defaultNCSpecificNumericOption = $null
	$domainNCReplicationScopeNumericSelection = $null
	ForEach ($domainNCReplicationScopeOption in $domainReplicationScopeToCheck) {
		$domainNCReplicationScopeSpecificOption++
		If ($domainNCReplicationScopeOption -eq $domainReplicationScopeToCheck[0]) {
			writeLog -dataToLog "[$domainNCReplicationScopeSpecificOption] $domainNCReplicationScopeOption [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
			$defaultDomainNCReplicationScopeSpecificNumericOption = $domainNCReplicationScopeSpecificOption
		} Else {
			writeLog -dataToLog "[$domainNCReplicationScopeSpecificOption] $domainNCReplicationScopeOption" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}
	writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "REMARK: Specify A Number Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	If ([String]::IsNullOrEmpty($targetedReplScope)) {
		Do {
			$domainNCReplicationScopeNumericSelection = Read-Host "Please Choose The Replication Scope To Target......."
		} Until (([int]$domainNCReplicationScopeNumericSelection -gt 0 -And [int]$domainNCReplicationScopeNumericSelection -le ($domainReplicationScopeToCheck | Measure-Object).Count) -Or $([string]::IsNullOrEmpty($domainNCReplicationScopeNumericSelection)))
		If ([string]::IsNullOrEmpty($domainNCReplicationScopeNumericSelection)) {
			$domainNCReplicationScopeNumericSelection = $defaultDomainNCReplicationScopeSpecificNumericOption
		}
	} Else {
		$domainReplicationScopeToCheckHT = @{}
		$domainReplicationScopeToCheckHT["DomainAndGCs"] = "Domain And All GCs"
		$domainReplicationScopeToCheckHT["DomainOnly"] = "Domain Only"
		$domainNCReplicationScopeNumericSelection = $domainReplicationScopeToCheck.IndexOf($domainReplicationScopeToCheckHT[$targetedReplScope]) + 1
	}
	$domainNCReplicationScopeOptionChosen = $domainReplicationScopeToCheck[$domainNCReplicationScopeNumericSelection - 1]
	writeLog -dataToLog " > Option Chosen: [$domainNCReplicationScopeNumericSelection] $domainNCReplicationScopeOptionChosen" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
}

###
# Get A List Of App NCs
###
If ($ncOptionChosen."NC Type" -eq "App NC") {
	$searchRootAppNC = [ADSI]"LDAP://$rwdcFQDN/CN=Partitions,$configNCDN"
	$searcherAppNC = New-Object System.DirectoryServices.DirectorySearcher($searchRootAppNC)
	$searcherAppNC.Filter = "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=4))"
	$appNCObjects = $searcherAppNC.FindAll()
}

###
# Get A List Of DCs (RW/RO) In The AD Forest, Including Their Characteristics
###
$searchRootNTDSdsa = [ADSI]"LDAP://$rwdcFQDN/CN=Sites,$configNCDN"
$searcherNTDSdsa = New-Object System.DirectoryServices.DirectorySearcher($searchRootNTDSdsa)
$searcherNTDSdsa.Filter = "(objectClass=nTDSDSA)"
[void]$($searcherNTDSdsa.PropertiesToLoad.Add("distinguishedName"))
[void]$($searcherNTDSdsa.PropertiesToLoad.Add("msDS-hasDomainNCs"))
[void]$($searcherNTDSdsa.PropertiesToLoad.Add("msDS-hasMasterNCs"))
[void]$($searcherNTDSdsa.PropertiesToLoad.Add("msDS-isGC"))
[void]$($searcherNTDSdsa.PropertiesToLoad.Add("msDS-isRODC"))
$ntdsDsaObjects = $searcherNTDSdsa.FindAll()
$tableOfDCsInADForest = @()
$ntdsDsaObjects | ForEach-Object {
	$ntdsSettingsDN = $_.Properties.distinguishedname[0]
	$dcName = $ntdsSettingsDN.Substring(("CN=NTDS Settings,CN=").Length)
	$dcName = $dcName.Substring(0,$dcName.IndexOf(","))
	$dcFQDN = convertNTDSSettingsObjectDNToFQDN -rwdcFQDN $rwdcFQDN -ntdsSettingsObjectDN $ntdsSettingsDN
	$dcIPv4 = Try {([System.Net.Dns]::GetHostEntry($dcFQDN).AddressList | Where-Object{$_.AddressFamily -eq "InterNetwork"}).IPAddressToString} Catch {"<UNKNOWN>"}
	$dcSite = $ntdsSettingsDN.Substring(("CN=NTDS Settings,CN=$dcName,CN=Servers,CN=").Length)
	$dcSite = $dcSite.Substring(0,$dcSite.IndexOf(","))
	$dcDomainNC = $_.Properties."msds-hasdomainncs"[0]
	$dcType = $(If ($_.Properties."msds-isrodc"[0] -eq $true) {"RODC"} ElseIf ($_.Properties."msds-isrodc"[0] -eq $false) {"RWDC"} Else {"<UNKNOWN>"})
	$dcIsGC = $_.Properties."msds-isgc"[0]
	If ($ncOptionChosen."NC Type" -eq "App NC") {
		If ($dcType -eq "RWDC") {
			$hostedAppNCs = $_.Properties."msds-hasmasterncs" | Where-Object {$_ -ne $schemaNCDN -And $_ -ne $configNCDN -And $_ -ne $dcDomainNC}
		}
		If ($dcType -eq "RODC") {
			$hostedAppNCs = $appNCObjects | Where-Object {$appNCObject = $_; ($appNCObject.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "msds-nc-ro-replica-locations" -And $appNCObject.Properties."msds-nc-ro-replica-locations" -contains $ntdsSettingsDN} | ForEach-Object {$_.Properties.ncname}
		}
	}
	$tableOfDCsInADForestEntry = New-Object -TypeName System.Object
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "DC Name" -Value $dcName
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $dcFQDN
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $dcIPv4
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $dcSite
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $dcType
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $dcDomainNC
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "In Root" -Value $(If ($dcDomainNC -eq $("DC=" + $adForestRootDomainObject.Name.Replace(".",",DC="))) {$true} Else {$false})
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $dcIsGC
	If ($ncOptionChosen."NC Type" -eq "App NC") {
		$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "App NCs" -Value $hostedAppNCs
	}
	$tableOfDCsInADForest += $tableOfDCsInADForestEntry
}
$tableOfDCsInADForest = $tableOfDCsInADForest | Sort-Object -Property "Domain NC","DC FQDN"

###
# For The NC Chosen, And if Applicable The Chosen Replication Scope, Build A List Of Directory Servers Supporting That NC And Replication Scope, And Finally Display That List
###
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
$tableOfDCsToProcess = @()
If ($ncOptionChosen."NC Type" -eq "Forest NC") {
	writeLog -dataToLog "+++ LIST DCs SUPPORTING THE NAMING CONTEXT '$($ncOptionChosen."NC DN") ($($($ncOptionChosen.'Name/FQDN')))' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	$iNr = 0
	$tableOfDCsInADForest | ForEach-Object {
		$iNr++
		showProgress -itemNr $iNr -activityMessage "Processing The Configuration And State For '$($_."DC FQDN")'" -totalItems $(($tableOfDCsInADForest | Measure-Object).Count)
		$tableOfDCsToProcessEntry = New-Object -TypeName System.Object
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Name" -Value $($_."DC Name")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $($_."DC FQDN")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $($_."DC IPv4")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($_."Site Name")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $($_."DC Type")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $($_."Domain NC")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "In Root" -Value $($_."In Root")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $($_."Is GC")
		If ($ncOptionChosen."NC Type" -eq "App NC") {
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "App NCs" -Value $($_."App NCs")
		}
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $(If ($(portConnectionCheck -fqdnServer $($_."DC FQDN") -port $ldapPort -timeOut $connectionTimeout) -eq "SUCCESS") {$true} Else {$false})
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
		$tableOfDCsToProcess += $tableOfDCsToProcessEntry
	}
	Write-Progress -Completed -Activity " "
	$discoveredRWDCFQDN = $rwdcFQDN
	$searchRootFSMORoleOwner = [ADSI]"LDAP://$discoveredRWDCFQDN/CN=Partitions,$($ncOptionChosen.'NC DN')"
	$searcherFSMORoleOwner = New-Object System.DirectoryServices.DirectorySearcher($searchRootFSMORoleOwner)
	$fsmoRoleOwnerObject = $searcherFSMORoleOwner.FindOne()
	If (($fsmoRoleOwnerObject.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -notcontains "fsmoroleowner") {
		$fsmoRoleOwnerFQDN = "UNDEFINED / INVALID"
	} ElseIf (($fsmoRoleOwnerObject.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "fsmoroleowner" -And $($fsmoRoleOwnerObject.Properties.fsmoroleowner[0]) -match "0ADEL:") {
		$fsmoRoleOwnerFQDN = "UNDEFINED / INVALID"
	} Else {
		$ntdsSettingsObjectFsmoRoleOwnerDN = $fsmoRoleOwnerObject.Properties.fsmoroleowner[0]
		$fsmoRoleOwnerFQDN = convertNTDSSettingsObjectDNToFQDN -rwdcFQDN $rwdcFQDN -ntdsSettingsObjectDN $ntdsSettingsObjectFsmoRoleOwnerDN
	}
}
If ($ncOptionChosen."NC Type" -eq "Domain NC") {
	If ($domainNCReplicationScopeOptionChosen -eq "Domain And All GCs") {
		writeLog -dataToLog "+++ LIST DCs SUPPORTING THE NAMING CONTEXT '$($ncOptionChosen."NC DN") ($($($ncOptionChosen.'Name/FQDN')))' (Domain And All GCs) +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		$iNr = 0
		$tableOfDCsInADForest | Where-Object {$_."Domain NC" -eq $($ncOptionChosen."NC DN")} | ForEach-Object {
			$iNr++
			showProgress -itemNr $iNr -activityMessage "Processing The Configuration And State For '$($_."DC FQDN")'" -totalItems $(($tableOfDCsInADForest | Where-Object {$_."Domain NC" -eq $($ncOptionChosen."NC DN")} | Measure-Object).Count)
			$tableOfDCsToProcessEntry = New-Object -TypeName System.Object
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Name" -Value $($_."DC Name")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $($_."DC FQDN")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $($_."DC IPv4")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($_."Site Name")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $($_."DC Type")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $($_."Domain NC")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "In Root" -Value $($_."In Root")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $($_."Is GC")
			If ($ncOptionChosen."NC Type" -eq "App NC") {
				$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "App NCs" -Value $($_."App NCs")
			}
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $(If ($(portConnectionCheck -fqdnServer $($_."DC FQDN") -port $ldapPort -timeOut $connectionTimeout) -eq "SUCCESS") {$true} Else {$false})
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
			$tableOfDCsToProcess += $tableOfDCsToProcessEntry
		}
		$iNr = 0
		$tableOfDCsInADForest | Where-Object {$_."Domain NC" -ne $($ncOptionChosen."NC DN") -And $_."Is GC" -eq $true} | ForEach-Object {
			$iNr++
			showProgress -itemNr $iNr -activityMessage "Processing The Configuration And State For '$($_."DC FQDN")'" -totalItems $(($tableOfDCsInADForest | Where-Object {$_."Domain NC" -ne $($ncOptionChosen."NC DN") -And $_."Is GC" -eq $true} | Measure-Object).Count)
			$tableOfDCsToProcessEntry = New-Object -TypeName System.Object
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Name" -Value $($_."DC Name")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $($_."DC FQDN")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $($_."DC IPv4")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($_."Site Name")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $($_."DC Type")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $($_."Domain NC")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "In Root" -Value $($_."In Root")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $($_."Is GC")
			If ($ncOptionChosen."NC Type" -eq "App NC") {
				$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "App NCs" -Value $($_."App NCs")
			}
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $(If ($(portConnectionCheck -fqdnServer $($_."DC FQDN") -port $gcPort -timeOut $connectionTimeout) -eq "SUCCESS") {$true} Else {$false})
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
			$tableOfDCsToProcess += $tableOfDCsToProcessEntry
		}
	}
	If ($domainNCReplicationScopeOptionChosen -eq "Domain Only") {
		writeLog -dataToLog "+++ LIST DCs SUPPORTING THE NAMING CONTEXT '$($ncOptionChosen."NC DN") ($($($ncOptionChosen.'Name/FQDN')))' (Domain Only) +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		$iNr = 0
		$tableOfDCsInADForest | Where-Object {$_."Domain NC" -eq $($ncOptionChosen."NC DN")} | ForEach-Object {
			$iNr++
			showProgress -itemNr $iNr -activityMessage "Processing The Configuration And State For '$($_."DC FQDN")'" -totalItems $(($tableOfDCsInADForest | Where-Object {$_."Domain NC" -eq $($ncOptionChosen."NC DN")} | Measure-Object).Count)
			$tableOfDCsToProcessEntry = New-Object -TypeName System.Object
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Name" -Value $($_."DC Name")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $($_."DC FQDN")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $($_."DC IPv4")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($_."Site Name")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $($_."DC Type")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $($_."Domain NC")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "In Root" -Value $($_."In Root")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $($_."Is GC")
			If ($ncOptionChosen."NC Type" -eq "App NC") {
				$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "App NCs" -Value $($_."App NCs")
			}
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $(If ($(portConnectionCheck -fqdnServer $($_."DC FQDN") -port $ldapPort -timeOut $connectionTimeout) -eq "SUCCESS") {$true} Else {$false})
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
			$tableOfDCsToProcess += $tableOfDCsToProcessEntry
		}
	}
	Write-Progress -Completed -Activity " "
	$discoveredRWDCFQDN = locateRWDC -fqdnADdomain $($ncOptionChosen.'Name/FQDN')
	$searchRootFSMORoleOwner = [ADSI]"LDAP://$discoveredRWDCFQDN/$($ncOptionChosen.'NC DN')"
	$searcherFSMORoleOwner = New-Object System.DirectoryServices.DirectorySearcher($searchRootFSMORoleOwner)
	$fsmoRoleOwnerObject = $searcherFSMORoleOwner.FindOne()
	If (($fsmoRoleOwnerObject.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -notcontains "fsmoroleowner") {
		$fsmoRoleOwnerFQDN = "UNDEFINED / INVALID"
	} ElseIf (($fsmoRoleOwnerObject.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "fsmoroleowner" -And $($fsmoRoleOwnerObject.Properties.fsmoroleowner[0]) -match "0ADEL:") {
		$fsmoRoleOwnerFQDN = "UNDEFINED / INVALID"
	} Else {
		$ntdsSettingsObjectFsmoRoleOwnerDN = $fsmoRoleOwnerObject.Properties.fsmoroleowner[0]
		$fsmoRoleOwnerFQDN = convertNTDSSettingsObjectDNToFQDN -rwdcFQDN $rwdcFQDN -ntdsSettingsObjectDN $ntdsSettingsObjectFsmoRoleOwnerDN
	}
}
If ($ncOptionChosen."NC Type" -eq "App NC") {
	writeLog -dataToLog "+++ LIST DCs SUPPORTING THE NAMING CONTEXT '$($ncOptionChosen."NC DN")' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	$iNr = 0
	$tableOfDCsInADForest | Where-Object {$_."App NCs" -contains $($ncOptionChosen."NC DN")} | ForEach-Object {
		$iNr++
		showProgress -itemNr $iNr -activityMessage "Processing The Configuration And State For '$($_."DC FQDN")'" -totalItems $(($tableOfDCsInADForest | Where-Object {$_."App NCs" -contains $($ncOptionChosen."NC DN")} | Measure-Object).Count)
		$tableOfDCsToProcessEntry = New-Object -TypeName System.Object
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Name" -Value $($_."DC Name")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $($_."DC FQDN")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $($_."DC IPv4")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($_."Site Name")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $($_."DC Type")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $($_."Domain NC")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "In Root" -Value $($_."In Root")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $($_."Is GC")
		If ($ncOptionChosen."NC Type" -eq "App NC") {
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "App NCs" -Value $($_."App NCs")
		}
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $(If ($(portConnectionCheck -fqdnServer $($_."DC FQDN") -port $ldapPort -timeOut $connectionTimeout) -eq "SUCCESS") {$true} Else {$false})
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
		$tableOfDCsToProcess += $tableOfDCsToProcessEntry
	}
	Write-Progress -Completed -Activity " "
	If ($($tableOfDCsToProcess | Where-Object {$_."Site Name" -eq $localComputerSiteName -And $_.Reachable -eq $true})) {
		$discoveredRWDCFQDN = $($tableOfDCsToProcess | Where-Object {$_."Site Name" -eq $localComputerSiteName -And $_.Reachable -eq $true})[0]."DC FQDN"
	} Else {
		$discoveredRWDCFQDN = $($tableOfDCsToProcess | Where-Object {$_.Reachable -eq $true})[0]."DC FQDN"
	}
	$searchRootFSMORoleOwner = [ADSI]"LDAP://$discoveredRWDCFQDN/CN=Infrastructure,$($ncOptionChosen.'NC DN')"
	$searcherFSMORoleOwner = New-Object System.DirectoryServices.DirectorySearcher($searchRootFSMORoleOwner)
	$fsmoRoleOwnerObject = $searcherFSMORoleOwner.FindOne()
	If (($fsmoRoleOwnerObject.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -notcontains "fsmoroleowner") {
		$fsmoRoleOwnerFQDN = "UNDEFINED / INVALID"
	} ElseIf (($fsmoRoleOwnerObject.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "fsmoroleowner" -And $($fsmoRoleOwnerObject.Properties.fsmoroleowner[0]) -match "0ADEL:") {
		$fsmoRoleOwnerFQDN = "UNDEFINED / INVALID"
	} Else {
		$ntdsSettingsObjectFsmoRoleOwnerDN = $fsmoRoleOwnerObject.Properties.fsmoroleowner[0]
		$fsmoRoleOwnerFQDN = convertNTDSSettingsObjectDNToFQDN -rwdcFQDN $rwdcFQDN -ntdsSettingsObjectDN $ntdsSettingsObjectFsmoRoleOwnerDN
	}
}
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "`n$($tableOfDCsToProcess | Format-Table -Property * -Wrap -Autosize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> Found [$($($tableOfDCsToProcess | Measure-Object).Count)] Domain Controllers(s) Supporting/Hosting The Chosen NC..." -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

###
# For The NC Chosen, Ask Which DC To Use As The Source RWDC To Create The Canary Object On
###
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "+++ SOURCE RWDC OPTIONS FOR THE NAMING CONTEXT '$($ncOptionChosen."NC DN")' - PLEASE CHOOSE AN RWDC TO BE THE SOURCE RWDC +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
$sourceRWDCOptions = @()
$sourceRWDCOptions += "FSMO [$fsmoRoleOwnerFQDN] ($(If ($ncOptionChosen."NC Type" -eq "Forest NC") {"Domain Naming Master FSMO"} ElseIf ($ncOptionChosen."NC Type" -eq "Domain NC") {"PDC Emulator FSMO"} Else {"Infrastructure FSMO"}))"
$sourceRWDCOptions += "Discovered RWDC [$discoveredRWDCFQDN]"
$sourceRWDCOptions += "Specify RWDC FQDN"
$sourceRWDCSpecificOption = 0
$defaultSourceRWDCSpecificNumericOption = $null
$sourceRWDCNumericSelection = $null
ForEach ($sourceRWDCOption in $sourceRWDCOptions) {
	$sourceRWDCSpecificOption++
	If ($fsmoRoleOwnerFQDN -ne "UNDEFINED / INVALID" -And $sourceRWDCOption -eq $sourceRWDCOptions[0]) {
		writeLog -dataToLog "[$sourceRWDCSpecificOption] $($sourceRWDCOption.PadRight(75, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
		$defaultSourceRWDCSpecificNumericOption = $sourceRWDCSpecificOption
	} ElseIf ($fsmoRoleOwnerFQDN -eq "UNDEFINED / INVALID" -And $sourceRWDCOption -eq $sourceRWDCOptions[1]) {
		writeLog -dataToLog "[$sourceRWDCSpecificOption] $($sourceRWDCOption.PadRight(75, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
		$defaultSourceRWDCSpecificNumericOption = $sourceRWDCSpecificOption
	} Else {
		writeLog -dataToLog "[$sourceRWDCSpecificOption] $sourceRWDCOption" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	}
}
writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "REMARK: Specify A Number Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
If ([String]::IsNullOrEmpty($targetRWDC)) {
	Do {
		$sourceRWDCNumericSelection = Read-Host "Please Choose Source RWDC To Use For The Object....."
	} Until (([int]$sourceRWDCNumericSelection -gt 0 -And [int]$sourceRWDCNumericSelection -le ($sourceRWDCOptions | Measure-Object).Count) -Or $([string]::IsNullOrEmpty($sourceRWDCNumericSelection)))
	If ([string]::IsNullOrEmpty($sourceRWDCNumericSelection)) {
		$sourceRWDCNumericSelection = $defaultSourceRWDCSpecificNumericOption
	}
} Else {
	$sourceRWDCOptionsHT = @{}
	$sourceRWDCOptionsHT["Fsmo"] = $sourceRWDCOptions[0]
	$sourceRWDCOptionsHT["Discover"] = $sourceRWDCOptions[1]
	If ($targetRWDC -match "(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]*?\.[\d]+?)(?<=[\w\-]{2,})(?<![\w\-]{25})") {
		$sourceRWDCOptionsHT[$targetRWDC] = $sourceRWDCOptions[2]
	}
	$sourceRWDCNumericSelection = $sourceRWDCOptions.IndexOf($sourceRWDCOptionsHT[$targetRWDC]) + 1
}
$sourceRWDCOptionChosen = $sourceRWDCOptions[$sourceRWDCNumericSelection - 1]
writeLog -dataToLog " > Option Chosen: [$sourceRWDCNumericSelection] $sourceRWDCOptionChosen" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
If ($sourceRWDCOptionChosen -eq "FSMO [$fsmoRoleOwnerFQDN] ($(If ($ncOptionChosen."NC Type" -eq "Forest NC") {"Domain Naming Master FSMO"} ElseIf ($ncOptionChosen."NC Type" -eq "Domain NC") {"PDC Emulator FSMO"} Else {"Infrastructure FSMO"}))") {
	$sourceRWDCFQDN = $fsmoRoleOwnerFQDN
}
If ($sourceRWDCOptionChosen -eq "Discovered RWDC [$discoveredRWDCFQDN]") {
	$sourceRWDCFQDN = $discoveredRWDCFQDN
}
If ($sourceRWDCOptionChosen -eq "Specify RWDC FQDN") {
	If ([String]::IsNullOrEmpty($targetRWDC)) {
		$sourceRWDCFQDN = Read-Host "Please Specify An RWDC That Supports The Chosen NC.."
	} Else {
		$sourceRWDCFQDN = $targetRWDC
	}
	writeLog -dataToLog " > RWDC Specified: $sourceRWDCFQDN" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
}

###
# Validate The RWDC Exists, Is Available And Can Be Used. Update The Table Of DCs To Process If It Can Be Used!
###
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "Checking Existence And Connectivity Of The Specified RWDC '$sourceRWDCFQDN' For The Naming Context '$($ncOptionChosen."NC DN")'..." -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
If ($(($ncOptionChosen."NC Type" -eq "Forest NC" -Or $ncOptionChosen."NC Type" -eq "App NC") -And $($tableOfDCsToProcess | Where-Object {$_."DC FQDN" -eq $sourceRWDCFQDN -And $_."DC Type" -eq "RWDC" -And $_.Reachable -eq $true})) -Or $($ncOptionChosen."NC Type" -eq "Domain NC" -And $($tableOfDCsToProcess | Where-Object {$_."DC FQDN" -eq $sourceRWDCFQDN -And $_."DC Type" -eq "RWDC" -And $_.Reachable -eq $true -And $_."Domain NC" -eq $($ncOptionChosen."NC DN")}))) {
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "The Specified DC '$sourceRWDCFQDN':" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " > Exists, And" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " > Is An RWDC, And" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " > Is Available/Reachable, And" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " > Supports/Hosts A Writable Copy Of The Chosen NC '$($ncOptionChosen."NC DN")'!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false

	($tableOfDCsToProcess | Where-Object {$_."DC FQDN" -eq $sourceRWDCFQDN})."Source" = $true
	($tableOfDCsToProcess | Where-Object {$_."DC FQDN" -ne $sourceRWDCFQDN}) | ForEach-Object {$_."Source" = $false}
	($tableOfDCsToProcess | Where-Object {$_."DC FQDN" -eq $sourceRWDCFQDN})."DC FQDN" = "$($sourceRWDCFQDN + " [SOURCE RWDC]")"
	$tableOfDCsToProcess = $tableOfDCsToProcess | Sort-Object -Property Source -Descending
} Else {
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "The Specified DC '$sourceRWDCFQDN':" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " > DOES NOT Exist, And/Or" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " > IS NOT An RWDC, And/Or" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " > IS NOT Available/Reachable, And/Or" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog " > DOES NOT Support/Host A Writable Copy Of The Chosen NC '$($ncOptionChosen."NC DN")'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Please Re-Run The Script And Make Sure To Use An RWDC That Is Available/Reachable And Supports/Hosts The Chosen NC '$($ncOptionChosen."NC DN")'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

	BREAK
}

###
# Define And Create The TEMP Object On The Chosen Source RWDC
###
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "+++ CREATING TEMPORARY CANARY OBJECT IN AD +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
If ($ncOptionChosen."NC Type" -eq "Forest NC") {
	$container = "CN=Services," + $($ncOptionChosen."NC DN")
}
If ($ncOptionChosen."NC Type" -eq "Domain NC") {
	$container = "CN=Users," + $($ncOptionChosen."NC DN")
}
If ($ncOptionChosen."NC Type" -eq "App NC") {
	$container = $($ncOptionChosen."NC DN")
}
$tempCanaryObjectBaseName = "_adReplConvergenceCheckTempObject_"
$tempCanaryObjectName = $tempCanaryObjectBaseName + (Get-Date -f yyyyMMddHHmmss)
$tempCanaryObjectDescription = "...!!!...TEMP OBJECT TO TEST AD REPLICATION LATENCY/CONVERGENCE THROUGH THE '$($ncOptionChosen."NC Type".ToUpper())'...!!!..."
writeLog -dataToLog "  --> On Source RWDC......: $sourceRWDCFQDN" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> With Full Name......: $tempCanaryObjectName" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> With Description....: $tempCanaryObjectDescription" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> In Naming Context...: $($ncOptionChosen."NC DN")" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> In Container........: $container" -logFileOnly $false -noDateTimeInLogLine $false
$tempCanaryObject = ([ADSI]"LDAP://$sourceRWDCFQDN/$container").Create("contact","CN=$tempCanaryObjectName")
$tempCanaryObject.Put("Description", $tempCanaryObjectDescription)
$tempCanaryObject.SetInfo()
$tempCanaryObjectDN = $tempCanaryObject.distinguishedname
$tempCanaryObjectWhenChanged = $tempCanaryObject.Properties.whenChanged[0]
$startDateTime = Get-Date
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  Temporary Canary Object [$tempCanaryObjectDN] Has Been Created On Source RWDC [$sourceRWDCFQDN] In Naming Context '$($ncOptionChosen."NC DN")'!" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

###
# Go Through The Process Of Checking Each Domain Controller To See If The Temporary Canary Object Already Has Replicated To It
###
$nrTotalDCsSupportingNC = $($tableOfDCsToProcess | Measure-Object).Count
$nrTotalDCsReachable = $($tableOfDCsToProcess | Where-Object {$_.Reachable -eq $true} | Measure-Object).Count
$nrTotalDCsUnreachable = $($tableOfDCsToProcess | Where-Object {$_.Reachable -eq $false} | Measure-Object).Count
writeLog -dataToLog "  --> Discovered Total Of [$nrTotalDCsSupportingNC] Domain Controllers(s) Supporting/Hosting The Chosen NC..." -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> Discovered Total Of [$nrTotalDCsReachable] REACHABLE Domain Controllers(s) Supporting/Hosting The Chosen NC..." -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> Discovered Total Of [$nrTotalDCsUnreachable] UNREACHABLE Domain Controllers(s) Supporting/Hosting The Chosen NC..." -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

# Create And Open Runspace Pool, Setup Runspaces Array With Min And Max Threads
$runspacePool = [RunspaceFactory]::CreateRunspacePool($runspacePoolMinThreads, $runspacePoolMaxThreads)
$runspacePool.ApartmentState = "MTA" # STA = Single Threaded Appartment, MTA = Multi Threaded Appartment
$runspacePool.Open()
$runspacesCollection = @()
$runspacesResults = @()

# Create The Base HTML File And Open In The Default Browser
$htmlContent1 = $htmlBaseContent.Replace("REPLACEME_EXECUTION_DATE_TIME",$([STRING]$execDateTimeYEAR + "-" + $("{0:D2}" -f $execDateTimeMONTH) + "-" + $("{0:D2}" -f $execDateTimeDAY) + " " + $("{0:D2}" -f $execDateTimeHOUR) + ":" + $("{0:D2}" -f $execDateTimeMINUTE) + ":" + $("{0:D2}" -f $execDateTimeSECOND)))
$htmlContent1 = $htmlContent1.Replace("REPLACEME_VERSION_DATE_TIME",$version)
$htmlContent1 = $htmlContent1.Replace("REPLACEME_SOURCERWDC",$sourceRWDCFQDN)
$htmlContent1 = $htmlContent1.Replace("REPLACEME_OBJNAME",$tempCanaryObjectName)
$htmlContent1 = $htmlContent1.Replace("REPLACEME_OBJDESCRIPTION",$tempCanaryObjectDescription)
$htmlContent1 = $htmlContent1.Replace("REPLACEME_NCDN",$($ncOptionChosen."NC DN"))
$htmlContent1 = $htmlContent1.Replace("REPLACEME_CONTAINERDN",$container)
$htmlContent1 | Out-File $htmlFullPath -Force
If (-not $skipOpenHTMLFileInBrowser) {
	Try {
		$ext = $htmlFullPath.Substring($htmlFullPath.LastIndexOf("."))
		[void]$((Get-ItemProperty "Registry::HKEY_Classes_root\$((Get-ItemProperty "Registry::HKEY_Classes_root\$ext" -ErrorAction Stop)."(default)")" -ErrorAction Stop)."(default)")
		writeLog -dataToLog "File Association Found For '$ext'. Opening The File '$htmlFullPath' With The Default File Handler" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		Invoke-Item $htmlFullPath
	} Catch {
		writeLog -dataToLog "No File Association Found For '$ext'. Cannot Open The File '$htmlFullPath'" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	}
}

# Reusable ScriptBlock That Needs To Be Executed Within Every Runspace. This Is The Stuff That Iteratively Needs To Be Executed
$scriptblock = {
	Param (
		[string]$ntDsaDCFQDN,
		[string]$ntDsaDCIPv4,
		[string]$ntDsaDCSite,
		[string]$ntDsaDCType,
		[string]$ntDsaDomainNC,
		[bool]$inRoot,
		[bool]$isGC,	
		[bool]$reachable,
		[string]$objectConnectionString,
		[DateTime]$tempCanaryObjectWhenChanged,
		[string]$sourceRWDCFQDN,
		[DateTime]$startDateTime,
		[Decimal]$timeoutInMinutes,
		[Decimal]$delayInMilliSecondsBetweenChecks
	)

	$objectPath = $null
	$checkResult = $null
	$objectWhenDiscvrd = $null
	$deltaDiscvrd = $null
	$objectWhenChanged = $null
	$deltaReplctd = $null
	$canaryObjectSource = $null
	$replicated = $null
	$continue = $true

	$startDateTimeIteration1 = Get-Date
	$startDateTimeIteration2 = Get-Date $startDateTimeIteration1 -format "yyyy-MM-dd HH:mm:ss"

	If ($ntDsaDCFQDN -match $sourceRWDCFQDN) {
		$ntDsaDCFQDN = $sourceRWDCFQDN
		$checkResult = "CHECK_OK"
		$objectWhenDiscvrd = Get-Date
		$deltaDiscvrd = $([decimal]$('{0:N2}' -f "0.00"))
		$objectWhenChanged = $tempCanaryObjectWhenChanged
		$deltaReplctd = $([decimal]$('{0:N2}' -f "0.00"))
		$canaryObjectSource = $true
	} Else {
		If ($reachable -eq $true) {
			While($continue -eq $true) {
				$objectPath = [ADSI]$objectConnectionString
				If (-not [string]::IsNullOrEmpty($objectPath.name)) {
					$replicated = $true
					$checkResult = "CHECK_OK"
					$objectWhenDiscvrd = Get-Date
					$deltaDiscvrd = $([decimal]$("{0:n2}" -f ($objectWhenDiscvrd - $startDateTime).TotalSeconds))
					$objectWhenChanged = $objectPath.Properties.whenChanged[0]
					$deltaReplctd = $([decimal]$("{0:n2}" -f ($objectWhenChanged - $tempCanaryObjectWhenChanged).TotalSeconds))
				} Else {
					$replicated = $false
					If ([decimal](New-TimeSpan -Start $startDateTimeIteration1 -End $(Get-Date)).TotalMinutes -ge [decimal]$timeoutInMinutes) {
						$checkResult = "TIMEOUT"
						$objectWhenDiscvrd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
						$deltaDiscvrd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
						$objectWhenChanged = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
						$deltaReplctd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
					} Else {
						$checkResult = "CHECK_OK"
					}
				}
				Start-Sleep -Milliseconds $delayInMilliSecondsBetweenChecks
				If ($replicated -eq $true -Or $checkResult -ne "CHECK_OK") {
					$continue = $false
				} Else {
					$continue = $true
				}
			}
		} Else {
			$checkResult = "NOT_REACHABLE"
			$objectWhenDiscvrd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
			$deltaDiscvrd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
			$objectWhenChanged = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
			$deltaReplctd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
		}
		$canaryObjectSource = $false
	}

	$endDateTimeIteration = Get-Date -format "yyyy-MM-dd HH:mm:ss"

	Return [PSCustomObject]@{
		ntDsaDCFQDN            = $ntDsaDCFQDN
		ntDsaDCIPv4            = $ntDsaDCIPv4
		ntDsaDCSite            = $ntDsaDCSite
		ntDsaDCType            = $ntDsaDCType
		ntDsaDomainNC          = $ntDsaDomainNC
		inRoot                 = $inRoot
		isGC                   = $isGC
		reachable              = $reachable
		canaryObjectSource     = $canaryObjectSource
		objectWhenDiscvrd      = $(If ($objectWhenDiscvrd -is [DateTime]) {$(Get-Date $objectWhenDiscvrd -f "yyyy-MM-dd HH:mm:ss")} Else {$objectWhenDiscvrd})
		deltaDiscvrd           = $deltaDiscvrd
		objectWhenChanged      = $(If ($objectWhenChanged -is [DateTime]) {$(Get-Date $objectWhenChanged -f "yyyy-MM-dd HH:mm:ss")} Else {$objectWhenChanged})
		deltaReplctd           = $deltaReplctd
		checkResult            = $checkResult
		startDateTimeIteration = $startDateTimeIteration2
		endDateTimeIteration   = $endDateTimeIteration
		objectConnectionString = $objectConnectionString
	}
}

# Define The Start Time For The Check And The Expected End Time If Applicable Due To A Possible Timeout. Adding 1 Extra Minute
$startDateTimeCheck = Get-Date
$endDateTimeCheck = $startDateTimeCheck.AddMinutes([decimal]$timeoutInMinutes + 1)

# For Each Domain Controller In The List/Table With DCs To Process '$tableOfDCsToProcess' Perform A Number Of Steps
$dcListHTML = @()
$tableOfDCsToProcess | ForEach-Object {
	$ntDsa = $_
	$rwdcInstanceFQDN = $ntDsa."DC FQDN".ToUpper()

	# If The Other Domain Controller Hosts The Forest NC, Or Hosts The Domain NC And Is Part Of The Domain NC, Or Hosts The App NC, Then Connect Through LDAP (TCP:389)
	If ($ncOptionChosen."NC Type" -eq "Forest NC" -Or ($ncOptionChosen."NC Type" -eq "Domain NC" -And $domainNCReplicationScopeOptionChosen -eq "Domain Only") -Or ($ncOptionChosen."NC Type" -eq "Domain NC" -And $domainNCReplicationScopeOptionChosen -eq "Domain And All GCs" -And $ntDsa."Domain NC" -eq $($ncOptionChosen."NC DN")) -Or $ncOptionChosen."NC Type" -eq "App NC") {
		$objectConnectionString = "LDAP://$($rwdcInstanceFQDN.Replace(' [SOURCE RWDC]',''))/$tempCanaryObjectDN"
	}

	# If The Domain Controller Hosts The Domain NC And Is NOT Part Of The Domain NC, Then Connect Through LDAP-GC (TCP:3268)
	If ($ncOptionChosen."NC Type" -eq "Domain NC" -And $domainNCReplicationScopeOptionChosen -eq "Domain And All GCs" -And $ntDsa."Domain NC" -ne $($ncOptionChosen."NC DN")) {
		$objectConnectionString = "GC://$($rwdcInstanceFQDN.Replace(' [SOURCE RWDC]',''))/$tempCanaryObjectDN"
	}

	$dcNr = ($dcListHTML | Measure-Object).Count + 1
	$rowType = If (($dcNr % 2 -eq 0) -eq $true) {"evenRow"} Else {"oddRow"}

	# Only For The Domain Controller Used As The Source RWDC
	If ($rwdcInstanceFQDN -match $sourceRWDCFQDN) {
		$dcListHTML += "<TR class=`"$rowType`"><TD>$dcNr</TD><TD>$sourceRWDCFQDN</TD><TD>TRUE</TD><TD>LDAP (389)</TD><TD data-val=`"OK`">TRUE</TD><TD data-val=`"OK`">NOW DOES EXIST</TD></TR>"
	}

	# For The Other Domain Controllers.....
	If ($rwdcInstanceFQDN -notmatch $sourceRWDCFQDN) {
		# If The Other Domain Controller Hosts The Forest NC, Or Hosts The Domain NC And Is Part Of The Domain NC, Or Hosts The App NC, Then Connect Through LDAP (TCP:389)
		If ($ncOptionChosen."NC Type" -eq "Forest NC" -Or ($ncOptionChosen."NC Type" -eq "Domain NC" -And $domainNCReplicationScopeOptionChosen -eq "Domain Only") -Or ($ncOptionChosen."NC Type" -eq "Domain NC" -And $domainNCReplicationScopeOptionChosen -eq "Domain And All GCs" -And $ntDsa."Domain NC" -eq $($ncOptionChosen."NC DN")) -Or $ncOptionChosen."NC Type" -eq "App NC") {
			If ($ntDsa.Reachable -eq $true) {
				$dcListHTML += "<TR class=`"$rowType`"><TD>$dcNr</TD><TD>$rwdcInstanceFQDN</TD><TD>FALSE</TD><TD>LDAP (389)</TD><TD data-val=`"OK`">TRUE</TD><TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD></TR>"
			}
			If ($ntDsa.Reachable -eq $false) {
				$dcListHTML += "<TR class=`"$rowType`"><TD>$dcNr</TD><TD>$rwdcInstanceFQDN</TD><TD>FALSE</TD><TD>LDAP (389)</TD><TD data-val=`"NOK`">FALSE</TD><TD data-val=`"NOK`">UNABLE TO CHECK</TD></TR>"
			}
		}

		# If The Domain Controller Hosts The Domain NC And Is NOT Part Of The Domain NC, Then Connect Through LDAP-GC (TCP:3268)
		If ($ncOptionChosen."NC Type" -eq "Domain NC" -And $domainNCReplicationScopeOptionChosen -eq "Domain And All GCs" -And $ntDsa."Domain NC" -ne $($ncOptionChosen."NC DN")) {
			If ($ntDsa.Reachable -eq $true) {
				$dcListHTML += "<TR class=`"$rowType`"><TD>$dcNr</TD><TD>$rwdcInstanceFQDN</TD><TD>FALSE</TD><TD>LDAP-GC (3268)</TD><TD data-val=`"OK`">TRUE</TD><TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD></TR>"
			}
			If ($ntDsa.Reachable -eq $false) {
				$dcListHTML += "<TR class=`"$rowType`"><TD>$dcNr</TD><TD>$rwdcInstanceFQDN</TD><TD>FALSE</TD><TD>LDAP-GC (3268)</TD><TD data-val=`"NOK`">FALSE</TD><TD data-val=`"NOK`">UNABLE TO CHECK</TD></TR>"
			}
		}
	}
	
	$runspaceIteration = [PowerShell]::Create()
	[void]$($runspaceIteration.AddScript($scriptblock))
	[void]$($runspaceIteration.AddArgument($rwdcInstanceFQDN))
	[void]$($runspaceIteration.AddArgument($ntDsa."DC IPv4"))
	[void]$($runspaceIteration.AddArgument($ntDsa."Site Name"))
	[void]$($runspaceIteration.AddArgument($ntDsa."DC Type"))
	[void]$($runspaceIteration.AddArgument($ntDsa."Domain NC"))
	[void]$($runspaceIteration.AddArgument($ntDsa."In Root"))
	[void]$($runspaceIteration.AddArgument($ntDsa."Is GC"))
	[void]$($runspaceIteration.AddArgument($ntDsa."Reachable"))
	[void]$($runspaceIteration.AddArgument($objectConnectionString))
	[void]$($runspaceIteration.AddArgument($tempCanaryObjectWhenChanged))
	[void]$($runspaceIteration.AddArgument($sourceRWDCFQDN))
	[void]$($runspaceIteration.AddArgument($startDateTime))
	[void]$($runspaceIteration.AddArgument($timeoutInMinutes))
	[void]$($runspaceIteration.AddArgument($delayInMilliSecondsBetweenChecks))

	# Assign The Runspace To The Runspace Pool
	$runspaceIteration.RunspacePool = $runspacePool

	# Add The Runspace To The Runspaces Collection, And Start The Runspace
	$runspacesCollection += [PSCustomObject]@{ Pipe = $runspaceIteration; Status = $runspaceIteration.BeginInvoke() }
}

# Write The Data To The HTML File Which Will Refresh Automatically In The Browser
$htmlContent2 = $htmlContent1.Replace("<!-- REPLACEME_DCLIST -->", $dcListHTML)
$htmlContent2 = $htmlContent2.Replace("</TR> <TR","</TR>`n<TR")
$htmlContent2 | Out-File $htmlFullPath -Force

# Get The Data From The Runspaces That Were Created
$nrTotalDCsObjectDetected = 0
$nrTotalDCsTimedOut = 0
While ($runspacesCollection.Status -ne $null) {
	$nrTotalDCsObjectNotDetectedYet = 0
	$completedRunspaces = @()
	$runspacesCollection | ForEach-Object {
		$runSpace = $_
		If ($runSpace.Status) {
			$runSpaceStatus = $runSpace.Status
			If ($runSpaceStatus.IsCompleted -eq $true) {
				$completedRunspaces += $runSpace
			}
			If ($runSpaceStatus.IsCompleted -eq $false) {
				$nrTotalDCsObjectNotDetectedYet++
			}
		}
	}

	ForEach ($completedRunspaceIteration in $completedRunspaces) {
		# When Desired, Process Data HERE As Soon As It Becomes Available From Any Runspace
		$runspaceResult = $completedRunspaceIteration.Pipe.EndInvoke($completedRunspaceIteration.Status)
		$rwdcInstanceFQDN = $runspaceResult.ntDsaDCFQDN.ToUpper()

		If ($($runspaceResult.checkResult) -eq "CHECK_OK") {
			$nrTotalDCsObjectDetected++
			If ($rwdcInstanceFQDN -eq $sourceRWDCFQDN) {
				$dcListHTML[$($dcListHTML.IndexOf($($dcListHTML | Where-Object {$_ -match $rwdcInstanceFQDN})))] = ($dcListHTML | Where-Object {$_ -match $rwdcInstanceFQDN}).Replace("<TD data-val=`"OK`">NOW DOES EXIST</TD>","<TD data-val=`"OK`">NOW DOES EXIST</TD>")
			} Else {
				$dcListHTML[$($dcListHTML.IndexOf($($dcListHTML | Where-Object {$_ -match $rwdcInstanceFQDN})))] = ($dcListHTML | Where-Object {$_ -match $rwdcInstanceFQDN}).Replace("<TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD>","<TD data-val=`"OK`">NOW DOES EXIST</TD>")
			}
		} ElseIf ($($runspaceResult.checkResult) -eq "TIMEOUT") {
			$nrTotalDCsTimedOut++
			$dcListHTML[$($dcListHTML.IndexOf($($dcListHTML | Where-Object {$_ -match $rwdcInstanceFQDN})))] = ($dcListHTML | Where-Object {$_ -match $rwdcInstanceFQDN}).Replace("<TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD>","<TD data-val=`"NOK`">UNABLE TO CHECK (TIMEOUT)</TD>")
		} ElseIf ($($runspaceResult.checkResult) -eq "NOT_REACHABLE") {
			$dcListHTML[$($dcListHTML.IndexOf($($dcListHTML | Where-Object {$_ -match $rwdcInstanceFQDN})))] = ($dcListHTML | Where-Object {$_ -match $rwdcInstanceFQDN}).Replace("<TD data-val=`"NOK`">UNABLE TO CHECK</TD>","<TD data-val=`"NOK`">UNABLE TO CHECK (UNREACHABLE)</TD>")
		} Else { # "UNKNOWN_ERROR"
			$nrTotalDCsUnreachable++
			$dcListHTML[$($dcListHTML.IndexOf($($dcListHTML | Where-Object {$_ -match $rwdcInstanceFQDN})))] = ($dcListHTML | Where-Object {$_ -match $rwdcInstanceFQDN}).Replace("<TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD>","<TD data-val=`"NOK`">UNABLE TO CHECK (UNKNOWN)</TD>")
		}

		$runspacesResults += $runspaceResult
		$completedRunspaceIteration.Status = $null
		$completedRunspaceIteration.Pipe.Dispose()
	}
	
	# If The Other Domain Controller Hosts The Forest NC, Or Hosts The Domain NC And Is Part Of The Domain NC, Or Hosts The App NC, Then Connect Through LDAP (TCP:389)
	If ($ncOptionChosen."NC Type" -eq "Forest NC" -Or ($ncOptionChosen."NC Type" -eq "Domain NC" -And $domainNCReplicationScopeOptionChosen -eq "Domain Only") -Or ($ncOptionChosen."NC Type" -eq "Domain NC" -And $domainNCReplicationScopeOptionChosen -eq "Domain And All GCs" -And $ntDsa."Domain NC" -eq $($ncOptionChosen."NC DN")) -Or $ncOptionChosen."NC Type" -eq "App NC") {
		writeLog -dataToLog "  # DCs Supporting NC: $nrTotalDCsSupportingNC >> # DCs Unreachable: $nrTotalDCsUnreachable | # DCs Object Detected: $nrTotalDCsObjectDetected | # DCs Object Not Detected Yet: $nrTotalDCsObjectNotDetectedYet | # DCs Timed Out: $nrTotalDCsTimedOut | Approx $([decimal]$("{0:n2}" -f ($endDateTimeCheck - $(Get-Date)).TotalMinutes)) Minutes Remaining Before Timeout" -logFileOnly $false -noDateTimeInLogLine $false
	}

	# If The Domain Controller Hosts The Domain NC And Is NOT Part Of The Domain NC, Then Connect Through LDAP-GC (TCP:3268)
	If ($ncOptionChosen."NC Type" -eq "Domain NC" -And $domainNCReplicationScopeOptionChosen -eq "Domain And All GCs" -And $ntDsa."Domain NC" -ne $($ncOptionChosen."NC DN")) {
		writeLog -dataToLog "  # DCs/GCs Supporting NC: $nrTotalDCsSupportingNC >> # DCs/GCs Unreachable: $nrTotalDCsUnreachable | # DCs/GCs Object Detected: $nrTotalDCsObjectDetected | # DCs/GCs Object Not Detected Yet: $nrTotalDCsObjectNotDetectedYet | # DCs Timed Out: $nrTotalDCsTimedOut | Approx $([decimal]$("{0:n2}" -f ($endDateTimeCheck - $(Get-Date)).TotalMinutes)) Minutes Remaining Before Timeout" -logFileOnly $false -noDateTimeInLogLine $false
	}

	# Write The Data To The HTML File Which Will Refresh Automatically In The Browser
	$htmlContent2 = $htmlContent1.Replace("<!-- REPLACEME_DCLIST -->", $dcListHTML)
	$htmlContent2 = $htmlContent2.Replace("</TR> <TR","</TR>`n<TR")
	$htmlContent2 | Out-File $htmlFullPath -Force

	Start-Sleep -s 1
}

# Close The Runspace And Clean It Up
$runspacePool.Close() 
$runspacePool.Dispose()

###
# Create The Results Table Containing The Information Of Each Domain Controller And How Long It Took To Reach That Domain Controller/Global Catalog After The Creation On The Source RWDC
###
$resultsTableOfProcessedDCs = @()
$runspacesResults | ForEach-Object {
	$resultsTableOfProcessedDsaEntry = New-Object -TypeName System.Object
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $($_.ntDsaDCFQDN)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $($_.ntDsaDCIPv4)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($_.ntDsaDCSite)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $($_.ntDsaDCType)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $($_.ntDsaDomainNC)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "In Root" -Value $($_.inRoot)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $($_.isGC)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $($_.reachable)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $($_.canaryObjectSource)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "When Discvrd" -Value $($_.objectWhenDiscvrd)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "Delta Discvrd" -Value $($_.deltaDiscvrd)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "When Changed" -Value $($_.objectWhenChanged)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "Delta Replctd" -Value $($_.deltaReplctd)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "Start Iteration" -Value $($_.startDateTimeIteration)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "End Iteration" -Value $($_.endDateTimeIteration)
	$resultsTableOfProcessedDsaEntry | Add-Member -MemberType NoteProperty -Name "Object Connection String" -Value $($_.objectConnectionString)
	$resultsTableOfProcessedDCs += $resultsTableOfProcessedDsaEntry
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
# Delete The Temporary Canary Object On The Source RWDC, Which Will Replicate To The Other DCs/GCs
###
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  Deleting Temporary Canary Object... " -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
([ADSI]"LDAP://$sourceRWDCFQDN/$container").Delete("contact","CN=$tempCanaryObjectName")
writeLog -dataToLog "  Temporary Canary Object [$tempCanaryObjectDN] Has Been Deleted On Source RWDC [$sourceRWDCFQDN]!" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

###
# Output The Results Table Containing The Information Of Each Domain Controller And How Long It Took To Reach That Domain Controller After The Creation On The Source RWDC
###
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "`n$($resultsTableOfProcessedDCs | Sort-Object -Property Reachable,'Delta Replctd' | Format-Table -Property * -Wrap -AutoSize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "Log File Full Path....................: $scriptLogFullPath"
writeLog -dataToLog ""
writeLog -dataToLog "HTML File Full Path...................: $htmlFullPath"
writeLog -dataToLog ""
If ($exportResultsToCSV) {
	$resultsTableOfProcessedDCs | Sort-Object -Property Reachable,'Delta Replctd' | Export-Csv -Path $replResultsExportCsvFullPath -Delimiter ";" -NoTypeInformation
	writeLog -dataToLog "Repl Results Export CSV Full Path.....: $replResultsExportCsvFullPath" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
}

If (-not $skipCheckForOrphanedCanaryObjects) {
	###
	# Checking If There Are Temporary Canary Objects Left Over From Previous Executions Of The Script
	###
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "+++ TEMPORARY CANARY OBJECTS FROM PREVIOUS EXECUTIONS EXIST IN THE NAMING CONTEXT '$($ncOptionChosen."NC DN")' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Checking Existence Of Temporary Canary Objects From Previous Executions Of The Script Within The Container '$container'..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	$searchRootPrevTempCanaryObjs = [ADSI]"LDAP://$sourceRWDCFQDN/$container"
	$searcherPrevTempCanaryObjs = New-Object System.DirectoryServices.DirectorySearcher($searchRootPrevTempCanaryObjs)
	$searcherPrevTempCanaryObjs.Filter = "(&(objectClass=contact)(name=$tempCanaryObjectBaseName*))"
	$prevTempCanaryObjs = $searcherPrevTempCanaryObjs.FindAll()
	If (($prevTempCanaryObjs | Measure-Object).Count -gt 0) {
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Following Temporary Canary Objects From Previous Executions Of The Script Were Found:" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		$prevTempCanaryObjs | ForEach-Object {
			writeLog -dataToLog "  $($_.Properties.distinguishedname[0])" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		}
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "WARNING" -logFileOnly $false -noDateTimeInLogLine $false
		$tempCanaryObjConfirmationOptions = @()
		$tempCanaryObjConfirmationOptions += "No"
		$tempCanaryObjConfirmationOptions += "Yes"
		$tempCanaryObjConfirmationSpecificOption = 0
		$defaultTempCanaryObjConfirmationSpecificNumericOption = $null
		$tempCanaryObjConfirmationNumericSelection = $null
		ForEach ($tempCanaryObjConfirmationOption in $tempCanaryObjConfirmationOptions) {
			$tempCanaryObjConfirmationSpecificOption++
			If ($tempCanaryObjConfirmationOption -eq $tempCanaryObjConfirmationOptions[0]) {
				writeLog -dataToLog "[$tempCanaryObjConfirmationSpecificOption] $($tempCanaryObjConfirmationOption.PadRight(75, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
				$defaultTempCanaryObjConfirmationSpecificNumericOption = $tempCanaryObjConfirmationSpecificOption
			} Else {
				writeLog -dataToLog "[$tempCanaryObjConfirmationSpecificOption] $tempCanaryObjConfirmationOption" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
			}
		}
		writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "REMARK: Specify A Number Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		If (-not $cleanupOrhanedCanaryObjects) {
			Do {
				$tempCanaryObjConfirmationNumericSelection = Read-Host "Cleanup Temp Canary Objects Previous Executions?...."
			} Until (([int]$tempCanaryObjConfirmationNumericSelection -gt 0 -And [int]$tempCanaryObjConfirmationNumericSelection -le ($tempCanaryObjConfirmationOptions | Measure-Object).Count) -Or $([string]::IsNullOrEmpty($tempCanaryObjConfirmationNumericSelection)))
			If ([string]::IsNullOrEmpty($tempCanaryObjConfirmationNumericSelection)) {
				$tempCanaryObjConfirmationNumericSelection = $defaultTempCanaryObjConfirmationSpecificNumericOption
			}
		} Else {
			$tempCanaryObjConfirmationNumericSelection = $tempCanaryObjConfirmationOptions.ToUpper().IndexOf("YES".ToUpper()) + 1
		}
		$tempCanaryObjConfirmationOptionChosen = $tempCanaryObjConfirmationOptions[$tempCanaryObjConfirmationNumericSelection - 1]
		writeLog -dataToLog " > Option Chosen: [$tempCanaryObjConfirmationNumericSelection] $tempCanaryObjConfirmationOptionChosen" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
		If ($tempCanaryObjConfirmationOptionChosen -eq "Yes") {
			$prevTempCanaryObjs | ForEach-Object {
				writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  Deleting Temporary Canary Object From Previous Execution Of The Script... " -logFileOnly $false -noDateTimeInLogLine $false
				([ADSI]"LDAP://$sourceRWDCFQDN/$container").Delete("contact","CN=$($_.Properties.name[0])")
				writeLog -dataToLog "  Temporary Canary Object [$($_.Properties.distinguishedname[0])] Has Been Deleted On Source RWDC [$sourceRWDCFQDN]!" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false			
			}
		}
	} Else {
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "No Temporary Canary Objects From Previous Executions Of The Script Were Found" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	}
}