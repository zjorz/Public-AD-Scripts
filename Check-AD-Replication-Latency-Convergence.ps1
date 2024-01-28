###
# Parameters Used By Script
###
Param (
	[Parameter(Mandatory=$False)]
	[string]$targetNCDN,

	[Parameter(Mandatory=$False)]
	[ValidateSet("DomainAndGCs","DomainOnly")]
	[string]$targetedReplScope,
	
	[Parameter(Mandatory=$False)]
	[ValidatePattern("^(Fsmo|Discover|(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]*?\.[\d]+?)(?<=[\w\-]{2,})(?<![\w\-]{25}))$")]
	[string]$targetRWDC
)

###
# Version Of Script
###
$version = "v0.5, 2024-01-28"

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
		- https://github.com/zjorz/Public-AD-Scripts/blob/master/Check-AD-Replication-Latency-Convergence.ps1

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
			- Added few extra columns to output extra info of DCs,
			- Code Improvement: Better detection of unavailable DCs/GCs
			- Added screen adjustment section

		v0.1, 2013-03-02, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Initial version of the script
#>

<#
.SYNOPSIS
	This PoSH Script Checks The AD Replication Latency/Convergence Across Specified NC And Replication Scope

.DESCRIPTION
    This PoSH Script Checks The AD Replication Latency/Convergence Across Specified NC And Replication Scope
	This PoSH script provides the following functions:
	- It executes on a per specified NC basis. For multiple NCs use automation with parameters
	- For automation, it is possible to define the DN of an naming context, the replication scope (only applicable for domain NCs), and the RWDC to use as the source RWDC to create the temoporary canary object on
	- It supports non-interacive mode through automation with parameters, or interactive mode
	- It supports AD replication convergence check for any NC within an AD forest.
		- Configuration Partition As The Forest NC to test AD replication convergence/latency across the AD forest
		- Domain NCs with domain only scope to test AD replication convergence/latency across the AD domain
		- Domain NCs with domain and GCs scope to test AD replication convergence/latency across the AD domain and the GCs in other AD domains
		- App NCs to test AD replication convergence/latency across the application partition
	- As the source RWDC, it is possible to:
		- Use the FSMO
			- For the Configuration Partition  => FSMO = RWDC with Domain Naming Master FSMO Role (Partitions (Container) Object, Attribute fSMORoleOwner has NTDS Settings Object DN of RWDC)
			- For the Domain Partition         => FSMO = RWDC with PDC Emulator FSMO Role (Domain NC Object, Attribute fSMORoleOwner Has NTDS Settings Object DN of RWDC)
			- For the Application Partition    => FSMO = RWDC with Infrastructure Master FSMO Role (Infrastructure Object, Attribute fSMORoleOwner has NTDS Settings Object DN of RWDC)
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
	- All is displayed on screen using different colors depending on what is occuring. The same thing is also logged to a log file without colors
	- It checks if specified NC exists. If not, the script aborts.
	- It checks if specified RWDC exists. If not, the script aborts.

.PARAMETER targetNCDN
	With this parameter it is possible to specify the DN of a naming Context to target for AD Replication Convergence/Latency check


.PARAMETER targetedReplScope
	With this parameter it is possible to specify the replication scope when targeting a domain NC, being "Domain Only" (DomainOnly) or "Domain And GCs" (DomainAndGCs)

.PARAMETER targetRWDC
	With this parameter it is possible to specify the RWDC to use to create the temporary cabary object on. Options that are available for this are "Fsmo", "Discover" or the FQDN of an RWDC

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
	- No check is done for the required permissions		
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

###
# Clear The Screen
###
Clear-Host

###
# Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
###
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ CHECKING AD REPLICATION LATENCY/CONVERGENCE +++"
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
$ldapPort = 389
$gcPort = 3268
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
writeLog -dataToLog "                                                                       \/     \/" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
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
$searcherADNCs.Filter = "(&(objectClass=crossRef)(!(name=Enterprise Schema)))"
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
ForEach ($ncOption in $($tableOfNCsInADForest | Sort-Object -Property "NC Type" -Descending)) {
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
Write-Host ""
If ([String]::IsNullOrEmpty($targetNCDN)) {
	Do {
		$ncNumericSelection = Read-Host "Please Choose The Naming Context To Target.........."
	} Until (([int]$ncNumericSelection -gt 0 -And [int]$ncNumericSelection -le ($tableOfNCsInADForest | Measure-Object).Count) -Or $([string]::IsNullOrEmpty($ncNumericSelection)))
	If ([string]::IsNullOrEmpty($ncNumericSelection)) {
		$ncNumericSelection = $defaultNCSpecificNumericOption
	}
} Else {
	$ncNumericSelection = ($($tableOfNCsInADForest | Sort-Object -Property "NC Type" -Descending)."NC DN").IndexOf($targetNCDN) + 1
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
$ncOptionChosen = $($tableOfNCsInADForest | Sort-Object -Property "NC Type" -Descending)[$ncNumericSelection - 1]
writeLog -dataToLog " > Option Chosen: [$ncNumericSelection] $($ncOptionChosen.'NC DN') | Name/FQDN: $($ncOptionChosen.'Name/FQDN') | NC Type: $($ncOptionChosen.'NC Type')" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
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
	Write-Host ""
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
$searcherNTDSdsa.PropertiesToLoad.Add("distinguishedName") | Out-Null
$searcherNTDSdsa.PropertiesToLoad.Add("msDS-hasDomainNCs") | Out-Null
$searcherNTDSdsa.PropertiesToLoad.Add("msDS-hasMasterNCs") | Out-Null
$searcherNTDSdsa.PropertiesToLoad.Add("msDS-isGC") | Out-Null
$searcherNTDSdsa.PropertiesToLoad.Add("msDS-isRODC") | Out-Null
$ntdsDsaObjects = $searcherNTDSdsa.FindAll()
$tableOfDCsInADForest = @()
$ntdsDsaObjects | ForEach-Object {
	$ntdsSettingsDN = $_.Properties.distinguishedname[0]
	$dcName = $ntdsSettingsDN.Substring(("CN=NTDS Settings,CN=").Length)
	$dcName = $dcName.Substring(0,$dcName.IndexOf(","))
	$dcFQDN = convertNTDSSettingsObjectDNToFQDN -rwdcFQDN $rwdcFQDN -ntdsSettingsObjectDN $ntdsSettingsDN
	$dcIPv4 = Try {[System.Net.Dns]::GetHostAddresses($dcFQDN).IPAddressToString} Catch {"<Failed To Resolve>"}
	$dcSite = $ntdsSettingsDN.Substring(("CN=NTDS Settings,CN=$dcName,CN=Servers,CN=").Length)
	$dcSite = $dcSite.Substring(0,$dcSite.IndexOf(","))
	$dcDomainNC = $_.Properties."msds-hasdomainncs"[0]
	$dcType = $(If ($_.Properties."msds-isrodc"[0] -eq $true) {"RODC"} ElseIf ($_.Properties."msds-isrodc"[0] -eq $false) {"RWDC"} Else {"<Unknown>"})
	$dcIsGC = $_.Properties."msds-isgc"[0]
	If ($ncOptionChosen."NC Type" -eq "App NC" -And $dcType -eq "RWDC") {
		$hostedAppNCs = $_.Properties."msds-hasmasterncs" | Where-Object {$_ -ne $schemaNCDN -And $_ -ne $configNCDN -And $_ -ne $dcDomainNC}
	}
	$tableOfDCsInADForestEntry = New-Object -TypeName System.Object
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "DC Name" -Value $dcName
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $dcFQDN
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $dcIPv4
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $dcSite
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $dcType
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $dcDomainNC
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Root" -Value $(If ($dcDomainNC -eq $("DC=" + $adForestRootDomainObject.Name.Replace(".",",DC="))) {$true} Else {$false})
	$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $dcIsGC
	If ($ncOptionChosen."NC Type" -eq "App NC") {
		$tableOfDCsInADForestEntry | Add-Member -MemberType NoteProperty -Name "App NCs" -Value $(If ($dcType -eq "RWDC") {$hostedAppNCs} Else {$($appNCObjects | Where-Object {$_.Properties."msds-nc-ro-replica-locations" -contains "CN=NTDS Settings,CN=R1FSRODC1,CN=Servers,CN=BRANCH01,CN=Sites,CN=Configuration,DC=IAMTEC,DC=NET"} | ForEach-Object {$_.Properties.ncname})})
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
	$tableOfDCsInADForest | ForEach-Object {
		$tableOfDCsToProcessEntry = New-Object -TypeName System.Object
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Name" -Value $($_."DC Name")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $($_."DC FQDN")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $($_."DC IPv4")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($_."Site Name")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $($_."DC Type")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $($_."Domain NC")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Root" -Value $($_."Root")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $($_."Is GC")
		If ($ncOptionChosen."NC Type" -eq "App NC") {
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "App NCs" -Value $($_."App NCs")
		}
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $(If ($(portConnectionCheck -fqdnServer $($_."DC FQDN") -port $ldapPort -timeOut $connectionTimeout) -eq "SUCCESS") {$true} Else {$false})
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
		$tableOfDCsToProcess += $tableOfDCsToProcessEntry
	}
	$discoveredRWDCFQDN = $rwdcFQDN
	$searchRootFSMORoleOwner = [ADSI]"LDAP://$discoveredRWDCFQDN/CN=Partitions,$($ncOptionChosen.'NC DN')"
	$searcherFSMORoleOwner = New-Object System.DirectoryServices.DirectorySearcher($searchRootFSMORoleOwner)
	$fsmoRoleOwnerObject = $searcherFSMORoleOwner.FindOne()
	$ntdsSettingsObjectFsmoRoleOwnerDN = $fsmoRoleOwnerObject.Properties.fsmoroleowner[0]
	If ([String]::IsNullOrEmpty($ntdsSettingsObjectFsmoRoleOwnerDN) -Or $ntdsSettingsObjectFsmoRoleOwnerDN -match "0ADEL:") {
		$fsmoRoleOwnerFQDN = "UNDEFINED / INVALID"
	} Else {
		$fsmoRoleOwnerFQDN = convertNTDSSettingsObjectDNToFQDN -rwdcFQDN $rwdcFQDN -ntdsSettingsObjectDN $ntdsSettingsObjectFsmoRoleOwnerDN
	}	
}
If ($ncOptionChosen."NC Type" -eq "Domain NC") {
	If ($domainNCReplicationScopeOptionChosen -eq "Domain And All GCs") {
		writeLog -dataToLog "+++ LIST DCs SUPPORTING THE NAMING CONTEXT '$($ncOptionChosen."NC DN") ($($($ncOptionChosen.'Name/FQDN')))' (Domain And All GCs) +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		$tableOfDCsInADForest | Where-Object {$_."Domain NC" -eq $($ncOptionChosen."NC DN")} | ForEach-Object {
			$tableOfDCsToProcessEntry = New-Object -TypeName System.Object
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Name" -Value $($_."DC Name")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $($_."DC FQDN")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $($_."DC IPv4")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($_."Site Name")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $($_."DC Type")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $($_."Domain NC")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Root" -Value $($_."Root")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $($_."Is GC")
			If ($ncOptionChosen."NC Type" -eq "App NC") {
				$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "App NCs" -Value $($_."App NCs")
			}
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $(If ($(portConnectionCheck -fqdnServer $($_."DC FQDN") -port $ldapPort -timeOut $connectionTimeout) -eq "SUCCESS") {$true} Else {$false})
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
			$tableOfDCsToProcess += $tableOfDCsToProcessEntry
		}
		$tableOfDCsInADForest | Where-Object {$_."Domain NC" -ne $($ncOptionChosen."NC DN") -And $_."Is GC" -eq $true} | ForEach-Object {
			$tableOfDCsToProcessEntry = New-Object -TypeName System.Object
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Name" -Value $($_."DC Name")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $($_."DC FQDN")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $($_."DC IPv4")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($_."Site Name")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $($_."DC Type")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $($_."Domain NC")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Root" -Value $($_."Root")
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
		$tableOfDCsInADForest | Where-Object {$_."Domain NC" -eq $($ncOptionChosen."NC DN")} | ForEach-Object {
			$tableOfDCsToProcessEntry = New-Object -TypeName System.Object
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Name" -Value $($_."DC Name")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $($_."DC FQDN")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $($_."DC IPv4")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($_."Site Name")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $($_."DC Type")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $($_."Domain NC")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Root" -Value $($_."Root")
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $($_."Is GC")
			If ($ncOptionChosen."NC Type" -eq "App NC") {
				$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "App NCs" -Value $($_."App NCs")
			}
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $(If ($(portConnectionCheck -fqdnServer $($_."DC FQDN") -port $ldapPort -timeOut $connectionTimeout) -eq "SUCCESS") {$true} Else {$false})
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
			$tableOfDCsToProcess += $tableOfDCsToProcessEntry
		}
	}
	$discoveredRWDCFQDN = locateRWDC -fqdnADdomain $($ncOptionChosen.'Name/FQDN')
	$searchRootFSMORoleOwner = [ADSI]"LDAP://$discoveredRWDCFQDN/$($ncOptionChosen.'NC DN')"
	$searcherFSMORoleOwner = New-Object System.DirectoryServices.DirectorySearcher($searchRootFSMORoleOwner)
	$fsmoRoleOwnerObject = $searcherFSMORoleOwner.FindOne()
	$ntdsSettingsObjectFsmoRoleOwnerDN = $fsmoRoleOwnerObject.Properties.fsmoroleowner[0]
	If ([String]::IsNullOrEmpty($ntdsSettingsObjectFsmoRoleOwnerDN) -Or $ntdsSettingsObjectFsmoRoleOwnerDN -match "0ADEL:") {
		$fsmoRoleOwnerFQDN = "UNDEFINED / INVALID"
	} Else {
		$fsmoRoleOwnerFQDN = convertNTDSSettingsObjectDNToFQDN -rwdcFQDN $rwdcFQDN -ntdsSettingsObjectDN $ntdsSettingsObjectFsmoRoleOwnerDN
	}
}
If ($ncOptionChosen."NC Type" -eq "App NC") {
	writeLog -dataToLog "+++ LIST DCs SUPPORTING THE NAMING CONTEXT '$($ncOptionChosen."NC DN")' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	$tableOfDCsInADForest | Where-Object {$_."App NCs" -contains $($ncOptionChosen."NC DN")} | ForEach-Object {
		$tableOfDCsToProcessEntry = New-Object -TypeName System.Object
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Name" -Value $($_."DC Name")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $($_."DC FQDN")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $($_."DC IPv4")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($_."Site Name")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $($_."DC Type")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $($_."Domain NC")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Root" -Value $($_."Root")
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $($_."Is GC")
		If ($ncOptionChosen."NC Type" -eq "App NC") {
			$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "App NCs" -Value $($_."App NCs")
		}
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $(If ($(portConnectionCheck -fqdnServer $($_."DC FQDN") -port $ldapPort -timeOut $connectionTimeout) -eq "SUCCESS") {$true} Else {$false})
		$tableOfDCsToProcessEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
		$tableOfDCsToProcess += $tableOfDCsToProcessEntry
	}
	If ($($tableOfDCsToProcess | Where-Object {$_."Site Name" -eq $localComputerSiteName -And $_.Reachable -eq $true})) {
		$discoveredRWDCFQDN = $($tableOfDCsToProcess | Where-Object {$_."Site Name" -eq $localComputerSiteName -And $_.Reachable -eq $true})[0]."DC FQDN"
	} Else {
		$discoveredRWDCFQDN = $($tableOfDCsToProcess | Where-Object {$_.Reachable -eq $true})[0]."DC FQDN"
	}
	$searchRootFSMORoleOwner = [ADSI]"LDAP://$discoveredRWDCFQDN/CN=Infrastructure,$($ncOptionChosen.'NC DN')"
	$searcherFSMORoleOwner = New-Object System.DirectoryServices.DirectorySearcher($searchRootFSMORoleOwner)
	$fsmoRoleOwnerObject = $searcherFSMORoleOwner.FindOne()
	$ntdsSettingsObjectFsmoRoleOwnerDN = $fsmoRoleOwnerObject.Properties.fsmoroleowner[0]
	If ([String]::IsNullOrEmpty($ntdsSettingsObjectFsmoRoleOwnerDN) -Or $ntdsSettingsObjectFsmoRoleOwnerDN -match "0ADEL:") {
		$fsmoRoleOwnerFQDN = "UNDEFINED / INVALID"
	} Else {
		$fsmoRoleOwnerFQDN = convertNTDSSettingsObjectDNToFQDN -rwdcFQDN $rwdcFQDN -ntdsSettingsObjectDN $ntdsSettingsObjectFsmoRoleOwnerDN
	}
}
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "`n$($tableOfDCsToProcess | Format-Table * -Wrap -Autosize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
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
Write-Host ""
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
$tempCanaryObjectName = "_adReplConvergenceCheckTempObject_" + (Get-Date -f yyyyMMddHHmmss)
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
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  Temporary Canary Object [$tempCanaryObjectDN] Has Been Created On RWDC [$sourceRWDCFQDN] In Naming Context '$($ncOptionChosen."NC DN")'!" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

###
# Create The Results Table And Already Insert The Source RWDC As The First RWDC
###
$resultsTableOfProcessedDCs = @()
$resultsTableOfProcessedDCEntry = New-Object -TypeName System.Object
$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $(($tableOfDCsToProcess | Where-Object {$_."DC FQDN" -match $sourceRWDCFQDN})."DC FQDN")
$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $(($tableOfDCsToProcess | Where-Object {$_."DC FQDN" -match $sourceRWDCFQDN})."DC IPv4")
$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $(($tableOfDCsToProcess | Where-Object {$_."DC FQDN" -match $sourceRWDCFQDN})."Site Name")
$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $(($tableOfDCsToProcess | Where-Object {$_."DC FQDN" -match $sourceRWDCFQDN})."DC Type")
$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $(($tableOfDCsToProcess | Where-Object {$_."DC FQDN" -match $sourceRWDCFQDN})."Domain NC")
$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Root" -Value $(($tableOfDCsToProcess | Where-Object {$_."DC FQDN" -match $sourceRWDCFQDN})."Root")
$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $(($tableOfDCsToProcess | Where-Object {$_."DC FQDN" -match $sourceRWDCFQDN})."Is GC")
$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $(($tableOfDCsToProcess | Where-Object {$_."DC FQDN" -match $sourceRWDCFQDN})."Reachable")
$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Time" -Value $([decimal]$('{0:N2}' -f "0.00"))
$resultsTableOfProcessedDCs += $resultsTableOfProcessedDCEntry

###
# Go Through The Process Of Checking Each Domain Controller To See If The Temporary Canary Object Already Has Replicated To It
###
$startDateTime = Get-Date
$i = 0
writeLog -dataToLog "  --> Found [$($($tableOfDCsToProcess | Measure-Object).Count)] Domain Controllers(s) Supporting/Hosting The Chosen NC..." -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

While($continue) {
    $i++
    $oldpos = $host.UI.RawUI.CursorPosition
	writeLog -dataToLog "  =============================== CHECK $i ===============================" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "  REMARK: Each DC In The List Below Must Be At Least Accessible Through LDAP Over TCP ($ldapPort)" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	If ($ncOptionChosen."NC Type" -eq "Domain NC" -And $domainNCReplicationScopeOptionChosen -eq "Domain And All GCs") {
		writeLog -dataToLog "  REMARK: Each GC In The List Below Must Be At Least Accessible Through LDAP-GC Over TCP ($gcPort)" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	}
	writeLog -dataToLog "" -lineType "REMARK" -logFileOnly $false -noDateTimeInLogLine $false
	Start-Sleep 1
    $replicated = $true
	
	# For Each Domain Controller In The List/Table With DCs To Process '$tableOfDCsToProcess' Perform A Number Of Steps
    ForEach ($ntDsa in $tableOfDCsToProcess) {
		If ($ntDsa."DC FQDN" -match $sourceRWDCFQDN) {
			writeLog -dataToLog "  * Contacting DC For Naming Context '$($ncOptionChosen."NC DN")' ...[$($ntDsa."DC FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "     - DC Is Reachable..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "     - Object [$tempCanaryObjectDN] Exists In The Database" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
			continue
		}

		# If The Domain Controller Hosts The Forest NC, Or Hosts The Domain NC And Is Part Of The Domain NC, Or Hosts The App NC, Then Connect Through LDAP (TCP:389)
        If ($ncOptionChosen."NC Type" -eq "Forest NC" -Or ($ncOptionChosen."NC Type" -eq "Domain NC" -And $domainNCReplicationScopeOptionChosen -eq "Domain Only") -Or ($ncOptionChosen."NC Type" -eq "Domain NC" -And $domainNCReplicationScopeOptionChosen -eq "Domain And All GCs" -And $ntDsa."Domain NC" -eq $($ncOptionChosen."NC DN")) -Or $ncOptionChosen."NC Type" -eq "App NC") {
			writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  * Contacting DC For Naming Context '$($ncOptionChosen."NC DN")' ...[$($ntDsa."DC FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
			$connectionResult = $null
			If ($ntDsa.Reachable -eq $true) {
				writeLog -dataToLog "     - DC Is Reachable..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				$objectPath = [ADSI]"LDAP://$($ntDsa."DC FQDN")/$tempCanaryObjectDN"
				$connectionResult = "SUCCESS"
			}			
			If ($ntDsa.Reachable -eq $false) {
				writeLog -dataToLog "     - DC IS NOT Reachable..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				$connectionResult = "FAILURE"
			}			
		}
		
		# If The Domain Controller Hosts The Domain NC And Is NOT Part Of The Domain NC, Then Connect Through LDAP-GC (TCP:3268)
        If ($ncOptionChosen."NC Type" -eq "Domain NC" -And $domainNCReplicationScopeOptionChosen -eq "Domain And All GCs" -And $ntDsa."Domain NC" -ne $($ncOptionChosen."NC DN")) {
			writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  * Contacting GC For Naming Context '$($ncOptionChosen."NC DN")' ...[$($ntDsa."DC FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
			$connectionResult = $null
			If ($ntDsa.Reachable -eq $true) {
				writeLog -dataToLog "     - DC/GC Is Reachable..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				$objectPath = [ADSI]"GC://$($ntDsa."DC FQDN")/$tempCanaryObjectDN"
				$connectionResult = "SUCCESS"
			}			
			If ($ntDsa.Reachable -eq $false) {
				writeLog -dataToLog "     - DC/GC IS NOT Reachable..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				$connectionResult = "FAILURE"
			}
		}
        
		# If The Connection To The DC Is Successful
		If ($connectionResult -eq "SUCCESS") {
			If ($objectPath.name) { # If The Temp Canary Object Already Exists Populated The Results Table
				writeLog -dataToLog "     - Object [$tempCanaryObjectDN] Now Does Exist In The Database                               " -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				If ([string]::IsNullOrEmpty($($resultsTableOfProcessedDCs | Where-Object {$_."DC FQDN" -match $ntDsa."DC FQDN"}))) {
					$resultsTableOfProcessedDCEntry = New-Object -TypeName System.Object
					$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $($ntDsa."DC FQDN")
					$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $($ntDsa."DC IPv4")
					$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($ntDsa."Site Name")
					$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $($ntDsa."DC Type")
					$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $($ntDsa."Domain NC")
					$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Root" -Value $($ntDsa."Root")
					$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $($ntDsa."Is GC")
					$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $($ntDsa."Reachable")
					$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Time" -Value $([decimal]$("{0:n2}" -f ((Get-Date) - $startDateTime).TotalSeconds))
					$resultsTableOfProcessedDCs += $resultsTableOfProcessedDCEntry
				}
			} Else { # If The Temp Canary Object Does Not Yet Exist
				writeLog -dataToLog "     - Object [$tempCanaryObjectDN] Does NOT Exist (Yet) In The Database" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				$replicated  = $false
			}
		}
		
		# If The Connection To The DC Is Unsuccessful
		If ($connectionResult -eq "FAILURE") {
			writeLog -dataToLog "     - Unable To Connect To DC/GC And Check For The Temporary Canary Object..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			If ([string]::IsNullOrEmpty($($resultsTableOfProcessedDCs | Where-Object {$_."DC FQDN" -match $ntDsa."DC FQDN"}))) {
				$resultsTableOfProcessedDCEntry = New-Object -TypeName System.Object
				$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "DC FQDN" -Value $($ntDsa."DC FQDN")
				$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "DC IPv4" -Value $($ntDsa."DC IPv4")
				$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($ntDsa."Site Name")
				$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "DC Type" -Value $($ntDsa."DC Type")
				$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Domain NC" -Value $($ntDsa."Domain NC")
				$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Root" -Value $($ntDsa."Root")
				$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Is GC" -Value $($ntDsa."Is GC")
				$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Reachable" -Value $($ntDsa."Reachable")
				$resultsTableOfProcessedDCEntry | Add-Member -MemberType NoteProperty -Name "Time" -Value $([string]"<FAIL>")
				$resultsTableOfProcessedDCs += $resultsTableOfProcessedDCEntry
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
# Delete The Temp Canary Object On The Source RWDC, Which Will Replicate To The Other DCs/GCs
###
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  Deleting Temporary Canary Object... " -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
([ADSI]"LDAP://$sourceRWDCFQDN/$container").Delete("contact","CN=$tempCanaryObjectName")
writeLog -dataToLog "  Temp Canary Object [$tempCanaryObjectDN] Has Been Deleted On The Source RWDC!" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

###
# Output The Results Table Containing The Information Of Each Domain Controller And How Long It Took To Reach That Domain Controllerr After The Creation On The Source RWDC
###
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "`n$($resultsTableOfProcessedDCs | Sort-Object -Property Time | Format-Table -Wrap -AutoSize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false