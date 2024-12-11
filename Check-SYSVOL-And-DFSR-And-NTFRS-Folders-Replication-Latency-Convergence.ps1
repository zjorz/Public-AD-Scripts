###
# Parameters Used By Script
###
Param (
	[Parameter(Mandatory=$False)]
	[switch]$cleanupOrhanedCanaryFiles,

	[Parameter(Mandatory=$False)]
	[switch]$exportResultsToCSV,

	[Parameter(Mandatory=$False)]
	[switch]$skipCheckForOrphanedCanaryFiles,

	[Parameter(Mandatory=$False)]
	[switch]$skipFileCount,

	[Parameter(Mandatory=$False)]
	[switch]$skipOpenHTMLFileInBrowser,

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
$version = "v0.9, 2024-12-11"

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
		- Documentation: https://github.com/zjorz/Public-AD-Scripts/blob/master/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.md
		- Script: https://github.com/zjorz/Public-AD-Scripts/blob/master/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1

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
		- When migrating SYSVOL Replication from NTFRS to DFSR, the NTFRS Replica Set for the SYSVOL might still show up with no replication mechanism specified. This will resolve itself as soon as ALL DCs have reached the ELIMINATED state!
		- Without additional tooling on every Replica Member, it is not possible to determine when the file arrived at a specific Replica Member. The calculation is therefore done when the script "sees" the file on a Replica Member
		- The content of the HTML file in the browser might suddenly appear to be blank. This might resolve by itself during the refresh or when the admin refreshes manually
		- Reachability of a certain replica member depends on the required port being open, AND the speed a replica member responds back. If the configured timeout is too low while a high latency is experienced, increase the configured timeout by using the XML configuration file

	RELEASE NOTES
		v0.9, 2024-12-11, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Improved User Experience: Changed the layout of the output on screen to display a summary of the progress.
			- Improved User Experience: Added URL for documentation to the ORIGINAL SOURCE(S) section above
			- Improved User Experience: Support for an XML file to specify environment specific connection parameters. At the same time this also allows upgrades/updates of the script without loosing those specify environment specific connection parameters
			- Improved User Experience: For a more detailed view of the progress, that information will automatically be displayed through an HTML file in a browser and refreshed every 5 seconds to display any changes.
			- Code Improvement: Implemented StrictMode Latest Version (Tested On PoSH 5.x And 7.x)
			- Code Improvement: Replaced "Get-WmiObject" with "Get-CimInstance" to also support PowerShell 7.x
			- New Feature: Added the function "showProgress" to display the progress of an action
			- New Feature: Added parameter to skip opening the HTML in a browser to support automation

		v0.8, 2024-09-03, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
			- Code Improvement: DFSR - For scenarios where metadata cleanup was not fully complete where also the "msDFSR-Member" is cleaned, an additional check is added to make sure the "msDFSR-Member" object has a value for "msDFSR-ComputerReference"
			- Code Improvement: NTFRS - For scenarios where metadata cleanup was not fully complete where also the "nTFRSMember" is cleaned, an additional check is added to make sure the "nTFRSMember" object has a value for "frsComputerReference"
			- Code Improvement: Better/improved detection of replication mechanism used for SYSVOL
			- Code Improvement: Redefined reachability specifically for WinRM and SMB
			- Improved User Experience: Added a check to determine if orphaned metadata exists of replication members for either NTFRS and DFS-R
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
			- Improved User Experience: Added at the beginning the output of the command line and all parameters used
			- New Feature: Added the function "checkDNExistence" to check if an object exists or not
			- New Feature: SYSVOL Repl through NTFRS only is supported, SYSVOL Repl through DFSR only is supported and now also SYSVOL Repl through both NTFRS and DFSR (only when migrating, in either the PREPARED or REDIRECTED state) is supported
			- Bug Fix: Added forgotten parameter to automatically cleanup orphaned canary files when found
			- Bug Fix: The value specified for the parameter targetReplMember now is used
			- Bug Fix: Corrected the name of the log that is created
			- New Feature: Added parameter to skip cleaning of orphaned canary files when found
			- New Feature: Added variable that specifies the delay in milliseconds between the checks for each member. The default is 0, which means NO DELAY and go for it!
			- New Feature: Added a parameter to allow the export of the results into a CSV

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
	- It executes all checks in parallel at the same time against all replica members in scope.
	- It executes on a per replicated folder basis. For multiple replicated folder use automation with parameters.
	- For automation, it is possible to define the FQDN of the AD Domain to target, the name of the replica set (NTFRS) or the name of the replicated folder (DFSR) within that AD domain, and the member to use as the source
		member to create the temoporary canary file on.
	- It supports non-interacive mode through automation with parameters, or interactive mode.
	- It supports file replication convergence check for any replica set (NTFRS) or replicated folder (DFSR) within an AD forest.
		- Connectivity check to replica members through TCP:WinRM/5985 for the purpose of counting files locally on the replica member
		- Connectivity check to replica members through TCP:SMB/5985 for the purpose of checking the existance of the canary file
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
	- In the PowerShell command prompt window the global progress is displayed. The same thing is also logged to a log file
	- When a default browser is available/configured, the generated HTML file will be opened and automatically refreshed every 5 seconds as the script progresses. This HTML file displays the replica member specific state/result
	- It checks if specified replica set (NTFRS) or replicated folder (DFSR) exists. If not, the script aborts.
	- It checks if specified member exists. If not, the script aborts.
	- At the end it checks if any Temporary Canary Files exist from previous execution of the script and offers to clean up (In the chosen Replicated Folder only!).
	- Disjoint namespaces and discontiguous namespaces are supported.
	- The script uses default values for specific connection parameters. If those do not meet expectation, an XML configuration file can be used with custom values.
	- For the specific replicated folder, the script also checks if any remaining canary files exists from previous script executions that either failed or were aborted. It provides the option to also clean those or not.
		Through a parameter it allows to default to always clean previous canary files when found. This behavior is ignored when the parameter to skip the check of previous canary files is used
	- In addition to displaying the end results on screen, it is also possible to export those end results to a CSV file
	- Through a parameter it is possible to skip the check of previous canary files
	- During interactive mode, after specifying the source member, it will count the files in the replicated folder on every member by default. This can be disabled through a parameter.
	- Through a parameter it is possible to not open the generated HTML in the default browser
	- The script supports automation by using parameters with pre-specified details of the targeted Domain FQDN, the targeted Replicated Folder and the targeted source Replica Member

.PARAMETER cleanupOrhanedCanaryFiles
	With this parameter it is possible to automatically cleanup orphaned canary files when found

.PARAMETER exportResultsToCSV
	With this parameter it is possible to export the results to a CSV file in addition of displaying it on screen on in the log file

.PARAMETER skipCheckForOrphanedCanaryFiles
	With this parameter it is possible not to check for orphaned canary files

.PARAMETER skipFileCount
	With this parameter it is possible not count files in the replicated folder on every member

.PARAMETER skipOpenHTMLFileInBrowser
	With this parameter it is possible to not open the HTML file in the default browser

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
	- No check is done for the required permissions. The script simply assumes the required permissions are available. If not, errors will occur
	- No PowerShell modules are needed to use this script
	- For the SYSVOL, it only works correctly when either using NTFRS, or DFSR in a completed state!
	- Admin shares MUST be enabled
	- For File Count, WinRM must be possible against the remote machines (TCP:WinRM/5985)
	- Yes, I'm aware, there is duplicate code to support both NTFRS and DFSR. This was the easiest way to support both without too much complexity. It also allows to remove it easily when NTFRS cannot be used anymore
	- Detailed NTFRS Info: https://www.betaarchive.com/wiki/index.php?title=Microsoft_KB_Archive/296183
	- Script Has StrictMode Enabled For Latest Version - Tested With PowerShell 7.4.5
	- Reachbility for counting files locally on the member within the replicated folder is determined by checking against the required port (WinRM HTTP Transport Port TCP:5985 for Replica Members) and if the member responds
		fast enough before the defined connection timeout
	- Reachbility for checking the existance of the canary file on the member within the replicated folder is determined by checking against the required port (SMB Over TCP/IP TCP:445 for Replica Members) and if the member
		responds fast enough before the defined connection timeout
	- The XML file for the environment specific oonnection parameters should have the exact same name as the script and must be in the same folder as the script. If the script is renamed, the XML should be renamed accordingly.
		For example, if the script is called "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_v09.ps1", the XML file should be called "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_v09.xml".
		When a decision is made to use the XML Configuration File, then ALL connection parameters MUST be defined in it. The structure of the XML file is:
============ Configuration XML file ============
<?xml version="1.0" encoding="utf-8"?>
<checkFileReplConvergence xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<!-- Use The Connection Parameters In The XML Config File -->
	<useXMLConfigFileSettings>TRUE_OR_FALSE</useXMLConfigFileSettings>

	<!-- Default In Script = 500 | When Checking If The Host Is Reachable Over Certain Port, This Is The Timeout In Milliseconds -->
	<connectionTimeoutInMilliSeconds>REPLACE_WITH_NUMERIC_VALUE</connectionTimeoutInMilliSeconds>

	<!-- Default In Script = 30 | When Checking The Canary Object Against A Certain Replica Member, And The Replica Member Is Reachable, This Is The Amount Of Minutes, When Exceeded, It Stops Checking That Replica Member (This Could Be The Case When NTFRS/DFSR Replication Is Broken Somehow Or The Replica Member Is In A Unhealthy State) -->
	<timeoutInMinutes>REPLACE_WITH_NUMERIC_VALUE</timeoutInMinutes>

	<!-- Default In Script = 1 | Minimum Amount Of Threads Per Runspace Pool -->
	<runspacePoolMinThreads>REPLACE_WITH_NUMERIC_VALUE</runspacePoolMinThreads>

	<!-- Default In Script = 2048 | Minimum Amount Of Threads Per Runspace Pool -->
	<runspacePoolMaxThreads>REPLACE_WITH_NUMERIC_VALUE</runspacePoolMaxThreads>

	<!-- Default In Script = 500 | The Check Delay In Milliseconds Between Checks Against Each Individual Replica Member -->
	<delayInMilliSecondsBetweenChecks>REPLACE_WITH_NUMERIC_VALUE</delayInMilliSecondsBetweenChecks>
</checkFileReplConvergence>
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

### FUNCTION: Check If An OU/Container/Object Exists On The Specified DC
Function checkDNExistence {
	Param (
		$dnsHostNameRWDC,
		$dn
	)

	Try {
		If([ADSI]::Exists("LDAP://$dnsHostNameRWDC/$dn")) {
			Return "SUCCESS"
		} Else {
			Return "ERROR"
		}
	} Catch {
		Return "ERROR"
	}
}

### FUNCTION: Determine SYSVOL Replication Mechanism, Being Either NTFRS Or DFSR
Function determineSYSVOLReplicationMechanism {
	Param (
		$adDomainDN,
		$rwdcFQDN
	)

	$sysvolReplMechanisms = @()

	$frsReplicaSetDNForSYSVOL = "CN=Domain System Volume (SYSVOL share),CN=File Replication Service,CN=System,$adDomainDN"
	If ($(checkDNExistence -dnsHostNameRWDC $rwdcFQDN -dn $frsReplicaSetDNForSYSVOL) -eq "SUCCESS") {
		$frsReplicaSetDNForSYSVOLExists = $true
	} Else {
		$frsReplicaSetDNForSYSVOLExists = $false
	}
	
	If ($frsReplicaSetDNForSYSVOLExists -eq $true) {
		$searchRootSYSVOLReplSetMemberRefs = [ADSI]"LDAP://$rwdcFQDN/CN=Domain System Volume (SYSVOL share),CN=File Replication Service,CN=System,$adDomainDN"
		$searcherSYSVOLReplSetMemberRefs = New-Object System.DirectoryServices.DirectorySearcher($searchRootSYSVOLReplSetMemberRefs)
		$searcherSYSVOLReplSetMemberRefs.Filter = "(&(objectClass=nTFRSMember)(frsComputerReference=*))"
		$ntfrsSYSVOLReplSetMemberRefs = $searcherSYSVOLReplSetMemberRefs.FindAll()
		
		If (($ntfrsSYSVOLReplSetMemberRefs | Measure-Object).Count -gt 0) {
			$ntfrsSYSVOLReplSetMembersExists = $true
		} Else {
			$ntfrsSYSVOLReplSetMembersExists = $false
		}
	} Else {
		$ntfrsSYSVOLReplSetMembersExists = $false
	}

	$dfsrReplGroupDNForSYSVOL = "CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,$adDomainDN"
	If ($(checkDNExistence -dnsHostNameRWDC $rwdcFQDN -dn $dfsrReplGroupDNForSYSVOL) -eq "SUCCESS") {
		$dfsrReplGroupDNForSYSVOLExists = $true
	} Else {
		$dfsrReplGroupDNForSYSVOLExists = $false
	}

	If ($dfsrReplGroupDNForSYSVOLExists -eq $true) {
		$searchRootSYSVOLReplGroupMemberRefs = [ADSI]"LDAP://$rwdcFQDN/CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,$adDomainDN"
		$searcherSYSVOLReplGroupMemberRefs = New-Object System.DirectoryServices.DirectorySearcher($searchRootSYSVOLReplGroupMemberRefs)
		$searcherSYSVOLReplGroupMemberRefs.Filter = "(&(objectClass=msDFSR-Member)(msDFSR-ComputerReference=*))"
		$dfsrSYSVOLReplGroupMemberRefs = $searcherSYSVOLReplGroupMemberRefs.FindAll()
		
		If (($dfsrSYSVOLReplGroupMemberRefs | Measure-Object).Count -gt 0) {
			$dfsrSYSVOLReplGroupMembersExists = $true
		} Else {
			$dfsrSYSVOLReplGroupMembersExists = $false
		}
	} Else {
		$dfsrSYSVOLReplGroupMembersExists = $false
	}

	If ($dfsrSYSVOLReplGroupMembersExists -eq $true -And $frsReplicaSetDNForSYSVOLExists -eq $false) {
		# SYSVOL Replication Initially Through DFSR
		$sysvolReplMechanisms += "DFSR"
	} ElseIf ($dfsrSYSVOLReplGroupMembersExists -eq $true -And $frsReplicaSetDNForSYSVOLExists -eq $true -And $ntfrsSYSVOLReplSetMembersExists -eq $false) {
		# SYSVOL Replication Migrated To DFSR And Migration Is Completed
		# ELIMINATED State (GlobalState = 3) > DFSR is replicating SYSVOL and NTFRS is removed
		$sysvolReplMechanisms += "DFSR"
	} ElseIf ($dfsrSYSVOLReplGroupMembersExists -eq $false -And $ntfrsSYSVOLReplSetMembersExists -eq $true) {
		# SYSVOL Replication Initially Through NTFRS
		$sysvolReplMechanisms += "NTFRS"
	} Else {
		# SYSVOL Replication Most Likely Being Migrated
		# PREPARED State (GlobalState = 1) > Both NTFRS and DFSR are replicating their own individual copies of SYSVOL, but the NTFRS copy mounts the SYSVOL and Netlogon shares
		# REDIRECTED State (GlobalState = 2) > Both NTFRS and DFSR are replicating their own individual copies of SYSVOL, but the DFSR copy mounts the SYSVOL and Netlogon shares
		
		$searchRootDFSRGlobalSettings = [ADSI]"LDAP://$rwdcFQDN/CN=DFSR-GlobalSettings,CN=System,$adDomainDN"
		$searcherDFSRGlobalSettings = New-Object System.DirectoryServices.DirectorySearcher($searchRootDFSRGlobalSettings)
		[void]$($searcherDFSRGlobalSettings.PropertiesToLoad.Add("msDFSR-Flags"))
		$dfsrGlobalSettings = $searcherDFSRGlobalSettings.FindOne()

		If (($dfsrGlobalSettings.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "msdfsr-flags" -And -not [string]::IsNullOrEmpty($dfsrGlobalSettings.Properties."msdfsr-flags")) {
			$dfsrGlobalState = $dfsrGlobalSettings.Properties."msdfsr-flags"[0]
		} Else {
			$dfsrGlobalState = $null
		}
		
		If ($dfsrGlobalState -eq 0 -Or $dfsrGlobalState -eq 16) {
			# 0: Instruction For DCs To Get To PREPARED State
			# 16: All DCs Are In PREPARED State (GlobalState = 1) > Both NTFRS and DFSR are replicating their own individual copies of SYSVOL, but the NTFRS copy mounts the SYSVOL and Netlogon shares
			
			$sysvolReplMechanisms += "NTFRS (ACTIVE)"
			$sysvolReplMechanisms += "DFSR (PASSIVE)"
		}

		If ($dfsrGlobalState -eq 96 -Or $dfsrGlobalState -eq 32) {
			# 96: Instruction For DCs To Get To REDIRECTED State
			# 32: All DCs Are In REDIRECTED State (GlobalState = 2) > Both NTFRS and DFSR are replicating their own individual copies of SYSVOL, but the DFSR copy mounts the SYSVOL and Netlogon shares
			
			$sysvolReplMechanisms += "NTFRS (PASSIVE)"
			$sysvolReplMechanisms += "DFSR (ACTIVE)"
		}

		If ($dfsrGlobalState -eq 112 -Or $dfsrGlobalState -eq 48) {
			# 112: Instruction For DCs To Get To ELIMINATED State
			# 48: All DCs Are In ELIMINATED State (GlobalState = 3) > DFSR is replicating SYSVOL and NTFRS is removed
			
			$sysvolReplMechanisms += "DFSR"
		}
	}
	
	Return $sysvolReplMechanisms
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
	[void]$($searcherReplContentSets.PropertiesToLoad.Add("distinguishedName"))
	[void]$($searcherReplContentSets.PropertiesToLoad.Add("name"))
	[void]$($searcherReplContentSets.PropertiesToLoad.Add("objectGuid"))
	$dfsrReplContentSets = $searcherReplContentSets.FindAll()

	If (($dfsrReplContentSets | Measure-Object).Count -gt 0) {
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
	[void]$($searcherReplGroupMemberRefs.PropertiesToLoad.Add("distinguishedName"))
	[void]$($searcherReplGroupMemberRefs.PropertiesToLoad.Add("msDFSR-ComputerReference"))
	[void]$($searcherReplGroupMemberRefs.PropertiesToLoad.Add("name"))
	$dfsrReplGroupMemberRefs = $searcherReplGroupMemberRefs.FindAll()

	If (($dfsrReplGroupMemberRefs | Measure-Object).Count -gt 0) {
		$dfsrReplGroupMemberRefs | ForEach-Object{
			If (($_.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "msdfsr-computerreference") {
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
				[void]$($searcherReplGroupMemberCompAccount.PropertiesToLoad.Add("dNSHostName"))
				$replGroupMemberCompAccount = $searcherReplGroupMemberCompAccount.FindOne()
				$dfsrReplGroupMemberRefFQDN = $replGroupMemberCompAccount.Properties.dnshostname[0]
				
				$dfsrReplGroupMemberMetadataState = "METADATA-COMPLETE"
			} Else {
				$dfsrReplGroupMemberNameGuid = "UNDETERMINED"
				$dfsrReplGroupMemberRefDN = "UNDETERMINED"
				$dfsrReplGroupMemberRefFQDN = "UNDETERMINED"
				$dfsrReplGroupMemberMetadataState = "METADATA-ORPHANED"
			}

			$dfsrReplGroupMemberEntry = New-Object -TypeName System.Object
			$dfsrReplGroupMemberEntry | Add-Member -MemberType NoteProperty -Name "Name" -Value $($_.Properties.name[0])
			$dfsrReplGroupMemberEntry | Add-Member -MemberType NoteProperty -Name "MemberGuidName" -Value $dfsrReplGroupMemberNameGuid
			$dfsrReplGroupMemberEntry | Add-Member -MemberType NoteProperty -Name "ComputerReferenceDN" -Value $dfsrReplGroupMemberRefDN
			$dfsrReplGroupMemberEntry | Add-Member -MemberType NoteProperty -Name "DNSHostName" -Value $dfsrReplGroupMemberRefFQDN
			$dfsrReplGroupMemberEntry | Add-Member -MemberType NoteProperty -Name "MetadataState" -Value $dfsrReplGroupMemberMetadataState
			$dfsrReplGroupMemberList += $dfsrReplGroupMemberEntry
		}
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

	$iNr = 0
	$dfsrReplGroupMemberList | ForEach-Object{
		$iNr++

		$dfsrReplGroupMemberFQDN = $_.DNSHostName

		showProgress -itemNr $iNr -activityMessage "Retrieving The Configuration And State For '$dfsrReplGroupMemberFQDN'" -totalItems $(($dfsrReplGroupMemberList | Measure-Object).Count)

		$dfsrReplGroupMemberRefDN = $_.ComputerReferenceDN

		$dfsrReplGroupMemberGuidName = $_.MemberGuidName

		$dfsrReplGroupMemberRefADDomainRWDC = $($domainsAndDCsHT[$($dfsrReplGroupMemberRefDN.SubString($dfsrReplGroupMemberRefDN.IndexOf("DC=")))])

		Try {
			$dfsrReplGroupMemberIPv4 = ([System.Net.Dns]::GetHostEntry($dfsrReplGroupMemberFQDN).AddressList | Where-Object{$_.AddressFamily -eq "InterNetwork"}).IPAddressToString
		} Catch {
			$dfsrReplGroupMemberIPv4 = "<UNKNOWN>"
		}

		$dfsrReplGroupMemberSiteNLTEST = NLTEST.EXE /DSGETSITE /SERVER:$dfsrReplGroupMemberFQDN 2>$null # It Needs To Be Done Like This To Also Support Non-DCs As Replica Members
		If (-not [String]::IsNullOrEmpty($dfsrReplGroupMemberSiteNLTEST)) {
			$dfsrReplGroupMemberSite = $dfsrReplGroupMemberSiteNLTEST[0]
		} Else {
			$dfsrReplGroupMemberSite = "<UNKNOWN>"
		}

		$searchRootReplGroupMember = [ADSI]"LDAP://$dfsrReplGroupMemberRefADDomainRWDC/$dfsrReplGroupMemberRefDN"
		$searcherReplGroupMember = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplGroupMember)
		[void]$($searcherReplGroupMember.PropertiesToLoad.Add("operatingSystem"))
		[void]$($searcherReplGroupMember.PropertiesToLoad.Add("operatingSystemVersion"))
		$replGroupMemberObject = $searcherReplGroupMember.FindOne()
		If (($replGroupMemberObject.PSObject.Properties | Where-Object {$_.Name -eq 'Properties'}).Value.Keys -contains "operatingsystem" -And -not [String]::IsNullOrEmpty($replGroupMemberObject.Properties.operatingsystem)) {
			$dfsrReplGroupMemberOS = $replGroupMemberObject.Properties.operatingsystem[0]
		} Else {
			$dfsrReplGroupMemberOS = "<UNKNOWN>"
		}
		If (($replGroupMemberObject.PSObject.Properties | Where-Object {$_.Name -eq 'Properties'}).Value.Keys -contains "operatingsystemversion" -And -not [String]::IsNullOrEmpty($replGroupMemberObject.Properties.operatingsystemversion)) {
			$dfsrReplGroupMemberOSVersion = $replGroupMemberObject.Properties.operatingsystemversion[0]
		} Else {
			$dfsrReplGroupMemberOSVersion = "<UNKNOWN>"
		}
		If ($(portConnectionCheck -fqdnServer $dfsrReplGroupMemberFQDN -port $smbPort -timeOut $connectionTimeout) -eq "SUCCESS") {
			$dfsrReplGroupMemberReachableSMB = $true
		} Else {
			$dfsrReplGroupMemberReachableSMB = $false
		}
		If ($(portConnectionCheck -fqdnServer $dfsrReplGroupMemberFQDN -port $remotePoSHHTTPPort -timeOut $connectionTimeout) -eq "SUCCESS") {
			Try {
				$remotePoSHTest = $null
				$remotePoSHTest = Invoke-Command -ComputerName $dfsrReplGroupMemberFQDN -ScriptBlock {pwd} -ErrorAction Stop
				If (-not [String]::IsNullOrEmpty($remotePoSHTest)) {
					$dfsrReplGroupMemberReachableWINRM = $true
				} Else {
					$dfsrReplGroupMemberReachableWINRM = $false
				}
			} Catch {
				$dfsrReplGroupMemberReachableWINRM = $false
			}
		} Else {
			$dfsrReplGroupMemberReachableWINRM = $false
		}

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
		[void]$($searcherReplFolderSubscription.PropertiesToLoad.Add("msDFSR-Enabled"))
		[void]$($searcherReplFolderSubscription.PropertiesToLoad.Add("msDFSR-RootPath"))
		[void]$($searcherReplFolderSubscription.PropertiesToLoad.Add("msDFSR-ReadOnly"))
		Try {
			$replFolderSubscriptionObject = $searcherReplFolderSubscription.FindOne()
		} Catch {
			$replFolderSubscriptionObject = $null
		}

		If (-not [String]::IsNullOrEmpty($replFolderSubscriptionObject) -And ($replFolderSubscriptionObject.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "msdfsr-rootpath" -And -not [String]::IsNullOrEmpty($replFolderSubscriptionObject.Properties."msdfsr-rootpath")) {
			$dfsrReplGroupMemberFolderPath = $($replFolderSubscriptionObject.Properties."msdfsr-rootpath"[0])
		} Else {
			$dfsrReplGroupMemberFolderPath = "<UNKNOWN>"
		}

		If (-not [String]::IsNullOrEmpty($replFolderSubscriptionObject) -And ($replFolderSubscriptionObject.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "msdfsr-enabled" -And -not [String]::IsNullOrEmpty($replFolderSubscriptionObject.Properties."msdfsr-enabled") -And $($replFolderSubscriptionObject.Properties."msdfsr-enabled"[0]) -eq $true) {
			$dfsrReplGroupMemberFolderState = "Enabled"
		} ElseIf (-not [String]::IsNullOrEmpty($replFolderSubscriptionObject) -And ($replFolderSubscriptionObject.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "msdfsr-rootpath" -And -not [String]::IsNullOrEmpty($replFolderSubscriptionObject.Properties."msdfsr-enabled") -And $($replFolderSubscriptionObject.Properties."msdfsr-enabled"[0]) -eq $false) {
			$dfsrReplGroupMemberFolderState = "Disabled"
		} Else {
			$dfsrReplGroupMemberFolderState = "<UNKNOWN>"
		}

		If (-not [String]::IsNullOrEmpty($replFolderSubscriptionObject) -And ($replFolderSubscriptionObject.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "msdfsr-readonly" -And -not [String]::IsNullOrEmpty($replFolderSubscriptionObject.Properties."msdfsr-readonly") -And $($replFolderSubscriptionObject.Properties."msdfsr-readonly"[0]) -eq $true) {
			$dfsrReplGroupMemberFolderType = "RO"
		} ElseIf (-not [String]::IsNullOrEmpty($replFolderSubscriptionObject) -And ($replFolderSubscriptionObject.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "msdfsr-readonly" -And -not [String]::IsNullOrEmpty($replFolderSubscriptionObject.Properties."msdfsr-readonly") -And $($replFolderSubscriptionObject.Properties."msdfsr-readonly"[0]) -eq $false) {
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
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "ReachableSMB" -Value $dfsrReplGroupMemberReachableSMB
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "ReachableWinRM" -Value $dfsrReplGroupMemberReachableWINRM
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Repl Folder Path" -Value $dfsrReplGroupMemberFolderPath
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "State" -Value $dfsrReplGroupMemberFolderState
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $dfsrReplGroupMemberFolderType
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "File Count" -Value $null
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Start Time Check" -Value $null
		$dfsrReplFolderConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "End Time Check" -Value $null
		$dfsrReplFolderConfigAndStateList += $dfsrReplFolderConfigAndStateEntry
	}
	Write-Progress -Completed -Activity " "

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
	[void]$($searcherReplicaSets.PropertiesToLoad.Add("distinguishedName"))
	[void]$($searcherReplicaSets.PropertiesToLoad.Add("name"))
	[void]$($searcherReplicaSets.PropertiesToLoad.Add("msDS-Approx-Immed-Subordinates")) # In Some Environments The Replica Set "Domain System Volume (SYSVOL share)" Might Still Exist While DFSR Is Already Being Used. If The Replica Set DOES NOT Contain Subobjects, Then DFSR Is Assumed To Be Used
	<#
	[void]$($searcherReplicaSets.PropertiesToLoad.Add("fRSReplicaSetGUID"))
	#>
	$ntfrsReplicaSets = $searcherReplicaSets.FindAll()

	If (($ntfrsReplicaSets | Measure-Object).Count -gt 0) {
		$ntfrsReplicaSets | Where-Object {$_.Properties."msds-approx-immed-subordinates"[0] -gt 0} | ForEach-Object{
			$ntfrsReplicaSetName = $($_.Properties.name[0])
			$ntfrsReplicaSetEntry = New-Object -TypeName System.Object
			$ntfrsReplicaSetEntry | Add-Member -MemberType NoteProperty -Name "Domain DN" -Value $adDomainDN
			$ntfrsReplicaSetEntry | Add-Member -MemberType NoteProperty -Name "Repl Set Name" -Value $ntfrsReplicaSetName
			$ntfrsReplicaSetEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value "NTFRS"
			$ntfrsReplicaSetList += $ntfrsReplicaSetEntry
		}
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
	[void]$($searcherReplSetMemberRefs.PropertiesToLoad.Add("distinguishedName"))
	[void]$($searcherReplSetMemberRefs.PropertiesToLoad.Add("frsComputerReference"))
	[void]$($searcherReplSetMemberRefs.PropertiesToLoad.Add("name"))
	$ntfrsReplSetMemberRefs = $searcherReplSetMemberRefs.FindAll()

	If (($ntfrsReplSetMemberRefs | Measure-Object).Count -gt 0) {
		$ntfrsReplSetMemberRefs | ForEach-Object {
			If (($_.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "frscomputerreference") {
				$ntfrsReplSetMemberRefDN = $_.Properties.frscomputerreference[0]

				$searchRootReplSetMemberCompAccount = [ADSI]"LDAP://$rwdcFQDN/$ntfrsReplSetMemberRefDN"
				$searcherReplSetMemberCompAccount = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplSetMemberCompAccount)
				[void]$($searcherReplSetMemberCompAccount.PropertiesToLoad.Add("dNSHostName"))
				[void]$($searcherReplSetMemberCompAccount.PropertiesToLoad.Add("msDS-isRODC"))
				$replSetMemberCompAccount = $searcherReplSetMemberCompAccount.FindOne()
				$ntfrsReplSetMemberRefFQDN = $replSetMemberCompAccount.Properties.dnshostname[0]
				If (($replSetMemberCompAccount.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "msds-isrodc") {
					$ntfrsReplSetMemberRefIsRODC = $replSetMemberCompAccount.Properties."msds-isrodc"[0]
				} Else {
					$ntfrsReplSetMemberRefIsRODC = "UNKNOWN"
				}
				$ntfrsReplSetMemberMetadataState = "METADATA-COMPLETE"
			} Else {
				$ntfrsReplSetMemberRefDN = "UNDETERMINED"
				$ntfrsReplSetMemberRefFQDN = "UNDETERMINED"
				$ntfrsReplSetMemberRefIsRODC = "UNDETERMINED"
				$ntfrsReplSetMemberMetadataState = "METADATA-ORPHANED"
			}

			$ntfrsReplSetMemberEntry = New-Object -TypeName System.Object
			$ntfrsReplSetMemberEntry | Add-Member -MemberType NoteProperty -Name "Name" -Value $($_.Properties.name[0])
			$ntfrsReplSetMemberEntry | Add-Member -MemberType NoteProperty -Name "ComputerReferenceDN" -Value $ntfrsReplSetMemberRefDN
			$ntfrsReplSetMemberEntry | Add-Member -MemberType NoteProperty -Name "DNSHostName" -Value $ntfrsReplSetMemberRefFQDN
			$ntfrsReplSetMemberEntry | Add-Member -MemberType NoteProperty -Name "IsRODC" -Value $ntfrsReplSetMemberRefIsRODC
			$ntfrsReplSetMemberEntry | Add-Member -MemberType NoteProperty -Name "MetadataState" -Value $ntfrsReplSetMemberMetadataState
			$ntfrsReplSetMemberList += $ntfrsReplSetMemberEntry
		}
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

	$iNr = 0
	$ntfrsReplSetMemberList | ForEach-Object{
		$iNr++

		$ntfrsReplSetMemberFQDN = $_.DNSHostName

		showProgress -itemNr $iNr -activityMessage "Retrieving The Configuration And State For '$ntfrsReplSetMemberFQDN'" -totalItems $(($ntfrsReplSetMemberList | Measure-Object).Count)

		$ntfrsReplSetMemberRefDN = $_.ComputerReferenceDN

		Try {
			$ntfrsReplSetMemberIPv4 = ([System.Net.Dns]::GetHostEntry($ntfrsReplSetMemberFQDN).AddressList | Where-Object{$_.AddressFamily -eq "InterNetwork"}).IPAddressToString
		} Catch {
			$ntfrsReplSetMemberIPv4 = "<UNKNOWN>"
		}

		$ntfrsReplSetMemberSiteNLTEST = NLTEST.EXE /DSGETSITE /SERVER:$ntfrsReplSetMemberFQDN 2>$null
		If (-not [String]::IsNullOrEmpty($ntfrsReplSetMemberSiteNLTEST)) {
			$ntfrsReplSetMemberSite = $ntfrsReplSetMemberSiteNLTEST[0]
		} Else {
			$ntfrsReplSetMemberSite = "<UNKNOWN>"
		}

		$searchRootReplSetMember = [ADSI]"LDAP://$rwdcFQDN/$ntfrsReplSetMemberRefDN"
		$searcherReplSetMember = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplSetMember)
		[void]$($searcherReplSetMember.PropertiesToLoad.Add("operatingSystem"))
		[void]$($searcherReplSetMember.PropertiesToLoad.Add("operatingSystemVersion"))
		[void]$($searcherReplSetMember.PropertiesToLoad.Add("msDS-isRODC"))
		$replSetMemberObject = $searcherReplSetMember.FindOne()
		If (($replSetMemberObject.PSObject.Properties | Where-Object {$_.Name -eq 'Properties'}).Value.Keys -contains "operatingsystem" -And -not [String]::IsNullOrEmpty($replSetMemberObject.Properties.operatingsystem)) {
			$ntfrsReplSetMemberOS = $replSetMemberObject.Properties.operatingsystem[0]
		} Else {
			$ntfrsReplSetMemberOS = "<UNKNOWN>"
		}
		If (($replSetMemberObject.PSObject.Properties | Where-Object {$_.Name -eq 'Properties'}).Value.Keys -contains "operatingsystemversion" -And -not [String]::IsNullOrEmpty($replSetMemberObject.Properties.operatingsystemversion)) {
			$ntfrsReplSetMemberOSVersion = $replSetMemberObject.Properties.operatingsystemversion[0]
		} Else {
			$ntfrsReplSetMemberOSVersion = "<UNKNOWN>"
		}
		If (($replSetMemberObject.PSObject.Properties | Where-Object {$_.Name -eq 'Properties'}).Value.Keys -contains "msds-isrodc" -And -not [String]::IsNullOrEmpty($replSetMemberObject.Properties."msds-isrodc")) {
			$ntfrsReplSetMemberIsRODC = $replSetMemberObject.Properties."msds-isrodc"[0]
		} Else {
			$ntfrsReplSetMemberIsRODC = "<UNKNOWN>"
		}

		If ($(portConnectionCheck -fqdnServer $ntfrsReplSetMemberFQDN -port $smbPort -timeOut $connectionTimeout) -eq "SUCCESS") {
			$ntfrsReplSetMemberReachableSMB = $true
		} Else {
			$ntfrsReplSetMemberReachableSMB = $false
		}
		If ($(portConnectionCheck -fqdnServer $ntfrsReplSetMemberFQDN -port $remotePoSHHTTPPort -timeOut $connectionTimeout) -eq "SUCCESS") {
			Try {
				$remotePoSHTest = $null
				$remotePoSHTest = Invoke-Command -ComputerName $ntfrsReplSetMemberFQDN -ScriptBlock {pwd} -ErrorAction Stop
				If (-not [String]::IsNullOrEmpty($remotePoSHTest)) {
					$ntfrsReplSetMemberReachableWINRM = $true
				} Else {
					$ntfrsReplSetMemberReachableWINRM = $false
				}
			} Catch {
				$ntfrsReplSetMemberReachableWINRM = $false
			}
		} Else {
			$ntfrsReplSetMemberReachableWINRM = $false
		}

		If ($(-not [String]::IsNullOrEmpty($ntfrsReplSetName)) -And $(-not [String]::IsNullOrEmpty($ntfrsReplSetMemberRefDN))) {
			$ntfrsReplSetMemberSubscriberDN = "CN=" + $ntfrsReplSetName + ",CN=NTFRS Subscriptions," + $ntfrsReplSetMemberRefDN
		} Else {
			$ntfrsReplSetMemberSubscriberDN = $null
		}

		$searchRootReplSetSubscriber = [ADSI]"LDAP://$rwdcFQDN/$ntfrsReplSetMemberSubscriberDN"
		$searcherReplSetSubscriber = New-Object System.DirectoryServices.DirectorySearcher($searchRootReplSetSubscriber)
		[void]$($searcherReplSetSubscriber.PropertiesToLoad.Add("fRSRootPath"))
		Try {
			$replSetSubscriberObject = $searcherReplSetSubscriber.FindOne()
		} Catch {
			$replSetSubscriberObject = $null
		}

		If (-not [String]::IsNullOrEmpty($replSetSubscriberObject) -And ($replSetSubscriberObject.PSObject.Properties | Where-Object {$_.Name -eq "Properties"}).Value.Keys -contains "frsrootpath" -And -not [String]::IsNullOrEmpty($replSetSubscriberObject.Properties.frsrootpath)) {
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
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "ReachableSMB" -Value $ntfrsReplSetMemberReachableSMB
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "ReachableWinRM" -Value $ntfrsReplSetMemberReachableWINRM
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Repl Folder Path" -Value $ntfrsReplSetMemberFolderPath
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $ntfrsReplSetMemberFolderType
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $null
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "File Count" -Value $null
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "Start Time Check" -Value $null
		$ntfrsReplSetConfigAndStateEntry | Add-Member -MemberType NoteProperty -Name "End Time Check" -Value $null
		$ntfrsReplSetConfigAndStateList += $ntfrsReplSetConfigAndStateEntry
	}
	Write-Progress -Completed -Activity " "

	Return $ntfrsReplSetConfigAndStateList
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
$uiConfig.WindowTitle = "+++ CHECKING SYSVOL, DFSR FOLDERS, NTFRS FOLDERS REPLICATION LATENCY/CONVERGENCE +++"
$uiConfig.ForegroundColor = "Yellow"
$uiConfigBufferSize = $uiConfig.BufferSize
$uiConfigBufferSize.Width = 400
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
[string]$scriptLogFullPath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.log")
[string]$fileCountResultsExportCsvFullPath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_FileCountResults.csv")
[string]$replResultsExportCsvFullPath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_ReplResults.csv")
[string]$htmlFullPath = Join-Path $currentScriptFolderPath $($execDateTimeCustom + "_" + $localComputerName + "_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.html")
$smbPort = 445                                  # SMB Over TCP/IP Port (Used For Checking If The Canary File Exist Or Not)
$remotePoSHHTTPPort = 5985                      # WinRM HTTP Transport Port (Used For Counting Files Locally On The Member Within The Replicated Folder - When Connecting Through HTTP, The Default)
$remotePoSHHTTPSPort = 5986                     # WinRM HTTPS Transport Port (Used For Counting Files Locally On The Member Within The Replicated Folder - When Connecting Through HTTPS, UNUSED)
If (Test-Path $scriptConfigFullPath) {
	[XML]$scriptConfig = Get-Content $scriptConfigFullPath

	$useXMLConfigFileSettings = $scriptConfig.checkFileReplConvergence.useXMLConfigFileSettings
	If ($useXMLConfigFileSettings.ToUpper() -eq "TRUE") {
		$connectionParametersSource = "XML Config File '$scriptConfigFullPath'"

		$connectionTimeout = $scriptConfig.checkFileReplConvergence.connectionTimeoutInMilliSeconds
		If ($connectionTimeout -notmatch "^\d+$") {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptConfigFullPath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'connectionTimeoutInMilliSeconds'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}

		$timeoutInMinutes = $scriptConfig.checkFileReplConvergence.timeoutInMinutes
		If ($timeoutInMinutes -notmatch "^\d+$") {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptConfigFullPath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'timeoutInMinutes'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}

		$runspacePoolMinThreads = $scriptConfig.checkFileReplConvergence.runspacePoolMinThreads
		If ($runspacePoolMinThreads -notmatch "^\d+$") {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptConfigFullPath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'runspacePoolMinThreads'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}

		$runspacePoolMaxThreads = $scriptConfig.checkFileReplConvergence.runspacePoolMaxThreads
		If ($runspacePoolMaxThreads -notmatch "^\d+$") {
			writeLog -dataToLog ""
			writeLog -dataToLog "The XML Config File '$scriptConfigFullPath' Has A Wrong Value For The Connection Parameter:" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "  > 'runspacePoolMaxThreads'..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""
			writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog ""

			BREAK
		}

		$delayInMilliSecondsBetweenChecks = $scriptConfig.checkFileReplConvergence.delayInMilliSecondsBetweenChecks
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
		$timeoutInMinutes = 30                          # When Checking The Canary Object Against A Certain Replica Member, And The Replica Member Is Reachable, This Is The Amount Of Minutes, When Exceeded, It Stops Checking That Replica Member (This Could Be The Case When NTFRS/DFSR Replication Is Broken Somehow Or The Replica Member Is In A Unhealthy State)
		$runspacePoolMinThreads = 1                     # Minimum Amount Of Threads Per Runspace Pool
		$runspacePoolMaxThreads = 2048                  # Maximum Amount Of Threads Per Runspace Pool # [int]$env:NUMBER_OF_PROCESSORS + 1
		$delayInMilliSecondsBetweenChecks = 500         # The Check Delay In Milliseconds Between Checks Against Each Individual Replica Member.
	}
} Else {
	$connectionParametersSource = "Default Values In Script - No XML Config File Found"

	# No XML Config File Was Found => Using Default Values In Script
	$connectionTimeout = 500                        # When Checking If The Host Is Reachable Over Certain Port, This Is The Timeout In Milliseconds
	$timeoutInMinutes = 30                          # When Checking The Canary Object Against A Certain Replica Member, And The Replica Member Is Reachable, This Is The Amount Of Minutes, When Exceeded, It Stops Checking That Replica Member (This Could Be The Case When NTFRS/DFSR Replication Is Broken Somehow Or The Replica Member Is In A Unhealthy State)
	$runspacePoolMinThreads = 1                     # Minimum Amount Of Threads Per Runspace Pool
	$runspacePoolMaxThreads = 2048                  # Maximum Amount Of Threads Per Runspace Pool # [int]$env:NUMBER_OF_PROCESSORS + 1
	$delayInMilliSecondsBetweenChecks = 500         # The Check Delay In Milliseconds Between Checks Against Each Individual Replica Member.
}

$htmlBaseContent = @"
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<HTML xmlns="http://www.w3.org/1999/xhtml">
	<HEAD>
		<TITLE>SYSVOL/DFSR/NTFRS REPLICATION LATENCY TEST</TITLE>
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
		<H1>SYSVOL/DFSR/NTFRS REPLICATION LATENCY/CONVERGENCE TEST</H1>
		<H3>(Provided By: IAMTEC)</H3>
		<P><img src="data:image/png;base64,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" alt="IAMTEC - Identity | Security | Recovery" /></P>
		<H3>REPLACEME_VERSION_DATE_TIME</H3>
		<H3>Execution: REPLACEME_EXECUTION_DATE_TIME</H3>
		<BR>
		<TABLE align="center" border="1">
			<TR><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #000000; COLOR: #FFFF00"><B>AD DOMAIN FQDN:</B></TD><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #D4E1F5">REPLACEME_ADDOMAINFQDN</TD></TR>
			<TR><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #000000; COLOR: #FFFF00"><B>REPL MECHANISM:</B></TD><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #D4E1F5">REPLACEME_REPLMECHANISM</TD></TR>
			<TR><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #000000; COLOR: #FFFF00"><B>REPLICATED FOLDER:</B></TD><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #D4E1F5">REPLACEME_REPLICATEDFOLDER</TD></TR>
			<TR><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #000000; COLOR: #FFFF00"><B>SOURCE MEMBER:</B></TD><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #D4E1F5">REPLACEME_SOURCEMEMBER</TD></TR>
			<TR><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #000000; COLOR: #FFFF00"><B>FOLDER UNC PATH:</B></TD><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #D4E1F5">REPLACEME_FOLDERUNCPATH</TD></TR>
			<TR><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #000000; COLOR: #FFFF00"><B>FILE NAME:</B></TD><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #D4E1F5">REPLACEME_FILENAME</TD></TR>
			<TR><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #000000; COLOR: #FFFF00"><B>FILE CONTENT:</B></TD><TD style = "TEXT-ALIGN: LEFT; BACKGROUND-COLOR: #D4E1F5">REPLACEME_FILECONTENT</TD></TR>
		</TABLE>
		<BR>
		<BR>

		<TABLE align="center" border="1">
			<TR><TH style = "width: 40px;">NR</TH><TH style = "width: 500px;">MEMBER INSTANCE FQDN</TH><TH style = "width: 100px;">SOURCE</TH><TH style = "width: 150px;">PORT</TH><TH style = "width: 125px;">REACHABLE</TH><TH style = "width: 550px;">TEMPORARY CANARY FILE STATE IN FOLDER OF INSTANCE</TH></TR>
			<!-- INSERT ROWS AFTER THIS LINE -->
			<!-- REPLACEME_MEMBERLIST -->
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
### Logging Where The Script Is Being Executed From And How
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
	writeLog -dataToLog "File Count Export CSV Full Path.......: $fileCountResultsExportCsvFullPath"
	writeLog -dataToLog ""
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
$adDomainObjects | ForEach-Object {
	$adDomainObjectProperties = $_.Properties
	$tableOfDomainsInADForestEntry = New-Object -TypeName System.Object
	$tableOfDomainsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Domain DN" -Value $($adDomainObjectProperties.ncname[0])
	$tableOfDomainsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Domain FQDN" -Value $($adDomainObjectProperties.dnsroot[0])
	$tableOfDomainsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Domain Name" -Value $($adDomainObjectProperties.name[0])
	$tableOfDomainsInADForestEntry | Add-Member -MemberType NoteProperty -Name "Domain Type" -Value $(If (($adDomainObjectProperties.PSObject.Properties | Where-Object {$_.Name -eq "PropertyNames"}).Value -notcontains "roottrust" -And ($adDomainObjectProperties.PSObject.Properties | Where-Object {$_.Name -eq "PropertyNames"}).Value -notcontains "trustparent") {"Root Domain"} ElseIf (($adDomainObjectProperties.PSObject.Properties | Where-Object {$_.Name -eq "PropertyNames"}).Value -contains "trustparent" -And -not [String]::IsNullOrEmpty($adDomainObjectProperties.trustparent)) {"Child Domain"} ElseIf (($adDomainObjectProperties.PSObject.Properties | Where-Object {$_.Name -eq "PropertyNames"}).Value -contains "roottrust" -And -not [String]::IsNullOrEmpty($adDomainObjectProperties.roottrust)) {"Tree Root Domain"} Else {"UNKNOWN"})
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
writeLog -dataToLog "REMARK: Specify A NUMBER Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
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
Try {
	$fsmoRoleOwnerObject = $searcherFSMORoleOwner.FindOne()
	$ntdsSettingsObjectFsmoRoleOwnerDN = $fsmoRoleOwnerObject.Properties.fsmoroleowner[0]
} Catch {
	$fsmoRoleOwnerObject = $null
	$ntdsSettingsObjectFsmoRoleOwnerDN = $null
}
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
writeLog -dataToLog "+++ LIST OF REPLICATED SETS/FOLDERS WITHIN THE AD DOMAIN '$($domainOptionChosen.'Domain DN') ($($domainOptionChosen.'Domain FQDN'))' - PLEASE CHOOSE A NTFRS/DFSR REPLICATED SET/FOLDER TO TARGET +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
$ntfrsReplSetsList = $null
If ($(checkDNExistence -dnsHostNameRWDC $rwdcADDomainFQDN -dn "CN=File Replication Service,CN=System,$($domainOptionChosen.'Domain DN')") -eq "SUCCESS") {
	$ntfrsReplSetsList = getNTFRSReplicaSetsInADDomain -adDomainDN $($domainOptionChosen.'Domain DN') -rwdcFQDN $rwdcADDomainFQDN
}
$dfsrReplFoldersList = $null
If ($(checkDNExistence -dnsHostNameRWDC $rwdcADDomainFQDN -dn "CN=DFSR-GlobalSettings,CN=System,$($domainOptionChosen.'Domain DN')") -eq "SUCCESS") {
	$dfsrReplFoldersList = getDFSRReplGroupsAndFoldersInADDomain -adDomainDN $($domainOptionChosen.'Domain DN') -rwdcFQDN $rwdcADDomainFQDN  | Sort-Object -Property "Repl Folder Guid" -Descending
}
# Determine How SYSVOL Is REPLICATED
# SYSVOL Replication Initially Through NTFRS -> Only NTFRS Included
# SYSVOL Replication Initially Through DFSR -> Only DFSR Included
# SYSVOL Replication Most Likely Being Migrated
# PREPARED State (GlobalState = 1) > "NTFRS (ACTIVE)" And "DFSR (PASSIVE)"
# REDIRECTED State (GlobalState = 2) > "NTFRS (PASSIVE)" And "DFSR (ACTIVE)"
$sysvolReplMechanisms = determineSYSVOLReplicationMechanism -adDomainDN $($domainOptionChosen.'Domain DN') -rwdcFQDN $rwdcADDomainFQDN
$sysvolReplMechanismsCount = ($sysvolReplMechanisms | Measure-Object).Count
# Create Complete List Of Replicated Sets/Folders
$replFolderList = @()
# If Any NTFRS Replica Set Exists, Them Process It
If ($ntfrsReplSetsList) {
	$ntfrsReplSetsList | ForEach-Object {
		$replFolderListEntry = New-Object -TypeName System.Object
		$replFolderListEntry | Add-Member -MemberType NoteProperty -Name "Repl Folder Name" -Value $($_."Repl Set Name")
		$replFolderListEntry | Add-Member -MemberType NoteProperty -Name "Repl Group Name" -Value "N.A."
		$replFolderListEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $(If ($_."Repl Set Name" -eq "Domain System Volume (SYSVOL share)" -And $(-not [string]::IsNullOrEmpty($($sysvolReplMechanisms | Where-Object {$_ -match "NTFRS"})))) {$($sysvolReplMechanisms | Where-Object {$_ -match "NTFRS"})} Else {$($_.Type)})
		$replFolderList += $replFolderListEntry
	}
}
# If Any NTFRS Replica Set Exists, Them Process It
If ($dfsrReplFoldersList) {
	$dfsrReplFoldersList | ForEach-Object {
		$replFolderListEntry = New-Object -TypeName System.Object
		$replFolderListEntry | Add-Member -MemberType NoteProperty -Name "Repl Folder Name" -Value $($_."Repl Folder Name")
		$replFolderListEntry | Add-Member -MemberType NoteProperty -Name "Repl Group Name" -Value $($_."Repl Group Name")
		$replFolderListEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $(If ($_."Repl Folder Name" -eq "SYSVOL Share" -And $(-not [string]::IsNullOrEmpty($($sysvolReplMechanisms | Where-Object {$_ -match "DFSR"})))) {$($sysvolReplMechanisms | Where-Object {$_ -match "DFSR"})} Else {$($_.Type)})
		$replFolderList += $replFolderListEntry
	}
}
# Build Up The List To Display
$dfsrReplFolderSpecificOption = 0
$defaultDfsrReplFolderSpecificNumericOption = $null
$dfsrReplFolderNumericSelection = $null
ForEach ($dfsrReplFolderOption in $replFolderList) {
	$dfsrReplFolderSpecificOption++
	If ($sysvolReplMechanismsCount -eq 1 -And $dfsrReplFolderOption."Repl Folder Name" -eq "SYSVOL Share" -And $sysvolReplMechanisms -Contains "DFSR") {
		writeLog -dataToLog "[$dfsrReplFolderSpecificOption] Repl Folder Name: $($dfsrReplFolderOption.'Repl Folder Name'.PadRight(43, " ")) | Repl Group Name: $($dfsrReplFolderOption.'Repl Group Name'.PadRight(34, " ")) | Type: $($dfsrReplFolderOption.'Type'.PadRight(32, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
		$defaultDfsrReplFolderSpecificNumericOption = $dfsrReplFolderSpecificOption
	} ElseIf ($sysvolReplMechanismsCount -eq 1 -And $dfsrReplFolderOption."Repl Folder Name" -eq "Domain System Volume (SYSVOL share)" -And $sysvolReplMechanisms -Contains "NTFRS") {
		writeLog -dataToLog "[$dfsrReplFolderSpecificOption] Repl Folder Name: $($dfsrReplFolderOption.'Repl Folder Name'.PadRight(43, " ")) | Repl Group Name: $($dfsrReplFolderOption.'Repl Group Name'.PadRight(34, " ")) | Type: $($dfsrReplFolderOption.'Type'.PadRight(32, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
		$defaultDfsrReplFolderSpecificNumericOption = $dfsrReplFolderSpecificOption
	} ElseIf ($sysvolReplMechanismsCount -eq 2 -And $dfsrReplFolderOption."Repl Folder Name" -eq "SYSVOL Share" -And $sysvolReplMechanisms -Contains "DFSR (ACTIVE)") {
		writeLog -dataToLog "[$dfsrReplFolderSpecificOption] Repl Folder Name: $($dfsrReplFolderOption.'Repl Folder Name'.PadRight(43, " ")) | Repl Group Name: $($dfsrReplFolderOption.'Repl Group Name'.PadRight(34, " ")) | Type: $($dfsrReplFolderOption.'Type'.PadRight(32, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
		$defaultDfsrReplFolderSpecificNumericOption = $dfsrReplFolderSpecificOption
	} ElseIf ($sysvolReplMechanismsCount -eq 2 -And $dfsrReplFolderOption."Repl Folder Name" -eq "Domain System Volume (SYSVOL share)" -And $sysvolReplMechanisms -Contains "NTFRS (ACTIVE)") {
		writeLog -dataToLog "[$dfsrReplFolderSpecificOption] Repl Folder Name: $($dfsrReplFolderOption.'Repl Folder Name'.PadRight(43, " ")) | Repl Group Name: $($dfsrReplFolderOption.'Repl Group Name'.PadRight(34, " ")) | Type: $($dfsrReplFolderOption.'Type'.PadRight(32, " ")) [DEFAULT]" -lineType "DEFAULT" -logFileOnly $false -noDateTimeInLogLine $false
		$defaultDfsrReplFolderSpecificNumericOption = $dfsrReplFolderSpecificOption
	} Else {
		writeLog -dataToLog "[$dfsrReplFolderSpecificOption] Repl Folder Name: $($dfsrReplFolderOption.'Repl Folder Name'.PadRight(43, " ")) | Repl Group Name: $($dfsrReplFolderOption.'Repl Group Name'.PadRight(34, " ")) | Type: $($dfsrReplFolderOption.'Type'.PadRight(32, " "))" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	}
}
writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "REMARK: Specify A NUMBER Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
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
If ($replFolderOptionChosen.Type -match "NTFRS") {
	$ntfrsReplFolderOptionChosen = $ntfrsReplSetsList | Where-Object {$_."Repl Set Name" -eq $($replFolderOptionChosen."Repl Folder Name")}
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "+++ LIST MEMBERS SUPPORTING THE REPLICATED FOLDER '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	$ntfrsReplSetMemberList = getNTFRSReplSetMembers -adDomainDN $($domainOptionChosen.'Domain DN') -rwdcFQDN $($domainsAndDCsHT[$($domainOptionChosen.'Domain FQDN')]) -ntfrsReplicaSetName $($ntfrsReplFolderOptionChosen."Repl Set Name")
	If (($ntfrsReplSetMemberList | Where-Object {$_.MetadataState -eq "METADATA-COMPLETE"} | Measure-Object).Count -gt 0) {
		$ntfrsReplFolderConfigAndState = getNTFRSReplSetConfigAndState -ntfrsReplSetMemberList $($ntfrsReplSetMemberList | Where-Object {$_.MetadataState -eq "METADATA-COMPLETE"}) -ntfrsReplSetName $($ntfrsReplFolderOptionChosen."Repl Set Name") -rwdcFQDN $($domainsAndDCsHT[$($domainOptionChosen.'Domain FQDN')])
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "`n$($ntfrsReplFolderConfigAndState | Format-Table -Property * -Wrap -Autosize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [$((($ntfrsReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $true}) | Measure-Object).count)] NTFRS Members That Are REACHABLE Over SMB..." -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [$((($ntfrsReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $false}) | Measure-Object).count)] NTFRS Members That Are NOT REACHABLE Over SMB..." -logFileOnly $false -noDateTimeInLogLine $false
	}
	If ((($ntfrsReplSetMemberList | Where-Object {$_.MetadataState -eq "METADATA-ORPHANED"}) | Measure-Object).Count -gt 0) {
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [$((($ntfrsReplSetMemberList | Where-Object {$_.MetadataState -eq 'METADATA-ORPHANED'}) | Measure-Object).Count)] NTFRS Members (NOT Listed In The Table Above) That Have Orphaned Metadata...CLEANUP NEEDED! (Look For Member Objects WITHOUT A Value For 'frsComputerReference')" -logFileOnly $false -noDateTimeInLogLine $false
	}
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	If (($ntfrsReplSetMemberList | Where-Object {$_.MetadataState -eq "METADATA-COMPLETE"} | Measure-Object).Count -gt 0) {
		If ($($ntfrsReplFolderConfigAndState | Where-Object {$_."Site Name" -eq $localComputerSiteName -And $_.ReachableSMB -eq $true})) {
			$discoveredMemberFQDN = $($ntfrsReplFolderConfigAndState | Where-Object {$_."Site Name" -eq $localComputerSiteName -And $_.ReachableSMB -eq $true})[0]."Member FQDN"
		} Else {
			$discoveredMemberFQDN = $($ntfrsReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $true})[0]."Member FQDN"
		}
	} Else {
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [0] NTFRS Members For The Specified Replica Set..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

		BREAK
	}
}

# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -match "DFSR") {
	$dfsrReplFolderOptionChosen = $dfsrReplFoldersList | Where-Object {$_."Repl Folder Name" -eq $($replFolderOptionChosen."Repl Folder Name")}
	$dfsrReplFolderOptionChosenGuid = ($dfsrReplFoldersList | Where-Object {$_."Repl Folder Name" -eq $($dfsrReplFolderOptionChosen."Repl Folder Name")})."Repl Folder Guid"
	$dfsrReplFolderOptionChosenGroupName = ($dfsrReplFoldersList | Where-Object {$_."Repl Folder Name" -eq $($dfsrReplFolderOptionChosen."Repl Folder Name")})."Repl Group Name"
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "+++ LIST MEMBERS SUPPORTING THE REPLICATED FOLDER '$($dfsrReplFolderOptionChosen.'Repl Folder Name') ($dfsrReplFolderOptionChosenGroupName)' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	$dfsrReplGroupMemberList = getDFSRReplGroupMembers -adDomainDN $($domainOptionChosen.'Domain DN') -rwdcFQDN $($domainsAndDCsHT[$($domainOptionChosen.'Domain FQDN')]) -dfsrReplGroupName $dfsrReplFolderOptionChosenGroupName -domainsAndDCsHT $domainsAndDCsHT
	If (($dfsrReplGroupMemberList | Where-Object {$_.MetadataState -eq "METADATA-COMPLETE"} | Measure-Object).Count -gt 0) {
		$dfsrReplFolderConfigAndState = getDFSRReplFolderConfigAndState -dfsrReplGroupName $dfsrReplFolderOptionChosenGroupName -dfsrReplGroupMemberList $($dfsrReplGroupMemberList | Where-Object {$_.MetadataState -eq "METADATA-COMPLETE"}) -dfsrReplGroupContentSetName $($dfsrReplFolderOptionChosen."Repl Folder Name") -dfsrReplGroupContentSetGuid $dfsrReplFolderOptionChosenGuid -domainsAndDCsHT $domainsAndDCsHT
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "`n$($dfsrReplFolderConfigAndState | Format-Table -Property * -Wrap -Autosize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $true}) | Measure-Object).count)] DFS-R Members That Are REACHABLE Over SMB..." -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $false}) | Measure-Object).count)] DFS-R Members That Are NOT REACHABLE Over SMB..." -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $true -And $_.State -eq 'Enabled'}) | Measure-Object).count)] DFS-R Members With ENABLED DFS-R Replication State For The DFR-R Replicated Folder '$($dfsrReplFolderOptionChosen."Repl Folder Name")' (REACHABLE Over SMB)..." -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $false -And $_.State -eq 'Enabled'}) | Measure-Object).count)] DFS-R Members With ENABLED DFS-R Replication State For The DFR-R Replicated Folder '$($dfsrReplFolderOptionChosen."Repl Folder Name")' (NOT REACHABLE Over SMB)..." -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $true -And $_.State -eq 'Disabled'}) | Measure-Object).count)] DFS-R Members With DISABLED DFS-R Replication State For The DFR-R Replicated Folder '$($dfsrReplFolderOptionChosen."Repl Folder Name")' (REACHABLE Over SMB)..." -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $false -And $_.State -eq 'Disabled'}) | Measure-Object).count)] DFS-R Members With DISABLED DFS-R Replication State For The DFR-R Replicated Folder '$($dfsrReplFolderOptionChosen."Repl Folder Name")' (NOT REACHABLE Over SMB)..." -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $true -And $_.State -eq '<UNKNOWN>'}) | Measure-Object).count)] DFS-R Members With UNKNOWN DFS-R Replication State For The DFR-R Replicated Folder '$($dfsrReplFolderOptionChosen."Repl Folder Name")' (REACHABLE Over SMB)..." -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [$((($dfsrReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $false -And $_.State -eq '<UNKNOWN>'}) | Measure-Object).count)] DFS-R Members With UNKNOWN DFS-R Replication State For The DFR-R Replicated Folder '$($dfsrReplFolderOptionChosen."Repl Folder Name")' (NOT REACHABLE Over SMB)..." -logFileOnly $false -noDateTimeInLogLine $false
	}
	If ((($dfsrReplGroupMemberList | Where-Object {$_.MetadataState -eq "METADATA-ORPHANED"}) | Measure-Object).Count -gt 0) {
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [$((($dfsrReplGroupMemberList | Where-Object {$_.MetadataState -eq 'METADATA-ORPHANED'}) | Measure-Object).Count)] DFS-R Members (NOT Listed In The Table Above) That Have Orphaned Metadata...CLEANUP NEEDED! (Look For Member Objects WITHOUT A Value For 'msDFSR-ComputerReference')" -logFileOnly $false -noDateTimeInLogLine $false
	}
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	If (($dfsrReplGroupMemberList | Where-Object {$_.MetadataState -eq "METADATA-COMPLETE"} | Measure-Object).Count -gt 0) {
		If ($($dfsrReplFolderConfigAndState | Where-Object {$_."Site Name" -eq $localComputerSiteName -And $_.ReachableSMB -eq $true -And $_.State -eq "Enabled"})) {
			$discoveredMemberFQDN = $($dfsrReplFolderConfigAndState | Where-Object {$_."Site Name" -eq $localComputerSiteName -And $_.ReachableSMB -eq $true -And $_.State -eq "Enabled" -And $_.Type -eq "RW"})[0]."Member FQDN"
		} Else {
			$discoveredMemberFQDN = $($dfsrReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $true -And $_.State -eq "Enabled" -And $_.Type -eq "RW"})[0]."Member FQDN"
		}
	} Else {
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " --> Found [0] DFS-R Members For The Specified Replicated Folder..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

		BREAK
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
If ($replFolderOptionChosen.Type -match "NTFRS") {
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
	writeLog -dataToLog "REMARK: Specify A NUMBER Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	If ([String]::IsNullOrEmpty($targetReplMember)) {
		Do {
			$sourceMemberNumericSelection = Read-Host "Please Choose Source Member To Use For The File....."
		} Until (([int]$sourceMemberNumericSelection -gt 0 -And [int]$sourceMemberNumericSelection -le ($sourceMemberOptions | Measure-Object).Count) -Or $([string]::IsNullOrEmpty($sourceMemberNumericSelection)))
		If ([string]::IsNullOrEmpty($sourceMemberNumericSelection)) {
			$sourceMemberNumericSelection = $defaultSourceRWDCSpecificNumericOption
		}
	} Else {
		$sourceMemberOptionsHT = @{}
		If ($($ntfrsReplFolderOptionChosen.'Repl Set Name') -eq "Domain System Volume (SYSVOL share)") {
			$sourceMemberOptionsHT["Fsmo"] = $sourceMemberOptions[0]
			$sourceMemberOptionsHT["Discover"] = $sourceMemberOptions[1]
			$sourceMemberOptionsHT[$targetReplMember] = $sourceMemberOptions[2]
		} Else {
			$sourceMemberOptionsHT["Discover"] = $sourceMemberOptions[0]
			$sourceMemberOptionsHT[$targetReplMember] = $sourceMemberOptions[1]
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
If ($replFolderOptionChosen.Type -match "DFSR") {
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
	writeLog -dataToLog "REMARK: Specify A NUMBER Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	If ([String]::IsNullOrEmpty($targetReplMember)) {
		Do {
			$sourceMemberNumericSelection = Read-Host "Please Choose Source Member To Use For The File....."
		} Until (([int]$sourceMemberNumericSelection -gt 0 -And [int]$sourceMemberNumericSelection -le ($sourceMemberOptions | Measure-Object).Count) -Or $([string]::IsNullOrEmpty($sourceMemberNumericSelection)))
		If ([string]::IsNullOrEmpty($sourceMemberNumericSelection)) {
			$sourceMemberNumericSelection = $defaultSourceRWDCSpecificNumericOption
		}
	} Else {
		$sourceMemberOptionsHT = @{}
		If ($($dfsrReplFolderOptionChosen.'Repl Folder Name') -eq "SYSVOL Share") {
			$sourceMemberOptionsHT["Fsmo"] = $sourceMemberOptions[0]
			$sourceMemberOptionsHT["Discover"] = $sourceMemberOptions[1]
			$sourceMemberOptionsHT[$targetReplMember] = $sourceMemberOptions[2]
		} Else {
			$sourceMemberOptionsHT["Discover"] = $sourceMemberOptions[0]
			$sourceMemberOptionsHT[$targetReplMember] = $sourceMemberOptions[1]
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
If ($replFolderOptionChosen.Type -match "NTFRS") {
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Checking Existence And Connectivity Of The Specified Member '$sourceMemberFQDN' For The Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')'..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	If ($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $sourceMemberFQDN -And $_.ReachableSMB -eq $true -And $_.Type -eq "RW"}) {
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Specified Member '$sourceMemberFQDN':" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Exists, And" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Is Available/Reachable Over SMB, And" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Supports/Hosts A Writable Copy Of The Chosen Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')'!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false

		($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $sourceMemberFQDN})."Source" = $true
		($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -ne $sourceMemberFQDN}) | ForEach-Object {$_."Source" = $false}
		($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $sourceMemberFQDN})."Member FQDN" = "$($sourceMemberFQDN + " [SOURCE MEMBER]")"
		$ntfrsReplFolderConfigAndState = $ntfrsReplFolderConfigAndState | Sort-Object -Property Source -Descending # To Make Sure The Source Member Is At The Top Of The List!
	} Else {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Specified Member '$sourceMemberFQDN':" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > DOES NOT Exist, And/Or" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > IS NOT Available/Reachable Over SMB, And/Or" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > DOES NOT Support/Host A Writable Copy Of The Chosen Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Please Re-Run The Script And Make Sure To Use A Member That Is Available/Reachable Over SMB And Supports/Hosts A Writable Copy Of The Chosen Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Make Sure To Review The List Of Members Supporting The Replicated Folder, And Pay Special Attention To The Columns 'Member FQDN', 'ReachableSMB' and 'Type'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		BREAK
	}
}

# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -match "DFSR") {
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "Checking Existence And Connectivity Of The Specified Member '$sourceMemberFQDN' For The Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'..." -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
	If ($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $sourceMemberFQDN -And $_.ReachableSMB -eq $true -And $_.State -eq "Enabled" -And ($_.Type -eq "RW" -Or $_.Type -eq "<UNKNOWN>")}) {
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Specified Member '$sourceMemberFQDN':" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Exists, And" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Is Available/Reachable Over SMB, And" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Has An Enabled Replication State, And" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > Supports/Hosts A Writable Copy Of The Chosen Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Continuing Script..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false

		($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $sourceMemberFQDN})."Source" = $true
		($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -ne $sourceMemberFQDN}) | ForEach-Object {$_."Source" = $false}
		($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -eq $sourceMemberFQDN})."Member FQDN" = "$($sourceMemberFQDN + " [SOURCE MEMBER]")"
		$dfsrReplFolderConfigAndState = $dfsrReplFolderConfigAndState | Sort-Object -Property Source -Descending # To Make Sure The Source Member Is At The Top Of The List!
	} Else {
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "The Specified Member '$sourceMemberFQDN':" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > DOES NOT Exist, And/Or" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > IS NOT Available/Reachable Over SMB, And/Or" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > DOES NOT Have An Enabled Replication State, And/Or" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " > DOES NOT Support/Host A Writable Copy Of The Chosen Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Please Re-Run The Script And Make Sure To Use A Member That Is Available/Reachable Over SMB, Has An Enabled Replication State And Supports/Hosts A Writable Copy Of The Chosen Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Make Sure To Review The List Of Members Supporting The Replicated Folder, And Pay Special Attention To The Columns 'Member FQDN', 'ReachableSMB', 'State' and 'Type'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
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

	# Create And Open Runspace Pool, Setup Runspaces Array With Min And Max Threads
	$runspacePool = [RunspaceFactory]::CreateRunspacePool($runspacePoolMinThreads, $runspacePoolMaxThreads)
	$runspacePool.ApartmentState = "MTA" # STA = Single Threaded Appartment, MTA = Multi Threaded Appartment
	$runspacePool.Open()
	$runspacesCollection = @()
	$runspacesResults = @()

	# Reusable ScriptBlock That Needs To Be Executed Within Every Runspace. This Is The Stuff That Iteratively Needs To Be Executed
	$scriptblock = {
		Param (
			$reachableWINRM,
			$replMemberFQDN,
			$replFolderPath
		)

		$startDateTimeIteration = Get-Date -format "yyyy-MM-dd HH:mm:ss"

		If ($reachableWINRM -eq $true) {
			$fileCountInReplFolder = Invoke-Command -ComputerName $replMemberFQDN -ArgumentList $replFolderPath -ScriptBlock {
				Param (
					$replFolderPath
				)
				
				Try {
					$listOfFiles = Get-ChildItem $replFolderPath -Recurse -ErrorAction Stop
					$fileCountInReplFolder = ($listOfFiles | Measure-Object).Count
				} Catch [UnauthorizedAccessException] {
					$fileCountInReplFolder = "ERROR_ACCESS_DENIED_$($_.Exception.Message)"
				} Catch {
					$fileCountInReplFolder = "ERROR_UNKNOWN_$($_.Exception.Message)"
				}
				
				Return $fileCountInReplFolder
			}
		} Else {
			$fileCountInReplFolder = "<SKIP>"
		}

		$endDateTimeIteration = Get-Date -format "yyyy-MM-dd HH:mm:ss"

		Return [PSCustomObject]@{
			replMemberFQDN         = $replMemberFQDN
			fileCountInReplFolder  = $fileCountInReplFolder
			startDateTimeIteration = $startDateTimeIteration
			endDateTimeIteration   = $endDateTimeIteration
		}
	}

	# If The Replicated Folder Is Using NTFRS
	If ($replFolderOptionChosen.Type -match "NTFRS") {
		writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "+++ COUNTING THE FILES IN THE REPLICATED FOLDER '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		# For Each Member In The List/Table With Members To Process '$ntfrsReplFolderConfigAndState' Perform A Number Of Steps
		$ntfrsReplFolderConfigAndState | ForEach-Object {
			$replMember = $_
			# Only For The Replication Member Used As The Source Member
			If ($replMember.ReachableWINRM -eq $true) {
				writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  * Contacting Member For Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' ...[$($replMember."Member FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Member Is Reachable Over WinRM..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Counting Files..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				$replFolderPath = $replMember."Repl Folder Path"

				If ($replMember."Member FQDN" -match $sourceMemberFQDN) {
					$ntfrsReplMember = $sourceMemberFQDN
				} Else {
					$ntfrsReplMember = $replMember."Member FQDN"
				}

				# Create The Runspace For The Iteration, Add Script(s), Argument(s), Parameter(s) As Needed
				$runspaceIteration = [PowerShell]::Create()
				[void]$($runspaceIteration.AddScript($scriptblock))
				[void]$($runspaceIteration.AddArgument($replMember.ReachableWINRM))
				[void]$($runspaceIteration.AddArgument($ntfrsReplMember))
				[void]$($runspaceIteration.AddArgument($replFolderPath))

				# Assign The Runspace To The Runspace Pool
				$runspaceIteration.RunspacePool = $runspacePool

				# Add The Runspace To The Runspaces Collection, And Start The Runspace
				$runspacesCollection += [PSCustomObject]@{ Pipe = $runspaceIteration; Status = $runspaceIteration.BeginInvoke() }
			}
			If ($replMember.ReachableWINRM -eq $false) {
				writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  * Contacting Member For Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' ...[$($replMember."Member FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Member IS NOT Reachable Over WinRM..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Skipping Counting Files..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				$replFolderPath = $replMember."Repl Folder Path"

				# Create The Runspace For The Iteration, Add Script(s), Argument(s), Parameter(s) As Needed
				$runspaceIteration = [PowerShell]::Create()
				[void]$($runspaceIteration.AddScript($scriptblock))
				[void]$($runspaceIteration.AddArgument($replMember.ReachableWINRM))
				[void]$($runspaceIteration.AddArgument($($replMember."Member FQDN")))
				[void]$($runspaceIteration.AddArgument($replFolderPath))

				# Assign The Runspace To The Runspace Pool
				$runspaceIteration.RunspacePool = $runspacePool

				# Add The Runspace To The Runspaces Collection, And Start The Runspace
				$runspacesCollection += [PSCustomObject]@{ Pipe = $runspaceIteration; Status = $runspaceIteration.BeginInvoke() }
			}
		}

		# Get The Data From The Runspaces That Were Created
		While ($runspacesCollection.Status -ne $null) {
			$completedRunspaces = @()
			$runspacesCollection | ForEach-Object {
				$runSpace = $_
				If ($runSpace.Status) {
					$runSpaceStatus = $runSpace.Status
					If ($runSpaceStatus.IsCompleted -eq $true) {
						$completedRunspaces += $runSpace
					}
				}
			}

			ForEach ($completedRunspaceIteration in $completedRunspaces) {
				# When Desired, Process Data HERE As Soon As It Becomes Available From Any Runspace
				$runspaceResult = $completedRunspaceIteration.Pipe.EndInvoke($completedRunspaceIteration.Status)
				$runspacesResults += $runspaceResult
				$completedRunspaceIteration.Status = $null
				$completedRunspaceIteration.Pipe.Dispose()
			}
		}

		# Close The Runspace Pool And Clean It Up
		$runspacePool.Close() 
		$runspacePool.Dispose()

		# Populate The Missing Data In Config And State Table
		$runspacesResults | ForEach-Object {
			$replMemberFQDN = $_.replMemberFQDN
			$fileCountInReplFolder = $_.fileCountInReplFolder
			$startDateTimeIteration = $_.startDateTimeIteration
			$endDateTimeIteration = $_.endDateTimeIteration
			
			($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $replMemberFQDN})."File Count" = $fileCountInReplFolder
			($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $replMemberFQDN})."Start Time Check" = $startDateTimeIteration
			($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $replMemberFQDN})."End Time Check" = $endDateTimeIteration
		}

		# Display The Data
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "`n$($ntfrsReplFolderConfigAndState | Format-Table -Property * -Wrap -Autosize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

		If ($exportResultsToCSV) {
			$ntfrsReplFolderConfigAndState | Export-Csv -Path $fileCountResultsExportCsvFullPath -Delimiter ";" -NoTypeInformation
			writeLog -dataToLog "File Count Export CSV Full Path.......: $fileCountResultsExportCsvFullPath" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		}
	}

	# If The Replicated Folder Is Using DFSR
	If ($replFolderOptionChosen.Type -match "DFSR") {
		writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "+++ COUNTING THE FILES IN THE REPLICATED FOLDER '$($dfsrReplFolderOptionChosen.'Repl Folder Name') ($dfsrReplFolderOptionChosenGroupName)' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
		# For Each Member In The List/Table With Members To Process '$dfsrReplFolderConfigAndState' Perform A Number Of Steps
		$dfsrReplFolderConfigAndState | ForEach-Object {
			$replMember = $_
			# Only For The Replication Member Used As The Source Member
			If ($replMember.ReachableWINRM -eq $true) {
				writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  * Contacting Member For Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')' ...[$($replMember."Member FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Member Is Reachable Over WinRM..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Counting Files..." -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
				$replFolderPath = $replMember."Repl Folder Path"

				If ($replMember."Member FQDN" -match $sourceMemberFQDN) {
					$dfsrReplMember = $sourceMemberFQDN
				} Else {
					$dfsrReplMember = $replMember."Member FQDN"
				}

				# Create The Runspace For The Iteration, Add Script(s), Argument(s), Parameter(s) As Needed
				$runspaceIteration = [PowerShell]::Create()
				[void]$($runspaceIteration.AddScript($scriptblock))
				[void]$($runspaceIteration.AddArgument($replMember.ReachableWINRM))
				[void]$($runspaceIteration.AddArgument($dfsrReplMember))
				[void]$($runspaceIteration.AddArgument($replFolderPath))

				# Assign The Runspace To The Runspace Pool
				$runspaceIteration.RunspacePool = $runspacePool

				# Add The Runspace To The Runspaces Collection, And Start The Runspace
				$runspacesCollection += [PSCustomObject]@{ Pipe = $runspaceIteration; Status = $runspaceIteration.BeginInvoke() }
			}
			If ($replMember.ReachableWINRM -eq $false) {
				writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "  * Contacting Member For Replicated Folder '$($dfsrReplFolderOptionChosen.'Repl Folder Name')' ...[$($replMember."Member FQDN".ToUpper())]..." -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Member IS NOT Reachable Over WinRM..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
				writeLog -dataToLog "     - Skipping Counting Files..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

				# Create The Runspace For The Iteration, Add Script(s), Argument(s), Parameter(s) As Needed
				$runspaceIteration = [PowerShell]::Create()
				[void]$($runspaceIteration.AddScript($scriptblock))
				[void]$($runspaceIteration.AddArgument($replMember.ReachableWINRM))
				[void]$($runspaceIteration.AddArgument($replMember."Member FQDN"))
				[void]$($runspaceIteration.AddArgument($replFolderPath))

				# Assign The Runspace To The Runspace Pool
				$runspaceIteration.RunspacePool = $runspacePool

				# Add The Runspace To The Runspaces Collection, And Start The Runspace
				$runspacesCollection += [PSCustomObject]@{ Pipe = $runspaceIteration; Status = $runspaceIteration.BeginInvoke() }
			}
		}

		# Get The Data From The Runspaces That Were Created
		While ($runspacesCollection.Status -ne $null) {
			$completedRunspaces = @()
			$runspacesCollection | ForEach-Object {
				$runSpace = $_
				If ($runSpace.Status) {
					$runSpaceStatus = $runSpace.Status
					If ($runSpaceStatus.IsCompleted -eq $true) {
						$completedRunspaces += $runSpace
					}
				}
			}

			ForEach ($completedRunspaceIteration in $completedRunspaces) {
				# When Desired, Process Data HERE As Soon As It Becomes Available From Any Runspace
				$runspaceResult = $completedRunspaceIteration.Pipe.EndInvoke($completedRunspaceIteration.Status)
				$runspacesResults += $runspaceResult
				$completedRunspaceIteration.Status = $null
				$completedRunspaceIteration.Pipe.Dispose()
			}
		}

		# Close The Runspace Pool And Clean It Up
		$runspacePool.Close() 
		$runspacePool.Dispose()

		# Populate The Missing Data In Config And State Table
		$runspacesResults | ForEach-Object {
			$replMemberFQDN = $_.replMemberFQDN
			$fileCountInReplFolder = $_.fileCountInReplFolder
			$startDateTimeIteration = $_.startDateTimeIteration
			$endDateTimeIteration = $_.endDateTimeIteration
			
			($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $replMemberFQDN})."File Count" = $fileCountInReplFolder
			($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $replMemberFQDN})."Start Time Check" = $startDateTimeIteration
			($dfsrReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $replMemberFQDN})."End Time Check" = $endDateTimeIteration
		}

		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "`n$($dfsrReplFolderConfigAndState | Format-Table -Property * -Wrap -Autosize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false

		If ($exportResultsToCSV) {
			$dfsrReplFolderConfigAndState | Export-Csv -Path $fileCountResultsExportCsvFullPath -Delimiter ";" -NoTypeInformation
			writeLog -dataToLog "File Count Export CSV Full Path.......: $fileCountResultsExportCsvFullPath" -logFileOnly $false -noDateTimeInLogLine $false
			writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		}
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
If ($replFolderOptionChosen.Type -match "NTFRS") {
	$replFolderPath = ($ntfrsReplFolderConfigAndState | Where-Object {$_."Member FQDN" -match $sourceMemberFQDN})."Repl Folder Path"
	If ($($ntfrsReplFolderOptionChosen.'Repl Set Name') -eq "Domain System Volume (SYSVOL share)") {
		$uncPathFolderSource = "\\" + $sourceMemberFQDN + "\" + $($replFolderPath.Replace(":","$")) + "\Scripts"
	} Else {
		$uncPathFolderSource = "\\" + $sourceMemberFQDN + "\" + $($replFolderPath.Replace(":","$"))
	}	
}
# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -match "DFSR") {
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
If ($replFolderOptionChosen.Type -match "NTFRS") {
	$tempCanaryFileContent = "...!!!...TEMP FILE TO TEST REPLICATION LATENCY/CONVERGENCE FOR REPLICATED FOLDER $($ntfrsReplFolderOptionChosen.'Repl Set Name'.ToUpper()) IN AD DOMAIN $($domainOptionChosen.'Domain FQDN') USING MEMBER $($sourceMemberFQDN.ToUpper()) AS THE SOURCE MEMBER...!!!..."
}
# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -match "DFSR") {
	$tempCanaryFileContent = "...!!!...TEMP FILE TO TEST REPLICATION LATENCY/CONVERGENCE FOR REPLICATED FOLDER $($dfsrReplFolderOptionChosen.'Repl Folder Name'.ToUpper()) IN AD DOMAIN $($domainOptionChosen.'Domain FQDN') USING MEMBER $($sourceMemberFQDN.ToUpper()) AS THE SOURCE MEMBER...!!!..."
}
writeLog -dataToLog "  --> AD Domain FQDN......: $($domainOptionChosen.'Domain FQDN')" -logFileOnly $false -noDateTimeInLogLine $false
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -match "NTFRS") {
	writeLog -dataToLog "  --> Repl Mechanism......: NTFRS" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "  --> In Replicated Folder: $($ntfrsReplFolderOptionChosen.'Repl Set Name')" -logFileOnly $false -noDateTimeInLogLine $false
}
# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -match "DFSR") {
	writeLog -dataToLog "  --> Repl Mechanism......: DFSR" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "  --> In Replicated Folder: $($dfsrReplFolderOptionChosen.'Repl Folder Name')" -logFileOnly $false -noDateTimeInLogLine $false
}
writeLog -dataToLog "  --> On Source Member....: $sourceMemberFQDN" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> In Folder (UNC Path): $uncPathFolderSource" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> With Full Name......: $tempCanaryFileName" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> With Content........: $tempCanaryFileContent" -logFileOnly $false -noDateTimeInLogLine $false
$uncPathCanaryFileSource = $uncPathFolderSource + "\" + $tempCanaryFileName + ".txt"
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -match "NTFRS") {
	Try {
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " Creating The Temporary Canary File..." -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		$tempCanaryFileContent | Out-File -FilePath $uncPathCanaryFileSource -ErrorAction Stop
		$startDateTime = Get-Date
		writeLog -dataToLog " Temporary Canary File [$uncPathCanaryFileSource] Has Been Created On Source Member [$sourceMemberFQDN] In Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')'!" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	} Catch {
		writeLog -dataToLog " Temporary Canary File [$uncPathCanaryFileSource] Could Not Be Created On Source Member [$sourceMemberFQDN] In Replicated Folder '$($ntfrsReplFolderOptionChosen.'Repl Set Name')'!" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "Aborting Script..." -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ERROR" -logFileOnly $false -noDateTimeInLogLine $false

		BREAK
	}
}
# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -match "DFSR") {
	Try {
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog " Creating The Temporary Canary File..." -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		$tempCanaryFileContent | Out-File -FilePath $uncPathCanaryFileSource -ErrorAction Stop
		$startDateTime = Get-Date
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
# Go Through The Process Of Checking Each Member To See If The Temporary Canary File Already Has Replicated To It
###
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -match "NTFRS") {
	$nrTotalMembersSupportingFolder = $($ntfrsReplFolderConfigAndState | Measure-Object).Count
	$nrTotalMembersReachable = $($ntfrsReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $true} | Measure-Object).Count
	$nrTotalMembersUnreachable = $($ntfrsReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $false} | Measure-Object).Count
}
# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -match "DFSR") {
	$nrTotalMembersSupportingFolder = $($dfsrReplFolderConfigAndState | Measure-Object).Count
	$nrTotalMembersReachable = $($dfsrReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $true} | Measure-Object).Count
	$nrTotalMembersUnreachable = $($dfsrReplFolderConfigAndState | Where-Object {$_.ReachableSMB -eq $false} | Measure-Object).Count
}
writeLog -dataToLog "  --> Discovered Total Of [$nrTotalMembersSupportingFolder] Member(s) Supporting/Hosting The Chosen Replicated Folder..." -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> Discovered Total Of [$nrTotalMembersReachable] REACHABLE Member(s) Supporting/Hosting The Chosen Replicated Folder..." -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "  --> Discovered Total Of [$nrTotalMembersUnreachable] UNREACHABLE Member(s) Supporting/Hosting The Chosen Replicated Folder..." -logFileOnly $false -noDateTimeInLogLine $false
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
$htmlContent1 = $htmlContent1.Replace("REPLACEME_ADDOMAINFQDN",$($domainOptionChosen.'Domain FQDN'))
# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -match "DFSR") {
	$htmlContent1 = $htmlContent1.Replace("REPLACEME_REPLMECHANISM","DFSR")
	$htmlContent1 = $htmlContent1.Replace("REPLACEME_REPLICATEDFOLDER",$($dfsrReplFolderOptionChosen.'Repl Folder Name'))
}
# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -match "NTFRS") {
	$htmlContent1 = $htmlContent1.Replace("REPLACEME_REPLMECHANISM","NTFRS")
	$htmlContent1 = $htmlContent1.Replace("REPLACEME_REPLICATEDFOLDER",$($ntfrsReplFolderOptionChosen.'Repl Set Name'))
}
$htmlContent1 = $htmlContent1.Replace("REPLACEME_SOURCEMEMBER",$sourceMemberFQDN)
$htmlContent1 = $htmlContent1.Replace("REPLACEME_FOLDERUNCPATH",$uncPathFolderSource)
$htmlContent1 = $htmlContent1.Replace("REPLACEME_FILENAME",$tempCanaryFileName)
$htmlContent1 = $htmlContent1.Replace("REPLACEME_FILECONTENT",$tempCanaryFileContent)
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
		[string]$replMemberFQDN,
		[string]$replMemberIPv4,
		[string]$replMemberSite,
		[bool]$reachableSMB,
		[string]$replMemberType,
		[string]$uncPathCanaryFile,
		[string]$sourceReplMemberFQDN,
		[DateTime]$startDateTime,
		[Decimal]$timeoutInMinutes,
		[Decimal]$delayInMilliSecondsBetweenChecks
	)

	$checkResult = $null
	$fileWhenDiscvrd = $null
	$deltaDiscvrd = $null
	$canaryFileSource = $null
	$replicated = $null
	$continue = $true

	$startDateTimeIteration1 = Get-Date
	$startDateTimeIteration2 = Get-Date $startDateTimeIteration1 -format "yyyy-MM-dd HH:mm:ss"

	If ($replMemberFQDN -match $sourceReplMemberFQDN) {
		$replMemberFQDN = $sourceReplMemberFQDN
		$checkResult = "CHECK_OK"
		$fileWhenDiscvrd = Get-Date
		$deltaDiscvrd = $([decimal]$('{0:N2}' -f "0.00"))
		$canaryFileSource = $true
	} Else {
		If ($reachableSMB -eq $true) {
			While($continue -eq $true) {
				Try {
					# If The Temporary Canary File Already Exists (Assumption Is The Correct Permissions To Access The Temporary Canary File Are In Place!)
					If (Test-Path -Path $uncPathCanaryFile) {
						$replicated = $true
						$checkResult = "CHECK_OK"
						$fileWhenDiscvrd = Get-Date
						$deltaDiscvrd = $([decimal]$("{0:n2}" -f ($fileWhenDiscvrd - $startDateTime).TotalSeconds))
					} Else {
						$replicated = $false
						If ([decimal](New-TimeSpan -Start $startDateTimeIteration1 -End $(Get-Date)).TotalMinutes -ge [decimal]$timeoutInMinutes) {
							$checkResult = "TIMEOUT"
							$fileWhenDiscvrd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
							$deltaDiscvrd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
						} Else {
							$checkResult = "CHECK_OK"
						}
					}
					Start-Sleep -Milliseconds $delayInMilliSecondsBetweenChecks
				} Catch [UnauthorizedAccessException] {
					# If An Access Denied Occurs For Whatever Reason
					$checkResult = "ACCESS_DENIED"
					$fileWhenDiscvrd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
					$deltaDiscvrd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
				} Catch {
					# Something Else Happened....
					$checkResult = "UNKNOWN_ERROR (ERROR: $($_.Exception.Message))"
					$fileWhenDiscvrd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
					$deltaDiscvrd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
				}

				If ($replicated -eq $true -Or $checkResult -ne "CHECK_OK") {
					$continue = $false
				} Else {
					$continue = $true
				}
			}
		} Else {
			$checkResult = "NOT_REACHABLE_OVER_SMB"
			$fileWhenDiscvrd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
			$deltaDiscvrd = $([string]"<SKIPPED_DUE_TO_ERROR_$checkResult>")
		}
		$canaryFileSource = $false
	}

	$endDateTimeIteration = Get-Date -format "yyyy-MM-dd HH:mm:ss"

	Return [PSCustomObject]@{
		replMemberFQDN         = $replMemberFQDN
		replMemberIPv4         = $replMemberIPv4
		replMemberSite         = $replMemberSite
		reachableSMB           = $reachableSMB
		replMemberType         = $replMemberType
		canaryFileSource       = $canaryFileSource
		fileWhenDiscvrd        = $(If ($fileWhenDiscvrd -is [DateTime]) {$(Get-Date $fileWhenDiscvrd -f "yyyy-MM-dd HH:mm:ss")} Else {$fileWhenDiscvrd})
		deltaDiscvrd           = $deltaDiscvrd
		checkResult            = $checkResult
		startDateTimeIteration = $startDateTimeIteration2
		endDateTimeIteration   = $endDateTimeIteration
		uncPathCanaryFile      = $uncPathCanaryFile
	}
}

# Define The Start Time For The Check And The Expected End Time If Applicable Due To A Possible Timeout. Adding 1 Extra Minute
$startDateTimeCheck = Get-Date
$endDateTimeCheck = $startDateTimeCheck.AddMinutes([decimal]$timeoutInMinutes + 1)

# If The Replicated Folder Is Using NTFRS
If ($replFolderOptionChosen.Type -match "NTFRS") {
	# For Each Member In The List/Table With Members To Process '$ntfrsReplFolderConfigAndState' Perform A Number Of Steps
	$memberListHTML = @()
	$ntfrsReplFolderConfigAndState | ForEach-Object {
		$replMember = $_
		$memberInstanceFQDN = $replMember."Member FQDN".ToUpper()

		# Determine The Full UNC Path Of The Canary File For The Member
		$replFolderPath = $replMember."Repl Folder Path"
		If ($($ntfrsReplFolderOptionChosen.'Repl Set Name') -eq "Domain System Volume (SYSVOL share)") {
			$uncPathFolder = "\\" + $($memberInstanceFQDN.Replace(" [SOURCE MEMBER]","")) + "\" + $($replFolderPath.Replace(":","$")) + "\Scripts"
		} Else {
			$uncPathFolder = "\\" + $($memberInstanceFQDN.Replace(" [SOURCE MEMBER]","")) + "\" + $($replFolderPath.Replace(":","$"))
		}
		$uncPathCanaryFile = $uncPathFolder + "\" + $tempCanaryFileName + ".txt"

		$memberNr = ($memberListHTML | Measure-Object).Count + 1
		$rowType = If (($memberNr % 2 -eq 0) -eq $true) {"evenRow"} Else {"oddRow"}

		# Only For The Replication Member Used As The Source Member
		If ($memberInstanceFQDN -match $sourceMemberFQDN) {
			$memberListHTML += "<TR class=`"$rowType`"><TD>$memberNr</TD><TD>$sourceMemberFQDN</TD><TD>TRUE</TD><TD>SMB (445)</TD><TD data-val=`"OK`">TRUE</TD><TD data-val=`"OK`">NOW DOES EXIST</TD></TR>"
		}
		
		# For The Other Replication Members, Connect To The Member Through SMB (TCP:445)
	   If ($memberInstanceFQDN -notmatch $sourceMemberFQDN) {
			If ($replMember.ReachableSMB -eq $true) {
				$memberListHTML += "<TR class=`"$rowType`"><TD>$memberNr</TD><TD>$memberInstanceFQDN</TD><TD>FALSE</TD><TD>SMB (445)</TD><TD data-val=`"OK`">TRUE</TD><TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD></TR>"
			}
			If ($replMember.ReachableSMB -eq $false) {
				$memberListHTML += "<TR class=`"$rowType`"><TD>$memberNr</TD><TD>$memberInstanceFQDN</TD><TD>FALSE</TD><TD>SMB (445)</TD><TD data-val=`"NOK`">FALSE</TD><TD data-val=`"NOK`">UNABLE TO CHECK</TD></TR>"
			}
		}

		$runspaceIteration = [PowerShell]::Create()
		[void]$($runspaceIteration.AddScript($scriptblock))
		[void]$($runspaceIteration.AddArgument($memberInstanceFQDN))
		[void]$($runspaceIteration.AddArgument($replMember."Member IPv4"))
		[void]$($runspaceIteration.AddArgument($replMember."Site Name"))
		[void]$($runspaceIteration.AddArgument($replMember."ReachableSMB"))
		[void]$($runspaceIteration.AddArgument($replMember."Type"))
		[void]$($runspaceIteration.AddArgument($uncPathCanaryFile))
		[void]$($runspaceIteration.AddArgument($sourceMemberFQDN))
		[void]$($runspaceIteration.AddArgument($startDateTime))
		[void]$($runspaceIteration.AddArgument($timeoutInMinutes))
		[void]$($runspaceIteration.AddArgument($delayInMilliSecondsBetweenChecks))

		# Assign The Runspace To The Runspace Pool
		$runspaceIteration.RunspacePool = $runspacePool

		# Add The Runspace To The Runspaces Collection, And Start The Runspace
		$runspacesCollection += [PSCustomObject]@{ Pipe = $runspaceIteration; Status = $runspaceIteration.BeginInvoke() }
	}
	
	# Write The Data To The HTML File Which Will Refresh Automatically In The Browser
	$htmlContent2 = $htmlContent1.Replace("<!-- REPLACEME_MEMBERLIST -->", $memberListHTML)
	$htmlContent2 = $htmlContent2.Replace("</TR> <TR","</TR>`n<TR")
	$htmlContent2 | Out-File $htmlFullPath -Force

	# Get The Data From The Runspaces That Were Created
	$nrTotalMembersFileDetected = 0
	$nrTotalMembersTimedOut = 0
	While ($runspacesCollection.Status -ne $null) {
		$nrTotalMembersFileNotDetectedYet = 0
		$completedRunspaces = @()
		$runspacesCollection | ForEach-Object {
			$runSpace = $_
			If ($runSpace.Status) {
				$runSpaceStatus = $runSpace.Status
				If ($runSpaceStatus.IsCompleted -eq $true) {
					$completedRunspaces += $runSpace
				}
				If ($runSpaceStatus.IsCompleted -eq $false) {
					$nrTotalMembersFileNotDetectedYet++
				}
			}
		}

		ForEach ($completedRunspaceIteration in $completedRunspaces) {
			# When Desired, Process Data HERE As Soon As It Becomes Available From Any Runspace
			$runspaceResult = $completedRunspaceIteration.Pipe.EndInvoke($completedRunspaceIteration.Status)
			$memberInstanceFQDN = $runspaceResult.replMemberFQDN.ToUpper()

			If ($($runspaceResult.checkResult) -eq "CHECK_OK") {
				$nrTotalMembersFileDetected++
				If ($memberInstanceFQDN -eq $sourceMemberFQDN) {
					$memberListHTML[$($memberListHTML.IndexOf($($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN})))] = ($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN}).Replace("<TD data-val=`"OK`">NOW DOES EXIST</TD>","<TD data-val=`"OK`">NOW DOES EXIST</TD>")
				} Else {
					$memberListHTML[$($memberListHTML.IndexOf($($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN})))] = ($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN}).Replace("<TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD>","<TD data-val=`"OK`">NOW DOES EXIST</TD>")
				}
			} ElseIf ($($runspaceResult.checkResult) -eq "TIMEOUT") {
				$nrTotalMembersTimedOut++
				$memberListHTML[$($memberListHTML.IndexOf($($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN})))] = ($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN}).Replace("<TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD>","<TD data-val=`"NOK`">UNABLE TO CHECK (TIMEOUT)</TD>")
			} ElseIf ($($runspaceResult.checkResult) -eq "ACCESS_DENIED") {
				$nrTotalMembersUnreachable++
				$memberListHTML[$($memberListHTML.IndexOf($($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN})))] = ($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN}).Replace("<TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD>","<TD data-val=`"NOK`">UNABLE TO CHECK (ACCESS DENIED)</TD>")
			} ElseIf ($($runspaceResult.checkResult) -eq "NOT_REACHABLE_OVER_SMB") {
				$memberListHTML[$($memberListHTML.IndexOf($($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN})))] = ($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN}).Replace("<TD data-val=`"NOK`">UNABLE TO CHECK</TD>","<TD data-val=`"NOK`">UNABLE TO CHECK (UNREACHABLE)</TD>")
			} Else { # "UNKNOWN_ERROR"
				$nrTotalMembersUnreachable++
				$memberListHTML[$($memberListHTML.IndexOf($($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN})))] = ($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN}).Replace("<TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD>","<TD data-val=`"NOK`">UNABLE TO CHECK (UNKNOWN)</TD>")
			}

			$runspacesResults += $runspaceResult
			$completedRunspaceIteration.Status = $null
			$completedRunspaceIteration.Pipe.Dispose()
		}

		writeLog -dataToLog "  # Members Supporting Folder: $nrTotalMembersSupportingFolder >> # Members Unreachable: $nrTotalMembersUnreachable | # Members File Detected: $nrTotalMembersFileDetected | # Members File Not Detected Yet: $nrTotalMembersFileNotDetectedYet | # Members Timed Out: $nrTotalMembersTimedOut | Approx $([decimal]$("{0:n2}" -f ($endDateTimeCheck - $(Get-Date)).TotalMinutes)) Minutes Remaining Before Timeout" -logFileOnly $false -noDateTimeInLogLine $false
		
		# Write The Data To The HTML File Which Will Refresh Automatically In The Browser
		$htmlContent2 = $htmlContent1.Replace("<!-- REPLACEME_MEMBERLIST -->", $memberListHTML)
		$htmlContent2 = $htmlContent2.Replace("</TR> <TR","</TR>`n<TR")
		$htmlContent2 | Out-File $htmlFullPath -Force

		Start-Sleep -s 1
	}
}

# If The Replicated Folder Is Using DFSR
If ($replFolderOptionChosen.Type -match "DFSR") {
	# For Each Member In The List/Table With Members To Process '$dfsrReplFolderConfigAndState' Perform A Number Of Steps
	$memberListHTML = @()
	$dfsrReplFolderConfigAndState | ForEach-Object {
		$replMember = $_
		$memberInstanceFQDN = $replMember."Member FQDN".ToUpper()

		# Determine The Full UNC Path Of The Canary File For The Member
		$replFolderPath = $replMember."Repl Folder Path"
		If ($($dfsrReplFolderOptionChosen.'Repl Folder Name') -eq "SYSVOL Share") {
			$uncPathFolder = "\\" + $($memberInstanceFQDN.Replace(" [SOURCE MEMBER]","")) + "\" + $($replFolderPath.Replace(":","$")) + "\Scripts"
		} Else {
			$uncPathFolder = "\\" + $($memberInstanceFQDN.Replace(" [SOURCE MEMBER]","")) + "\" + $($replFolderPath.Replace(":","$"))
		}
		$uncPathCanaryFile = $uncPathFolder + "\" + $tempCanaryFileName + ".txt"

		$memberNr = ($memberListHTML | Measure-Object).Count + 1
		$rowType = If (($memberNr % 2 -eq 0) -eq $true) {"evenRow"} Else {"oddRow"}

		# Only For The Replication Member Used As The Source Member
		If ($memberInstanceFQDN -match $sourceMemberFQDN) {
			$memberListHTML += "<TR class=`"$rowType`"><TD>$memberNr</TD><TD>$sourceMemberFQDN</TD><TD>TRUE</TD><TD>SMB (445)</TD><TD data-val=`"OK`">TRUE</TD><TD data-val=`"OK`">NOW DOES EXIST</TD></TR>"
		}
		
		# For The Other Replication Members, Connect To The Member Through SMB (TCP:445)
	   If ($memberInstanceFQDN -notmatch $sourceMemberFQDN) {
			If ($replMember.ReachableSMB -eq $true) {
				$memberListHTML += "<TR class=`"$rowType`"><TD>$memberNr</TD><TD>$memberInstanceFQDN</TD><TD>FALSE</TD><TD>SMB (445)</TD><TD data-val=`"OK`">TRUE</TD><TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD></TR>"
			}
			If ($replMember.ReachableSMB -eq $false) {
				$memberListHTML += "<TR class=`"$rowType`"><TD>$memberNr</TD><TD>$memberInstanceFQDN</TD><TD>FALSE</TD><TD>SMB (445)</TD><TD data-val=`"NOK`">FALSE</TD><TD data-val=`"NOK`">UNABLE TO CHECK</TD></TR>"
			}
		}

		$runspaceIteration = [PowerShell]::Create()
		[void]$($runspaceIteration.AddScript($scriptblock))
		[void]$($runspaceIteration.AddArgument($memberInstanceFQDN))
		[void]$($runspaceIteration.AddArgument($replMember."Member IPv4"))
		[void]$($runspaceIteration.AddArgument($replMember."Site Name"))
		[void]$($runspaceIteration.AddArgument($replMember."ReachableSMB"))
		[void]$($runspaceIteration.AddArgument($replMember."Type"))
		[void]$($runspaceIteration.AddArgument($uncPathCanaryFile))
		[void]$($runspaceIteration.AddArgument($sourceMemberFQDN))
		[void]$($runspaceIteration.AddArgument($startDateTime))
		[void]$($runspaceIteration.AddArgument($timeoutInMinutes))
		[void]$($runspaceIteration.AddArgument($delayInMilliSecondsBetweenChecks))

		# Assign The Runspace To The Runspace Pool
		$runspaceIteration.RunspacePool = $runspacePool

		# Add The Runspace To The Runspaces Collection, And Start The Runspace
		$runspacesCollection += [PSCustomObject]@{ Pipe = $runspaceIteration; Status = $runspaceIteration.BeginInvoke() }
	}
	
	# Write The Data To The HTML File Which Will Refresh Automatically In The Browser
	$htmlContent2 = $htmlContent1.Replace("<!-- REPLACEME_MEMBERLIST -->", $memberListHTML)
	$htmlContent2 = $htmlContent2.Replace("</TR> <TR","</TR>`n<TR")
	$htmlContent2 | Out-File $htmlFullPath -Force

	# Get The Data From The Runspaces That Were Created
	$nrTotalMembersFileDetected = 0
	$nrTotalMembersTimedOut = 0
	While ($runspacesCollection.Status -ne $null) {
		$nrTotalMembersFileNotDetectedYet = 0
		$completedRunspaces = @()
		$runspacesCollection | ForEach-Object {
			$runSpace = $_
			If ($runSpace.Status) {
				$runSpaceStatus = $runSpace.Status
				If ($runSpaceStatus.IsCompleted -eq $true) {
					$completedRunspaces += $runSpace
				}
				If ($runSpaceStatus.IsCompleted -eq $false) {
					$nrTotalMembersFileNotDetectedYet++
				}
			}
		}

		ForEach ($completedRunspaceIteration in $completedRunspaces) {
			# When Desired, Process Data HERE As Soon As It Becomes Available From Any Runspace
			$runspaceResult = $completedRunspaceIteration.Pipe.EndInvoke($completedRunspaceIteration.Status)
			$memberInstanceFQDN = $runspaceResult.replMemberFQDN.ToUpper()

			#$host.UI.RawUI.CursorPosition = $positionHT[$($runspaceResult.replMemberFQDN)]
			If ($($runspaceResult.checkResult) -eq "CHECK_OK") {
				$nrTotalMembersFileDetected++
				If ($memberInstanceFQDN -eq $sourceMemberFQDN) {
					$memberListHTML[$($memberListHTML.IndexOf($($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN})))] = ($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN}).Replace("<TD data-val=`"OK`">NOW DOES EXIST</TD>","<TD data-val=`"OK`">NOW DOES EXIST</TD>")
				} Else {
					$memberListHTML[$($memberListHTML.IndexOf($($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN})))] = ($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN}).Replace("<TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD>","<TD data-val=`"OK`">NOW DOES EXIST</TD>")
				}
			} ElseIf ($($runspaceResult.checkResult) -eq "TIMEOUT") {
				$nrTotalMembersTimedOut++
				$memberListHTML[$($memberListHTML.IndexOf($($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN})))] = ($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN}).Replace("<TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD>","<TD data-val=`"NOK`">UNABLE TO CHECK (TIMEOUT)</TD>")
			} ElseIf ($($runspaceResult.checkResult) -eq "ACCESS_DENIED") {
				$nrTotalMembersUnreachable++
				$memberListHTML[$($memberListHTML.IndexOf($($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN})))] = ($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN}).Replace("<TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD>","<TD data-val=`"NOK`">UNABLE TO CHECK (ACCESS DENIED)</TD>")
			} ElseIf ($($runspaceResult.checkResult) -eq "NOT_REACHABLE_OVER_SMB") {
				$memberListHTML[$($memberListHTML.IndexOf($($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN})))] = ($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN}).Replace("<TD data-val=`"NOK`">UNABLE TO CHECK</TD>","<TD data-val=`"NOK`">UNABLE TO CHECK (UNREACHABLE)</TD>")
			} Else { # "UNKNOWN_ERROR"
				$nrTotalMembersUnreachable++
				$memberListHTML[$($memberListHTML.IndexOf($($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN})))] = ($memberListHTML | Where-Object {$_ -match $memberInstanceFQDN}).Replace("<TD data-val=`"NOTSET`">NOT CHECKED/FOUND YET</TD>","<TD data-val=`"NOK`">UNABLE TO CHECK (UNKNOWN)</TD>")
			}

			$runspacesResults += $runspaceResult
			$completedRunspaceIteration.Status = $null
			$completedRunspaceIteration.Pipe.Dispose()
		}

		writeLog -dataToLog "  # Members Supporting Folder: $nrTotalMembersSupportingFolder >> # Members Unreachable: $nrTotalMembersUnreachable | # Members File Detected: $nrTotalMembersFileDetected | # Members File Not Detected Yet: $nrTotalMembersFileNotDetectedYet | # Members Timed Out: $nrTotalMembersTimedOut | Approx $([decimal]$("{0:n2}" -f ($endDateTimeCheck - $(Get-Date)).TotalMinutes)) Minutes Remaining Before Timeout" -logFileOnly $false -noDateTimeInLogLine $false
		
		# Write The Data To The HTML File Which Will Refresh Automatically In The Browser
		$htmlContent2 = $htmlContent1.Replace("<!-- REPLACEME_MEMBERLIST -->", $memberListHTML)
		$htmlContent2 = $htmlContent2.Replace("</TR> <TR","</TR>`n<TR")
		$htmlContent2 | Out-File $htmlFullPath -Force

		Start-Sleep -s 1
	}
}

# Close The Runspace And Clean It Up
$runspacePool.Close() 
$runspacePool.Dispose()

###
# Create The Results Table Containing The Information Of Each Replica Member And How Long It Took To Reach That Replica Member After The Creation On The Source Replica Member
###
$resultsTableOfProcessedMembers = @()
$runspacesResults | ForEach-Object {
	$resultsTableOfProcessedMemberEntry = New-Object -TypeName System.Object
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member FQDN" -Value $($_.replMemberFQDN)
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Member IPv4" -Value $($_.replMemberIPv4)
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Site Name" -Value $($_.replMemberSite)
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "ReachableSMB" -Value $($_.reachableSMB)
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value $($_.replMemberType)
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Source" -Value $($_.canaryFileSource)
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "When Discvrd" -Value $($_.fileWhenDiscvrd)
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Delta Discvrd" -Value $($_.deltaDiscvrd)
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "Start Iteration" -Value $($_.startDateTimeIteration)
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "End Iteration" -Value $($_.endDateTimeIteration)
	$resultsTableOfProcessedMemberEntry | Add-Member -MemberType NoteProperty -Name "UNC Path Canary File" -Value $($_.uncPathCanaryFile)
	$resultsTableOfProcessedMembers += $resultsTableOfProcessedMemberEntry
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
# Output The Results Table Containing The Information Of Each Replica Member And How Long It Took To Reach That Replica Member After The Creation On The Source Replica Member
###
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "`n$($resultsTableOfProcessedMembers | Sort-Object -Property ReachableSMB,'Delta Discvrd' | Format-Table -Property * -Wrap -AutoSize | Out-String)" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "Log File Full Path....................: $scriptLogFullPath"
writeLog -dataToLog ""
writeLog -dataToLog "HTML File Full Path...................: $htmlFullPath"
writeLog -dataToLog ""
If ($exportResultsToCSV) {
	$resultsTableOfProcessedMembers | Sort-Object -Property ReachableSMB,'Delta Discvrd' | Export-Csv -Path $replResultsExportCsvFullPath -Delimiter ";" -NoTypeInformation
	writeLog -dataToLog "Repl Results Export CSV Full Path.....: $replResultsExportCsvFullPath" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false	
}

If (-not $skipCheckForOrphanedCanaryFiles) {
	###
	# Checking If There Are Temporary Canary Files Left Over From Previous Executions Of The Script
	###
	writeLog -dataToLog "" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	writeLog -dataToLog "-----------------------------------------------------------------------------------------------------------------------------------------------" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	# If The Replicated Folder Is Using NTFRS
	If ($replFolderOptionChosen.Type -match "NTFRS") {
		writeLog -dataToLog "+++ TEMPORARY CANARY FILES FROM PREVIOUS EXECUTIONS EXIST IN THE REPLICATED FOLDER '$($ntfrsReplFolderOptionChosen.'Repl Set Name')' +++" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
	}
	# If The Replicated Folder Is Using DFSR
	If ($replFolderOptionChosen.Type -match "DFSR") {
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
		writeLog -dataToLog "REMARK: Specify A NUMBER Or Press [ENTER] For The Default Option" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "ACTION" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -logFileOnly $false -noDateTimeInLogLine $false
		If (-not $cleanupOrhanedCanaryFiles) {
			Do {
				$tempCanaryFileConfirmationNumericSelection = Read-Host "Cleanup Temp Canary Files Previous Executions?...."
			} Until (([int]$tempCanaryFileConfirmationNumericSelection -gt 0 -And [int]$tempCanaryFileConfirmationNumericSelection -le ($tempCanaryFileConfirmationOptions | Measure-Object).Count) -Or $([string]::IsNullOrEmpty($tempCanaryFileConfirmationNumericSelection)))
			If ([string]::IsNullOrEmpty($tempCanaryFileConfirmationNumericSelection)) {
				$tempCanaryFileConfirmationNumericSelection = $defaultTempCanaryFileConfirmationSpecificNumericOption
			}
		} Else {
			$tempCanaryFileConfirmationNumericSelection = $tempCanaryFileConfirmationOptions.ToUpper().IndexOf("YES".ToUpper()) + 1
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
		writeLog -dataToLog "NO Temporary Canary Files From Previous Executions Of The Script Were Found" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
		writeLog -dataToLog "" -lineType "SUCCESS" -logFileOnly $false -noDateTimeInLogLine $false
	}
}