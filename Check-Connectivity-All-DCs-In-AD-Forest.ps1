###
# Parameters Used By Script
###
# N.A.

###
# Version Of Script
###
$version = "v0.1, 2025-02-20"

<#
	AUTHOR
		Written By....................: Jorge de Almeida Pinto [Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:]
		Re-Written By.................: N.A.
		Company.......................: IAMTEC >> Identity | Security | Recovery [https://www.iamtec.eu/]
		Blog..........................: Jorge's Quest For Knowledge [http://jorgequestforknowledge.wordpress.com/]
		For Feedback/Questions........: scripts.gallery@iamtec.eu
			--> Please Describe Your Scenario As Best As Possible With As Much Detail As Possible.
			--> If Applicable Describe What Does and/Or Does Not Work.
			--> If Applicable Describe What Should Be/Work Different And Explain Why/How.
			--> Please Add Screendumps.

	ORIGINAL SOURCES
		- https://github.com/zjorz/Public-AD-Scripts/blob/master/Check-Connectivity-All-DCs-In-AD-Forest.md
		- https://github.com/zjorz/Public-AD-Scripts/blob/master/Check-Connectivity-All-DCs-In-AD-Forest.ps1

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
		- Target AD Forest by FQDN
		- Target AD Domain by FQDN
		- Target Specific DCs by FQDN
		- Check only GC ports when DC is GC
		- Check only DNS port when DC is DNS server

	KNOWN ISSUES/BUGS
		- N.A.

	RELEASE NOTES
		v0.1, 2025-02-20, Jorge de Almeida Pinto [MVP Identity And Access - Security / Lead Identity/Security Architect]:
			- Initial version of the script
#>

<#
.SYNOPSIS
	This PoSH Script Test Connectivity To Targeted DCs For Specified (TCP) Ports

.DESCRIPTION
	This PoSH script provides the following functions:
	- Create a list of DCs to target
	- Check connectivity for specified TCP ports for targeted DCs

.EXAMPLE
	Execute The Script - On-Demand

	.\Check-Connectivity-All-DCs-In-AD-Forest.ps1

.NOTES
	- N.A.
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
				[Void]$([System.Net.Dns]::GetHostEntry($serverIPOrFQDN))
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
			
			[Void]$($tcpPortSocket.EndConnect($portConnect))
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

###
# Clear The Screen
###
Clear-Host

###
# Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
###
$randomNr = Get-Random -Minimum 1000 -Maximum 9999
$windowTitle = "+++ CHECK CONNECTIVITY TARGETED DCS +++ ($randomNr)"
$uiConfig = (Get-Host).UI.RawUI
$host.UI.RawUI.WindowTitle = $windowTitle
Start-Sleep -s 1
$poshProcess = Get-Process | Where-Object { $_.MainWindowTitle -eq $windowTitle }
$poshProcessName = $poshProcess.ProcessName
$poshProcessId = $poshProcess.Id
If ($poshProcessName -eq "WindowsTerminal") {
	Get-Process -Id $poshProcessId | Set-Window -X 100 -Y 100 -Width 1800 -Height 800 # -Passthru
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
	If ($uiConfigScreenSizeMaxWidth -lt 200) {
		$uiConfigScreenSize.Width = $uiConfigScreenSizeMaxWidth
	} Else {
		$uiConfigScreenSize.Width = 200
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
$scriptFullPath = $MyInvocation.MyCommand.Definition
$currentScriptFolderPath = $null
If ($scriptFullPath -match "^.*\:\\") {
	$currentScriptFolderPath = Split-Path $scriptFullPath
} Else {
	$currentScriptFolderPath = (Get-Location).Path
}
$timeOut = 500
$execDateTime = Get-Date
$execDateTimeForLog = Get-Date $execDateTime -Format "yyyy-MM-dd HH:mm:ss"
$execDateTimeForFileName = Get-Date $execDateTime -Format "yyyy-MM-dd_HH.mm.ss"
$thisADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$adForestFQDN = $thisADForest.Name
$adForestNCDN = "DC=" + $adForestFQDN.Replace(".",",DC=")
$adForestRWDCFQDN = $thisADForest.NamingRoleOwner.Name
$logFilePath = Join-Path $currentScriptFolderPath $($execDateTimeForFileName + "_" + $adForestFQDN + "_" + "Check-Connectivity-All-DCs-In-AD-Forest.log")
$localComputerName = (Get-CimInstance -class Win32_ComputerSystem).Name
$localComputerDomain = (Get-CimInstance -class Win32_ComputerSystem).Domain
$localComputerFQDN = $localComputerName + "." + $localComputerDomain
# SOURCE: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements
# SOURCE: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts
# SOURCE: https://lazyadmin.nl/it/domain-controller-ports/
$portsToCheck = @()
$portsToCheck += 53   # TCP:DNS - Reliable Result ONLY When DNS Is Installed Is On The DC (AD Integrated DNS)
$portsToCheck += 88   # TCP:Kerberos
$portsToCheck += 135  # TCP:RPC Endpoint Mapper
$portsToCheck += 389  # TCP:LDAP
$portsToCheck += 445  # TCP:SMB
$portsToCheck += 464  # TCP:Kerberos Password Change
$portsToCheck += 636  # TCP:LDAP (Over SSL)
$portsToCheck += 3268 # TCP:GC - Reliable Result ONLY When DC Is A GC
$portsToCheck += 3269 # TCP:GC (Over SSL) - Reliable Result ONLY When DC Is A GC
$portsToCheck += 5985 # TCP:WinRM/RemotePowerShell
$portsToCheck += 5986 # TCP:WinRM/RemotePowerShell (Over SSL)
$portsToCheck += 9389 # TCP:Active Directory Web Services (ADWS)

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
writeLog -dataToLog "                                          **********************************************************" -lineType "MAINHEADER"
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER"
writeLog -dataToLog "                                          *        --> Check Connectivity Targeted DCs <--         *" -lineType "MAINHEADER"
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *      Written By: Jorge de Almeida Pinto [MVP-EMS]      *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *            BLOG: Jorge's Quest For Knowledge           *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *   (URL: http://jorgequestforknowledge.wordpress.com/)  *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                    $version                    *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          *                                                        *" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog "                                          **********************************************************" -lineType "MAINHEADER" -logFileOnly $false -noDateTimeInLogLine $false
writeLog -dataToLog ""

writeLog -dataToLog "" -lineType ""
writeLog -dataToLog "Date/Time..................: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -lineType ""
writeLog -dataToLog "" -lineType ""
writeLog -dataToLog "TimeOut....................: $timeOut" -lineType ""
writeLog -dataToLog "" -lineType ""
writeLog -dataToLog "Local Computer FQDN........: $localComputerFQDN" -lineType ""
Try {
	$localComputerIPAddress = ([System.Net.Dns]::GetHostEntry($localComputerFQDN)).AddressList.IPAddressToString
} Catch {
	$localComputerIPAddress = "ERROR"
}
writeLog -dataToLog "Local Computer IP Address..: $($localComputerIPAddress -join ', ')" -lineType ""
writeLog -dataToLog "" -lineType ""
writeLog -dataToLog "Ports To Check.............:" -lineType ""
$portsToCheck | ForEach-Object {
	writeLog -dataToLog "              .............: $($_.ToString())" -lineType ""
}
writeLog -dataToLog "" -lineType ""
writeLog -dataToLog "AD Forest FQDN.............: $adForestFQDN" -lineType ""
writeLog -dataToLog "Root AD Domain NC DN.......: $adForestNCDN" -lineType ""
writeLog -dataToLog "RWDC FQDN..................: $adForestRWDCFQDN" -lineType ""
writeLog -dataToLog "" -lineType ""
writeLog -dataToLog "Log File Path..............: $logFilePath" -lineType ""
writeLog -dataToLog "" -lineType ""

$dsDirSearcherDCs = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$dsDirSearcherDCs.SearchRoot = "LDAP://$adForestRWDCFQDN/CN=Sites,CN=Configuration,$adForestNCDN"
$dsDirSearcherDCs.SearchScope = "Subtree"
$dsDirSearcherDCs.Filter = "(objectClass=nTDSDSA)"
[void]($dsDirSearcherDCs.PropertiesToLoad.Add("distinguishedName"))
[void]($dsDirSearcherDCs.PropertiesToLoad.Add("msDS-isGC"))
$allNTDSDsaInADForest = ($dsDirSearcherDCs.FindAll()).Properties.distinguishedname
$allSrvObjsInADForest = $allNTDSDsaInADForest.Replace("CN=NTDS Settings,","")
$numDCs = ($allSrvObjsInADForest | Measure-Object).Count
$resultsDCList = @()
$i = 0
$allSrvObjsInADForest | ForEach-Object {
	$i++
	$srvObject = [ADSI]"LDAP://$adForestRWDCFQDN/$($_)"
	$dnsHostName = $srvObject.Properties.dNSHostName[0]
	Try {
		$ipAddress = ([System.Net.Dns]::GetHostEntry($dnsHostName)).AddressList.IPAddressToString
	} Catch {
		$ipAddress = "ERROR"
	}
	writeLog -dataToLog "Testing DC '$dnsHostName' (IP Address: $ipAddress) ($($i.ToString().PadLeft($($numDCs.ToString().Length),'0')) Of $numDCs)..." -lineType ""
	$dcResult = New-Object -TypeName System.Object
	$dcResult | Add-Member -MemberType NoteProperty -Name "Nr" -Value $($i.ToString().PadLeft($($numDCs.ToString().Length),'0'))
	$dcResult | Add-Member -MemberType NoteProperty -Name "Host Name" -Value $dnsHostName
	$dcResult | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $ipAddress
	$portsToCheck | ForEach-Object {
		$testResult = $null
		$testResult = portConnectionCheck -serverIPOrFQDN $dnsHostName -port $($_) -timeout $timeOut
		If ($testResult -eq "SUCCESS") {
			writeLog -dataToLog " > Port '$($_)' - $testResult..." -lineType "SUCCESS"
		} Else {
			writeLog -dataToLog " > Port '$($_)' - $testResult..." -lineType "ERROR"
		}
		$dcResult | Add-Member -MemberType NoteProperty -Name "Port$($_)" -Value $testResult
	}
	$resultsDCList += $dcResult
	writeLog -dataToLog "" -lineType ""
}
writeLog -dataToLog "$($resultsDCList | Format-Table * -Wrap -AutoSize | Out-String)" -lineType ""

writeLog -dataToLog "" -lineType ""
writeLog -dataToLog "Log File Path..............: $logFilePath" -lineType ""
writeLog -dataToLog "" -lineType ""