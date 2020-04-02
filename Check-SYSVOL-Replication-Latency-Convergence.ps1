# Abstract: This PoSH Script Checks The SYSVOL Replication Latency/Convergence
# Written By: Jorge de Almeida Pinto [MVP-DS]
# Blog: http://jorgequestforknowledge.wordpress.com/
#
# 2013-03-02: (v0.1): Initial version of the script
# 2014-02-01: (v0.2): Updated to also work on W2K3, added STOP option, added few extra columns to output extra info of DCs, better detection of unavailable DCs, and screen adjustment section added
# 2014-02-09: (v0.3): Solved a bug with regards to the detection/location of RWDCs and RODCs
# 2014-02-11: (v0.4): Added additional logic to determine if a DC is either an RWDC or RODC when it fails using the first logic and changed the layout a little bit
#
# REQUIRES: PowerShell v2.0 or higher
# REQUIRES: At least 2 RWDCs
# SUPPORTS: W2K3(R2), W2K8(R2), W2K12(R2) DCs and most likely higher
# SUPPORTS: NTFRS or DFS-R Replication for the SYSVOL
#
# -----> !!! DISCLAIMER/REMARKS !!! <------
# * The script is freeware, you are free to distribute it, but always refer to this website (http://jorgequestforknowledge.wordpress.com/) as the location where you got it 
# * This script is furnished "AS IS". No warranty is expressed or implied! 
# * Always test first in lab environment to see if it meets your needs! 
# * Use this script at your own risk! 
# * I do not warrant this script to be fit for any purpose, use or environment 
# * I have tried to check everything that needed to be checked, but I do not guarantee the script does not have bugs. 
# * I do not guarantee the script will not damage or destroy your system(s), environment or whatever. 
# * I do not accept any liability in any way if you screw up, use the script wrong or in any other way where damage is caused to your environment/systems! 
# * If you do not accept these terms do not use the script and delete it immediately! 
# -----> !!! DISCLAIMER/REMARKS !!! <------

# Clear The Screen
Clear-Host

# Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ CHECKING SYSVOL REPLICATION LATENCY/CONVERGENCE +++"
$uiConfig.ForegroundColor = "Yellow"
$uiConfigBufferSize = $uiConfig.BufferSize
$uiConfigBufferSize.Width = 150
$uiConfigBufferSize.Height = 9999
$uiConfigScreenSizeMax = $uiConfig.MaxPhysicalWindowSize
$uiConfigScreenSizeMaxWidth = $uiConfigScreenSizeMax.Width
$uiConfigScreenSizeMaxHeight = $uiConfigScreenSizeMax.Height
$uiConfigScreenSize = $uiConfig.WindowSize
If ($uiConfigScreenSizeMaxWidth -lt 150) {
	$uiConfigScreenSize.Width = $uiConfigScreenSizeMaxWidth
} Else {
	$uiConfigScreenSize.Width = 150
}
If ($uiConfigScreenSizeMaxHeight -lt 75) {
	$uiConfigScreenSize.Height = $uiConfigScreenSizeMaxHeight - 5
} Else {
	$uiConfigScreenSize.Height = 75
}
$uiConfig.BufferSize = $uiConfigBufferSize
$uiConfig.WindowSize = $uiConfigScreenSize

# Start...
Write-Host "                                              *******************************************************" -ForeGroundColor Magenta
Write-Host "                                              *                                                     *" -ForeGroundColor Magenta
Write-Host "                                              * --> Test SYSVOL Replication Latency/Convergence <-- *" -ForeGroundColor Magenta
Write-Host "                                              *                                                     *" -ForeGroundColor Magenta
Write-Host "                                              *     Written By: Jorge de Almeida Pinto [MVP-DS]     *" -ForeGroundColor Magenta
Write-Host "                                              *    (http://jorgequestforknowledge.wordpress.com/)   *" -ForeGroundColor Magenta
Write-Host "                                              *                                                     *" -ForeGroundColor Magenta
Write-Host "                                              *******************************************************" -ForeGroundColor Magenta

##########
# Some Constants
$continue = $true
$cleanupTempObject = $true

##########
# The Function To Test The Port Connection
Function PortConnectionCheck($fqdnDC,$port,$timeOut) {
	$tcpPortSocket = $null
	$portConnect = $null
	$tcpPortWait = $null
	$tcpPortSocket = New-Object System.Net.Sockets.TcpClient
	$portConnect = $tcpPortSocket.BeginConnect($fqdnDC,$port,$null,$null)
	$tcpPortWait = $portConnect.AsyncWaitHandle.WaitOne($timeOut,$false)
	If(!$tcpPortWait) {
		$tcpPortSocket.Close()
		#Write-Host "Connection Timeout"
		Return "ERROR"
	} Else {
		#$error.Clear()
		$ErrorActionPreference = "SilentlyContinue"
		$tcpPortSocket.EndConnect($portConnect) | Out-Null
		If (!$?) {
			#Write-Host $error[0]
			Return "ERROR"
		} Else {
			Return "SUCCESS"
		}
		$tcpPortSocket.Close()
		$ErrorActionPreference = "Continue"
	}
}

##########
# Get The FQDN Of The Local AD Domain From The Server This Script Is Executed On
$ADDomainToWriteTo = $(Get-WmiObject -Class Win32_ComputerSystem).Domain

##########
# Get List Of Directory Servers In AD Forest
$ThisADForest = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$configNCDN = $ThisADForest.schema.Name.Substring(("CN=Schema,").Length)
$searchRootNTDSdsa = [ADSI]"LDAP://CN=Sites,$configNCDN"
$searcherNTDSdsaRW = New-Object System.DirectoryServices.DirectorySearcher($searchRootNTDSdsa)
$searcherNTDSdsaRO = New-Object System.DirectoryServices.DirectorySearcher($searchRootNTDSdsa)
$searcherNTDSdsaRW.Filter = "(objectCategory=NTDSDSA)"
$searcherNTDSdsaRO.Filter = "(objectCategory=NTDSDSARO)"
$objNTDSdsaRW = $searcherNTDSdsaRW.FindAll()
$objNTDSdsaRO = $searcherNTDSdsaRO.FindAll()
$TableOfRWDCsInADForest = @()
$objNTDSdsaRW | %{
	$ntdsDN = $_.Properties.distinguishedname
	$nbtRWDCName = $ntdsDN[0].Substring(("CN=NTDS Settings,CN=").Length)
	$nbtRWDCName = $nbtRWDCName.Substring(0,$nbtRWDCName.IndexOf(","))
	$nbtRWDCSite = $ntdsDN[0].Substring(("CN=NTDS Settings,CN=$nbtRWDCName,CN=Servers,CN=").Length)
	$nbtRWDCSite = $nbtRWDCSite.Substring(0,$nbtRWDCSite.IndexOf(","))
	$TableOfRWDCsInADForestObj = "" | Select "DS Name","Site Name"
	$TableOfRWDCsInADForestObj."DS Name" = $nbtRWDCName
	$TableOfRWDCsInADForestObj."Site Name" = $nbtRWDCSite
	$TableOfRWDCsInADForest += $TableOfRWDCsInADForestObj
}
$TableOfRODCsInADForest = @()
$objNTDSdsaRO | %{
	$ntdsDN = $_.Properties.distinguishedname
	$nbtRODCName = $ntdsDN[0].Substring(("CN=NTDS Settings,CN=").Length)
	$nbtRODCName = $nbtRODCName.Substring(0,$nbtRODCName.IndexOf(","))
	$nbtRODCSite = $ntdsDN[0].Substring(("CN=NTDS Settings,CN=$nbtRODCName,CN=Servers,CN=").Length)
	$nbtRODCSite = $nbtRODCSite.Substring(0,$nbtRODCSite.IndexOf(","))
	$TableOfRODCsInADForestObj = "" | Select "DS Name","Site Name"
	$TableOfRODCsInADForestObj."DS Name" = $nbtRODCName
	$TableOfRODCsInADForestObj."Site Name" = $nbtRODCSite
	$TableOfRODCsInADForest += $TableOfRODCsInADForestObj
}
$TableOfDCsInADForest = $TableOfRWDCsInADForest + $TableOfRODCsInADForest

##########
# Get List Of DCs In AD Domain, Create And Present In A Table
$contextADDomainToWriteTo = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$ADDomainToWriteTo)
$ListOfDCsInADDomain = [System.DirectoryServices.ActiveDirectory.DomainController]::findall($contextADDomainToWriteTo)
$ListOfRWDCsInADDomain = $ListOfDCsInADDomain | ?{$_.InboundConnections -ne $null -and !($_.InboundConnections -match "RODC Connection")}
$ListOfRODCsInADDomain = $ListOfDCsInADDomain | ?{$_.InboundConnections -match "RODC Connection"}
$TableOfDCsInADDomain = @()
Write-Host ""
Write-Host "----------------------------------------------------------------------------------------------------------------------------------------------------" -ForeGroundColor Cyan
Write-Host "LIST OF DCs IN THE AD DOMAIN '$ADDomainToWriteTo'..." -ForeGroundColor Cyan
ForEach ($DC in $ListOfDCsInADDomain) {
	$TableOfDCsInADDomainObj = "" | Select Name,PDC,"Site Name","DS Type","IP Address","OS Version"
	$TableOfDCsInADDomainObj.Name = $DC.Name
	$TableOfDCsInADDomainObj.PDC = "FALSE"
	If ($DC.Roles -ne $null -And $DC.Roles -Contains "PdcRole") {
		$TableOfDCsInADDomainObj.PDC = "TRUE"
		$pdcFQDN = $DC.Name
		$pdcSite = $DC.SiteName
	}
	If ( $DC.SiteName -ne $null -And  $DC.SiteName -ne "") {
		$TableOfDCsInADDomainObj."Site Name" = $DC.SiteName
	} Else {
		If (($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($DC.Name).Substring(0,$($DC.Name).IndexOf(".")))} | Measure-Object).Count -eq 1) {
			$TableOfDCsInADDomainObj."Site Name" = ($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($DC.Name).Substring(0,$($DC.Name).IndexOf(".")))})."Site Name"
		}
		If (($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($DC.Name).Substring(0,$($DC.Name).IndexOf(".")))} | Measure-Object).Count -eq 0) {
			$TableOfDCsInADDomainObj."Site Name" = "<Fail>"
		}
		If (($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($DC.Name).Substring(0,$($DC.Name).IndexOf(".")))} | Measure-Object).Count -gt 1) {
			$TableOfDCsInADDomainObj."Site Name" = "<Fail>"
		}
	}
	$DStype = $null
	If ($DStype -eq $null) {
		ForEach ($RWDC In $ListOfRWDCsInADDomain) {
			If ($RWDC.Name -like $DC.Name) {
				$DStype = "Read/Write"
				BREAK
			}
		}
	}
	If ($DStype -eq $null) {
		ForEach ($RODC In $ListOfRODCsInADDomain) {
			If ($RODC.Name -like $DC.Name) {
				$DStype = "Read-Only"
				BREAK
			}
		}
	}
	If ($DStype -eq $null) {
		$DStype = "<Unknown>"

		If (($TableOfRWDCsInADForest | ?{$_."DS Name" -eq $($($DC.Name).Substring(0,$($DC.Name).IndexOf(".")))} | Measure-Object).Count -eq 1) {
			$DStype = "Read/Write"
		}
		If (($TableOfRODCsInADForest | ?{$_."DS Name" -eq $($($DC.Name).Substring(0,$($DC.Name).IndexOf(".")))} | Measure-Object).Count -eq 1) {
			$DStype = "Read-Only"
		}
	}
	$TableOfDCsInADDomainObj."DS Type" = $DStype
	If ($DC.IPAddress -ne $null -And $DC.IPAddress -ne "") {
		$TableOfDCsInADDomainObj."IP Address" = $DC.IPAddress
	} Else {
		$TableOfDCsInADDomainObj."IP Address" = "<Fail>"
	}
	If ($DC.OSVersion -ne $null -And $DC.OSVersion -ne "") {
		$TableOfDCsInADDomainObj."OS Version" = $DC.OSVersion
	} Else {
		$TableOfDCsInADDomainObj."OS Version" = "<Fail>"
	}
	$TableOfDCsInADDomain += $TableOfDCsInADDomainObj
}
$TableOfDCsInADDomain | FT -AutoSize
Write-Host "  --> Found [$($ListOfDCsInADDomain.count)] DC(s) In AD Domain..." -ForeGroundColor Cyan
Write-Host ""

##########
# Specify A RWDC From The Selected AD Domain
Write-Host "----------------------------------------------------------------------------------------------------------------------------------------------------" -ForeGroundColor Cyan
Write-Host "Which RWDC In The AD Domain '$ADDomainToWriteTo' Should Be Used To Create The Object?" -ForeGroundColor Cyan
Write-Host ""
Write-Host "Available Options Are:" -ForeGroundColor Yellow
Write-Host "[*] Specify 'PDC' To Use The DC With The PDC FSMO Role" -ForeGroundColor Yellow
Write-Host "[*] Just Press Enter To Locate An RWDC" -ForeGroundColor Yellow
Write-Host "[*] Specify The FQDN Of A Specific RWDC" -ForeGroundColor Yellow
Write-Host "[*] Specify 'STOP' To End The Script" -ForeGroundColor Yellow
Write-Host ""
$SourceRWDCInADDomain = Read-Host "Please Choose An Option"

# If PDC Was Specified Find The RWDC With The PDC FSMO Role And Use That
If ($SourceRWDCInADDomain -eq "PDC") {
	$SourceRWDCInADDomainFQDN = $pdcFQDN
	$SourceRWDCInADDomainSITE = $pdcSite
}

# If Nothing Was Specified Automatically Locate An RWDC To Use
If ($SourceRWDCInADDomain -eq "") {
	# Locate Just ONE DC (This Could Be An RWDC Or RODC)
	$SourceRWDCInADDomainObjectONE = [System.DirectoryServices.ActiveDirectory.DomainController]::findone($contextADDomainToWriteTo)

	# Locate All RWDCs In The AD Domain
	$SourceRWDCInADDomainObjectALL = $ListOfRWDCsInADDomain
	$UseRWDC = $False
	
	# Check If The Single DC Found Is An RWDC Or Not By Checking If It Is In The List Of RWDCs
	ForEach ($RWDC In $SourceRWDCInADDomainObjectALL) {
		If ($RWDC.Name -like $SourceRWDCInADDomainObjectONE.Name) {
			$UseRWDC = $True
		}
	}
	
	# If The Single DC Found Is An RWDC, Then Use That One
	If ($UseRWDC -eq $True) {
		$SourceRWDCInADDomainFQDN = $SourceRWDCInADDomainObjectONE.Name
		$SourceRWDCInADDomainSITE = $SourceRWDCInADDomainObjectONE.SiteName
	}

	# If The Single DC Found Is An RODC, Then Find The RWDC With The PDC FSMO Role And Use That
	If ($UseRWDC -eq $False) {
		$SourceRWDCInADDomainFQDN = $pdcFQDN
		$SourceRWDCInADDomainSITE = $pdcSite
	}	

}

# If A Specific RWDC Was Specified Then Use That One
If ($SourceRWDCInADDomain -ne "" -And $SourceRWDCInADDomain -ne "PDC" -And $SourceRWDCInADDomain -ne "STOP") {
	$contextRWDCToWriteTo = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer",$SourceRWDCInADDomain)
	$SourceRWDCInADDomainObject = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($contextRWDCToWriteTo)
	$SourceRWDCInADDomainFQDN = $SourceRWDCInADDomainObject.Name
	$SourceRWDCInADDomainSITE = $SourceRWDCInADDomainObject.SiteName	
}

# If STOP Was Specified Then End The Script
If ($SourceRWDCInADDomain -eq "STOP") {
    Write-Host ""
    Write-Host "'STOP' Was Specified..." -ForeGroundColor Red
    Write-Host "Aborting Script..." -ForeGroundColor Red
    Write-Host ""
    EXIT	
}

# Check If The Selected DC Actually Exists In The AD Domain And Its Is An RWDC And NOT An RODC
$RWDCvalidity = $False
ForEach ($DC in $ListOfRWDCsInADDomain) {
	If ($DC.Name -like $SourceRWDCInADDomainFQDN) {
		$RWDCvalidity = $True
	}
}
Write-Host ""
Write-Host "Checking Existence And Connectivity Of The Specified RWDC '$SourceRWDCInADDomainFQDN' In The AD Domain '$ADDomainToWriteTo'..." -ForeGroundColor Yellow
If ($RWDCvalidity -eq $True) {
	Write-Host ""
	Write-Host "The Specified DC '$SourceRWDCInADDomainFQDN' Is An RWDC And It Exists In The AD Domain '$ADDomainToWriteTo'!" -ForeGroundColor Green
	Write-Host ""
	Write-Host "Continuing Script..." -ForeGroundColor Green
	$smbPort = "445"
	$timeOut = "500"
	$smbConnectionResult = $null
	$fqdnDC = $SourceRWDCInADDomainFQDN
	$smbConnectionResult = PortConnectionCheck $fqdnDC $smbPort $timeOut
	If ($smbConnectionResult -eq "SUCCESS") {
		Write-Host ""
		Write-Host "The Specified RWDC '$SourceRWDCInADDomainFQDN' Is Reachable!" -ForeGroundColor Green
		Write-Host ""
		Write-Host "Continuing Script..." -ForeGroundColor Green
		Write-Host ""
	}
	If ($smbConnectionResult -eq "ERROR") {
		Write-Host ""
		Write-Host "The Specified RWDC '$SourceRWDCInADDomainFQDN' Is NOT Reachable!" -ForeGroundColor Red
		Write-Host ""
		Write-Host "Please Re-Run The Script And Make Sure To Use An RWDC That Is Reachable!" -ForeGroundColor Red
		Write-Host ""
		Write-Host "Aborting Script..." -ForeGroundColor Red
		Write-Host ""
		Break
	}
}
If ($RWDCvalidity -eq $False) {
	Write-Host ""
	Write-Host "The Specified DC '$SourceRWDCInADDomainFQDN' Either Does NOT Exist In The AD Domain '$ADDomainToWriteTo' Or Is NOT And RWDC!" -ForeGroundColor Red
	Write-Host ""
	Write-Host "Please Re-Run The Script And Provide The FQDN Of An RWDC Within The AD Domain '$ADDomainToWriteTo' That Does Exist" -ForeGroundColor Red
	Write-Host ""
	Write-Host "Aborting Script..." -ForeGroundColor Red
	Write-Host ""
	Break
}

##########
# Determine SYSVOL Replication Mechanism And SYSVOL/NetLogon Location On Sourcing RWDC
Write-Host "----------------------------------------------------------------------------------------------------------------------------------------------------" -ForeGroundColor Cyan
Write-Host "SYSVOL REPLICATION MECHANISM..." -ForeGroundColor Cyan
Write-Host ""

# Get The Default Naming Contexr
$defaultNamingContext = (([ADSI]"LDAP://$SourceRWDCInADDomainFQDN/rootDSE").defaultNamingContext)

# Find The Computer Account Of The Sourcing RWDC
$Searcher = New-Object DirectoryServices.DirectorySearcher
$Searcher.Filter = "(&(objectClass=computer)(dNSHostName=$SourceRWDCInADDomainFQDN))"
$Searcher.SearchRoot = "LDAP://" + $SourceRWDCInADDomainFQDN + "/OU=Domain Controllers," + $defaultNamingContext
# The following appears NOT to work on W2K3, but it does upper-level OSes
# $dcObjectPath = $Searcher.FindAll().Path
# The following appears to work on all OSes
$dcObjectPath = $Searcher.FindAll() | %{$_.Path}

# Check If An NTFRS Subscriber Object Exists To Determine If NTFRS Is Being Used Instead Of DFS-R
$SearcherNTFRS = New-Object DirectoryServices.DirectorySearcher
$SearcherNTFRS.Filter = "(&(objectClass=nTFRSSubscriber)(name=Domain System Volume (SYSVOL share)))"
$SearcherNTFRS.SearchRoot = $dcObjectPath
$ntfrsSubscriptionObject = $SearcherNTFRS.FindAll()
If ($ntfrsSubscriptionObject -ne $null) {
    Write-Host "SYSVOL Replication Mechanism Being Used...: NTFRS"
    # Get The Local Root Path For The SYSVOL
	# The following appears NOT to work on W2K3, but it does upper-level OSes
    # $sysvolRootPathOnSourcingRWDC = $ntfrsSubscriptionObject.Properties.frsrootpath
    # The following appears to work on all OSes
    $sysvolRootPathOnSourcingRWDC = $ntfrsSubscriptionObject | %{$_.Properties.frsrootpath}
}

# Check If An DFS-R Subscriber Object Exists To Determine If DFS-R Is Being Used Instead Of NTFRS
$SearcherDFSR = New-Object DirectoryServices.DirectorySearcher
$SearcherDFSR.Filter = "(&(objectClass=msDFSR-Subscription)(name=SYSVOL Subscription))"
$SearcherDFSR.SearchRoot = $dcObjectPath
$dfsrSubscriptionObject = $SearcherDFSR.FindAll()
If ($dfsrSubscriptionObject -ne $null) {
    Write-Host "SYSVOL Replication Mechanism Being Used...: DFS-R" -ForeGroundColor Yellow
	Write-Host ""
    # Get The Local Root Path For The SYSVOL
	# The following appears NOT to work on W2K3, but it does not upper-level OSes. NOT really needed, because W2K3 does not support DFS-R for SYSVOL!
    # $sysvolRootPathOnSourcingRWDC = $dfsrSubscriptionObject.Properties."msdfsr-rootpath"
    # The following appears to work on all OSes
    $sysvolRootPathOnSourcingRWDC = $dfsrSubscriptionObject | %{$_.Properties."msdfsr-rootpath"}
}

# Determine The UNC Of The Folder To Write The Temp File To
$scriptsUNCPathOnSourcingRWDC = "\\" + $SourceRWDCInADDomainFQDN + "\" + $($sysvolRootPathOnSourcingRWDC.Replace(":","$")) + "\Scripts"
##########
# Get List Of DCs In AD Domain To Which The Temp Object Will Replicate, Create And Present In A Table
Write-Host "----------------------------------------------------------------------------------------------------------------------------------------------------" -ForeGroundColor Cyan
Write-Host "LIST OF DIRECTORY SERVERS THE TEMP OBJECT REPLICATES TO..." -ForeGroundColor Cyan

# Put The Selected RWDC Already In the Table [A] Of Directory Servers To Which The Temp Object Will Replicate
$TableOfDSServersA = @()
$TableOfDSServersAObj = "" | Select Name,"Site Name",Reachable
$TableOfDSServersAObj.Name = ("$SourceRWDCInADDomainFQDN [SOURCE RWDC]").ToUpper()
$TableOfDSServersAObj."Site Name" = $SourceRWDCInADDomainSITE
$TableOfDSServersAObj.Reachable = "TRUE"
$TableOfDSServersA += $TableOfDSServersAObj

# Put The Selected RWDC Already In the Table [B] Of Directory Servers Where The Replication Starts
$TableOfDSServersB = @()
$TableOfDSServersBObj = "" | Select Name,"Site Name",Time
$TableOfDSServersBObj.Name = ("$SourceRWDCInADDomainFQDN [SOURCE RWDC]").ToUpper()
$TableOfDSServersBObj."Site Name" = $SourceRWDCInADDomainSITE
$TableOfDSServersBObj.Time = 0.00
$TableOfDSServersB += $TableOfDSServersBObj

# Add All Other Remaining DCs In The Targeted AD Domain To The List Of Directory Servers [A]
ForEach ($DC In $ListOfDCsInADDomain) {
	If(!($DC.Name -like $SourceRWDCInADDomainFQDN)) {
		$TableOfDSServersAObj = "" | Select Name,"Site Name",Reachable
		$TableOfDSServersAObj.Name = $DC.Name
		If ($DC.SiteName -ne $null -And $DC.SiteName -ne "") {
			$TableOfDSServersAObj."Site Name" = $DC.SiteName
		} Else {
			If (($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($DC.Name).Substring(0,$($DC.Name).IndexOf(".")))} | Measure-Object).Count -eq 1) {
				$TableOfDSServersAObj."Site Name" = ($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($DC.Name).Substring(0,$($DC.Name).IndexOf(".")))})."Site Name"
			}
			If (($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($DC.Name).Substring(0,$($DC.Name).IndexOf(".")))} | Measure-Object).Count -eq 0) {
				$TableOfDSServersAObj."Site Name" = "<Fail>"
			}
			If (($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($DC.Name).Substring(0,$($DC.Name).IndexOf(".")))} | Measure-Object).Count -gt 1) {
				$TableOfDSServersAObj."Site Name" = "<Fail>"
			}	
		}
		$smbPort = "445"
		$timeOut = "500"
		$smbConnectionResult = $null
		$fqdnDC = $DC.Name
		$smbConnectionResult = PortConnectionCheck $fqdnDC $smbPort $timeOut
		If ($smbConnectionResult -eq "SUCCESS") {
			$TableOfDSServersAObj.Reachable = "TRUE"
		}
		If ($smbConnectionResult -eq "ERROR") {
			$TableOfDSServersAObj.Reachable = "FALSE"
		}
		$TableOfDSServersA += $TableOfDSServersAObj
	}
}
$TableOfDSServersA | FT -AutoSize
Write-Host "  --> Found [$($TableOfDSServersA.count)] Directory Server(s)..." -ForeGroundColor Cyan
Write-Host ""

##########
# Create The Temp Object On The Targeted RWDC
Write-Host "----------------------------------------------------------------------------------------------------------------------------------------------------" -ForeGroundColor Cyan
Write-Host "CREATING TEMP TEXT FILE IN SYSVOL/NETLOGON...:" -ForeGroundColor Cyan
Write-Host ""
$domainNCDN = $defaultNamingContext
$tempObjectName = "sysvolReplTempObject" + (Get-Date -f yyyyMMddHHmmss) + ".txt"
Write-Host "  --> On RWDC.............: $SourceRWDCInADDomainFQDN" -ForeGroundColor Yellow
Write-Host "  --> With Full Name......: $tempObjectName" -ForeGroundColor Yellow
Write-Host "  --> With Contents.......: ...!!!...TEMP OBJECT TO TEST SYSVOL REPLICATION LATENCY/CONVERGENCE...!!!..." -ForeGroundColor Yellow
Write-Host "  --> In AD Domain........: $ADDomainToWriteTo ($domainNCDN)" -ForeGroundColor Yellow
"...!!!...TEMP OBJECT TO TEST AD REPLICATION LATENCY/CONVERGENCE...!!!..." | Out-File -FilePath $($scriptsUNCPathOnSourcingRWDC + "\" + $tempObjectName)
Write-Host "`n  Temp Text File [$tempObjectName] Has Been Created In The NetLogon Share Of RWDC [$SourceRWDCInADDomainFQDN]! `n" -ForeGroundColor Yellow

##########
# Go Through The Process Of Checking Each Directory Server To See If The Temp Object Already Has Replicated To It
$startDateTime = Get-Date
$i = 0
Write-Host "  --> Found [$($TableOfDSServersA.count)] Directory Server(s)..." -ForeGroundColor Yellow
Write-Host ""
While($continue) {
    $i++
    $oldpos = $host.UI.RawUI.CursorPosition
    Write-Host "  ====================== CHECK $i ======================" -ForeGroundColor Yellow
    Write-Host ""
    Write-Host "  REMARK: Each DC In The List Below Must Be At Least Accessible Through SMB Over TCP (445)" -ForeGroundColor Red
	Write-Host ""
    Start-Sleep 1
    $replicated = $true
	
	# For Each Directory Server In The List/Table [A] Perform A Number Of Steps
    ForEach ($DSsrv in $TableOfDSServersA) {
		If ($DSsrv.Name -match $SourceRWDCInADDomainFQDN) {
			Write-Host "  * Contacting DC In AD domain ...[$($DSsrv.Name.ToUpper())]..." -ForeGroundColor Yellow
			Write-Host "     - DC Is Reachable..." -ForeGroundColor Green
			Write-Host "     - Object [$tempObjectName] Exists In The NetLogon Share" (" "*3) -ForeGroundColor Green
			continue
		}

		# If The Directory Server Is A DC In The AD Domain, Then Connect Through LDAP (TCP:445)
        If ($DSsrv.Name -notmatch $SourceRWDCInADDomainFQDN) {
			Write-Host ""
			Write-Host "  * Contacting DC In AD domain ...[$($DSsrv.Name.ToUpper())]..." -ForeGroundColor Yellow
			$connectionResult = $null
			If ($DSsrv.Reachable -eq "TRUE") {
				Write-Host "     - DC Is Reachable..." -ForeGroundColor Green
				$objectPath = "\\" + $($DSsrv.Name) + "\Netlogon\" + $tempObjectName
				$connectionResult = "SUCCESS"
			}			
			If ($DSsrv.Reachable -eq "FALSE") {
				Write-Host "     - DC Is NOT Reachable..." -ForeGroundColor Red
				$connectionResult = "FAILURE"
			}			
		}
		
		# If The Connection To The DC Is Successful
		If ($connectionResult -eq "SUCCESS") {
			If (Test-Path -Path $objectPath) {
				# If The Temp Object Already Exists
				Write-Host "     - Object [$tempObjectName] Now Does Exist In The NetLogon Share" (" "*3) -ForeGroundColor Green
				If (!($TableOfDSServersB | ?{$_.Name -match $DSsrv.Name})) {
					$TableOfDSServersBobj = "" | Select Name,"Site Name",Time
					$TableOfDSServersBobj.Name = $DSsrv.Name
					$TableOfDSServersBObj."Site Name" = $DSsrv."Site Name"
					$TableOfDSServersBObj.Time = ("{0:n2}" -f ((Get-Date)-$startDateTime).TotalSeconds)
					$TableOfDSServersB += $TableOfDSServersBObj
				}
			} Else {
				# If The Temp Object Does Not Yet Exist
				Write-Host "     - Object [$tempObjectName] Does NOT Exist Yet In The NetLogon Share" -ForeGroundColor Red
				$replicated  = $false
			}
		}
		
		# If The Connection To The DC Is Unsuccessful
		If ($connectionResult -eq "FAILURE") {
			Write-Host "     - Unable To Connect To DC/GC And Check For The Temp Object..." -ForeGroundColor Red
			If (!($TableOfDSServersB | ?{$_.Name -match $DSsrv.Name})) {
				$TableOfDSServersBobj = "" | Select Name,"Site Name",Time
				$TableOfDSServersBobj.Name = $DSsrv.Name
				$TableOfDSServersBObj."Site Name" = $DSsrv."Site Name"
				$TableOfDSServersBObj.Time = "<Fail>"
				$TableOfDSServersB += $TableOfDSServersBObj
			}
		}
    }
    If ($replicated) {
		$continue = $false
	} Else {
		$host.UI.RawUI.CursorPosition = $oldpos
	}
}

##########
# Show The Start Time, The End Time And The Duration Of The Replication
$endDateTime = Get-Date
$duration = "{0:n2}" -f ($endDateTime.Subtract($startDateTime).TotalSeconds)
Write-Host "`n  Start Time......: $(Get-Date $startDateTime -format "yyyy-MM-dd HH:mm:ss")" -ForeGroundColor Yellow
Write-Host "  End Time........: $(Get-Date $endDateTime -format "yyyy-MM-dd HH:mm:ss")" -ForeGroundColor Yellow
Write-Host "  Duration........: $duration Seconds" -ForeGroundColor Yellow

##########
# Delete The Temp Object On The RWDC
If ($cleanupTempObject) {
	Write-Host ""
    Write-Host "  Deleting Temp Text File... `n" -ForeGroundColor Yellow
    Remove-Item $($scriptsUNCPathOnSourcingRWDC + "\" + $tempObjectName) -Force
	Write-Host "  Temp Text File [$tempObjectName] Has Been Deleted On The Target RWDC! `n" -ForeGroundColor Yellow
}

##########
# Output The Table [B] Containing The Information Of Each Directory Server And How Long It Took To Reach That Directory Server After The Creation On The Source RWDC
$TableOfDSServersB | Sort-Object Time | FT -AutoSize