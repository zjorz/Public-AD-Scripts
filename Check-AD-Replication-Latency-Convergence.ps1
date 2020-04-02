# Abstract: This PoSH Script Checks The AD Replication Latency/Convergence
# Re-Written by: Jorge de Almeida Pinto [MVP-DS]
# Blog: http://jorgequestforknowledge.wordpress.com/
#
# 2013-03-02: (v0.1): Initial version of the script
# 2014-02-01: (v0.2): Added STOP option, added few extra columns to output extra info of DCs, better detection of unavailable DCs/GCs, and screen adjustment section added
# 2014-02-09: (v0.3): Solved a bug with regards to the detection/location of RWDCs and RODCs
# 2014-02-11: (v0.4): Added additional logic to determine if a DC is either an RWDC or RODC when it fails using the first logic and changed the layout a little bit
#
# REQUIRES: PowerShell v2.0 or higher
# REQUIRES: At least 2 RWDCs
# SUPPORTS: W2K3(R2), W2K8(R2), W2K12(R2) DCs and most likely higher
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
$uiConfig.WindowTitle = "+++ CHECKING AD REPLICATION LATENCY/CONVERGENCE +++"
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
Clear-Host
Write-Host "                                              *******************************************************" -ForeGroundColor Magenta
Write-Host "                                              *                                                     *" -ForeGroundColor Magenta
Write-Host "                                              *   --> Test AD Replication Latency/Convergence <--   *" -ForeGroundColor Magenta
Write-Host "                                              *                                                     *" -ForeGroundColor Magenta
Write-Host "                                              *    Re-Written By: Jorge de Almeida Pinto [MVP-DS]   *" -ForeGroundColor Magenta
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
# Get List Of AD Domains In The AD Forest, Create And Present In A Table
$ThisADForest = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$ListOfADDomainsInADForest = $ThisADForest.Domains
$TableOfADDomainsInADForest = @()
Write-Host ""
Write-Host "----------------------------------------------------------------------------------------------------------------------------------------------------" -ForeGroundColor Cyan
Write-Host "LIST OF DOMAINs IN THE AD FOREST..." -ForeGroundColor Cyan
Write-Host ""
Write-Host "Forest Mode/Level...: "$ThisADForest.ForestMode
ForEach ($Domain in $ListOfADDomainsInADForest) {
	$TableOfADDomainsInADForestObj = "" | Select Name,RootDomain,DomainMode,CurrentDomain
	$TableOfADDomainsInADForestObj.Name = $Domain.Name
	$TableOfADDomainsInADForestObj.RootDomain = "FALSE"
	If ($ThisADForest.RootDomain -like $Domain.Name) {
		$TableOfADDomainsInADForestObj.RootDomain = "TRUE"
	}
	$TableOfADDomainsInADForestObj.DomainMode = $Domain.DomainMode

	If ($Domain.Name -like $ENV:USERDNSDOMAIN) {
		$TableOfADDomainsInADForestObj.CurrentDomain = "TRUE"
	} Else {
		$TableOfADDomainsInADForestObj.CurrentDomain = "FALSE"
	}
	$TableOfADDomainsInADForest += $TableOfADDomainsInADForestObj
}
$TableOfADDomainsInADForest | FT -AutoSize
Write-Host "  --> Found [$($ListOfADDomainsInADForest.count)] AD Domain(s) In AD Forest..." -ForeGroundColor Cyan
Write-Host ""

##########
# Determine Which AD Domain To Use For The Temp Object. This Does Assume The Correct Permissions In That AD Domain To Create/Delete The Object!
Write-Host "----------------------------------------------------------------------------------------------------------------------------------------------------" -ForeGroundColor Cyan
Write-Host "In Which AD Domain Should The Temp Object Be Created?" -ForeGroundColor Cyan
Write-Host ""
$ADDomainToWriteTo = Read-Host "Please Provide FQDN Or Just Press ENTER For Current AD Domain"

# If No FQDN Of An AD Domain Is Specified, Then Use The Local AD Domain
If ($ADDomainToWriteTo -eq "") {
	$ADDomainToWriteTo = $(Get-WmiObject -Class Win32_ComputerSystem).Domain
}

# If The FQDN Of An AD Domain Is Specified, Then Check If It Exists In This AD Forest
If ($ADDomainToWriteTo -ne "") {
	$ADdomainvalidity = $False
	ForEach ($Domain in $ListOfADDomainsInADForest) {
		If ($Domain.Name -like $ADDomainToWriteTo) {
			$ADdomainvalidity = $True
		}
	}
	Write-Host ""
	Write-Host "Checking Existence Of The Specified AD Domain '$ADDomainToWriteTo' In The AD Forest..." -ForeGroundColor Yellow
	If ($ADdomainvalidity -eq $True) {
		Write-Host ""
		Write-Host "The Specified AD Domain '$ADDomainToWriteTo' Exists In The AD Forest!" -ForeGroundColor Green
		Write-Host ""
		Write-Host "Continuing Script..." -ForeGroundColor Green
	}
	If ($ADdomainvalidity -eq $False) {
		Write-Host ""
		Write-Host "The Specified AD Domain '$ADDomainToWriteTo' Does Not Exist In The AD Forest!" -ForeGroundColor Red
		Write-Host ""
		Write-Host "Please Re-Run The Script And Provide The FQDN Of An AD Domain That Does Exist In The AD Forest" -ForeGroundColor Red
		Write-Host ""
		Write-Host "Aborting Script..." -ForeGroundColor Red
		Write-Host ""
		BREAK
	}
}
Write-Host ""

##########
# Get List Of Directory Servers In AD Forest
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
# Get List Of GCs In AD Forest, Create And Present In A Table
$ListOfGCsInADForest = $ThisADForest.GlobalCatalogs
$TableOfGCsInADForest = @()
Write-Host "----------------------------------------------------------------------------------------------------------------------------------------------------" -ForeGroundColor Cyan
Write-Host "LIST OF GCs IN THE AD FOREST '$ThisADForest'..." -ForeGroundColor Cyan
ForEach ($GC in $ListOfGCsInADForest) {
	$TableOfGCsInADForestObj = "" | Select Name,Domain,"Site Name","IP Address","OS Version"
	$TableOfGCsInADForestObj.Name = $GC.Name
	If ($GC.Domain -ne $null -And $GC.Domain -ne "") {
		$TableOfGCsInADForestObj.Domain = $GC.Domain
	} Else {
		$TableOfGCsInADForestObj.Domain = $($GC.Name).Substring($($GC.Name).IndexOf(".") + 1)
	}
	If ($GC.SiteName -ne $null -And $GC.SiteName -ne "") {
		$TableOfGCsInADForestObj."Site Name" = $GC.SiteName
	} Else {
		If (($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($GC.Name).Substring(0,$($GC.Name).IndexOf(".")))} | Measure-Object).Count -eq 1) {
			$TableOfGCsInADForestObj."Site Name" = ($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($GC.Name).Substring(0,$($GC.Name).IndexOf(".")))})."Site Name"
		}
		If (($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($GC.Name).Substring(0,$($GC.Name).IndexOf(".")))} | Measure-Object).Count -eq 0) {
			$TableOfGCsInADForestObj."Site Name" = "<Fail>"
		}
		If (($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($GC.Name).Substring(0,$($GC.Name).IndexOf(".")))} | Measure-Object).Count -gt 1) {
			$TableOfGCsInADForestObj."Site Name" = "<Fail>"
		}
	}
	If ($GC.IPAddress -ne $null -And $GC.IPAddress -ne "") {
		$TableOfGCsInADForestObj."IP Address" = $GC.IPAddress
	} Else {
		$TableOfGCsInADForestObj."IP Address" = "<Fail>"
	}
	If ($GC.OSVersion -ne $null -And $GC.OSVersion -ne "") {
		$TableOfGCsInADForestObj."OS Version" = $GC.OSVersion
	} Else {
		$TableOfGCsInADForestObj."OS Version" = "<Fail>"
	}
	$TableOfGCsInADForest += $TableOfGCsInADForestObj
}
$TableOfGCsInADForest | FT -AutoSize
Write-Host "  --> Found [$($ListOfGCsInADForest.count)] GC(s) In AD Forest..." -ForeGroundColor Cyan
Write-Host ""

##########
# Get List Of DCs In AD Domain, Create And Present In A Table
$contextADDomainToWriteTo = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$ADDomainToWriteTo)
$ListOfDCsInADDomain = [System.DirectoryServices.ActiveDirectory.DomainController]::findall($contextADDomainToWriteTo)
$ListOfRWDCsInADDomain = $ListOfDCsInADDomain | ?{$_.InboundConnections -ne $null -and !($_.InboundConnections -match "RODC Connection")}
$ListOfRODCsInADDomain = $ListOfDCsInADDomain | ?{$_.InboundConnections -match "RODC Connection"}
#$ListOfUnknownDCsInADDomain = $ListOfDCsInADDomain | ?{!($_.InboundConnections -ne $null)}
	
$TableOfDCsInADDomain = @()
Write-Host "----------------------------------------------------------------------------------------------------------------------------------------------------" -ForeGroundColor Cyan
Write-Host "LIST OF DCs IN THE AD DOMAIN '$ADDomainToWriteTo'..." -ForeGroundColor Cyan
ForEach ($DC in $ListOfDCsInADDomain) {
	$TableOfDCsInADDomainObj = "" | Select Name,Domain,GC,FSMO,"Site Name","DS Type","IP Address","OS Version"
	$TableOfDCsInADDomainObj.Name = $DC.Name
	$TableOfDCsInADDomainObj.Domain = $ADDomainToWriteTo
	$TableOfDCsInADDomainObj.GC = "FALSE"
	ForEach ($GC in $ListOfGCsInADForest) {
		If ($DC.Name -like $GC.Name) {
			$TableOfDCsInADDomainObj.GC = "TRUE"
		}
	}
	If ($DC.Roles -ne $null) {
		If ($DC.Roles -Contains "PdcRole") {
			$pdcFQDN = $DC.Name
			$pdcDomain = $ADDomainToWriteTo
			$pdcSite = $DC.SiteName
		}
		ForEach ($FSMO In $DC.Roles) {
			If ($FSMO -eq "SchemaRole") {$FSMO = "SCH"}
			If ($FSMO -eq "NamingRole") {$FSMO = "DNM"}
			If ($FSMO -eq "PdcRole") {$FSMO = "PDC"}
			If ($FSMO -eq "RidRole") {$FSMO = "RID"}
			If ($FSMO -eq "InfrastructureRole") {$FSMO = "INF"}
			$TableOfDCsInADDomainObj.FSMO += $FSMO+"/"
		}
		$TableOfDCsInADDomainObj.FSMO = ($TableOfDCsInADDomainObj.FSMO).Substring(0,$TableOfDCsInADDomainObj.FSMO.Length-1)
	} Else {
		$TableOfDCsInADDomainObj.FSMO = "....."
	}
	If ($DC.SiteName -ne $null -And $DC.SiteName -ne "") {
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
	$SourceRWDCInADDomainDOMAIN = $pdcDomain
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
		$SourceRWDCInADDomainDOMAIN = $SourceRWDCInADDomainObjectONE.Domain
		$SourceRWDCInADDomainSITE = $SourceRWDCInADDomainObjectONE.SiteName
	}
	
	# If The Single DC Found Is An RODC, Then Find The RWDC With The PDC FSMO Role And Use That
	If ($UseRWDC -eq $False) {
		$SourceRWDCInADDomainFQDN = $pdcFQDN
		$SourceRWDCInADDomainDOMAIN = $pdcDomain
		$SourceRWDCInADDomainSITE = $pdcSite
	}
}

# If A Specific RWDC Was Specified Then Use That One
If ($SourceRWDCInADDomain -ne "" -And $SourceRWDCInADDomain -ne "PDC" -And $SourceRWDCInADDomain -ne "STOP") {
	$contextRWDCToWriteTo = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer",$SourceRWDCInADDomain)
	$SourceRWDCInADDomainObject = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($contextRWDCToWriteTo)
	$SourceRWDCInADDomainFQDN = $SourceRWDCInADDomainObject.Name
	$SourceRWDCInADDomainDOMAIN = $SourceRWDCInADDomainObject.Domain
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
	$ldapPort = "389"
	$timeOut = "500"
	$ldapConnectionResult = $null
	$fqdnDC = $SourceRWDCInADDomainFQDN
	$ldapConnectionResult = PortConnectionCheck $fqdnDC $ldapPort $timeOut
	If ($ldapConnectionResult -eq "SUCCESS") {
		Write-Host ""
		Write-Host "The Specified RWDC '$SourceRWDCInADDomainFQDN' Is Reachable!" -ForeGroundColor Green
		Write-Host ""
		Write-Host "Continuing Script..." -ForeGroundColor Green
		Write-Host ""
	}
	If ($ldapConnectionResult -eq "ERROR") {
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
# Get List Of DCs/GCs In AD Domain/Forest To Which The Temp Object Will Replicate, Create And Present In A Table
Write-Host "----------------------------------------------------------------------------------------------------------------------------------------------------" -ForeGroundColor Cyan
Write-Host "LIST OF DIRECTORY SERVERS THE TEMP OBJECT REPLICATES TO..." -ForeGroundColor Cyan

# Put The Selected RWDC Already In the Table [A] Of Directory Servers To Which The Temp Object Will Replicate
$TableOfDSServersA = @()
$TableOfDSServersAObj = "" | Select Name,Domain,GC,"Site Name",Reachable
$TableOfDSServersAObj.Name = ("$SourceRWDCInADDomainFQDN [SOURCE RWDC]").ToUpper()
$TableOfDSServersAObj.Domain = $ADDomainToWriteTo
$TableOfDSServersAObj.GC = "FALSE"
ForEach ($GC in $ListOfGCsInADForest) {
	If ($SourceRWDCInADDomainFQDN -like $GC.Name) {
		$TableOfDSServersAObj.GC = "TRUE"
	}
}
$TableOfDSServersAObj."Site Name" = $SourceRWDCInADDomainSITE
$TableOfDSServersAObj.Reachable = "TRUE"
$TableOfDSServersA += $TableOfDSServersAObj

# Put The Selected RWDC Already In the Table [B] Of Directory Servers Where The Replication Starts
$TableOfDSServersB = @()
$TableOfDSServersBObj = "" | Select Name,Domain,GC,"Site Name",Time
$TableOfDSServersBObj.Name = ("$SourceRWDCInADDomainFQDN [SOURCE RWDC]").ToUpper()
$TableOfDSServersBObj.Domain = $ADDomainToWriteTo
$TableOfDSServersBObj.GC = "FALSE"
ForEach ($GC in $ListOfGCsInADForest) {
	If ($SourceRWDCInADDomainFQDN -like $GC.Name) {
		$TableOfDSServersBObj.GC = "TRUE"
	}
}
$TableOfDSServersBObj."Site Name" = $SourceRWDCInADDomainSITE
$TableOfDSServersBObj.Time = 0.00
$TableOfDSServersB += $TableOfDSServersBObj

# Add All Other Remaining DCs In The Targeted AD Domain To The List Of Directory Servers [A]
ForEach ($DC In $ListOfDCsInADDomain) {
	If(!($DC.Name -like $SourceRWDCInADDomainFQDN)) {
		$TableOfDSServersAObj = "" | Select Name,Domain,GC,"Site Name",Reachable
		$TableOfDSServersAObj.Name = $DC.Name
		If ($DC.Domain -ne $null -And $DC.Domain -ne "") {
			$TableOfDSServersAObj.Domain = $DC.Domain
		} Else {
			$TableOfDSServersAObj.Domain = $($DC.Name).Substring($($DC.Name).IndexOf(".") + 1)
		}
		$TableOfDSServersAObj.GC = "FALSE"
		ForEach ($GC in $ListOfGCsInADForest) {
			If ($DC.Name -like $GC.Name) {
				$TableOfDSServersAObj.GC = "TRUE"
			}
		}
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
		$ldapPort = "389"
		$timeOut = "500"
		$ldapConnectionResult = $null
		$fqdnDC = $DC.Name
		$ldapConnectionResult = PortConnectionCheck $fqdnDC $ldapPort $timeOut
		If ($ldapConnectionResult -eq "SUCCESS") {
			$TableOfDSServersAObj.Reachable = "TRUE"
		}
		If ($ldapConnectionResult -eq "ERROR") {
			$TableOfDSServersAObj.Reachable = "FALSE"
		}
		$TableOfDSServersA += $TableOfDSServersAObj
	}
}

# Add All Other Remaining GCs In The AD Forest To The List Of Directory Servers [A]
ForEach ($GC In $ListOfGCsInADForest) {
	$ToBeAdded = $True
	ForEach ($DC In $ListOfDCsInADDomain) {
		If($DC.Name -like $GC.Name) {
			$ToBeAdded = $False
		}
	}
	If ($ToBeAdded) {
		$TableOfDSServersAObj = "" | Select Name,Domain,GC,"Site Name",Reachable
		$TableOfDSServersAObj.Name = $GC.Name
		If ($GC.Domain -ne $null -And $GC.Domain -ne "") {
			$TableOfDSServersAObj.Domain = $GC.Domain
		} Else {
			$TableOfDSServersAObj.Domain = $($GC.Name).Substring($($GC.Name).IndexOf(".") + 1)
		}
		$TableOfDSServersAObj.GC = "TRUE"
		If ($GC.SiteName -ne $null -And $GC.SiteName -ne "") {
			$TableOfDSServersAObj."Site Name" = $GC.SiteName
		} Else {
			If (($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($GC.Name).Substring(0,$($GC.Name).IndexOf(".")))} | Measure-Object).Count -eq 1) {
				$TableOfDSServersAObj."Site Name" = ($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($GC.Name).Substring(0,$($GC.Name).IndexOf(".")))})."Site Name"
			}
			If (($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($GC.Name).Substring(0,$($GC.Name).IndexOf(".")))} | Measure-Object).Count -eq 0) {
				$TableOfDSServersAObj."Site Name" = "<Fail>"
			}
			If (($TableOfDCsInADForest | ?{$_."DS Name" -eq $($($GC.Name).Substring(0,$($GC.Name).IndexOf(".")))} | Measure-Object).Count -gt 1) {
				$TableOfDSServersAObj."Site Name" = "<Fail>"
			}
		}
		$gcPort = "3268"
		$timeOut = "500"
		$gcConnectionResult = $null
		$fqdnGC = $GC.Name
		$gcConnectionResult = PortConnectionCheck $fqdnGC $gcPort $timeOut
		If ($gcConnectionResult -eq "SUCCESS") {
			$TableOfDSServersAObj.Reachable = "TRUE"
		}
		If ($gcConnectionResult -eq "ERROR") {
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
Write-Host "CREATING TEMP CONTACT OBJECT IN AD...:" -ForeGroundColor Cyan
Write-Host ""
$domainNCDN = (([ADSI]"LDAP://$SourceRWDCInADDomainFQDN/rootDSE").defaultNamingContext)
$container = "CN=Users," + $domainNCDN
$tempObjectName = "adReplTempObject" + (Get-Date -f yyyyMMddHHmmss)
Write-Host "  --> On RWDC.............: $SourceRWDCInADDomainFQDN" -ForeGroundColor Yellow
Write-Host "  --> With Full Name......: $tempObjectName" -ForeGroundColor Yellow
Write-Host "  --> With Description....: ...!!!...TEMP OBJECT TO TEST AD REPLICATION LATENCY/CONVERGENCE...!!!..." -ForeGroundColor Yellow
Write-Host "  --> In AD Domain........: $ADDomainToWriteTo ($domainNCDN)" -ForeGroundColor Yellow
Write-Host "  --> In Container........: $container" -ForeGroundColor Yellow
$tempObject = ([ADSI]"LDAP://$SourceRWDCInADDomainFQDN/$container").Create("contact","CN=$tempObjectName")
$tempObject.Put("Description","...!!!...TEMP OBJECT TO TEST AD REPLICATION LATENCY/CONVERGENCE...!!!...")
$tempObject.SetInfo()
$tempObjectDN = $tempObject.distinguishedname
Write-Host "`n  Temp Contact Object [$tempObjectDN] Has Been Created On RWDC [$SourceRWDCInADDomainFQDN]! `n" -ForeGroundColor Yellow

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
	Write-Host "  REMARK: Each DC In The List Below Must Be At Least Accessible Through LDAP Over TCP (389)" -ForeGroundColor Red
	Write-Host "  REMARK: Each GC In The List Below Must Be At Least Accessible Through LDAP-GC Over TCP (3268)" -ForeGroundColor Red
    Write-Host ""
	Start-Sleep 1
    $replicated = $true
	
	# For Each Directory Server In The List/Table [A] Perform A Number Of Steps
    ForEach ($DSsrv in $TableOfDSServersA) {
		If ($DSsrv.Name -match $SourceRWDCInADDomainFQDN) {
			Write-Host "  * Contacting DC In AD domain ...[$($DSsrv.Name.ToUpper())]..." -ForeGroundColor Yellow
			Write-Host "     - DC Is Reachable..." -ForeGroundColor Green
			Write-Host "     - Object [$tempObjectDN] Exists In The Database" (" "*3) -ForeGroundColor Green
			continue
		}

		# If The Directory Server Is A DC In The AD Domain, Then Connect Through LDAP (TCP:389)
        If ($DSsrv.Domain -like $ADDomainToWriteTo) {
			Write-Host ""
			Write-Host "  * Contacting DC In AD domain ...[$($DSsrv.Name.ToUpper())]..." -ForeGroundColor Yellow
			$connectionResult = $null
			If ($DSsrv.Reachable -eq "TRUE") {
				Write-Host "     - DC Is Reachable..." -ForeGroundColor Green
				$objectPath = [ADSI]"LDAP://$($DSsrv.Name)/$tempObjectDN"
				$connectionResult = "SUCCESS"
			}			
			If ($DSsrv.Reachable -eq "FALSE") {
				Write-Host "     - DC Is NOT Reachable..." -ForeGroundColor Red
				$connectionResult = "FAILURE"
			}			
		}
		
		# If The Directory Server Is A GC In Another AD Domain, Then Connect Through LDAP-GC (TCP:3268)
        If (!($DSsrv.Domain -like $ADDomainToWriteTo) -And $DSsrv.Domain -ne $null -And $DSsrv.Domain -ne "" -And $DSsrv.Domain -ne "<Fail>") {
			Write-Host ""
			Write-Host "  * Contacting GC In Other AD Domain ...[$($DSsrv.Name.ToUpper())]..." -ForeGroundColor Yellow
			$connectionResult = $null
			If ($DSsrv.Reachable -eq "TRUE") {
				Write-Host "     - DC Is Reachable..." -ForeGroundColor Green
				$objectPath = [ADSI]"GC://$($DSsrv.Name)/$tempObjectDN"
				$connectionResult = "SUCCESS"
			}			
			If ($DSsrv.Reachable -eq "FALSE") {
				Write-Host "     - DC Is NOT Reachable..." -ForeGroundColor Red
				$connectionResult = "FAILURE"
			}
		}
		# If The Directory Server Is Not Available
        If ($DSsrv.Domain -eq $null -Or $DSsrv.Domain -eq "" -Or $DSsrv.Domain -eq "<Fail>") {
			Write-Host ""
			Write-Host "  * Contacting DC/GC In AD Forest ...[$($DSsrv.Name.ToUpper())]..." -ForeGroundColor Yellow
			$connectionResult = $null		
			If ($DSsrv.Reachable -eq "FALSE") {
				Write-Host "     - DC Is NOT Reachable..." -ForeGroundColor Red
				$connectionResult = "FAILURE"
			}
		}
        
		# If The Connection To The DC Is Successful
		If ($connectionResult -eq "SUCCESS") {
			If ($objectPath.name) {
				# If The Temp Object Already Exists
				Write-Host "     - Object [$tempObjectDN] Now Does Exist In The Database" (" "*3) -ForeGroundColor Green
				If (!($TableOfDSServersB | ?{$_.Name -match $DSsrv.Name})) {
					$TableOfDSServersBobj = "" | Select Name,Domain,GC,"Site Name",Time
					$TableOfDSServersBobj.Name = $DSsrv.Name
					$TableOfDSServersBObj.Domain = $DSsrv.Domain
					$TableOfDSServersBObj.GC = $DSsrv.GC
					$TableOfDSServersBObj."Site Name" = $DSsrv."Site Name"
					$TableOfDSServersBObj.Time = ("{0:n2}" -f ((Get-Date)-$startDateTime).TotalSeconds)
					$TableOfDSServersB += $TableOfDSServersBObj
				}
			} Else {
				# If The Temp Object Does Not Yet Exist
				Write-Host "     - Object [$tempObjectDN] Does NOT Exist Yet In The Database" -ForeGroundColor Red
				$replicated  = $false
			}
		}
		
		# If The Connection To The DC Is Unsuccessful
		If ($connectionResult -eq "FAILURE") {
			Write-Host "     - Unable To Connect To DC/GC And Check For The Temp Object..." -ForeGroundColor Red
			If (!($TableOfDSServersB | ?{$_.Name -match $DSsrv.Name})) {
				$TableOfDSServersBobj = "" | Select Name,Domain,GC,"Site Name",Time
				$TableOfDSServersBobj.Name = $DSsrv.Name
				$TableOfDSServersBObj.Domain = $DSsrv.Domain
				$TableOfDSServersBObj.GC = $DSsrv.GC
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
    Write-Host "  Deleting Temp Contact Object... `n" -ForeGroundColor Yellow
    ([ADSI]"LDAP://$SourceRWDCInADDomainFQDN/$container").Delete("contact","CN=$tempObjectName")
	Write-Host "  Temp Contact Object [$tempObjectDN] Has Been Deleted On The Target RWDC! `n" -ForeGroundColor Yellow
}

##########
# Output The Table [B] Containing The Information Of Each Directory Server And How Long It Took To Reach That Directory Server After The Creation On The Source RWDC
$TableOfDSServersB | Sort-Object Time | FT -AutoSize