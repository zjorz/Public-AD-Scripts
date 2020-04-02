### Abstract: This PoSH Script Scans And Checks All Accounts In The AD Forest And Creates A CSV Report And Outputs To GridView
### Written by: Jorge de Almeida Pinto [MVP-EMS]
### BLOG: http://jorgequestforknowledge.wordpress.com/
###
### 2019-10-26: Initial version of the script (v0.1)
###

<#
.SYNOPSIS
.DESCRIPTION
	This PoSH Script Leverages LDAP Queries To:
	* Generate CSV Report With The Results. For every account (user, computer, gMSA, inetOrgPerson), the following is gathered and listed
		* Domain FQDN (e.g. 'IAMTEC.NET')
		* Domain NBT (e.g. 'IAMTEC')
		* Domain DN (e.g. 'DC=IAMTEC,DC=NET')
		* Sam Account Name (e.g. 'jorge')
		* Account Name (e.g. 'IAMTEC\jorge')
		* Account Type (computer, inetOrgPerson, msDS-GroupManagedServiceAccount, trust (user), user)
		* User Principal Name  (e.g. 'jorge@iamtec.nl')
		* Display Name (e.g. Jorge de Almeida Pinto)
		* Enabled (e.g. TRUE or FALSE)
		* Locked (e.g. TRUE - At:<date/time> or FALSE - Never Locked or FALSE - Has Been Locked Before)
		* Account Expires On (e.g. <date/time> or NEVER)
		* Pwd Last Set On (e.g. <date/time> or "Must Chng At Next Logon")
		* Pwd Never Expires (e.g. TRUE or FALSE)
		* Last Logon Timestamp (e.g. <date/time> or NEVER)
		* Last Logon (RWDC) (e.g. <date/time> or NEVER Or NOT AVAILABLE (On '<FQDN RWDC>')) <-- THIS MEANS IT WILL QUERY EVERY DC (RWDC And RODC) In The AD Domain To Get The LastLogon Property From That DC!

.EXAMPLE
	Scan/Check All Accounts In The AD Forest And Create The Report

	.\Scan-And-Check-All-Accounts-In-AD-Forest_01_Basic-Info.ps1

.NOTES
	This script requires:
	* PowerShell Module: ActiveDirectory 
	* Basic Permissions, Nothing Special!
#>

### FUNCTION: Logging Data To The Log File
Function Logging($dataToLog, $lineType) {
	$datetimeLogLine = "[" + $(Get-Date -format "yyyy-MM-dd HH:mm:ss") + "] : "
	Out-File -filepath "$logFilePath" -append -inputObject "$datetimeLogLine$dataToLog"
	#Write-Output($datetimeLogLine + $dataToLog)
	If ($lineType -eq $NULL) {
		Write-Host "$datetimeLogLine$dataToLog"
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
	If ($lineType -eq "HEADER") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Magenta
	}
	If ($lineType -eq "REMARK") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Cyan
	}
}

### FUNCTION: Load Required PowerShell Modules
Function loadPoSHModules($PoSHModule) {
	If(@(Get-Module | Where-Object {$_.Name -eq $PoSHModule}).count -eq 0) {
		If(@(Get-Module -ListAvailable | Where-Object {$_.Name -eq $PoSHModule} ).count -ne 0) {
			Import-Module $PoSHModule
			Write-Host ""
			Write-Host "PoSH Module '$PoSHModule' Has Been Loaded..." -ForeGroundColor Green
			Write-Host "Continuing Script..." -ForeGroundColor Green
			Write-Host ""
		} Else {
			Write-Host ""
			Write-Host "PoSH Module '$PoSHModule' Is Not Available To Load..." -ForeGroundColor Red
			Write-Host "Aborting Script..." -ForeGroundColor Red
			Write-Host ""
			
			EXIT
		}
	} Else {
		Write-Host ""
		Write-Host "PoSH Module '$PoSHModule' Already Loaded..." -ForeGroundColor Yellow
		Write-Host "Continuing Script..." -ForeGroundColor Yellow
		Write-Host ""
	}
}

### FUNCTION: Test The Port Connection
Function portConnectionCheck($fqdnServer, $port, $timeOut) {
	# Test To See If The HostName Is Resolvable At All
	Try {
		[System.Net.Dns]::gethostentry($fqdnServer) | Out-Null
	} Catch {
		Return "ERROR"
	}
	
	$tcpPortSocket = $null
	$portConnect = $null
	$tcpPortWait = $null
	$tcpPortSocket = New-Object System.Net.Sockets.TcpClient
	$portConnect = $tcpPortSocket.BeginConnect($fqdnServer, $port, $null, $null)
	$tcpPortWait = $portConnect.AsyncWaitHandle.WaitOne($timeOut, $false)
	If(!$tcpPortWait) {
		$tcpPortSocket.Close()
		Return "ERROR"
	} Else {
		#$error.Clear()
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

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ SCAN AND CHECK ALL ACCOUNTS IN AD FOREST - BASIC INFO +++"
$uiConfig.ForegroundColor = "Yellow"
$uiConfigBufferSize = $uiConfig.BufferSize
$uiConfigBufferSize.Width = 160
$uiConfigBufferSize.Height = 9999
$uiConfigScreenSizeMax = $uiConfig.MaxPhysicalWindowSize
$uiConfigScreenSizeMaxWidth = $uiConfigScreenSizeMax.Width
$uiConfigScreenSizeMaxHeight = $uiConfigScreenSizeMax.Height
$uiConfigScreenSize = $uiConfig.WindowSize
If ($uiConfigScreenSizeMaxWidth -lt 160) {
	$uiConfigScreenSize.Width = $uiConfigScreenSizeMaxWidth
} Else {
	$uiConfigScreenSize.Width = 160
}
If ($uiConfigScreenSizeMaxHeight -lt 75) {
	$uiConfigScreenSize.Height = $uiConfigScreenSizeMaxHeight - 5
} Else {
	$uiConfigScreenSize.Height = 75
}
$uiConfig.BufferSize = $uiConfigBufferSize
$uiConfig.WindowSize = $uiConfigScreenSize

### Definition Of Some Constants
$startExecDateTime = Get-Date
$execStartDateTimeDisplay = Get-Date $startExecDateTime -Format "yyyy-MM-dd HH:mm:ss"
$execStartDateTimeCustom = Get-Date $startExecDateTime -Format "yyyy-MM-dd_HH.mm.ss"
$currentScriptFilePath = $MyInvocation.MyCommand.Definition
$currentScriptFolderPath = Split-Path $currentScriptFilePath
$thisADForest = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$thisADForestRootDomain = $thisADForest.RootDomain.Name
$outputCSVFileName = $($execStartDateTimeCustom + "_" + $thisADForestRootDomain + "_Scan-And-Check-All-Accounts-In-AD-Forest_01_Basic-Info.csv")
$outputCSVFilePath	= $currentScriptFolderPath + "\" + $outputCSVFileName
$logFileName = $($execStartDateTimeCustom + "_" + $thisADForestRootDomain + "_Scan-And-Check-All-Accounts-In-AD-Forest_01_Basic-Info.log")
$logFilePath = $currentScriptFolderPath + "\" + $logFileName

Logging "" "HEADER"
Logging "                     **********************************************************************************" "HEADER"
Logging "                     *                                                                                *" "HEADER"
Logging "                     *          --> Scan And Check All Accounts In AD Forest - Basic Info <--         *" "HEADER"
Logging "                     *                                                                                *" "HEADER"
Logging "                     *                   Written By: Jorge de Almeida Pinto [MVP-EMS]                 *" "HEADER"
Logging "                     *                                                                                *" "HEADER"
Logging "                     *                BLOG: http://jorgequestforknowledge.wordpress.com/              *" "HEADER"
Logging "                     *                                                                                *" "HEADER"
Logging "                     **********************************************************************************" "HEADER"
Logging "" "HEADER"

### Test For Availability Of PowerShell CMDlets And Load Required PowerShell Module
"ActiveDirectory" | %{loadPoSHModules $_}

### Define The Empty Table To Hold All The Gathered Data
$accountData = @()

### Retrieve AD Forest Info
$adforest = Get-ADForest

# AD Forest FQDN
$adForestRootDomainFQDN = $adforest.RootDomain

# AD Forest Root Domain
$adForestRootDomain = Get-ADDomain $adForestRootDomainFQDN

# AD Forest DN
$adForestRootDomainDN = $adForestRootDomain.DistinguishedName

# AD Forest Domain SID
$adForestRootDomainDomainSID = $adForestRootDomain.DomainSID.Value

# Nearest AD DC For AD Forest Info
$adRwdcFQDN = ((Get-ADDomainController -Discover).HostName)[0]

# Nearest AD GC
$adGcFQDN = (Get-ADDomainController -Discover -Service GlobalCatalog).HostName[0]

# Root DSE Of The AD DC
$adRootDSENearestRWDC = Get-ADRootDSE -Server $adRwdcFQDN

# Schema NC DN
$adForestSchemaNC = $adRootDSENearestRWDC.schemaNamingContext

# Config NC DN
$adForestConfigNC = $adRootDSENearestRWDC.configurationNamingContext

### Displaying The AD Forest Info
Logging ""
Logging "AD Forest...................: '$adForestRootDomainFQDN'"
Logging "Nearest RWDC For AD Info....: '$adRwdcFQDN'"
Logging "Nearest GC For AD Info......: '$adGcFQDN'"
Logging "AD Forest Root Domain DN....: '$adForestRootDomainDN'"
Logging "Schema NC DN................: '$adForestSchemaNC'"
Logging "Config NC DN ...............: '$adForestConfigNC'"
Logging ""

### Security Principals Of Interest That Can Authenticate
# At Least 1 Must Be Specified!
$securityPrincipalsThatCanAuthN = @()
$securityPrincipalsThatCanAuthN += "user"
$securityPrincipalsThatCanAuthN += "computer"
$securityPrincipalsThatCanAuthN += "msDS-GroupManagedServiceAccount"
$securityPrincipalsThatCanAuthN += "inetOrgPerson"

### LDAP Filter To Find Security Principal That AuthN
$ldapFilterClause = $null
$ldapFilterSecurityPrincipalsThatCanAuthN = $null
$securityPrincipalsThatCanAuthN | %{
	$securityPrincipalThatCanAuthN = $null
	$securityPrincipalThatCanAuthN = $_
	$ldapFilterClause = $ldapFilterClause + "(objectClass=$securityPrincipalThatCanAuthN)"
}
$ldapFilterClauseCount = ([regex]::Matches($ldapFilterClause, "objectClass")).count
If ($ldapFilterClauseCount -eq 1) {
	$ldapFilterSecurityPrincipalsThatCanAuthN = $ldapFilterClause
} Else {
	$ldapFilterSecurityPrincipalsThatCanAuthN = "(|" + $ldapFilterClause + ")"
}

### Retrieve AD Domain FQDNs In AD Forest And Build The Order As Such The Forest Root AD Domain Is At The Top Of The List. This Is Done To Have The Processing Of The Accounts In A Specific Order
# Get All AD Domains In The AD Forest
$adDomainFQDNs = $adforest.Domains

# Define Empty List Of FQDNs In The AD Forest
$script:adDomainFQDNList = @()

# Add The Forest Root AD Domain To That List
$script:adDomainFQDNList += $adForestRootDomainFQDN

# Continue If There Is More Than 1 AD Domain In The AD Forest
If ($adDomainFQDNs.Count -gt 1) {
	# For Every Child AD Domain Under The Forest Root AD Domain Add It In A Sorted Manner To That List
	$adDomainFQDNs | ?{$_ -ne $adForestRootDomainFQDN -And $_ -match $adForestRootDomainFQDN} | Sort-Object | %{
		$script:adDomainFQDNList += $_
	}
	# Retrieve All Cross References In The AD Forest To Determine If other Tree Roots Are Available Or Not
	$adDomainCrossRefs = Get-ADObject -LDAPFilter "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))" -SearchBase "CN=Partitions,$adForestConfigNC" -Properties *
	$adRootDomainCrossRefDN = ($adDomainCrossRefs | ?{$_.nCName -eq $adForestRootDomainDN}).DistinguishedName
	
	# For Every Cross Reference Found Process It
	If ($adDomainCrossRefs) {
		# For Every Cross Reference Not Being The One For The Forest Root AD Domain, But Rather A Tree Root AD Domain, Process it
		$adDomainCrossRefs | ?{$_.rootTrust -eq $adRootDomainCrossRefDN} | %{
			# Distinguished Name Of The Naming Context Of The Tree Root AD Domain
			$ncName = $null
			$ncName = $_.nCName
			
			# The FQDN Of The Tree Root AD Domain
			$adDomainFQDN = $null
			$adDomainFQDN = $ncName.Replace(",DC=",".").Replace("DC=","")
			
			# Add It To The List Of FQDNs
			$script:adDomainFQDNList += $adDomainFQDN
			
			# For Every Child AD Domain Of The Tree Root AD Domain Add It In A Sorted Manner To That List
			$adDomainFQDNs | ?{$_ -ne $adDomainFQDN -And $_ -match $adDomainFQDN} | Sort-Object | %{
				$script:adDomainFQDNList += $_
			}
		}
	}
}

### For Every AD Domain In The AD Forest, Now Process The Accounts From That AD Domain
$adDomainFQDNList | %{
	# Define The Counter
	$totalAccounts = 0
	
	# Define The Start Execution Date And Time For This AD Domain
	$startExecDateTimeThisADDomain = $null
	$startExecDateTimeThisADDomain = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

	# AD Domain FQDN
	$adDomainFQDN = $null
	$adDomainFQDN = $_
	
	# AD Domain Object
	$adDomain = $null
	$adDomain = Get-ADDomain $adDomainFQDN

	# AD Domain NetBIOS Name
	$adDomainNBT = $null
	$adDomainNBT = $adDomain.NetBIOSName

	# AD Domain DN
	$adDomainDN = $null
	$adDomainDN = $adDomain.DistinguishedName
	
	# An RWDC For The AD Domain
	$adDomainRwdcFQDN = $null
	$adDomainRwdcFQDN = ((Get-ADDomainController -Domain $adDomainFQDN -Discover).HostName)[0]

	# All RWDCs In The AD Domain
	$adDomainRWDCsFQDN = $null
	$adDomainRWDCsFQDN = $adDomain.ReplicaDirectoryServers

	# All RODCs In The AD Domain
	$adDomainRODCsFQDN = $null
	$adDomainRODCsFQDN = $adDomain.ReadOnlyReplicaDirectoryServers

	# All DCs (RWDCs And RODCs) In The AD Domain
	$adDomainDCsFQDN = @()
	$adDomainDCsFQDN = $adDomainRWDCsFQDN + $adDomainRODCsFQDN

	# Display The Start Of Processing Certain AD Domain
	Logging "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" "HEADER"
	Logging "" "HEADER"
	Logging "Starting Processing Security Principals That Can Authenticate From AD Domain '$adDomainFQDN ($adDomainDN) ($adDomainRwdcFQDN)'..." "HEADER"
	Logging "" "HEADER"

	# Get Accounts And Properties From Within Targeted Naming Context
	Logging " > Getting Objects And Properties From '$adDomainRwdcFQDN' Within '$adDomainDN'..." "REMARK"
	Logging "" "REMARK"
	$allAuthSecurityPrincipals = $null
	$allAuthSecurityPrincipals = Get-ADObject -LDAPFilter $ldapFilterSecurityPrincipalsThatCanAuthN -Server $adDomainRwdcFQDN -SearchBase $adDomainDN -Properties *
	
	# Determine The Amount Of Objects
	$allAuthSecurityPrincipalsCount = $null
	$allAuthSecurityPrincipalsCount = $allAuthSecurityPrincipals.Count
	
	# Determine The Length Of The Upper Value To Pad The Numbers So All Have The Same Width In The Output
	$lengthOfUpperValueTotalAccounts = $null
	$lengthOfUpperValueTotalAccounts = $allAuthSecurityPrincipalsCount.ToString().Length
	Logging "   # Total Objects Found......: $allAuthSecurityPrincipalsCount" "REMARK"
	Logging "" "REMARK"

	# For Every Account In The List
	Logging " > Processing All Objects..." "REMARK"
	Logging "" "REMARK"
	If ($allAuthSecurityPrincipals) {
		$allAuthSecurityPrincipals | %{
			#Increase The Counter
			$totalAccounts++
			
			# The AD Object
			$authSecurityPrincipal = $null
			$authSecurityPrincipal = $_
			
			# The sAMAccountName Of The Object
			$sAMAccountName = $null
			$sAMAccountName = $authSecurityPrincipal.SamAccountName
			
			# The Account Name Of The Object
			$accountName = $null
			$accountName = $adDomainNBT + "\" + $sAMAccountName

			# Trust Objects Are Using The User Object Class. However, To Make It Clear It Is A Trust Object Determine If As Such A Define It Accordingly
			# Otherwise Define The Object Class As Listed
			If ($sAMAccountName.EndsWith('$') -And $($authSecurityPrincipal.objectClass) -eq "user") {
				$accountType = "trust (user)"
			} Else {
				$accountType = $authSecurityPrincipal.objectClass
			}

			# Get The UserPrincipalName
			$userPrincipalName = $null
			If ($authSecurityPrincipal.UserPrincipalName) {
				$userPrincipalName = $authSecurityPrincipal.UserPrincipalName
			} Else {
				$userPrincipalName = "NOT CONFIGURED"
			}
			
			# Get The ObjectGuid
			$objectGuid = $null
			$objectGuid = $authSecurityPrincipal.ObjectGUID.Guid
			
			# Get The Display Name
			$displayName = $null
			If ($authSecurityPrincipal.DisplayName) {
				$displayName = $authSecurityPrincipal.DisplayName
			} Else {
				$displayName = "NOT CONFIGURED"
			}
			
			# Get The Account Enabled Or Disabled
			# UserAccountControl: ACCOUNTDISABLE (2, 0x0002)
			$accountIsEnabled = $null
			If ($($authSecurityPrincipal.userAccountControl -band 2) -eq 0) {
				$accountIsEnabled = $true
			} Else {
				$accountIsEnabled = $false
			}
			
			# Check If The Account Is Locked Or Unlocked
			$accountIsLocked = $null
			$accountLockoutFileTime = $null
			$accountLockoutFileTime = $authSecurityPrincipal.lockoutTime
			$accountLockoutDateTime = $null
			If ($accountLockoutFileTime -eq $null -Or $accountLockoutFileTime -eq "") {
				$accountIsLocked = "FALSE - Never Locked"
			} ElseIf ($accountLockoutFileTime -eq 0) {
				$accountIsLocked = "FALSE - Has Been Locked Before"
			} Else {
				$accountLockoutDateTime = Get-Date $([datetime]::fromFileTime($accountLockoutFileTime)) -Format "yyyy-MM-dd HH:mm:ss"
				$accountIsLocked = "TRUE - At: $accountLockoutDateTime"
			}

			# Get The Account Expiration Date/Time And Convert It From Filetime To Normal Date/Time
			$accountExpirationFileTime = $null
			$accountExpirationFileTime = $authSecurityPrincipal.accountExpires
			$accountExpirationDateTime = $null
			If ($accountExpirationFileTime -eq 0 -Or $accountExpirationFileTime -eq 9223372036854775807) {
				$accountExpirationDateTime = "NEVER"
			} Else {
				$accountExpirationDateTime = Get-Date $([datetime]::fromFileTime($accountExpirationFileTime)) -Format "yyyy-MM-dd HH:mm:ss"
			}

			# Get The Password Last Set Date/Time And Convert It From Filetime To Normal Date/Time
			$pwdLastSetFileTime = $null
			$pwdLastSetFileTime = $authSecurityPrincipal.pwdLastSet
			$pwdLastSetDateTime = $null
			If ($pwdLastSetFileTime -eq 0) {
				$pwdLastSetDateTime = "Must Chng At Next Logon"
			} Else {
				$pwdLastSetDateTime = Get-Date $([datetime]::fromFileTime($pwdLastSetFileTime)) -Format "yyyy-MM-dd HH:mm:ss"
			}

			# Check If The Account Has Password Never Expires
			# UserAccountControl: DONT_EXPIRE_PASSWD (65536, 0x10000) | Misc User Account Control Values https://support.microsoft.com/en-gb/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
			$accountPwdNeverExpires = $null
			If ($($authSecurityPrincipal.userAccountControl -band 65536) -eq 65536) {
				$accountPwdNeverExpires = $true
			} Else {
				$accountPwdNeverExpires = $false
			}

			# Get The Account Last Logon TimeStamp Date/Time And Convert It From Filetime To Normal Date/Time (Does Replicate)
			$accountLastLogonTimeStampFileTime = $null
			$accountLastLogonTimeStampFileTime = $authSecurityPrincipal.lastLogonTimestamp
			$accountLastLogonTimeStampDateTime = $null
			If ($accountLastLogonTimeStampFileTime) {
				$accountLastLogonTimeStampDateTime = Get-Date $([datetime]::fromFileTime($accountLastLogonTimeStampFileTime)) -Format "yyyy-MM-dd HH:mm:ss"
			} Else {
				$accountLastLogonTimeStampDateTime = "NEVER"
			}

			# Get The Account Last Logon Date/Time And Convert It From Filetime To Normal Date/Time (Specific Per RWDC And DOES NOT Replicate)
			$accountLastLogonDateTimeOnDCs = @()
			$adDomainDCsFQDN | %{
				$adDomainDCFQDN = $null
				$adDomainDCFQDN = $_
				$lastLogonOnDCFileTime = $null
				$lastLogonOnDCDateTime = $null
				
				# Check The Connection To The RWDC
				$ports = 389	# LDAP
				$connectionCheckOK = $true
				$ports | %{
					$port = $null
					$port = $_
					$connectionResult = $null
					$connectionResult = portConnectionCheck $adDomainDCFQDN $port 100
					If ($connectionResult -eq "ERROR") {
						$connectionCheckOK = $false
					}
				}
				If ($connectionCheckOK -eq $true) {
					Try {
						$lastLogonOnDCFileTime = (Get-ADObject -Identity $objectGuid -Server $adDomainDCFQDN -Properties lastLogon).lastLogon
					} Catch {
						$lastLogonOnDCFileTime = "FAILED/NOT AVAILABLE"
					}
					If ($lastLogonOnDCFileTime -eq "FAILED/NOT AVAILABLE") {
						$lastLogonOnDCDateTime = "FAILED/NOT AVAILABLE (on '$adDomainDCFQDN')"
					} ElseIf ($lastLogonOnDCFileTime -eq $null -Or $lastLogonOnDCFileTime -eq "" -Or $lastLogonOnDCFileTime -eq 0) {
						$lastLogonOnDCDateTime = "NEVER (on '$adDomainDCFQDN')"
					} Else {
						$lastLogonOnDCDateTime = "$(Get-Date $([datetime]::fromFileTime($lastLogonOnDCFileTime)) -Format 'yyyy-MM-dd HH:mm:ss') (On '$adDomainDCFQDN')"
					}
				} Else {
					$lastLogonOnDCDateTime = "FAILED/NOT AVAILABLE (on '$adDomainDCFQDN')"
				}
				$accountLastLogonDateTimeOnDCs += $lastLogonOnDCDateTime
			}
			$accountLastLogonDateTimeOnDCs = $accountLastLogonDateTimeOnDCs -join ",`n"

			# Display Some Info On Screen So That It Is Visible Something Is Happening
			Logging "   # $($totalAccounts.ToString().PadLeft($lengthOfUpperValueTotalAccounts, '0')) Of $allAuthSecurityPrincipalsCount - Processing Account '$adDomainFQDN\$sAMAccountName' ($accountType)..." "REMARK"
			Logging "" "REMARK"
			
			# Create An Object Entry For The Account And Add It To The Total List
			$accountEntry = New-Object -TypeName System.Object
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Domain FQDN" -Value $adDomainFQDN
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Domain NBT" -Value $adDomainNBT
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Domain DN" -Value $adDomainDN
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Sam Account Name" -Value $sAMAccountName
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Account Name" -Value $accountName
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Account Type" -Value $accountType
			$accountEntry | Add-Member -MemberType NoteProperty -Name "User Principal Name" -Value $userPrincipalName
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $displayName
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $accountIsEnabled
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Locked" -Value $accountIsLocked
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Account Expires On" -Value $accountExpirationDateTime
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Pwd Last Set On" -Value $pwdLastSetDateTime
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Pwd Never Expires" -Value $accountPwdNeverExpires
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Last Logon Timestamp" -Value $accountLastLogonTimeStampDateTime
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Last Logon (Per RWDC)" -Value $accountLastLogonDateTimeOnDCs
			$accountData += $accountEntry
		}
	} Else {
		Logging "" "REMARK"
		Logging " > What The Heck? No Objects? Looks Like It!..." "REMARK"
		Logging "" "REMARK"
	}

	# Define The End Execution Date And Time For This AD Domain
	$endExecDateTimeThisADDomain = $null
	$endExecDateTimeThisADDomain = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	
	# Calculate The Time Spent For This AD Domain
	$timeDiff = $null
	$timeDiff = (New-Timespan -Start $(Get-Date $startExecDateTimeThisADDomain) -End $(Get-Date $endExecDateTimeThisADDomain)).TotalMinutes	

	Logging "" "REMARK"
	Logging " > Finished Processing AD Domain '$adDomainFQDN'..." "REMARK"
	Logging " > Start Time...........: $startExecDateTimeThisADDomain" "REMARK"
	Logging " > End Time.............: $endExecDateTimeThisADDomain" "REMARK"
	Logging " > Duration (Minutes)...: $timeDiff" "REMARK"
	Logging "" "REMARK"
}

# Define The End Execution Date And Time
$execEndDateTimeDisplay = Get-Date -Format "yyyy-MM-dd_HH.mm.ss"
Logging "End Date/Time Script................................: $execEndDateTimeDisplay"
Logging ""

# Define The Location Of The Report
Logging "CSV Report AD Account Scan (Folder).................: $currentScriptFolderPath"
Logging "CSV Report AD Account Scan (File Name)..............: $outputCSVFileName"
Logging ""

# Define The Location Of The Log File
Logging "Log File AD Account Scan (Folder)...................: $currentScriptFolderPath"
Logging "Log File AD Account Scan (File Name)................: $logFileName"
Logging ""

# Sort The Table/List
#$accountDataSorted = $accountData | Sort-Object -Descending:$False -Property "Domain NBT","Account Type","Account Name"

# Export The Table/List To The CSV File
#$accountDataSorted | Export-Csv -Path $outputCSVFilePath -Force -NoTypeInformation
#$accountDataSorted | Out-GridView
$accountData | Export-Csv -Path $outputCSVFilePath -Force -NoTypeInformation
$accountData | Out-GridView
Write-Host ""
Write-Host "DONE!"
Write-Host ""