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
		* Service Principal Name(s) (e.g. <comma separated list of SPNs> or "No SPNs")
		* Acc Based Deleg Type (e.g. "No-Acc-Deleg" or "Acc-Unc-Deleg" or "Acc-Con-Deleg-AnyAuthN" or "Acc-Con-Deleg-KerbAuthN"
		* Acc Based Deleg To (e.g. <comma separated list of SPNs> or "No Delegated SPNs")
		* Res Based Deleg For (e.g. <comma separated list of user account names with type and domain listed> or "No-Res-Deleg")

.EXAMPLE
	Scan/Check All Accounts In The AD Forest And Create The Report

	.\Scan-And-Check-All-Accounts-In-AD-Forest_02_Delegation-Info.ps1

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

<#
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
#>

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ SCAN AND CHECK ALL ACCOUNTS IN AD FOREST - DELEGATION INFO +++"
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
$outputCSVFileName = $($execStartDateTimeCustom + "_" + $thisADForestRootDomain + "_Scan-And-Check-All-Accounts-In-AD-Forest_02_Delegation-Info.csv")
$outputCSVFilePath	= $currentScriptFolderPath + "\" + $outputCSVFileName
$logFileName = $($execStartDateTimeCustom + "_" + $thisADForestRootDomain + "_Scan-And-Check-All-Accounts-In-AD-Forest_02_Delegation-Info.log")
$logFilePath = $currentScriptFolderPath + "\" + $logFileName

Logging "" "HEADER"
Logging "                     **********************************************************************************" "HEADER"
Logging "                     *                                                                                *" "HEADER"
Logging "                     *       --> Scan And Check All Accounts In AD Forest - Delegation Info <--       *" "HEADER"
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

			# Check If The Account Has Based Kerberos Delegation Configured
			# TRUSTED_FOR_DELEGATION (524288, 0x80000) | Misc User Account Control Values https://support.microsoft.com/en-gb/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
			$accountIsTrustedForUnConstrainedDeleg = $null
			If ($($authSecurityPrincipal.userAccountControl -band 524288) -eq 524288) {
				$accountIsTrustedForUnConstrainedDeleg = $true
			} Else {
				$accountIsTrustedForUnConstrainedDeleg = $false
			}

			# Determine If Account Based Kerberos Delegation
			# TRUSTED_TO_AUTH_FOR_DELEGATION (16777216, 0x1000000) | Misc User Account Control Values https://support.microsoft.com/en-gb/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
			$accountIsTrustedForConstrainedDelegAnyAuthN = $null
			If ($($authSecurityPrincipal.userAccountControl -band 16777216) -eq 16777216) {
				$accountIsTrustedForConstrainedDelegAnyAuthN = $true
			} Else {
				$accountIsTrustedForConstrainedDelegAnyAuthN = $false
			}

			# Determine Account Delegation Type 
			$accountBasedDelegType = $null
			If ($accountIsTrustedForUnConstrainedDeleg -eq $true) {
				# Account Based Unconstrained Delegation
				$accountBasedDelegType = "Acc-Unc-Deleg"
			} ElseIf ($accountIsTrustedForConstrainedDelegAnyAuthN -eq $true) {
				# Account Based Constrained Delegation - Any AuthN
				$accountBasedDelegType = "Acc-Con-Deleg-AnyAuthN"
			} ElseIf ($accountIsTrustedForUnConstrainedDeleg -eq $false -And $accountIsTrustedForConstrainedDelegAnyAuthN -eq $false -And $authSecurityPrincipal."msDS-AllowedToDelegateTo" -ne $null) {
				# Account Based Constrained Delegation - Kerberos AuthN
				$accountBasedDelegType = "Acc-Con-Deleg-KerbAuthN"
			} Else {
				# No Account Based Constrained Delegation
				$accountBasedDelegType = "No-Acc-Deleg"
			}

			# Check If The Account Has SPNs Configured Or Not
			$spnList = $null
			$spnList = $authSecurityPrincipal.servicePrincipalName
			If ($spnList) {
				$spnList = $spnList -join ",`n"
			} Else {
				$spnList = "No SPNs"
			}

			# Check If The Account Has Constrained Delegation Configured For Services Or Not, And If Yes Which Services
			$accountBasedConstrainedDelegationToList = $null
			If ($authSecurityPrincipal."msDS-AllowedToDelegateTo") {
				$accountBasedConstrainedDelegationToList = $authSecurityPrincipal."msDS-AllowedToDelegateTo"
				$accountBasedConstrainedDelegationToList = $accountBasedConstrainedDelegationToList -join ",`n"
			} ElseIf ($accountIsTrustedForUnConstrainedDeleg -eq $true) {
				$accountBasedConstrainedDelegationToList = "Any Applicable SPN (!)"
			} Else {
				$accountBasedConstrainedDelegationToList = "No Delegated SPNs"
			}

			# Check If The Account Has Resource Based Delegation Configured Or Not, And If Yes, From Which Accounts
			$accountHasResourceBasedDelegationConfigured = $null
			$accountHasResourceBasedDelegationConfigured = $authSecurityPrincipal."msDS-AllowedToActOnBehalfOfOtherIdentity"
			If ($accountHasResourceBasedDelegationConfigured) {
				# Get The Accounts Having Resource Based Delegation On This Account
				$accountsDelegatedForThisResource = $null
				$accountsDelegatedForThisResource = $authSecurityPrincipal."msDS-AllowedToActOnBehalfOfOtherIdentity".Access.IdentityReference.Value
				
				# The List Of Accounts Having Resource Based Delegation On This Account, With Additional Information
				$accountsDelegatedForThisResourceList = @()
				
				# For Every Account Having Resource Based Delegation On This Account
				$accountsDelegatedForThisResource | %{
					# Account Having Resource Based Delegation On This Account
					$accountDelegatedForThisResource = $null
					$accountDelegatedForThisResource = $_
					
					# Get The NetBIOS Name Of The AD Domain Of The Account Having Resource Based Delegation On This Account
					$accountDelegatedForThisResourceFromADDomainNBT = $null
					$accountDelegatedForThisResourceFromADDomainNBT = $accountDelegatedForThisResource.SubString(0, $accountDelegatedForThisResource.IndexOf("\"))
					
					# Get The sAMAccountName Of The Account Having Resource Based Delegation On This Account
					$accountDelegatedForThisResourceAccountName = $null
					$accountDelegatedForThisResourceAccountName = $accountDelegatedForThisResource.SubString($accountDelegatedForThisResource.IndexOf("\") + 1)
					
					# Retrieve The AD Data Of The Object
					$accountDelegatedForThisResourceObject = $null
					$accountDelegatedForThisResourceObject = Get-ADObject -Filter "sAMAccountName -eq '$accountDelegatedForThisResourceAccountName'" -Server $accountDelegatedForThisResourceFromADDomainNBT
					
					# Get The Object Type/Class Of The Account Having Resource Based Delegation On This Account
					$accountDelegatedForThisResourceObjectClass = $null
					$accountDelegatedForThisResourceObjectClass = $accountDelegatedForThisResourceObject.ObjectClass
					
					# Get The DN Of The Account Having Resource Based Delegation On This Account
					$accountDelegatedForThisResourceDN = $null
					$accountDelegatedForThisResourceDN = $accountDelegatedForThisResourceObject.DistinguishedName
					
					# Get The FQDN Of The AD Domain Of The Account Having Resource Based Delegation On This Account
					$accountDelegatedForThisResourceFromADDomainFQDN = $null
					$accountDelegatedForThisResourceFromADDomainFQDN = $accountDelegatedForThisResourceDN.Substring($accountDelegatedForThisResourceDN.IndexOf("DC=")).Replace(",DC=",".").Replace("DC=","")
					
					# Add To The List Of Accounts Having Resource Based Delegation On This Account, With Additional Information
					$accountsDelegatedForThisResourceList += "$accountDelegatedForThisResource (Account Type: $accountDelegatedForThisResourceObjectClass) (AD Domain: $accountDelegatedForThisResourceFromADDomainFQDN)"
				}
				$accountsDelegatedForThisResourceList = $accountsDelegatedForThisResourceList -join ",`n"
			} Else {
				$accountsDelegatedForThisResourceList = "No-Res-Deleg"
			}

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
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Service Principal Name(s)" -Value $spnList
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Acc Based Deleg Type" -Value $accountBasedDelegType
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Acc Based Deleg To" -Value $accountBasedConstrainedDelegationToList
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Res Based Deleg For" -Value $accountsDelegatedForThisResourceList
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