### Abstract: This PoSH Script Scans And Checks All Accounts In The AD Forest And Creates A CSV Report And Outputs To GridView
### Written by: Jorge de Almeida Pinto [MVP-EMS]
### BLOG: http://jorgequestforknowledge.wordpress.com/
###
### 2019-10-27: Initial version of the script (v0.1)
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
		* DS Repl Chng Perms (e.g. "<comma separated list of domain DNs> (<Assigned Security Principal>)" or "No Perms")
		* DS Repl Chng All Perms (e.g. "<comma separated list of domain DNs> (<Assigned Security Principal>)" or "No Perms")
		* Migr SID History Perms (e.g. "<comma separated list of domain DNs> (<Assigned Security Principal>)" or "No Perms")

.EXAMPLE
	Scan/Check All Accounts In The AD Forest And Create The Report

	.\Scan-And-Check-All-Accounts-In-AD-Forest_03_NC-Level-Permissions-Info.ps1

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

### FUNCTION: Get Domain NC CAR Specific ACEs And Add To Hash Table
Function getDomainNCCarACEsForAccounts ($adDomainDN, $adDomainNBT, $adDomainRwdcFQDN, $adDomainDNACL, $carRightsGuid, $carRightsName, $carPermsHT) {
	# Defining Hash Table For The Specified CAR List Of Permissions Throughout The AD Forest To Start With The Existing Hash Table If Any
	$carPermsUpdatedHT = $carPermsHT
	
	# Retrieving The ACEs For Specified CAR
	$adDomainDNACEs = $null
	$adDomainDNACEs = $adDomainDNACL | ?{(($_.ActiveDirectoryRights.ToString().Split(",").Trim() -contains "ExtendedRight" -And ($_.ObjectType -eq $carRightsGuid -Or $_.ObjectType -eq "00000000-0000-0000-0000-000000000000")) -Or ($_.ActiveDirectoryRights.ToString() -eq "GenericAll" -And $_.ObjectType -eq "00000000-0000-0000-0000-000000000000"))}
	
	# Creating Hash Table With Accounts Having ACEs For The Specified CAR
	If ($adDomainDNACEs) {
		Logging " > Creating Hash Table With Accounts Having ACEs For '$carRightsName'..." "REMARK"
		Logging "" "REMARK"
		$adDomainDNACEs | %{
			# Identity/Account Name Referenced In The ACE (E.g. "<Domain>\<sAMAccountName>")
			$adDomainDNAceSecurityPrincipalAccount = $null
			$adDomainDNAceSecurityPrincipalAccount = $_.IdentityReference.ToString().Trim()

			# Based Upon The Security Principal Determine The NetBIOS Domain Name, The sAMAccountName And The Object Type/Class
			$adDomainDNAceSecurityPrincipalADDomainNBT = $null
			$adDomainDNAceSecurityPrincipalSamAccountName = $null
			$adDomainDNAceSecurityPrincipalObject = $null
			$adDomainDNAceSecurityPrincipalObjectType = $null
			If ($adDomainDNAceSecurityPrincipalAccount -ne "Everyone" -And $adDomainDNAceSecurityPrincipalAccount.IndexOf("\") -eq -1) {
				# Only If The Security Principal Does Not Have A \ In The Name
				# Just As A PlaceHolder For If This Happens
				
			} ElseIf ($adDomainDNAceSecurityPrincipalAccount.SubString(0, $adDomainDNAceSecurityPrincipalAccount.IndexOf("\")) -eq "BUILTIN") {
				# Determine The NetBIOS Domain Name
				$adDomainDNAceSecurityPrincipalADDomainNBT = $adDomainNBT

				# The sAMAccountName And The Object Type
				$adDomainDNAceSecurityPrincipalSamAccountName = $adDomainDNAceSecurityPrincipalAccount.SubString($adDomainDNAceSecurityPrincipalAccount.IndexOf("\") + 1)

				# Get The Object From AD
				$adDomainDNAceSecurityPrincipalObject = Get-ADObject -LDAPFilter "(sAMAccountName=$adDomainDNAceSecurityPrincipalSamAccountName)" -Server $adDomainRwdcFQDN -SearchBase $adDomainDN

				# Determine The Object Type/Class
				$adDomainDNAceSecurityPrincipalObjectType = $adDomainDNAceSecurityPrincipalObject.ObjectClass
				
			} ElseIf($adDomainDNAceSecurityPrincipalAccount -eq "NT AUTHORITY\Authenticated Users") {
				# Define The Object Class For These Well-Known Security Principals As Specified
				$adDomainDNAceSecurityPrincipalObjectType = "AuthEdUsers"
				
			} ElseIf($adDomainDNAceSecurityPrincipalAccount -eq "Everyone") {
				# Define The Object Class For These Well-Known Security Principals As Specified
				$adDomainDNAceSecurityPrincipalObjectType = "EVERYONE"
				
			} ElseIf($adDomainDNAceSecurityPrincipalAccount.IndexOf("\") -gt 0 -And $adDomainDNAceSecurityPrincipalAccount.SubString(0, $adDomainDNAceSecurityPrincipalAccount.IndexOf("\")) -ne "NT AUTHORITY" -And $adDomainDNAceSecurityPrincipalAccount.SubString(0, $adDomainDNAceSecurityPrincipalAccount.IndexOf("\")) -ne "NT BUILTIN") {
				# Determine The NetBIOS Domain Name
				$adDomainDNAceSecurityPrincipalADDomainNBT = $adDomainDNAceSecurityPrincipalAccount.SubString(0, $adDomainDNAceSecurityPrincipalAccount.IndexOf("\"))
				
				# The sAMAccountName And The Object Type
				$adDomainDNAceSecurityPrincipalSamAccountName = $adDomainDNAceSecurityPrincipalAccount.SubString($adDomainDNAceSecurityPrincipalAccount.IndexOf("\") + 1)
				
				# Get The Object From AD
				$adDomainDNAceSecurityPrincipalObject = Get-ADObject -LDAPFilter "(sAMAccountName=$adDomainDNAceSecurityPrincipalSamAccountName)" -Server $adDomainDNAceSecurityPrincipalADDomainNBT
				
				# Determine The Object Type/Class
				$adDomainDNAceSecurityPrincipalObjectType = $adDomainDNAceSecurityPrincipalObject.ObjectClass
			}

			$aceTypeApplied = $null
			# Only For These Specified Object Classes, Define It Is A Direct ACE For The Security Principal
			If ($securityPrincipalsThatCanAuthN -contains $adDomainDNAceSecurityPrincipalObjectType) {
				$aceTypeApplied = "Direct ACE For '$carRightsName'"
			}
			
			# Only For These Specified Object Classes, Define It Is A InDirect ACE For The Members Of The Security Principal
			If ($adDomainDNAceSecurityPrincipalObjectType -eq "AuthEdUsers") {
				$aceTypeApplied = "ACE Through 'AuthEd Users'"
			}
			
			# Only For These Specified Object Classes, Define It Is A InDirect ACE For The Members Of The Security Principal
			If ($adDomainDNAceSecurityPrincipalObjectType -eq "EVERYONE") {
				$aceTypeApplied = "ACE Through 'Everyone'"
			}
			
			# Only For These Specified Object Classes, Define It Is A InDirect ACE For The Members Of The Security Principal
			If ($adDomainDNAceSecurityPrincipalObjectType -eq "group") {
				$aceTypeApplied = "ACE Through '$adDomainDNAceSecurityPrincipalAccount'"
			}

			# Process For These Types/Classes Of Objects
			If ($securityPrincipalsThatCanAuthN -contains $adDomainDNAceSecurityPrincipalObjectType -Or $adDomainDNAceSecurityPrincipalObjectType -eq "AuthEdUsers" -Or $adDomainDNAceSecurityPrincipalObjectType -eq "EVERYONE") {
				# If The Hash Table Does Not Yet Include An Entry For The Security Principal, Then Add A New Entry
				# If The Hash Table Does Include An Entry For The Security Principal, Then Update The Existing Entry, But Only If The NC DN Is Not Already Listed
				If (!$carPermsUpdatedHT[$adDomainDNAceSecurityPrincipalAccount]) {
					# Create An Empty List For The Applicable NC DNs And Add The New NC
					$ncDNsWithCarAce = @()
					$ncDNsWithCarAce += $($adDomainDN + " (" + $aceTypeApplied + ")")

					# Update The Hash Table With The New Data
					$carPermsUpdatedHT[$adDomainDNAceSecurityPrincipalAccount] = $ncDNsWithCarAce
					
				} ElseIf ($carPermsUpdatedHT[$adDomainDNAceSecurityPrincipalAccount] -And $carPermsUpdatedHT[$adDomainDNAceSecurityPrincipalAccount] -notcontains $($adDomainDN + " (" + $aceTypeApplied + ")")) {
					# Create An Empty List For The Applicable NC DNs, Get The Existing NCs And Add The New NC
					$ncDNsWithCarAce = @()
					$carPermsUpdatedHT[$adDomainDNAceSecurityPrincipalAccount] | %{
						$ncDNsWithCarAce += $_
					}
					$ncDNsWithCarAce += $($adDomainDN + " (" + $aceTypeApplied + ")")
					
					# Update The Hash Table With The New Data
					$carPermsUpdatedHT[$adDomainDNAceSecurityPrincipalAccount] = $ncDNsWithCarAce
				}
			}
			
			# Process For These Types/Classes Of Objects
			If ($adDomainDNAceSecurityPrincipalObjectType -eq "group") {
				$adGroupMembers = $null
				# If The Security Principal Account Is Builtin Or From The AD Domain Being Processed, Then Recursively Retrieve The Group Members By Targeting The Corresponding RWDC
				# If The Security Principal Account From An AD Domain, Other Than The AD Domain Being Processed, Then Recursively Retrieve The Group Members By Targeting The AD Domain Itself To Find An RWDC
				If ($adDomainDNAceSecurityPrincipalADDomainNBT -eq $adDomainNBT) {
					$adGroupMembers = Get-ADGroupMember -Identity $adDomainDNAceSecurityPrincipalSamAccountName -Server $adDomainRwdcFQDN -Recursive
				} Else {
					$adGroupMembers = Get-ADGroupMember -Identity $adDomainDNAceSecurityPrincipalSamAccountName -Server $adDomainDNAceSecurityPrincipalADDomainNBT -Recursive
				}

				# If There Are Any Group Member, Then Process The Data For Every Group Member
				If ($adGroupMembers) {
					$adGroupMembers | %{
						# Get The DN Of The Group Member
						$adGroupMemberDN = $null
						$adGroupMemberDN = $_.distinguishedName

						# Get The FQDN Of The AD Domain Of The Group Member
						$adGroupMemberDomainFQDN = $null
						$adGroupMemberDomainFQDN = $adGroupMemberDN.SubString($adGroupMemberDN.IndexOf(",DC=") + 4).Replace(",DC=",".")

						# Get The sAMAccountName Of The Group Member
						$adGroupMemberSamAccountName = $null
						$adGroupMemberSamAccountName = $_.SamAccountName

						# Get The Object From AD By Querying AD
						$adGroupMemberAccount = $null
						$adGroupMemberAccount = (Get-ADObject -LDAPFilter "(sAMAccountName=$adGroupMemberSamAccountName)" -Server $adGroupMemberDomainFQDN -Properties "msDS-PrincipalName")."msDS-PrincipalName"

						# Create An Empty List For The Applicable NC DNs
						$ncDNsWithCarAce = @()
						
						# If The Hash Table Does Not Yet Include An Entry For The Security Principal, Then Add A New Entry
						# If The Hash Table Does Include An Entry For The Security Principal, Then Update The Existing Entry, But Only If The NC DN Is Not Already Listed
						If (!$carPermsUpdatedHT[$adGroupMemberAccount]) {
							# Create An Empty List For The Applicable NC DNs And Add The New NC
							$ncDNsWithCarAce = @()
							$ncDNsWithCarAce += $($adDomainDN + " (" + $aceTypeApplied + ")")

							# Update The Hash Table With The New Data
							$carPermsUpdatedHT[$adGroupMemberAccount] = $ncDNsWithCarAce
							
						} ElseIf ($carPermsUpdatedHT[$adGroupMemberAccount] -And $carPermsUpdatedHT[$adGroupMemberAccount] -notcontains $($adDomainDN + " (" + $aceTypeApplied + ")")) {
							# Create An Empty List For The Applicable NC DNs, Get The Existing NCs And Add The New NC
							$ncDNsWithCarAce = @()
							$carPermsUpdatedHT[$adGroupMemberAccount] | %{
								$ncDNsWithCarAce += $_
							}
							$ncDNsWithCarAce += $($adDomainDN + " (" + $aceTypeApplied + ")")
							
							# Update The Hash Table With The New Data
							$carPermsUpdatedHT[$adGroupMemberAccount] = $ncDNsWithCarAce
						}
					}
				}
			}
		}
	} Else {
		Logging " > There Are No ACEs For '$carRightsName' To Process..." "REMARK"
		Logging "" "REMARK"
	}

	Return $carPermsUpdatedHT
}

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ SCAN AND CHECK ALL ACCOUNTS IN AD FOREST - NC LEVEL PERMISSIONS INFO +++"
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
$outputCSVFileName = $($execStartDateTimeCustom + "_" + $thisADForestRootDomain + "_Scan-And-Check-All-Accounts-In-AD-Forest_03_NC-Level-Permissions-Info.csv")
$outputCSVFilePath	= $currentScriptFolderPath + "\" + $outputCSVFileName
$logFileName = $($execStartDateTimeCustom + "_" + $thisADForestRootDomain + "_Scan-And-Check-All-Accounts-In-AD-Forest_03_NC-Level-Permissions-Info.log")
$logFilePath = $currentScriptFolderPath + "\" + $logFileName

Logging "" "HEADER"
Logging "                     **********************************************************************************" "HEADER"
Logging "                     *                                                                                *" "HEADER"
Logging "                     *  --> Scan And Check All Accounts In AD Forest - NC Level Permissions Info <--  *" "HEADER"
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
$script:securityPrincipalsThatCanAuthN = @()
$script:securityPrincipalsThatCanAuthN += "user"
$script:securityPrincipalsThatCanAuthN += "computer"
$script:securityPrincipalsThatCanAuthN += "msDS-GroupManagedServiceAccount"
$script:securityPrincipalsThatCanAuthN += "inetOrgPerson"

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

### Create Mapping HashTable Between Control Access Right displayName And rightsGuid, And Also Between Control Access Right rightsGuid And displayName
$mappingTable_CAR_displayName_rightsGuidHT = @{} # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!
$mappingTable_CAR_rightsGuid_displayNameHT = @{} # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!
$DAPDisplayNameWithRightsGuidCAR = Get-ADObject -SearchBase $adForestConfigNC -LDAPFilter "(&(objectClass=controlAccessRight)(rightsGuid=*)(validAccesses=256))" -Properties displayName,rightsGuid -Server $adRwdcFQDN | Select-Object displayName,rightsGuid
$DAPDisplayNameWithRightsGuidCAR | %{
	$mappingTable_CAR_displayName_rightsGuidHT[$_.displayName] = $_.rightsGuid
	$mappingTable_CAR_rightsGuid_displayNameHT[$_.rightsGuid] = $_.displayName
}
$carDSReplChangesDisplayName = "Replicating Directory Changes"
$carDSReplChangesRightsGuid = $mappingTable_CAR_displayName_rightsGuidHT[$carDSReplChangesDisplayName]
$carDSReplChangesAllDisplayName = "Replicating Directory Changes All"
$carDSReplChangesAllRightsGuid = $mappingTable_CAR_displayName_rightsGuidHT[$carDSReplChangesAllDisplayName]
$carMigSidHistDisplayName = "Migrate SID History"
$carMigSidHistRightsGuid = $mappingTable_CAR_displayName_rightsGuidHT[$carMigSidHistDisplayName]

### Defining (Empty) Hash Table For The DS Replicating Changes List Of Permissions Throughout The AD Forest
$dsReplChangesPermsHT = New-Object System.Collections.Hashtable # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!

### Defining (Empty) Hash Table For The DS Replicating Changes All List Of Permissions Throughout The AD Forest
$dsReplChangesAllPermsHT = New-Object System.Collections.Hashtable # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!

### Defining (Empty) Hash Table For The Migrate SidHistory List Of Permissions Throughout The AD Forest
$migSidHistPermsHT = New-Object System.Collections.Hashtable # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!

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

### For Every AD Domain In The AD Forest, Retrieve And Build List For:
# * 'DS Repl Changes' Permissions On AD Domain NCs
# * 'DS Repl Changes All' Permissions On AD Domain NCs
# * 'Migrate sIDHistory' Permissions On AD Domain NCs
$adDomainFQDNList | %{
	# AD Domain FQDN
	$adDomainFQDN = $null
	$adDomainFQDN = $_

	# RWDC For The AD Domain
	$adDomainRwdcFQDN = $null
	$adDomainRwdcFQDN = ((Get-ADDomainController -Domain $adDomainFQDN -Discover).HostName)[0]

	# AD Domain Object
	$adDomain = $null
	$adDomain = Get-ADDomain $adDomainFQDN -Server $adDomainRwdcFQDN

	# AD Domain NetBIOS Name
	$adDomainNBT = $null
	$adDomainNBT = $adDomain.NetBIOSName

	# AD Domain DN
	$adDomainDN = $null
	$adDomainDN = $adDomain.DistinguishedName

	# Display The Start Of Processing Certain AD Domain
	Logging "" "REMARK"
	Logging "Starting Building Lists For AD Domain '$adDomainFQDN ($adDomainDN) ($adDomainRwdcFQDN)'..." "REMARK"
	Logging "> Please Be Patient, It May Take Some Time Depending On The Amount Of Objects To Process <" "REMARK"
	Logging "" "REMARK"
	
	# Create PowerShell Drive For The Corresponding AD Domain. Using The Default Drive (AD:) Only Works For The Domain The User Account Executing The Script Is In
	$psDriveADDSName = "ADDS"
	$psDriveADDS = Get-PSDrive $psDriveADDSName -ErrorAction SilentlyContinue
	If ($psDriveADDS) {
		Remove-PSDrive $psDriveADDSName -Force
	}
	New-PSDrive -Name $psDriveADDSName -PSProvider "ActiveDirectory" -Root "//RootDSE/" -Server $adDomainRwdcFQDN | Out-Null

	# Retrieving The ACL From The AD Domain NC DN
	$adDomainDNACL = $null
	$adDomainDNACL = (Get-Acl "$psDriveADDSName`:\$adDomainDN").access

	# Delete PowerShell Drive For The Corresponding AD Domain
	$psDriveADDSName = "ADDS"
	$psDriveADDS = Get-PSDrive $psDriveADDSName -ErrorAction SilentlyContinue
	If ($psDriveADDS) {
		Remove-PSDrive $psDriveADDSName -Force | Out-Null
	}
	
	# Update Hash Table For The DS Replicating Changes List Of Permissions
	$dsReplChangesPermsHT = getDomainNCCarACEsForAccounts $adDomainDN $adDomainNBT $adDomainRwdcFQDN $adDomainDNACL $carDSReplChangesRightsGuid $carDSReplChangesDisplayName $dsReplChangesPermsHT

	# Update Hash Table For The DS Replicating Changes All List Of Permissions
	$dsReplChangesAllPermsHT = getDomainNCCarACEsForAccounts $adDomainDN $adDomainNBT $adDomainRwdcFQDN $adDomainDNACL $carDSReplChangesAllRightsGuid $carDSReplChangesAllDisplayName $dsReplChangesAllPermsHT

	# Update Hash Table For The Migrate SID History List Of Permissions
	$migSidHistPermsHT = getDomainNCCarACEsForAccounts $adDomainDN $adDomainNBT $adDomainRwdcFQDN $adDomainDNACL $carMigSidHistRightsGuid $carMigSidHistDisplayName $migSidHistPermsHT
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

			# Check If The Account Has DS Replicating Changes Permissions On Some AD Domain DN
			$accountHasDSReplChng = $null
			$domainDNListForDSReplChng = $null
			If ($dsReplChangesPermsHT[$accountName]) {
				$domainDNListForDSReplChng = $dsReplChangesPermsHT[$accountName]
				$accountHasDSReplChng = $domainDNListForDSReplChng -join ",`n"
			} Else {
				$accountHasDSReplChng = "No Perms"
			}
			
			# Check If The Account Has DS Replicating Changes All Permissions On Some AD Domain DN
			$accountHasDSReplChngAll = $null
			$domainDNListForDSReplChngAll = $null
			If ($dsReplChangesAllPermsHT[$accountName]) {
				$domainDNListForDSReplChngAll = $dsReplChangesAllPermsHT[$accountName]
				$accountHasDSReplChngAll = $domainDNListForDSReplChngAll -join ",`n"
			} Else {
				$accountHasDSReplChngAll = "No Perms"
			}
			
			# Check If The Account Has Migrate SidHistory Permissions On Some AD Domain DN
			$accountHasMigSidHist = $null
			$domainDNListForMigSidHist = $null
			If ($migSidHistPermsHT[$accountName]) {
				$domainDNListForMigSidHist = $migSidHistPermsHT[$accountName]
				$accountHasMigSidHist = $domainDNListForMigSidHist -join ",`n"
			} Else {
				$accountHasMigSidHist = "No Perms"
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
			$accountEntry | Add-Member -MemberType NoteProperty -Name "DS Repl Chng Perms" -Value $accountHasDSReplChng
			$accountEntry | Add-Member -MemberType NoteProperty -Name "DS Repl Chng All Perms" -Value $accountHasDSReplChngAll
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Migr SID History Perms" -Value $accountHasMigSidHist
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