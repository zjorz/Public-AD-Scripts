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
		* Prot Group Membership (e.g. <comma separated list of group account names> or "No Memberships")
			REMARK: With protected groups, the focus is ONLY on default AD Protected Groups (e.g. BUILTIN\Administrators", "<DOMAIN>\Domain Admins", etc.)
			REMARK: if protected groups are listed then any ACEs for those protected groups are NOT listed to prevent an overload of ACEs
		* ACE On AdminSDHolder (e.g. <comma separated list of objects with configured permissions> or "No ACEs")
			REMARK: If protected groups are listed then any ACEs for those protected groups are NOT listed to prevent an overload of ACEs
			REMARK: It will only look at explicit defined ACEs. Inherited ACEs are NOT listed to prevent an overload of ACEs
		* Powerful ACEs On Objects (e.g. <comma separated list of objects with configured permissions> or "No ACEs")
			REMARK: If protected groups are listed then any ACEs for those protected groups are NOT listed to prevent an overload of ACEs
			REMARK: It will only look at explicit defined ACEs. Inherited ACEs are NOT listed to prevent an overload of ACEs

.EXAMPLE
	Scan/Check All Accounts In The AD Forest And Create The Report

	.\Scan-And-Check-All-Accounts-In-AD-Forest_04_Object-Level-Permissions-Info.ps1

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

### FUNCTION: Get Permissions List For Accounts And Add To Array List Of Permissions
Function getPermissionsListForAccounts($objectCN, $objectACL, $adDomainDN, $adDomainNBT, $adDomainRwdcFQDN, $objectsPermsArr) {
	# Defining Array For The List Of Permissions Throughout The AD Forest To Start With The Existing Array If Any
	$objectsPermsUpdatedArr = @()
	If ($objectsPermsArr) {
		$objectsPermsArr | %{
			$objectsPermsUpdatedArr += $_
		}
	}

	# Scope The Allow ACEs Within The DACL Of The Object And Only look For Specific Allow ACEs
	$objectACLInScope = $null
	$objectACLInScope = $objectACL | ?{ `
		$_.AccessControlType -eq "Allow" -And `
		$_.IsInherited -eq $false -And `
			($_.ActiveDirectoryRights.ToString() -eq "GenericAll" -Or `
			($_.ActiveDirectoryRights.ToString() -eq "ExtendedRight" -And $_.ObjectType -eq $carResetPwdRightsGuid) -Or `
			($_.ActiveDirectoryRights.ToString().Split(",").Trim() -contains "ExtendedRight" -And $_.ObjectType -eq "00000000-0000-0000-0000-000000000000") -Or `
			($_.ActiveDirectoryRights.ToString().Split(",").Trim() -contains "WriteOwner" -And $_.ObjectType -eq "00000000-0000-0000-0000-000000000000") -Or `
			($_.ActiveDirectoryRights.ToString().Split(",").Trim() -contains "WriteDacl" -And $_.ObjectType -eq "00000000-0000-0000-0000-000000000000") -Or `
			($_.ActiveDirectoryRights.ToString().Split(",").Trim() -contains "WriteProperty" -And $_.ObjectType -eq "00000000-0000-0000-0000-000000000000") -Or `
			($_.ActiveDirectoryRights.ToString().Split(",").Trim() -contains "WriteProperty" -And $_.ObjectType -eq $mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT["lockoutTime"]) -Or `
			($_.ActiveDirectoryRights.ToString().Split(",").Trim() -contains "WriteProperty" -And $_.ObjectType -eq $mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT["member"]) -Or `
			($_.ActiveDirectoryRights.ToString().Split(",").Trim() -contains "WriteProperty" -And $_.ObjectType -eq $mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT["msDS-AllowedToDelegateTo"]) -Or `
			($_.ActiveDirectoryRights.ToString().Split(",").Trim() -contains "WriteProperty" -And $_.ObjectType -eq $mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT["msDS-AllowedToActOnBehalfOfOtherIdentity"]) -Or `
			($_.ActiveDirectoryRights.ToString().Split(",").Trim() -contains "WriteProperty" -And $_.ObjectType -eq $mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT["servicePrincipalName"]) -Or `
			($_.ActiveDirectoryRights.ToString().Split(",").Trim() -contains "WriteProperty" -And $_.ObjectType -eq $mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT["userAccountControl"]))}

	# Scope The ACEs For Specific Security Principals.
	# OK If: "<Security Principal>" Equals "NT AUTHORITY\Authenticated Users"
	# OR
	# OK If: "<Security Principal>" Equals "Everyone"
	# OR
	# OK If: "<Security Principal>" Contains "\" And 
	#			("<Security Principal>" Starts With "BuiltIn\*" Or "<Security Principal>" Starts With "<NetBIOS Name>\" Or "<Security Principal>" Starts With "<DNS Name>\") And 
	#			Protected Groups List Does Not Contain <Security Principal>
	$objectACLInScope | ?{( `
		$_.IdentityReference.ToString() -eq "NT AUTHORITY\Authenticated Users" -Or `
		$_.IdentityReference.ToString() -eq "Everyone" -Or `
		($($_.IdentityReference.ToString()).IndexOf("\") -gt 0 -And `
			($_.IdentityReference.ToString() -like "BUILTIN\*" -Or `
				$adDomainNBTList -contains $($_.IdentityReference.ToString()).SubString(0, $($_.IdentityReference.ToString()).IndexOf("\")) -Or `
				$adDomainFQDNList -contains $($_.IdentityReference.ToString()).SubString(0, $($_.IdentityReference.ToString()).IndexOf("\"))) -And `
			$($secPrincipal = $null;$secPrincipal = $_.IdentityReference.ToString();If ($protectedGroups | ?{$_ -like "*$($secPrincipal.Substring($secPrincipal.IndexOf('\')))"}) {$false} Else {$true})))} | %{

		# An ACE On The Object
		$ace = $null
		$ace = $_
		
		# The Security Principal Specified In the ACE
		$objectDNSecurityPrincipalAccount = $null
		$objectDNSecurityPrincipalAccount = $ace.IdentityReference.ToString()
		
		# Build List Of AD Rights Specified In The ACE
		$objectDNADRights = @()
		$ace.ActiveDirectoryRights.ToString().Split(",").Trim() | ?{$adRightsOfInterest -contains $_} | %{$objectDNADRights += $_}

		# The Inheritance Type From This Parent Object To Lower Level Objects
		$objectDNInheritType = $null
		$objectDNInheritType = $ace.InheritanceType
		
		# Translate The Guid Into A Name Of A Attribute, Property Set Or Control Access Right
		# "00000000-0000-0000-0000-000000000000" --> All Attributes, Property Sets And Control Access Rights
		# $mappingTable_SCHEMA_schemaIDGUID_lDAPDisplayNameHT --> Hash Table To Translate schemaIDGUID Value To (Pretty) The Targeted Attribute Display Name
		# $mappingTable_PROPSET_rightsGuid_displayNameHT --> Hash Table To Translate rightsGuid Value To (Pretty) The Targeted Property Set Display Name
		# $mappingTable_CAR_rightsGuid_displayNameHT --> Hash Table To Translate rightsGuid Value To (Pretty) lDAPDisplayName Of The Targeted Control Access Right Display Name
		$objectDNObjectType = $null
		If ($ace.ObjectType.ToString() -eq "00000000-0000-0000-0000-000000000000") {
			# For All Attributes, Property Sets And Control Access Rights
			$objectDNObjectType = "All"
			
		} Else {
			# For Specific Attributes, Property Sets And Control Access Rights
			# Try First To Translate It As A schemaIDGUID To An Attribute Display Name
			$objectDNObjectType = $mappingTable_SCHEMA_schemaIDGUID_lDAPDisplayNameHT[$ace.ObjectType.ToString()]
			If (!$objectDNObjectType) {
				# If That Does Not Return Anything, Then Try To Translate It As A rightsGuid To A Property Set Display Name
				$objectDNObjectType = $mappingTable_PROPSET_rightsGuid_displayNameHT[$ace.ObjectType.ToString()]
				
				If (!$objectDNObjectType) {
					# If That Does Not Return Anything, Then Try To Translate It As A rightsGuid To A Control Access Right Display Name
					$objectDNObjectType = $mappingTable_CAR_rightsGuid_displayNameHT[$ace.ObjectType.ToString()]
					If (!$objectDNObjectType) {
						# If That Does Not Return Anything, Then Something Is Wrong!
						$objectDNObjectType = "Damn! This Should Not Happen!"
					}
				}
			}
		}

		# Translate The Guid Into A Name Of An Object Class
		# "00000000-0000-0000-0000-000000000000" --> All Object Classes
		# $mappingTable_SCHEMA_schemaIDGUID_lDAPDisplayNameHT --> Hash Table To Translate schemaIDGUID Value To (Pretty) The Targeted Object Class Display Name
		$objectDNInheritedObjectType = $null
		If ($ace.InheritedObjectType.ToString() -eq "00000000-0000-0000-0000-000000000000") {
			# For All Object Classes
			If ($objectDNInheritType -eq "All" -Or $objectDNInheritType -eq "Descendents") {
				# All Objects (This And Descendent) Or Only Only Descendent Objects
				$objectDNInheritedObjectType = "All"
			}
			If ($objectDNInheritType -eq "None") {
				# No Descendent Objects, This Object Only
				$objectDNInheritedObjectType = "This Object"
			}
		} Else {
			# For Specific  Object Classes
			$objectDNInheritedObjectType = $mappingTable_SCHEMA_schemaIDGUID_lDAPDisplayNameHT[$ace.InheritedObjectType.ToString()]
		}

		# For The Listed Security Principal In The ACE Retrieve The AD Domain NetBIOS Name, The sAMAccountName And The Object Class
		$objectDNSecurityPrincipalADDomainNBT = $null
		$objectDNSecurityPrincipalSamAccountName = $null
		$objectDNSecurityPrincipalObject = $null
		$objectDNSecurityPrincipalObjectType = $null
		If ($objectDNSecurityPrincipalAccount -ne "Everyone" -And $objectDNSecurityPrincipalAccount.IndexOf("\") -eq -1) {
			# Only If The Security Principal Does Not Have A \ In The Name
			# Just As A PlaceHolder For If This Happens

		} ElseIf ($objectDNSecurityPrincipalAccount.SubString(0, $objectDNSecurityPrincipalAccount.IndexOf("\")) -eq "BUILTIN") {
			# Only If The Security Principal Is A Well-Known Security Principal
			
			# Define The Local AD Domain NetBIOS Name For The Security Principal
			$objectDNSecurityPrincipalADDomainNBT = $adDomainNBT
			
			# Retrieve The sAMAccountName Of The Security Principal
			$objectDNSecurityPrincipalSamAccountName = $objectDNSecurityPrincipalAccount.SubString($objectDNSecurityPrincipalAccount.IndexOf("\") + 1)
			
			# Retrieve The AD Data Of The Security Principal
			$objectDNSecurityPrincipalObject = Get-ADObject -LDAPFilter "(sAMAccountName=$objectDNSecurityPrincipalSamAccountName)" -Server $adDomainRwdcFQDN -SearchBase $adDomainDN
			
			# Determine The Object Class Of The Security Principal
			$objectDNSecurityPrincipalObjectType = $objectDNSecurityPrincipalObject.ObjectClass
		} ElseIf($objectDNSecurityPrincipalAccount -eq "NT AUTHORITY\Authenticated Users") {
			# Define The Object Class For These Well-Known Security Principals As Specified
			$objectDNSecurityPrincipalObjectType = "AuthEdUsers"
			
		} ElseIf($objectDNSecurityPrincipalAccount -eq "Everyone") {
			# Define The Object Class For These Well-Known Security Principals As Specified
			$objectDNSecurityPrincipalObjectType = "EVERYONE"
			
		} ElseIf($objectDNSecurityPrincipalAccount.IndexOf("\") -gt 0 -And $objectDNSecurityPrincipalAccount.SubString(0, $objectDNSecurityPrincipalAccount.IndexOf("\")) -ne "NT AUTHORITY" -And $objectDNSecurityPrincipalAccount.SubString(0, $objectDNSecurityPrincipalAccount.IndexOf("\")) -ne "NT BUILTIN") {
			# Retrieve The AD Domain NetBIOS Name Of The Security Principal
			$objectDNSecurityPrincipalADDomainNBT = $objectDNSecurityPrincipalAccount.SubString(0, $objectDNSecurityPrincipalAccount.IndexOf("\"))
			
			# Retrieve The sAMAccountName Of The Security Principal
			$objectDNSecurityPrincipalSamAccountName = $objectDNSecurityPrincipalAccount.SubString($objectDNSecurityPrincipalAccount.IndexOf("\") + 1)
			
			# Retrieve The AD Data Of The Security Principal
			$objectDNSecurityPrincipalObject = Get-ADObject -LDAPFilter "(sAMAccountName=$objectDNSecurityPrincipalSamAccountName)" -Server $objectDNSecurityPrincipalADDomainNBT
			
			# Determine The Object Class Of The Security Principal
			$objectDNSecurityPrincipalObjectType = $objectDNSecurityPrincipalObject.ObjectClass
		}

		# Building The Permissions List For The ACE
		$permissions = @()
		# For Every Right In The ACE Process This As There Might Be More Than 1
		$objectDNADRights | %{
			# Define The Right
			$objectDNADRight = $null
			$objectDNADRight = "RIGHT: " + $_
			$aceTypeApplied = $null
			
			# Only For These Specified Object Classes, Define It Is A Direct ACE For The Security Principal
			If ($securityPrincipalsThatCanAuthN -contains $objectDNSecurityPrincipalObjectType) {
				$aceTypeApplied = "Direct ACE"
			}
			
			# Only For These Specified Object Classes, Define It Is A InDirect ACE For The Members Of The Security Principal
			If ($objectDNSecurityPrincipalObjectType -eq "AuthEdUsers") {
				$aceTypeApplied = "ACE Through 'AuthEd Users'"
			}
			
			# Only For These Specified Object Classes, Define It Is A InDirect ACE For The Members Of The Security Principal
			If ($objectDNSecurityPrincipalObjectType -eq "EVERYONE") {
				$aceTypeApplied = "ACE Through 'Everyone'"
			}
			
			# Only For These Specified Object Classes, Define It Is A InDirect ACE For The Members Of The Security Principal
			If ($objectDNSecurityPrincipalObjectType -eq "group") {
				$aceTypeApplied = "ACE Through '$objectDNSecurityPrincipalAccount'"
			}
			
			# Define The Permission And Add It To The List
			$permissions += "Object CN: " + $objectCN + "||" + $aceTypeApplied + "||" + $objectDNADRight + ":" + $objectDNObjectType + "|INHERITTYPE: " + $objectDNInheritType + ":" + $objectDNInheritedObjectType
		}

		# Process It Like This For The Specified Objects Types/Classes
		If ($securityPrincipalsThatCanAuthN -contains $objectDNSecurityPrincipalObjectType -Or $objectDNSecurityPrincipalObjectType -eq "AuthEdUsers" -Or $objectDNSecurityPrincipalObjectType -eq "EVERYONE") {
			If (($objectsPermsUpdatedArr | ?{$_."Account Name" -eq $objectDNSecurityPrincipalAccount}).Count -eq 0) {
				# Create A New Object Entry For The Account And Add It To The Total List
				$accountEntry = New-Object -TypeName System.Object
				$accountEntry | Add-Member -MemberType NoteProperty -Name "Account Name" -Value $objectDNSecurityPrincipalAccount
				$accountEntry | Add-Member -MemberType NoteProperty -Name "Effective Permissions" -Value $permissions
				$objectsPermsUpdatedArr += $accountEntry
				
			} ElseIf (($objectsPermsUpdatedArr | ?{$_."Account Name" -eq $objectDNSecurityPrincipalAccount}).Count -gt 0) {
				# Update The Object Entry For The Account And Add Additional Permissions To The Total List If Not Already Available
				$permissions | %{
					$permission = $null
					$permission = $_
					If (($objectsPermsUpdatedArr | ?{$_."Account Name" -eq $objectDNSecurityPrincipalAccount})."Effective Permissions" -notcontains $permission) {
						($objectsPermsUpdatedArr | ?{$_."Account Name" -eq $objectDNSecurityPrincipalAccount})."Effective Permissions" += $_
					}
				}
			}
		}
		
		# Process It Like This For The Specified Objects Types/Classes
		If ($objectDNSecurityPrincipalObjectType -eq "group") {
			$adGroupMembers = $null
			# If The Security Principal Account Is Builtin Or From The AD Domain Being Processed, Then Recursively Retrieve The Group Members By Targeting The Corresponding RWDC
			# If The Security Principal Account From An AD Domain, Other Than The AD Domain Being Processed, Then Recursively Retrieve The Group Members By Targeting The AD Domain Itself To Find An RWDC
			If ($objectDNSecurityPrincipalADDomainNBT -eq $adDomainNBT) {
				$adGroupMembers = Get-ADGroupMember -Identity $objectDNSecurityPrincipalSamAccountName -Server $adDomainRwdcFQDN -Recursive
			} Else {
				$adGroupMembers = Get-ADGroupMember -Identity $objectDNSecurityPrincipalSamAccountName -Server $objectDNSecurityPrincipalADDomainNBT -Recursive
			}
			
			# If There Are Any Group Members
			If ($adGroupMembers) {
				# For Any Group Member
				$adGroupMembers | %{
					# Get The DN Of The Group Member
					$adGroupMemberDN = $null
					$adGroupMemberDN = $_.distinguishedName
					
					# Determine The FQDN Of The AD Domain Of The Group Member
					$adGroupMemberDomainFQDN = $null
					$adGroupMemberDomainFQDN = $adGroupMemberDN.SubString($adGroupMemberDN.IndexOf(",DC=") + 4).Replace(",DC=",".")
					
					# Get The sAMAccountName Of The Group Member
					$adGroupMemberSamAccountName = $null
					$adGroupMemberSamAccountName = $_.SamAccountName
					
					# Retrieve The AD Data Of The Group Member
					$adGroupMemberAccount = $null
					$adGroupMemberAccount = (Get-ADObject -LDAPFilter "(sAMAccountName=$adGroupMemberSamAccountName)" -Server $adGroupMemberDomainFQDN -Properties "msDS-PrincipalName")."msDS-PrincipalName"
					
					If (($objectsPermsUpdatedArr | ?{$_."Account Name" -eq $adGroupMemberAccount}).Count -eq 0) {
						# Create A New Object Entry For The Account And Add It To The Total List
						$accountEntry = New-Object -TypeName System.Object
						$accountEntry | Add-Member -MemberType NoteProperty -Name "Account Name" -Value $adGroupMemberAccount
						$accountEntry | Add-Member -MemberType NoteProperty -Name "Effective Permissions" -Value $permissions
						$objectsPermsUpdatedArr += $accountEntry
						
					} ElseIf (($objectsPermsUpdatedArr | ?{$_."Account Name" -eq $adGroupMemberAccount}).Count -gt 0) {
						# Update The Object Entry For The Account And Add Additional Permissions To The Total List If Not Already Available
						$permissions | %{
							$permission = $null
							$permission = $_
							If (($objectsPermsUpdatedArr | ?{$_."Account Name" -eq $adGroupMemberAccount})."Effective Permissions" -notcontains $permission) {
								($objectsPermsUpdatedArr | ?{$_."Account Name" -eq $adGroupMemberAccount})."Effective Permissions" += $_
							}
						}
					}
				}
			}
		}
	}
	
	Return $objectsPermsUpdatedArr
}

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ SCAN AND CHECK ALL ACCOUNTS IN AD FOREST - OBJECT LEVEL PERMISSIONS INFO +++"
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
$outputCSVFileName = $($execStartDateTimeCustom + "_" + $thisADForestRootDomain + "_Scan-And-Check-All-Accounts-In-AD-Forest_04_Object-Level-Permissions-Info.csv")
$outputCSVFilePath	= $currentScriptFolderPath + "\" + $outputCSVFileName
$logFileName = $($execStartDateTimeCustom + "_" + $thisADForestRootDomain + "_Scan-And-Check-All-Accounts-In-AD-Forest_04_Object-Level-Permissions-Info.log")
$logFilePath = $currentScriptFolderPath + "\" + $logFileName

Logging "" "HEADER"
Logging "                     **********************************************************************************" "HEADER"
Logging "                     *                                                                                *" "HEADER"
Logging "                     *--> Scan And Check All Accounts In AD Forest - Object Level Permissions Info <--*" "HEADER"
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

### Create Mapping HashTable Between Control Access Right displayName And rightsGuid, And Also Between Control Access Right rightsGuid And displayName
$script:mappingTable_CAR_displayName_rightsGuidHT = @{} # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!
$script:mappingTable_CAR_rightsGuid_displayNameHT = @{} # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!
$DAPDisplayNameWithRightsGuidCAR = Get-ADObject -SearchBase $adForestConfigNC -LDAPFilter "(&(objectClass=controlAccessRight)(rightsGuid=*)(validAccesses=256))" -Properties displayName,rightsGuid -Server $adRwdcFQDN | Select-Object displayName,rightsGuid
$DAPDisplayNameWithRightsGuidCAR | %{
	$script:mappingTable_CAR_displayName_rightsGuidHT[$_.displayName] = $_.rightsGuid
	$script:mappingTable_CAR_rightsGuid_displayNameHT[$_.rightsGuid] = $_.displayName
}
$carResetPwdDisplayName = "Reset Password"
$carResetPwdRightsGuid = $mappingTable_CAR_displayName_rightsGuidHT[$carResetPwdDisplayName]

### Create Mapping HashTable Between Property Sets rightsGuid And displayName
$script:mappingTable_PROPSET_rightsGuid_displayNameHT = @{} # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!
$DAPDisplayNameWithRightsGuidPROPSET = Get-ADObject -SearchBase $adForestConfigNC -LDAPFilter "(&(objectClass=controlAccessRight)(rightsGuid=*)(validAccesses=48))" -Properties displayName,rightsGuid -Server $adRwdcFQDN | Select-Object displayName,rightsGuid
$DAPDisplayNameWithRightsGuidPROPSET | %{
	$script:mappingTable_PROPSET_rightsGuid_displayNameHT[$_.rightsGuid] = $_.displayName
}

### Create Mapping HashTable Between Validated Write rightsGuid And displayName NOT NEEDED!
#$script:mappingTable_VALWRITE_rightsGuid_displayNameHT = @{} # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!
#$DAPDisplayNameWithRightsGuid = Get-ADObject -SearchBase $adForestConfigNC -LDAPFilter "(&(objectClass=controlAccessRight)(rightsGuid=*)(validAccesses=8))" -Properties displayName,rightsGuid -Server $adRwdcFQDN | Select-Object displayName,rightsGuid
#$DAPDisplayNameWithRightsGuid | %{
#	$script:mappingTable_VALWRITE_rightsGuid_displayNameHT[$_.rightsGuid] = $_.displayName
#}

### Create Mapping HashTable Between schemaIDGUID And lDAPDisplayName, And Also Between Control lDAPDisplayName And schemaIDGUID
$script:mappingTable_SCHEMA_schemaIDGUID_lDAPDisplayNameHT = @{} # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!
$script:mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT = @{} # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!
$schemaIDGUIDsWithLDAPDisplayName = Get-ADObject -SearchBase $adForestSchemaNC -LDAPFilter "(schemaIDGUID=*)" -Properties lDAPDisplayName,schemaIDGUID -Server $adRwdcFQDN | Select-Object lDAPDisplayName,schemaIDGUID
$schemaIDGUIDsWithLDAPDisplayName | %{
	$script:mappingTable_SCHEMA_schemaIDGUID_lDAPDisplayNameHT[$([System.GUID]$_.schemaIDGUID).ToString()] = $_.lDAPDisplayName
	$script:mappingTable_SCHEMA_lDAPDisplayName_schemaIDGUIDHT[$_.lDAPDisplayName] = $([System.GUID]$_.schemaIDGUID).ToString()
}

### All Protected Groups By SID Up Windows Server 2016 That Are Of Interest. Not All Are Listed!
# SOURCE: https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
# All Well-Known Forest/Domain Based Security Groups (Universal Or Global)
$protectedRIDs = @()
$protectedRIDs += "512"		# Domain Admins (Domain Based)
$protectedRIDs += "516"		# Domain Controllers (Domain Based)
$protectedRIDs += "518"		# Schema Admins (Forest Based)
$protectedRIDs += "519"		# Enterprise Admins (Forest Based)
$protectedRIDs += "520"		# Group Policy Creator Owners (Domain Based)
$protectedRIDs += "521"		# Read-only Domain Controllers (Domain Based)
$protectedRIDs += "526"		# Key Admins (Domain Based)
$protectedRIDs += "527"		# Enterprise Key Admins (Forest Based)
$protectedRIDs += "1101"	# DNS Admins (Domain Based)
# All Well-Known Domain Based Builtin Security Groups (Domain Local)
$protectedLocalSIDs = @()
$protectedLocalSIDs += "S-1-5-32-548" # Account Operators (Domain Based)
$protectedLocalSIDs += "S-1-5-32-544" # Administrators (Domain Based)
$protectedLocalSIDs += "S-1-5-32-549" # Server Operators (Domain Based)
$protectedLocalSIDs += "S-1-5-32-550" # Print Operators (Domain Based)
$protectedLocalSIDs += "S-1-5-32-551" # Backup Operators (Domain Based)
$protectedLocalSIDs += "S-1-5-32-552" # Replicator (Domain Based)

### Define The AD Rights Of Interest In An Array. Only The "Powerful" Rights Are Listed. We Do Not Care About Other Rights
# "GenericAll" --> Full Control On Targeted Object
# "ExtendedRight" --> Some Or All Control Access Rights (E.g. Password Reset) On Targeted Object
# "WriteOwner" --> Write The Owner Of The Targeted Object (The Owner Can Always Write The DACL!)
# "WriteDacl" --> Write The DACL (Security On) Of The Targeted Object
# "WriteProperty" --> Write Value(s) InTo The Property (WP:lockOuttime, WP:member, WP:msDS-AllowedToDelegateTo, WP:msDS-AllowedToActOnBehalfOfOtherIdentity, WP:servicePrincipalName, WP:userAccountControl)
$script:adRightsOfInterest = @("GenericAll","ExtendedRight","WriteOwner","WriteDacl","WriteProperty")

### Defining (Empty) Hash Table For The Membership Of Protected Groups Throughout The AD Forest
$protectedGroupMemberhipHT = New-Object System.Collections.Hashtable # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!

### Defining (Empty) Table For List Of AD Domain NetBIOS Names
$script:adDomainNBTList = @()

### Defining (Empty) Table For List Of AD Domain Domain SIDs
$script:adDomainSIDList = @()

### Defining (Empty) Table For All The Protected Groups In The AD Forest
$script:protectedGroups = @()

### Defining (Empty) Table For The AdminSDHolder List Of Permissions Throughout The AD Forest
$adminSDHolderPermsList = @()

### Defining (Empty) Table For The Overall List Of Explicite Permissions Throughout The AD Forest
$objectsPermsList = @()

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
# * Domain NetBIOS Name
# * Domain SID
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
	$script:adDomainNBTList += $adDomainNBT

	# AD Domain Domain SIDs
	$adDomainSID = $null
	$adDomainSID = $adDomain.DomainSID.Value
	$script:adDomainSIDList += $adDomainSID
}

### All/Specific Domain Based Protected Group SIDs Translated To Names For All AD Domains In The AD Forest
$adDomainSIDList | %{
	# AD Domain Domain SID
	$domainSID = $null
	$domainSID = $_
	
	# Build List Of All Protected Groups By Account Name
	$protectedRIDs | %{
		# RID Of The Object
		$rid = $null
		$rid = $_

		# The Domain Specific Object SID
		$groupSid = $null
		$groupSid = $domainSID + "-" + $rid

		# Translating Object SIDs To Names And Adding To The List
		# In General This Always Succeeds. However, In This Case I'm Checking Every Group Against Every AD Domain, Incl. Groups That Only Exist In The Root AD Domain
		# Instead Of Resolving The Sid A Query Is Done Against AD To Find The Group With The Sid If It Exists
		Try {
			$groupObject = $null
			$groupObject = (Get-ADGroup -server $adGcFQDN`:3268 -SearchBase "" -LDAPFilter "(objectSid=$groupSid)" -Properties "msDS-PrincipalName")."msDS-PrincipalName"
		} Catch {
			# PlaceHolder
		}
		
		# If A Group Object (<Domain NetBIOS Name>\<Group sAMAccountName>) Is Found/Returned, Then Add It To The List Of Protected Groups
		If ($groupObject) {
			$script:protectedGroups += $groupObject
		}
	}
}

### All Well-Known Protected Group SIDs Translated To Names For All AD Domains In The AD Forest. Only Needed To Translate In One AD Domain As The Object SID Is The Same In Every AD Domain
$protectedLocalSIDs | %{
	# Well-Known SID Of The Object
	$protectedLocalSID = $null
	$protectedLocalSID = $_

	# Translating Object SIDs To Names And Adding To The List
	# Instead Of Resolving The Sid A Query Is Done Against AD To Find The Group With The Sid If It Exists. This Is Done To Prevent An Issue When This Script Is Executed On A Member Server As
	#	In That Case Resolving Sids Occurs Against The Local Member Server And Not The AD Domain. Some Builtin Groups Exist In AD, But Not On Servers (e.g. Account Operators)
	Try {
		$groupObject = $null
		$groupObject = (Get-ADGroup -server $adRwdcFQDN -Identity $protectedLocalSID -Properties "msDS-PrincipalName")."msDS-PrincipalName"
	} Catch {
		# PlaceHolder
	}

	# If A Group Object (BUILTIN\<Group sAMAccountName>) Is Found/Returned, For Every AD Domain FQDN, Add The Well-Known Protected Group To The List Of Protected Groups While Changing
	#	BUILTIN To The Actual Domain FQDN
	If ($groupObject) {
		$adDomainFQDNList | %{
			$adDomainFQDN = $null
			$adDomainFQDN = $_
			$script:protectedGroups += $groupObject.Replace("BUILTIN",$adDomainFQDN)
		}
	}
}

### For Every AD Domain In The AD Forest, Retrieve And Build List For Protected Groups And Their Memberships
Logging " > Building List Of Default Protected Groups Within The AD Forest And Their Memberships..." "REMARK"
Logging "" "REMARK"
$protectedGroups | %{
	# Protected Group
	$protectedGroup = $null
	$protectedGroup = $_
	
	# Get The AD Domain Of The Protected Group
	$protectedGroupObjectADDomain = $null
	$protectedGroupObjectADDomain = $protectedGroup.SubString(0, $protectedGroup.IndexOf("\"))
	
	# Get The sAMAccountName Of The Protected Group
	$protectedGroupObjectSamAccountName = $null
	$protectedGroupObjectSamAccountName = $protectedGroup.SubString($protectedGroup.IndexOf("\") + 1)
	
	# Get All The Direct Group Members Of The Protected Group
	$adGroupMembers = $null
	$adGroupMembers = Get-ADGroupMember -Identity $protectedGroupObjectSamAccountName -Server $protectedGroupObjectADDomain -Recursive
	
	# If The Are Group Members Build The Hash Table With It
	If ($adGroupMembers) {
		# For Every Group Member Process The Info
		$adGroupMembers | %{
			# Get The DN Of The Group Member (User)
			$adGroupMemberDN = $null
			$adGroupMemberDN = $_.distinguishedName
			
			# Determine The FQDN Of The Group Member (User)
			$adGroupMemberDomainFQDN = $null
			$adGroupMemberDomainFQDN = $adGroupMemberDN.SubString($adGroupMemberDN.IndexOf(",DC=") + 4).Replace(",DC=",".")
			
			# Determine The sAMAccountName Of The Group Member (User)
			$adGroupMemberSamAccountName = $null
			$adGroupMemberSamAccountName = $_.SamAccountName
			
			# Query For The Object Data Of The Group Member (User)
			$adGroupMemberAccount = $null
			$adGroupMemberAccount = (Get-ADObject -LDAPFilter "(sAMAccountName=$adGroupMemberSamAccountName)" -Server $adGroupMemberDomainFQDN -Properties "msDS-PrincipalName")."msDS-PrincipalName"
			
			# If The Group Member (User) IS NOT Already In The Hash Table Then Add It
			# If The Group Member (User) IS Already In The Hash Table, And The Protected Group Is Not Already Listed, Then Get The Existing List Of Protected Groups, Add The New Protected Group And Write Back The Complete New List Of Protected Groups
			$memberOfProtectedGroups = @()
			If (!$protectedGroupMemberhipHT[$adGroupMemberAccount]) {
				$memberOfProtectedGroups += $protectedGroup
				
				# Update The Hash Table With The New Data
				$protectedGroupMemberhipHT[$adGroupMemberAccount] = $memberOfProtectedGroups
				
			} ElseIf ($protectedGroupMemberhipHT[$adGroupMemberAccount] -And $protectedGroupMemberhipHT[$adGroupMemberAccount] -notcontains $protectedGroup) {
				$protectedGroupMemberhipHT[$adGroupMemberAccount] | %{
					$memberOfProtectedGroups += $_
				}
				$memberOfProtectedGroups += $protectedGroup
				
				# Update The Hash Table With The New Data
				$protectedGroupMemberhipHT[$adGroupMemberAccount] = $memberOfProtectedGroups
			}
		}
	}
}

### For Every AD Domain In The AD Forest, Retrieve And Build List For:
# * ACEs On AdminSDHolder Object Within Every AD Domain
# * Explicit ACEs On Object(s) Within Every AD Domain
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
	
	# AD Domain AdminSDHolder DN
	$adDomainAdminSDHolderDN = $null
	$adDomainAdminSDHolderDN = "CN=AdminSDHolder,CN=System," + $adDomainDN

	# AD Domain AdminSDHolder CN
	$adDomainAdminSDHolderCN = $null
	$adDomainAdminSDHolderCN = $adDomainFQDN + "/System/AdminSDHolder"

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

	# Retrieving The ACL From The AD Domain AdminSDHolder DN
	$adDomainAdminSDHolderDNACL = $null
	$adDomainAdminSDHolderDNACL = (Get-Acl "$psDriveADDSName`:\$adDomainAdminSDHolderDN").access

	# Get All The AD Objects In Scope To Retrieve The DACLs From
	Logging " > Building List Of Accounts With Powerful ACEs Configured..." "REMARK"
	Logging "" "REMARK"
	$adObjectsInScope = $null
	$adObjectsInScope = Get-ADObject -LDAPFilter "(|(objectClass=user)(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount)(objectClass=inetOrgPerson)(objectClass=group)(&(objectClass=container)(!name=AdminSDHolder))(objectClass=organizationalUnit)(objectClass=domainDNS))" -Properties distinguishedName,canonicalName -Server $adDomainRwdcFQDN -SearchBase $adDomainDN
	
	# For All AD Objects In Scope Process The DACLs
	$adObjectsInScope | %{
		# DN Of The Object
		$objectDN = $null
		$objectDN = $_.DistinguishedName
		
		# Canonical Name Of The Object
		$objectCN = $null
		$objectCN = $_.CanonicalName

		# Retrieving The ACL From The Object
		$objectACL = $null
		$objectACL = (Get-Acl "$psDriveADDSName`:\$objectDN").access

		# Get The Permissions List For The Object And Add It To The Existing List If Applicable
		$objectsPermsList = getPermissionsListForAccounts $objectCN $objectACL $adDomainDN $adDomainNBT $adDomainRwdcFQDN $objectsPermsList
	}

	# Delete PowerShell Drive For The Corresponding AD Domain
	$psDriveADDSName = "ADDS"
	$psDriveADDS = Get-PSDrive $psDriveADDSName -ErrorAction SilentlyContinue
	If ($psDriveADDS) {
		Remove-PSDrive $psDriveADDSName -Force | Out-Null
	}
	
	# Building List With Accounts Having ACEs On The AdminSDHolder Object
	Logging " > Building List With Accounts Having ACEs On The AdminSDHolder Object(s)..." "REMARK"
	Logging "" "REMARK"	
	
	# Get The Permissions List For The Object And Add It To The Existing List If Applicable
	$adminSDHolderPermsList = getPermissionsListForAccounts $adDomainAdminSDHolderCN $adDomainAdminSDHolderDNACL $adDomainDN $adDomainNBT $adDomainRwdcFQDN $adminSDHolderPermsList
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

			# Check If The Account Is Member Of Protected Group In Some AD Domain | From LDAP Query
			$accountIsMemberOfProtectedGroup = $null
			$protectedGroupList = $null
			If ($protectedGroupMemberhipHT[$accountName]) {
				$protectedGroupList = $protectedGroupMemberhipHT[$accountName]
				$totalAccountsMemberOfProtectedGroups++
				$accountIsMemberOfProtectedGroup = $protectedGroupList -join ",`n"
			} Else {
				$accountIsMemberOfProtectedGroup = "No Memberships"
			}

			# Check If The Account Has ACE(s) (Directly Or Indirectly Through Security Groups) On The AdminSDHolder Object In Some AD Domain | From LDAP Query
			# Also Add Any ACE From Authenticated Users Or Everyone
			# ACEs From Protected Groups Defined At The Beginning Of This Script Will Not Be Listed As The Membership Of Such A Protected Group Says Enough And Needs Carefull Consideration
			$accountHasAdminSDHolderACE = $null
			$adminSDHolderPermsArrayList = $null
			If ($adminSDHolderPermsList | ?{$_."Account Name" -eq $accountName -Or $_."Account Name" -eq "NT AUTHORITY\Authenticated Users" -or $_."Account Name" -eq "Everyone"}) {
				$adminSDHolderPermsArrayList = @()
				$adminSDHolderPermsList | ?{$_."Account Name" -eq $accountName -Or $_."Account Name" -eq "NT AUTHORITY\Authenticated Users" -or $_."Account Name" -eq "Everyone"} | %{
					$adminSDHolderPermsArrayList += $_."Effective Permissions"
				}
				$accountHasAdminSDHolderACE = $adminSDHolderPermsArrayList -join ",`n"
			} Else {
				$accountHasAdminSDHolderACE = "No ACEs"
			}
			
			# Check If The Account Has A Powerfull ACE(s) (Directly Or Indirectly Through Security Groups) On Object(s) In Some AD Domain | From LDAP Query
			# Also Add Any ACE From Authenticated Users Or Everyone
			# ACEs From Protected Groups Defined At The Beginning Of This Script Will Not Be Listed As The Membership Of Such A Protected Group Says Enough And Needs Carefull Consideration. In 
			#	Addition, Adding Those ACEs Would Blow Up The Report And End Up With A Corrupted Report/Data
			$accountHasPowerfulACEsOnObjects = $null
			$objectPermsArrayList = $null
			If ($objectsPermsList | ?{$_."Account Name" -eq $accountName -Or $_."Account Name" -eq "NT AUTHORITY\Authenticated Users" -or $_."Account Name" -eq "Everyone"}) {
				$objectPermsArrayList = @()
				$objectsPermsList | ?{$_."Account Name" -eq $accountName -Or $_."Account Name" -eq "NT AUTHORITY\Authenticated Users" -or $_."Account Name" -eq "Everyone"} | %{
					$objectPermsArrayList += $_."Effective Permissions"
				}
				$accountHasPowerfulACEsOnObjects = $objectPermsArrayList -join ",`n"
			} Else {
				$accountHasPowerfulACEsOnObjects = "No ACEs"
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
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Prot Group Membership" -Value $accountIsMemberOfProtectedGroup
			$accountEntry | Add-Member -MemberType NoteProperty -Name "ACE On AdminSDHolder" -Value $accountHasAdminSDHolderACE
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Powerful ACEs On Objects" -Value $accountHasPowerfulACEsOnObjects
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