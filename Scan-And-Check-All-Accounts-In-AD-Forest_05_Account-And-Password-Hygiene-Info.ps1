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
		* Enabled (e.g. TRUE or FALSE)
		* Pwd Last Set On (e.g. <date/time> or "Must Chng At Next Logon")
		* Has Adm Count Stamp (e.g. TRUE or FALSE)
		* Delegatable Adm (e.g. TRUE or FALSE)
		* Does Not Req Pre-AuthN (e.g. TRUE or FALSE)
		* Has Sid History (e.g. TRUE or FALSE)
		* Has LM Hash (e.g. TRUE or FALSE)
		* Has Default Pwd (e.g. TRUE or FALSE)
		* Has Blank Pwd (e.g. TRUE or FALSE)
		* Uses DES Keys Only (e.g. TRUE or FALSE)
		* Has Missing AES Keys (e.g. TRUE or FALSE)
		* Pwd Rev Encrypt (e.g. TRUE or FALSE)
		* Pwd Not Req (e.g. TRUE or FALSE)		
		* Pwd Never Expires (e.g. TRUE or FALSE)
		* Has Shared Pwd (e.g. TRUE - Domain Shrd Pwd Grp x Of y or FALSE)
		* Compromised Pwd (e.g. TRUE or FALSE)
		* Most Used Hash (e.g. <hash> (<count>) or N.A.)

.EXAMPLE
	Scan/Check All Accounts In The AD Forest And Create The Report

	.\Scan-And-Check-All-Accounts-In-AD-Forest_05_Account-And-Password-Hygiene-Info.ps1

.NOTES
	This script requires:
	* PowerShell Module: ActiveDirectory
	* PowerShell Module: LithnetPasswordProtection
	* PowerShell Module: DSInternals
	* LithNet Active Directory Password Protection Store With Banned Words And/Or Compromised Passwords/Hashes
	* Enterprise Admin Permissions, or at least "Replicate Directory Changes" and "Replicate Directory Changes All" for EVERY NC in the AD forest!
	(REMARK: Script does check for Enterprise Admin role permissions!)
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

### FUNCTION: Test Credentials For Specific Admin Role
Function testAdminRole($adminRole) {
	# Determine Current User
	$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
	# Check The Current User Is In The Specified Admin Role
	(New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole($adminRole)
}

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ SCAN AND CHECK ALL ACCOUNTS IN AD FOREST - ACCOUNT AND PASSWORD HYGIENE INFO +++"
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
$outputCSVFileName = $($execStartDateTimeCustom + "_" + $thisADForestRootDomain + "_Scan-And-Check-All-Accounts-In-AD-Forest_05_Account-And-Password-Hygiene-Info.csv")
$outputCSVFilePath	= $currentScriptFolderPath + "\" + $outputCSVFileName
$logFileName = $($execStartDateTimeCustom + "_" + $thisADForestRootDomain + "_Scan-And-Check-All-Accounts-In-AD-Forest_05_Account-And-Password-Hygiene-Info.log")
$logFilePath = $currentScriptFolderPath + "\" + $logFileName

Logging "" "HEADER"
Logging "                     **********************************************************************************" "HEADER"
Logging "                     *                                                                                *" "HEADER"
Logging "                     *--> Scan And Check All Accounts In AD Forest - Account/Password Hygiene Info <--*" "HEADER"
Logging "                     *                                                                                *" "HEADER"
Logging "                     *                   Written By: Jorge de Almeida Pinto [MVP-EMS]                 *" "HEADER"
Logging "                     *                                                                                *" "HEADER"
Logging "                     *                BLOG: http://jorgequestforknowledge.wordpress.com/              *" "HEADER"
Logging "                     *                                                                                *" "HEADER"
Logging "                     **********************************************************************************" "HEADER"
Logging "" "HEADER"

### Test For Availability Of PowerShell CMDlets And Load Required PowerShell Module
"ActiveDirectory","LithnetPasswordProtection","DSInternals" | %{loadPoSHModules $_}

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

### Validate The User Account Running This Script Is A Member Of The Enterprise Admins Group Of The AD Forest
$enterpriseAdminRID = "519"
$enterpriseAdminObjectSID = $adForestRootDomainDomainSID + "-" + $enterpriseAdminRID
$enterpriseAdminRole = (New-Object System.Security.Principal.SecurityIdentifier($enterpriseAdminObjectSID)).Translate([System.Security.Principal.NTAccount]).Value
$userIsEnterpriseAdmin = $null
$userIsEnterpriseAdmin = testAdminRole $enterpriseAdminRole
If (!$userIsEnterpriseAdmin) {
	# The User Account Running This Script Has Been Validated Not Being A Member Of The Enterprise Admins Group Of The AD Forest
	Logging "" "ERROR"
	Logging "WARNING: Your User Account Is Not Running With Enterprise Administrator Equivalent Permissions In The AD Forest '$adForestRootDomainFQDN'!..." "ERROR"
	Logging "For This Script To Run Successfully, Enterprise Administrator Equivalent Permissions Are Required..." "ERROR"
	Logging "Aborting Script..." "ERROR"
	Logging "" "ERROR"
	
	EXIT
} Else {
	# The User Account Running This Script Has Been Validated To Be A Member Of The Enterprise Admins Group Of The AD Forest
	Logging "" "SUCCESS"
	Logging "Your User Account Is Running With Enterprise Administrator Equivalent Permissions In The AD Forest '$adForestRootDomainFQDN'!..." "SUCCESS"
	Logging "Continuing Script..." "SUCCESS"
	Logging "" "SUCCESS"
}

### Validate The LithNet Store Is Configured And Accessible To Be Able Test Passwords
$lithStoreLocation = $null
$lithStoreLocation = (Get-ItemProperty "HKLM:\SOFTWARE\Lithnet\PasswordFilter\" -Name Store -ErrorAction SilentlyContinue).Store
If ($lithStoreLocation) {
	If (Test-Path $lithStoreLocation) {
		Logging "" "SUCCESS"
		Logging "The LithNet Password Store '$lithStoreLocation' Is Configured And Accessible!..." "SUCCESS"
		Logging "The Test For Compromised Passwords Will Be Executed..." "SUCCESS"
		Logging "" "SUCCESS"
		
		$testForCompromisedPassword = $true
	} Else {
		Logging "" "WARNING"
		Logging "The LithNet Password Store '$lithStoreLocation' Is NOT Accessible!..." "WARNING"
		Logging "The Test For Compromised Passwords Will NOT Be Executed (Will Be Skipped!)..." "WARNING"
		Logging "" "WARNING"
		
		$testForCompromisedPassword = $false
	}
} Else {
	Logging "" "WARNING"
	Logging "The LithNet Password Store '$lithStoreLocation' Is NOT Configured!..." "WARNING"
	Logging "The Test For Compromised Passwords Will NOT Be Executed (Will Be Skipped!)..." "WARNING"
	Logging "" "WARNING"
	
	$testForCompromisedPassword = $false
}

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

### For Every AD Domain In The AD Forest, Retrieve And Build List For:
# * ACEs On AdminSDHolder Object(s)
# * Explicit ACEs On Object(s)
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

	# Get Accounts, Security Info And Secrets From Within Targeted Naming Context
	Logging " > Replicating Objects, Security Info And Secrets From '$adDomainRwdcFQDN' Within '$adDomainDN'..." "REMARK"
	Logging "" "REMARK"
	$allObjectsSecurityAndSecrets = $null
	$allObjectsSecurityAndSecrets = Get-ADReplAccount -All -NamingContext $adDomainDN -Server $adDomainRwdcFQDN

	# Create An Account Quality Report With The Overal Quality Of Each Account Within The AD Domain
	# The Test-PasswordQuality cmdlet is a simple tool for Active Directory password auditing. It can detect weak, duplicate, default, non-expiring or empty passwords and find
	# 	accounts that are violating security best practices. The cmdlet accepts output of the Get-ADDBAccount and Get-ADReplAccount cmdlets, so both offline (ntds.dit) and
	#	online (DCSync) password analysis can be done.
	Logging " > Testing Account And Password Quality Of All Replicated Objects Within '$adDomainDN'..." "REMARK"
	Logging "" "REMARK"
	$accountQualityReport = $null
	$accountQualityReport = $allObjectsSecurityAndSecrets | Test-PasswordQuality -IncludeDisabledAccounts

	# Account Quality Report - Delegateble Admins
	Logging " > Creating List Of Delegateble Admins Within '$adDomainDN'..." "REMARK"
	Logging "" "REMARK"
	$accountsDelegatableAdmin = $null
	$accountsDelegatableAdmin = $accountQualityReport.DelegatableAdmins

	# Account Quality Report - Accounts With LM Hashes Stored
	Logging " > Creating List Of Accounts With LM Hashes Stored Within '$adDomainDN'..." "REMARK"
	Logging "" "REMARK"
	$accountsWithLMHashes = $null
	$accountsWithLMHashes = $accountQualityReport.LMHash

	# Account Quality Report - Default Computer Password Listing
	Logging " > Creating List Of Accounts With Default Computer Passwords Within '$adDomainDN'..." "REMARK"
	Logging "" "REMARK"
	$accountsWithDefaultPassword = $null
	$accountsWithDefaultPassword = $accountQualityReport.DefaultComputerPassword

	# Account Quality Report - Accounts With Empty Password Listing
	Logging " > Creating List Of Accounts With Empty Password Within '$adDomainDN'..." "REMARK"
	Logging "" "REMARK"
	$accountsWithEmptyPassword = $null
	$accountsWithEmptyPassword = $accountQualityReport.EmptyPassword
	
	# Account Quality Report - Accounts With Missing AES Keys Listing
	Logging " > Creating List Of Accounts With Missing AES Keys Within '$adDomainDN'..." "REMARK"
	Logging "" "REMARK"
	$accountsMissingAESKeys = $null
	$accountsMissingAESKeys = $accountQualityReport.AESKeysMissing

	# Account Quality Report - Determine Shared Password Groups Listing Specifying In Which Shared Password Group An Account Is Listed
	$accountsSharedPwd = $null
	$accountsSharedPwd = $accountQualityReport.DuplicatePasswordGroups
	
	# Account Quality Report - Determine The Number Of Shared Password Groups
	$accountsSharedPwdNrOfGrps = $null
	$accountsSharedPwdNrOfGrps = $accountsSharedPwd.Count
	
	# Determine The Length Of The Upper Value To Pad The Numbers So All Have The Same Width In The Output
	$lengthOfUpperValueAccountsSharedPwd = $null
	$lengthOfUpperValueAccountsSharedPwd = $accountsSharedPwdNrOfGrps.ToString().Length
	
	# Creating HashTable With Accounts And Corresponding Groups To Be Searchable
	Logging " > Creating Hash Table With Accounts And Shared Password Groups Within '$adDomainDN'..." "REMARK"
	Logging "" "REMARK"
	$accountsSharedPwdHT = New-Object System.Collections.Hashtable # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!
	# For Every Account Determine To Which Shared Password Group The Password Of The Account Belongs To And Store That In The Hash Table 
	For ($i = 0; $i -le $accountsSharedPwdNrOfGrps - 1; $i++) {
		$accountsSharedPwd[$i] | %{
			$account = $null
			$account = $_
			$accountsSharedPwdHT[$account] = "Domain Shrd Pwd Grp $(($i + 1).ToString().PadLeft($lengthOfUpperValueAccountsSharedPwd, '0')) Of $accountsSharedPwdNrOfGrps"
		}
	}

	# Creating HashTable With All Accounts And Corresponding Hashes To Be Searchable, And A List With Most Used Hashes
	Logging " > Creating Hash Table With Accounts And NT Hashes Within '$adDomainDN'..." "REMARK"
	Logging "" "REMARK"
	Logging " > Creating List Of NT Hashes Used Within '$adDomainDN'..." "REMARK"
	Logging "" "REMARK"
	$accountsNTHashesHT = $null
	$accountsNTHashesHT = New-Object System.Collections.Hashtable # @{} = not-case-sensitive! | New-Object System.Collections.Hashtable = case-sensitive!
	$hashList = @()
	
	# From The List Of Accounts With Some Properties Process The Data
	$allObjectsSecurityAndSecrets |  %{
		# Get The sAMAccountName
		$nTAccountSAMAccountName = $null
        $nTAccountSAMAccountName = $_.SamAccountName
		
		# Get The Hash For The Account
		$ntHashBytes = $null
        $ntHashBytes = $_.NTHash
		
		# If The Account Has A Hash Listed, Then Convert It To A String Value And Add It To The Hash List
		$ntHash = $null
		If ($ntHashBytes) {
			$ntHash = ([System.BitConverter]::ToString($ntHashBytes) -replace '-','').ToLower()
			$hashList += $ntHash
		} Else {
			$ntHash = "No Hash Value"
			$hashList += $ntHash
		}
		$accountsNTHashesHT[$nTAccountSAMAccountName] = $ntHash
	}
	
	# Sort The Hash List
	Logging " > Sorting List Of NT Hashes Used Within '$adDomainDN'..." "REMARK"
	Logging "" "REMARK"
	$hashListSorted = @()
	$hashListSorted = $hashList | Sort-Object
	
	# Create Groups Of Hashes From Within The Hash List To Be Able To Count How Many Times A Hash Is Being Reused
	Logging " > Grouping List Of NT Hashes Used Within '$adDomainDN'..." "REMARK"
	Logging "" "REMARK"
	$hashListGrouped = @()
	$hashListGrouped = $hashListSorted | Group-Object | Sort-Object -Property Count -Descending

	# Hashes That Are Uniquely Used Are Not Interesting As Those Are Unique (Not Reused!). Create The Most Used Hash List Including Count Of Usage
	Logging " > Removing Unique NT Hashes And Keeping Only Duplicate NT Hashes Used Within '$adDomainDN' (For Most Used NT Hashes List)..." "REMARK"
	Logging "" "REMARK"
	$mostUsedHashes = @()
	$mostUsedHashes = $hashListGrouped | ?{$_.Count -ge 2} | Select-Object Name,Count

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

			# Get The Account Enabled Or Disabled
			# UserAccountControl: ACCOUNTDISABLE (2, 0x0002)
			$accountIsEnabled = $null
			If ($($authSecurityPrincipal.userAccountControl -band 2) -eq 0) {
				$accountIsEnabled = $true
			} Else {
				$accountIsEnabled = $false
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

			# Check If The Account Has Admin Account Stamp | From DS Internals
			$accountHasAdminCountStamp = $null
			If ($authSecurityPrincipal.AdminCount) {
				$accountHasAdminCountStamp = $true
			} Else {
				$accountHasAdminCountStamp = $false
			}

			# Check If The Account Is Delegatble As Admin Or Not
			$accountIsDelegatableAdmin = $null
			$accountIsDelegatableAdmin = $accountsDelegatableAdmin -contains $sAMAccountName

			# Check If The Account Does Not Require Pre-AuthN
			# UserAccountControl: DONT_REQUIRE_PREAUTH (4194304, 0x400000) | Misc User Account Control Values https://support.microsoft.com/en-gb/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
			$accountDoesNotReqPreAuthN = $null
			If ($($authSecurityPrincipal.userAccountControl -band 4194304) -eq 4194304) {
				$accountDoesNotReqPreAuthN = $true
			} Else {
				$accountDoesNotReqPreAuthN = $false
			}

			# Check If The Account Has sIDHistory Or Not
			$accountHasSidHistory = $null
			If ($authSecurityPrincipal.SidHistory) {
				$accountHasSidHistory = $true
			} Else {
				$accountHasSidHistory = $false
			}

			# Check If The Account Has LM Hashes Stored Or Not
			$accountHasLMHash = $null
			$accountHasLMHash = $accountsWithLMHashes -contains $sAMAccountName

			# Check If The Account Has Default Password Or Not
			$accountHasDefaultPassword = $null
			$accountHasDefaultPassword = $accountsWithDefaultPassword -contains $sAMAccountName

			# Check If The Account Has Empty Password Or Not
			$accountHasEmptyPassword = $null
			$accountHasEmptyPassword = $accountsWithEmptyPassword -contains $sAMAccountName

			# Check If The Account Only Use DES Encryption Keys
			# UserAccountControl: USE_DES_KEY_ONLY (2097152, 0x200000) | Misc User Account Control Values https://support.microsoft.com/en-gb/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
			$accountUsesDesKeysOnly = $null
			If ($($authSecurityPrincipal.userAccountControl -band 2097152) -eq 2097152) {
				$accountUsesDesKeysOnly = $true
			} Else {
				$accountUsesDesKeysOnly = $false
			}

			# Check If The Account Has AES Keys Or Not
			$accountHasMissingAESKeys = $null
			$accountHasMissingAESKeys = $accountsMissingAESKeys -contains $sAMAccountName

			# Check If The Account Has Plain Text Storage Allowed / Storage Using Reversible Encryption | From LDAP Query
			# UserAccountControl: ENCRYPTED_TEXT_PASSWORD_ALLOWED (128, 0x0080) | Misc User Account Control Values https://support.microsoft.com/en-gb/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
			$accountHasPwdStoredWithRevEncr = $null
			If ($($authSecurityPrincipal.userAccountControl -band 128) -eq 128) {
				$accountHasPwdStoredWithRevEncr = $true
			} Else {
				$accountHasPwdStoredWithRevEncr = $false
			}

			# Check If The Account Has Password Not Required
			# UserAccountControl: PASSWD_NOTREQD (32, 0x0020) | Misc User Account Control Values https://support.microsoft.com/en-gb/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
			$accountDoesNotReqPwd = $null
			If ($($authSecurityPrincipal.userAccountControl -band 32) -eq 32) {
				$accountDoesNotReqPwd = $true
			} Else {
				$accountDoesNotReqPwd = $false
			}

			# Check If The Account Has Password Never Expires
			# UserAccountControl: DONT_EXPIRE_PASSWD (65536, 0x10000) | Misc User Account Control Values https://support.microsoft.com/en-gb/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties
			$accountPwdNeverExpires = $null
			If ($($authSecurityPrincipal.userAccountControl -band 65536) -eq 65536) {
				$accountPwdNeverExpires = $true
			} Else {
				$accountPwdNeverExpires = $false
			}

			# Check If The Account Has Shared Password Or Not
			If ($accountsSharedPwdHT[$sAMAccountName]) {
				$accountHasSharedPwd = "TRUE - $($accountsSharedPwdHT[$sAMAccountName])"
			} Else {
				$accountHasSharedPwd = $false
			}

			# Check If The Account Has A Compromised Password Or Not
			$testCompromisedPwdResult = $null
			If ($testForCompromisedPassword -eq $true) {
				$testCompromisedPwdResult = Test-IsADUserPasswordCompromised -AccountName $sAMAccountName -DomainName $adDomainNBT -Server $adDomainRwdcFQDN
			} Else {
				$testCompromisedPwdResult = "Not Possible To Test!"
			}

			# Check If The Account Has Most Used Hash Or Not
			# Get The Number Of Occurences Also Having The Same Hash
			$hashCount = $null
			$hashCount = ($mostUsedHashes | ?{$_.Name -eq $accountsNTHashesHT[$sAMAccountName]}).Count
			$accountHasMostUsedHash = $null
			# If No Occurence Exists
			# If 1 Or More Occurence Exists And The Hash Value Is A Specific Value Then It Is The Hash Of A Blank Password.  If The Option "showReUsedHashInReport" Has Been Specified As A Switch Parameter For The Script, Display The Hash In The Report, Otherwise Do Not Display The Hash Value
			# If 1 Or More Occurence Exists And The Hash Value Is Any Other Value. If The Option "showReUsedHashInReport" Has Been Specified As A Switch Parameter For The Script, Display The Hash In The Report, Otherwise Do Not Display The Hash Value
			If ($hashCount -eq 0) {
				$accountHasMostUsedHash = "N.A."
			} ElseIf ($hashCount -gt 0 -And $accountsNTHashesHT[$sAMAccountName] -eq "31d6cfe0d16ae931b73c59d7e0c089c0") {
				$accountHasMostUsedHash = "$($accountsNTHashesHT[$sAMAccountName]) (Blank Pwd With Hash!) ($hashCount)"
			} ElseIf ($hashCount -gt 0 -And $accountsNTHashesHT[$sAMAccountName] -eq "No Hash Value") {
				$accountHasMostUsedHash = "$($accountsNTHashesHT[$sAMAccountName]) (Blank Pwd Without Hash!) ($hashCount)"
			} Else {
				$accountHasMostUsedHash = "$($accountsNTHashesHT[$sAMAccountName]) ($hashCount)"
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
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $accountIsEnabled
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Pwd Last Set On" -Value $pwdLastSetDateTime
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Has Adm Count Stamp" -Value $accountHasAdminCountStamp
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Delegatable Adm" -Value $accountIsDelegatableAdmin
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Does Not Req Pre-AuthN" -Value $accountDoesNotReqPreAuthN
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Has Sid History" -Value $accountHasSidHistory
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Has LM Hash" -Value $accountHasLMHash
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Has Default Pwd" -Value $accountHasDefaultPassword
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Has Blank Pwd" -Value $accountHasEmptyPassword
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Uses DES Keys Only" -Value $accountUsesDesKeysOnly
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Has Missing AES Keys" -Value $accountHasMissingAESKeys
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Pwd Rev Encrypt" -Value $accountHasPwdStoredWithRevEncr
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Pwd Not Req" -Value $accountDoesNotReqPwd
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Pwd Never Expires" -Value $accountPwdNeverExpires
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Has Shared Pwd" -Value $accountHasSharedPwd
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Compromised Pwd" -Value $testCompromisedPwdResult
			$accountEntry | Add-Member -MemberType NoteProperty -Name "Most Used Hash (Count)" -Value $accountHasMostUsedHash
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