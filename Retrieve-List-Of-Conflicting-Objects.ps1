# Clear The Screen
Clear-Host

# Checking Number Of Arguments
$numArgs = $args.count
$arg0 = $args[0]

# Discovering A GC Retrieving Its DNS HostName 
$dnsHostNameGC = (Get-ADDomainController -Service GlobalCatalog -Discover:$true).HostName[0]
$gcHostPort = $dnsHostNameGC + ":3268"
$dsContextDC = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer",$dnsHostNameGC)
$dc = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($dsContextDC)

# General Execution Of Script
If ($numArgs -eq 0) {	
	$listOfConflictingObjects = Get-ADObject -server $gcHostPort -LDAPFilter '(name=*CNF:*)'
}
If ($numArgs -eq 1) {
	If ($arg0.ToLower() -eq "computer") {
		$listOfConflictingObjects = Get-ADComputer -server $gcHostPort -LDAPFilter '(name=*CNF:*)' -Properties pwdLastSet
	}
	If ($arg0.ToLower() -eq "user") {
		$listOfConflictingObjects = Get-ADUser -server $gcHostPort -LDAPFilter '(name=*CNF:*)' -Properties pwdLastSet
	}
}
If ($listOfConflictingObjects -ne $null) {
	$listOfDuplicates = @()
	$listOfConflictingObjects | %{
		$objCNF = $_
		$dnCNFobj = $objCNF.DistinguishedName
		$classCNFobj = $_.ObjectClass
		$guidCNFobj = $_.ObjectGUID
		If ($numArgs -eq 1 -And ($arg0.ToLower() -eq "computer" -Or $arg0.ToLower() -eq "user")) {
			$sAMAccountCNFobj = $_.SamAccountName
			$pwdLastSetCNFobj = $_.pwdLastSet
			If ($pwdLastSetCNFobj -ne $null){
				$pwdLastSetCNFobj = Get-Date -Date ([DateTime]::FromFileTime([Int64]::Parse($pwdLastSetCNFobj))) -Format "yyyy-MM-dd HH:mm:ss"
			} Else {
				$pwdLastSetCNFobj = "---"
			}
		}
		$objCNFMetadata = $dc.GetReplicationMetadata($dnCNFobj)
		$objCNFOrigSrv = $objCNFMetadata | %{($_.objectclass).OriginatingServer}
		$objCNFOrigTime = $objCNFMetadata | %{($_.objectclass).LastOriginatingChangeTime}
		$dnORGobj = $dnCNFobj.Substring(0,$dnCNFobj.IndexOf("\")) + $dnCNFobj.Substring($dnCNFobj.IndexOf(","))
		If ($numArgs -eq 0) {
			$objORG = Get-ADObject -server $gcHostPort -Identity $dnORGobj
		}
		If ($numArgs -eq 1) {
			If ($arg0.ToLower() -eq "computer") {
				$objORG = Get-ADComputer -server $gcHostPort -Identity $dnORGobj -Properties pwdLastSet
			}
			If ($arg0.ToLower() -eq "user") {
				$objORG = Get-ADUser -server $gcHostPort -Identity $dnORGobj -Properties pwdLastSet
			}
		}
		$dnORGobj = $null
		$classORGobj = $null
		$guidORGobj = $null
		$sAMAccountORGobj = $null
		$pwdLastSetORGobj = $null
		$objORGMetadata = $null
		If ($objORG -ne $null) {
			$dnORGobj = $objORG.DistinguishedName
			$classORGobj = $objORG.ObjectClass
			$guidORGobj = $objORG.ObjectGUID
			If ($numArgs -eq 1 -And ($arg0.ToLower() -eq "computer" -Or $arg0.ToLower() -eq "user")) {
				$sAMAccountORGobj = $objORG.SamAccountName
				$pwdLastSetORGobj = $objORG.pwdLastSet
				If ($pwdLastSetORGobj -ne $null){
					$pwdLastSetORGobj = Get-Date -Date ([DateTime]::FromFileTime([Int64]::Parse($pwdLastSetORGobj))) -Format "yyyy-MM-dd HH:mm:ss"
				} Else {
					$pwdLastSetORGobj = "---"
				}
			}
			$objORGMetadata = $dc.GetReplicationMetadata($dnORGobj)
			$objORGOrigSrv = $objORGMetadata | %{($_.objectclass).OriginatingServer}
			$objORGOrigTime = $objORGMetadata | %{($_.objectclass).LastOriginatingChangeTime}
		} Else {
			$dnORGobj = "Does Not Exit"
			$classORGobj = "Does Not Exit"
			$guidORGobj = "Does Not Exit"
			If ($numArgs -eq 1 -And ($arg0.ToLower() -eq "computer" -Or $arg0.ToLower() -eq "user")) {
				$sAMAccountORGobj = "Does Not Exit"
				$pwdLastSetORGobj = "Does Not Exit"
			}
			$objORGOrigSrv = "Does Not Exit"
			$objORGOrigTime = "Does Not Exit"
		}

		If ($numArgs -eq 0) {
			$adObj = "" | Select "> > >DN (CNF)..........","objectClass (CNF)......","objectGUID (CNF).......","Originating DC (CNF)...","Originating Time (CNF).","> > >DN (ORG)..........","objectClass (ORG)......","objectGUID (ORG).......","Originating DC (ORG)...","Originating Time (ORG)."
		}		
		If ($numArgs -eq 1 -And ($arg0.ToLower() -eq "computer" -Or $arg0.ToLower() -eq "user")) {
			$adObj = "" | Select "> > >DN (CNF)..........","objectClass (CNF)......","objectGUID (CNF).......","Account Name (CNF).....","PWD Last Set (CNF).....","Originating DC (CNF)...","Originating Time (CNF).","> > >DN (ORG)..........","objectClass (ORG)......","objectGUID (ORG).......","Account Name (ORG).....","PWD Last Set (ORG).....","Originating DC (ORG)...","Originating Time (ORG)."
		}
		$adObj."> > >DN (CNF).........." = $dnCNFobj
		$adObj."objectClass (CNF)......" = $classCNFobj
		$adObj."objectGUID (CNF)......." = $guidCNFobj
		If ($numArgs -eq 1 -And ($arg0.ToLower() -eq "computer" -Or $arg0.ToLower() -eq "user")) {
			$adObj."Account Name (CNF)....." = $sAMAccountCNFobj
			$adObj."PWD Last Set (CNF)....." = $pwdLastSetCNFobj
		}
		$adObj."Originating DC (CNF)..." = $objCNFOrigSrv
		$adObj."Originating Time (CNF)." = $objCNFOrigTime
		$adObj."> > >DN (ORG).........." = $dnORGobj
		$adObj."objectClass (ORG)......" = $classORGobj
		$adObj."objectGUID (ORG)......." = $guidORGobj
		If ($numArgs -eq 1 -And ($arg0.ToLower() -eq "computer" -Or $arg0.ToLower() -eq "user")) {
			$adObj."Account Name (ORG)....." = $sAMAccountORGobj
			$adObj."PWD Last Set (ORG)....." = $pwdLastSetORGobj
		}
		$adObj."Originating DC (ORG)..." = $objORGOrigSrv
		$adObj."Originating Time (ORG)." = $objORGOrigTime
		
		$listOfDuplicates += $adObj
	}
	Write-Host ""
	If ($numArgs -eq 0) {
		Write-Host "LIST OF DUPLICATE/CONFLICTING OBJECTS IN THE AD FOREST" -Foregroundcolor Cyan
	}
	If ($numArgs -eq 1 -And $arg0.ToLower() -eq "computer") {
		Write-Host "LIST OF DUPLICATE/CONFLICTING COMPUTER OBJECTS IN THE AD FOREST" -Foregroundcolor Cyan
	}
	If ($numArgs -eq 1 -And $arg0.ToLower() -eq "user") {
		Write-Host "LIST OF DUPLICATE/CONFLICTING USER OBJECTS IN THE AD FOREST" -Foregroundcolor Cyan
	}
	$listOfDuplicates | FL
} Else {
	Write-Host "NO DUPLICATE/CONFLICTING OBJECTS DETECTED IN THE AD FOREST" -Foregroundcolor Green
}