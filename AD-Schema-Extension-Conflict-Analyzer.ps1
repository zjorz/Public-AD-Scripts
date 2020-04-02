# Abstract: This PoSH Script Checks/Validates (New) Schema Extensions
# Written by: Justin Hall [MSFT]
# Original Location: http://gallery.technet.microsoft.com/scriptcenter/0672d181-ab2c-4c92-8466-d93a67412207
#
# Re-Written by: Jorge de Almeida Pinto [MVP-DS]
# BLOG: http://jorgequestforknowledge.wordpress.com/
#
# 2010-05-07: (v0.1): Initial version of the script
# 2014-07-07: (v0.2): Re-written script with additional checks in current schema en extensions file and resolved bugs
# 2014-08-14: (v0.3): Also added to check uniqueness of schemaIDGUID value (if provided), rangeLower/rangeUpper check (if provided), resolved few bugs, change output layout a bit!
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

Param(
	[Parameter(Mandatory=$true)]
	[array]$inputLDIFFileList,				# [Mandatory] The List Of Input LDIF Files (Comma Separated) With The Schema Extensions To Check For Conflicts
	[Parameter(Mandatory=$true)]
	[string]$outputLDIFFile,				# [Mandatory] The Output LDIF File With The Results Of The Analyses Of The Schema Extensions
	[Parameter(Mandatory=$false)]
	[string]$currentSchemaLDIFFile			# [Optional] The LDIF File Containing The AD Schema To Check Against. When Not Specified It will Exported
)

$global:errorCount = 0
$global:warningCount = 0

# Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ AD SCHEMA EXTENSION CONFLICT ANALYZER +++"
$uiConfig.Foregroundcolor = "White"
$uiConfigBufferSize = $uiConfig.BufferSize
$uiConfigBufferSize.Width = 120
$uiConfigBufferSize.Height = 9999
$uiConfigScreenSizeMax = $uiConfig.MaxPhysicalWindowSize
$uiConfigScreenSizeMaxWidth = $uiConfigScreenSizeMax.Width
$uiConfigScreenSizeMaxHeight = $uiConfigScreenSizeMax.Height
$uiConfigScreenSize = $uiConfig.WindowSize
If ($uiConfigScreenSizeMaxWidth -lt 120) {
	$uiConfigScreenSize.Width = $uiConfigScreenSizeMaxWidth
} Else {
	$uiConfigScreenSize.Width = 120
}
If ($uiConfigScreenSizeMaxHeight -lt 75) {
	$uiConfigScreenSize.Height = $uiConfigScreenSizeMaxHeight - 5
} Else {
	$uiConfigScreenSize.Height = 75
}
$uiConfig.BufferSize = $uiConfigBufferSize
$uiConfig.WindowSize = $uiConfigScreenSize

Clear-Host

Write-Host "                                *****************************************************" -Foregroundcolor Magenta
Write-Host "                                *                                                   *" -Foregroundcolor Magenta
Write-Host "                                *   --> AD SCHEMA EXTENSION CONFLICT ANALYZER <--   *" -Foregroundcolor Magenta
Write-Host "                                *                                                   *" -Foregroundcolor Magenta
Write-Host "                                *          Written By: Justin Hall [MSFT]           *" -Foregroundcolor Magenta
Write-Host "                                *(http://gallery.technet.microsoft.com/scriptcenter)*" -Foregroundcolor Magenta
Write-Host "                                *                                                   *" -Foregroundcolor Magenta
Write-Host "                                *   Re-Written By: Jorge de Almeida Pinto [MVP-DS]  *" -Foregroundcolor Magenta
Write-Host "                                *   (http://jorgequestforknowledge.wordpress.com/)  *" -Foregroundcolor Magenta
Write-Host "                                *                                                   *" -Foregroundcolor Magenta
Write-Host "                                *****************************************************" -Foregroundcolor Magenta

Function global:DisplayScriptUsage { 
    Write-Host "====================================================" 
    Write-Host "`n         EXTENSION CHECKER SCRIPT USAGE         `n" 
    Write-Host "====================================================" 
    Write-Host "USAGE SUMMARY"     
    Write-Host "`n -inputLDIFFileList " -Foregroundcolor darkCyan 
    Write-Host "`n [MANDATORY] Provide the path to the input file containing the custom schema extensions here.`n" 
    Write-Host "`n -outputLDIFFile " -Foregroundcolor darkCyan 
    Write-Host "`n [MANDATORY] Provide the path to the output LDF file containing the annotations and suggested corrections. `n" 
    Write-Host "`n -currentSchemaLDIFFile " -Foregroundcolor darkCyan 
    Write-Host "`n [OPTIONAL] This is a required field If the operation is being run on a test DC." 
    Write-Host " If the validate operation is being performed on a production DC, the current schema file need not be provided. The script will extract it.`n" 
    Write-Host "EXAMPLES" -Foregroundcolor darkCyan 
    Write-Host " .\AD-Schema-Extension-Conflict-Analyzer.ps1 -inputLDIFFileList sampleldf1.ldf,sampleldf2.ldf -outputLDIFFile results.ldf -currentSchemaLDIFFile myProductionSchema.ldf `n"     
    Exit 
}

# The function below will check current production schema file and/or the input custom extension file to make sure that the class / attribute being referenced (in systemMayContain,  
# systemMustContain, mayContain, mustContain, subClassOf , systemAuxiliaryClass , auxiliaryClass , systemPossSuperiors , and possSuperiors)  has already been created. 
# If it has not been created but is still being referenced in one of the attributes above then that is an error and it needs to be flagged. 
 
Function global:ConfirmExistenceofReferencedAttributesOrClasses($attrClassList) {    
    $tempError = $null
	$attrsClasses = $attrClassList.Split(",") 
    ForEach($item in $attrsClasses) { 
        If (!($currentSchemaLDIFFileContent | Select-String -pattern $item -quiet)) { 
            # The attribute/class under consideration was not found in current production schema file. We need to check the input file now. May be it is a new addition. 
            $searchString = "CN=" + $item 
            If(!($consolidatedLDIFFileContent | Select-String -pattern $searchString -quiet)) { 
                $searchString = "lDAPDisplayName: " + $item 
                If(!($consolidatedLDIFFileContent | Select-String -pattern $searchString -quiet)) { 
                    # No declaration of the attribute/class under consideration was found in the inputFile too. Looks like an error. The attribute/class should have been created before referencing it. 
                    Write-Host "[ERROR] : The class or attribute under consideration " $item " is being referenced but has not been created so far. Make sure it is created before using it!" -Foregroundcolor Red 
                    $tempError = "### ERROR : The class or attribute under consideration - " + $item + " - is being referenced but has not been created so far. Make sure it is created before using it!"
                    Add-Content -path $outputLDIFFile -value $tempError
					$global:errorCount += 1
                } 
            } 
        } 
    }
	Return $tempError
} 

# The function below will check current production schema file to look for a particular value of attributeID. attributeID is expected to be unique!
Function global:checkUniquenessOfattributeIDCurrentSchema([string]$attributeIDValue) {
	$tempError = $null
	If($currentSchemaLDIFFileContent | Select-String -pattern $attributeIDValue | ForEach { $_.Line | Select-String $attributeIDValue -quiet}) { 
		Write-Host "[ERROR] : The attributeID value is already used in the schema. Make sure the attributeID OID is unique!" -Foregroundcolor Red 
		$tempError = "### ERROR : The attributeID value is already used in the schema. Make sure the attributeID OID is unique!"
		Add-Content -path $outputLDIFFile -value $tempError
		$global:errorCount += 1
    }
	Return $tempError
}

# The function below will check extension file to look for a particular value of attributeID. attributeID is expected to be unique!
Function global:checkUniquenessOfattributeIDNewExtensions([string]$attributeIDValue) {
	$tempError = $null
	If(($consolidatedLDIFFileContent | Select-String -Pattern "^(?i)(governsID:|attributeID:).*$attributeIDValue$" | Measure).Count -gt 1) {
		Write-Host "[ERROR] : The attributeID value is already used in the extension. Make sure the attributeID OID is unique!" -Foregroundcolor Red 
		$tempError = "### ERROR : The attributeID value is already used in the extension. Make sure the attributeID OID is unique!" 
		Add-Content -path $outputLDIFFile -value $tempError
		$global:errorCount += 1 
	}
	Return $tempError
}

# The function below will check current production schema file to look for a particular value of governsID. governsID is expected to be unique!
Function global:checkUniquenessOfgovernsIDCurrentSchema([string]$governsIDValue) { 
	$tempError = $null
	If($currentSchemaLDIFFileContent | Select-String -pattern $governsIDValue | ForEach { $_.Line | Select-String $governsIDValue -quiet}) { 
		Write-Host "[ERROR] : The governsID value is already used in the schema. Make sure the governsID OID is unique!" -Foregroundcolor Red 
		$tempError = "### ERROR : The governsID value is already used in the schema. Make sure the governsID OID is unique!"
		Add-Content -path $outputLDIFFile -value $tempError
		$global:errorCount += 1
    }
	Return $tempError
}

# The function below will check extension file to look for a particular value of governsID. governsID is expected to be unique!
Function global:checkUniquenessOfgovernsIDNewExtensions([string]$governsIDValue) {
	$tempError = $null
	If(($consolidatedLDIFFileContent | Select-String -Pattern "^(?i)(governsID:|attributeID:).*$governsIDValue$" | Measure).Count -gt 1) { 
		Write-Host "[ERROR] : The governsID value is already used in the extension. Make sure the governsID OID is unique!" -Foregroundcolor Red 
		$tempError = "### ERROR : The governsID value is already used in the extension. Make sure the governsID OID is unique!" 
		Add-Content -path $outputLDIFFile -value $tempError
		$global:errorCount += 1 
	}
	Return $tempError
} 

# The function below will check current production schema file to look for a particular value of schemaIDGUID. schemaIDGUID is expected to be unique!
Function global:checkUniquenessOfschemaIDGUIDCurrentSchema([string]$schemaIDGUIDValue) { 
	$tempError = $null
	If($currentSchemaLDIFFileContent | Select-String -Pattern $schemaIDGUIDValue | ForEach { $_.Line | Select-String $schemaIDGUIDValue -quiet}) { 
		Write-Host "[ERROR] : The schemaID GUID value is already used in the schema. Make sure the schemaID GUID is unique!" -Foregroundcolor Red 
		$tempError = "### ERROR : The schemaID GUID value is already used in the schema. Make sure the schemaID GUID OID is unique!"
		Add-Content -path $outputLDIFFile -value $tempError
		$global:errorCount += 1
    }
	Return $tempError
}

# The function below will check extension file to look for a particular value of schemaIDGUID. schemaIDGUID is expected to be unique!
Function global:checkUniquenessOfschemaIDGUIDNewExtensions([string]$schemaIDGUIDValue) {
	$tempError = $null
	If(($consolidatedLDIFFileContent | Select-String -Pattern $schemaIDGUIDValue | Measure).Count -gt 1) { 
		Write-Host "[ERROR] : The schemaID GUID value is already used in the extension. Make sure the schemaID GUID is unique!" -Foregroundcolor Red 
		$tempError = "### ERROR : The schemaID GUID value is already used in the extension. Make sure the schemaID GUID is unique!" 
		Add-Content -path $outputLDIFFile -value $tempError
		$global:errorCount += 1 
	}
	Return $tempError
}

# The function below will check current production schema file to look for a particular value of mAPIID. mAPIID is expected to be unique!
Function global:checkUniquenessOfmAPIIDCurrentSchema([string]$mAPIIDValue) {
    $tempError = $null
	If($currentSchemaLDIFFileContent | Select-String -pattern "mAPIID" -quiet) { 
        If($currentSchemaLDIFFileContent | Select-String -pattern "^(?i)mAPIID:.*$mAPIIDValue$" | ForEach { $_.Line | Select-String $mAPIIDValue -quiet}) { 
            Write-Host "[ERROR] : The mAPIID value is already used in the schema. Make sure the mAPIID is unique!" -Foregroundcolor Red 
            $tempError = "### ERROR : The mAPIID value is already used in the schema. Make sure the mAPIID is unique!" 
			Add-Content -path $outputLDIFFile -value $tempError
            $global:errorCount += 1 
        }
    }
	Return $tempError
}

# The function below will check extension file to look for a particular value of mAPIID. mAPIID is expected to be unique!
Function global:checkUniquenessOfmAPIIDNewExtensions([string]$mAPIIDValue) {
	$tempError = $null
	If(($consolidatedLDIFFileContent | Select-String -Pattern "^(?i)mAPIID:.*$mAPIIDValue$" | Measure).Count -gt 1) { 
		Write-Host "[ERROR] : The mAPIID value is already used in the extension. Make sure the mAPIID is unique!" -Foregroundcolor Red 
		$tempError = "### ERROR : The mAPIID value is already used in the extension. Make sure the mAPIID is unique!" 
		Add-Content -path $outputLDIFFile -value $tempError
		$global:errorCount += 1 
	}
	Return $tempError
} 

# The function below will go through current production schema file to make sure the attribute/class that is being added is NOT already present in the current production schema 
Function global:checkExistenceCurrentSchema([string]$attribValue) {
    $tempError = $null
	ForEach ($line in $currentSchemaLDIFFileContent) { 
        $SchemaValues = @($line.Split(":"))  
        If ($SchemaValues[1].length -gt 0) { 
            $SchemaValues[1] = $SchemaValues[1].TrimStart() 
        }
 		If ($SchemaValues[0].ToLower() -like "cn" -And $SchemaValues[1].Contains($attribValue)) { 
            Write-Host "[ERROR] : Attempt being made to add an attribute/class which already exists in the schema!" -Foregroundcolor Red 
            $tempError = "### ERROR : Attempt being made to add an attribute/class which already exists in the schema!"
			Add-Content -path $outputLDIFFile -value $tempError
            $global:errorCount += 1     
        }
		If ($SchemaValues[0].ToLower() -like "ldapdisplayname" -And $SchemaValues[1].Contains($attribValue)) {
            Write-Host "[ERROR] : The lDAPDisplayName value is already used in the schema. Make sure the lDAPDisplayName is unique!" -Foregroundcolor Red 
            $tempError = "### ERROR : The lDAPDisplayName value is already used in the schema. Make sure the lDAPDisplayName is unique!"
			Add-Content -path $outputLDIFFile -value $tempError
            $global:errorCount += 1 
		}
    }
	Return $tempError
}

# The function below will check extension file to make sure the attribute/class that is being added is not being added twice
Function global:checkExistenceCNNewExtensions([string]$attribValue) {
	$tempError = $null
	If (($consolidatedLDIFFileContent | Select-String -Pattern "^(?i)cn:.*$attribValue$" | Measure).Count -gt 1) { 
		Write-Host "[ERROR] : Attempt being made to add an attribute/class twice through the extension!" -Foregroundcolor Red 
		$tempError = "### ERROR : Attempt being made to add an attribute/class twice through the extension!"
		Add-Content -path $outputLDIFFile -value $tempError 
		$global:errorCount += 1 
	}
	Return $tempError
}

# The function below will check extension file to look for a particular value of lDAPDisplayName. lDAPDisplayName is expected to be unique!
Function global:checkExistenceLDAPDisplayNameNewExtensions([string]$attribValue) {
	$tempError = $null
	If (($consolidatedLDIFFileContent | Select-String -Pattern "^(?i)lDAPDisplayName:.*$attribValue$" | Measure).Count -gt 1) { 
		Write-Host "[ERROR] : The lDAPDisplayName value is already used in the extension. Make sure the lDAPDisplayName is unique!" -Foregroundcolor Red
		$tempError = "### ERROR : The lDAPDisplayName value is already used in the extension. Make sure the lDAPDisplayName is unique!"
		Add-Content -path $outputLDIFFile -value $tempError
		$global:errorCount += 1 
	}
	Return $tempError
}
 
# The function below will go through current production schema file to look for the attribute $attrName which has been set as rdnAttid for another attribute 
# The syntax of $attrName should be UNICODE 2.5.5.9 
 Function global:checkSyntaxOfRdnattidAttribute($attrName) { 
    $tempError = $null
	$encounteredDn = 0 
    # The variable $encounteredDn will track whether or not we have come across the block that describes the attribute $attrName. 
    # Every "dn: " statement in the current production schema file will be checked till $attrName is encountered. On encountering it $encounteredDn will be set to 1. 
    # Once $attrName has been found its attributeSyntax attribute needs to be verified to make sure its value is 2.5.5.9 
    ForEach ($line in $currentSchemaLDIFFileContent) { 
        If($encounteredDn -eq 0) { 
			$SchemaValues = @($line.Split(":"))  
			If ($SchemaValues[1].length -gt 0) { 
				$SchemaValues[1] = $SchemaValues[1].TrimStart() 
			} 
			If (!$SchemaValues[0].CompareTo("dn") -AND $SchemaValues[1].Contains($attrName)) { 
				$encounteredDn = 1 
				Continue                              
			} 
        } Else { 
            $SchemaValues = @($line.Split(":")) 
            If ($SchemaValues[1].length -gt 0) { 
				$SchemaValues[1] = $SchemaValues[1].TrimStart(" ") 
            } 
            If (!$SchemaValues[0].CompareTo("attributeSyntax")) { 
				If($SchemaValues[1].CompareTo("2.5.5.9")) { 
					# This means attributeSyntax of the attribute which is the rdnAttid for another attribute is not INTEGER. This is not expected. 
					Write-Host "[ERROR] : AttributeSyntax of rDNAttID attribute should be INTEGER 2.5.5.9. Please correct this!" -Foregroundcolor Red 
					$tempError = "### ERROR : AttributeSyntax of rDNAttID attribute should be INTEGER 2.5.5.9. Please correct this!"
					Add-Content -path $outputLDIFFile -value $tempError
					$global:errorCount += 1 
				}
				Break
            } 
        }        
    }
	Return $tempError
} 
 
Function global:ValidateExtensions {     
 	# Valid Syntaxes for Attributes in the Active Directory Schema
	$attributeSyntaxList = @{ 
								"2.5.5.1"  = "(DISTNAME)"; 
								"2.5.5.2"  = "(OBJECT_ID)"; 
								"2.5.5.3"  = "(CASE_STRING)"; 
								"2.5.5.4"  = "(NOCASE_STRING)"; 
								"2.5.5.5"  = "(PRINT_CASE_STRING)"; 
                                "2.5.5.6"  = "(NUMERIC_STRING)"; 
                                "2.5.5.7"  = "(DISTNAME_BINARY)"; 
                                "2.5.5.8"  = "(BOOLEAN)"; 
                                "2.5.5.9"  = "(INTEGER)"; 
                                "2.5.5.10" = "(OCTET_STRING)"; 
                                "2.5.5.11" = "(TIME)"; 
                                "2.5.5.12" = "(UNICODE)"; 
                                "2.5.5.13" = "(ADDRESS)"; 
                                "2.5.5.14" = "(DISTNAME_STRING)"; 
                                "2.5.5.15" = "(NT_SECURITY_DESCRIPTOR)"; 
                                "2.5.5.16" = "(I8)"; 
                                "2.5.5.17" = "(SID)" 
                            } 
    
	# The systemFlags Attribute Specifies An Integer Value That Contains Flags That Define Additional Properties Of The Class
    $systemFlagsList = @{ 
							0x0			= "<NOT SET>";
							0x1  		= "FLAG_ATTR_NOT_REPLICATED"; 
							0x2  		= "FLAG_ATTR_REQ_PARTIAL_SET_MEMBER"; 
							0x4  		= "FLAG_ATTR_IS_CONSTRUCTED"; 
							0x8  		= "FLAG_ATTR_IS_OPERATIONAL"; 
							0x10 		= "FLAG_SCHEMA_BASE_OBJECT"; 
							0x20 		= "FLAG_ATTR_IS_RDN";
							0x2000000 	= "FLAG_DISALLOW_MOVE_ON_DELETE";
							0x4000000 	= "FLAG_DOMAIN_DISALLOW_MOVE";
							0x8000000 	= "FLAG_DOMAIN_DISALLOW_RENAME";
							0x10000000 	= "FLAG_CONFIG_ALLOW_LIMITED_MOVE";
							0x20000000 	= "FLAG_CONFIG_ALLOW_MOVE";
							0x40000000 	= "FLAG_CONFIG_ALLOW_RENAME";
							0x80000000 	= "FLAG_DISALLOW_DELETE"
                        } 
 
	# The searchFlags Property Specifies The Characteristics And Behavior Of The Attribute
    $searchFlagsList = @{ 
							0		= "<NOT SET>";
							1		= "fATTINDEX"; 
							2  	 	= "fPDNTATTINDEX"; 
							4  	 	= "fANR"; 
							8  		= "fPRESERVEONDELETE"; 
							16		= "fCOPY"; 
							32		= "fTUPLEINDEX"; 
							64		= "fSUBTREEATTINDEX"; 
							128		= "fCONFIDENTIAL"; 
							256		= "fNEVERVALUEAUDIT"; 
							512		= "fRODCFilteredAttribute";
							1024	= "fEXTENDEDLINKTRACKING";
							2048	= "fBASEONLY";
							4096	= "fPARTITIONSECRET";
                        } 

	# Valid Syntaxes for Attributes in the Active Directory Schema
    $oMSyntaxList    = @{ 
							"0"   = "(NO_MORE_SYNTAXES)"; 
							"1"   = "(BOOLEAN)"; 
							"2"   = "(INTEGER)"; 
							"3"   = "(BIT_STRING)"; 
							"4"   = "(OCTET_STRING)"; 
							"5"   = "(NULL)"; 
							"6"   = "(OBJECT_IDENTIFIER_STRING)"; 
							"7"   = "(OBJECT_DESCRIPTOR_STRING)"; 
							"8"   = "(ENCODING_STRING)"; 
							"10"  = "(ENUMERATION)"; 
							"18"  = "(NUMERIC_STRING)"; 
							"19"  = "(PRINTABLE_STRING)"; 
							"20"  = "(TELETEX_STRING)"; 
							"21"  = "(VIDEOTEX_STRING)"; 
							"22"  = "(IA5_STRING)"; 
							"23"  = "(UTC_TIME_STRING)"; 
							"24"  = "(GENERALISED_TIME_STRING)"; 
							"25"  = "(GRAPHIC_STRING)"; 
							"26"  = "(VISIBLE_STRING)"; 
							"27"  = "(GENERAL_STRING)"; 
							"64"  = "(UNICODE_STRING)"; 
							"65"  = "(I8)"; 
							"66"  = "(OBJECT_SECURITY_DESCRIPTOR)"; 
							"127" = "(OBJECT)" 
						} 

	# This attribute specifies the unique object ID (OID) for the attribute or class
    $oMObjectClassList = @{ 
							"KoZIhvcUAQEBBg=="  = "1.2.840.113556.1.1.1.6 (REPLICA-LINK)";  
							"KoZIhvcUAQEBCw=="  = "1.2.840.113556.1.1.1.11 (DN-BINARY)";  
							"KoZIhvcUAQEBDA=="  = "1.2.840.113556.1.1.1.12 (DN-STRING)";  
							"KwwCh3McAIVK"      = "1.35.44.2.1011.60.0.746 (DS-DN)";  
							"KwwCh3McAIU+"      = "1.35.44.2.1011.60.0.734 (ACCESS-POINT)";  
							"KwwCh3McAIVc"      = "1.35.44.2.1011.60.0.764 (PRESENTATION-ADDRESS)";  
							"VgYBAgULHQ=="      = "2.6.6.1.2.5.43.61 (OR-NAME)" 
						} 
    
	# Mapping Between attributeSyntax And OmSyntax
    $attributeSyntaxToOmSyntaxList = @{ 
                                "2.5.5.1"  = "127"; 
                                "2.5.5.2"  = "6"; 
                                "2.5.5.3"  = "27"; 
                                "2.5.5.4"  = "20"; 
                                "2.5.5.5"  = "19,22"; 
                                "2.5.5.6"  = "18"; 
                                "2.5.5.7"  = "127"; 
                                "2.5.5.8"  = "1"; 
                                "2.5.5.9"  = "2,10"; 
                                "2.5.5.10" = "4"; 
                                "2.5.5.11" = "23,24"; 
                                "2.5.5.12" = "64"; 
                                "2.5.5.13" = "127"; 
                                "2.5.5.14" = "127"; 
                                "2.5.5.15" = "66"; 
                                "2.5.5.16" = "65"; 
                                "2.5.5.17" = "4" 
                            } 
 
    $linkedAttrsDisplayNameList = @{} 
    $linkedAttrsOIDList = @{} 
 
    $schemaUpdateNowFlag = "FALSE" 
    $startedAddingClassesFlag = "FALSE" 
 
	$cnValue = $null
	$ldapDisplayNameValue = $null
 
    # Now Start Scanning The (Combined) Input LDIF File 
    $linecount = 0     
    Add-Content -path $outputLDIFFile -value "############################################################################################################"
    Add-Content -path $outputLDIFFile -value "#Scanned LDIF File With Corrections/Suggestions"
	Add-Content -path $outputLDIFFile -value "############################################################################################################"
    ForEach($line in $consolidatedLDIFFileContent)  {  
		$linecount++ 
		If ($line.StartsWith("#")) { 
			# Also Add Comments To Output
			Add-Content -path $outputLDIFFile -value $line
			Continue 
		} Else { 
			# To Get An Array Of Items, Values[0]..Values[x-1] Where [x] Is The Number Of Items Created  
			Add-Content -path $outputLDIFFile -value $line 
			
			# Split The Lines In a Left Part And A Right Part, Using The : As the Separator And Remove Any Trailing Spaces
			$Values = @($line.Split(":"))
			$attribute = $null
			$attributeLowerCase = $null
			$extraSeparator = $null
			$attributeValue = $null

			If ($Values.count -le 2) {
				$attribute = $values[0]
				$attributeLowerCase = $values[0].ToLower()
				$extraSeparator = $null
				If ($values[1].length -gt 0) { 
					$attributeValue = $values[1].TrimStart()
				} Else {             
					Continue 
				}
			}
			If ($Values.count -eq 3) {
				$attribute = $values[0]
				$attributeLowerCase = $values[0].ToLower()
				$extraSeparator = $values[1]
				If ($values[2].length -gt 0) { 
					$attributeValue = $values[2].TrimStart()
				} Else {             
					Continue 
				}
			}
			
			# Show The Info On Screen
			Write-Host "LINE.................#"$linecount 
			Write-Host "Attribute............:"$attribute
			Write-Host "Value................:"$attributeValue        

			$tempStr = "" 
			$cnValue = $null
			$lDAPDisplayNameValue = $null
			
			# Convert The Left Side To Lower For The Switch Below To Work Correctly And Always Have Expected Results
			
			switch -wildcard ($attributeLowerCase) { 
				"dn"
						{ 
							$rangeLower = $null # This must be reset for every new object
							$rangeUpper = $null # This must be reset for every new object
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						}
						
				"attributesyntax"
						{ 
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$attributeSyntaxValue = $attributeValue						
							If(!$attributeSyntaxList.ContainsKey($attributeSyntaxValue)) { 
								Write-Host "[ERROR] : The value provided for attribute syntax is invalid. Please correct the value!" -Foregroundcolor Red 
								$tempError = "### ERROR : The value provided for attribute syntax is invalid. Please correct the value!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$attributeSyntaxValue = $null 
								$global:errorCount += 1 
								continue 
                            } 
                            Write-Host "attributeSyntax is...:" $attributeSyntaxList[$attributeValue] 
                            $tempStr = "# attributeSyntax is:" + $attributeSyntaxList[$attributeValue] 
                            Add-Content -path $outputLDIFFile -value $tempStr
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						}
             
				"systemflags"  
						{ 
							$tempError = $null
							$tempWarning = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$flags = $null                                                       
							For ($i = 1; $i -le 0x8000000; $i *= 2) { 
								If ($attributeValue -band $i) { 
									If ($flags.length -gt 0) { 
										$flags = $flags + " | " + $systemFlagsList[$i]                                         
									} Else { 
										If (!$systemFlagsList.ContainsKey($i)) {
											Write-Host "[ERROR] : The systemFlags value is invalid. Please correct it!" -Foregroundcolor Red
                                            $tempError = "### ERROR : The systemFlags value is invalid. Please correct it!"
											Add-Content -path $outputLDIFFile -value $tempError
											$global:errorCount += 1 
											Continue                                             
										} 
										$flags = $systemFlagsList[$i]                                      
									}
                                     
                                    If ($i -eq 0x10) { 
										# systemFlags contains 0x10 which means base schema object. This needs to be flagged.                                         
										Write-Host "[WARNING] : This attribute/class has been marked as BASE_SCHEMA_OBJECT. This would need approval from MSFT Active Directory schema team!" -Foregroundcolor Yellow 
										$tempWarning = "### WARNING : This attribute/class has been marked as BASE_SCHEMA_OBJECT. This would need approval from MSFT Active Directory schema team!"
										Add-Content -path $outputLDIFFile -value $tempWarning
									}                                     
								}
								If ($attributeValue -eq 0) {
									$flags = $systemFlagsList[$attributeValue]
								}
							} 
							$tempStr = "# systemFlags is:" + $flags
							Write-Host "systemFlags is.......:" $flags 
							Add-Content -path $outputLDIFFile -value $tempStr
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						}         
                           
				"searchflags"
						{ 
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$flags = "";                             
							For ($i = 1; $i -le 512; $i *= 2) { 
								If ($attributeValue -band $i) { 
									If ($flags.length -gt 0) {
										$flags = $flags + " | " + $searchFlagsList[$i]
                                    } Else { 
										$flags = $searchFlagsList[$i] 
									} 
                                     
                                    If ($i -eq 8) { 
										# fPreserveOnDelete Is Set. Make Sure This Is Really Required
										Write-Host "[WARNING] : This attribute has been marked as fpreserveOnDelete. Please confirm the need to do so!" -Foregroundcolor Yellow
										$tempWarning = "### WARNING : This attribute has been marked as fPreserveOnDelete. Please confirm the need to do so!"
										Add-Content -path $outputLDIFFile -value $tempWarning
										$global:warningCount += 1 
									} 

									If($i -eq 128) { 
										# fConfidential Is Set. Make Sure This Is Really Required
										Write-Host "[WARNING] : This attribute has been marked as fConfidential. Please confirm the need to do so!" -Foregroundcolor Yellow
										$tempWarning = "### WARNING : This attribute has been marked as fConfidential. Please confirm the need to do so!"
										Add-Content -path $outputLDIFFile -value $tempWarning
										$global:warningCount += 1                                         
									} 
								} 
							} 
							Write-Host "searchFlags is.......:" $flags
							$tempStr = "# searchFlags:" + $flags 
							Add-Content -path $outputLDIFFile -value $tempStr
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						} 
                     
				"omsyntax"     
						{ 
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							Write-Host "oMSyntax is..........:" $oMSyntaxList[$attributeValue]
							If(!$oMSyntaxList.ContainsKey($attributeValue)) { 
								Write-Host "[ERROR] : The value provided for oMSyntax is invalid. Please correct the value!" -Foregroundcolor Red                                 
								$tempError = "### ERROR : The value provided for oMSyntax is invalid. Please correct the value!"
								Add-Content -path $outputLDIFFile -value $tempError
								$global:errorCount += 1 
								Continue                                 
							} 
							$tempStr = "# oMSyntax:" + $oMSyntaxList[$attributeValue] 
							Add-Content -path $outputLDIFFile -value $tempStr 
							$compareResult = $attributeValue.CompareTo($attributeSyntaxToOmSyntaxList[$attributeSyntaxValue]) 
							If ($compareResult -ne 0) { 
								$omValues = @($attributeSyntaxToOmSyntaxList[$attributeSyntaxValue].Split(","))  
								$compareResult = $attributeValue.CompareTo($omValues[0])  
								If($compareResult -ne 0) { 
									$compareResult = $attributeValue.CompareTo($omValues[1]) 
									If($compareResult -ne 0) {                                 
										Write-Host "###[ERROR] : oMSyntax does not seem to match the attributeSyntax value specified earlier for this attribute!" -Foregroundcolor Red
										$tempError = "### ERROR : oMSyntax does not seem to match the attributeSyntax value specified earlier for this attribute!"
										Add-Content -path $outputLDIFFile -value $tempError
									} 
								} 
							}  
							$attributeSyntaxValue = ""
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						} 
             
				"omobjectclass"  
						{
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							If (!$oMObjectClassList.ContainsKey($attributeValue)) { 
								Write-Host "[ERROR] : oMObjectClass specified is invalid. Please correct the value and try again!" -Foregroundcolor Red                                 
								$tempError = "### ERROR : oMObjectClass specified is invalid. Please correct the value and try again!"
								Add-Content -path $outputLDIFFile -value $tempError
								$global:errorCount += 1 
								Continue 
							} 
							Write-Host "oMObjectClass is.....:" $oMObjectClassList[$attributeValue]
							$tempStr = "# oMObjectClass is:" + $oMObjectClassList[$attributeValue] 
							Add-Content -path $outputLDIFFile -value $tempStr     
							$objectClass = $attributeValue
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						} 
                           
				"objectclass" 
                        {                             
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							If($attributeValue.CompareTo("classSchema") -eq 0) { 
								If($schemaUpdateNowFlag.CompareTo("TRUE") -ne 0 -and $startedAddingClassesFlag.CompareTo("TRUE") -eq 0) {     
									Write-Host "[ERROR] : schemaUpdateNow needs to be inserted before adding new classes!" -Foregroundcolor Red 
									$tempError = "### ERROR : schemaUpdateNow needs to be inserted before adding new classes!"
									Add-Content -path $outputLDIFFile -value $tempError
									$startedAddingClassesFlag = "TRUE"         
									$global:errorCount += 1                     
								} 
							}
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						} 
                           
				"admindescription" 
						{ 
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							If ($attributeValue.length -le 1) {
                                Write-Host "[ERROR] : Adequate description has not been specified. Please correct this!" -Foregroundcolor Red 
								$tempError = "### ERROR : Adequate description has not been specified. Please correct this!"
								Add-Content -path $outputLDIFFile -value $tempError
                                $global:errorCount += 1 
                            }
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						}                       
             
                           
				"systemonly" 
                        {
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$systemOnlyCheck = $attributeValue.CompareTo("TRUE") 
							If ($systemOnlyCheck -eq 0) { 
                                # Object Has Been Flagged As systemOnly. Needs To Be Checked Further. 
                                Write-Host "[ERROR] : This object has been marked as systemOnly. This needs approval from the MSFT Active Directory schema team!" -Foregroundcolor Red 
                                $tempError = "### ERROR : This object has been marked as systemOnly. This needs approval from the MSFT Active Directory schema team!"
								Add-Content -path $outputLDIFFile -value $tempError
                                $global:errorCount += 1 
							}
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						} 
                           
				"attributeid" 
						{ 
							$tempError = $null
							$tempErrorConfirm1 = $null
							$tempErrorConfirm2 = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$tempErrorConfirm1 = checkUniquenessOfattributeIDCurrentSchema($attributeValue)
							$tempErrorConfirm2 = checkUniquenessOfattributeIDNewExtensions($attributeValue)
							If ($tempError -eq $null -And $tempErrorConfirm1 -eq $null -And $tempErrorConfirm2 -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}						
						} 
                           
				"governsid" 
                        { 
							$tempError = $null
							$tempErrorConfirm1 = $null
							$tempErrorConfirm2 = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$tempErrorConfirm1 = checkUniquenessOfgovernsIDCurrentSchema($attributeValue)
							$tempErrorConfirm2 = checkUniquenessOfgovernsIDNewExtensions($attributeValue)
							If ($tempError -eq $null -And $tempErrorConfirm1 -eq $null -And $tempErrorConfirm2 -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						}
						
				"schemaidguid" 
                        { 
							$tempError = $null
							$tempErrorConfirm1 = $null
							$tempErrorConfirm2 = $null
							If ($extraSeparator -eq $null) {
								Write-Host "[ERROR] : Only one semi-colon ':' detected as separator. Two semi-colons '::' must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Only one semi-colon ':' detected as separator. Two semi-colons '::' must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$tempErrorConfirm1 = checkUniquenessOfschemaIDGUIDCurrentSchema($attributeValue)
							$tempErrorConfirm2 = checkUniquenessOfschemaIDGUIDNewExtensions($attributeValue)
							If ($tempError -eq $null -And $tempErrorConfirm1 -eq $null -And $tempErrorConfirm2 -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						} 
             
				"cn" 
                        { 
							$tempError = $null
							$tempErrorConfirm1 = $null
							$tempErrorConfirm2 = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$cnValue = $attributeValue
							If ($changetypeValue -like "add" -or $changetypeValue -like "ntdsSchemaAdd") { 
                                # add operation is being performed for this attribute/class. Make sure that the object doesn't already exist in the schema. 
                                $tempErrorConfirm1 = checkExistenceCurrentSchema($cnValue)
								$tempErrorConfirm2 = checkExistenceCNNewExtensions($cnValue)
                            }     
                            $cnValue = $null
                            #$changetypeValue = ""
							If ($tempError -eq $null -And $tempErrorConfirm1 -eq $null -And $tempErrorConfirm2 -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}						
						}
						  
				"ldapdisplayname" 
                        { 
							$tempError = $null
							$tempErrorConfirm1 = $null
							$tempErrorConfirm2 = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$lDAPDisplayNameValue = $attributeValue
                            If ($changetypeValue -like "add" -or $changetypeValue -like "ntdsSchemaAdd") { 
                                # add operation is being performed for this attribute/class. Make sure that the object doesn't already exist in the schema. 
                                $tempErrorConfirm1 = checkExistenceCurrentSchema($lDAPDisplayNameValue)
								$tempErrorConfirm2 = checkExistenceLDAPDisplayNameNewExtensions($lDAPDisplayNameValue)
                            }     
                            $lDAPDisplayNameValue = $null
                            #$changetypeValue = ""
							If ($tempError -eq $null -And $tempErrorConfirm1 -eq $null -And $tempErrorConfirm2 -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}						
						}
						  
				"linkid" 
						{ 
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							If ($attributeValue -eq "1.2.840.113556.1.2.50") { 
                                $linkedAttrsDisplayNameList.Add($ldapDisplayNameValue, 0);                                 
                                $linkedAttrsOIDList.Add($oid, 0);                                 
                            } Else { 
								If(!$linkedAttrsDisplayNameList.ContainsKey($attributeValue)) { 
                                    If(!$linkedAttrsOIDList.ContainsKey($attributeValue)) { 
                                        Write-Host "[ERROR] : An attempt is being made to access a forward link that doesn't seem to exist. If this is a hard coded linkID that is not valid. Please follow the guidelines for obtaining a linkID!" -Foregroundcolor Red 
                                        $tempError = "### ERROR : An attempt is being made to access a forward link that doesn't seem to exist. If this is a hard coded linkID that is not valid. Please follow the guidelines for obtaining a linkID!"
										Add-Content -path $outputLDIFFile -value $tempError
                                        $global:errorCount += 1 
                                    } Else { 
										$linkedAttrsOIDList[$attributeValue] = $linkedAttrsOIDList[$attributeValue] + 1; 
                                    } 
                                } Else { 
                                    $linkedAttrsDisplayNameList[$attributeValue] = $linkedAttrsDisplayNameList[$attributeValue] + 1;             
                                    Write-Host "[OK] A forward link does exist for this back link. Usage is valid!" -Foregroundcolor Green
									Add-Content -path $outputLDIFFile -value "### A forward link does exist for this back link. Usage is valid!"                           
                                }
								
								If(($consolidatedLDIFFileContent | Select-String -Pattern "^(?i)linkID:.*$($attributeValue)$" | Measure).Count -gt 1) { 
									Write-Host "[ERROR] : The linkID value is already used in the extension. Make sure the linkID is unique!" -Foregroundcolor Red 
									$tempError = "### ERROR : The linkID value is already used in the extension. Make sure the linkID is unique!"
									Add-Content -path $outputLDIFFile -value $tempError
									$global:errorCount += 1 
								}
                            }
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						} 
						  
				"mapiid" 
						{ 
							$tempError = $null
							$tempErrorConfirm1 = $null
							$tempErrorConfirm2 = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$tempErrorConfirm1 = checkUniquenessOfmAPIIDCurrentSchema($attributeValue)
							$tempErrorConfirm2 = checkUniquenessOfmAPIIDNewExtensions($attributeValue)
							If ($tempError -eq $null -And $tempErrorConfirm1 -eq $null -And $tempErrorConfirm2 -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						} 
                           
				# systemMayContain, systemMustContain,systemAuxiliaryClass, systemPossSuperiors 
				# mayContain, mustContain 
				# subClassOf ,  
				# auxiliaryClass   
				# possSuperiors                        
				# ConfirmExistenceofReferencedAttributesOrClasses($attrClassList) 
                           
				"systemmaycontain" 
						{ 
							$tempError = $null
							$tempErrorConfirm = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							If ($changetypeValue -like "modify" -or $changetypeValue -like "ntdsSchemaModify") { 
                                Write-Host "[ERROR] : A systemOnly attribute is being added to an existing object. This operation is not allowed. Addition of systemOnly attributes while creating new objects is permitted!" -Foregroundcolor Red 
                                $tempError = "### ERROR : A systemOnly attribute is being added to an existing object. This operation is not allowed. Addition of systemOnly attributes while creating new objects is permitted!"
								Add-Content -path $outputLDIFFile -value $tempError
                                $global:errorCount += 1  
                            } Else { 
                                Write-Host "[OK] $changeTypeValue operation, so system attribute addition is permitted!" -Foregroundcolor Green
                                $tempErrorConfirm = ConfirmExistenceofReferencedAttributesOrClasses($attributeValue)  
                            } 
							If ($tempError -eq $null -And $tempErrorConfirm -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						}     
                           
				"systemmustcontain" 
						{ 
							$tempError = $null
							$tempErrorConfirm = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							If ($changetypeValue -like "modify" -or $changetypeValue -like "ntdsSchemaModify") { 
                                Write-Host "[ERROR] : A systemOnly attribute is being added to an existing object. This operation is not allowed. Addition of systemOnly attributes while creating new objects is permitted!" -Foregroundcolor Red 
                                $tempError = "### ERROR : A systemOnly attribute is being added to an existing object. This operation is not allowed. Addition of systemOnly attributes while creating new objects is permitted!"
								Add-Content -path $outputLDIFFile -value $tempError
                                $global:errorCount += 1 
                            } Else { 
                                Write-Host "[OK] $changeTypeValue operation, so system attribute addition is permitted!" -Foregroundcolor Green
                                $tempErrorConfirm = ConfirmExistenceofReferencedAttributesOrClasses($attributeValue)  
                            } 
							If ($tempError -eq $null -And $tempErrorConfirm -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						}     
                 
				"systemauxiliaryclass" 
						{ 
							$tempError = $null
							$tempErrorConfirm = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							If ($changetypeValue -like "modify" -or $changetypeValue -like "ntdsSchemaModify") { 
                                Write-Host "[ERROR] : A systemOnly attribute is being added to an existing object. This operation is not allowed. Addition of systemOnly attributes while creating new objects is permitted!" -Foregroundcolor Red 
                                $tempError = "### ERROR : A systemOnly attribute is being added to an existing object. This operation is not allowed. Addition of systemOnly attributes while creating new objects is permitted!"
								Add-Content -path $outputLDIFFile -value $tempError
                                $global:errorCount += 1   
                            } Else { 
                                Write-Host "[OK] $changeTypeValue operation, so system attribute addition is permitted!" -Foregroundcolor Green
                                $tempErrorConfirm = ConfirmExistenceofReferencedAttributesOrClasses($attributeValue)  
                            } 
							If ($tempError -eq $null -And $tempErrorConfirm -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						}     
                           
				"systemposssuperiors" 
						{ 
							$tempError = $null
							$tempErrorConfirm = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							If ($changetypeValue -like "modify" -or $changetypeValue -like "ntdsSchemaModify") { 
                                Write-Host "[ERROR] : A systemOnly attribute is being added to an existing object. This operation is not allowed. Addition of systemOnly attributes while creating new objects is permitted!" -Foregroundcolor Red 
                                $tempError = "### ERROR : A systemOnly attribute is being added to an existing object. This operation is not allowed. Addition of systemOnly attributes while creating new objects is permitted!"
								Add-Content -path $outputLDIFFile -value $tempError
                                $global:errorCount += 1 
                            } Else { 
                                Write-Host "[OK] $changeTypeValue operation, so system attribute addition is permitted!" -Foregroundcolor Green
                                $tempErrorConfirm = ConfirmExistenceofReferencedAttributesOrClasses($attributeValue) 
                            } 
							If ($tempError -eq $null -And $tempErrorConfirm -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						}                                              
                      
				"m*contain" 
						{ 
							$tempError = $null
							$tempErrorConfirm = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$tempErrorConfirm = ConfirmExistenceofReferencedAttributesOrClasses($attributeValue)
							If ($tempError -eq $null -And $tempErrorConfirm -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						} 
                          
				"subclassof" 
						{
							$tempError = $null
							$tempErrorConfirm = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$tempErrorConfirm = ConfirmExistenceofReferencedAttributesOrClasses($attributeValue)
							If ($tempError -eq $null -And $tempErrorConfirm -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
                        } 
             
				"*auxiliaryclass" 
                        { 
							$tempError = $null
							$tempErrorConfirm = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$tempErrorConfirm = ConfirmExistenceofReferencedAttributesOrClasses($attributeValue)
							If ($tempError -eq $null -And $tempErrorConfirm -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
                        } 
                          
				"posssuperiors" 
                        { 
							$tempError = $null
							$tempErrorConfirm = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$tempErrorConfirm = ConfirmExistenceofReferencedAttributesOrClasses($attributeValue)
							If ($tempError -eq $null -And $tempErrorConfirm -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
                        }       
                                       
				"ismemberofpartialattributeset" 
						{ 
							$tempError = $null
							$tempWarning = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$attributeValue = $attributeValue.ToLower() 
                            If($attributeValue.CompareTo("true") -eq 0) { 
                                Write-Host "[WARNING] : Attribute has been marked as a member of the partial attribute set. Please confirm this requirement!" -Foregroundcolor Yellow
                                $tempWarning = "### WARNING : Attribute has been marked as a member of the partial attribute set. Please confirm this requirement!" 
								Add-Content -path $outputLDIFFile -value $tempWarning
                                $global:warningCount += 1 
                            }
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						} 
             
				"schemaupgradeinprogress" 
                        { 
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$attributeValue = $attributeValue.ToLower() 
                            If($attributeValue.CompareTo("true") -eq 0) { 
                                Write-Host "[ERROR] : Invalid element. Please consider removing it!" -Foregroundcolor Red 
                                $tempError = "### ERROR : Invalid element. Please consider removing it!" 
								Add-Content -path $outputLDIFFile -value $tempError
                                $global:errorCount += 1 
                            }
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						} 
                          
				"schemaupdatenow" 
                        { 
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							If($attributeValue.CompareTo("1") -eq  0) { 
                                $schemaUpdateNowFlag = "TRUE"
                            }
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
                        } 
                          
				"oid" 
                        { 
                            $oid = $attributeValue;
                        } 
            
				"objectclasscategory" 
                        { 
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							switch ($attributeValue) { 
                                "structural" 
									{                                     
										Add-Content -path $outputLDIFFile -value "###ObjectClassCategory : Structural" 
									} 
                                 
								"auxiliary" 
									{                                  
										Add-Content -path $outputLDIFFile -value "###ObjectClassCategory : Auxiliary" 
									} 
                                 
                                "abstract" 
									{ 
										Add-Content -path $outputLDIFFile -value "###ObjectClassCategory : Abstract" 
									} 
                                 
                                "88" 
									{ 
										Add-Content -path $outputLDIFFile -value "###ObjectClassCategory : 88" 
									} 
                                 
                                default 
									{                                     
										Write-Host "[ERROR] : The value provided for objectClassCategory $attributeValue is not valid. Please correct it and try again. Accepted values are Structural, Auxiliary, Abstract, 88!" -Foregroundcolor Red 
										$tempError = "### ERROR : The value provided for objectClassCategory $attributeValue is not valid. Please correct it and try again. Accepted values are Structural, Auxiliary, Abstract, 88!" 
										Add-Content -path $outputLDIFFile -value $tempError
										$global:errorCount += 1 
									} 
                            }
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
                        } 
                         
				"rdnattid" 
                        { 
							$tempError = $null
							$tempErrorConfirm = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$tempErrorConfirm = checkSyntaxOfRdnattidAttribute($attributeValue)
							If ($tempError -eq $null -And $tempErrorConfirm -eq $null) {
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
                        } 
                         
				"changetype" 
                        { 
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$changetypeValue = $attributeValue
							$attributeValue = $attributeValue.ToLower() 
                            switch($attributeValue) { 
                                "add" 
									{ 
										Write-Host "[OK] : Allowed changeType" -Foregroundcolor Green
									} 
                                  
                                "ntdsschemaadd" 
									{ 
										Write-Host "[OK] : Allowed changeType" -Foregroundcolor Green
									} 
                                  
                                "modify" 
									{ 
										Write-Host "[OK] : Allowed changeType" -Foregroundcolor Green
									} 
                                  
                                "ntdsschemamodify" 
									{ 
										Write-Host "[OK] : Allowed changeType" -Foregroundcolor Green
									} 
                                  
                                "delete" 
									{ 
										Write-Host "[OK] : Allowed changeType" -Foregroundcolor Green
									} 
                                  
                                "ntdsschemadelete" 
									{ 
										Write-Host "[OK] : Allowed changeType" -Foregroundcolor Green
									} 
                                  
                                "ntdsschemamodrdn" 
									{ 
										Write-Host "[OK] : Allowed changeType" -Foregroundcolor Green
									} 
                                  
                                 default 
									{ 
										Write-Host "[ERROR] : ChangeType " $attributeValue " is invalid. Allowed changeType values are - add, ntdsschemaadd, modify, ntdsschemamodify, delete, ntdsschemadelete, ntdsschemamodrdn." 
										$tempError = "### ERROR : ChangeType value is invalid. Allowed changeType values are - add, ntdsschemaadd, modify, ntdsschemamodify, delete, ntdsschemadelete, ntdsschemamodrdn." 
										Add-Content -path $outputLDIFFile -value $tempError
										$global:errorCount += 1 
									} 
                            }
							$schemaUpdateNowFlag = "FALSE"
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						}

				"rangelower" 
						{ 
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$rangeLower = $attributeValue
							If ($rangeLower -notmatch "^[0-9]+$") {
								Write-Host "[ERROR] : The rangeLower property must only contain numeric values. Please correct this!" -Foregroundcolor Red 
								$tempError = "### ERROR : The rangeLower property must only contain numeric values. Please correct this!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							If ($rangeLower -ne $null -And $rangeLower -match "^[0-9]+$" -And $rangeUpper -ne $null -And $rangeUpper -match "^[0-9]+$") {
								If ($rangeLower -gt $rangeUpper) {
									Write-Host "[ERROR] : The rangeLower property has a higher value than rangeUpper property. Please correct this!" -Foregroundcolor Red 
									$tempError = "### ERROR : The rangeLower property has a higher value than rangeUpper property. Please correct this!" 
									Add-Content -path $outputLDIFFile -value $tempError 
									$global:errorCount += 1 
									continue 
								}
							}
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						}

				"rangeupper"  
						{ 
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							$rangeUpper = $attributeValue
							If ($rangeUpper -notmatch "^[0-9]+$") {
								Write-Host "[ERROR] : The rangeUpper property must only contain numeric values. Please correct this!" -Foregroundcolor Red 
								$tempError = "### ERROR : The rangeUpper property must only contain numeric values. Please correct this!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							If ($rangeLower -ne $null -And $rangeLower -match "^[0-9]+$" -And $rangeUpper -ne $null -And $rangeUpper -match "^[0-9]+$") {
								If ($rangeLower -gt $rangeUpper) {
									Write-Host "[ERROR] : The rangeUpper property has a lower value than rangeLower property. Please correct this!" -Foregroundcolor Red 
									$tempError = "### ERROR : The rangeUpper property has a lower value than rangeLower property. Please correct this!" 
									Add-Content -path $outputLDIFFile -value $tempError 
									$global:errorCount += 1 
									continue 
								}
							}
							If ($tempError -eq $null){
								Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
							}
						}					
						
				default 
						{ 
							$tempError = $null
							If ($extraSeparator -ne $null) {
								Write-Host "[ERROR] : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" -Foregroundcolor Red 
								$tempError = "### ERROR : Multiple semi-colons ':' detected as separator. Only one semi-colon must be used for this attribute. Please correct that!" 
								Add-Content -path $outputLDIFFile -value $tempError 
								$global:errorCount += 1 
								continue 
							}
							Write-Host "[OK] : No issues/problems detected!" -Foregroundcolor Green
						}
		} 
        Write-Host "*******************************************************************************************************************" -Foregroundcolor DarkCyan
    }
  } 
   
  Write-Host "`n                                                    +++ SUMMARY +++" -Foregroundcolor Cyan
  Write-Host "                                                    Errors....: " $errorCount -Foregroundcolor Red
  Write-Host "                                                    Warnings..: " $warningCount -Foregroundcolor Yellow 

  Write-Host "REMARK: This script just helps you to validate new schema extensions and give you more confidence about the new" -Foregroundcolor Red
  Write-Host "extensions. However, it is in no way a full replacement of designing, validating, testing and implementing the" -Foregroundcolor Red
  Write-Host "extension. YOU remain responsible for the end-to-end process of correctly implementing any new extension into" -Foregroundcolor Red
  Write-Host "the schema!" -Foregroundcolor Red
  
  # Now that the whole file has been checked go through the $linkedAttrsOIDList and $linkedAttrsDisplayNameList to make sure the reference counts are > 0 
  # A count of zero means that a forward link was created but a back link was never created for it 
} 

# Main Program
Function global:ExtensionChecker() {     
    Write-Host "`nValidating Extensions...`n"
	
	# Get The Script Path
	$scriptFolderPath = (Get-Location).Path
	
	# Process All Specified Input Files And Get The Combined Content
	$consolidatedLDIFFileContent = $null
	$consolidatedLDIFFile = "combinedSchemaExtensions.ldif"
	$consolidatedLDIFFileFullPath = $scriptFolderPath + "\" + $consolidatedLDIFFile
	If (Test-Path $consolidatedLDIFFileFullPath) {
		Clear-Content $consolidatedLDIFFileFullPath
	}
    ForEach ($inputLDIFFile in $inputLDIFFileList) { 
        Write-Host "`nInput File To Validate..........:" $inputLDIFFile
		If(!(Test-Path $inputLDIFFile)) { 
			Write-Host "`nInput file provided " $inputLDIFFile " does not exist. Please check the path and try again.`n" -Foregroundcolor Red
			Exit
		}  
		$inputLDIFFileContent = Get-Content $inputLDIFFile
		Add-Content $consolidatedLDIFFileFullPath "############################################################################################################"
		Add-Content $consolidatedLDIFFileFullPath "### INPUT FILE: $inputLDIFFile"
		Add-Content $consolidatedLDIFFileFullPath "###---------------------------------------------------------------------------------------------------------"
		Add-Content $consolidatedLDIFFileFullPath $inputLDIFFileContent
    }
	Write-Host "`nConsolidated Input File Used....:" $consolidatedLDIFFileFullPath
	$consolidatedLDIFFileContent = Get-Content $consolidatedLDIFFileFullPath
	
	# Create A New Output File For The Results
	If ($outputLDIFFile -notmatch ":\\") {
		$outputLDIFFile = $scriptFolderPath + "\" + $outputLDIFFile
	}
	Write-Host "`nResults File With Corrections...:" $outputLDIFFile
	New-Item -ItemType file $outputLDIFFile -force  | Out-Null

	# Export The Schema If Not Schema File Was Specified
	If (!$currentSchemaLDIFFile) {
		$ThisADForest = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
		$fqdnSchemaFSMO = $ThisADForest.SchemaRoleOwner.Name
		Write-Host "`nNo current schema file specified. Attempting to grab the schema from the Schema FSMO ($fqdnSchemaFSMO)..." 
		$currentSchemaLDIFFile = $scriptFolderPath + "\currentSchemaLDIFFile.ldif"
		CMD.EXE /C "START /Wait LDIFDE.EXE -s $fqdnSchemaFSMO -f $currentSchemaLDIFFile -d #SchemaNamingContext -c #DefaultNamingContext DC=X"
	}
	
	# Get The Content From The Current Schema File
	Write-Host "`nCurrent Schema File.............:" $currentSchemaLDIFFile
	Write-Host ""
	If(!(Test-Path $currentSchemaLDIFFile)) { 
		Write-Host "`nSchema file " $currentSchemaLDIFFile " does not exist. Please check the path and try again.`n" -Foregroundcolor Red
		Exit
	} Else {
		$currentSchemaLDIFFileContent = Get-Content $currentSchemaLDIFFile
	}
	
	# Go For It And Validate The Extensions
	ValidateExtensions
}

# Execute Main Program
ExtensionChecker($args)