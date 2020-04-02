### Abstract: This PoSH Script Creates An (HTML) Report Of All Password Policies Within The AD Forest
###
### Written by: Jorge de Almeida Pinto [MVP-EMS]
### BLOG: http://jorgequestforknowledge.wordpress.com/
### E-Mail Address For Feedback/Questions: scripts.gallery@iamtec.eu
###
### Paste The Following Quick Link Between The Double Quotes In Browser To Send Mail:
### --> "mailto:Jorge's Script Gallery <scripts.gallery@iamtec.eu>?subject=[Script Gallery Feedback:] 'REPLACE-THIS-PART-WITH-SOMETHING-MEANINGFULL'"
###
### For Questions/Feedback:
### --> Please Describe Your Scenario As Best As Possible With As Much Detail As Possible.
### --> If Applicable Describe What Does and Does Not Work.
### --> If Applicable Describe What Should Be/Work Different And Explain Why/How.
### --> Please Add Screendumps.
###

<#
.SYNOPSIS
	This PoSH Script Creates An (HTML) Report Of All Password Policies Within The AD Forest

.VERSION
	v0.2, 2020-02-06
	
.AUTHOR
	Written By....................: Jorge de Almeida Pinto [MVP Enterprise Mobility And Security, EMS]
	Re-Written By.................: N.A.
	Blog..........................: http://jorgequestforknowledge.wordpress.com/
	For Feedback/Questions........: scripts.gallery@iamtec.eu ("mailto:Jorge's Script Gallery <scripts.gallery@iamtec.eu>?subject=[Script Gallery Feedback:] 'REPLACE-THIS-PART-WITH-SOMETHING-MEANINGFULL'")
	
.DESCRIPTION
	This PoSH Script Fixes Targeted Accounts In The AD Forest With Regards To Security Related Configurations

.TODO
	- N.A.

.KNOWN ISSUES/BUGS
	- N.A.

.RELEASE NOTES
	v0.2, 2020-02-06, Jorge de Almeida Pinto [MVP-EMS]:
		- Updated some variables and add condition for "Forever" for Max Pwd Age and lockout duration

	v0.1, 2020-02-06, Jorge de Almeida Pinto [MVP-EMS]:
		- Initial version of the script

.DESCRIPTION
	This PoSH Script creates an HTML report of all Password And Account Lockout Policies It Finds In The AD Forest.
	It takes into account settings in both the Default Domain Policy and Password Settings Objects (PSOs)

.EXAMPLE
	Remove "Cannot Change Password" Configuration From All Targeted Accounts (Enabled, Disabled Or All)

	.\Build-Password-Policy-Config-Report.ps1

.NOTES
	This script requires:
	* PowerShell Module: ActiveDirectory, 
	* To read info from the Default Domain Context, a regular user account is good enough
    * To read PSOs an account with:
		> "Domain Admins" permissions if the AD forest has a single AD domain, OR
		> "Enterprise Admins" permissions if the AD forest has multiple AD domains, OR
		> Delegated permissions to read PSO objects and attributes from any AD domain in the AD forest
#>

### FUNCTION: Load Required PowerShell Modules
Function loadPoSHModules($poSHModule) {
	If(@(Get-Module | Where-Object {$_.Name -eq $poSHModule}).count -eq 0) {
		If(@(Get-Module -ListAvailable | Where-Object {$_.Name -eq $poSHModule} ).count -ne 0) {
			Import-Module $poSHModule
			Write-Host ""
			Write-Host "PoSH Module '$poSHModule' Has Been Loaded..." -ForeGroundColor Green
			Write-Host "Continuing Script..." -ForeGroundColor Green
			Write-Host ""
		} Else {
			Write-Host ""
			Write-Host "PoSH Module '$poSHModule' Is Not Available To Load..." -ForeGroundColor Red
			Write-Host "Aborting Script..." -ForeGroundColor Red
			Write-Host ""
			
			EXIT
		}
	} Else {
		Write-Host ""
		Write-Host "PoSH Module '$poSHModule' Already Loaded..." -ForeGroundColor Yellow
		Write-Host "Continuing Script..." -ForeGroundColor Yellow
		Write-Host ""
	}
}

### FUNCTION: Advanced Conversion Of Output To HTML With Additional Features
# SOURCE: https://thesurlyadmin.com/script-help/convertto-advhtml-help/
# SOURCE: https://community.spiceworks.com/scripts/show/2448-create-advanced-html-tables-in-powershell-convertto-advhtml
Function ConvertTo-AdvHTML {
    <#
    .SYNOPSIS
        Advanced replacement of ConvertTo-HTML cmdlet
    .DESCRIPTION
        This function allows for vastly greater control over cells and rows
        in a HTML table.  It takes ConvertTo-HTML to a whole new level!  You
        can now specify what color a cell or row is (either dirctly or through 
        the use of CSS).  You can add links, pictures and pictures AS links.
        You can also specify a cell to be a bar graph where you control the 
        colors of the graph and text that can be included in the graph.
        
        All color functions are through the use of imbedded text tags inside the
        properties of the object you pass to this function.  It is important to note 
        that this function does not do any processing for you, you must make sure all 
        control tags are already present in the object before passing it to the 
        function.
        
        Here are the different tags available:
        
        Syntax                          Comment
        ===================================================================================
        [cell:<color>]<optional text>   Designate the color of the cell.  Must be 
                                        at the beginning of the string.
                                        Example:
                                            [cell:red]System Down

        [text:<color>]<optional text>   Designate the color of the text.  Must be 
                                        at the beginning of the string.
                                        Example:
                                            [text:red]System Down
                                            
        [row:<color>]                   Designate the color of the row.  This control
                                        can be anywhere, in any property of the object.
                                        Example:
                                            [row:orchid]
                                            
        [cellclass:<class>]<optional text>  
                                        Designate the color, and other properties, of the
                                        cell based on a class in your CSS.  You must 
                                        have the class in your CSS (use the -CSS parameter).
                                        Must be at the beginning of the string.
                                        Example:
                                            [cellclass:highlight]10mb
                                            
        [rowclass:<class>]              Designate the color, and other properties, of the
                                        row based on a class in your CSS.  You must 
                                        have the class in your CSS (use the -CSS parameter).
                                        This control can be anywhere, in any property of the 
                                        object.
                                        Example:
                                            [rowclass:greyishbold]
                                            
        [image:<height;width;url>]<alternate text>
                                        Include an image in your cell.  Put size of picture
                                        in pixels and url seperated by semi-colons.  Format
                                        must be height;width;url.  You can also include other
                                        text in the cell, but the [image] tag must be at the
                                        end of the tag (so the alternate text is last).
                                        Example:
                                            [image:100;200;http://www.sampleurl.com/sampleimage.jpg]Alt Text For Image
                                            
        [link:<url>]<link text>         Include a link in your cell.  Other text is allowed in
                                        the string, but the [link] tag must be at the end of the 
                                        string.
                                        Example:
                                            blah blah blah [link:www.thesurlyadmin.com]Cool PowerShell Link
                                            
        [linkpic:<height;width;url to pic>]<url for link>
                                        This tag uses a picture which you can click on and go to the
                                        specified link.  You must specify the size of the picture and 
                                        url where it is located, this information is seperated by semi-
                                        colons.  Other text is allowed in the string, but the [link] tag 
                                        must be at the end of the string.
                                        Example:
                                            [linkpic:100;200;http://www.sampleurl.com/sampleimage.jpg]www.thesurlyadmin.com
                                            
        [bar:<percent;bar color;remainder color>]<optional text>
                                        Bar graph makes a simple colored bar graph within the cell.  The
                                        length of the bar is controlled using <percent>.  You can 
                                        designate the color of the bar, and the color of the remainder
                                        section.  Due to the mysteries of HTML, you must designate a 
                                        width for the column with the [bar] tag using the HeadWidth parameter.
                                        
                                        So if you had a percentage of 95, say 95% used disk you
                                        would want to highlight the remainder for your report:
                                        Example:
                                            [bar:95;dark green;red]5% free
                                        
                                        What if you were at 30% of a sales goal with only 2 weeks left in
                                        the quarter, you would want to highlight that you have a problem.
                                        Example:
                                            [bar:30;darkred;red]30% of goal
    .PARAMETER InputObject
        The object you want converted to an HTML table
    .PARAMETER HeadWidth
        You can specify the width of a cell.  Cell widths are in pixels
        and are passed to the parameter in array format.  Each element
        in the array corresponds to the column in your table, any element
        that is set to 0 will designate the column with be dynamic.  If you had
        four elements in your InputObject and wanted to make the 4th a fixed
        width--this is required for using the [bar] tag--of 600 pixels:
        
        -HeadWidth 0,0,0,600
    .PARAMETER CSS
        Designate custom CSS for your HTML
    .PARAMETER Title
        Specifies a title for the HTML file, that is, the text that appears between the <TITLE> tags.
    .PARAMETER PreContent
        Specifies text to add before the opening <TABLE> tag. By default, there is no text in that position.
    .PARAMETER PostContent
        Specifies text to add after the closing </TABLE> tag. By default, there is no text in that position.
    .PARAMETER Body
        Specifies the text to add after the opening <BODY> tag. By default, there is no text in that position.
    .PARAMETER Fragment
        Generates only an HTML table. The HTML, HEAD, TITLE, and BODY tags are omitted.
    .INPUTS
        System.Management.Automation.PSObject
        You can pipe any .NET object to ConvertTo-AdvHtml.
    .OUTPUTS
        System.String
        ConvertTo-AdvHtml returns series of strings that comprise valid HTML.
    .EXAMPLE
        $Data = @"
Server,Description,Status,Disk
[row:orchid]Server1,Hello1,[cellclass:up]Up,"[bar:45;Purple;Orchid]55% Free"
Server2,Hello2,[cell:green]Up,"[bar:65;DarkGreen;Green]65% Used"
Server3,Goodbye3,[cell:red]Down,"[bar:95;DarkGreen;DarkRed]5% Free"
server4,This is quite a cool test,[cell:green]Up,"[image:150;650;http://pughspace.files.wordpress.com/2014/01/test-connection.png]Test Images"
server5,SurlyAdmin,[cell:red]Down,"[link:http://thesurlyadmin.com]The Surly Admin"
server6,MoreSurlyAdmin,[cell:purple]Updating,"[linkpic:150;650;http://pughspace.files.wordpress.com/2014/01/test-connection.png]http://thesurlyadmin.com"
"@
        $Data1 = $Data | ConvertFrom-Csv
        $HTML = $Data1 | ConvertTo-AdvHTML -HeadWidth 0,0,0,600 -PreContent "<p><h1>This might be the best report EVER</h1></p><br>" -PostContent "<br>Done! $(Get-Date)" -Title "Cool Test!"
        
        This is some sample code where I try to put every possibile tag and use into a single set
        of data.  $Data is the PSObject 4 columns.  Default CSS is used, so the [cellclass:up] tag
        will not work but I left it there so you can see how to use it.
    .NOTES
        Author:             Martin Pugh
        Twitter:            @thesurlyadm1n
        Spiceworks:         Martin9700
        Blog:               www.thesurlyadmin.com
          
        Changelog:
            1.0             Initial Release
    .LINK
        http://thesurlyadmin.com/convertto-advhtml-help/
    .LINK
        http://community.spiceworks.com/scripts/show/2448-create-advanced-html-tables-in-powershell-convertto-advhtml
    #>
    #requires -Version 2.0
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true)]
        [Object[]]$InputObject,
        [string[]]$HeadWidth,
        [string]$CSS = @"
<style>
TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;font-size:120%;}
TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
</style>
"@,
        [string]$Title,
        [string]$PreContent,
        [string]$PostContent,
        [string]$Body,
        [switch]$Fragment
    )
    
    Begin {
        If ($Title)
        {   $CSS += "`n<title>$Title</title>`n"
        }
        $Params = @{
            Head = $CSS
        }
        If ($PreContent)
        {   $Params.Add("PreContent",$PreContent)
        }
        If ($PostContent)
        {   $Params.Add("PostContent",$PostContent)
        }
        If ($Body)
        {   $Params.Add("Body",$Body)
        }
        If ($Fragment)
        {   $Params.Add("Fragment",$true)
        }
        $Data = @()
    }
    
    Process {
        ForEach ($Line in $InputObject)
        {   $Data += $Line
        }
    }
    
    End {
        $Html = $Data | ConvertTo-Html @Params

        $NewHTML = @()
        ForEach ($Line in $Html)
        {   If ($Line -like "*<th>*")
            {   If ($Headwidth)
                {   $Index = 0
                    $Reg = $Line | Select-String -AllMatches -Pattern "<th>(.*?)<\/th>"
                    ForEach ($th in $Reg.Matches)
                    {   If ($Index -le ($HeadWidth.Count - 1))
                        {   If ($HeadWidth[$Index] -and $HeadWidth[$Index] -gt 0)
                            {   $Line = $Line.Replace($th.Value,"<th style=""width:$($HeadWidth[$Index])px"">$($th.Groups[1])</th>")
                            }
                        }
                        $Index ++
                    }
                }
            }
        
            Do {
                Switch -regex ($Line)
                {   "<td>\[cell:(.*?)\].*?<\/td>"
                    {   $Line = $Line.Replace("<td>[cell:$($Matches[1])]","<td style=""background-color:$($Matches[1])"">")
                        Break
                    }
					"<td>\[text:(.*?)\].*?<\/td>"
                    {   $Line = $Line.Replace("<td>[text:$($Matches[1])]","<td><p style=""color:$($Matches[1])"">")
						$Line = $Line.Replace("</td>","</p></td>")
                        Break
                    }
                    "\[cellclass:(.*?)\]"
                    {   $Line = $Line.Replace("<td>[cellclass:$($Matches[1])]","<td class=""$($Matches[1])"">")
                        Break
                    }
                    "\[row:(.*?)\]"
                    {   $Line = $Line.Replace("<tr>","<tr style=""background-color:$($Matches[1])"">")
                        $Line = $Line.Replace("[row:$($Matches[1])]","")
                        Break
                    }
                    "\[rowclass:(.*?)\]"
                    {   $Line = $Line.Replace("<tr>","<tr class=""$($Matches[1])"">")
                        $Line = $Line.Replace("[rowclass:$($Matches[1])]","")
                        Break
                    }
                    "<td>\[bar:(.*?)\](.*?)<\/td>"
                    {   $Bar = $Matches[1].Split(";")
                        $Width = 100 - [int]$Bar[0]
                        If (-not $Matches[2])
                        {   $Text = "&nbsp;"
                        }
                        Else
                        {   $Text = $Matches[2]
                        }
                        $Line = $Line.Replace($Matches[0],"<td><div style=""background-color:$($Bar[1]);float:left;width:$($Bar[0])%"">$Text</div><div style=""background-color:$($Bar[2]);float:left;width:$width%"">&nbsp;</div></td>")
                        Break
                    }
                    "\[image:(.*?)\](.*?)<\/td>"
                    {   $Image = $Matches[1].Split(";")
                        $Line = $Line.Replace($Matches[0],"<img src=""$($Image[2])"" alt=""$($Matches[2])"" height=""$($Image[0])"" width=""$($Image[1])""></td>")
                    }
                    "\[link:(.*?)\](.*?)<\/td>"
                    {   $Line = $Line.Replace($Matches[0],"<a href=""$($Matches[1])"">$($Matches[2])</a></td>")
                    }
                    "\[linkpic:(.*?)\](.*?)<\/td>"
                    {   $Image = $Matches[1].Split(";")
                        $Line = $Line.Replace($Matches[0],"<a href=""$($Matches[2])""><img src=""$($Image[2])"" height=""$($Image[0])"" width=""$($Image[1])""></a></td>")
                    }
                    Default
                    {   Break
                    }
                }
            } Until ($Line -notmatch "\[.*?\]")
            $NewHTML += $Line
        }
        Return $NewHTML
    }
}

### FUNCTION: Export Output To An HTML File
Function exportToHTMLFile($outputHTMLFilePath, $dataContentToProcess, $outputHTMLHeadWidth, $outputHTMLTitle, $outputHTMLPreContent, $outputHTMLPostContent) {
	$dataContentToProcess | ConvertTo-AdvHTML -HeadWidth $outputHTMLHeadWidth -Title $outputHTMLTitle -PreContent $outputHTMLPreContent -PostContent $outputHTMLPostContent | Out-File $outputHTMLFilePath
}

### Clear The Screen
Clear-Host

### Configure The Appropriate Screen And Buffer Size To Make Sure Everything Fits Nicely
$uiConfig = (Get-Host).UI.RawUI
$uiConfig.WindowTitle = "+++ BUILD PASSWORD POLICY CONFIG HTML REPORT +++"
$uiConfig.ForegroundColor = "Yellow"
$uiConfigBufferSize = $uiConfig.BufferSize
$uiConfigBufferSize.Width = 300
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
If ($uiConfigScreenSizeMaxHeight -lt 60) {
	$uiConfigScreenSize.Height = $uiConfigScreenSizeMaxHeight - 5
} Else {
	$uiConfigScreenSize.Height = 60
}
$uiConfig.BufferSize = $uiConfigBufferSize
$uiConfig.WindowSize = $uiConfigScreenSize

### Definition Of Some Constants
$execDateTime = Get-Date
$execDateTimeDisplay = Get-Date $execDateTime -f "yyyy-MM-dd HH:mm:ss"
$currentScriptFolderPath = Split-Path $MyInvocation.MyCommand.Definition

Write-Host ""
Write-Host "                                                               **********************************************************"
Write-Host "                                                               *                                                        *"
Write-Host "                                                               *    --> Build Password Policy Config HTML Report <--    *"
Write-Host "                                                               *                                                        *"
Write-Host "                                                               *      Written By: Jorge de Almeida Pinto [MVP-EMS]      *"
Write-Host "                                                               *                                                        *"
Write-Host "                                                               *   BLOG: http://jorgequestforknowledge.wordpress.com/   *"
Write-Host "                                                               *                                                        *"
Write-Host "                                                               **********************************************************"
Write-Host ""

### Test For Availability Of PowerShell CMDlets And Load Required PowerShell Module
"ActiveDirectory" | ForEach-Object{loadPoSHModules $_}


### Retrieve AD Forest Info
$adforest = Get-ADForest

# AD Forest FQDN
$adForestRootDomainFQDN = $adforest.RootDomain

# AD Forest Root Domain
$adForestRootDomain = Get-ADDomain $adForestRootDomainFQDN

# AD Forest DN
$adForestRootDomainDN = $adForestRootDomain.DistinguishedName

# Nearest AD DC For AD Forest Info
$adRwdcFQDN = ((Get-ADDomainController -Discover).HostName)[0]

# Root DSE Of The AD DC
$adRootDSENearestRWDC = Get-ADRootDSE -Server $adRwdcFQDN

# Config NC DN
$adForestConfigNC = $adRootDSENearestRWDC.configurationNamingContext

### Retrieve AD Domain FQDNs In AD Forest And Build The Order As Such The Forest Root AD Domain Is At The Top Of The List
# Get All AD Domains In The AD Forest
$adDomainFQDNs = $adforest.Domains

# Define Empty List Of FQDNs In The AD Forest
$script:adDomainFQDNList = @()

# Add The Forest Root AD Domain To That List
$script:adDomainFQDNList += $adForestRootDomainFQDN

# Continue If There Is More Than 1 AD Domain In The AD Forest
If ($adDomainFQDNs.Count -gt 1) {
	# For Every Child AD Domain Under The Forest Root AD Domain Add It In A Sorted Manner To That List
	$adDomainFQDNs | Where-Object{$_ -ne $adForestRootDomainFQDN -And $_ -match $adForestRootDomainFQDN} | Sort-Object | ForEach-Object{
		$script:adDomainFQDNList += $_
	}
	# Retrieve All Cross References In The AD Forest To Determine If other Tree Roots Are Available Or Not
	$adDomainCrossRefs = Get-ADObject -LDAPFilter "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))" -SearchBase "CN=Partitions,$adForestConfigNC" -Properties *
	$adRootDomainCrossRefDN = ($adDomainCrossRefs | Where-Object{$_.nCName -eq $adForestRootDomainDN}).DistinguishedName
	
	# For Every Cross Reference Found Process It
	If ($adDomainCrossRefs) {
		# For Every Cross Reference Not Being The One For The Forest Root AD Domain, But Rather A Tree Root AD Domain, Process it
		$adDomainCrossRefs | Where-Object{$_.rootTrust -eq $adRootDomainCrossRefDN} | ForEach-Object{
			# Distinguished Name Of The Naming Context Of The Tree Root AD Domain
			$ncName = $null
			$ncName = $_.nCName
			
			# The FQDN Of The Tree Root AD Domain
			$adDomainFQDN = $null
			$adDomainFQDN = $ncName.Replace(",DC=",".").Replace("DC=","")
			
			# Add It To The List Of FQDNs
			$script:adDomainFQDNList += $adDomainFQDN
			
			# For Every Child AD Domain Of The Tree Root AD Domain Add It In A Sorted Manner To That List
			$adDomainFQDNs | Where-Object{$_ -ne $adDomainFQDN -And $_ -match $adDomainFQDN} | Sort-Object | ForEach-Object{
				$script:adDomainFQDNList += $_
			}
		}
	}
}

### Create Empty List For All Password Policies
$pwdPolList = @()

### For Every AD Domain Retrieve Password And Account Lockout Policies
$adDomainFQDNList | ForEach-Object{
	# AD Domain FQDN
	$adDomainFQDN = $null
	$adDomainFQDN = $_
	
	# AD Domain Object
	$adDomain = $null
	$adDomain = Get-ADDomain $adDomainFQDN
	
	# AD Domain DN
	$adDomainDN = $null
	$adDomainDN = $adDomain.DistinguishedName
	
	# RWDC With PDC FSMO Role In AD Domain
	$adDomainRWDCpdcFQDN = $null
	$adDomainRWDCpdcFQDN = $adDomain.PDCEmulator
	
	# Retrieving The Password And Account Lockout Policy Settings From The Domain NC (Which Are Configured By Default In The Default Domain Policy GPO)
	$adDomainNC = $null
	$adDomainNC = Get-ADObject -Identity $adDomainDN -Properties * -Server $adDomainRWDCpdcFQDN
	
	# Max Password Age
	$defDomPolMaxPwdAge = $null
	If ($($adDomainNC.maxPwdAge) -eq -9223372036854775808) {
	    $defDomPolMaxPwdAge = "Forever"
	} Else {
        $defDomPolMaxPwdAge = $($($($adDomainNC.maxPwdAge) * -1 / (24 * 60 * 60 * 10000000)).ToString() + " days")
    }
	
	# Min Password Age
	$defDomPolMinPwdAge = $null
	$defDomPolMinPwdAge = $($($($adDomainNC.minPwdAge) * -1 / (24 * 60 * 60 * 10000000)).ToString() + " days")
	
	# Min Password Length
	$defDomPolMinPwdLen = $null
	$defDomPolMinPwdLen = $adDomainNC.minPwdLength
	
	# Password History Length
	$defDomPolPwdHistLen = $null
	$defDomPolPwdHistLen = $adDomainNC.pwdHistoryLength
	
	# Password Complexity Enabled Or Not
	$defDomPolPwdComplexOn = $null	
	$defDomPolPwdComplexOn = If (($adDomainNC.pwdProperties -band 1) -eq 1) {"True"} Else {"False"}
	
	# Password Clear Text Storage Enabled Or Not
	$defDomPolPwdRevEncrOn = $null
	$defDomPolPwdRevEncrOn = If (($adDomainNC.pwdProperties -band 16) -eq 16) {"True"} Else {"False"}
	
	# To Whom This Particular Password Policy Applies
	$appliesToList = $null
	$appliesToList = "<All Users In AD Domain>"
	
	# Lockout Duration After An Account Is Locked
	$defDomPolLockDuration = $null
	If ($($adDomainNC.lockoutDuration) -eq -9223372036854775808) {
	    $defDomPolLockDuration = "Forever"
	} Else {
	    $defDomPolLockDuration = $($($($($adDomainNC.lockoutDuration) * -1 / (60 * 10000000)).ToString() + " min") + "/" + $($([math]::Round($($($adDomainNC.lockoutDuration) * -1 / (24 * 60 * 60 * 10000000)),3)).ToString() + " days"))
	}
	
	# Period Of Time That Needs To Pass Before The Bad Password Counter Is Reset To Zero (0)
	$defDomPolLockWindow = $null
	$defDomPolLockWindow = 	$($($($($adDomainNC.lockOutObservationWindow) * -1 / (60 * 10000000)).ToString() + " min") + "/" + $($([math]::Round($($($adDomainNC.lockOutObservationWindow) * -1 / (24 * 60 * 60 * 10000000)),3)).ToString() + " days"))
	
	# Number Of Failed Attempts Before An Account Is Locked
	$defDomPolLockThreshold = $null
	$defDomPolLockThreshold = $adDomainNC.lockoutThreshold
	
	# Building The List
	$defDomPolEntry = New-Object -TypeName System.Object
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Domain" -Value $adDomainFQDN
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value "Default Domain Policy"
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Name" -Value "Default Domain Policy"
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Precedence" -Value "9999999999"
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Max Pwd Age" -Value $defDomPolMaxPwdAge
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Min Pwd Age" -Value $defDomPolMinPwdAge
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Min Pwd Len" -Value $defDomPolMinPwdLen
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Pwd Hist" -Value $defDomPolPwdHistLen
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Pwd Complex" -Value $defDomPolPwdComplexOn
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Pwd Rev Encr" -Value $defDomPolPwdRevEncrOn
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Applies To" -Value $($appliesToList -join ",`n")
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Lockout Duration" -Value $defDomPolLockDuration
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Lockout Window" -Value $defDomPolLockWindow
	$defDomPolEntry | Add-Member -MemberType NoteProperty -Name "Lockout Threshold" -Value $defDomPolLockThreshold
	$pwdPolList += $defDomPolEntry

    # Retrieving The Password And Account Lockout Policy Settings From Any Password Settings Object (PSO)_
	$adDomainPSOs = $null
	$adDomainPSOs = Get-ADObject -LDAPFilter "(objectClass=msDS-PasswordSettings)" -SearchBase "CN=Password Settings Container,CN=System,$adDomainDN" -Properties * -Server $adDomainRWDCpdcFQDN
	
	# If Any PSO Is Found/Accessible
	If ($adDomainPSOs) {
	    # Process For Each PSO Found
    	$adDomainPSOs | ForEach-Object{
    		# The PSO Object
    		$pso = $null
    		$pso = $_
    		
    		# The AD Domain The PSO Resides In
    		$psoDomain = $null
    		$psoDomain = $adDomainFQDN
    		
    		# The Name Of The PSO
    		$psoName = $null
    		$psoName = $pso.name
    		
    		# The Precedence Of The PSO. The Lower The Value, The "Cheaper" The PSO And Therefore The Higher The Priority Is To Use It In Case Of Any Conflict
    		$psoPrec = $null
    		$psoPrec = $pso."msDS-PasswordSettingsPrecedence"
    		
    		# Max Password Age
    		$psoMaxPwdAge = $null
            If ($($pso."msDS-MaximumPasswordAge") -eq -9223372036854775808) {
                $psoMaxPwdAge = "Forever"
            } Else {
                $psoMaxPwdAge = $($($($pso."msDS-MaximumPasswordAge") * -1 / (24 * 60 * 60 * 10000000)).ToString() + " days")
            }

    		# Min Password Age
    		$psoMinPwdAge = $null
    		$psoMinPwdAge = $($($($pso."msDS-MinimumPasswordAge") * -1 / (24 * 60 * 60 * 10000000)).ToString() + " days")
    		
    		# Min Password Length
    		$psoMinPwdLen = $null
    		$psoMinPwdLen = $pso."msDS-MinimumPasswordLength"
    		
    		# Password History Length
    		$psoPwdHistLen = $null
    		$psoPwdHistLen = $pso."msDS-PasswordHistoryLength"
    		
    		# Password Complexity Enabled Or Not
    		$psoPwdComplexOn = $null
    		$psoPwdComplexOn = $pso."msDS-PasswordComplexityEnabled"
    		
    		# Password Clear Text Storage Enabled Or Not
    		$psoPwdRevEncrOn = $null
    		$psoPwdRevEncrOn = $pso."msDS-PasswordReversibleEncryptionEnabled"
    		
    		# To Whom This Particular Password Policy Applies
    		$psoAppliesTo = $null
    		$psoAppliesTo = $pso."msDS-PSOAppliesTo"
    		$appliesToList = @()
    		If ($psoAppliesTo) {
    			$psoAppliesTo | ForEach-Object{
    				$object = Get-ADObject -Identity $_ -Server $adDomainRWDCpdcFQDN
    				$appliesToList += $($($object.objectClass) + ": " + $($object.Name))
    			}
    		} Else {
    			$appliesToList = "<No Group Or User Assigned>"
    		}
    		
    		# Lockout Duration After An Account Is Locked
            $psoLockDuration = $null
            If ($($pso."msDS-LockoutDuration") -eq -9223372036854775808) {
                $psoLockDuration = "Forever"
            } Else {
                $psoLockDuration = $($($($($pso."msDS-LockoutDuration") * -1 / (60 * 10000000)).ToString() + " min") + "/" + $($([math]::Round($($($pso."msDS-LockoutDuration") * -1 / (24 * 60 * 60 * 10000000)),3)).ToString() + " days"))
            }

    		# Period Of Time That Needs To Pass Before The Bad Password Counter Is Reset To Zero (0)
    		$psoLockWindow = $null
    		$psoLockWindow = $($($($($pso."msDS-LockoutObservationWindow") * -1 / (60 * 10000000)).ToString() + " min") + "/" + $($([math]::Round($($($pso."msDS-LockoutObservationWindow") * -1 / (24 * 60 * 60 * 10000000)),3)).ToString() + " days"))
    		
    		# Number Of Failed Attempts Before An Account Is Locked
    		$psoLockThreshold = $null
    		$psoLockThreshold = $pso."msDS-LockoutThreshold"
    		
    		# Building The List
    		$psoEntry = New-Object -TypeName System.Object
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Domain" -Value $psoDomain
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Type" -Value "PSO"
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Name" -Value $psoName
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Precedence" -Value $psoPrec
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Max Pwd Age" -Value $psoMaxPwdAge
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Min Pwd Age" -Value $psoMinPwdAge
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Min Pwd Len" -Value $psoMinPwdLen
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Pwd Hist" -Value $psoPwdHistLen
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Pwd Complex" -Value $psoPwdComplexOn
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Pwd Rev Encr" -Value $psoPwdRevEncrOn
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Applies To" -Value $($appliesToList -join ",`n")
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Lockout Duration" -Value $psoLockDuration
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Lockout Window" -Value $psoLockWindow
    		$psoEntry | Add-Member -MemberType NoteProperty -Name "Lockout Threshold" -Value $psoLockThreshold
    		$pwdPolList += $psoEntry
    	}
    }
}
### Displaying The List On Screen
$pwdPolList | Format-Table * -Autosize -Wrap

$outputHTMLFilePath = $null
$outputHTMLFilePath = Join-Path $currentScriptFolderPath $($execDateTimeDisplay.Replace(":",".") + "_" + $adForestRootDomainFQDN + "_Password-Policy-Configuration-Report.html")
$outputHTMLHeadWidth = 0,0,0,0,0,0,0,0,0,0,0,0,0,0
$outputHTMLTitle = "Password Policy Configuration Report"
$outputHTMLPreContent = @"
<DIV align='center'><P><H1>   ===>>> $outputHTMLTitle <<<===   </H1></P></DIV>"
<DIV align='center'><P><H1>   ===>>> AD Forest: $adForestRootDomainFQDN | Report: $execDateTimeDisplay <<<===   </H1></P></DIV><BR>"
"@
$outputHTMLPostContent = @"
<BR><DIV align='Left'><H3 style='color:red;'>LEGEND:</H3>

<TABLE style="width:100%">
    <TR>
        <TD>'Domain'</TD>
        <TD>The AD domain the password and account lockout policy lives in.</TD>
    </TR>
    <TR>
        <TD>'Type'</TD>
        <TD>The type of password and account lockout policy, either Default Domain Policy (Legacy) or Password Settings Object (Modern).</TD>
    </TR>
    <TR>
        <TD>'Name'</TD>
        <TD>The name of the password and account lockout policy</TD>
    </TR>
    <TR>
        <TD>'Precedence'</TD>
        <TD>When multiple policies applies to a specific user, the policy with the lowest value (highest priority) wins.</TD>
    </TR>
    <TR>
        <TD>'Max Pwd Age'</TD>
        <TD>The maximum lifetime of a password before it must be changed again.</TD>
    </TR>
    <TR>
        <TD>'Min Pwd Age'</TD>
        <TD>The minimum lifetime of a password before it can be changed again.</TD>
    </TR>
    <TR>
        <TD>'Min Pwd Len'</TD>
        <TD>The minimum amount of characters that must be used in a password.</TD>
    </TR>
    <TR>
        <TD>'Pwd Hist'</TD>
        <TD>The number of previous passwords that cannot be reused as a new password.</TD>
    </TR>
    <TR>
        <TD>'Pwd Complex'</TD>
        <TD>Whether or not password complexity is enabled. When enabled characters from 3 out of 4 character sets must be used in the password.</TD>
    </TR>
    <TR>
        <TD>'Pwd Rev Encr'</TD>
        <TD>Whether or not the password is stored in the AD database as clear text.</TD>
    </TR>
    <TR>
        <TD>'Applies To'</TD>
        <TD>To which user or group os users the password policy applies.</TD>
    </TR>
    <TR>
        <TD>'Lockout Duration'</TD>
        <TD>When an account is locked, the duration of the lock before being unlocked again.</TD>
    </TR>
    <TR>
        <TD>'Lockout Window'</TD>
        <TD>The period of time that needs to pass before the bad password counter is reset to zero (0).</TD>
    </TR>
    <TR>
        <TD>'Lockout Threshold'</TD>
        <TD>The number of failed attempts before an account is locked.</TD>
    </TR>
</TABLE>
</DIV>
"@

exportToHTMLFile $outputHTMLFilePath $pwdPolList $outputHTMLHeadWidth $outputHTMLTitle $outputHTMLPreContent $outputHTMLPostContent
Write-Host "HTML Report Password Policies In AD Forest '$adForestRootDomainFQDN'...: $outputHTMLFilePath" -ForegroundColor Magenta
Write-Host ""