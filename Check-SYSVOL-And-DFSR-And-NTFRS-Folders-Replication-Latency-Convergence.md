# SCRIPT: Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence

## AUTHOR/FEEDBACK

* Written By: Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]
* Re-Written By: N.A.
* Company: IAMTEC &gt;&gt; Identity | Security | Recovery [https://www.iamtec.eu/]
* Blog: Jorge's Quest For Knowledge [http://jorgequestforknowledge.wordpress.com/]
* For Feedback/Questions: scripts DOT gallery AT iamtec.eu
  * Please Describe Your Scenario As Best As Possible With As Much Detail As Possible.
  * If Applicable Describe What Does and/Or Does Not Work.
  * If Applicable Describe What Should Be/Work Different And Explain Why/How.
  * Please Add Screendumps.

## ORIGINAL SOURCE(S)

* <https://github.com/zjorz/Public-AD-Scripts/blob/master/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1>

## DISCLAIMER

* The script is FREEWARE, you are free to distribute/update it, but always refer to the original source(s) as the location where you got it
* This script is furnished "AS IS". NO warranty is expressed or implied!
* I HAVE NOT tested it in every scenario or environment
* ALWAYS TEST FIRST in lab environment to see if it meets your needs!
* Use this script at YOUR OWN RISK! YOU ARE RESPONSIBLE FOR ANY OUTCOME/RESULT BY USING THIS SCRIPT!
* I DO NOT warrant this script to be fit for any purpose, use or environment!
* I have tried to check everything that needed to be checked, but I DO NOT guarantee the script does not have bugs!
* I DO NOT guarantee the script will not damage or destroy your system(s), environment or anything else due to improper use or bugs!
* I DO NOT accept liability in any way when making mistakes, use the script wrong or in any other way where damage is caused to your environment/systems!
* If you do not accept these terms DO NOT use the script in any way and delete it immediately!

## KNOWN ISSUES/BUGS

* When migrating SYSVOL Replication from NTFRS to DFSR, the NTFRS Replica Set for the SYSVOL might still show up with no replication mechanism specified. This will resolve itself as soon as ALL DCs have reached the ELIMINATED state!
* Without additional tooling on every Replica Member, it is not possible to determine when the file arrived at a specific Replica Member. The calculation is therefore done when the script "sees" the file on a Replica Member
* The content of the HTML file in the browser might suddenly appear to be blank. This might resolve by itself during the refresh or when the admin refreshes manually
* Reachability of a certain replica member depends on the required port being open, AND the speed a replica member responds back. If the configured timeout is too low while a high latency is experienced, increase the configured timeout by using the XML configuration file

## RELEASE NOTES

* v0.9, 2024-12-11, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:

  * Improved User Experience: Changed the layout of the output on screen to display a summary of the progress.
  * Improved User Experience: Added URL for documentation to the ORIGINAL SOURCE(S) section above
  * Improved User Experience: Support for an XML file to specify environment specific connection parameters. At the same time this also allows upgrades/updates of the script without loosing those specify environment specific connection parameters
  * Improved User Experience: For a more detailed view of the progress, that information will automatically be displayed through an HTML file in a browser and refreshed every 5 seconds to display any changes.
  * Code Improvement: Implemented StrictMode Latest Version (Tested On PoSH 5.x And 7.x)
  * Code Improvement: Replaced "Get-WmiObject" with "Get-CimInstance" to also support PowerShell 7.x
  * New Feature: Added the function "showProgress" to display the progress of an action
  * New Feature: Added parameter to skip opening the HTML in a browser to support automation

* v0.8, 2024-09-03, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:

  * Code Improvement: DFSR - For scenarios where metadata cleanup was not fully complete where also the "msDFSR-Member" is cleaned, an additional check is added to make sure the "msDFSR-Member" object has a value for "msDFSR-ComputerReference"
  * Code Improvement: NTFRS - For scenarios where metadata cleanup was not fully complete where also the "nTFRSMember" is cleaned, an additional check is added to make sure the "nTFRSMember" object has a value for "frsComputerReference"
  * Code Improvement: Better/improved detection of replication mechanism used for SYSVOL
  * Code Improvement: Redefined reachability specifically for WinRM and SMB
  * Improved User Experience: Added a check to determine if orphaned metadata exists of replication members for either NTFRS and DFS-R
  * Improved User Experience: Faster processing due to paralellel processing through RunSpaces. (MAJOR CHANGE and WILL IMPACT CPU/RAM usage when checking against many members!)
      To configure the behavior of the processing in the Runspaces, review and update as needed the variables "$runspacePoolMinThreads", "$runspacePoolMaxThreads" And "$delayInMilliSecondsBetweenChecks"
      Inspired by:
      <https://blog.netnerds.net/2016/12/runspaces-simplified/>
      <https://blog.netnerds.net/2016/12/immediately-output-runspace-results-to-the-pipeline/>
      <https://github.com/EliteLoser/misc/blob/master/PowerShell/PowerShell%20Runspace%20Example%20Template%20Code.ps1>
      <https://devblogs.microsoft.com/scripting/beginning-use-of-powershell-runspaces-part-1/>
      <https://devblogs.microsoft.com/scripting/beginning-use-of-powershell-runspaces-part-2/>
      <https://devblogs.microsoft.com/scripting/beginning-use-of-powershell-runspaces-part-3/>
      <https://devblogs.microsoft.com/scripting/weekend-scripter-a-look-at-the-poshrsjob-module/>
  * Improved User Experience: Added at the beginning the output of the command line and all parameters used
  * New Feature: Added the function "checkDNExistence" to check if an object exists or not
  * New Feature: SYSVOL Repl through NTFRS only is supported, SYSVOL Repl through DFSR only is supported and now also SYSVOL Repl through both NTFRS and DFSR (only when migrating, in either the PREPARED or REDIRECTED state) is supported
  * Bug Fix: Added forgotten parameter to automatically cleanup orphaned canary files when found
  * Bug Fix: The value specified for the parameter targetReplMember now is used
  * Bug Fix: Corrected the name of the log that is created
  * New Feature: Added parameter to skip cleaning of orphaned canary files when found
  * New Feature: Added variable that specifies the delay in milliseconds between the checks for each member. The default is 0, which means NO DELAY and go for it!
  * New Feature: Added a parameter to allow the export of the results into a CSV

* v0.7, 2024-07-30, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:

  * Bug Fix: Fixed case sensitivity bug when specifying a DFR Replicated Folder Name through the command line
  * Bug Fix: Fixed case sensitivity bug when specifying a Domain FQDN through the command line

* v0.6, 2024-02-06, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:

  * Code Improvement: Changed the function "getDFSRReplGroupMembers" to not use a GC, but instead use a RWDC from the respective AD domain of the object that is being looked for
  * Code Improvement: When discovering a member, added a check to choose a member with a writable copy of the replicated folder
  * Improved User Experience: Added a check to determine if there are Temporary Canary Object leftovers from previous executions of the script that were not cleaned up because the script was aborted or it crashed
  *	Improved User Experience: Changed the timing column from "Time" to "TimeDiscvrd" (Time Discovered) which specifies how much time it took to find/see the file on the member of the replicated folder
  *	Improved User Experience: The AD domain list presented is now consistently presented in the same order
  *	Bug Fix: Fixed the unc path for the folder when SYSVOL is still using NTFRS. Temporary Canary File is now created in the Scripts folder (SYSVOL only!)
  *	Bug Fix: When not using SYSVOL as replicated folder, fixed the Member to target for checking the existence of the Temporary Canary File
  *	Bug Fix: Changed the variable name of the unc path for the folder on the source from $uncPathFolder to $uncPathFolderSource, to also target the correct (source) Member for cleanup of the file

* v0.5, 2024-01-31, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:

  * Script Improvement: Complete rewrite of the script
  * New Feature: Parameters added to support automation
  * New Feature: Logging Function
  * New Feature: Support for all replicated folders (SYSVOL and Custom), replicated either through NTFRS or DFSR
  * New Feature: File count across each member (enabled by default), can be disabled with parameter
  * Code Improvement: As target member use specific role owner hosting the PDC FSMO (SYSVOL only!), disccovered member, specific member

* v0.4, 2014-02-11, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Code Improvement: Added additional logic to determine if a DC is either an RWDC or RODC when it fails using the first logic and changed the layout a little bit

* v0.3, 2014-02-09, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Bug Fix: Solved a bug with regards to the detection/location of RWDCs and RODCs

* v0.2, 2014-02-01, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:

  * New Feature: Updated to also work on W2K3
  * New Feature: Added STOP option
  * Code Improvement: Added few extra columns to output extra info of DCs,
  * Code Improvement: Better detection of unavailable DCs/GCs
  * Code Improvement: Added screen adjustment section

* v0.1, 2013-03-02, Jorge de Almeida Pinto [MVP Security / Lead Identity/Security Architect]:
  * Initial version of the script

## SYNOPSIS/DESCRIPTION

This PoSH Script Checks The File Replication Latency/Convergence For Replicated Folders (SYSVOL And Custom) Using Either NTFRS Or DFSR.

This PoSH script provides the following functions:

* It executes all checks in parallel at the same time against all replica members in scope.
* It executes on a per replicated folder basis. For multiple replicated folder use automation with parameters.
* For automation, it is possible to define the FQDN of the AD Domain to target, the name of the replica set (NTFRS) or the name of the replicated folder (DFSR) within that AD domain, and the member to use as the source
    member to create the temoporary canary file on.
* It supports non-interacive mode through automation with parameters, or interactive mode.
* It supports file replication convergence check for any replica set (NTFRS) or replicated folder (DFSR) within an AD forest.
  * Connectivity check to replica members through TCP:WinRM/5985 for the purpose of counting files locally on the replica member
  * Connectivity check to replica members through TCP:SMB/5985 for the purpose of checking the existance of the canary file
* As the source member, it is possible to:
  * Use the FSMO of the AD Domain, when it concerns the SYSVOL only
  * Use a discovered member (best effort)
  * Specify the FQDN of a member that hosts the replica set (NTFRS) or the replicated folder (DFSR)
* For the temporary canary file:
  * Initially created on the source member and deleted from the source member at the end
  * Name            = _fileReplConvergenceCheckTempFile_yyyyMMddHHmmss (e.g. _fileReplConvergenceCheckTempFile_20240102030405)
  * Content         = ...!!!...TEMP FILE TO TEST REPLICATION LATENCY/CONVERGENCE FOR REPLICATED FOLDER &lt;REPLICA SET NAME (NTFRS) OR REPLICATED FOLDER NAME (DFSR)&gt; IN AD DOMAIN &lt;AD DOMAIN FQDN&gt; USING MEMBER &lt;SOURCE MEMBER&gt; AS THE SOURCE MEMBER...!!!...
  * Container:
    * For custom replicated folders    =&gt; Folder = At the root of the folder
    * For SYSVOL                       =&gt; Folder = "&lt;SYSVOL LOCAL PATH&gt;\Scripts"
* In the PowerShell command prompt window the global progress is displayed. The same thing is also logged to a log file
* When a default browser is available/configured, the generated HTML file will be opened and automatically refreshed every 5 seconds as the script progresses. This HTML file displays the replica member specific state/result
* It checks if specified replica set (NTFRS) or replicated folder (DFSR) exists. If not, the script aborts.
* It checks if specified member exists. If not, the script aborts.
* At the end it checks if any Temporary Canary Files exist from previous execution of the script and offers to clean up (In the chosen Replicated Folder only!).
* Disjoint namespaces and discontiguous namespaces are supported.
* The script uses default values for specific connection parameters. If those do not meet expectation, an XML configuration file can be used with custom values.
* For the specific replicated folder, the script also checks if any remaining canary files exists from previous script executions that either failed or were aborted. It provides the option to also clean those or not.
    Through a parameter it allows to default to always clean previous canary files when found. This behavior is ignored when the parameter to skip the check of previous canary files is used
* In addition to displaying the end results on screen, it is also possible to export those end results to a CSV file
* Through a parameter it is possible to skip the check of previous canary files
* During interactive mode, after specifying the source member, it will count the files in the replicated folder on every member by default. This can be disabled through a parameter.
* Through a parameter it is possible to not open the generated HTML in the default browser
* The script supports automation by using parameters with pre-specified details of the targeted Domain FQDN, the targeted Replicated Folder and the targeted source Replica Member

## PARAMETER(S)

cleanupOrhanedCanaryFiles

* With this parameter it is possible to automatically cleanup orphaned canary files when found

exportResultsToCSV

* With this parameter it is possible to export the results to a CSV file in addition of displaying it on screen on in the log file

skipCheckForOrphanedCanaryFiles

* With this parameter it is possible not to check for orphaned canary files

skipFileCount

* With this parameter it is possible not count files in the replicated folder on every member

skipOpenHTMLFileInBrowser

* With this parameter it is possible to not open the HTML file in the default browser

targetDomainFQDN

* With this parameter it is possible to specify the FQDN of an AD domain to target for File Replication Convergence/Latency check against a chosen replica set (NTFRS) or the replicated folder (DFSR) within that AD domain

targetReplFolder

* With this parameter it is possible to specify the name of the replica set (NTFRS) or the replicated folder (DFSR) within the chosen AD domain to target for the File Replication Convergence/Latency check

targetReplMember

* With this parameter it is possible to specify the member to use to create the temporary canary file on. Options that are available for this are "Fsmo" (SYSVOL only!), "Discover" or the FQDN of a member

## EXAMPLE(S)

Check The File Replication Convergence/Latency Using Interactive Mode (Including File Count)

``` powershell
.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1
```

Check The File Replication Convergence/Latency Using Interactive Mode (Excluding File Count)

``` powershell
.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -skipFileCount
```

Check The File Replication Convergence/Latency Using Automated Mode For The SYSVOL Replicated Through NTFRS Using The Fsmo Role Owner As The Source Member To Create The Temporary Canary File On (Including File Count)

``` powershell
.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "Domain System Volume (SYSVOL share)" -targetReplMember Fsmo
```

Check The File Replication Convergence/Latency Using Automated Mode For The SYSVOL Replicated Through DFSR Using The Fsmo Role Owner As The Source Member To Create The Temporary Canary File On (Including File Count)

``` powershell
.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "SYSVOL Share" -targetReplMember Fsmo
```

Check The File Replication Convergence/Latency Using Automated Mode For The Replicated Folder "LPPStoreForAD" Using A Discovered Member As The Source Member To Create The Temporary Canary File On (Including File Count)

``` powershell
.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "LPPStoreForAD" -targetRWDC Discover
```

Check The File Replication Convergence/Latency Using Automated Mode For The Replicated Folder "LPPStoreForAD" Using A Specific Member As The Source Member To Create The Temporary Canary File On (Including File Count)

``` powershell
.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "LPPStoreForAD" -targetRWDC "R1FSRWDC1.IAMTEC.NET"
```

Check The File Replication Convergence/Latency Using Automated Mode For The SYSVOL Replicated Through NTFRS Using The Fsmo Role Owner As The Source Member To Create The Temporary Canary File On (Excluding File Count)

``` powershell
.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "Domain System Volume (SYSVOL share)" -targetReplMember Fsmo -skipFileCount
```

Check The File Replication Convergence/Latency Using Automated Mode For The SYSVOL Replicated Through DFSR Using The Fsmo Role Owner As The Source Member To Create The Temporary Canary File On (Excluding File Count)

``` powershell
.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "SYSVOL Share" -targetReplMember Fsmo -skipFileCount
```

Check The File Replication Convergence/Latency Using Automated Mode For The Replicated Folder "LPPStoreForAD" Using A Discovered Member As The Source Member To Create The Temporary Canary File On (Excluding File Count)

``` powershell
.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "LPPStoreForAD" -targetRWDC Discover -skipFileCount
```

Check The File Replication Convergence/Latency Using Automated Mode For The Replicated Folder "LPPStoreForAD" Using A Specific Member As The Source Member To Create The Temporary Canary File On (Excluding File Count)

``` powershell
.\Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence.ps1 -targetDomainFQDN IAMTEC.NET -targetReplFolder "LPPStoreForAD" -targetRWDC "R1FSRWDC1.IAMTEC.NET" -skipFileCount
```

## NOTES

* To execute this script, the account running the script MUST have the permissions to create and delete the file in the local folder of the source member through the drive share (C$, D$, etc). Being a local admin on all
    the member allows, the creation, deletion and monitoring of the file
* The credentials used are the credentials of the logged on account. It is not possible to provided other credentials. Other credentials could maybe be used through RUNAS /NETONLY /USER
* No check is done for the required permissions. The script simply assumes the required permissions are available. If not, errors will occur
* No PowerShell modules are needed to use this script
* For the SYSVOL, it only works correctly when either using NTFRS, or DFSR in a completed state!
* Admin shares MUST be enabled
* For File Count, WinRM must be possible against the remote machines (TCP:WinRM/5985)
* Yes, I'm aware, there is duplicate code to support both NTFRS and DFSR. This was the easiest way to support both without too much complexity. It also allows to remove it easily when NTFRS cannot be used anymore
* Detailed NTFRS Info: <https://www.betaarchive.com/wiki/index.php?title=Microsoft_KB_Archive/296183>
* Script Has StrictMode Enabled For Latest Version - Tested With PowerShell 7.4.5
* Reachbility for counting files locally on the member within the replicated folder is determined by checking against the required port (WinRM HTTP Transport Port TCP:5985 for Replica Members) and if the member responds
    fast enough before the defined connection timeout
* Reachbility for checking the existance of the canary file on the member within the replicated folder is determined by checking against the required port (SMB Over TCP/IP TCP:445 for Replica Members) and if the member
    responds fast enough before the defined connection timeout
* The XML file for the environment specific oonnection parameters should have the exact same name as the script and must be in the same folder as the script. If the script is renamed, the XML should be renamed accordingly.
    For example, if the script is called "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_v09.ps1", the XML file should be called "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_v09.xml".
    When a decision is made to use the XML Configuration File, then ALL connection parameters MUST be defined in it. The structure of the XML file is:

```XML
<!-- ============ Configuration XML file ============ -->
<?xml version="1.0" encoding="utf-8"?>
<checkFileReplConvergence xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
	<!-- Use The Connection Parameters In The XML Config File -->
	<useXMLConfigFileSettings>TRUE_OR_FALSE</useXMLConfigFileSettings>

	<!-- Default In Script = 500 | When Checking If The Host Is Reachable Over Certain Port, This Is The Timeout In Milliseconds -->
	<connectionTimeoutInMilliSeconds>REPLACE_WITH_NUMERIC_VALUE</connectionTimeoutInMilliSeconds>

	<!-- Default In Script = 30 | When Checking The Canary Object Against A Certain Replica Member, And The Replica Member Is Reachable, This Is The Amount Of Minutes, When Exceeded, It Stops Checking That Replica Member (This Could Be The Case When NTFRS/DFSR Replication Is Broken Somehow Or The Replica Member Is In A Unhealthy State) -->
	<timeoutInMinutes>REPLACE_WITH_NUMERIC_VALUE</timeoutInMinutes>

	<!-- Default In Script = 1 | Minimum Amount Of Threads Per Runspace Pool -->
	<runspacePoolMinThreads>REPLACE_WITH_NUMERIC_VALUE</runspacePoolMinThreads>

	<!-- Default In Script = 2048 | Minimum Amount Of Threads Per Runspace Pool -->
	<runspacePoolMaxThreads>REPLACE_WITH_NUMERIC_VALUE</runspacePoolMaxThreads>

	<!-- Default In Script = 500 | The Check Delay In Milliseconds Between Checks Against Each Individual Replica Member -->
	<delayInMilliSecondsBetweenChecks>REPLACE_WITH_NUMERIC_VALUE</delayInMilliSecondsBetweenChecks>
</checkFileReplConvergence>
<!-- ============ Configuration XML file ============ -->
```

## SCREENSHOTS (NEW WAY OF EXECUTION AND PROCESSING!)

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture01.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture02.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture03.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture04.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture05.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture06.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture07.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture08.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture09.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture10.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture11.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture12.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture13.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture14.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture15.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture16.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture17.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture18.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture18.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

## SCREENSHOTS (PREVIOUS WAY OF EXECUTION AND PROCESSING!)

![Alt](Images/OLD_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture01.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/OLD_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture02.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/OLD_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture03.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/OLD_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture04.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/OLD_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture05.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/OLD_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture06.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/OLD_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture07.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/OLD_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture08.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/OLD_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture09.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/OLD_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture10.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/OLD_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture11.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/OLD_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture12.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")

![Alt](Images/OLD_Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence_Picture13.png "Check-SYSVOL-And-DFSR-And-NTFRS-Folders-Replication-Latency-Convergence")
