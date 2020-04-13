# AD Expiration Notification

## Social Media Channels
* [Visit my blog](https://jorgequestforknowledge.wordpress.com/)
* [Follow me on twitter](https://twitter.com/JsQForKnowledge/)![](https://twitter.com/favicon.ico)
* [Follow me on facebook](https://www.facebook.com/JorgesQuestForKnowledge/)![](https://facebook.com/favicon.ico)
* [Follow me on linkedin](http://www.linkedin.com/in/jorgedealmeidapinto)![](https://www.linkedin.com/favicon.ico)

## Main Features
* **Account Expiration Notification** - Send a notification to the corresponding user when the AD account is about to expire, as the number of days until the account expiration date falls within a defined warn period
* **Password Expiration Notification** - Send a notification to the corresponding user when the password of the AD account is about to expire, as the number of days until the password expiration date falls within a defined warn period

## Getting Started
* Determine the notification features to use globally
* Determine the FROM e-mail address, the Test Mode TO e-mail address, the Support TO e-mail afddress and the mail/smtp server
* Determine whatever is applicable the URLs for "Requesting Account Extension", "Changing Password", "Register for Self-Service Password Reset" and "Resetting Password"
* Determine the AD Domains to target and for each AD domain determine if you want a specific DC or want to discover a DC, and within each AD domain which OUs need to be target
* For each targeted OU determine which notification featiure you want to enable or disable and which language template to use
* Determine how many HTML body template files and picture files are needed. Every HTML body template file targets a specific feature AND language. Do not have overlaps!
* Determine the warning periods for every feature you enable
* Determine the AD user account to use to execute the script
* Configure the required AD permissions
* Create the HTML body files and the picture files. See the included examples. The following variables can be used in the subject and/or HTML body files. It is not mandatory to use variables:
	* Generic:
		* IMAGE_BASE_FILE_NAME
		* FQDN_DOMAIN
		* NBT_DOMAIN
		* FIRST_NAME
		* LAST_NAME
		* DISPLAY_NAME
		* EMAIL_ADDRESS
		* UPN
		* SAM_ACCOUNT_NAME
		* PRINCIPAL_ACCOUNT_NAME
	* For accountExpiryNotification only:
		* ACCOUNT_EXPIRY_DATE
		* ACCOUNT_EXPIRE_IN_NUM_DAYS
		* ACCOUNT_EXTENSION_URL
	* For pwdExpiryNotification only
		* PWD_LAST_SET
		* PWD_EXPIRY_DATE
		* PWD_EXPIRE_IN_NUM_DAYS
		* PWD_MIN_LENGTH
		* PWD_MIN_AGE
		* PWD_MAX_AGE
		* PWD_HISTORY
		* PWD_COMPLEX
		* PWD_CHANGE_URL
		* SSPR_REGISTRATION_URL
		* PWD_RESET_URL
* Configure the Windows Server to host and execute the script
* Configure the XML configuration file of the script
* After every is configured:
(**REMARK**: When executing the script check screen output and or LOG files and any CSV files if enabled in the XML file. If users are in scope for notification, the screen output and/or the log file will publish non-zero values for at least one 'User Count Within Warning Period' and 'User Count To Be Notified'. At the same time, the CSV file will contain the list of users that would be notified)
	* Execute the PowerShell script manually (using the execution account through RUNAS) WITHOUT the '-force parameter', evaluate results and (re)configure whatever needs to be (re)configured
	* Execute the PowerShell script manually (using the execution account through RUNAS) WITH the '-force parameter' and execution mode 'DEV', evaluate results and (re)configure whatever needs to be (re)configured
	* Execute the PowerShell script manually (using the execution account through RUNAS) WITH the '-force parameter' and execution mode 'TEST', evaluate results and (re)configure whatever needs to be (re)configured
	* Execute the PowerShell script through the scheduled task WITHOUT the '-force parameter', evaluate results and (re)configure whatever needs to be (re)configured
	* Execute the PowerShell script through the scheduled task WITH the '-force parameter' and execution mode 'DEV', evaluate results and (re)configure whatever needs to be (re)configured
	* Execute the PowerShell script through the scheduled task WITH the '-force parameter' and execution mode 'TEST', evaluate results and (re)configure whatever needs to be (re)configured
	* Execute the PowerShell script through the scheduled task WITH the '-force parameter' and execution mode 'PROD', when you are ready to put this in production\
	(**REMARK**: Before running in PROD mode, make sure to notify users that they will start to receive e-mails about account/password expirations! Not doing this may end up in users seeing it as spam or phishing and that may overload the service desk!)

## Configuration - Script XML
* The script uses the default 'AD-Exp-Notify.xml' file in the same folder as the PowerShell script. If the parameter '-xmlconfigfilepath' is used with the full path to the XML file, then that will be used instead.
* Enable or disable at global level the notification features you need. By default all features are disabled:\
(**REMARK**: Notifications will only work if enabled at global level!)

```XML
	<!-- enabled="false" : feature is disabled -->
	<!-- enabled="true" : feature is enabled -->
	<features>
		<feature name="accountExpiryNotification" enabled="false" />
		<feature name="pwdExpiryNotification" enabled="false" />
	</features>	
```

* When NOT using the '-force' parameter, the script will always operate in TEST mode with NO mailings at all, no matter what the XML configuration file specifies. Try this first!
* When using the '-force' parameter, the script will operate in the mode specified in the XM configuration file\
(**REMARK**: When the execitionMode is 'DEV' then the mail address specified in 'toSMTPAddressInTestMode' will receive just 1 mail for every globally enabled feature!)\
(**REMARK**: When the execitionMode is 'TEST' then the mail address specified in 'toSMTPAddressInTestMode' will receive all mails that would have been send to scoped individual users for every globally enabled feature and if a warn period is matched!)\
(**REMARK**: When the execitionMode is 'PROD' then the scoped individual users will receive the mail for every globally enabled feature and if a warn period is matched!)\

```XML
	<!-- Execution Mode: DEV (1x Mail To Admin User) or TEST (All Mails To Admin User) or PROD (All Mails To Individual Users) -->
	<executionMode>DEV</executionMode>
```

* When sending an e-mail, the following e-mail address is the FROM/SENDER address:

```XML
	<!-- The SMTP Address Used In The FROM Field -->
	<mailFromSender>FROM_XXX@YYY.ZZZ</mailFromSender>
```

* When sending an e-mail in DEV or TEST mode, the following e-mail address is the TO/RECIPIENT address:

```XML
	<!-- The SMTP Address Used When Running In DEV/TEST Mode And Also Used For Notifications -->
	<toSMTPAddressInTestMode>TO_XXX@YYY.ZZZ</toSMTPAddressInTestMode>
```

* When script encounters a pre-defined issue the following e-mail address is the TO/RECIPIENT address:

```XML
	<!-- The SMTP Address Used When Something Goes Wrong -->
	<toSMTPAddressSupport>TO_XXX@YYY.ZZZ</toSMTPAddressSupport>
```

* When script sends any e-mail the following specified mail/smtp server is used:

```XML
	<!-- FQDN Of The Mail Server Or Mail Relay -->
	<smtpServer>XXX.YYY.ZZZ</smtpServer>
```

* When script sends a notification e-mail the following is the priority of that e-mail:

```XML
	<!-- The Priority Of The Message: Low, Normal, High -->
	<mailPriority>XXX</mailPriority>
```
	
* When script sends a notification e-mail, depending on the notification type (account expiry notification or password expiry notification) and the language, the correct HTML body file and picture file are determined and used as the mail template:

```XML
	<!-- The File With The HTML Body Text For A Specific Language And The Subject. Supported Variables: FIRST_NAME, LAST_NAME, DISPLAY_NAME, FQDN_DOMAIN, PWD_EXPIRE_IN_NUM_DAYS, PWD_EXPIRY_DATE, PWD_MIN_LENGTH, PWD_MIN_AGE, PWD_MAX_AGE, PWD_HISTORY, PWD_COMPLEX, PWD_CHANGE_RESET_URL  -->
	<htmlBodyFiles>
		<htmlBodyFile featureName="pwdExpiryNotification" language="default" mailSubject="Expiring Password In Approx. PWD_EXPIRE_IN_NUM_DAYS Days - Change Your Password As Soon As Possible!" htmlBodyFullPath="C:\AD-Support\Scripts\AD-Expiry-Notification\AD-Pwd-Exp-Notify_Message-Body_US.html" attachedPictureFullPath="C:\AD-Support\Scripts\AD-Expiry-Notification\iamTEC_PasswordExpiration_US.png" />
		<htmlBodyFile featureName="pwdExpiryNotification" language="US" mailSubject="Expiring Password In Approx. PWD_EXPIRE_IN_NUM_DAYS Days - Change Your Password As Soon As Possible!" htmlBodyFullPath="C:\AD-Support\Scripts\AD-Expiry-Notification\AD-Pwd-Exp-Notify_Message-Body_US.html" attachedPictureFullPath="C:\AD-Support\Scripts\AD-Expiry-Notification\iamTEC_PasswordExpiration_US.png" />
		<htmlBodyFile featureName="pwdExpiryNotification" language="NL" mailSubject="Verlopen Wachtwoord In Ongeveer PWD_EXPIRE_IN_NUM_DAYS Dagen - Wijzig Uw Wachtwoord Zo Snel Als Mogelijk!" htmlBodyFullPath="C:\AD-Support\Scripts\AD-Expiry-Notification\AD-Pwd-Exp-Notify_Message-Body_NL.html" attachedPictureFullPath="C:\AD-Support\Scripts\AD-Expiry-Notification\iamTEC_PasswordExpiration_NL.png" />
		<htmlBodyFile featureName="accountExpiryNotification" language="default" mailSubject="Expiring Account In Approx. ACCOUNT_EXPIRE_IN_NUM_DAYS Days - Request Account Extension As Soon As Possible!" htmlBodyFullPath="C:\AD-Support\Scripts\AD-Expiry-Notification\AD-Account-Exp-Notify_Message-Body_US.html" attachedPictureFullPath="C:\AD-Support\Scripts\AD-Expiry-Notification\iamTEC_AccountExpiration_US.png" />
		<htmlBodyFile featureName="accountExpiryNotification" language="US" mailSubject="Expiring Account In Approx. ACCOUNT_EXPIRE_IN_NUM_DAYS Days - Request Account Extension As Soon As Possible!" htmlBodyFullPath="C:\AD-Support\Scripts\AD-Expiry-Notification\AD-Account-Exp-Notify_Message-Body_US.html" attachedPictureFullPath="C:\AD-Support\Scripts\AD-Expiry-Notification\iamTEC_AccountExpiration_US.png" />
		<htmlBodyFile featureName="accountExpiryNotification" language="NL" mailSubject="Verlopen Account In Ongeveer ACCOUNT_EXPIRE_IN_NUM_DAYS Dagen - Verleng Uw Account Zo Snel Als Mogelijk!" htmlBodyFullPath="C:\AD-Support\Scripts\AD-Expiry-Notification\AD-Account-Exp-Notify_Message-Body_NL.html" attachedPictureFullPath="C:\AD-Support\Scripts\AD-Expiry-Notification\iamTEC_AccountExpiration_NL.png" />
	</htmlBodyFiles>
```

* When users receives an e-mail that notifies about upcoming account expiry and in your guidance you want to provide a URL where users can request account extension, the following can be used:

```XML
	<!-- The URL Where The Users Can Extend Their Account -->
	<!-- e.g. FIM/MIM: https://<Identity Management Portal For FIM/MIM>/IdentityManagement/ -->
	<accountExtensionURL>https://idmportal.iamtec.net:444/IdentityManagement/</accountExtensionURL>
```

* When users receives an e-mail that notifies about upcoming password expiry and in your guidance you want to provide a URL where users can change their password, the following can be used:\
(**REMARK**: If you want to use the ADFS Password Change Portal, the URL is 'https://<ADFS Service FQDN>/adfs/portal/updatepassword.aspx')\
(**REMARK**: If you want to use the Azure AD Password Change Portal, the URL is 'https://account.activedirectory.windowsazure.com/ChangePassword.aspx')
```XML
	<!-- The URL Where The Users Can Change Their Password -->
	<!-- e.g. ADFS: https://<ADFS Service FQDN>/adfs/portal/updatepassword.aspx -->
	<!-- e.g. Azure AD: https://account.activedirectory.windowsazure.com/ChangePassword.aspx -->
	<pwdChangeURL>https://account.activedirectory.windowsazure.com/ChangePassword.aspx</pwdChangeURL>
```

* When users receives an e-mail that notifies about upcoming password expiry and in your guidance you want to provide a URL where users can register for password reset, the following can be used:\
(**REMARK**: If you want to use the FIM/MIM Registration Portal, the URL is 'https://<Self Service Password Reset Registration URL For FIM/MIM>/'. You must have this portal already in use, and the URL depends on what you configured during it installation)\
(**REMARK**: If you want to use the combined Azure AD Password Security Info Registration Portal, the URL is 'https://aka.ms/setupsecurityinfo')
```XML
	<!-- The URL Where The Users Can Register For Self Service Password Reset -->
	<!-- e.g. FIM/MIM: https://<Self Service Password Reset Registration URL For FIM/MIM>/ -->
	<!-- e.g. Azure AD: https://aka.ms/setupsecurityinfo -->
	<ssprRegistrationURL>https://aka.ms/setupsecurityinfo</ssprRegistrationURL>
```

* When users receives an e-mail that notifies about upcoming password expiry and in your guidance you want to provide a URL where users can reset their password, the following can be used:\
(**REMARK**: If you want to use the FIM/MIM Self-Service Password Reset Portal, the URL is 'https://<Self Service Password Reset URL For FIM/MIM>/'. You must have this portal already in use, and the URL depends on what you configured during it installation)\
(**REMARK**: If you want to use the Azure AD Password Reset Portal, the URL is 'https://passwordreset.microsoftonline.com/?whr=mydomain.com'. Do not forget to configure the domain at the end of the URL)
```XML
	<!-- The URL Where The Users Can Reset Their Password -->
	<!-- e.g. FIM/MIM: https://<Self Service Password Reset URL For FIM/MIM>/ -->
	<!-- e.g. Azure AD: https://passwordreset.microsoftonline.com/?whr=mydomain.com -->
	<pwdResetURL>https://passwordreset.microsoftonline.com/?whr=mydomain.com</pwdResetURL>
```

* When the script executes, a log file is created in the folder specified below. Specify the full path of the folder where log files should be created:
```XML
	<!-- Full Path Of The Folder For The LOG File -->
	<logFileFolderPath>C:\AD-Support\Scripts\AD-Expiry-Notification</logFileFolderPath>
```


* When the script executes, with the following setting it cleans all log files, except the last specified number of log files:
```XML
	<!-- Number Of LOG Files To Keep -->
	<numLOGsToKeep>30</numLOGsToKeep>	
```

* When the script executes, with the following setting you can specify if CSV files should be created or not:
```XML
	<!-- Enable/Disable Export Of Notified Accounts To A CSV File: ON or OFF -->
	<exportToCSV>ON</exportToCSV>
```

* When the script executes, a csv file is created in the folder specified below if export of csv files has been enabled. Specify the full path of the folder where csv files should be created:
```XML
	<!-- Full Path Of The Folder For The CSV File -->
	<csvFileFolderPath>C:\AD-Support\Scripts\AD-Expiry-Notification</csvFileFolderPath>
```

* When the script executes, with the following setting it cleans all csv files, except the last specified number of csv files:
```XML
	<!-- Number Of CSV Files To Keep -->
	<numCSVsToKeep>30</numCSVsToKeep>
```

* When the script executes, with the following setting you can define a date and time format:
```XML
	<!-- Date And Time Format To Use On Screen, In Logs And In E-mail Message -->
	<formatDateTime>yyyy-MM-dd HH:mm:ss</formatDateTime>
```

* When the script executes, the following section determines which AD domains to target and in the AD domain which OUs with users to target. For each OU (Search Base) you can specify which feature to use, the language and the search scope to in the query. 'OneLevel' means only that specified OU, and 'Subtree' means the specified OU and any sub OUs if any:\
(**REMARK**: For every AD domain, you can either list a specific DC through its FQDN to always target or you can specify DISCOVER so that a DC is discovered through the DC locator process. If you list a specific DC, then that DC must be available, otherwise the corresponding AD domain will not be processed)\
(**REMARK**: Be aware NOT to overlap OUs as users might receive e-mails more than once! The only way to overlap an OU with sub OUs is if you specify the search scope 'OneLevel' for the top level OU and the search scope 'Subtree' for the sub OUs)\
(**REMARK**: Only enable a feature for an OU/searchBase if it really is needed, otherwise do not enable it)\
(**REMARK**: accountExpiryNotificationEnabled="true" : enables account expiration notifications for that OU/searchBase)\
(**REMARK**: accountExpiryNotificationEnabled="false" : disables account expiration notifications for that OU/searchBase)\
(**REMARK**: pwdExpiryNotificationEnabled="true" : enables password expiration notifications for that OU/searchBase)\
(**REMARK**: pwdExpiryNotificationEnabled="false" : disables password expiration notifications for that OU/searchBase)\
(**REMARK**: The language 'code' is used to match the correct HTML body file and picture file)
```XML
	<!-- Targeted Domains, Specify DISCOVER To Discover A DC Or Use Specific DC And Search Bases Per Domain -->
	<!-- WARNING: Make Sure The Search Bases DO NOT Overlap Each Other!!! -->
	<domains>
		<domain FQDN="<DOMAIN1.COM>" DC="DISCOVER">
			<searchBase nr="1" accountExpiryNotificationEnabled="true" pwdExpiryNotificationEnabled="false" language="default" searchScope="OneLevel">OU=EMPLOYEES,OU=Org-Users,DC=IAMTEC,DC=NET</searchBase>
			<searchBase nr="2" accountExpiryNotificationEnabled="true" pwdExpiryNotificationEnabled="true" language="default" searchScope="Subtree">OU=Users,OU=EMPLOYEES,OU=Org-Users,DC=IAMTEC,DC=NET</searchBase>
			<searchBase nr="3" accountExpiryNotificationEnabled="true" pwdExpiryNotificationEnabled="true" language="default" searchScope="Subtree">OU=DoesNotExist1,OU=EMPLOYEES,OU=Org-Users,DC=IAMTEC,DC=NET</searchBase>
			<searchBase nr="4" accountExpiryNotificationEnabled="true" pwdExpiryNotificationEnabled="true" language="default" searchScope="OneLevel">OU=OU=CONTRACTORS,OU=Org-Users,DC=IAMTEC,DC=NET</searchBase>
			<searchBase nr="5" accountExpiryNotificationEnabled="true" pwdExpiryNotificationEnabled="true" language="default" searchScope="Subtree">OU=Users,OU=OU=CONTRACTORS,OU=Org-Users,DC=IAMTEC,DC=NET</searchBase>
			<searchBase nr="6" accountExpiryNotificationEnabled="true" pwdExpiryNotificationEnabled="true" language="default" searchScope="Subtree">OU=DoesNotExist2,OU=OU=CONTRACTORS,OU=Org-Users,DC=IAMTEC,DC=NET</searchBase>
			<searchBase nr="7" accountExpiryNotificationEnabled="true" pwdExpiryNotificationEnabled="true" language="US" searchScope="Subtree">OU=Users,OU=CONTRACTORS,OU=Org-Users,DC=IAMTEC,DC=NET</searchBase>
			<searchBase nr="8" accountExpiryNotificationEnabled="true" pwdExpiryNotificationEnabled="true" language="US" searchScope="Subtree">OU=Users,OU=CONTRACTORZZZ,OU=Org-Users,DC=IAMTEC,DC=NET</searchBase>
			<searchBase nr="9" accountExpiryNotificationEnabled="true" pwdExpiryNotificationEnabled="true" language="NL" searchScope="Subtree">OU=Users,OU=HISTORY1,OU=Org-Users,DC=IAMTEC,DC=NET</searchBase>
			<searchBase nr="10" accountExpiryNotificationEnabled="true" pwdExpiryNotificationEnabled="true" language="NL" searchScope="Subtree">OU=Users,OU=HISTORY2,OU=Org-Users,DC=IAMTEC,DC=NET</searchBase>
			<searchBase nr="11" accountExpiryNotificationEnabled="true" pwdExpiryNotificationEnabled="true" language="NL" searchScope="Subtree">OU=BLA,OU=Org-Users,DC=IAMTEC,DC=NET</searchBase>
		</domain>
		<domain FQDN="TROOT.NET" DC="DISCOVER">
			<searchBase nr="1" accountExpiryNotificationEnabled="true" pwdExpiryNotificationEnabled="true" language="default" searchScope="Subtree">DC=TROOT,DC=NET</searchBase>
		</domain>
		<domain FQDN="CHLD.IAMTEC.NET" DC="DISCOVER">
			<searchBase nr="1" accountExpiryNotificationEnabled="true" pwdExpiryNotificationEnabled="true" language="default" searchScope="Subtree">DC=CHLD,DC=IAMTEC,DC=NET</searchBase>
		</domain>
	</domains>
```

* When the script executes, and users in specified OUs/searchbases are checked, it will check, per enabled feature if the number days until expiry match a single warn period:\
(**REMARK**: It is suggested to execute the script on a weekly basis and specify 1 or more warning periods taking a factor of 7 days into account)\
(**REMARK**: Numbers shown are just examples used for testing and do not take the recommendation of the factor into account)\
(**REMARK**: Be aware NOT to overlap warning periods)
```XML
	<daysBeforeWarn>
		<!-- Number Of Days Before The AccountExpires To Send Notifications -->
		<!-- WARNING: Make Sure The Periods DO NOT Overlap Each Other!!! -->
		<feature name="accountExpiryNotification">
			<period nr="1" Max="175" MinOrEqual="98" />
			<period nr="2" Max="98" MinOrEqual="90" />
			<period nr="3" Max="69" MinOrEqual="40" />
			<period nr="4" Max="10" MinOrEqual="6" />
			<period nr="5" Max="5" MinOrEqual="2" />
			<period nr="6" Max="1" MinOrEqual="0" />
		</feature>

		<!-- Number Of Days Before The Password Expires To Send Notifications -->
		<!-- WARNING: Make Sure The Periods DO NOT Overlap Each Other!!! -->
		<feature name="pwdExpiryNotification">
			<period nr="1" Max="175" MinOrEqual="118" />
			<period nr="2" Max="118" MinOrEqual="100" />
			<period nr="3" Max="69" MinOrEqual="50" />
			<period nr="4" Max="10" MinOrEqual="9" />
			<period nr="5" Max="5" MinOrEqual="4" />
			<period nr="6" Max="2" MinOrEqual="0" />
		</feature>
	</daysBeforeWarn>
```

## Configuration - Active Directory
### *Permissions*
* NOT needed to be a member of Domain Admins, Enterprise Admins or any other powerfull AD group/role
* A normal domain user is good enough
* When using the script for notifications due to password expiry, the details of the Password Settings Objects (PSO) in the same AD domain as the targeted users must be read. By default only members of Domain Admins can read the contents of the PSO container. Instead of making the user account executing this script a member of Domain Admins, delegate Allow:Read permissions to that user account, preferrably through a security group if other security principals (e.g. admins, helpdesk, etc) require the same permissions for support and/or troubleshooting. For more information about this see the blog post: https://jorgequestforknowledge.wordpress.com/2007/08/09/windows-server-2008-fine-grained-password-policies/. For ANY AD Domain with users for which password expiry notifications are required, execute the following to delegate:

```BATCH
DSACLS "\\<FQDN OF RWDC OF AD DOMAIN TO BE SUPPORTED>\CN=Password Settings Container,CN=System,<DN OF AD DOMAIN TO BE SUPPORTED>" /G "<SECURITY PRINCIPAL>:GR" /I:T
```
* If the account executing the script does not own the mail address specified in the 'mailFromSender' in the XML configuration file, that execution account requires the 'Allow:Send As' permission on the AD account that does own that e-mail address. If the account that owns that e-mail address is also a member of any protected group, either directly or indirectly, you need to assign the 'Allow:Send As' permission on the AdminSDHolder object.\
(**REMARK**: If the account executing the script does own the mail address, this additional configuration is not needed)\
(**REMARK**: If you use an (open) internal relay server that authenticates based upon the IP address of the server the script is running on, this additional configuration is not needed)\

```BATCH
For Account: DSACLS "\\<FQDN OF RWDC OF AD DOMAIN CONTAINING MAILBOX ACCOUNT>\<DN OF ACCOUNT OWNING MAIL ADDRESS SPECIFIED IN 'mailFromSender'>" /G "<DOMAIN\EXEC_USER>:CA;Send As"
For AdminDSHolder: DSACLS "\\<FQDN OF RWDC OF AD DOMAIN CONTAINING MAILBOX ACCOUNT>\CN=AdminSDHolder,CN=System,<DN OF AD DOMAIN TO BE SUPPORTED>" /G "<DOMAIN\EXEC_USER>:CA;Send As"
```

## Configuration - Windows Server
* NOT needed to run on a domain controller
* A regular Windows Server is good enough
* 'Allow Log On As A Batch Job' user right is required when using a scheduled task
	* That can be configured as follows:
		* Grant-UserRight -Right SeBatchLogonRight -Account "<span style="color: red;">\<Domain>\\\<User></span>"\
		(**REMARK**: Part of PowerShell Module: https://gallery.technet.microsoft.com/scriptcenter/Grant-Revoke-Query-user-26e259b0)\
		OR
		* NTRIGHTS.EXE +r SeBatchLogonRight -u "<span style="color: red;">\<Domain>\\\<User></span>"\
		(**REMARK**: Part of W2K3 Resource Kit Tools: https://www.microsoft.com/en-us/download/details.aspx?id=17657)\
		OR
		* Assign it through a GPO Policy (*Computer Configuration -> Policies --> Windows Settings --> Security Settings --> Local Policies --> User Rights Assignment --> Log on as a batch job*)
* A scheduled task to execute the batch which in turn executes the powershell script\
(**REMARK**: In all cases the default 'Least Privilege' is configured. Try that first to see if it works. However due to UAC when reading password related user properties you may need to reconfigure the scheduled task to use 'Highest Privileges')
	* That can be configured as follows:
		* Using the template "scheduledTask_Notify Users With Expired Accounts And Or Passwords.xml" to import. Before the import make sure to edit the template:
			* Replace '<span style="color: red;">DOMAIN\AUTHOR_USER</span>' with the corresponding info of the user used to import the scheduled task (*Section: Task\RegistrationInfo\Author*)
			* Replace '<span style="color: red;">DOMAIN\EXEC_USER</span>' with the corresponding info of the user used run the scheduled task on a regular basis (*Section: Task\Principals\Principal\UserId*)
			* Replace '<span style="color: red;">FULL PATH TO AD-Exp-Notify.cmd</span>' with the full path of the batch file 'AD-Exp-Notify.cmd' (*Section: Task\Actions\Exec\Command*)
			* Replace '<span style="color: red;">FULL PATH OF FOLDER OF AD-Exp-Notify.cmd</span>' with the full path of the folder containing the batch file 'AD-Exp-Notify.cmd' (*Section: Task\Actions\Exec\WorkingDirectory*)\
		OR
		* Assign it through a GPO Preference (*Computer Configuration -> Preferences --> Control Panel Settings --> Scheduled Tasks --> Local Policies --> User Rights Assignment*)\
		OR
		* Using PowerShell to create and configure the scheduled task
```PowerShell
$scheduledTaskAction = New-ScheduledTaskAction -Execute "<FULL PATH TO AD-Exp-Notify.cmd>" -WorkingDirectory "<FULL PATH OF FOLDER OF AD-Exp-Notify.cmd>"
$scheduledTaskTrigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek "<WEEKDAY>" -At "<TIME>"
$scheduledTaskSettings = New-ScheduledTaskSettingsSet
$scheduledTask = New-ScheduledTask -Action $scheduledTaskAction -Trigger $scheduledTaskTrigger -Settings $scheduledTaskSettings
Register-ScheduledTask -TaskName "iamTEC_Notify Users With Expired Accounts And Or Passwords" -InputObject $scheduledTask -User "<DOMAIN\EXEC_USER>" -Password '<PASSWORD>'
```

## Examples
#### If you execute the script without enabling any notification feature, you will see the following on screen
![](https://www.dropbox.com/s/qzw6mnaqcvwo7yp/AD-Exp-Not_Test-No-Mailings_Features-Not-Enabled_01_On-Screen.png?raw=1)
![](https://www.dropbox.com/s/fm5z7cqbwhhpxge/AD-Exp-Not_Test-No-Mailings_Features-Not-Enabled_02_On-Screen.png?raw=1)

#### If you execute the script without enabling any notification feature, you will see the following in the error e-mail
![](https://www.dropbox.com/s/wj8tltkl6edp1aq/AD-Exp-Not_Test-No-Mailings_Features-Not-Enabled_03_Error-Mailing.png?raw=1)

#### If you execute the script with notification features enabled, you will see something similar to the following on screen
![](https://www.dropbox.com/s/4v7w5fzp9faroeb/AD-Exp-Not_Features-Enabled_01_On-Screen.png?raw=1)
![](https://www.dropbox.com/s/d1gxa31he3u9sek/AD-Exp-Not_Features-Enabled_02_On-Screen.png?raw=1)
![](https://www.dropbox.com/s/2gx1o37bt07k78e/AD-Exp-Not_Features-Enabled_03_On-Screen.png?raw=1)
![](https://www.dropbox.com/s/j717mgihf7osk43/AD-Exp-Not_Features-Enabled_04_On-Screen.png?raw=1)
![](https://www.dropbox.com/s/cqb9z9seeyat9bg/AD-Exp-Not_Features-Enabled_05_On-Screen.png?raw=1)
![](https://www.dropbox.com/s/du6xvdgvl80jxt7/AD-Exp-Not_Features-Enabled_06_On-Screen.png?raw=1)
![](https://www.dropbox.com/s/msiwfa834ka64mh/AD-Exp-Not_Features-Enabled_07_On-Screen.png?raw=1)
![](https://www.dropbox.com/s/oxdxfzru0on4kjz/AD-Exp-Not_Features-Enabled_08_On-Screen.png?raw=1)
![](https://www.dropbox.com/s/fs8zkd52j99f683/AD-Exp-Not_Features-Enabled_09_On-Screen.png?raw=1)
![](https://www.dropbox.com/s/8bbjcm3h31nnvyw/AD-Exp-Not_Features-Enabled_10_On-Screen.png?raw=1)
![](https://www.dropbox.com/s/fgwqskio3zfsy2j/AD-Exp-Not_Features-Enabled_11_On-Screen.png?raw=1)
![](https://www.dropbox.com/s/llg44x4z5j1bpu6/AD-Exp-Not_Features-Enabled_12_On-Screen.png?raw=1)
![](https://www.dropbox.com/s/nof00g1ki2zsm17/AD-Exp-Not_Features-Enabled_13_On-Screen.png?raw=1)

#### If any AD domain and/or OU/searchBase specified does not exist, you will see something similar in the error e-mail
![](https://www.dropbox.com/s/wgu9re4trqe8r5z/AD-Exp-Not_Features-Enabled_Non-Existing_01_Error-Mail.png?raw=1)
![](https://www.dropbox.com/s/dzejub1thxlx238/AD-Exp-Not_Features-Enabled_Non-Existing_02_Error-Mail.png?raw=1)

#### If you execute the script with the '-force' parameter and DEV configured in the XML configuration file, you will see something similar to the following on screen (pay attention to only 1 e-mail being send per enabled notification feature)
![](https://www.dropbox.com/s/ows5a3zy2yufoj2/AD-Exp-Not_Features-Enabled_Force-DEV-Mode_01_On-Screen.png?raw=1)

#### If you execute the script with the '-force' parameter and DEV configured in the XML configuration file, you will see something similar to the following in the account expiration notification e-mail to the Test Mode User
![](https://www.dropbox.com/s/19vy7xoyeeh3i7y/AD-Exp-Not_Features-Enabled_Force-DEV-Mode_02_Mailing.png?raw=1)

#### If you execute the script with the '-force' parameter and DEV configured in the XML configuration file, you will see something similar to the following in the password expiration notification e-mail to the Test Mode User
![](https://www.dropbox.com/s/5vzydrhugcv1q8y/AD-Exp-Not_Features-Enabled_Force-DEV-Mode_03a_Mailing.png?raw=1)
![](https://www.dropbox.com/s/zrlutsue02i3152/AD-Exp-Not_Features-Enabled_Force-DEV-Mode_03b_Mailing.png?raw=1)

#### If you execute the script with the '-force' parameter and TEST configured in the XML configuration file, you will see something similar to the following on screen (pay attention to all e-mails being send to the Test Mode User for every scoped user)
![](https://www.dropbox.com/s/w4t7z6fy827mrvh/AD-Exp-Not_Features-Enabled_Force-TEST-Mode_01_On-Screen.png?raw=1)

#### If you execute the script with the '-force' parameter and TEST configured in the XML configuration file, you will see something similar to the following in the account expiration notification e-mail to the Test Mode User from one of the scoped users
![](https://www.dropbox.com/s/rt4xscvqnzrcqpm/AD-Exp-Not_Features-Enabled_Force-TEST-Mode_02_Mailing.png?raw=1)

#### If you execute the script with the '-force' parameter and TEST configured in the XML configuration file, you will see something similar to the following in the password expiration notification e-mail to the Test Mode User from one of the scoped users
![](https://www.dropbox.com/s/j6po4q0gihmp5rf/AD-Exp-Not_Features-Enabled_Force-TEST-Mode_03a_Mailing.png?raw=1)
![](https://www.dropbox.com/s/7nf73nd3fv57xka/AD-Exp-Not_Features-Enabled_Force-TEST-Mode_03b_Mailing.png?raw=1)

#### If you execute the script with the '-force' parameter and PROD configured in the XML configuration file, you will see something similar to the following on screen (pay attention to all e-mails being send to the individual users)
![](https://www.dropbox.com/s/x166vh9f7eq3h4q/AD-Exp-Not_Features-Enabled_Force-PROD-Mode_01_On-Screen.png?raw=1)