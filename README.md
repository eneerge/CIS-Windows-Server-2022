![alt text](https://github.com/eneerge/CIS-Windows-Server-2022/raw/main/hardening%20output.png?raw=true)

# CIS-Windows-Server-2022
This repository contains documents used to implement recommendations provided by the Center for Information Security (www.cisecurity.org). Both L1 and L2 configurations have been included. The script is based off the following benchmark: https://workbench.cisecurity.org/benchmarks/8932 (login required, but free)

# Spreadsheet
Spreadsheet contains all CIS Recommendations without modifications. Some items require further admin setup (EG: LAPS) and have been noted.

# Powershell Script
Script is provided that implements all configurations (L1 and L2). Each configuration can be easily commented out if not required. Please review the spreadsheet to see if any additional setup is required for any particular configuration.
To use:
- Configure `$LogonLegalNoticeMessageTitle` and `$LogonLegalNoticeMessage` if you require one to be set (optional)
- Configure `$WindowsFirewallLogSize` (defaults to 4gb)
- Configure `$EventLogMaxFileSize` (defaults to 4gb)
- Configure `$AdminAccountName` to what you want to call the built-in admin account that is disabled after the script has been run (required, defaults to "Administrator")
- Configure `$GuestAccountName` to what you want to call the built-in guest account that is disabled after the script has been run (required, defaults to "NoGuest")
- Configure compatibility assurance - These options will oppose CIS settings that may break your server. Setting the value to true will alter your policy settings to maintain compatibility.
  - `$AllowRDPFromLocalAccount` - This option enables you to remote desktop into the server using a local account. If you are using ActiveDirectory, you will want to set this to $false. If you are not using ActiveDirectory, you will likely want this to be $true.
  - `$AllowRDPClipboard` - This option allows you to copy/paste into a remote desktop session. Otherwise, the feature won't work. Recommend to leave it $true if you need to copy/paste in an RDP session.
  - `$AllowDefenderMAPS` - This enables joining Microsoft MAPS (Spynet). CIS recommends disabling this for privacy reasons, but certain features of Microsoft Defender require this to be enabled to work. Recommend this to $true if you prefer greater AV protection. Set to $false if you prefer better privacy with the con of losing some of the cloud protection features of Defender.
  - `$AllowStoringPasswordsForTasks` - This option allows you to save passwords in the Windows Task Scheduler. If you need to run automated tasks using the Windows Task Scheduler under an account that has a password, this must be set to $true. If you use a dedicated service account to run automated tasks (NetworkService, etc), you can probably set this to $false and increase your hardening.
  - `$AllowAccessToSMBWithDifferentSPN` - This allows connecting to an SMB share using an SPN the server does not recognize. This may be common in a non-ActiveDirectory environment when the server does not know it can be accessed through alternate hostnames.
  - `$DontSetEnableLUAForVeeamBackup` - This disables the Admin Approval Mode. Mainly here because Veeam requires this setting. See https://www.veeam.com/kb4185
  - `$AdditionalUsersToDenyNetworkAccess` - By default, the script denies CIS recommend users from accessing the server over the network. If you would like to restrict even more users, you can provide them here. If you know a user should not access this server over the network, you should include them here to increase your hardening.
  - `$AdditionalUsersToDenyRemoteDesktopServiceLogon` - Similar to the above option, deny additional users who should not be able to RDP into the server.
  - `$AdditionalUsersToDenyLocalLogon` - Similar to above, deny users who can log on locally. Good idea to include users that are used for only batch jobs who do not need to login to the machine directly.
- Each CIS option can be commented out by placing a # in front of that option. Review the items in the $ExecutionList to see if there is any option you would like to disable.
- After configuring the above options, open an admin powershell (64-bit) window and run the script
- Script will inform you that a new admin user will be created
- Enter a new admin password for that user
- Reboot and login with your new admin user

The script produces the following logs. The logs are written to the location the script is run from. By default this will be C:\users\<username>:
- CommandsReport.txt - This records the output of running Windows commands to import the local security policy
- PoliciesApplied.txt - This records the policies that were specified in the $ExecutionList
- PolicyChangesMade.txt - This records all of the changes that the script applied. It only records what changed and not what the script was configured to change. IE: If you already had a CIS setting in place, it will not record that change - only the CIS settings this script altered.
- PolicyResults.txt - This records the entire results of each CIS setting with each having a "Before" and "After" so that you can see how the script affected your configuration. If a setting was changed "Value changed" will be reported in the output so that you can easily search through the log to locate any settings that changed. The same changes are also reported in PolicyChangesMade.txt.

# Notes
Windows Server on-premise machines can not currently be managed by Intune. If you have removed all Active Directory components from your environment as I have, one solution to ensure servers adhere to a baseline is to run a script to apply all of the configurations. My intention of this script is to set it up to be run automatically every day on the server to ensure it doesn't trickle away from the baseline. A couple things to note:
- The script currently creates a new admin user. If the script is run daily, it will need to be modified so that it doesn't attempt to recreate the admin user
- Script will need to be modified anytime a change needs to be made or it will be wiped out when the script is automatically run on the next iteration.

# Credits
The prelimb of this script was Windows Server 2019 CIS script that I originally downloaded from @viniciusmiguel repository at https://github.com/viniciusmiguel . The original script is no longer available.
