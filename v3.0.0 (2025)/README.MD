# CIS v3.0.0

![alt text](https://github.com/eneerge/CIS-Windows-Server-2022/raw/main/hardening%20output.png?raw=true)

# Harden Windows Server 2022 (CIS)
This repository contains a powershell script and excel file that can be used to implement recommendations provided by the Center for Internet Security (www.cisecurity.org). Both L1 and L2 configurations have been included. This is based on the following benchmark: https://workbench.cisecurity.org/benchmarks/16913

# Spreadsheet
Spreadsheet contains all CIS Recommendations without modifications. Some items require further admin setup (EG: LAPS) and have been noted.

# Powershell Script
Script is provided that implements all configurations (L1, L2, NG). Each configuration can be easily commented out if not required. Please review the spreadsheet to see if any additional setup is required for any particular configuration.

Please note that you do NOT have to configure anything and you can simply run as is if you're just looking to quickly harden your machine. I have provided hardened defaults. However, you should at least review the compatibility assurance options to make sure you don't break anything.

## Basic Configuration Variables
- `$LogonLegalNoticeMessageTitle`
- `$LogonLegalNoticeMessage`
- `$WindowsFirewallLogSize` (defaults to 32MB, the max)
- `$EventLogMaxFileSize` (defaults to 100MB)
- `$EventLogSecurityMaxFileSize` (defaults to 2GB)
- `$WindowsDefenderLogSize` (defaults to 2gb)

## Admin and Guest User Name Prefixes
- `$AdminAccountPrefix` 
  - This is the built-in admin account username that will be disabled after running. To randomize the username, a random number will be added to the specified prefix (EG: MyAdminPrefix1234). 
  - **NOTE:** If you have already run the script once, it will not rename again unless you change the prefix to avoid continuously changing the admin name.
- `$GuestAccountName` 
  - This is the built-in guest account which will be renamed. Similarly, it will not be renamed if it has already been renamed by the script once before.

## Compatibility Assurance
To reduce the risk of breaking any functionality on your server, compatibility assurance variables have been created to guide you.  These options will oppose CIS settings that may affect a certain functionality. Setting the value to true will alter your policy settings to maintain compatibility.

- `$AllowRDPFromLocalAccount`
  - This option enables you to remote desktop into the server using a local account. If you are using ActiveDirectory, you probably want to set this to $false. If you are not using ActiveDirectory, you will likely want this to be $true or you won't be able to RDP into the server.

- `$AllowRDPClipboard` 
  - This option allows you to copy/paste into a remote desktop session. Recommend to leave it $true if you need to copy/paste in an RDP session.

- `$AllowDefenderMAPS` 
  - This enables joining Microsoft MAPS (Spynet). CIS recommends disabling this for privacy reasons, but certain features of Microsoft Defender require this to be enabled to work. Recommend this to $true if you prefer greater AV protection. Set to $false if you prefer better privacy with the con of losing some of the cloud protection features of Defender.

- `$AllowStoringPasswordsForTasks` 
  - This option allows you to save passwords in the Windows Task Scheduler. If you need to run automated tasks using the Windows Task Scheduler under an account that has a password, this must be set to $true. If you use a dedicated service account to run automated tasks (NetworkService, etc), you can probably set this to $false and increase your hardening.

- `$AllowAccessToSMBWithDifferentSPN` 
  - This allows connecting to an SMB share using an SPN the server does not recognize. This may be common in a non-ActiveDirectory environment when the server does not know it can be accessed through alternate hostnames. Without this, you will receive access denied when attempting to connect to the server using an alternate dns name. If you only access via IP address, you can safely set this to false.

- `$DontSetEnableLUAForVeeamBackup`
  - This disables the Admin Approval Mode. Mainly here because Veeam requires this setting. See https://www.veeam.com/kb4185
  - The EnableLUA hardening option causes UAC popups for every app that runs as admin, including the Sever Manager which could be quite annoying, but it does increase your hardening.

- `$DontSetTokenFilterPolicyForPSExec`
  - This alters the LocalAccountTokenFilterPolicy so that PSExec can run on the machine
  - Leave this set to $false unless you use PSExec. PSExec is often times used illegitimately and leaving this enabled increases risk.

- `$DnsOverHttpsInt`
  - This sets the DNS-Over-Https setting which routes all DNS traffic (normally port 53) over https (443). DNS-Over-Https is better for privacy, but it could affect connectivity. By default, the script will prefer DNS-Over-Https, but will fallback to regular DNS if connection issues occur. This is the recommended CIS setting.
  - 2 (default) prefers DOH, but allows regular DNS  
  - 3 Forces Dns-Over-Https
  
## Attack Surface Reduction Exclusions
This script enables all Attack Surface Reduction rules - even those that CIS has not included in their recommendation, yet. For example, the "Block software that does not meet a prevalence". This greatly increases the hardening of the system, but it also greatly increases the risk of false positives. Simply updating php to a new version could potentially cause a web server to no longer work due to the latest version of PHP not being known by Microsoft, yet. You can specify known software here to ensure ASR does not block them.
`$AttackSurfaceReductionExclusions`
- Simply enter the path to a folder OR an executable to exclude from ASR detection.
- **Caution:** Highly recommend you only enter folders and executables that have been installed into a path that can't be altered by a non-admin. 
  - EG: C:\Program Files\Some Software"
  - If you enter a path that's easily manipulated by a user, malware could easily overwrite that executable and then bypass your ASR rules.

## Extra Hardening Options
- `$AdditionalUsersToDenyNetworkAccess` 
  - By default, the script denies users or groups from accessing the server over the network as defined by CIS recommendations. If you would like to restrict even more users, you can provide them here.

- `$AdditionalUsersToDenyRemoteDesktopServiceLogon`
  - Similar to the above option, deny additional users or groups who should not be able to RDP into the server.

- `$AdditionalUsersToDenyLocalLogon`
  - Similar to above, deny users or groups who can log on locally. Good idea to include users that are used for only batch jobs who do not need to login to the machine directly.

## Add/Remove Specific CIS Configurations
If a compatibility assurance option is not available for your particular need, you can comment out any policy called by the $ExecutionList by placing a # in front of the policy option. 

I recommend browsing each configuration option and commenting out any setting that appears could cause issues in your environment. When implementing for the first time, you can comment out every line and bring each setting in slowly to ensure everything still works on the server.

Note: This script does not reverse any settings when commenting out a configuration. You will need to manually reverse (or simply restore your VM snapshot) to revert back.
My recommended way of implementing:
1. Fresh OS install (not required)
2. Snapshot/Checkpoint the Virtual Machine
3. Apply script
4. Test
5. (If necessary) Revert to previous snapshot
6. Repeat until you have a working configuration

## Run It - First Time
After configuring the above options, open an admin powershell (64-bit) window and run the script.
On the first run, the script will require you to enter a new admin password. Successive runs will not require this interaction.

## Run It - Recurring
The script can be run on a recurring basis. This allows you to enforce the configurations on a interval.
On recurring runs, the script skips creating an admin user and does not prompt for a password. This allows it to run without any interaction. The script can be set up as a scheduled task or you can configure your RMM software to kick off the process at an interval of your choosing.

## Logging
The script produces the following logs. The logs are written to the location the script is run from.
- CommandsReport.txt - This records the output of running Windows commands to import the local security policy
- PoliciesApplied.txt - This records the policies that were specified in the $ExecutionList
- PolicyChangesMade.txt - This records all of the changes that the script applied. It only records what changed and not what the script was configured to change. IE: If you already had a CIS setting in place, it will not record that change - only the CIS settings this script altered.
- PolicyResults.txt - This records the entire results of each CIS setting with each having a "Before" and "After" so that you can see how the script affected your configuration. If a setting was changed "Value changed" will be reported in the output so that you can easily search through the log to locate any settings that changed. The same changes are also reported in PolicyChangesMade.txt.

# Validation/Audit Results
2025.02.22 All settings, except for LAPS-related configurations have been implemented. Full audit results are provided. Audits were conducted using the audit files from Tenable Windows Server 2022 CIS v3.0.0 L1, L2, and NG.

#### Audits Failed
Only LAPS related configurations are not set. The intention of this script is to be run against a non-AD environment, so LAPS is not usually an option for non-AD/non-intune.
| CIS Section | CIS Description | Notes |
| :---------- | :-------------- | :---- |
| 18.9.25.1   | (L1) Ensure 'Configure password backup directory' is set to 'Enabled: Active Directory' or 'Enabled: Azure Active Directory | This is a LAPs setting which this script doesn't implement since it's mainly for non-AD servers.
| 18.9.25.2 | (L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled' | LAPS related
| 18.9.25.3 | (L1) Ensure 'Enable password encryption' is set to 'Enabled' | LAPS related
| 18.9.25.4 | (L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' | LAPS related
| 18.9.25.5 | (L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more' | LAPS related
| 18.9.25.6 | (L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer' | LAPS related
| 18.9.25.7 | (L1) Ensure 'Post-authentication actions: Grace period (hours)' is set to 'Enabled: 8 or fewer hours, but not 0' | LAPS related
| 18.9.25.8 | (L1) Ensure 'Post-authentication actions: Actions' is set to 'Enabled: Reset the password and logoff the managed account' or higher | LAPS related

All other configurations passed.

# Notes
Windows Server on-premise machines can not currently be managed by Intune. If you have removed all Active Directory components from your environment, one solution to ensure servers adhere to a baseline is to run a script to apply all of the configurations.

# Credits
The prelimb of this script was Windows Server 2019 CIS script that I originally downloaded from @viniciusmiguel repository at https://github.com/viniciusmiguel . The original script is no longer available.
