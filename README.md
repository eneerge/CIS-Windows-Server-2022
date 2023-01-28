# CIS-Windows-Server-2022
This repository contains documents used to implement recommendations provided by the Center for Information Security (www.cisecurity.org). Both L1 and L2 configurations have been included.

# Spreadsheet
Spreadsheet contains all CIS Recommendations without modifications. Some items require further admin setup (EG: LAPS) and have been noted.

# Powershell Script
Script is provided that implements all configurations (L1 and L2). Each configuration can be easily commented out if not required. Please review the spreadsheet to see if any additional setup is required for any particular configuration.

# Notes
Windows Server on-premise machines can not currently be managed by Intune. If you have removed all Active Directory components from your environment as I have, one solution to ensure servers adhere to a baseline is to run a script to apply all of the configurations. My intention of this script is to set it up to be run automatically every day on the server to ensure it doesn't trickle away from the baseline. A couple things to note:
- The script currently creates a new admin user. If the script is run daily, it will need to be modified so that it doesn't attempt to recreate the admin user
- Script will need to be modified anytime a change needs to be made or it will be wiped out when the script is automatically run on the next iteration.

# Credits
The prelimb of this script was Windows Server 2019 CIS script that I originally downloaded from @viniciusmiguel repository at https://github.com/viniciusmiguel . The original script is no longer available.
