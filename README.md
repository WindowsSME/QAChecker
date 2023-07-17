Machine QA Compliance using PowerShell
(Windows PowerShell ISE)

This script will allow you to easily check multiple compliance items on a machine before signing off deployment

1. Login to the local machine using an adminstrator account
2. Open Windows Powershell ISE as Administrator
3. Click on View > Show Script Pane
4. Copy the cript block to the Script Pane window
5. Click on the Run Script icon or press F5
6. Results will show when completed. Logs will be generated for reference at this location: C:\Temp\. Filename will have a format hostname/computername.log

#Compliance Checker 5.0
#CompChecker.ps1
#Author: James Romeo Gaspar
#OG: Version 1.0 | 5.26.2023
#Revision: 2.0 | 5.28.2023 : Added Google Chrome fallback check; WorkspaceONE/Assist fallback check.
#Revision: 3.0 | 6.6.2023 : Added GlobalProtect; Logfile set to hostname; Code optimization
#Revision: 4.0 | 6.8.2023 : Added TPM check; Non-autorized accounts check; OS Version and Build check; Unused partition Check; Bios password status check, Wifi-Adapter status check, Installed OS Check, Added Device UDID check, Added Serial Number check
#Revision: 5.0 | 7.17.2023 : Added Manufacturer check, re-arranged BIOS query timing
