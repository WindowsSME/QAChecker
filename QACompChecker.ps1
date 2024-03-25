#Compliance Checker 6.0
#CompChecker.ps1
#Author: James Romeo Gaspar
#OG: Version 1.0 | 5.26.2023
#Revision: 2.0 | 5.28.2023 : Added Google Chrome fallback check; WorkspaceONE/Assist fallback check.
#Revision: 3.0 | 6.6.2023 : Added GlobalProtect; Logfile set to hostname; Code optimization
#Revision: 4.0 | 6.8.2023 : Added TPM check; Non-autorized accounts check; OS Version and Build check; Unused partition Check; Bios password status check, Wifi-Adapter status check, Installed OS Check, Added Device UDID check, Added Serial Number check
#Revision: 5.0 | 7.17.2023 : Added Manufacturer check, re-arranged BIOS query timing
#Revision: 6.0 | 3.25.2024 : Added additional fallback for Google Chrome check

$ErrorActionPreference = "SilentlyContinue"
Import-Module -Name Microsoft.PowerShell.Utility

function Get-BitLockerEncryptionStatus {
    $encryptionStatus = Get-BitLockerVolume -MountPoint C:
    $encryptionPercentage = [math]::Round($encryptionStatus.EncryptionPercentage, 2)
    $output = "Bitlocker Encryption: $($encryptionStatus.VolumeStatus) ($encryptionPercentage%)"

    Add-EntryToFile $output
    $output
}

function Get-WindowsUpdateStatus {
    $featureStatus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings" -Name "PausedFeatureStatus").PausedFeatureStatus
    $qualityStatus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings" -Name "PausedQualityStatus").PausedQualityStatus

    $featureResult = "Feature Updates: "
    switch ($featureStatus) {
        0 { $featureResult += "Not Paused" }
        1 { $featureResult += "Paused" }
        2 { $featureResult += "Auto-Resumed After Being Paused" }
        default { $featureResult += "Unknown Status" }
    }

    $qualityResult = "Quality Updates: "
    switch ($qualityStatus) {
        0 { $qualityResult += "Not Paused" }
        1 { $qualityResult += "Paused" }
        2 { $qualityResult += "Auto-Resumed After Being Paused" }
        default { $qualityResult += "Unknown Status" }
    }

    $output = "$featureResult | $qualityResult"

    Add-EntryToFile $output
    $output
}

function Get-SoftwareInfo {
    param (
        [string]$registryPath,
        [string]$wmiClass,
        [string]$softwareName,
        [string]$serviceName
    )

    $uninstallInfo = Get-ItemProperty -Path $registryPath |
        Where-Object { $_.DisplayName -like "*$softwareName*" } |
        Select-Object -Property DisplayName, DisplayVersion, InstallDate

    $wmiInfo = Get-WmiObject -Class $wmiClass |
        Where-Object { $_.Name -like "*$softwareName*" } |
        Select-Object -Property Name, Version, InstallDate

    if ($uninstallInfo) {
        $softwareInfo = $uninstallInfo
        $version = $softwareInfo.DisplayVersion
    }
    elseif ($wmiInfo) {
        $softwareInfo = $wmiInfo
        $version = $softwareInfo.Version
    }
    else {
        $softwareInfo = $null
    }

    if ($softwareInfo) {
        $installDate = $softwareInfo.InstallDate
        $service = Get-Service -Name $serviceName | Select-Object -Property Status, StartType
        $serviceStatus = $service.Status | Get-Unique
        $serviceType = $service.StartType | Get-Unique

        $output = "$softwareName Version: $version | Service Status: $serviceStatus ($serviceType) | Installed: $installDate"
    }
    else {
        $output = "${softwareName}: Not Installed"
    }

    Add-EntryToFile $output
    $output
}

function Get-GTBInfo {
    Get-SoftwareInfo -registryPath 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -wmiClass 'Win32_Product' -softwareName 'GTB' -serviceName 'GTB*'
}

function Get-CortexXDRInfo {
    Get-SoftwareInfo -registryPath 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -wmiClass 'Win32_Product' -softwareName 'Cortex XDR' -serviceName 'cyserver'
}

function Get-GoogleChromeInfo {
    $chromeRegKey = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $chromeRegEntry = Get-ItemProperty $chromeRegKey | Where-Object { $_.DisplayName -like "*Google Chrome*" }

    if ($chromeRegEntry -eq $null) {
        $wmiQuery = "SELECT * FROM Win32_Product WHERE Name LIKE '%Google Chrome%'"
        $wmiResult = Get-WmiObject -Query $wmiQuery -ErrorAction SilentlyContinue

        if ($wmiResult -eq $null) {
            $cimQuery = "SELECT * FROM CIM_Product WHERE Name LIKE '%Google Chrome%'"
            $cimResult = Get-CimInstance -Query $cimQuery -ErrorAction SilentlyContinue

            if ($cimResult -eq $null) {
                $chromeExePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
                if (Test-Path $chromeExePath) {
                    $chromeVersion = (Get-Command $chromeExePath).FileVersionInfo.FileVersion
                    $output = "Google Chrome version: $chromeVersion"
                } else {
                    $output = "Google Chrome: Not Installed."
                }
            } else {
                $chromeVersion = $cimResult.Version
                $output = "Google Chrome version: $chromeVersion"
            }
        } else {
            $chromeVersion = $wmiResult.Version
            $output = "Google Chrome version: $chromeVersion"
        }
    } else {
        $chromeVersion = $chromeRegEntry.DisplayVersion
        $output =  "Google Chrome version: $chromeVersion"
    }

    Add-EntryToFile $output
    $output
}

function Get-WorkspaceOneInfo {
    $workspaceOneVersion = (Get-WmiObject -Class Win32_Product | where {$_.Name -like 'Workspace*'} | where {$_.Name -eq 'Workspace ONE Intelligent Hub Installer'}).Version
    $assistVersion = (Get-WmiObject -Class Win32_Product | where {$_.Name -like 'Workspace*'} | where {$_.Name -eq 'Workspace ONE Assist'}).Version
    $output = if ($workspaceOneVersion) {
        if ($assistVersion) {
            "Workspace ONE Version: $workspaceOneVersion | Workspace ONE Assist Version: $assistVersion"
        }
        else {
            "Workspace ONE Version: $workspaceOneVersion | Workspace ONE Assist Version: Not Found"
        }
    }
    else {
        if ($assistVersion) {
            "Workspace ONE Version: Not Found | Workspace ONE Assist Version: $assistVersion"
        }
        else {
            "Workspace ONE Version: Not Found | Workspace ONE Assist Version: Not Found"
        }
    }
    Add-EntryToFile $output
    $output
}


function Get-ImageVersion {
    $Path = 'C:\Windows\System32'

    $FileSearch = Get-ChildItem $Path | Where {
        ($_.Name -like '@*') -and
        ($_.Name -notlike '*.png') -and
        ($_.Name -notlike '*.gif')
    }

    if ($FileSearch -ne $null) {
        $output = foreach ($file in $FileSearch) {
            $FileName = $file.Name
            $FileDate = $file.LastWriteTime
            $FilePath = Split-Path -Path $file.Fullname -Parent
            "Image Version: $FileName ($FileDate)"
        }
    } else {
        $output = "Image Version: Undefined / Windows 11 Machine"
    }

    Add-EntryToFile $output
    $output
}


function Get-OperatingSystemInstallDate {
    Write-Progress -Activity "Getting OS Install Date" -Status "In Progress"
    $installDate = (Get-CimInstance -ClassName Win32_OperatingSystem).InstallDate
    $output = "OS Installation Date : $installDate"

    Add-EntryToFile $output
    $output
}

function Get-GlobalProtectInfo {
    $wmiQuery = "SELECT * FROM Win32_Product WHERE Name LIKE '%GlobalProtect%'"
    $wmiResult = Get-WmiObject -Query $wmiQuery -ErrorAction SilentlyContinue

    if ($wmiResult -eq $null) {
        $cimQuery = "SELECT * FROM CIM_Product WHERE Name LIKE '%GlobalProtect%'"
        $cimResult = Get-CimInstance -Query $cimQuery -ErrorAction SilentlyContinue

        if ($cimResult -eq $null) {
            $output = "GlobalProtect: Not Installed."
        } else {
            $globalProtectVersion = $cimResult.Version
            $output = "GlobalProtect version (CIM): $globalProtectVersion"
        }
    } else {
        $globalProtectVersion = $wmiResult.Version
        $output = "GlobalProtect version: $globalProtectVersion"
    }

    Add-EntryToFile $output
    $output
}


function Get-TPMStatus {
    $tpm = Get-TPM

    if ($tpm -eq $null) {
        $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm
    }

    $output = if ($tpm.TPMEnabled -eq 'True' -or $tpm.IsEnabled_InitialValue -eq 'True') {
        "TPM: Enabled"
    } else {
        "TPM: Disabled"
    }
    Add-EntryToFile $output
    $output
}

function Get-NonCompliantAccounts {
    $adminAccounts = @(
        "$env:COMPUTERNAME\CISADMIN",
        'TU\TU-AD-Computer Admins-DL',
        'TU\TU-SysAdmin-GG'
    )

    $adminMembers = (Get-LocalGroupMember -Group "Administrators").Name

    $nonCompliant = $adminMembers | Where-Object { $_ -notin $adminAccounts }

    $output = if ($nonCompliant) {
        $nonCompliantAccounts = $nonCompliant -join ', '
        "Non-Compliant Account/s: $nonCompliantAccounts"
    } else {
        "Non-Compliant Account/s: None"
    }
    Add-EntryToFile $output
    $output
}

function Get-MachineType {
    $hardwareType = (Get-CimInstance -Class Win32_ComputerSystem).PCSystemType
    if ($hardwareType -eq $null) {
        $hardwareType = (Get-WmiObject -Class Win32_ComputerSystem).PCSystemType
    }

    $output = if ($hardwareType -eq "2") {
        "Machine Type: Laptop"
    } else {
        "Machine Type: Desktop"
    }
    Add-EntryToFile $output
    $output
}

function Get-WiFiAdapterStatus {
    $wifiAdapter = Get-NetAdapter | Where-Object Name -like "*Wi*Fi*"
    $output = if ($wifiAdapter) {
        $wifiStatus = $wifiAdapter.Status
        if ($wifiStatus -eq "Disabled") {
            "Wifi Adapter: Disabled"
        } else {
            "Wifi Adapter: Enabled ($wifiStatus)"
        }
    } else {
        "Wifi Adapter: None found or disabled in BIOS"
    }
    Add-EntryToFile $output
    $output
}

function Get-OSVersion {
    $osProperties = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property Caption, BuildNumber
    $osPropertiesReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $output = "Installed OS: $($osProperties.Caption) | Version $($osPropertiesReg.DisplayVersion) (OS Build $($osProperties.BuildNumber).$($osPropertiesReg.UBR))"
    Add-EntryToFile $output
    $output
}


function Get-RawPartition {
    $diskPartCheck = (Get-Disk | Where-Object PartitionStyle -eq "RAW").PartitionStyle

    $output = if ($diskPartCheck) {
        "Disk Partition: With RAW/Unused Partition"
    } else {
        "Disk Partition: No RAW/Unused Partition"
    }
    Add-EntryToFile $output
    $output
}

function Get-BIOSPasswordStatus {
    $ErrorActionPreference = "SilentlyContinue"
    Install-PackageProvider -Name NuGet -Force
    Install-Module -Name GetBIOS -Force
    $biosSettings = Get-Bios
    $isAdminPasswordSet = $biosSettings | Where-Object { $_.Setting -eq "IsAdminPasswordSet" } | Select-Object -ExpandProperty Value

    $output = if ($isAdminPasswordSet -eq "True") {
        "BIOS Admin Password: Set and Active"
    } else {
        "BIOS Admin Password: Not Set"
    }$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer

    Add-EntryToFile $output
    $output
}

function Get-DeviceClientID {
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\MDMDeviceID"
    $propertyName = "DeviceClientID"
    $propertyValue = (Get-ItemProperty -Path $registryPath -Name $propertyName).$propertyName

    $output = if ($propertyValue -eq $null) {
        "DeviceClientID is Unavailable."
    }
    else {
        "Device UDID: $propertyValue"
    }
    Add-EntryToFile $output
    $output
}

function Get-Hostname {
    $primary = $env:COMPUTERNAME
    $fallbacks = @(
        { [System.Net.Dns]::GetHostName() },
        { $env:HOSTNAME },
        { (Get-WmiObject -Class Win32_ComputerSystem).Name }
    )
    
    $output = "Hostname: $primary"
    foreach ($fallback in $fallbacks) {
        $hostname = &$fallback
        if ($hostname) {
            $output = "Hostname: $hostname"
            break
        }
    }
    Add-EntryToFile $output
    $output
}

function Get-SerialNumber {
    $classes = @('Win32_BIOS', 'Win32_SystemEnclosure', 'Win32_BaseBoard', 'Win32_ComputerSystemProduct')
    $serialNumber = $null

    foreach ($class in $classes) {
        $obj = Get-CimInstance -ClassName $class -ErrorAction SilentlyContinue
        if ($obj) {
            $serialNumber = $obj.SerialNumber
            break
        }
    }

    if (-not $serialNumber) {
        foreach ($class in $classes) {
            $obj = Get-WmiObject -Class $class -ErrorAction SilentlyContinue
            if ($obj) {
                $serialNumber = $obj.SerialNumber
                break
            }
        }
    }

    $output = if ($serialNumber) {
        "Serial Number: $serialNumber"
    } else {
        "Serial number: Not Found."
    }
    Add-EntryToFile $output
    $output
}

function Get-ComputerManufacturer {
    $manufacturer = $null
    try {
        $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    } catch {
        $manufacturer = $null
    }
    if ([string]::IsNullOrEmpty($manufacturer)) {
        try {
            $manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
        } catch {
            $manufacturer = $null
        }
    }
    $output = if ([string]::IsNullOrEmpty($manufacturer)) {
        Write-Output "Manufacturer cannot be retrieved."
    } elseif ($manufacturer -like "*asus*" -or $manufacturer -like "*acer*") {
        Write-Output "Computer Manufacturer: $manufacturer"
        Write-Output "BIOS Admin Password: PC Manufacturer Not Supported, Manual Capture Required"
    } else {
        Write-Output "Computer Manufacturer: $manufacturer"
    }
    Add-EntryToFile $output
    $output
}

function Add-EntryToFile {
    param (
        [string]$entry
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp - $entry"
    $computerName = $env:COMPUTERNAME
    $logFilePath = "C:\Temp\$computerName.log"
    $entry | Out-File -FilePath $logFilePath -Append
}

function Run-ScriptWithProgressBar {
    $functions = @(
        "Get-Hostname",
        "Get-SerialNumber",
        "Get-BitLockerEncryptionStatus",
        "Get-TPMStatus",
        "Get-WindowsUpdateStatus",
        "Get-GTBInfo",
        "Get-CortexXDRInfo",
        "Get-GoogleChromeInfo",
        "Get-WorkspaceOneInfo",
        "Get-DeviceClientID",
        "Get-GlobalProtectInfo",
        "Get-ImageVersion",
        "Get-NonCompliantAccounts",
        "Get-MachineType",
        "Get-WiFiAdapterStatus",
        "Get-RawPartition",
        "Get-OSVersion",
        "Get-OperatingSystemInstallDate",
        "Get-ComputerManufacturer",
        "Get-BIOSPasswordStatus"
    )

    $totalFunctions = $functions.Count
    $completedFunctions = 0
    $combinedOutput = ""

    Write-Progress -Activity "Script Progress" -Status "In Progress" -PercentComplete 0

    foreach ($function in $functions) {
        $output = Invoke-Expression $function
        $combinedOutput += $output + "`n"
        $completedFunctions++
        $percentComplete = [math]::Round(($completedFunctions / $totalFunctions) * 100)

        Write-Progress -Activity "Script Progress" -Status "Processing function: $function" -PercentComplete $percentComplete
    }

    $separatorLine = "============================================================"

    "`n$combinedOutput"
    Add-EntryToFile $separatorLine

    Write-Progress -Activity "Script Progress" -Status "Completed" -PercentComplete 100
}

Run-ScriptWithProgressBar
