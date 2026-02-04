#### Enable Advanced Security Audit Policy
`gpedit.msc` → `Computer Configuration` → `Windows Settings` → `Security Settings` → `Advanced Audit Policy Configuration` → `System Audit Policies` - `Local Group Policy Object`

#### Chris Titus Script
```powershell
iwr -useb https://christitus.com/win | iex
```
#### Microsoft Activation Scripts (MAS)
```powershell
irm https://get.activated.win | iex
```
#### Install Tweaks Tool (ITT)
```powershell
irm emadadel4.github.io/itt.ps1 | iex
```
#### Enable Advanced Security Audit Policy
gpedit.msc → Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → System Audit Policies - Local Group Policy Object.

#### CPL (Control Panel) Shortcuts

| **Applet** **Name**      | **File Name** |
| ------------------------ | ------------- |
| Add or Remove Programs   | appwiz.cpl    |
| Date and Time            | timedate.cpl  |
| Device Manager           | hdwwiz.cpl    |
| Display                  | desk.cpl      |
| Firewall                 | firewall.cpl  |
| Mouse                    | main.cpl      |
| Network Connections      | ncpa.cpl      |
| Power                    | powercfg.cpl  |
| Sound                    | mmsys.cpl     |
| System Properties        | sysdm.cpl     |
| Security and Maintenance | wscui.cpl     |
#### Microsoft Management Console (MSC) Shortcuts

| **Applet** **Name**                                    | **File Name** |
| ------------------------------------------------------ | ------------- |
| Opens the Computer Management console                  | compmgmt.msc  |
| Opens the Device Manager                               | devmgmt.msc   |
| Opens Disk Management                                  | diskmgmt.msc  |
| Opens the Event Viewer, which displays system logs     | eventvwr.msc  |
| Opens the Local Group Policy Editor                    | gpedit.msc    |
| Opens the Local Users and Groups manager               | lusrmgr.msc   |
| Opens the Services console                             | services.msc  |
| Opens the Task Scheduler, where you can automate tasks | taskschd.msc  |
gpedit.msc → Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration 

#### Microsoft Management Console MMC Keyboard Shortcuts

| Microsoft Management Console Window                                                                           | Keyboard Shortcuts |
| ------------------------------------------------------------------------------------------------------------- | ------------------ |
| Print the current page or active pane                                                                         | Ctrl+P             |
| Display the window menu for the active console window                                                         | Alt+Minus sign (-) |
| Display the Action shortcut menu for the selected item                                                        | Shift+F10          |
| Open the Help topic, if any, for the selected item                                                            | F1 key             |
| Update the content of all console windows                                                                     | F5 key             |
| Maximize the active console window                                                                            | Ctrl+F10           |
| Restore the active console window                                                                             | Ctrl+F5            |
| Display the Properties dialog box, if any, for the selected item                                              | Alt+Enter          |
| Rename the selected item                                                                                      | F2 key             |
| Close the active console window. When a console has only one console window, this shortcut closes the console | Ctrl+F4            |
#### Command Prompt (CMD)
```powershell
# Query the DNS to obtain domain name or IP address information
nslookup

# Send ICMP echo requests to a specified host to check connectivity
ping

# Log off the current user from the system
logoff

# Shut down the computer
shutdown /s

# Display a list of currently running tasks and their status
tasklist

# Forcefully terminate a process by its name
taskkill /f /im [process name]

# Forcefully terminate a process by its process ID
taskkill /f /pid [process ID]

# Check the file system and fix errors on the specified drive
chkdsk /f

# Scan and repair system files
sfc /scannow

# Format a specified drive with a given file system (e.g., NTFS, FAT32) and perform a quick format
format [drive letter]: /fs:[file system] /q

# Open the Disk Partition tool for managing disks and partitions
diskpart

# Display the current version of the operating system
ver

# Display detailed system information, including hardware and software configuration
systeminfo

# Delete one or more files
del

# Clear the command prompt screen
cls

# Display all IP configuration information for all network interfaces
ipconfig /all

# Flush the DNS resolver cache
ipconfig /flushdns

# Register the DNS names and IP addresses with the DNS server
ipconfig /registerdns

# Release the current DHCP lease for the specified adapter
ipconfig /release

# Renew the DHCP lease for the specified adapter
ipconfig /renew

# Display the contents of the DNS resolver cache
ipconfig /displaydns

# Force a Group Policy update
gpupdate /force

# Display Ethernet statistics
netstat -e

# Display statistics for all protocols
netstat -s

# Display active TCP connections and their associated processes
netstat -fopn tcp

# Stop the print spooler service
net stop spooler

# Start the print spooler service
net start spooler

# Display the MAC address of the network interfaces
getmac 

# Display the current user and their group memberships
whoami /all

# Display the hostname of the computer
hostname

# Manage scheduled tasks
schtasks

# Display the ARP table, which maps IP addresses to MAC addresses
arp -a

# Delete a specific entry from the ARP table
arp -d

# Trace the route taken by packets to a specified IP address or hostname
tracert [IP address or hostname]

# Show saved Wi-Fi profiles on the computer
netsh wlan show profiles

# Show details of a specific Wi-Fi profile, including the security key
netsh wlan show profile name=WiFi_SSID key=clear
```
#### PowerShell Commands
```powershell
# Check TLS version
[Net.ServicePointManager]::SecurityProtocol

# Test the connection to a specified host on port 80 (HTTP)
Test-Connection <host> -Port 80

# Retrieve a list of installed hotfixes on the system
Get-Hotfix

# Create a new item (file or directory) at the specified path
New-Item / ni

# Remove an item (file or directory) at the specified path
Remove-Item / del, erase, rmdir

# Copy an item (file or directory) from one location to another
Copy-Item / copy, cp

# Move an item (file or directory) from one location to another
Move-Item / move, mv

# Rename an item (file or directory) to a new name
Rename-Item / ren

# Get a list of services on the system
Get-Service / gsv

# Start a specified service
Start-Service / sasv

# Stop a specified service
Stop-Service / spsv

# Restart a specified service
Restart-Service

# Get a list of running processes on the system
Get-Process / ps

# Start a new process (application) with specified parameters
Start-Process / start

# Stop a running process by its ID or name
Stop-Process / kill

# Get a list of local user accounts on the system
Get-LocalUser / glu

# Create a new local user account
New-LocalUser / nlu

# Remove a local user account
Remove-LocalUser / rlu

# Resolve a DNS name to its corresponding IP address
Resolve-DnsName
```
#### PowerShell Security Fundamentals
Execution Policies
```powershell
# View Current Execution Policy: 
Get-ExecutionPolicy

# Set Execution Policy (RemoteSigned - common, but understand the risks):
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

|> Note: Avoid Unrestricted production.

# Understand Scope:
# ● CurrentUser, LocalMachine, Process, MachinePolicy, UserPolicy.
# ● Scopes define where the policy applies.
```
Constrained Language Mode
```powershell
# Enter Constrained Language Mode (demonstration):
powershell -CL

# Check Language Mode:
$ExecutionContext.SessionState.LanguageMode
# Results: FullLanguage, ConstrainedLanguage.
```
Script Signing
```powershell
# Create a Self-Signed Certificate (for testing):
New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -DnsName "MyScriptSignCert"

# Sign a Script:
Set-AuthenticodeSignature -FilePath "MyScript.ps1" -Certificate (Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*MyScriptSignCert*"})

# Verify a Signature:
Get-AuthenticodeSignature -FilePath "MyScript.ps1"

# Trust a Certificate (for testing, not production):
Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*MyScriptSignCert*"} | Move-Item -Destination Cert:\CurrentUser\TrustedPublisher
```
PowerShell Remoting Security
```powershell
# Enable PowerShell Remoting (with caution):
Enable-PSRemoting -Force

# Configure Trusted Hosts (for testing, not production):
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "RemoteComputer" -Force

# Just Enough Administration (JEA) (concept):
# ● JEA restricts what users can do in a remoting session. 
# ● Requires configuration files and role capabilities.
```
Safe Environment Setup
```powershell
# Virtual Machines:
# ● Use Hyper-V, VirtualBox, or VMware for secure testing.

# PowerShell Logging (enable): (Requires registry changes or Group Policy)
# ● Script Block Logging: Logs the content of executed scripts. 
# ● Module Logging: Logs the use of PowerShell modules.

# Event Log Monitoring:
Get-WinEvent -LogName Security
```
#### PowerShell System Information Gathering & Analysis
Basic System Information
```powershell
# Get Computer Information:
Get-ComputerInfo

# Get Operating System Information:
Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
```
Hardware Information
```powershell
# Get CPU Information:
Get-WmiObject Win32_Processor | Select-Object Name, NumberOfCores, MaxClockSpeed

# Get Memory Information:
Get-WmiObject Win32_PhysicalMemory | Select-Object Manufacturer, Capacity, Speed

# Get Disk Information:
Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle
```
Software Information
```powershell
# Get Installed Software:
Get-WmiObject Win32_Product | Select-Object Name, Version

# Alternative Command:
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion

# Get Installed Hotfixes:
Get-HotFix
```
Process and Service Information
```powershell
# Get Running Processes:
Get-Process | Select-Object Name, Id, CPU, WorkingSet

# Get Services:
Get-Service | Select-Object Name, Status, StartType
```
Registry Analysis
```powershell
# Get Registry Key Value:
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "ProgramFilesDir"

# Get Registry Key Contents:
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```
Network Information
```powershell
# Get IP Configuration:
Get-NetIPConfiguration

# Get Network Adapters:
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status
```
#### User and Access Management
Local User Management
```powershell
# List Local Users
Get-LocalUser

# Create a New Local User
$SecurePassword = ConvertTo-SecureString "Password123!" -AsPlainText -Force New-LocalUser -Name "NewUser" -Password $SecurePassword -Description "Test User"

# Disable a Local User
Disable-LocalUser -Name "NewUser"

# Enable a Local User
Enable-LocalUser -Name "NewUser"

# Remove a Local User
Remove-LocalUser -Name "NewUser"

# Modify User Properties
Set-LocalUser -Name "NewUser" -Description "Updated Description"

# Check User Status
Get-LocalUser -Name "NewUser" | Select-Object Enabled, AccountExpires, PasswordLastSet

# Unlock a Locked Account
Get-LocalUser -Name "LockedUser" | Unlock-LocalUser
```
Local Group Management
```powershell
# List Local Groups
Get-LocalGroup

# Add a User to a Local Group
Add-LocalGroupMember -Group "Administrators" -Member "NewUser"

# Remove a User from a Local Group
Remove-LocalGroupMember -Group "Administrators" -Member "NewUser"

# List Group Members
Get-LocalGroupMember -Group "Administrators"

# Create a New Local Group
New-LocalGroup -Name "MyGroup" -Description "Custom Group"

# Remove a Local Group
Remove-LocalGroup -Name "MyGroup"

# Rename a Local Group
Rename-LocalGroup -Name "OldGroupName" -NewName "NewGroupName"
```
Active Directory User and Group Management (If applicable)
```powershell
# Get AD User
Get-ADUser -Identity "UserName"

# Get AD Group
Get-ADGroup -Identity "GroupName"

# Add AD User to Group
Add-ADGroupMember -Identity "GroupName" -Members "UserName"

# Remove AD User from Group
Remove-ADGroupMember -Identity "GroupName" -Members "UserName"

# Check Account Lockout Status (Active Directory)
Get-ADUser -Identity "UserName" -Properties LockedOut

# Unlock an Active Directory Account
Unlock-ADAccount -Identity "UserName"
```
Access Control and Permissions
```powershell
# Get File/Folder ACL
Get-Acl -Path "C:\MyFolder"

# Check Effective Access
Get-EffectiveAccess -Path "C:\MyFolder" -Account "UserName"
```
#### Event Log Analysis & Auditing
Retrieving Event Logs
```powershell
# Get Events from a Specific Log (e.g., Security):
Get-WinEvent -LogName Security

# Get Events with Specific Event IDs:
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4625]]"

# Get Events from a Specific Time Range:
$startTime = (Get-Date).AddDays(-1)
Get-WinEvent -LogName Security -StartTime $startTime

# Get the Last N Events:
Get-WinEvent -LogName System -MaxEvents 100

# List All Available Logs:
Get-WinEvent -ListLog *
```
Filtering Event Logs
```powershell
# Filter by Message Content:
Get-WinEvent -LogName Security | Where-Object {$_.Message -like "*failed logon*"}

# Filter by User Name:
Get-WinEvent -LogName Security | Where-Object {$_.Properties | Where-Object {$_.Name -eq "TargetUserName" -and $_.Value -eq "UserName"}}

# Filter by Computer Name:
Get-WinEvent -LogName System | Where-Object {$_.MachineName -eq "ComputerName"}
```
Formatting and Exporting Event Logs
```powershell
# Format Output as a List:
Get-WinEvent -LogName Security -MaxEvents 5 | Format-List *

# Select Specific Properties:
Get-WinEvent -LogName Security -MaxEvents 5 | Select-Object TimeCreated, ID, Message

# Export to CSV:
Get-WinEvent -LogName System -MaxEvents 100 | Export-Csv -Path "C:\Logs\SystemEvents.csv" -NoTypeInformation

# Export to XML:
Get-WinEvent -LogName Security -MaxEvents 100 | Export-Clixml -Path "C:\Logs\SecurityEvents.xml"
```
Clearing Event Logs (Use with Caution)
```powershell
# Clear Event Log:
Clear-EventLog -LogName Security -Confirm:$false
```
Retrieving Event Log Properties
```powershell
# Get Log Properties:
Get-WinEvent -ListLog Security | Format-List *

# Get Log Maximum Size:
(Get-WinEvent -ListLog Security).MaximumSizeInBytes
```
Audit Policy (Using auditpol)
```powershell
# Get Current Audit Policy:
auditpol /get /category:*

# Set Audit Policy:
### Account Logon
auditpol /set /subcategory:"Credential Validation" /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /failure:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable

### Account Management
auditpol /set /subcategory:"Application Group Management" /success:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

### Detailed Tracking
auditpol /set /subcategory:"PNP Activity" /success:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable

### DS Access
auditpol /set /subcategory:"Directory Service Access" /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable

### Logon/Logoff
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"Group Membership" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable

### Object Access
auditpol /set /subcategory:"Detailed File Share" /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

### Policy Change
auditpol /set /subcategory:"Audit Policy Change" /success:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Other Policy Change Events" /failure:enable

### Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

### System
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
```
PowerShell Logging (Requires Registry/Group Policy)
```powershell
# Check Script Block Logging Status:
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging
```
#### File and Disk Security
File Permissions (ACLs)
```powershell
# Get File/Folder ACL:
Get-Acl -Path "C:\MyFolder"

# Modify File/Folder ACL (Example: Adding a User):
$acl = Get-Acl -Path "C:\MyFolder" $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain\UserName", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow") $acl.AddAccessRule($rule) Set-Acl -Path "C:\MyFolder" -AclObject $acl

# Remove Specific User Permissions:
$acl = Get-Acl -Path "C:\MyFolder" $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain\UserName", "FullControl", "ContainerInherit, ObjectInherit", "None", "Deny") $acl.RemoveAccessRule($rule) Set-Acl -Path "C:\MyFolder" -AclObject $acl
```
File Integrity (Hashes)
```powershell
# Get File Hash (SHA256):
Get-FileHash -Path "C:\MyFile.exe" -Algorithm SHA256

# Get File Hash (MD5):
Get-FileHash -Path "C:\MyFile.exe" -Algorithm MD5

# Compare File Hashes:
$hash1 = Get-FileHash -Path "C:\File1.exe" -Algorithm SHA256 
$hash2 = Get-FileHash -Path "C:\File2.exe" -Algorithm SHA256
if ($hash1.Hash -eq $hash2.Hash) { Write-Host "Hashes match." } else { Write-Host "Hashes do not match." }
```
Disk Management
```powershell
# Get Disk Information:
Get-Disk

# Get Partition Information:
Get-Partition -DiskNumber 0

# Get BitLocker Volume Status:
Get-BitLockerVolume

# Enable BitLocker (Example - TPM Protector):
Enable-BitLocker -DriveLetter C: -TPMProtector

# Disable BitLocker:
Disable-BitLocker -DriveLetter C:

# Get Volume Information:
Get-Volume
```
File System Navigation
```powershell
# Get Current Directory:
Get-Location

# Change Directory:
Set-Location -Path "C:\MyFolder"

# List Files and Folders:
Get-ChildItem -Path "C:\MyFolder"

# Create a New Folder:
New-Item -Path "C:\NewFolder" -ItemType Directory

# Remove a File or Folder:
Remove-Item -Path "C:\MyFile.txt"
```
#### Malware & Process Monitoring
Process Management
```powershell
# List Running Processes:
Get-Process

# List Processes with Specific Name:
Get-Process -Name "notepad"

# List Processes with Specific ID:
Get-Process -Id 1234

# Stop a Process by Name:
Stop-Process -Name "notepad" -Force

# Stop a Process by ID:
Stop-Process -Id 1234 -Force

# Get Process Information (Detailed):
Get-Process -Name "notepad" | Format-List *

# Get Processes Using High CPU/Memory:
Get-Process | Where-Object {$_.CPU -gt 50} | Sort-Object CPU -Descending
Get-Process | Where-Object {$_.WorkingSet64 -gt 1GB} | Sort-Object WorkingSet64 -Descending

# Get Process Owner:
Get-WmiObject Win32_Process -Filter "Name='notepad.exe'" | Select-Object Name, GetOwner()
```
Scheduled Tasks
```powershell
# List Scheduled Tasks:
Get-ScheduledTask

# List Tasks with Specific Name:
Get-ScheduledTask | Where-Object {$_.TaskName -like "*malware*"}

# Disable a Scheduled Task:
Disable-ScheduledTask -TaskName "MaliciousTask"

# Enable a Scheduled Task:
Enable-ScheduledTask -TaskName "MaliciousTask"

# Get Scheduled Task Information (Detailed):
Get-ScheduledTask -TaskName "MaliciousTask" | Format-List *
```
Services
```powershell
# List Services:
Get-Service

# List Services with Specific Name:
Get-Service -Name "Spooler"

# Start a Service:
Start-Service -Name "Spooler"

# Stop a Service:
Stop-Service -Name "Spooler"

# Get Service Information (Detailed):
Get-Service -Name "Spooler" | Format-List *

# Get Services with Specific Start Type:
Get-Service | Where-Object {$_.StartType -eq "Automatic"}
```
Network Connections (Related to Processes)
```powershell
# Get Network Connections (TCP):
Get-NetTCPConnection

# Get Network Connections (UDP):
Get-NetUDPEndpoint

# Find Process Using a Port:
Get-Process -Id (Get-NetTCPConnection -LocalPort 8080).OwningProcess
```
#### Group Policy Object (GPO) Editor Examples

| Policy Name                       | Description                                               | GPO Path                                                                                                               | Action/Configuration                                                                      | Notes                                                                  |
| --------------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **Disable USB Storage**           | Prevent the use of external drives and disks              | `Computer Configuration > Administrative Templates > System > Removable Storage Access`                                | Enable **All Removable Storage classes: Deny all access**                                 |                                                                        |
| **Password Policy**               | Enforce strong password complexity and history            | `Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy`        | Enable **Minimum password length**, **Complexity requirements**, and **Password history** |                                                                        |
| **Account Lockout Policy**        | Block brute-force password guessing attempts              | `Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Account Lockout Policy` | Configure **Account lockout threshold** (e.g., lock after 5 failed attempts)              |                                                                        |
| **Firewall Settings**             | Enable and customize Windows Defender Firewall rules      | `Computer Configuration > Administrative Templates > Network > Network Connections > Windows Defender Firewall`        | Enable firewall and define inbound/outbound rules                                         |                                                                        |
| **Disable Control Panel**         | Restrict user access to Control Panel and system settings | `User Configuration > Administrative Templates > Control Panel`                                                        | Enable **Prohibit access to Control Panel and PC settings**                               |                                                                        |
| **Prevent Command Prompt**        | Block users from accessing the command prompt             | `User Configuration > Administrative Templates > System`                                                               | Enable **Prevent access to the command prompt**                                           |                                                                        |
| **Prevent Registry Access**       | Restrict access to Registry editing tools                 | `User Configuration > Administrative Templates > System`                                                               | Enable **Prevent access to registry editing tools**                                       |                                                                        |
| **Disable Task Manager**          | Prevent users from opening Task Manager                   | `User Configuration > Administrative Templates > System > Ctrl+Alt+Del Options`                                        | Enable **Remove Task Manager**                                                            |                                                                        |
| **Set Desktop Wallpaper**         | Apply a uniform desktop wallpaper across devices          | `User Configuration > Administrative Templates > Desktop > Desktop`                                                    | Enable **Desktop Wallpaper** and specify the image path                                   |                                                                        |
| **Windows Update**                | Configure automatic updates and schedules                 | `Computer Configuration > Administrative Templates > Windows Components > Windows Update`                              | Enable **Configure Automatic Updates** and set update frequency                           |                                                                        |
| **Disable Windows Store**         | Block installation of apps from Microsoft Store           | `Computer Configuration > Administrative Templates > Windows Components > Store`                                       | Enable **Turn off the Store application**                                                 |                                                                        |
| **Disable Software Installation** | Prevent users from installing software                    | `User Configuration > Administrative Templates > Windows Components > Windows Installer`                               | Enable **Disable Windows Installer**                                                      |                                                                        |
| **Redirect My Documents**         | Redirect user documents to a network server               | `User Configuration > Windows Settings > Folder Redirection > Documents`                                               | Configure target folder path for redirection                                              | Useful for centralized backups.                                        |
| **Redirect Desktop**              | Store desktop files on a network server                   | `User Configuration > Windows Settings > Folder Redirection > Desktop`                                                 | Configure target folder path for redirection                                              |                                                                        |
| **Logoff Inactive Users**         | Automatically log off users after inactivity              | `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`                    | Configure inactivity timeout (often via scripts or policies)                              | Requires defining a suitable timeout (e.g., using PowerShell scripts). |
