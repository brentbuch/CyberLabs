# SOC Analyst Lab
This lab is meant to simulate a SOC environment. It utilizes two small virtual machines and LimaCharlie’s SecOps Cloud Platform.
## Languages Used
- 
## Environments Used
- Proxmox VE (8.0.3)
- Windows 
- Ubuntu Server (22.04)
## I. Setup Virtual Environment
1. Setup your virtual environment. I prefer Proxmox, but you can also use VMWare, VirtualBox, etc.
2. Create Windows 10 VM. 
- Download iso from [here](https://www.microsoft.com/en-us/software-download/windows10ISO)
- VM hardware allocation: 2 CPU cores, 4GB RAM, and 30GB storage
3. Create Ubuntu Server VM
- Download iso [here](https://ubuntu.com/download/server)
- VM hardware allocation: 2 CPU cores, 2GB RAM, 16GB storage
- Start the machine and go through the setup process. Choosing defaults unless noted below
- At the network setup, set a static IP

<img width="880" alt="UbuntuNetwork" src="https://github.com/brentbuch/CyberLabs/assets/142106637/572b5c4b-5d3f-4f63-9a58-f5c31da83fa1">
- When asked to install ssh server select yes
- Choose username, password, server name, etc...
 
## II. Configure the Windows VM

1. Boot the VM and go through OOBE

2. Make it vulnerable
#### Disable Tamper Protection
1. Disable Tamper Protection
2. Click the “Start” menu icon
3. Click “Settings”
4. Click “Privacy & security” on the left
5. Click “Windows Security”
6. Click “Virus & threat protection”
7. Under “Virus & threat protection  settings” click “Manage settings”
8. Toggle OFF the “Tamper Protection” switch. When prompted, click “Yes”
9. Toggle off all other settings here and close the windows

<img width="616" alt="Tamper" src="https://github.com/brentbuch/CyberLabs/assets/142106637/d11ddaae-7699-4d6d-a986-76c896658a77">

 #### Permanently turn off Windows Defender via Group Policy

1. Run Group Policy editor as admin (gpedit.msc)
2. Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus
3. Double-click “Turn off Microsoft Defender Antivirus”
4. Select Enabled and Apply

#### Disable defender via Registry
1. Open cmd prompt as admin
2. Run the following code:
```bash
REG ADD "hklm\software\policies\microsoft\windows defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
```
#### Boot into safe mode to disable all Defender Services
1. Open msconfig
2. Click boot tab
3. Select reboot and minimum and then OK
4. Once in safe mode open regedit
5. Navigate to the locations below and change the value of 'Start' to 4 for each one:
```
Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense

Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot

Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend

Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv

Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc

Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter
```
6. Leave safe mode by opening msconfig and changing the boot settings back to normal. Windows Defender should now be disabled.


#### Prevent VM from going into Standby Mode
1. Run the following commands from administrative cmd prompt:
```bash
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0
powercfg /change monitor-timeout-ac 0
powercfg /change monitor-timeout-dc 0
powercfg /change hibernate-timeout-ac 0
powercfg /change hibernate-timeout-dc 0
```
### Install Sysmon on Windows
<b>Sysmon makes parsing Windows Event Logs much easier. </b>

1. Open Admin Powershell prompt
2. Download Sysmon
```powershell
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Windows\Temp\Sysmon.zip
 ```
3. Unzip Sysmon
```powershell
Expand-Archive -LiteralPath C:\Windows\Temp\Sysmon.zip -DestinationPath C:\Windows\Temp\Sysmon
```
4. Download [SwiftOnSecuritys](https://infosec.exchange/@SwiftOnSecurity) Sysmon configuration
```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Windows\Temp\Sysmon\sysmonconfig.xml
```
5. Install Sysmon with the configuration
```powershell
C:\Windows\Temp\Sysmon\Sysmon64.exe -accepteula -i C:\Windows\Temp\Sysmon\sysmonconfig.xml
```
<img width="641" alt="sysmon1" src="https://github.com/brentbuch/CyberLabs/assets/142106637/32c64843-509e-404a-8d20-c37361b8150b">

6. Check that Sysmon64 service is running
```powershell
Get-Service sysmon64
```
7. Verify presence of Sysmon logs
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```
<img width="637" alt="sysmon2" src="https://github.com/brentbuch/CyberLabs/assets/142106637/ff5c039f-bf58-43a3-a8e1-e34dced03651">

## III. Install and Configure LimaCharlie on Windows VM
LimaCharlie is a cloud SecOps platform. They have a cross-platform EDR agent, log consolidation, and threat detection. There is a free tier available for up to 2 sensors that we can take advantage of.

Create an account on [LimaCharlie.io](https://limacharlie.io/)

1. Once logged in create an organization with the settings shown below and continue
<img width="776" alt="LimaOrg" src="https://github.com/brentbuch/CyberLabs/assets/142106637/b3b59df4-37bc-406b-9e56-e615b836ffc4">
    
2. Click 'Add Sensor' and select Windows for the endpoint type. Add a description like 'WindowsVM-Vulnerable' and create
3. Navigate to Sensors > Installation Keys and copy the 'Sensor Key'(#1) and the installation command(#2) as seen in the screenshot below. 
<img width="1258" alt="InstallationKey" src="https://github.com/brentbuch/CyberLabs/assets/142106637/71b24796-a2f9-4472-abf1-dab59483639e">
4. In the Windows VM open powershell as admin and run the two commands below:

```powershell
cd C:\Users\User\Downloads
```
```powershell
Invoke-WebRequest -Uri https://downloads.limacharlie.io/sensor/windows/64 -Outfile C:\Users\User\Downloads\lc_sensor.exe
```
5. Move to a standard command prompt by running:

```powershell
cmd.exe
```
6. Using the command and Installation key that we copied earlier, run the command:

```bash
lc_sensor.exe -i INSERT_YOUR_INSTALLATION_KEY
```
If successfull you should see this message. The "Error" is a bug and can be ignored.

<img width="591" alt="LimaSuccess" src="https://github.com/brentbuch/CyberLabs/assets/142106637/5f3a6729-65e5-4af3-b7f4-b0f70c58bc97">

And you should now see the desktop reporting under 'Sensors' inside LimaCharlie
<img width="988" alt="LimaSuccess2" src="https://github.com/brentbuch/CyberLabs/assets/142106637/f15bb0e1-b135-4878-b546-fea0f6b42ebc">

### Configuer LimaCharlie to collect Sysmon Logs
<b>This allows LimaCharlie to send Event Logs to be sent alongside it's own EDR data.</b>

1. In the LimaCharlie dashboard, select Artifacts on the sidebar, and then click 'Add Artifact Collection Rule'

<img width="1043" alt="Artifacts" src="https://github.com/brentbuch/CyberLabs/assets/142106637/6a47592b-e2a7-483d-a37b-7afac8ce21d2">

2. Add the following to the Rule and then save. 
    

```
Name: windows-sysmon-logs
Platforms: Windows
Path Pattern: wel://Microsoft-Windows-Sysmon/Operational:*
Retention Period: 10
```

<img width="775" alt="ArtifactRule" src="https://github.com/brentbuch/CyberLabs/assets/142106637/b81f2b80-7e7a-4f5b-974f-c8609740f6ba">

LimaCharlie will now collect Sysmon logs as well as its own EDR info. 

Now is a good time to snapshot or backup the Windows VM before we start attacking. If something breaks you'll have a clean machine to spin up. 

## IV. Setup the Attack Box

1. 
