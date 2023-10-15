# Nessus Vulnerability Management Lab

The purpose of this lab is to get familiar with vulnerability scanning and remediation. It utilizes Nessus Essentials, a free version of the powerful scanning tool that is a standard across the industry. The lab demonstrates the difference between credentialed and uncredentialed scans, and the importance of the former. It also demonstrates how vulnerabilites can be remediated.

## Envioronments and Tools used

- Windows 10
- Nessus

## Pre Lab Setup

1. Create a Windows 10 VM. During setup, create an admin account with a password that can easily be remembered.
2. Download and install Nessus Essentials. Create an account [here](https://www.tenable.com/products/nessus/nessus-essentials). You will receive an email with the activation code for Nessus Essentials.
3. Get the IP address from the VM using ipconfig and verify the VM is pingable from the local machine. May need to adjust the Windows firewall on the VM.

## Initial Nessus Scan

1. Login to Nessus. Select New Scan, and then select basic network scan. 
<img width="1149" alt="Nessus1" src="https://github.com/brentbuch/CyberLabs/assets/142106637/197ece2b-bb41-4ca1-8ff2-648959ee5263">

2. On the next screen, give the scan a name and description of your choosing. In the 'Targets' section, paste the IP address of the Windows 10 VM, and then save. 
<img width="1083" alt="NessusInitial" src="https://github.com/brentbuch/CyberLabs/assets/142106637/419d87a5-d1d8-4ac6-a2ad-7d3b66ee3cb2">

3. On the next screen, you can see the scan that we just created. The scan is not yet running, so we need to click on launch. 
<img width="1088" alt="NessusLaunch" src="https://github.com/brentbuch/CyberLabs/assets/142106637/536a36b3-98ce-445a-a887-4968a65d328a">

4. When finished, the scan will show as completed. Click on the scan to see the results. This initial scan was not using any credentials, so few vulnerabilities were found. I only had one 'medium' vulnerability found.
<img width="1087" alt="uncScanResults" src="https://github.com/brentbuch/CyberLabs/assets/142106637/7c820cd1-57c1-4d37-9482-ab070e75359d">

5. Clicking on any of these will provide further info about the specific vulnerability.
<img width="1089" alt="smbvuln" src="https://github.com/brentbuch/CyberLabs/assets/142106637/777e7583-f56e-4713-8ebf-325b3174a927">

## Configuring for Credentialed Scans
The initial scan did not provide much information to work with. We can run a credentialed scan, which will allow us to see much more in depth information about the machine, but we will need to configure the VM to allow for this. I am using the documentation provided by teneble [here](https://docs.tenable.com/nessus/Content/CredentialedChecksOnWindows.htm).

1. On the VM, open services.msc and find the 'Remote Registry' service. Change the service from 'Disabled' to 'Automatic' and then run the service. This allows Nessus to connect to the registry remotely and scan for any vulnerable keys, etc...
<img width="1133" alt="remoteregistry" src="https://github.com/brentbuch/CyberLabs/assets/142106637/abfe18c0-ab3a-4db7-ac41-020f2c1a576f">

2. Verify that 'file and printer sharing' is turned on. Mine was on by default, but if not, enable it now. 
<img width="928" alt="fileshare" src="https://github.com/brentbuch/CyberLabs/assets/142106637/00897809-9ee1-4fe7-b60a-4e0715d1c5e7">

3. Because the computer is not on a domain, we need to disable Windows UAC. This is not recommended for normal use, but is a workaround in this case. 
<img width="829" alt="winUAC" src="https://github.com/brentbuch/CyberLabs/assets/142106637/a6e0c362-8707-4a41-ad0a-f7c7c6cff5b5">

4. Next we will need to go into the registry and make a modification to also help get around UAC. In regedit, navigate to:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\
```

5. Right click in the window on the right, and select 'NEW> DWORD (32 bit value).'
Enter the name 'LocalAccountTokenFilterPolicy' for this new value. Right click the value and select modify. For Value data, enter 1 and click ok. Exit regedit and then reboot the VM. 
<img width="992" alt="RegEdit" src="https://github.com/brentbuch/CyberLabs/assets/142106637/a475fd63-cbb9-4335-aaa0-39e9a6d22885">

## Setup and run credential scan in Nessus

1. Back in Nessus, under 'My Scans,' select the checkbox next to the original scan we created. At the top of the screen there is a dropdown box that says more. Click on this and select 'Configure.' On the configuration page, select the "Credentials" tab. Select "Windows." Authentication method should be set to 'Password' and the admin account and password we created when setting up the VM can be entered here. Click 'Save' when finished.
 <img width="1075" alt="NessusCredentials" src="https://github.com/brentbuch/CyberLabs/assets/142106637/76a50760-47ee-4ece-9c08-37b5fadcd2ea">

 2. Back in the scans folder, launch the updated scan. This may take even longer than the first scan, so grab some coffee. Once the scan finishes, go ahead and click on it to see the results. This time there are some critical vulnerabilites that have been found, including a new vulnerability in curl. 
 <img width="1081" alt="credScan1" src="https://github.com/brentbuch/CyberLabs/assets/142106637/409d3011-da95-480a-8dbe-bb507ee2ef8b">
 <img width="1087" alt="curlvuln" src="https://github.com/brentbuch/CyberLabs/assets/142106637/4f610422-0c73-40aa-b7ba-6fbe5765af9d">

3. Next, I'm going to install a deprecated version of Firefox and run the scan again. This old version should provide many more vulnerabilities to observer and remediate. Old versions of Firefox can be found [here.](https://ftp.mozilla.org/pub/firefox/releases/) I chose version 3.5.10, but any version should do. Once installed to the VM, go ahead and run the Nessus scan again. 

4. Checking the results of this scan, we see that there are now a ton of Critical vulnerabilities detected. 
<img width="1082" alt="credScan2" src="https://github.com/brentbuch/CyberLabs/assets/142106637/9f29390b-652f-40db-9b4c-36272b7de027">

5. The Remediations tab shows the suggested steps to take to take care of the detected vulnerabilites. It looks like we need to update Firefox, run Windows updates, and update curl. 
<img width="1087" alt="remediations" src="https://github.com/brentbuch/CyberLabs/assets/142106637/4eb5386e-9900-44f2-acfc-41f13e383601">

## Remediating detected vulnerabilities

1. First started with running Windows updates until no new updates were found. If we check installed updates, we can see KB5031356 that was suggested by Nessus is now installed.
<img width="938" alt="installedupdates" src="https://github.com/brentbuch/CyberLabs/assets/142106637/837ded66-0834-4387-b4c2-c4952776e60a">

2. Next, we can update Firefox to the latest version. Because version 3.5.10 is so old, it cannot connect to the update servers. We need to uninstall that version, and then install the latest version from the Mozilla website.
<img width="770" alt="firefox" src="https://github.com/brentbuch/CyberLabs/assets/142106637/b924c2a9-34ed-4e62-b62f-776ca31f55e9">

3. After some research on how to update curl, it seems that since curl is integrated into Windows, updating it outside of official Windows updates can actually break Windows. As of this time, Microsoft has not yet released an update to address the vulnerability. It is likely that this will be covered by a future Windows update. 

4. Now we can run another Nessus scan to see the effects of our remediations. Once the scan completes, we check the results and see far fewer vulnerabilities present. 
<img width="1083" alt="credScan3After" src="https://github.com/brentbuch/CyberLabs/assets/142106637/0a582919-a23c-49b6-8ce5-3e9888f8380a">
