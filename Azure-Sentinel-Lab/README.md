# Microsoft Sentinel SIEM Lab

This lab is meant to familiarize with Azure and Azure Sentinel. The lab is based off of the original project by [Josh Madakor](https://www.youtube.com/@JoshMadakor), although Azure has changed since the original video was uploaded, so after some additional research, this readme is updated as of September 2023.  We will be setting up an instance of Microsoft Sentinel as well as a honeypot VM exposed to the internet. Logs will be parsed and ingested to Azure Log Analytics Workspace via a PowerShell script. The goal is to monitor incoming activity to the honeypot and plot the threats on a world map based on originating location. I expand upon the original project by then setting a custom alert that detects brute force attacks and creates incidents inside Sentinel grouped by originating IP address.

## Environments and Tools Used

- Azure VM
- Azure Log Analytics Workspaces
- Microsoft Sentinel (SIEM)
- Powershell
- Kusto Query Language (KQL)

## I. Create Honeypot VM

1. In Azure portal, search for virtual machines and create a new VM. Default settings are mostly fine. It is recommended to create a new resource group to add all resources for this lab. This will make it easier to manage the resources later. High availability and security options are not needed. Select Windows 10 VM. For size, the default machine should be fine. Create a username and password that will be used to login to the VM later. Once complete click next.
<img width="936" alt="createvm1" src="https://github.com/brentbuch/CyberLabs/assets/142106637/1d8e0199-09a2-49a6-8446-a342223f3258">
<img width="1105" alt="createvm2" src="https://github.com/brentbuch/CyberLabs/assets/142106637/1399722e-f61d-4f2a-96ff-1b469ab9999f">

2. On the disks options page, the defaults are fine, so click next.
3. On the networking page, under NIC network security group, select 'advanced'. Click 'Create new'
<img width="896" alt="createvmnetwork" src="https://github.com/brentbuch/CyberLabs/assets/142106637/13e77435-bc26-433e-9d4c-8edfe2cedcb3">
On the next page, remove the default rule that is in place and add an inbound rule. Under 'Destination port ranges' add '*'
Set 'Priority' to 100. Create a name and click 'Add'. On next page click 'OK'. Back on the networking page select ' Delete public IP and NIC when VM is deleted' and then click 'Review+Create' and then 'Create' to create to the VM.

## II. Create Log Analytics Workspace

1. In the search bar, type 'Log Analytics Workspace' and open.
2. Click 'Create Log Analytics Workspace'. On the next screen, add the resource group we created before, and give a name.
3. Click 'Review+Create' and then 'Create'
4. While that is creating, search for 'Microsoft Defender for Cloud' and open. On the overview page, scroll down and click 'Enable Defender Plans'
<img width="1257" alt="enabledef1" src="https://github.com/brentbuch/CyberLabs/assets/142106637/e0fde0f8-a527-49ef-9737-3e30860ce9e4">

5. On the next page, click on the Log Analytics Workspace that was created.
<img width="1031" alt="enabledef2" src="https://github.com/brentbuch/CyberLabs/assets/142106637/6183e9b5-cac5-42d0-bd4b-59761ff95890">

6. On the next page, set the sliders for 'Foundational CSPM' and 'Servers' to "ON." You can leave 'SQL Servers' off. Click 'Save'
<img width="1260" alt="enabledef4" src="https://github.com/brentbuch/CyberLabs/assets/142106637/c54f17f9-0bfd-49c3-96ee-a3cbafab3460">

7. On the left menu, go to 'Environmental Settings.' Scroll down and then click on your Azure subscription.
<img width="1259" alt="enabledef5" src="https://github.com/brentbuch/CyberLabs/assets/142106637/71909e3a-1cac-4d09-8b59-a608405efa85">

8. On the next page, on the plan for servers, click on 'Settings' under the 'Monitoring Coverage' column.
<img width="1249" alt="enabledef6" src="https://github.com/brentbuch/CyberLabs/assets/142106637/babd816f-cb95-477f-9518-25a7d5671158">

9. On this page, click 'Edit Configuration' under the Configuration column for the 'Log Analytics agent/Azure Monitor agent' component.
<img width="1272" alt="enabledef7" src="https://github.com/brentbuch/CyberLabs/assets/142106637/8858a4bd-7e32-405c-b7e8-fd273162bf11">

10. On the window that pops up, under 'Security events storage,' select All Events from the drop down, and then click apply. Select "Custom Workspace" and select our LAW. Click "Continue", and then "Save"
<img width="579" alt="enabledef8" src="https://github.com/brentbuch/CyberLabs/assets/142106637/c1b6b68b-421a-4f4f-a90b-866d1440b138">

11. Search for 'Log Analytics Workspaces' and open. Click on your workspace you created. On the next page, scroll down to 'Virtual Machines' and click on the honeypot VM. On the next page, click 'Connect'
<img width="1249" alt="enabledef9" src="https://github.com/brentbuch/CyberLabs/assets/142106637/bfce7bb7-1e78-4d57-9cc8-19af37d200f2">

12. Search for and open Microsoft Sentinel. Click 'Create Microsoft Sentinel.' On the next page, select the log analytics workspace we created, and then 'Add'

## III. Honeypot Configuration

1. In Azure Portal, search for Virtual Machines and open. Click on the honeypot VM and copy the public IP address. We will login with Remote Desktop
<img width="1275" alt="publicip" src="https://github.com/brentbuch/CyberLabs/assets/142106637/e6cb5053-c3dd-496b-931e-c8aabf5b5383">

2. Open Remote Desktop, and login to the honeypot using the username and password we created before. Run through the Windows setup until the desktop loads.

3. Open another instance of Remote Desktop, and attempt to connect to the honeypot, this time using an incorrect username and password. The login will fail.

4. Inside the honeypot, open Event Viewer and go to Windows Logs > Security. Here you should be able to see our failed login attempt, with an Event ID of 4625.
<img width="1102" alt="eventfail" src="https://github.com/brentbuch/CyberLabs/assets/142106637/a4cab204-e9ee-4b31-a806-d2383e7cb8e2">

5. Next we can configure the Windows Firewall inside our honeypot to respond to ICMP (Ping) requests. This will allow outsiders to find the honeypot faster.

- Search for Windows Firewall, and click to open it.
- Click Advanced Settings on the left.
- From the left pane of the resulting window, click Inbound Rules.
- In the right pane, find the rules titled File - and Printer Sharing (Echo Request - ICMPv4-In).
- Right-click each rule and choose Enable Rule.
- Double click each rule, and under the 'Advanced' tab, select Public, Domain, and Private for both rules.
- You now should be able to ping the IP address of the honeypot.
<img width="1045" alt="firewall" src="https://github.com/brentbuch/CyberLabs/assets/142106637/f5d74ddf-cc44-4a46-81ff-f2f84c379f3c">


6. Now we will handle the export of the logs from the Windows VM. I used a powershell script from [Josh Madakor](https://www.youtube.com/@JoshMadakor) who's work was the basis for this lab. The 'Custom Security Log Exporter' script can be found [here](https://github.com/joshmadakor1/Sentinel-Lab). Copy the contents of the script and paste it into a new entry in PowerShell ISE inside the Windows VM. Save this file as 'LogExporter.ps1' on the desktop of the VM.

7. At the top of the script, you will see some info about an API key.
<img width="629" alt="apikey" src="https://github.com/brentbuch/CyberLabs/assets/142106637/6df8c46f-1e04-408b-b4ac-158993f5d636">

8. You need to get your own API key for the geolocation by IP address to work. Head to [ipgeolocation.io](https://ipgeolocation.io) Sign up for a free account. You will need to verify the email address you sign up with to be able to access the API key.

9. After verifying email, login to ipgeolocation.io and on the dashboard, you will see youre API Key. Copy and paste this key into the script. Save, and then in Powershell ISE run the script. The script runs continuously, and it filters the windows logs, looking for failed login attempts, and grabs the IP address associated with the failed logins. The IP info is then sent to ipgeolocation.io which returns the latitude and longitude info associated to the IP address. This is output to a log file in C:\ProgramData\failed_rdp.log
When running for the first time, you should see your failed login attempt/s from before in the purple text output in the bottom window of PowerShell ISE.

## IV. Create custom log in Log Analytics Workspace (LAW)

1. Back in Azure, search for Log analytics workspaces and open. Click our workspace, then on the next menu click "Tables" and then Create New Custom log (MMA-based)
<img width="1106" alt="tables" src="https://github.com/brentbuch/CyberLabs/assets/142106637/48bb2ecb-52d1-42db-a634-ae2232abbb92">

2. Open the log file at C:\ProgramData\failed_rdp.log on the Windows VM and copy the data inside. This data will include some sample data that was added by the PowerShell script for training. Paste this into a text editor on your own workstation, and save that file as failedrdp.txt. Upload this file as the sample log in Azure LAW.
<img width="841" alt="uploadsample" src="https://github.com/brentbuch/CyberLabs/assets/142106637/456911a4-a2fb-4e5a-a6a1-29eb7b454c18">

3. Click 'Next' until you get to Collection paths. Choose Windows as 'Event Type' and for the Path, paste the log location from the VM, 'C:\ProgramData\failed_rdp.log'
<img width="790" alt="collectionpath" src="https://github.com/brentbuch/CyberLabs/assets/142106637/853706e9-aaef-4654-9250-083a9c7029d5">

4. Click 'Next' and then give the custom log a name, 'Failed_RDP' and click next again. "_CL" will automatically be added to the end of the name to indicate a custom log. Under Review + Create, click Create. We now have our custom log.

5. After the custom log is created, we can check data coming in. Under our log analytic workspace, click 'Logs' and then open a new query. In the query, type "Failed_RDP_CL" and then click the run button. You should see log data in the output.
<img width="1262" alt="querydata" src="https://github.com/brentbuch/CyberLabs/assets/142106637/98aeaff8-7a98-4cc1-b498-f6cc70ea344d">

6. Let the VM run for some time to collect more failed login attempts. Go grab a coffee or a sandwhich and then come back.

## V. Plotting the data to a world map with Sentinel

1. After some time has passed and you have collected some login failures, search for Sentinel and open. I had to toggle the 'Old' Overview setting, and then we can see activity, including our collected failed login events.
<img width="1276" alt="sentineloverview" src="https://github.com/brentbuch/CyberLabs/assets/142106637/f779a8c5-de8f-484a-8d59-185e4a626e83">

2. Click on 'Workbooks' and then 'Add Workbook'. On the next page click 'Edit' and then remove any widgets that are already present. Select 'Add' and then 'Add Query'. In the text box, add the following code. This will parse the location data so it can be added to a map. Under Visualization, select Map, and then hit 'Run Query'

```bash
Failed_RDP_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by latitude, longitude, sourcehost, label, destination, country
```

<img width="1242" alt="mapquery1" src="https://github.com/brentbuch/CyberLabs/assets/142106637/88619cca-6b24-40c7-918c-03378145080d">

3. Under 'Map Settings' make sure latitude and longitude are selected, and then scroll down, and under 'Metric label' select Label from the drop down menu. Click apply, and then save and close.
<img width="1269" alt="mapsettings" src="https://github.com/brentbuch/CyberLabs/assets/142106637/ae41802d-fe64-453b-be42-1e9b7a40f128">

4. Click 'Done editing' and then 'Save'. Give the workbook a title, make sure it is in the correct resource group, and then click 'Apply'
<img width="1278" alt="saveworkbook" src="https://github.com/brentbuch/CyberLabs/assets/142106637/a834d1eb-9731-417d-b6a7-49d699200f8c">

5. We should now be able to see our failed logins populating on the map. The larger the dot, the more logins attempted from that area.
<img width="850" alt="worldmap1" src="https://github.com/brentbuch/CyberLabs/assets/142106637/e616ec0e-9cc6-4a51-9516-1d6145611af7">

6. When I came back to check the VM the next day I was having issues logging in, and the World Map Workbook was showing 'The query returned no results.' From what I could tell, the free tier VM was running out of resources. The free machine was 1 cpu core and 1GB of RAM. I had to upgrade the VM size in Azure which was easy. Navigate to the VM, click size, pick a new size VM, and then click resize. I chose a machine with 2 CPU cores and 4GB of RAM. 
<img width="1269" alt="vmsize" src="https://github.com/brentbuch/CyberLabs/assets/142106637/000bf3e4-2675-4c22-95e8-b93f3abe5976">

7. After upgrading the VM, it rebooted and I was once again able to login. By this point the machine was receiving so many login attempts that it exceeding the 1000 request limit per day of ipgeolocation.io. 
<img width="1265" alt="worldmap2" src="https://github.com/brentbuch/CyberLabs/assets/142106637/fb77ebb5-2a6e-4508-9fab-40cb99e33e7b">

## VI. Setting up Alerts in Sentinel

Now we're going to setup alerts for failed logins. We know that the failed logins come in as Event ID 4625. We will use that as the basis for our alert. 

1. Inside Sentinel, click on 'Analytics' and then 'Create.' From the drop down select 'Scheduled query rule' to open the Analytics Rule Wizard.
<img width="1273" alt="alerts1" src="https://github.com/brentbuch/CyberLabs/assets/142106637/8c232a68-1af2-44e0-9ff9-85bb9846e8e8">

2. On the next page, give the rule a name and description. Set the Severity, and under Tactics and Techniques, I have selected Brute Force. Click Next
<img width="1271" alt="alerts2" src="https://github.com/brentbuch/CyberLabs/assets/142106637/701b9c2c-3df8-40e2-881e-129eb1562541">

3. Now we set the rule logic. The Rule query is created using Kusto Query Language (KQL). I used the simple rule below, but I'm sure there are probably other, more detailed rules that would apply. For entity mapping, map the Host to Computer, Account to Account, and the IP to IpAddress. Query scheduling can be set to run every 5 minutes and include data for the last 5 hours. Start running set to 'Immediately.' Alert Threshold set to 'is greater than' '0.' Event grouping should be set to 'Group all events into a single event' to prevent multiple incidents for the same alert. Click next when finished. 

```
SecurityEvent
| where EventID == 4625
| summarize FailedLogins = count() by Account,Computer, IpAddress
| where FailedLogins > 3
```
<img width="1273" alt="rulequery1" src="https://github.com/brentbuch/CyberLabs/assets/142106637/21676a45-b1ea-4807-9961-2a85dec03d91">
<img width="1274" alt="rulequery2" src="https://github.com/brentbuch/CyberLabs/assets/142106637/dbbde3c0-036c-4875-a158-6d4fb1b9834f">

4. Incident settings should be enabled. Alert grouping should also be enabled. Limit group alerts time frame is set to 5 hours, and 'Group alerts into a single incident if all entities match' is checked. Click Next
<img width="1254" alt="incidentsettings" src="https://github.com/brentbuch/CyberLabs/assets/142106637/04734316-d195-4b19-99b0-f7558740abf4">

5. We will leave the Automation rules empty for now. Click Next, and on the next page you should see 'Validation passed' and then save. 
<img width="1260" alt="saverule" src="https://github.com/brentbuch/CyberLabs/assets/142106637/cb1d7ed3-d25c-491c-9a71-998ca8067530">

6. If we navigate to Incidents, we see that our new alert has created several incidents which we can now take action against. 
<img width="1280" alt="incidents" src="https://github.com/brentbuch/CyberLabs/assets/142106637/813d6e3a-34d0-4a8b-913e-c7230f02e0d5">

<https://learn.microsoft.com/en-us/azure/defender-for-cloud/working-with-log-analytics-agent>
