# Threat Event (Unauthorized AnyDesk Installation)
**Unauthorized Remote Access Tool (RAT) Installation and Use – AnyDesk**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download AnyDesk (Portable Installer):
   - Open a web browser on your test machine.
   - Navigate to the official AnyDesk download link: https://download.anydesk.com/AnyDesk.exe
   - Save the file to a location like your Downloads folder or directly to the Desktop.
2. Run AnyDesk in Portable Mode (No Installation Required):
   - Open Command Prompt or PowerShell and navigate to the folder where you downloaded AnyDesk.exe. For example: cd "C:\Users\huy\Downloads"
   - Run AnyDesk using the portable flag: .\AnyDesk.exe --portable
   - This will launch AnyDesk without installing it system-wide. It runs directly from memory or the current folder and creates minimal footprints.
3. Enable Unattended Access (Optional / Simulated Configuration):
   - While AnyDesk is running, look for a newly created folder named AnyDesk in the same directory as the executable.
   - Inside that folder, you can create a config file named **ad.ini** or **service.conf**
   - Add a basic simulated configuration like:
[security]
password=Secret123
4. Connect to the Device Remotely (Simulated):
   - Note the AnyDesk ID displayed on the screen (9-digit number).
   - If you have a second device, install AnyDesk there and enter the ID to initiate a remote connection.
   - Accept the connection manually on the test machine (unless unattended access is properly configured).
   - Alternatively, simulate this step by keeping AnyDesk running and generating network logs by leaving the application open for several minutes — this will still create relevant entries in DeviceNetworkEvents.
5. Create a Bait File for Exfiltration Simulation:
   - On the Desktop, create a text file named: client-passwords.txt
   - Open the file and add fake content to simulate sensitive information:
Gmail: john.doe@gmail.com / Pass123!
Bank: td-bank / MySecretPass!
Company VPN: jdoe / vpnsecure!
   - Save and close the file.
6. Delete the Bait File and Close AnyDesk:
   - Right-click client-passwords.txt on the Desktop and delete it.
   - Confirm that the file is sent to the Recycle Bin or permanently deleted (Shift + Delete).
   - Close the AnyDesk application by right-clicking its tray icon or closing the window.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detects AnyDesk download, config file creation, and the bait file client-passwords.txt. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|	https://learn.microsoft.com/en-us/defender-xdr/deviceprocessevents-table |
| **Purpose**| 	Detects execution of AnyDesk in portable mode. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|	https://learn.microsoft.com/en-us/defender-xdr/devicenetworkevents-table |
| **Purpose**| Identifies AnyDesk's outbound connections, especially to known AnyDesk IPs or domains. |

---
# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-14.0.1.exe /S```
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites. For example:
   - **WARNING: The links to onion sites change a lot and these have changed. However if you connect to Tor and browse around normal sites a bit, the necessary logs should still be created:**
   - Current Dread Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion```
   - Dark Markets Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login```

6. Create a folder on your desktop called ```tor-shopping-list.txt``` and put a few fake (illicit) items in there
7. Delete the file.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
// Detect download of AnyDesk installer
DeviceFileEvents
| where FileName has "AnyDesk"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

// Detect AnyDesk being launched in portable mode
DeviceProcessEvents
| where ProcessCommandLine contains "--portable"
| where FileName == "AnyDesk.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Detect creation/deletion of bait file
DeviceFileEvents
| where FileName contains "client-passwords.txt"
| project Timestamp, DeviceName, FileName, ActionType

// Detect creation of AnyDesk config files
DeviceFileEvents
| where FileName in~ ("service.conf", "ad.ini")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

// Detect outbound connections made by AnyDesk
DeviceNetworkEvents
| where InitiatingProcessFileName == "AnyDesk.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
```

---

## Created By:
- **Author Name**: Josh Madakor
- **Author Contact**: https://www.linkedin.com/in/joshmadakor/
- **Date**: August 31, 2024

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `September  6, 2024`  | `Josh Madakor`   
## Related Queries:

// Detect download of AnyDesk installer
DeviceFileEvents
| where FileName has "AnyDesk"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

---

## Created By:
- **Author Name**: Huy Tang
- **Author Contact**: https://www.linkedin.com/in/huy-t-892a51317/
- **Date**: May 8, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | May 8, 2025     | Huy Tang          |  
