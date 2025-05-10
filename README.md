# Threat Hunt Report: Unauthorized AnyDesk Installation
- [Scenario Creation](https://github.com/huyrocks123/threat-hunting-scenario-anydesk/blob/main/threat-hunting-scenario-anydesk-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- AnyDesk Remote Access Tool (Portable Version)

##  Scenario

Management has raised concerns about possible unauthorized use of remote access tools (RATs) within the organization. Suspicious network traffic and system behavior suggest that an employee may have used AnyDesk without proper approval. The goal is to detect whether AnyDesk was downloaded and used in portable mode to bypass installation restrictions, whether any configuration for unattended access was applied, and if there was an attempt to exfiltrate data.

### High-Level AnyDesk-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any file events involving AnyDesk.exe, ad.ini or other suspicious configuration files that indicate the use of portable mode or setup for unattended access.
- **Check `DeviceProcessEvents`** for signs of AnyDesk.exe being executed, especially with flags like --portable, which indicate attempts to bypass installation restrictions.
- **Check `DeviceNetworkEvents`** for outbound connections initiated by AnyDesk.exe, which may suggest active remote sessions or attempts to communicate with AnyDesk servers.

---

## Steps Taken

### 1. Detected download of the AnyDesk installer

Used the DeviceFileEvents table to search for instances where a file with the name AnyDesk was downloaded or interacted with. A file named `AnyDesk.lnk` was downloaded to the Downloads folder at 2025-05-10T14:50:08.8422854Z. The `AnyDesk.exe` file was deleted at 2025-05-10T14:43:23.1536209Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "huy"
| where FileName has "AnyDesk"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
```


<img width="838" alt="Screenshot 2025-05-10 at 12 17 20 PM" src="https://github.com/user-attachments/assets/8c3a798d-9453-4ec4-85e1-a7e3aad4a100" />


---

### 2. Detected execution of AnyDesk in portable mode

Queried the DeviceProcessEvents table for processes where AnyDesk was executed with the --portable flag, indicating a launch without installation. According to the logs, the AnyDesk.exe --portable command was run at 2025-05-10T14:45:54.0760355Z.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "huy"
| where ProcessCommandLine contains "--portable"
| where FileName == "AnyDesk.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

<img width="704" alt="Screenshot 2025-05-10 at 11 33 28 AM" src="https://github.com/user-attachments/assets/1ec16955-6361-458d-b432-ec4c123fe2a5" />

---

### 3. Searched for creation and deletion of bait file

Queried DeviceFileEvents for evidence of a suspicious file named client-passwords.txt, which was used as a bait artifact to monitor interaction and deletion. According to the logs, the client-passwords.txt file was created at 2025-05-10T14:55:47.1100933Z. Logs did not capture the deletion of the file, which is odd.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "huy"
| where FileName contains "client-passwords.txt"
| project Timestamp, DeviceName, FileName, ActionType
```

<img width="652" alt="Screenshot 2025-05-10 at 11 37 16 AM" src="https://github.com/user-attachments/assets/a606d39e-c2c1-4765-8e6a-1f87d2325194" />

---

### 4. Detected creation of AnyDesk configuration files

Searched for creation of known AnyDesk configuration files using the DeviceFileEvents table to confirm setup or persistent activity. Confirmed the creation of the `ad.ini.lnk` file at 2025-05-10T14:50:08.7616586Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FolderPath has @"C:\Users\huy\AppData" or FolderPath has @"C:\Users\huy\Downloads"
| where ActionType == "FileCreated"
| project Timestamp, FileName, FolderPath, ActionType
| order by Timestamp desc
```

<img width="677" alt="Screenshot 2025-05-10 at 11 48 49 AM" src="https://github.com/user-attachments/assets/ca73bc27-152b-47fc-a140-953412d1d3a5" />

### 5. Detected outbound connections initiated by AnyDesk

Used the DeviceNetworkEvents table to identify outbound network connections initiated by the AnyDesk binary, confirming external communication attempts. Anydesk.exe executed and attempted external communication over port 443 (HTTPS) and port 80 (HTTP) multiple times, which supports a conclusion of unauthorized remote access activity or at least attempted communication with external hosts. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "huy"
| where InitiatingProcessFileName == "AnyDesk.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

<img width="1064" alt="Screenshot 2025-05-10 at 11 55 49 AM" src="https://github.com/user-attachments/assets/16f99bcb-5a94-4cbc-b9f0-3cbec3667dfd" />

---

## Chronological Event Timeline 

### 1. File Download - AnyDesk Installer

- **Timestamp:** `2025-05-10T14:50:08.8422854Z
- **Event:** The user "employee" downloaded AnyDesk.exe to their Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\huy\Downloads`

### 2. Process Execution - Portable AnyDesk Launch

- **Timestamp:** `2025-05-10T14:45:54.0760355Z`
- **Event:** The user "huy" ran AnyDesk with the --portable flag from Command Prompt.
- **Action:** Process execution detected.
- **Command:** `.\AnyDesk.exe --portable`
- **File Path:** `C:\Users\huy\Downloads\AnyDesk.exe`

### 3. Bait File Creation/Deletion - Sensitive Data Simulation

- **Timestamp:** `2025-05-10T14:55:47.1100933Z`
- **Event:** A bait file `client-passwords.txt` containing fake credentials was created on the Desktop. This file was then deleted, but I could not find any logs corresponding to the deletion.
- **Action:** File creation detected.
- **File Path:** `C:\Users\huy\Desktop\client-passwords.txt`
  
### 4. Config File Creation - Unattended Access

- **Timestamp:** `2025-05-10T14:50:08.7616586Z`
- **Event:** A folder named AnyDesk was created and a file ad.ini was written to simulate unattended access configuration.
- **Action:** Config file creation detected.
- **File Path:** `C:\Users\huy\Videos`


### 5. Network Connection - AnyDesk Communications

- **Timestamp:** `2025-05-10T14:43:41.9290178Z`
- **Event:** AnyDesk established outbound connections to external IPs while running.
- **Action:** Network activity detected.
- **Process:** AnyDesk.exe
- **File Path:** `C:\Users\huy\Downloads\AnyDesk.exe`

---

## Summary

- Unauthorized remote access tool (AnyDesk) was downloaded and run in portable mode to avoid detection.
- Configuration for unattended access may have been applied via ad.ini.
- Simulated sensitive data was created and deleted in a short time span, implying possible exfiltration.
- Outbound network activity confirmed that the tool attempted to connect externally.

---

## Response Taken

- Block the execution of known remote access tools such as AnyDesk via application control policies.
- Monitor for creation and execution of .exe files in user profile directories.
- Review network traffic for any unauthorized outbound connections to known AnyDesk servers.
- Educate employees about acceptable use policies and the risks associated with unapproved remote access tools.

---
