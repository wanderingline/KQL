## Creation of Shadow Copies

#### Description
Query detects creation of shadow copies through command line or PowerShell. This detection is important because it suggests that an attacker is attempting to manipulate or access data in an unauthorized manner, which can lead to data theft or other malicious activities. Attackers might use shadow copies to backup and exfiltrate sensitive data or to hide their tracks by restoring files to a previous state after an attack. 

An example of this exploit was used by Volt Typhoon where they created a shadow copy of the ntds.dit file. The ntds.dit file is the main Active Directory (AD) database file which contains information about users, groups, group memberships, and password hashes for all users in the domain. Although the ntds.dit file is locked while in use by AD, a copy can be made by creating a Volume Shadow Copy and extracting the ntds.dit file from the Shadow Copy.

## Sentinel
```KQL
DeviceProcessEvents
| where ProcessCommandLine has_all ("create", "shadow") or ProcessCommandLine has_any ("shadowcopy")
| where ProcessCommandLine has_any ("cmd.exe", "powershell.exe")
| where AccountName <> "system"
```

#### Investigations
- Review the user associated with the process - is there a genuine reason they could have copied the file based on their job role?
- Review command line, initiating processes - do previous/subsuquent commands also appear suspicious?
- Examine any relevant on-disk artifacts and review other concurrent processes to determine the source of the attack.

#### Associated CVEs
N/A

#### MITRE ATT&CK Technique(s)
| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1003.003 | OS Credential Dumping: NTDS | [https://attack.mitre.org/techniques/T1557/](https://attack.mitre.org/versions/v13/techniques/T1003/003/) |

#### References
-  https://www.ncsc.govt.nz/assets/NCSC-Documents/CSA_Living_off_the_Land.pdf#page5


