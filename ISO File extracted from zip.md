## WMIC Storage Device Mapping

#### Description
Query detects usage of commands which gather information about the storage devices on the local host, including drive letter, file system, free space and drive size in bytes, and an optional volume name. Note: This command does not require administrative credentials to run.


Use of this command has been seen in a number of attacks including Volt Typhoon.

## Sentinel Query
```KQL
DeviceEvents
| where InitiatingProcessCommandLine contains "win32_logicaldisk"
| project DeviceName, InitiatingProcessAccountUpn, InitiatingProcessCommandLine
```

#### Investigations
- Review the user associated with the process - is there a genuine reason they may need to check storage mapping based on their job role?
- Review command line, initiating processes - do previous/subsuquent commands also appear suspicious?

#### Associated CVEs
N/A

#### MITRE ATT&CK Technique(s)
| Technique ID | Title    | Link    |
| ---  | --- | --- |
|  T1082 | System Information Discovery | [https://attack.mitre.org/versions/v13/techniques/T1082/](https://attack.mitre.org/versions/v13/techniques/T1082/) |

#### References
-  https://www.ncsc.govt.nz/assets/NCSC-Documents/CSA_Living_off_the_Land.pdf#page5


