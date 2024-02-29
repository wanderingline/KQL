## Privileged User Discovery

#### Description
This detects usage of command line to discover admins either locally or across the domain. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior such as targeting specific accounts which possess particular privileges.

An example of this being exploted was seen in Volt Typhoon attacks where they run net group /dom and net group "Domain Admins" /dom in compromised environments for account discovery.

## Sentinel Query
```KQL
DeviceProcessEvents
| where ProcessCommandLine has_any ("localgroup", "group")
| where ProcessCommandLine has_any ("Administrators", "Domain Admins")
| where ProcessCommandLine contains " /d"
| where AccountName != "system"
```

#### Investigations
- Review the user associated with the process - is there a genuine reason they could have executed this command?
- Review command line, initiating processes - do previous/subsuquent commands also appear suspicious?

#### MITRE ATT&CK Technique(s)
| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1087 | Account Discovery | ([Link](https://attack.mitre.org/techniques/T1087/)) |

#### References
-  https://www.ncsc.govt.nz/assets/NCSC-Documents/CSA_Living_off_the_Land.pdf#page5

