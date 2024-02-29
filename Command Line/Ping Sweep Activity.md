## Ping Sweep Activity

#### Description
Query detects ping sweeps (also known as an ICMP sweep), which is a basic network scanning technique used to determine which of a range of IP addresses map to live hosts (computers).

An attacker could conduct a ping sweep to discover live hosts they can connect to.

This query is configured to alert when a device has pinged a large number of unique hosts. Note: In this query, timeframe and threshold can be adjusted to suit individual requirements.

## Sentinel Query
```KQL
let timeframe = 30m;
let threshold = 15;
DeviceNetworkEvents
| where TimeGenerated >= ago(timeframe)
| where ipv4_is_private(RemoteIP)
| where AdditionalFields.direction == "Out"
| where Protocol == "Icmp"
| summarize UniqueIPsPinged = dcount(RemoteIP), PingCount = count() by DeviceName
| project-reorder DeviceName, PingCount, UniqueIPsPinged
| where UniqueIPsPinged >= threshold
```

#### Investigations
- Review the user associated with the process - is there a genuine reason they may ping a number of hosts based on their job role?
- Review the initiating processes of the pings - is an application performing the reconnaissance?
- Review activity before/after the event to establish if there is any other suspicious activity.

#### Associated CVEs
N/A

#### MITRE ATT&CK Technique(s)
| Technique ID | Title    | Link    |
| ---  | --- | --- |
|  T1595 | Active Scanning | [https://attack.mitre.org/techniques/T1595/](https://attack.mitre.org/techniques/T1595/) |

#### References
-  https://thedfirreport.com/2024/02/26/seo-poisoning-to-domain-control-the-gootloader-saga-continues/


