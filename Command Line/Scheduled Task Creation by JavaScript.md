## Scheduled Task Creation by JavaScript

#### Description
Query detects the use of JavaScript to create a new scheduled task.

Scheduled tasks can be used to gain persistence on a device and the use of JavaScript to achieve this has been seen in SEO poisoning attacks whereby a user is tricked into downloading a .js file which matches their browser search. Once executed, the file then executes malicious commands.

## Sentinel Query
```KQL
DeviceProcessEvents
| where ProcessCommandLine contains "schtasks"
| where InitiatingProcessCommandLine contains ".js"
| where InitiatingProcessCommandLine <> "[Insert commonly seen commands to avoid false positives]"
```

#### Investigations
- Review the task created - where possible, establish what the task aims to do.
- Review the initiating processes of the task creation - is there a genuine use case?
- Review activity before/after the event to establish if there is any other suspicious activity.

#### Associated CVEs
N/A

#### MITRE ATT&CK Technique(s)
| Technique ID | Title    | Link    |
| ---  | --- | --- |
|  T1053 | Scheduled Task/Job | [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/) |

#### References
-  https://thedfirreport.com/2024/02/26/seo-poisoning-to-domain-control-the-gootloader-saga-continues/


