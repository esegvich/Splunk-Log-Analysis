# Splunk-SSH-Log-Analysis

A security monitoring project using Splunk to analyze SSH authentication activity, detect failed login attempts, and identify potentially malicious behavior such as brute-force attacks.

In this project, I used Splunk to ingest and analyze SSH authentication logs. The objectives were to:
- Upload and index Zeek-style JSON SSH logs
- Detect failed vs. successful SSH authentication attempts
- Identify unusual SSH activity and potential brute-force behavior
- Use SPL queries to extract security insights

Data Source: JSON-formatted Zeek SSH logs (uploaded manually into Splunk).

I used this JSON file: 




I did not fetch logs from a server endpoint — instead, I accessed the Splunk Web interface through:
```ccp
http://<your-server-ip>:8000
```

This URL is only used to access Splunk Web, not to download logs.

I manually downloaded the SSH JSON log file (provided separately) and uploaded it into Splunk using:

Add Data → Upload → Select JSON file → Index: main


Using SPL queries, I listed the  top 10 endpoints with failed SSH login attempts:
```spl
index=main sourcetype="_json" auth_success=false
| stats count by "id.orig_h"
| sort -count
| head 10
```

Then, I found the total number of SSH connections:
```spl
index=ssh_lab sourcetype="json"
| stats count as total_ssh_connections
```

Finall, I counted all of the event types (successful, failed, no-auth, multiple-failed) seen in the logs:
```spl
index=ssh_lab sourcetype="json"
| stats count by event_type
```
