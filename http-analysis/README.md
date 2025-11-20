# Splunk HTTP Log Analysis

In this project I:
Learn how to ingest and analyze HTTP logs using Splunk.
Detect client errors, server errors, and suspicious web activity.
Identify large file transfers and suspicious URI access attempts.



## Data Set

Data Source: JSON-formatted Zeek SSH logs (uploaded manually into Splunk).

I used this JSON file: 

**[HTTP Log File](./data/http_log.json)**


## SPL Queries and Findings

Using SPL queries, I found the top 10 endpoints generating web traffic:
```spl
index=http_lab sourcetype="json"
| stats count by "id.orig_h"
| sort -count
| head 10
```

![Top endpoints](./Images/Top10Endpoints.png)

Then I counted the number of server errors (5xx) observed:
```spl
index=http_lab sourcetype="json" status_code>=500 status_code<600
| stats count as server_errors
```

![5XX Server Errors](./Images/ServerErrors.png)

Next I identifed User-Agents associated with possible scripted attacks:
```spl
index=http_lab sourcetype="json" user_agent IN ("sqlmap/1.5.1", "curl/7.68.0", "python-requests/2.25.1", "botnet-checker/1.0")
| stats count by user_agent
```

![Possible scripted attacks](./Images/PossibleScsriptedAttacks.png)

Finally, I found large file transfers (greater than 500 KB):
```spl
index=http_lab sourcetype="json" resp_body_len>500000
| table ts "id.orig_h" "id.resp_h" uri resp_body_len
| sort -resp_body_len
```

![Large Transfer endpoints](./Images/LargeTransfers.png)

## Findings
