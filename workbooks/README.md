# Sentinel Workbooks

Four geo-mapped workbooks. Each JSON file is a single KQL map tile.

| File | Table | Filter |
|---|---|---|
| `Workbook-Windows-RDP-Attacks.json` | `SecurityEvent` | `EventID == 4625` |
| `Workbook-Linux-SSH-Attacks.json` | `Syslog` | `Facility == "auth"` and message starts with `Failed password for` |
| `Workbook-MSSQL-Attacks.json` | `Event` | `EventLog == "Application"` and `EventID == 18456` |
| `Workbook-NSG-Inbound-Flows.json` | `NTANetAnalytics` | `SubType == "FlowLog"` and `FlowType in ("ExternalPublic", "MaliciousFlow")` |

## Prerequisite: the `geoip` watchlist
Create a Sentinel watchlist with the alias **`geoip`** and `network` as the search key. It needs these columns:
`network` (CIDR), `latitude`, `longitude`, `cityname`, `countryname`.
Without it the queries fail, because every workbook calls `_GetWatchlist("geoip")`.

## Import steps
1. Microsoft Sentinel, then **Workbooks**, then **Add workbook**, then **Edit**.
2. Remove any default tiles, then click the **`</>`** (Advanced Editor) icon.
3. In the **Gallery Template** tab, paste the full contents of one JSON file.
4. Click **Apply**, then **Done Editing**, then **Save** (name it after the file).
5. The time range is fixed at 30 days inside the JSON (`durationMs: 2592000000`). Change it there if needed.
