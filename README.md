# Cloud-Native Threat Ingestion & Sentinel SIEM Telemetry Pipeline

##  Project Overview
This project establishes a cloud-native security monitoring and ingestion framework within Microsoft Azure to aggregate, parse, and visualize public endpoint threat landscapes. A target endpoint running Windows 11 was intentionally exposed to the public internet via open access vectors. Telemetry was engineered natively using the Azure Monitoring Agent (AMA) extension alongside structured Data Collection Rules (DCR) to capture high-fidelity authentication logs. 

Aggregated logs were streamed into an Azure Log Analytics Workspace and integrated with Microsoft Sentinel. By writing custom Kusto Query Language (KQL) lookups against an uploaded geographical matrix database, raw failed logon attempts were normalized into spatial tracking datasets and displayed on an interactive attack map dashboard.

---

##  Architectural Topology & Asset Flow
The cloud infrastructure funnels untrusted network traffic from perimeter boundaries straight into a centralized security analysis layer:

* **Public Internet Botnets**
    * Target management channels via Port 3389 running automated unauthenticated RDP sweeps.
* **Azure Virtual Machine (`NET-CORP-1`)**
    * Ingests perimeter authentication requests and generates native Windows Audit Logs containing Event ID 4625 (Logon Failure).
* **Data Collection Rule (`DataCollectionRuleDCR-Windows`)**
    * Acts as the centralized telemetry routing policy, executing data capture instructions via the in-guest Azure Monitoring Agent (AMA) extension.
* **Log Analytics Workspace (`LogAnalyticsWorkspace-SocLab`)**
    * Functions as the native stream aggregator and centralized cloud database for the collected system event tables.
* **Microsoft Sentinel UI (SIEM Logic Layer)**
    * Orchestrates analytics capabilities across raw logs by running relational queries against a custom uploaded `geoip` Threat Matrix Watchlist.
* **Interactive Workbook Layer (`AttackMapWorkbook`)**
    * Renders geospatial coordinate parameters into real-time analytical attack visualizations and map graphs.

---

##  Tech Stack, Protocols, & Deployed Azure Resources
* **Target Endpoint Computer:** `NET-CORP-1` (Windows 11 IaaS Compute Architecture)
* **Perimeter Security Boundary:** `NET-CORP-1-nsg` (Network Security Group Firewall)
* **Log Aggregation Container:** `LogAnalyticsWorkspace-SocLab`
* **Telemetry Routing Policy:** `DataCollectionRuleDCR-Windows` (Data Collection Rule Engine)
* **SIEM Core Extensions:** Microsoft Sentinel (`SecurityInsights` Solution Module)
* **Endpoint Telemetry Agent:** Azure Monitoring Agent (AMA Virtual Machine Extension)
* **Analytical Presentation Suite:** Azure Workbooks (`AttackMapWorkbook`)
* **Query & Data Parsing Language:** Kusto Query Language (KQL)
* **Target Security Metric:** Windows Security Auditing (Event ID 4625 - Logon Failure)

---

## Telemetry Pipeline Logical Layout
To map the active processing states within the SIEM instance, I constructed a logical dependency map matching the data transformation loop. The structural graph visualizes how incoming raw tables flow cleanly from schema definition queries straight into mapping layouts.

<img width="985" height="717" alt="Screenshot 2026-06-17 at 9 43 46 AM" src="https://github.com/user-attachments/assets/ace0e88c-4760-44b9-802f-5cc6564764e7" />

---

##  Configuration & Implementation Walkthrough

### Phase 1: Deploying Target Assets & Establishing the Exposure Baseline
A target Virtual Machine (`NET-CORP-1`) running Windows 11 was provisioned within the virtual network `VNET-SOC-LAB`. To facilitate rapid discovery by automated internet scanners, the inbound Network Security Group (`NET-CORP-1-nsg`) firewall policies were opened explicitly on management Port 3389 (RDP) to receive traffic from any public external source IP address. 

To ensure perimeter traffic could reach deep enough into the operating system stack to register authentication telemetry, the internal Windows Defender Firewall configuration windows were administrative deactivated for Domain, Private, and Public network profiles (`wf.msc`).

<img width="350" height="600" alt="Screenshot 2026-06-16 at 10 04 51 AM" src="https://github.com/user-attachments/assets/3aa955de-99d3-4178-9aef-cc0a4623e0e6" />
 <img width="600" height="200" alt="Screenshot 2026-06-16 at 10 03 49 AM" src="https://github.com/user-attachments/assets/bdc2089c-8239-477a-89fc-aea3d5f85cb7" />
<img width="685" height="386" alt="Screenshot 2026-06-16 at 10 13 11 AM" src="https://github.com/user-attachments/assets/f100de65-dd53-4587-946c-e995c9ec39f9" />


### Phase 2: Configuring In-Guest Telemetry Agents & Ingestion Rules
Rather than running legacy unmanaged parsing mechanisms, the system relies on modern Azure cloud data collection frameworks. The **Azure Monitoring Agent (AMA)** extension was deployed directly inside the Windows guest virtual machine. 

A centralized policy rule, `DataCollectionRuleDCR-Windows`, was configured in the Azure portal. This rule dictates the exact scoping parameters for log streaming, instructing the internal AMA extension to capture all local event logs and continuously stream them into `LogAnalyticsWorkspace-SocLab`. Our primary indicator of malicious discovery centers on **Windows Event ID 4625** (Audit Failure - Logon Attempt).


 <img width="1000" height="350" alt="Screenshot 2026-06-16 at 10 17 27 AM" src="https://github.com/user-attachments/assets/e4ef5fd3-d6b1-43b2-89d1-6515e49cce34" />
 <img width="1000" height="300" alt="Screenshot 2026-06-16 at 10 18 45 AM" src="https://github.com/user-attachments/assets/2c388baf-20ec-4960-b63e-93b2a964cfb9" />
 <img width="1000" height="600" alt="Screenshot 2026-06-16 at 10 19 25 AM" src="https://github.com/user-attachments/assets/0acbc2b9-c22e-47ea-9907-b9e790d29f7c" />


### Phase 3: Populating the Threat Intelligence Watchlist Database
Raw authentication event logs natively track an adversary's public IP address but omit physical spatial identifiers. To bridge this visibility gap, a summarized `geoip` relational mapping matrix was ingested into Microsoft Sentinel under the Watchlists blade. This mapping links structural public IP blocks to coordinate values (Latitude, Longitude, Country, and City fields), establishing a localized database lookup file within our workspace.

<img width="488" height="980" alt="Screenshot 2026-06-16 at 10 23 31 AM" src="https://github.com/user-attachments/assets/0f7a2da2-3c92-4951-b683-9989d18fcb5f" />

### GeoIP Watchlist Dataset

The GeoIP watchlist used in this project can be downloaded below:

[GeoIP CSV Dataset](https://drive.google.com/file/d/13EfjM_4BohrmaxqXZLB5VUBIz2sv9Siz/view)

### Phase 4: Constructing Relational Queries & Normalizing JSON Blobs
Data streams inside Microsoft Sentinel watchlists package secondary identifiers into a dense, nested string object (`WatchlistItems`). To extract these fields without destroying database efficiency, a custom Kusto Query Language (KQL) rule was written using the native `evaluate ipv4_lookup` join plugin. 

The analytical schema matches the live `IpAddress` string from the Windows telemetry with the `SearchKey` field of our watchlist dataset, projecting individual columns cleanly onto the security screen.

#### Core Analytical Query Implemented:
```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
SecurityEvent
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, SearchKey)
    | project 
        TimeGenerated, 
        Account, 
        IpAddress, 
        country, 
        latitude, 
        longitude, 
        label, 
        description
```
---

## Phase 5: Microsoft Sentinel Attack Map Workbook Orchestration
To transform raw database query logs into a functional, executive-ready security asset, a custom Azure Workbook (`AttackMapWorkbook`) was constructed. By initializing an interactive map layout widget, the spatial latitude and longitude coordinate vectors parsed out by our KQL query are actively mapped to pinpoint attacker locations globally in real time.

###  Microsoft Sentinel Workbook Configuration Code
The complete infrastructure template used to build out this map interface can be reviewed below. To deploy this yourself, open an empty Azure Workbook, activate the **Advanced Editor** (`</>`), and paste this entire configuration block:

```json
{
	"type": 3,
	"content": {
	"version": "KqlItem/1.0",
	"query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
	"size": 3,
	"timeContext": {
		"durationMs": 2592000000
	},
	"queryType": 0,
	"resourceType": "microsoft.operationalinsights/workspaces",
	"visualization": "map",
	"mapSettings": {
		"locInfo": "LatLong",
		"locInfoColumn": "countryname",
		"latitude": "latitude",
		"longitude": "longitude",
		"sizeSettings": "FailureCount",
		"sizeAggregation": "Sum",
		"opacity": 0.8,
		"labelSettings": "friendly_location",
		"legendMetric": "FailureCount",
		"legendAggregation": "Sum",
		"itemColorSettings": {
		"nodeColorField": "FailureCount",
		"colorAggregation": "Sum",
		"type": "heatmap",
		"heatmapPalette": "greenRed"
		}
	}
	},
	"name": "query - 0"
}
```



<img width="1252" height="704" alt="Screenshot 2026-06-16 at 10 31 37 AM" src="https://github.com/user-attachments/assets/bf686347-8264-4c2e-84c1-b24701818320" />
*(Image Above: Real-time global threat visualization workbook mapping automated protocol sweeps by country, city, and spatial tracking vectors.)*

### Key Tactical Discoveries & Telemetry Observations:
1. **Adversarial Credential Fingerprinting:** Malicious bots focused heavily on common default credentials, scanning for usernames like `Administrator`, `Admin`, `User`, and `Guest`.
2. **Global Distribution Patterns:** Cross-referencing the database confirmed high volume unauthenticated automated traffic hits exposed targets instantly from globally distributed botnets.
3. **Volumetric Incident Patterns:** Attack thresholds regularly reached high densities per minute, proving the speed at which internet-facing vulnerabilities are surfaced by malicious scripts.

---

##  Strategic Professional Takeaway
This project bridges the gap between cloud infrastructure configuration and blue-team detection engineering. By managing the full lifecycle of host auditing, cloud-native database ingestion pipelines via the Azure Monitoring Agent (AMA), and data enrichment using KQL lookups, I have demonstrated the technical competencies needed to reduce visibility gaps and deploy security baselines within an enterprise Security Operations Center (SOC).

