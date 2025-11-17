# Databricks Security Detection Engineering - Hands-On Lab

## Overview
This hands-on lab teaches security detection engineering on the Databricks platform. Participants will learn to ingest, normalize, analyze, and operationalize security event detection using real-world log sources.

**Duration:** 45-60 minutes  
**Level:** Intermediate  
**Prerequisites:** Basic SQL knowledge, familiarity with security concepts

## Lab Objectives
By the end of this lab, you will:
- Ingest and normalize security logs from multiple sources (Sysmon, Okta, Windows Events, CloudTrail)
- Build detection rules using SQL and PySpark
- Implement threshold-based and anomaly-based detections
- Operationalize detections with Delta Live Tables and Databricks Workflows
- Visualize alerts and metrics in Databricks dashboards

## Architecture Overview
```
┌─────────────────┐
│  Raw Log Data   │
│  (JSON/CSV)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Bronze Layer   │  ◄── Auto Loader / Lakeflow Connect
│  (Raw Ingestion)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Silver Layer   │  ◄── Normalized, Parsed, Enriched
│  (Cleaned Data) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Gold Layer    │  ◄── Detection Rules Applied
│   (Alerts)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Dashboards &   │
│  Alerting       │
└─────────────────┘
```

## Lab Structure

### Lab 01: Workspace Setup (10 minutes)
**Notebook:** `01_workspace_setup.py`
- Create catalog, schemas, and volumes
- Generate sample security logs (Sysmon, Okta, Windows Events, CloudTrail)
- Upload sample data to Unity Catalog Volumes
- Verify data accessibility

### Lab 02: Ingest and Normalize (10 minutes)
**Notebook:** `02_data_ingestion_dlt.py`
- Configure Auto Loader for streaming ingestion
- Create Bronze tables with raw data
- Build Silver transformations (parse JSON, flatten fields, standardize)
- Deploy Delta Live Tables pipeline

### Lab 03: Detection Logic Authoring (15 minutes)
**Notebook:** `03_detection_rules.sql` and `03_detection_rules.py`
- Write simple SQL detections (mimikatz, suspicious processes)
- Implement threshold-based rules (failed logins, privilege escalation)
- Create anomaly detection with ML (optional/advanced)
- Version and store detection rules in Gold layer

### Lab 04: Operationalize and Validate (10 minutes)
**Notebook:** `04_operationalize.py`
- Schedule detection workflows
- Configure alerting and notifications
- Test with malicious samples
- Build security dashboards
- Export alerts via API

## Quick Start

### Option 1: Import All Notebooks
1. Download this repository
2. In Databricks workspace, go to **Workspace** → **Import**
3. Upload the entire `databricks-security-detection-lab` folder
4. Run notebooks in sequence (01 → 02 → 03 → 04)

### Option 2: Git Integration (Recommended)
1. In Databricks, go to **Repos** → **Add Repo**
2. Clone this repository
3. Navigate through notebooks in order

## Prerequisites Setup

### 1. Databricks Requirements
- Databricks Runtime 13.3 LTS or higher
- Unity Catalog enabled workspace
- SQL Warehouse (size: Small or Medium)
- Cluster configuration:
  - **Cluster Mode:** Single Node or Standard
  - **Runtime:** 13.3 LTS ML or higher
  - **Node Type:** i3.xlarge (AWS) or equivalent

### 2. Permissions Required
- CREATE CATALOG or USE existing catalog
- CREATE SCHEMA
- CREATE TABLE
- CREATE VOLUME
- CREATE PIPELINE (for Delta Live Tables)
- CREATE JOB (for Workflows)

### 3. Python Libraries (Auto-installed)
- `faker` (for sample data generation)
- `pandas`
- `numpy`

## Lab Modules Detail

### Module 1: Workspace Setup
**Time:** 10 minutes  
**Learning Outcomes:**
- Understand Unity Catalog structure for security data
- Generate realistic sample security logs
- Configure data storage with Volumes

**Key Concepts:**
- Unity Catalog (Catalog → Schema → Tables/Volumes)
- Sample data generation strategies
- Security log types and formats

### Module 2: Data Ingestion
**Time:** 10 minutes  
**Learning Outcomes:**
- Configure Auto Loader for incremental data ingestion
- Build Bronze → Silver transformations
- Implement schema evolution and data quality checks

**Key Concepts:**
- Bronze-Silver-Gold architecture (Medallion)
- Delta Live Tables (DLT)
- Streaming vs. Batch processing
- Data normalization and enrichment

### Module 3: Detection Logic
**Time:** 15 minutes  
**Learning Outcomes:**
- Write signature-based detections
- Implement statistical threshold rules
- (Optional) Build ML-based anomaly detection

**Key Concepts:**
- MITRE ATT&CK framework
- Detection engineering principles
- False positive reduction
- Rule versioning and metadata

**Sample Detections:**
1. **Process Execution:** mimikatz, powershell obfuscation
2. **Authentication:** Brute force, impossible travel
3. **Privilege Escalation:** Token manipulation, SID history injection
4. **Lateral Movement:** Pass-the-hash, remote service creation
5. **Exfiltration:** Large data transfers, unusual destinations

### Module 4: Operationalization
**Time:** 10 minutes  
**Learning Outcomes:**
- Schedule automated detection workflows
- Configure alert routing and notifications
- Build executive security dashboards
- Test and validate detections

**Key Concepts:**
- Databricks Workflows
- Alert fatigue management
- Dashboard design for SOC teams
- Detection validation and tuning

## Sample Data Sources

### 1. Sysmon Logs
**Volume:** ~10,000 events  
**Fields:** EventID, ProcessName, CommandLine, User, Hash, ParentProcess  
**Detections:** Process execution, network connections, file creation

### 2. Okta Logs
**Volume:** ~5,000 events  
**Fields:** EventType, Actor, Target, Outcome, Location, IP  
**Detections:** Failed logins, MFA bypass, suspicious locations

### 3. Windows Event Logs
**Volume:** ~8,000 events  
**Fields:** EventID, LogonType, Account, SourceIP, Timestamp  
**Detections:** Privilege escalation, lateral movement

### 4. AWS CloudTrail
**Volume:** ~6,000 events  
**Fields:** EventName, UserIdentity, SourceIP, Resources, ErrorCode  
**Detections:** IAM changes, S3 access, unusual API calls

## Dashboard Examples

### 1. SOC Overview Dashboard
- Total alerts (24h, 7d, 30d)
- Alerts by severity (Critical, High, Medium, Low)
- Top attacked assets
- Detection rule effectiveness
- Mean time to detect (MTTD)

### 2. Detection Performance Dashboard
- True positive rate by rule
- False positive trends
- Detection coverage by MITRE ATT&CK technique
- Rule execution performance

### 3. Threat Hunting Dashboard
- Anomalous processes
- Suspicious network connections
- Authentication anomalies
- Timeline of related events

## Advanced Extensions (Optional)

### 1. MITRE ATT&CK Mapping
- Tag each detection with ATT&CK techniques
- Build coverage heatmap
- Track detection gaps

### 2. Threat Intelligence Integration
- Enrich with IOC feeds (IPs, domains, hashes)
- Integrate with TAXII/STIX feeds
- Build dynamic blocklists

### 3. Machine Learning Enhancements
- User behavior analytics (UEBA)
- Process sequence modeling
- Graph analytics for lateral movement

### 4. Response Automation
- Auto-disable compromised accounts
- Isolate affected hosts
- Create investigation cases

## Troubleshooting

### Issue: "Catalog not found"
**Solution:** Ensure Unity Catalog is enabled. Run `01_workspace_setup.py` completely.

### Issue: "Delta Live Tables pipeline fails"
**Solution:** Check cluster permissions and DLT configuration. Ensure Silver transformations have valid syntax.

### Issue: "No alerts generated"
**Solution:** Verify detection thresholds. Check that sample data contains malicious patterns (Lab 01 generates them).

### Issue: "Dashboard queries timeout"
**Solution:** Use SQL Warehouse instead of cluster. Optimize queries with partitioning on timestamp.

## Best Practices

### Detection Engineering
1. **Start simple:** Basic signature-based rules before complex ML
2. **Version everything:** Track rule changes in Git and metadata tables
3. **Test thoroughly:** Use known malicious samples and benign data
4. **Monitor performance:** Track rule execution time and resource usage
5. **Reduce false positives:** Iterate based on analyst feedback

### Data Pipeline
1. **Use incremental processing:** Auto Loader for efficiency
2. **Implement data quality checks:** Expectations in DLT
3. **Partition strategically:** By date for time-series queries
4. **Enable Change Data Feed:** For audit and replay
5. **Tag tables appropriately:** For governance and cost allocation

### Operational Security
1. **Implement RBAC:** Restrict access to raw logs and PII
2. **Encrypt at rest:** Use Unity Catalog encryption
3. **Audit data access:** Enable and monitor access logs
4. **Data retention:** Define policies for Bronze/Silver/Gold
5. **Compliance:** Ensure GDPR/HIPAA requirements met

## Resources

### Databricks Documentation
- [Delta Live Tables](https://docs.databricks.com/delta-live-tables/index.html)
- [Unity Catalog](https://docs.databricks.com/unity-catalog/index.html)
- [Auto Loader](https://docs.databricks.com/ingestion/auto-loader/index.html)
- [Workflows](https://docs.databricks.com/workflows/index.html)

### Security Resources
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

### Sample Detection Rules
- [Splunk Security Content](https://github.com/splunk/security_content)
- [Elastic Detection Rules](https://github.com/elastic/detection-rules)

## Support and Feedback

For questions or issues:
1. Check the Troubleshooting section
2. Review notebook comments and markdown cells
3. Consult Databricks documentation
4. Open an issue in the repository

## License
This lab is provided as-is for educational purposes. Sample data is synthetically generated.

---

**Ready to start?** → Open `01_workspace_setup.py` and begin your security detection engineering journey! 🔐

