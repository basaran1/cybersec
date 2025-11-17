# Getting Started with Databricks Security Detection Lab

Welcome! 👋 This guide will get you started in **5 simple steps**.

---

## What You'll Build

A complete security detection platform on Databricks that:
- Ingests 29,000+ sample security logs
- Runs 9+ detection rules automatically  
- Generates actionable security alerts
- Visualizes threats with dashboards

**Time Required:** 15-20 minutes

---

## Prerequisites Check

Before starting, ensure you have:

✅ **Databricks Workspace** with Unity Catalog enabled  
✅ **Permissions:**
   - CREATE CATALOG (or access to existing catalog)
   - CREATE SCHEMA
   - CREATE TABLE  
   - CREATE VOLUME
   
✅ **Compute:** Cluster or SQL Warehouse (any size works)

**Not sure?** Ask your Databricks workspace admin.

---

## Step 1: Download Lab Materials

### Option A: Via Git (Recommended)
```bash
# In Databricks workspace:
1. Click "Repos" in left sidebar
2. Click "Add Repo"  
3. Paste repository URL
4. Click "Create Repo"
```

### Option B: Manual Download
1. Download all files from this repository
2. In Databricks, go to **Workspace**
3. Right-click → **Import**
4. Upload all `.py` files

---

## Step 2: Generate Sample Data (5 minutes)

1. **Open:** `01_workspace_setup.py`
2. **Click:** Run All (▶▶ button at top)
3. **Wait:** ~3-4 minutes for completion
4. **Verify:** You should see:
   ```
   ✅ Generated 10,000 Sysmon events
   ✅ Generated 5,000 Okta events  
   ✅ Generated 8,000 Windows Event logs
   ✅ Generated 6,000 CloudTrail events
   ```

**⚠️ Troubleshooting:**
- If "Catalog not found" error: Change `CATALOG_NAME = "hive_metastore"` in notebook
- If Faker import fails: Click restart Python and re-run

---

## Step 3: Create Data Pipeline (4 minutes)

### Create Delta Live Tables Pipeline

1. **Go to:** Workflows → Delta Live Tables
2. **Click:** Create Pipeline
3. **Configure:**
   - **Pipeline Name:** `security_detection_pipeline`
   - **Notebook:** (select `02_data_ingestion_dlt.py`)
   - **Target:** `security_detection_lab.security_logs`
   - **Cluster Mode:** Single Node
   - **Pipeline Mode:** Triggered
4. **Click:** Create
5. **Click:** Start

**Wait 2-3 minutes** for pipeline to complete. You'll see a green DAG (graph) when done.

**⚠️ Troubleshooting:**
- If pipeline fails: Check error logs in DLT UI
- If "table not found": Verify Step 2 completed successfully

---

## Step 4: Run Detection Rules (2 minutes)

1. **Open:** `03_detection_rules.py`
2. **Click:** Run All
3. **Wait:** ~1-2 minutes

**What's happening:** Creating 1000+ security alerts from sample data

**Verify success:** Run this query in a new SQL cell:
```sql
SELECT severity, COUNT(*) as count
FROM security_detection_lab.security_logs.gold_security_alerts
GROUP BY severity;
```

You should see alerts across CRITICAL, HIGH, MEDIUM severities.

---

## Step 5: View Your Alerts (2 minutes)

### Quick Query to See Recent Alerts
```sql
SELECT 
  detection_time,
  alert_title,
  severity,
  user,
  host,
  description
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE severity IN ('CRITICAL', 'HIGH')
ORDER BY detection_time DESC
LIMIT 20;
```

**🎉 Congratulations!** You now have a working security detection platform!

---

## What You Just Built

In just 15 minutes, you created:

| Component | What It Does |
|-----------|--------------|
| **Unity Catalog** | Secure data governance layer |
| **Sample Data** | 29,000 realistic security events |
| **Bronze Tables** | Raw data ingestion layer |
| **Silver Tables** | Cleaned, normalized data |
| **Gold Tables** | Security alerts and detection rules |
| **9+ Detection Rules** | Automated threat detection |

---

## Next Steps (Choose Your Path)

### 🎯 Path 1: Quick Wins (10 more minutes)
1. Run `04_operationalize.py` for automation
2. Create your first dashboard (copy queries from `DASHBOARD_GUIDE.md`)
3. Schedule detection job to run every 15 minutes

### 📚 Path 2: Deep Learning (30-60 minutes)
1. Read full `README.md` for detailed explanations
2. Customize detection rules for your needs
3. Complete all lab exercises
4. Explore MITRE ATT&CK mappings

### 🚀 Path 3: Production Deployment (hours to days)
1. Connect real log sources (Sysmon, Okta, etc.)
2. Tune detection thresholds to reduce false positives
3. Integrate with SIEM/SOAR platforms
4. Build comprehensive dashboards for SOC team
5. Implement automated response playbooks

---

## Quick Reference

### Important Notebooks
- `01_workspace_setup.py` - Data generation
- `02_data_ingestion_dlt.py` - DLT pipeline
- `03_detection_rules.py` - Detection logic
- `04_operationalize.py` - Automation
- `validate_lab.py` - Validation script

### Important Tables
```sql
-- View raw logs
SELECT * FROM security_detection_lab.security_logs.bronze_sysmon LIMIT 10;

-- View normalized data  
SELECT * FROM security_detection_lab.security_logs.silver_sysmon_process LIMIT 10;

-- View alerts
SELECT * FROM security_detection_lab.security_logs.gold_security_alerts LIMIT 10;

-- View detection rules
SELECT * FROM security_detection_lab.security_logs.gold_detection_rules;
```

### Sample Queries

**Alert Summary:**
```sql
SELECT 
  severity,
  COUNT(*) as alert_count
FROM security_detection_lab.security_logs.gold_security_alerts
GROUP BY severity;
```

**Top Alerts:**
```sql
SELECT 
  alert_title,
  COUNT(*) as count
FROM security_detection_lab.security_logs.gold_security_alerts
GROUP BY alert_title
ORDER BY count DESC;
```

**MITRE Coverage:**
```sql
SELECT 
  mitre_tactic,
  mitre_technique,
  COUNT(*) as detections
FROM security_detection_lab.security_logs.gold_security_alerts
GROUP BY mitre_tactic, mitre_technique;
```

---

## Common Questions

### Q: Can I use this in production?
**A:** Yes! This is production-ready code. Just connect real log sources and tune detection rules.

### Q: How much does this cost?
**A:** Depends on usage. For this lab (~29K events), costs are minimal (<$1). Production scale will vary.

### Q: Can I add my own log sources?
**A:** Absolutely! Add new Bronze tables in Lab 02, then create Silver transformations.

### Q: How do I add more detection rules?
**A:** Copy existing rules in Lab 03 as templates. Modify the SQL logic for your use case.

### Q: Can I integrate with Slack/Teams?
**A:** Yes! See Lab 04 for webhook notification examples.

### Q: What about machine learning?
**A:** Lab covers SQL-based rules. ML detections can be added as advanced extension.

---

## Need Help?

### Documentation
- 📖 [Full Lab Guide](README.md) - Comprehensive documentation
- ⚡ [Quick Start](QUICKSTART.md) - Faster setup guide  
- 👨‍🏫 [Instructor Guide](INSTRUCTOR_GUIDE.md) - Teaching resources
- 📊 [Dashboard Guide](DASHBOARD_GUIDE.md) - Visualization queries

### Troubleshooting
- Run `validate_lab.py` to check setup
- Check `INSTRUCTOR_GUIDE.md` troubleshooting section
- Review error messages in notebook cells

### Support Channels
- 💬 Databricks Community Forum
- 📧 security-lab@company.com
- 🐛 GitHub Issues

---

## Keyboard Shortcuts (Databricks)

- `Shift + Enter` - Run current cell
- `Ctrl/Cmd + Enter` - Run cell and move to next
- `Esc` then `A` - Add cell above
- `Esc` then `B` - Add cell below
- `Esc` then `DD` - Delete cell

---

## What's Included

```
databricks-security-detection-lab/
├── 01_workspace_setup.py          # Lab 1: Setup & data generation
├── 02_data_ingestion_dlt.py       # Lab 2: DLT pipeline
├── 03_detection_rules.py          # Lab 3: Detection logic
├── 04_operationalize.py           # Lab 4: Automation
├── validate_lab.py                # Validation script
├── README.md                      # Complete guide
├── QUICKSTART.md                  # 15-min setup
├── INSTRUCTOR_GUIDE.md            # Teaching guide
├── DASHBOARD_GUIDE.md             # Dashboard SQL
├── MITRE_ATTACK_MAPPING.md        # Coverage analysis
└── PROJECT_SUMMARY.md             # This overview
```

---

## Success Checklist

After setup, you should have:

- ✅ 4 raw data files (~29K events)
- ✅ 4 Bronze tables (raw data)
- ✅ 5 Silver tables (normalized)
- ✅ 1 Gold alerts table
- ✅ 1000+ security alerts
- ✅ 9+ detection rules
- ✅ MITRE ATT&CK coverage (9 techniques, 6 tactics)

**Verify:** Run `validate_lab.py` - should pass all tests!

---

## Ready to Start?

👉 **Begin with:** `01_workspace_setup.py`

**Or** jump to:
- ⚡ [QUICKSTART.md](QUICKSTART.md) - Fastest path (15 min)
- 📖 [README.md](README.md) - Detailed guide (45-60 min)

---

**Happy Detecting! 🔍🛡️**

*Questions? Stuck? Check the troubleshooting section or run `validate_lab.py` for diagnostics.*

