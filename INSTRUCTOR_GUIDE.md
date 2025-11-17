# Instructor Guide: Databricks Security Detection Engineering Lab

## Overview
This guide provides instructors with detailed information for delivering the Security Detection Engineering hands-on lab.

**Total Duration:** 45-60 minutes  
**Skill Level:** Intermediate  
**Prerequisites:** Basic SQL, security concepts familiarity  
**Maximum Class Size:** 30 participants

---

## Lab Setup (Before Class)

### 1. Workspace Preparation (30 minutes before)

#### Create Student Accounts (if needed)
- Ensure all participants have Databricks workspace access
- Assign appropriate permissions:
  - CREATE CATALOG (or provide shared catalog)
  - CREATE SCHEMA
  - CREATE TABLE
  - CREATE VOLUME
  - CREATE PIPELINE
  - CREATE JOB

#### Pre-deploy Resources (Optional for faster labs)
If time is limited, you can pre-deploy:
- Unity Catalog structure
- Sample data files
- DLT pipeline (paused)

```bash
# Use provided setup script
python scripts/instructor_setup.py --workspace <URL> --num-students 30
```

#### Test Environment
- Run through all notebooks yourself
- Verify sample data generation works
- Test DLT pipeline creation
- Check dashboard queries execute
- Ensure webhook notifications work (if using)

### 2. Required Materials

**For Instructor:**
- [ ] Laptop with Databricks access
- [ ] Presentation slides (optional)
- [ ] Demo environment (separate from student workspace)
- [ ] Backup sample data (in case of generation issues)

**For Students:**
- [ ] Laptop with web browser
- [ ] Databricks workspace credentials
- [ ] Lab instructions (README.md)
- [ ] Note-taking materials

### 3. Room Setup
- [ ] Projector/screen for demonstrations
- [ ] Stable Wi-Fi connection
- [ ] Power outlets accessible
- [ ] Seating arrangement for group work (optional)

---

## Detailed Lesson Plan

### Introduction (5 minutes)

#### Welcome and Objectives
"Welcome to the Security Detection Engineering lab on Databricks. Today, you'll learn how to build a production-grade security detection platform using modern data lakehouse architecture."

**Learning Objectives:** (display on screen)
1. Understand security data pipelines (Bronze → Silver → Gold)
2. Write effective detection rules using SQL
3. Operationalize detections with automation
4. Visualize security metrics with dashboards

#### Logistics
- Location of restrooms
- Break schedule (optional for 1-hour lab)
- Q&A approach (ask anytime vs. hold for end)
- Troubleshooting support (raise hand, use chat, etc.)

#### Ice Breaker Question (optional)
"How many of you have experience with: SIEM platforms? Python/SQL? Machine learning?"

---

### Lab 01: Workspace Setup (10 minutes)

#### Introduction to Module (2 min)
**Key Concepts to Cover:**
- Unity Catalog: 3-level namespace (Catalog → Schema → Table/Volume)
- Sample data importance: realistic patterns matter
- Security log types: process, authentication, API, network

**Common Questions:**
- Q: "Why Unity Catalog vs. Hive Metastore?"
  - A: Fine-grained access control, data lineage, cross-cloud support
- Q: "Is this sample data realistic?"
  - A: Yes, patterns are based on real attacks; volumes scaled for lab

#### Walkthrough (3 min)
**Demo on Screen:**
1. Show catalog creation command
2. Highlight Faker library for realistic data
3. Point out `is_malicious` flag (for validation only)
4. Show file output in Volumes

**Tips:**
- Emphasize the ~5% malicious data ratio (realistic)
- Mention that in production, they'd use real log sources
- Point out the timestamp generation for time-based detections

#### Hands-On Time (5 min)
**Circulate and assist with:**
- Python kernel restart issues (`dbutils.library.restartPython()`)
- Permission errors (catalog creation)
- Slow data generation (adjust NUM_EVENTS variables)

**Expected Issues:**
1. **Faker import fails:** Restart Python kernel
2. **Catalog already exists:** Skip error or use different name
3. **Slow generation:** Reduce event counts by 50%

#### Validation Checkpoint
"Everyone should have 4 JSON files in their volume. Raise hand if stuck."

---

### Lab 02: Data Ingestion (10 minutes)

#### Introduction to Module (2 min)
**Key Concepts:**
- **Medallion Architecture:** Raw → Clean → Business-level
- **Auto Loader:** Incremental ingestion with schema inference
- **Delta Live Tables:** Declarative ETL framework
- **Data Quality:** Expectations and constraints

**Common Questions:**
- Q: "Why three layers (Bronze, Silver, Gold)?"
  - A: Separation of concerns, reprocessing capability, audit trail
- Q: "What's the difference between Auto Loader and Structured Streaming?"
  - A: Auto Loader has schema inference, file tracking, cost optimization

#### Walkthrough (3 min)
**Demo on Screen:**
1. Show `@dlt.table` decorator syntax
2. Highlight schema evolution with cloudFiles
3. Point out `expect_all` for data quality
4. Show enrichment logic (threat_indicator field)

**Architecture Diagram:**
Draw on whiteboard/screen:
```
Volume (JSON) → Bronze (Raw) → Silver (Normalized) → Gold (Alerts)
     ↓              ↓                  ↓                  ↓
 Auto Loader   Streaming DF      Transformations    Detection Rules
```

#### Hands-On Time (5 min)
**Circulate and assist with:**
- DLT pipeline creation (UI can be confusing first time)
- Cluster configuration (single node sufficient)
- Pipeline execution errors

**Expected Issues:**
1. **Pipeline won't start:** Check cluster permissions
2. **Schema evolution errors:** Enable `cloudFiles.schemaEvolutionMode`
3. **Tables not appearing:** DLT creates in target schema (check path)

**Important:** Tell students to wait for pipeline to complete before moving on (~2-3 minutes)

#### Validation Checkpoint
"Your DLT pipeline should show green checkmarks for all tables. Check the DAG view."

---

### Lab 03: Detection Logic (15 minutes)

#### Introduction to Module (3 min)
**Key Concepts:**
- **Detection Types:**
  1. Signature-based: Known patterns (e.g., mimikatz.exe)
  2. Threshold-based: Statistical rules (e.g., >5 failed logins)
  3. Anomaly-based: ML models (optional/advanced)
  
- **MITRE ATT&CK Framework:** Standard for categorizing adversary tactics and techniques

**Discussion Questions:**
- "What's worse: false positives or false negatives?"
  - Guide discussion: Depends on context, but FP cause alert fatigue
- "How do you balance detection coverage vs. alert volume?"
  - Answer: Prioritize high-impact, start with low FP rules, iterate

#### Walkthrough (5 min)
**Demo Signature Detection:**
```sql
-- Show mimikatz detection on screen
SELECT * FROM silver_sysmon_process
WHERE LOWER(process_name) LIKE '%mimikatz%';
```

**Demo Threshold Detection:**
```sql
-- Show brute force logic
SELECT user_email, COUNT(*) as failures
FROM silver_okta_auth
WHERE outcome = 'FAILURE'
GROUP BY user_email
HAVING COUNT(*) >= 5;
```

**Highlight:**
- Simple SQL = powerful detections
- Window functions for time-based rules
- Gold table for alert management

#### Hands-On Time (7 min)
**Tasks:**
1. Run all detection queries
2. Review Gold alerts table
3. Examine detection rule metadata
4. (Optional) Create custom detection rule

**Circulate and assist with:**
- SQL syntax errors
- Understanding window functions
- Interpreting MITRE techniques

**Expected Issues:**
1. **No alerts generated:** Check that Lab 01 injected malicious samples
2. **Queries timeout:** Use SQL Warehouse instead of cluster
3. **MITRE technique confusion:** Show ATT&CK website for reference

**Challenge Exercise (for fast finishers):**
"Create a detection for suspicious RDP connections (LogonType = 10) from external IPs"

```sql
-- Solution:
SELECT *
FROM silver_windows_auth
WHERE 
  logon_type = 10
  AND source_ip NOT LIKE '10.%'
  AND source_ip NOT LIKE '192.168.%';
```

#### Validation Checkpoint
"Everyone should have rows in gold_security_alerts. Check alert counts by severity."

---

### Lab 04: Operationalization (10 minutes)

#### Introduction to Module (2 min)
**Key Concepts:**
- **Workflows:** Scheduled job execution
- **Alert Management:** Status tracking, assignment, notes
- **Notifications:** Integration with external tools
- **Testing:** Validation with known samples

**Real-World Context:**
"In production SOCs, these detections run every 5-15 minutes, generate thousands of alerts daily, and integrate with ticketing systems like ServiceNow."

#### Walkthrough (3 min)
**Demo on Screen:**
1. Show `run_all_detections()` function
2. Demonstrate alert status update
3. Show notification format
4. Run test data injection
5. Verify test alerts appear

**Emphasize:**
- Automated scheduling critical for 24/7 monitoring
- Alert fatigue management through tuning
- Importance of validation testing

#### Hands-On Time (5 min)
**Tasks:**
1. Run detection pipeline
2. Update alert statuses
3. Inject test samples
4. Export alerts to JSON

**Circulate and assist with:**
- Understanding job creation (UI vs. API)
- Alert status workflow
- Export file locations

**Expected Issues:**
1. **Job creation fails:** Permission issues (CREATE JOB)
2. **Test data not detected:** Re-run detection queries
3. **Export path not found:** Check Volumes path

#### Validation Checkpoint
"Everyone should see test alerts with hostname TEST-WORKSTATION-999."

---

### Dashboard Demo (5 minutes)

**Note:** If time is limited, this can be instructor demo only (no hands-on)

#### Show Pre-built Dashboards
1. **SOC Overview Dashboard:**
   - Point out key metrics (alert counts, severity distribution)
   - Explain MTTD (Mean Time to Detect)
   
2. **Detection Performance Dashboard:**
   - Show true positive vs. false positive rates
   - Explain why rule tuning matters
   
3. **Threat Hunting Dashboard:**
   - Demonstrate drill-down investigation
   - Show how to correlate events

#### Dashboard Creation Instructions
"Full SQL queries are in DASHBOARD_GUIDE.md. Creating dashboards is straightforward:"
1. Copy query from guide
2. Paste into Databricks SQL
3. Choose visualization
4. Add to dashboard

**Time Permitting:**
Have students create one simple widget (Alert Summary)

---

## Break Points (for longer sessions)

If running as 90-minute workshop with break:
- **Break 1:** After Lab 02 (25 minutes in)
- **Break 2:** After Lab 03 (40 minutes in)

---

## Troubleshooting Guide

### Common Student Issues

#### Issue 1: "Catalog not found" Error
**Symptoms:** Cannot create or use catalog
**Causes:** 
- Insufficient permissions
- Typo in catalog name
- Unity Catalog not enabled

**Solutions:**
1. Check user has CREATE CATALOG permission
2. Use existing shared catalog: `spark.sql("USE CATALOG hive_metastore")`
3. Contact workspace admin

#### Issue 2: DLT Pipeline Fails
**Symptoms:** Pipeline shows red error state
**Causes:**
- Invalid syntax in transformations
- Schema mismatch
- Cluster permission issues

**Solutions:**
1. Check DLT error logs (click on failed task)
2. Verify source data files exist in Volume
3. Use smaller dataset for testing
4. Restart pipeline with "Full Refresh"

#### Issue 3: No Alerts Generated
**Symptoms:** `gold_security_alerts` table is empty
**Causes:**
- Detection thresholds too high
- Sample data didn't include malicious patterns
- Time window filters exclude all data

**Solutions:**
1. Check silver tables have data: `SELECT COUNT(*) FROM silver_sysmon_process`
2. Verify malicious samples exist: `SELECT * FROM silver_sysmon_process WHERE threat_indicator != 'normal'`
3. Adjust detection thresholds (reduce from 5 to 2 failures, etc.)
4. Re-run Lab 01 data generation

#### Issue 4: Slow Query Performance
**Symptoms:** Queries take >30 seconds
**Causes:**
- Running on small cluster
- Large time windows
- No partitioning

**Solutions:**
1. Use SQL Warehouse instead of cluster
2. Reduce time ranges (7 days → 24 hours)
3. Add LIMIT clauses for testing
4. Enable query result caching

#### Issue 5: Permission Denied Errors
**Symptoms:** Cannot create tables, volumes, or jobs
**Causes:**
- Insufficient workspace permissions
- Unity Catalog access control

**Solutions:**
1. Request permissions from workspace admin
2. Use shared resources (catalog, schema)
3. Skip job creation (manual execution only)

---

## Advanced Topics (for expert classes or follow-up sessions)

### 1. Machine Learning-Based Anomaly Detection
**Duration:** +30 minutes

Add module on:
- User behavior analytics (UEBA)
- Isolation forest for outlier detection
- Time-series forecasting for baseline

**Sample Code:**
```python
from pyspark.ml.clustering import KMeans
from pyspark.ml.feature import VectorAssembler

# Cluster users by behavior
features = ['login_count', 'unique_ips', 'failed_attempts']
assembler = VectorAssembler(inputCols=features, outputCol='features')
data = assembler.transform(user_activity_df)

kmeans = KMeans(k=5, seed=42)
model = kmeans.fit(data)
predictions = model.transform(data)

# Flag users in unusual clusters as anomalous
```

### 2. Threat Intelligence Integration
**Duration:** +20 minutes

Show how to:
- Ingest IOC feeds (AlienVault, MISP)
- Enrich logs with threat intel
- Auto-update detection rules

### 3. Response Automation
**Duration:** +20 minutes

Demonstrate:
- Automated account disabling (via API)
- Host isolation triggers
- Ticketing system integration (ServiceNow, Jira)

### 4. Purple Team Exercise
**Duration:** +30 minutes

Live red team/blue team simulation:
- Instructor runs attack simulation (Atomic Red Team)
- Students detect with platform
- Discussion of detection gaps

---

## Assessment and Feedback

### Knowledge Check Questions

**After Lab 01:**
1. What are the three levels of Unity Catalog? (Catalog, Schema, Table/Volume)
2. Why do we generate sample data instead of using random data? (Realistic patterns)

**After Lab 02:**
3. What are the three layers in Medallion Architecture? (Bronze, Silver, Gold)
4. What's the benefit of Auto Loader over manual file reading? (Schema inference, incremental)

**After Lab 03:**
5. What's the difference between signature and threshold detections? (Known patterns vs. statistical)
6. Why map detections to MITRE ATT&CK? (Standard framework, coverage analysis)

**After Lab 04:**
7. How often should detection rules run in production? (5-15 minutes typical)
8. What's more important to minimize: false positives or false negatives? (Depends, but FP cause fatigue)

### Lab Completion Criteria

Students have successfully completed the lab if they:
- ✅ Generated sample security logs (4 types)
- ✅ Created DLT pipeline with Bronze → Silver transformations
- ✅ Executed at least 5 detection rules
- ✅ Populated gold_security_alerts table
- ✅ Validated detections with test samples

### Feedback Survey (post-lab)

Use Google Form or similar:
1. Rate difficulty (1-5)
2. Rate pace (too fast / just right / too slow)
3. Most valuable learning
4. Suggestions for improvement
5. Would you recommend this lab?

---

## Post-Lab Follow-up

### For Students

**Next Steps Email Template:**
```
Subject: Databricks Security Detection Lab - Resources and Next Steps

Hi [Student],

Thanks for participating in today's lab! Here are resources for continued learning:

📚 Resources:
- Lab materials: [GitHub link]
- MITRE ATT&CK: https://attack.mitre.org
- Sigma rules library: https://github.com/SigmaHQ/sigma
- Databricks documentation: https://docs.databricks.com

🎯 Practice Projects:
1. Add 5 more detection rules from Sigma
2. Integrate with your own log sources
3. Build comprehensive dashboard set
4. Implement ML-based anomaly detection

📞 Support:
- Questions? Email: security-lab@company.com
- Community: [Slack/Discord link]

Best regards,
[Instructor Name]
```

### For Instructors

**After-Action Review:**
- [ ] Review feedback survey results
- [ ] Identify common pain points
- [ ] Update lab materials accordingly
- [ ] Document timing adjustments needed
- [ ] Note technical issues for future sessions

---

## Additional Resources

### Presentation Slides (if creating)

**Suggested Slide Deck:**
1. Title slide
2. Agenda and objectives
3. Security operations challenges
4. Databricks architecture overview
5. Medallion architecture explained
6. Detection engineering principles
7. MITRE ATT&CK framework intro
8. Demo: Lab walkthrough (screenshots)
9. Q&A and next steps
10. Thank you / contact info

### Handouts

- **Quick Reference Card:**
  - Common SQL patterns for detections
  - MITRE ATT&CK tactic/technique list
  - Databricks keyboard shortcuts
  
- **Cheat Sheet:**
  - DLT syntax examples
  - Alert status workflow
  - Dashboard query templates

### Pre-recorded Videos (optional)

For hybrid/async delivery:
- Lab 01 walkthrough (5 min)
- Lab 02 DLT pipeline creation (5 min)
- Lab 03 detection examples (7 min)
- Lab 04 operationalization (5 min)

---

## Contact and Support

**Lab Maintainer:** [Your Name]  
**Email:** [your.email@company.com]  
**Office Hours:** [Schedule]  
**GitHub Issues:** [Repository URL]

---

## Version History

- **v1.0** (2024-10-24): Initial release
- Future: Add ML module, extend to 2-hour format, add certification quiz

---

**Happy Teaching! 🎓**

