# Databricks notebook source
# MAGIC %md
# MAGIC # Lab 04: Operationalize and Validate Detection System
# MAGIC
# MAGIC ## Overview
# MAGIC In this lab, you will:
# MAGIC 1. Schedule automated detection workflows
# MAGIC 2. Configure alert routing and notifications
# MAGIC 3. Test detections with validation samples
# MAGIC 4. Build security dashboards for visualization
# MAGIC 5. Export alerts via API
# MAGIC
# MAGIC **Time:** ~10 minutes
# MAGIC
# MAGIC ## Production Architecture
# MAGIC ```
# MAGIC Delta Live Tables → Detection Rules → Gold Alerts
# MAGIC       ↓                   ↓               ↓
# MAGIC  (Streaming)      (Scheduled Job)  (Dashboard)
# MAGIC                                           ↓
# MAGIC                                      (API/Export)
# MAGIC ```

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

# DBTITLE 1,Setup
from pyspark.sql.functions import *
from datetime import datetime, timedelta
import json
import requests

# Configuration
CATALOG_NAME = "security_detection_engineering_lab"
SCHEMA_NAME = "security_logs"

# Set context
spark.sql(f"USE CATALOG {CATALOG_NAME}")
spark.sql(f"USE SCHEMA {SCHEMA_NAME}")

# Get workspace context for API calls
try:
    ctx = dbutils.notebook.entry_point.getDbutils().notebook().getContext()
    workspace_url = ctx.apiUrl().get()
    token = ctx.apiToken().get()
    notebook_path = ctx.notebookPath().get()
    print(f"✅ Workspace URL: {workspace_url}")
    print(f"✅ Notebook Path: {notebook_path}")
except:
    print("⚠️  Could not get workspace context (may be running outside Databricks)")
    workspace_url = None
    token = None

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 1: Automated Detection Workflow
# MAGIC
# MAGIC Create a job that runs detection rules on a schedule

# COMMAND ----------

# DBTITLE 1,Detection Runner Function
def run_all_detections():
    """
    Execute all detection rules and populate gold_security_alerts
    Returns summary of new alerts
    """
    
    print("=" * 80)
    print("RUNNING DETECTION PIPELINE")
    print("=" * 80)
    
    # Get starting alert count
    initial_count = spark.sql("SELECT COUNT(*) as cnt FROM gold_security_alerts").collect()[0]['cnt']
    print(f"\n📊 Initial alert count: {initial_count}")
    
    # Dictionary to track new alerts per rule
    new_alerts = {}
    
    # Run each detection rule
    detection_rules = [
        ('detect_mimikatz', 'Mimikatz detections'),
        ('detect_suspicious_powershell', 'PowerShell detections'),
        ('detect_psexec', 'PsExec detections'),
        ('detect_okta_bruteforce', 'Okta brute force'),
        ('detect_windows_bruteforce', 'Windows brute force'),
        ('detect_aws_api_failures', 'AWS API failures'),
        ('detect_network_scanning', 'Network scanning'),
        ('detect_impossible_travel', 'Impossible travel'),
        ('detect_aws_privilege_escalation', 'AWS privilege escalation')
    ]
    
    print("\n🔍 Running detection rules...\n")
    
    for rule_name, description in detection_rules:
        try:
            # Check if view exists and has data
            result = spark.sql(f"SELECT COUNT(*) as cnt FROM {rule_name}")
            count = result.collect()[0]['cnt']
            
            if count > 0:
                new_alerts[rule_name] = count
                print(f"  ✓ {description:30s} - {count:3d} alerts")
            else:
                print(f"  ○ {description:30s} - No alerts")
                
        except Exception as e:
            print(f"  ✗ {description:30s} - Error: {str(e)[:50]}")
    
    # Get final alert count
    final_count = spark.sql("SELECT COUNT(*) as cnt FROM gold_security_alerts").collect()[0]['cnt']
    new_total = final_count - initial_count
    
    print(f"\n📊 Final alert count: {final_count}")
    print(f"📊 New alerts generated: {new_total}")
    print("=" * 80)
    
    return new_alerts

# Run detection pipeline
alert_summary = run_all_detections()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 2: Alert Enrichment and Prioritization

# COMMAND ----------

# DBTITLE 1,Enrich Alerts with Risk Scores
# MAGIC %sql
# MAGIC -- Add risk score to alerts based on multiple factors
# MAGIC CREATE OR REPLACE TEMP VIEW enriched_alerts AS
# MAGIC SELECT
# MAGIC   *,
# MAGIC   CASE severity
# MAGIC     WHEN 'CRITICAL' THEN 100
# MAGIC     WHEN 'HIGH' THEN 75
# MAGIC     WHEN 'MEDIUM' THEN 50
# MAGIC     WHEN 'LOW' THEN 25
# MAGIC     ELSE 0
# MAGIC   END AS base_risk_score,
# MAGIC   
# MAGIC   -- Calculate composite risk score
# MAGIC   (
# MAGIC     CASE severity
# MAGIC       WHEN 'CRITICAL' THEN 100
# MAGIC       WHEN 'HIGH' THEN 75
# MAGIC       WHEN 'MEDIUM' THEN 50
# MAGIC       WHEN 'LOW' THEN 25
# MAGIC       ELSE 0
# MAGIC     END +
# MAGIC     
# MAGIC     -- Boost for credential access techniques
# MAGIC     CASE WHEN mitre_tactic = 'Credential Access' THEN 20 ELSE 0 END +
# MAGIC     
# MAGIC     -- Boost for privilege escalation
# MAGIC     CASE WHEN mitre_tactic = 'Privilege Escalation' THEN 15 ELSE 0 END +
# MAGIC     
# MAGIC     -- Boost for lateral movement
# MAGIC     CASE WHEN mitre_tactic = 'Lateral Movement' THEN 15 ELSE 0 END
# MAGIC     
# MAGIC   ) AS composite_risk_score,
# MAGIC   
# MAGIC   -- Priority for SOC triage
# MAGIC   CASE
# MAGIC     WHEN severity = 'CRITICAL' THEN 'P1 - Immediate'
# MAGIC     WHEN severity = 'HIGH' THEN 'P2 - Urgent'
# MAGIC     WHEN severity = 'MEDIUM' THEN 'P3 - Normal'
# MAGIC     ELSE 'P4 - Low'
# MAGIC   END AS priority,
# MAGIC   
# MAGIC   -- Recommended response time (SLA)
# MAGIC   CASE
# MAGIC     WHEN severity = 'CRITICAL' THEN 15  -- 15 minutes
# MAGIC     WHEN severity = 'HIGH' THEN 60      -- 1 hour
# MAGIC     WHEN severity = 'MEDIUM' THEN 240   -- 4 hours
# MAGIC     ELSE 1440                            -- 24 hours
# MAGIC   END AS response_time_minutes
# MAGIC   
# MAGIC FROM gold_security_alerts
# MAGIC WHERE status = 'NEW'
# MAGIC ORDER BY composite_risk_score DESC;
# MAGIC
# MAGIC SELECT * FROM enriched_alerts LIMIT 20;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 3: Alert Notification System

# COMMAND ----------

# DBTITLE 1,Send Alerts to Webhook (Slack/Teams/PagerDuty)
def send_alert_notification(alert_data, webhook_url=None):
    """
    Send alert to external webhook (Slack, Teams, PagerDuty, etc.)
    
    For demo purposes, this prints the alert.
    In production, you would send to actual webhook.
    """
    
    if webhook_url:
        # Production: Send to webhook
        try:
            payload = {
                "text": f"🚨 Security Alert: {alert_data['alert_title']}",
                "attachments": [{
                    "color": "danger" if alert_data['severity'] in ['CRITICAL', 'HIGH'] else "warning",
                    "fields": [
                        {"title": "Severity", "value": alert_data['severity'], "short": True},
                        {"title": "User", "value": alert_data.get('user', 'N/A'), "short": True},
                        {"title": "Host", "value": alert_data.get('host', 'N/A'), "short": True},
                        {"title": "MITRE Technique", "value": alert_data['mitre_technique'], "short": True},
                        {"title": "Description", "value": alert_data['description'], "short": False}
                    ]
                }]
            }
            
            response = requests.post(webhook_url, json=payload)
            return response.status_code == 200
            
        except Exception as e:
            print(f"❌ Error sending notification: {e}")
            return False
    else:
        # Demo mode: Print alert
        print("=" * 80)
        print(f"🚨 SECURITY ALERT NOTIFICATION")
        print("=" * 80)
        print(f"Title:       {alert_data['alert_title']}")
        print(f"Severity:    {alert_data['severity']}")
        print(f"MITRE:       {alert_data['mitre_technique']} - {alert_data['mitre_tactic']}")
        print(f"User:        {alert_data.get('user', 'N/A')}")
        print(f"Host:        {alert_data.get('host', 'N/A')}")
        print(f"Source IP:   {alert_data.get('source_ip', 'N/A')}")
        print(f"Description: {alert_data['description']}")
        print("=" * 80)
        return True

# Demo: Send notification for critical alerts
critical_alerts = spark.sql("""
    SELECT *
    FROM gold_security_alerts
    WHERE severity = 'CRITICAL'
    AND status = 'NEW'
    LIMIT 5
""").collect()

print(f"Found {len(critical_alerts)} critical alerts to notify\n")

for alert in critical_alerts[:3]:  # Send first 3 for demo
    alert_dict = alert.asDict()
    send_alert_notification(alert_dict)
    print()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 4: Alert Investigation Workflow

# COMMAND ----------

# DBTITLE 1,Alert Triage Functions
def update_alert_status(alert_id, new_status, assigned_to=None, notes=None):
    """
    Update alert status for investigation workflow
    """
    
    update_parts = [f"status = '{new_status}'", "updated_at = current_timestamp()"]
    
    if assigned_to:
        update_parts.append(f"assigned_to = '{assigned_to}'")
    
    if notes:
        # Escape single quotes in notes
        notes_escaped = notes.replace("'", "''")
        update_parts.append(f"notes = '{notes_escaped}'")
    
    update_clause = ", ".join(update_parts)
    
    query = f"""
        UPDATE gold_security_alerts
        SET {update_clause}
        WHERE alert_id = '{alert_id}'
    """
    
    spark.sql(query)
    print(f"✅ Alert {alert_id} updated to {new_status}")

# Demo: Update some alerts
sample_alerts = spark.sql("""
    SELECT alert_id, alert_title
    FROM gold_security_alerts
    WHERE status = 'NEW'
    LIMIT 3
""").collect()

if len(sample_alerts) > 0:
    print("Demo: Updating alert statuses\n")
    
    # Mark first as investigating
    update_alert_status(
        sample_alerts[0]['alert_id'],
        'INVESTIGATING',
        assigned_to='analyst@company.com',
        notes='Initial triage: checking with user'
    )
    
    # Mark second as false positive
    if len(sample_alerts) > 1:
        update_alert_status(
            sample_alerts[1]['alert_id'],
            'FALSE_POSITIVE',
            assigned_to='analyst@company.com',
            notes='Verified: legitimate admin activity'
        )
    
    # Display updated alerts
    print("\n📋 Updated Alerts:")
    display(spark.sql("""
        SELECT alert_id, alert_title, status, assigned_to, notes
        FROM gold_security_alerts
        WHERE status != 'NEW'
        LIMIT 10
    """))
else:
    print("⚠️  No alerts found to update")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 5: Validation Testing
# MAGIC
# MAGIC **Note:** Testing with malicious samples requires either:
# MAGIC - A **SQL Warehouse** (recommended)
# MAGIC - Or creating **separate test tables** (not DLT streaming tables)
# MAGIC
# MAGIC Since DLT creates streaming tables, we cannot directly INSERT into them from a cluster.

# COMMAND ----------

# DBTITLE 1,Option 1: Create Test Tables (Recommended)
print("🧪 Creating separate test tables for validation...\n")

# Create test tables that are NOT part of DLT pipeline
# These are regular Delta tables that we can insert into

# Test 1: Mimikatz execution
print("Creating test data for Mimikatz detection...")
test_mimikatz = spark.createDataFrame([
    {
        "event_time": datetime.now(),
        "host": "TEST-WORKSTATION-999",
        "process_name": "mimikatz.exe",
        "process_id": 9999,
        "command_line": "mimikatz.exe sekurlsa::logonpasswords",
        "user": "test_user",
        "parent_process_name": "cmd.exe",
        "parent_process_id": 9998,
        "file_hash_sha256": "test_hash_mimikatz",
        "threat_indicator": "suspicious_process",
        "log_source": "sysmon",
        "event_category": "process_creation",
        "processed_timestamp": datetime.now()
    }
])

# Create separate test table (not streaming)
test_mimikatz.write.mode("overwrite").saveAsTable("test_sysmon_process")
print("✅ Test table 'test_sysmon_process' created with Mimikatz sample")

# Test 2: Brute force login attempts
print("\nCreating test data for brute force detection...")
test_bruteforce = spark.createDataFrame([
    {
        "event_time": datetime.now() - timedelta(minutes=i),
        "event_id": f"test-bf-{i}",
        "event_type": "user.authentication.sso",
        "user_email": "test.victim@company.com",
        "user_name": "Test Victim",
        "source_ip": "192.168.100.100",
        "user_agent": "Mozilla/5.0",
        "city": "Unknown",
        "country": "Unknown",
        "outcome": "FAILURE",
        "failure_reason": "INVALID_CREDENTIALS",
        "target_application": "Salesforce",
        "risk_indicator": "failed_auth",
        "log_source": "okta",
        "event_category": "authentication",
        "processed_timestamp": datetime.now()
    }
    for i in range(10)  # 10 failed attempts
])

test_bruteforce.write.mode("overwrite").saveAsTable("test_okta_auth")
print("✅ Test table 'test_okta_auth' created with brute force samples")

# Test 3: Suspicious PowerShell
print("\nCreating test data for PowerShell detection...")
test_powershell = spark.createDataFrame([
    {
        "event_time": datetime.now(),
        "host": "TEST-WORKSTATION-999",
        "process_name": "powershell.exe",
        "process_id": 10000,
        "command_line": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA",
        "user": "test_user",
        "parent_process_name": "explorer.exe",
        "parent_process_id": 9999,
        "file_hash_sha256": "test_hash_ps",
        "threat_indicator": "suspicious_commandline",
        "log_source": "sysmon",
        "event_category": "process_creation",
        "processed_timestamp": datetime.now()
    }
])

# Append to test table
test_powershell.write.mode("append").saveAsTable("test_sysmon_process")
print("✅ Test table updated with PowerShell sample")

print("\n🧪 Test data creation complete!")
print("\n📊 Test Tables Created:")
print("  • test_sysmon_process: 2 samples (Mimikatz + PowerShell)")
print("  • test_okta_auth: 10 samples (Brute force attempts)")

# COMMAND ----------

# DBTITLE 1,Run Detection Rules on Test Data
print("🔍 Running detection rules on test data...\n")
print("=" * 80)

# Test Detection 1: Mimikatz
print("\nTEST 1: Mimikatz Detection")
print("-" * 80)
mimikatz_detections = spark.sql("""
    SELECT
        'detect_mimikatz' as detection_rule,
        event_time,
        host,
        user,
        process_name,
        command_line,
        'CRITICAL' as severity,
        'Mimikatz Credential Dumping Detected' as alert_title
    FROM test_sysmon_process
    WHERE LOWER(process_name) LIKE '%mimikatz%'
    OR LOWER(command_line) LIKE '%sekurlsa::logonpasswords%'
""")

mimikatz_count = mimikatz_detections.count()
if mimikatz_count > 0:
    print(f"✅ PASS: Detected {mimikatz_count} Mimikatz event(s)")
    display(mimikatz_detections)
else:
    print("❌ FAIL: No Mimikatz events detected")

# Test Detection 2: Brute Force
print("\nTEST 2: Okta Brute Force Detection")
print("-" * 80)
bruteforce_detections = spark.sql("""
    SELECT
        'detect_okta_bruteforce' as detection_rule,
        user_email,
        source_ip,
        COUNT(*) as failure_count,
        MIN(event_time) as first_failure,
        MAX(event_time) as last_failure,
        'HIGH' as severity,
        'Okta Brute Force Attack Detected' as alert_title
    FROM test_okta_auth
    WHERE outcome = 'FAILURE'
    AND event_time >= current_timestamp() - INTERVAL 15 MINUTES
    GROUP BY user_email, source_ip
    HAVING COUNT(*) >= 5
""")

bruteforce_count = bruteforce_detections.count()
if bruteforce_count > 0:
    print(f"✅ PASS: Detected {bruteforce_count} brute force attack(s)")
    display(bruteforce_detections)
else:
    print("❌ FAIL: No brute force attacks detected (may need to adjust threshold)")

# Test Detection 3: Suspicious PowerShell
print("\nTEST 3: Suspicious PowerShell Detection")
print("-" * 80)
powershell_detections = spark.sql("""
    SELECT
        'detect_suspicious_powershell' as detection_rule,
        event_time,
        host,
        user,
        process_name,
        command_line,
        'HIGH' as severity,
        'Suspicious PowerShell Execution' as alert_title
    FROM test_sysmon_process
    WHERE LOWER(process_name) LIKE '%powershell%'
    AND (
        command_line LIKE '%-enc%'
        OR command_line LIKE '%-encodedcommand%'
        OR command_line LIKE '%-w hidden%'
    )
""")

powershell_count = powershell_detections.count()
if powershell_count > 0:
    print(f"✅ PASS: Detected {powershell_count} suspicious PowerShell event(s)")
    display(powershell_detections)
else:
    print("❌ FAIL: No suspicious PowerShell events detected")

# Summary
print("\n" + "=" * 80)
print("VALIDATION SUMMARY")
print("=" * 80)
total_tests = 3
#passed_tests = sum([
#    1 if mimikatz_count > 0 else 0,
#    1 if bruteforce_count > 0 else 0,
#    1 if powershell_count > 0 else 0
#])

passed_tests = __builtins__.sum([
    1 if mimikatz_count > 0 else 0,
    1 if bruteforce_count > 0 else 0,
    1 if powershell_count > 0 else 0
])

print(f"Tests Passed: {passed_tests}/{total_tests}")
if passed_tests == total_tests:
    print("✅ ALL DETECTION TESTS PASSED!")
else:
    print(f"⚠️  {total_tests - passed_tests} test(s) failed - review detection logic")

print("=" * 80)
print(f"Tests Passed: {passed_tests}/{total_tests}")
if passed_tests == total_tests:
    print("✅ ALL DETECTION TESTS PASSED!")
else:
    print(f"⚠️  {total_tests - passed_tests} test(s) failed - review detection logic")

print("=" * 80)

# COMMAND ----------

# DBTITLE 1,Option 2: Validation Using SQL Warehouse (Advanced)
# 
# If you need to test with actual Silver tables (DLT streaming tables),
# you must use a SQL Warehouse instead of a cluster.
#
# Steps:
# 1. Go to SQL → SQL Warehouses
# 2. Start a warehouse
# 3. Run this SQL in the SQL editor:
#
# -- Create test view that unions real data with test data
# CREATE OR REPLACE TEMPORARY VIEW combined_sysmon AS
# SELECT * FROM security_detection_lab.security_logs.silver_sysmon_process
# UNION ALL
# SELECT 
#   current_timestamp() as event_time,
#   'TEST-WORKSTATION-999' as host,
#   'mimikatz.exe' as process_name,
#   9999 as process_id,
#   'mimikatz.exe sekurlsa::logonpasswords' as command_line,
#   'test_user' as user,
#   'cmd.exe' as parent_process_name,
#   9998 as parent_process_id,
#   'test_hash' as file_hash_sha256,
#   'suspicious_process' as threat_indicator,
#   'sysmon' as log_source,
#   'process_creation' as event_category,
#   current_timestamp() as processed_timestamp;
#
# -- Run detection on combined view
# SELECT * FROM combined_sysmon
# WHERE LOWER(process_name) LIKE '%mimikatz%';
#
# Note: This is for advanced users who need to test with actual DLT tables.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 6: Export Alerts via API

# COMMAND ----------

# DBTITLE 1,Export Alerts to JSON
# Export recent alerts to JSON format
alerts_json = spark.sql("""
    SELECT
        alert_id,
        detection_time,
        event_time,
        alert_title,
        description,
        severity,
        mitre_technique,
        mitre_tactic,
        detection_rule,
        user,
        host,
        source_ip,
        status
    FROM gold_security_alerts
    WHERE detection_time >= current_timestamp() - INTERVAL 24 HOURS
    ORDER BY detection_time DESC
""").toPandas()

# Convert to JSON
alerts_json_str = alerts_json.to_json(orient='records', date_format='iso')

print(f"📤 Exported {len(alerts_json)} alerts to JSON")
print(f"\nSample JSON output (first 500 chars):")
print(alerts_json_str[:500] + "...")

# Save to volume for external access
export_path = f"/Volumes/{CATALOG_NAME}/{SCHEMA_NAME}/raw_logs/exports/alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
dbutils.fs.put(export_path, alerts_json_str, overwrite=True)
print(f"\n✅ Alerts exported to: {export_path}")

# COMMAND ----------

# DBTITLE 1,Export to CSV
# Export to CSV for spreadsheet analysis
csv_export_path = f"/Volumes/{CATALOG_NAME}/{SCHEMA_NAME}/raw_logs/exports/alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

# Create exports directory if it doesn't exist
try:
    dbutils.fs.mkdirs(f"/Volumes/{CATALOG_NAME}/{SCHEMA_NAME}/raw_logs/exports")
except:
    pass  # Directory may already exist

# Use dbutils.fs.put for reliable file write
csv_content = alerts_json.to_csv(index=False)
dbutils.fs.put(csv_export_path, csv_content, overwrite=True)

print(f"✅ Alerts exported to CSV: {csv_export_path}")
print(f"📊 Total records: {len(alerts_json)}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 7: Create Databricks Workflow Job
# MAGIC
# MAGIC Automate the detection pipeline with a scheduled job

# COMMAND ----------

# DBTITLE 1,Create Detection Job via API
def create_detection_job(job_name="Security Detection Pipeline"):
    """
    Create a Databricks workflow job for automated detection
    """
    
    if not workspace_url or not token:
        print("⚠️  Cannot create job: workspace context not available")
        return None
    
    # Job configuration
    job_config = {
        "name": job_name,
        "tasks": [
            {
                "task_key": "run_detections",
                "description": "Execute all detection rules",
                "notebook_task": {
                    "notebook_path": notebook_path,
                    "source": "WORKSPACE"
                },
                "existing_cluster_id": dbutils.notebook.entry_point.getDbutils().notebook().getContext().clusterId().get(),
                "timeout_seconds": 3600,
                "max_retries": 2
            }
        ],
        "schedule": {
            "quartz_cron_expression": "0 0/15 * * * ?",  # Every 15 minutes
            "timezone_id": "UTC",
            "pause_status": "UNPAUSED"
        },
        "email_notifications": {
            "on_failure": ["security-team@company.com"],
            "on_success": [],
            "no_alert_for_skipped_runs": True
        },
        "max_concurrent_runs": 1,
        "format": "MULTI_TASK"
    }
    
    try:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        # Check if job exists
        list_response = requests.get(
            f"{workspace_url}/api/2.1/jobs/list",
            headers=headers,
            params={"name": job_name}
        )
        
        if list_response.status_code == 200:
            jobs = list_response.json().get('jobs', [])
            matching_jobs = [j for j in jobs if j['settings']['name'] == job_name]
            
            if matching_jobs:
                job_id = matching_jobs[0]['job_id']
                print(f"✅ Job '{job_name}' already exists (ID: {job_id})")
                print(f"   View at: {workspace_url}#job/{job_id}")
                return job_id
        
        # Create new job
        response = requests.post(
            f"{workspace_url}/api/2.1/jobs/create",
            headers=headers,
            json=job_config
        )
        
        if response.status_code == 200:
            job_id = response.json()['job_id']
            print(f"✅ Job '{job_name}' created successfully!")
            print(f"   Job ID: {job_id}")
            print(f"   Schedule: Every 15 minutes")
            print(f"   View at: {workspace_url}#job/{job_id}")
            return job_id
        else:
            print(f"❌ Error creating job: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Exception creating job: {e}")
        return None

# Create the job (comment out if not ready for production)
# job_id = create_detection_job()

print("ℹ️  To create a scheduled job, uncomment the line above")
print("   The job will run detection rules every 15 minutes")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 8: Manual Job Creation Instructions
# MAGIC
# MAGIC If you prefer to create the job via UI:
# MAGIC
# MAGIC ### Steps:
# MAGIC 1. **Navigate to Workflows:**
# MAGIC    - Click **Workflows** in left sidebar
# MAGIC    - Click **Create Job**
# MAGIC
# MAGIC 2. **Configure Job:**
# MAGIC    ```
# MAGIC    Job Name: Security Detection Pipeline
# MAGIC    Task Type: Notebook
# MAGIC    Notebook: 03_detection_rules.py
# MAGIC    Cluster: (Select your cluster)
# MAGIC    ```
# MAGIC
# MAGIC 3. **Set Schedule:**
# MAGIC    ```
# MAGIC    Schedule: Every 15 minutes
# MAGIC    Cron: 0 0/15 * * * ?
# MAGIC    Timezone: UTC
# MAGIC    ```
# MAGIC
# MAGIC 4. **Configure Notifications:**
# MAGIC    ```
# MAGIC    On Failure: security-team@company.com
# MAGIC    ```
# MAGIC
# MAGIC 5. **Click "Create"** and **"Run Now"** to test

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 9: Performance Metrics

# COMMAND ----------

# DBTITLE 1,Detection Performance Dashboard
# MAGIC %sql
# MAGIC -- Detection pipeline performance metrics
# MAGIC SELECT
# MAGIC   '24 Hours' as time_period,
# MAGIC   COUNT(*) as total_alerts,
# MAGIC   COUNT(DISTINCT user) as affected_users,
# MAGIC   COUNT(DISTINCT host) as affected_hosts,
# MAGIC   COUNT(DISTINCT detection_rule) as triggered_rules,
# MAGIC   SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_alerts,
# MAGIC   SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_alerts,
# MAGIC   SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium_alerts,
# MAGIC   SUM(CASE WHEN status = 'TRUE_POSITIVE' THEN 1 ELSE 0 END) as true_positives,
# MAGIC   SUM(CASE WHEN status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) as false_positives,
# MAGIC   ROUND(
# MAGIC     SUM(CASE WHEN status = 'TRUE_POSITIVE' THEN 1 ELSE 0 END) * 100.0 / 
# MAGIC     NULLIF(SUM(CASE WHEN status IN ('TRUE_POSITIVE', 'FALSE_POSITIVE') THEN 1 ELSE 0 END), 0),
# MAGIC     2
# MAGIC   ) as true_positive_rate
# MAGIC FROM gold_security_alerts
# MAGIC WHERE detection_time >= current_timestamp() - INTERVAL 24 HOURS;

# COMMAND ----------

# DBTITLE 1,Detection Rule Effectiveness
# MAGIC %sql
# MAGIC -- Rule-by-rule performance
# MAGIC SELECT
# MAGIC   detection_rule,
# MAGIC   severity,
# MAGIC   COUNT(*) as alert_count,
# MAGIC   COUNT(DISTINCT user) as affected_users,
# MAGIC   MIN(detection_time) as first_detection,
# MAGIC   MAX(detection_time) as last_detection,
# MAGIC   SUM(CASE WHEN status = 'TRUE_POSITIVE' THEN 1 ELSE 0 END) as true_positives,
# MAGIC   SUM(CASE WHEN status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) as false_positives
# MAGIC FROM gold_security_alerts
# MAGIC GROUP BY detection_rule, severity
# MAGIC ORDER BY alert_count DESC;

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Lab 04 Summary
# MAGIC
# MAGIC ### What You Built:
# MAGIC ✅ **Automated detection pipeline** with scheduled execution  
# MAGIC ✅ **Alert enrichment** with risk scoring and prioritization  
# MAGIC ✅ **Notification system** for external alerting (Slack/Teams/PagerDuty)  
# MAGIC ✅ **Investigation workflow** with status tracking  
# MAGIC ✅ **Validation testing** with malicious samples  
# MAGIC ✅ **Export capabilities** (JSON, CSV, API)  
# MAGIC ✅ **Performance metrics** and dashboards  
# MAGIC
# MAGIC ### Operational Capabilities:
# MAGIC 1. **24/7 Monitoring:** Scheduled detection execution
# MAGIC 2. **Alert Triage:** Status tracking and assignment
# MAGIC 3. **Integration:** Webhook notifications to SOC tools
# MAGIC 4. **Validation:** Test framework for detection tuning
# MAGIC 5. **Reporting:** Metrics and effectiveness tracking
# MAGIC 6. **Export:** API access for external systems
# MAGIC
# MAGIC ### Next Steps (Production):
# MAGIC 1. **Enable scheduled job** for continuous monitoring
# MAGIC 2. **Configure webhook URLs** for Slack/Teams integration
# MAGIC 3. **Set up dashboards** (see Dashboard Guide)
# MAGIC 4. **Integrate with SIEM/SOAR** platforms
# MAGIC 5. **Implement response playbooks** for each detection
# MAGIC 6. **Establish on-call rotation** and escalation procedures
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## 🎓 Complete Lab Summary
# MAGIC
# MAGIC ### You've Successfully Built:
# MAGIC
# MAGIC **Lab 01:** Data ingestion and sample generation  
# MAGIC **Lab 02:** Bronze → Silver transformation pipeline  
# MAGIC **Lab 03:** Detection rule authoring (9+ rules)  
# MAGIC **Lab 04:** Operational deployment and validation  
# MAGIC
# MAGIC ### Production Checklist:
# MAGIC - [ ] Enable DLT pipeline for continuous ingestion
# MAGIC - [ ] Schedule detection job (every 15 minutes)
# MAGIC - [ ] Configure alert notifications
# MAGIC - [ ] Set up security dashboards
# MAGIC - [ ] Integrate with ticketing system
# MAGIC - [ ] Document response playbooks
# MAGIC - [ ] Train SOC team on platform
# MAGIC - [ ] Establish SLAs and KPIs
# MAGIC - [ ] Implement feedback loop for tuning
# MAGIC - [ ] Regular review and update of detection rules
# MAGIC
# MAGIC ### Resources:
# MAGIC - **Dashboard Queries:** See `dashboard_queries.sql`
# MAGIC - **API Documentation:** Databricks REST API
# MAGIC - **MITRE ATT&CK:** https://attack.mitre.org
# MAGIC - **Detection Engineering:** https://www.splunk.com/en_us/blog/security/detection-spectrum.html
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## 🎓 Instructor Notes
# MAGIC
# MAGIC ### Discussion Points:
# MAGIC 1. **SOC Operations:**
# MAGIC    - Alert triage process
# MAGIC    - Escalation procedures
# MAGIC    - Mean time to detect/respond (MTTD/MTTR)
# MAGIC
# MAGIC 2. **Detection Lifecycle:**
# MAGIC    - Development → Testing → Production → Tuning
# MAGIC    - Version control and change management
# MAGIC    - Continuous improvement process
# MAGIC
# MAGIC 3. **Integration Architecture:**
# MAGIC    - SIEM platforms (Splunk, QRadar, Sentinel)
# MAGIC    - SOAR tools (Cortex XSOAR, Splunk Phantom)
# MAGIC    - Ticketing systems (Jira, ServiceNow)
# MAGIC
# MAGIC ### Advanced Topics:
# MAGIC - Automated response and remediation
# MAGIC - Threat hunting workflows
# MAGIC - Detection coverage assessment
# MAGIC - Purple team exercises
# MAGIC - Compliance reporting (SOC 2, ISO 27001)
# MAGIC