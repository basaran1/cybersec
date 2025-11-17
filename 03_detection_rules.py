# Databricks notebook source
# MAGIC %md
# MAGIC # Lab 03: Detection Logic Authoring
# MAGIC
# MAGIC ## Overview
# MAGIC In this lab, you will:
# MAGIC 1. Write signature-based SQL detection rules
# MAGIC 2. Implement threshold-based detections (e.g., brute force)
# MAGIC 3. Build anomaly detection models (optional/advanced)
# MAGIC 4. Version and store detection rules in Gold layer
# MAGIC 5. Map detections to MITRE ATT&CK framework
# MAGIC
# MAGIC **Time:** ~15 minutes
# MAGIC
# MAGIC ## Detection Types
# MAGIC - **Signature-based:** Known IOCs (hashes, process names, patterns)
# MAGIC - **Threshold-based:** Statistical rules (failed logins > N)
# MAGIC - **Anomaly-based:** ML models detecting unusual behavior

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

# DBTITLE 1,Setup and Configuration
from pyspark.sql.functions import *
from pyspark.sql.window import Window
from pyspark.sql.types import *
from datetime import datetime, timedelta

# Configuration
CATALOG_NAME = "security_detection_engineering_lab"
SCHEMA_NAME = "security_logs"

# Set context
spark.sql(f"USE CATALOG {CATALOG_NAME}")
spark.sql(f"USE SCHEMA {SCHEMA_NAME}")

print(f"✅ Using catalog: {CATALOG_NAME}")
print(f"✅ Using schema: {SCHEMA_NAME}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verify Prerequisites
# MAGIC
# MAGIC **Important:** Before running detection rules, verify that Lab 02 (DLT pipeline) completed successfully.

# COMMAND ----------

# DBTITLE 1,Verify Silver Tables Exist
print("=" * 80)
print("VERIFYING PREREQUISITES")
print("=" * 80)

# Check if required Silver tables exist
required_tables = [
    "silver_sysmon_process",
    "silver_okta_auth",
    "silver_windows_auth",
    "silver_cloudtrail"
]

all_tables_exist = True
for table in required_tables:
    try:
        count = spark.sql(f"SELECT COUNT(*) as cnt FROM {table}").collect()[0]['cnt']
        if count > 0:
            print(f"✅ {table}: {count:,} records")
        else:
            print(f"⚠️  {table}: Table exists but has 0 records")
            print(f"   → Re-run Lab 02 (DLT pipeline) to populate data")
            all_tables_exist = False
    except Exception as e:
        print(f"❌ {table}: NOT FOUND")
        print(f"   → Error: {str(e)[:80]}")
        print(f"   → Action: Run Lab 02 (DLT pipeline) first!")
        all_tables_exist = False

print("\n" + "=" * 80)
if all_tables_exist:
    print("✅ ALL PREREQUISITES MET - Ready to run detection rules!")
else:
    print("❌ PREREQUISITES NOT MET")
    print("\nRequired Actions:")
    print("1. Complete Lab 01: Generate sample data")
    print("2. Complete Lab 02: Run DLT pipeline and wait for completion")
    print("3. Verify all Silver tables exist with data")
    print("4. Then return to Lab 03")
print("=" * 80)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 1: Signature-Based Detections
# MAGIC
# MAGIC Signature-based rules detect known malicious patterns, IOCs, or behaviors.

# COMMAND ----------

# MAGIC %md
# MAGIC ### Detection 1.1: Mimikatz Execution
# MAGIC
# MAGIC **MITRE ATT&CK:** T1003.001 - Credential Dumping  
# MAGIC **Severity:** CRITICAL  
# MAGIC **Description:** Detects execution of Mimikatz credential dumping tool

# COMMAND ----------

# DBTITLE 1,Detection: Mimikatz Execution
# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMP VIEW detect_mimikatz AS
# MAGIC SELECT
# MAGIC   event_time,
# MAGIC   host,
# MAGIC   user,
# MAGIC   process_name,
# MAGIC   command_line,
# MAGIC   parent_process_name,
# MAGIC   file_hash_sha256,
# MAGIC   'T1003.001' AS mitre_technique,
# MAGIC   'Credential Access' AS mitre_tactic,
# MAGIC   'CRITICAL' AS severity,
# MAGIC   'Mimikatz Credential Dumping Detected' AS alert_title,
# MAGIC   'Detected execution of Mimikatz, a tool commonly used for credential theft' AS description,
# MAGIC   current_timestamp() AS detection_time
# MAGIC FROM silver_sysmon_process
# MAGIC WHERE 
# MAGIC   LOWER(process_name) LIKE '%mimikatz%'
# MAGIC   OR LOWER(command_line) LIKE '%sekurlsa::logonpasswords%'
# MAGIC   OR LOWER(command_line) LIKE '%lsadump::sam%'
# MAGIC ORDER BY event_time DESC;
# MAGIC
# MAGIC SELECT * FROM detect_mimikatz;

# COMMAND ----------

# MAGIC %md
# MAGIC ### Detection 1.2: Suspicious PowerShell Commands
# MAGIC
# MAGIC **MITRE ATT&CK:** T1059.001 - PowerShell  
# MAGIC **Severity:** HIGH  
# MAGIC **Description:** Detects obfuscated or suspicious PowerShell execution

# COMMAND ----------

# DBTITLE 1,Detection: Suspicious PowerShell
# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMP VIEW detect_suspicious_powershell AS
# MAGIC SELECT
# MAGIC   event_time,
# MAGIC   host,
# MAGIC   user,
# MAGIC   process_name,
# MAGIC   command_line,
# MAGIC   parent_process_name,
# MAGIC   'T1059.001' AS mitre_technique,
# MAGIC   'Execution' AS mitre_tactic,
# MAGIC   'HIGH' AS severity,
# MAGIC   'Suspicious PowerShell Execution' AS alert_title,
# MAGIC   CASE
# MAGIC     WHEN command_line LIKE '%-enc%' OR command_line LIKE '%-encodedcommand%' 
# MAGIC       THEN 'Base64 encoded PowerShell command'
# MAGIC     WHEN command_line LIKE '%-w hidden%' OR command_line LIKE '%-windowstyle hidden%'
# MAGIC       THEN 'Hidden window PowerShell execution'
# MAGIC     WHEN LOWER(command_line) LIKE '%iex%' OR LOWER(command_line) LIKE '%invoke-expression%'
# MAGIC       THEN 'PowerShell download and execute pattern'
# MAGIC     WHEN LOWER(command_line) LIKE '%downloadstring%' OR LOWER(command_line) LIKE '%downloadfile%'
# MAGIC       THEN 'PowerShell file download'
# MAGIC     ELSE 'Suspicious PowerShell pattern'
# MAGIC   END AS description,
# MAGIC   current_timestamp() AS detection_time
# MAGIC FROM silver_sysmon_process
# MAGIC WHERE 
# MAGIC   LOWER(process_name) LIKE '%powershell%'
# MAGIC   AND (
# MAGIC     command_line LIKE '%-enc%'
# MAGIC     OR command_line LIKE '%-encodedcommand%'
# MAGIC     OR command_line LIKE '%-w hidden%'
# MAGIC     OR command_line LIKE '%-windowstyle hidden%'
# MAGIC     OR command_line LIKE '%-nop%'
# MAGIC     OR command_line LIKE '%-noprofile%'
# MAGIC     OR LOWER(command_line) LIKE '%iex%'
# MAGIC     OR LOWER(command_line) LIKE '%invoke-%'
# MAGIC     OR LOWER(command_line) LIKE '%downloadstring%'
# MAGIC   )
# MAGIC ORDER BY event_time DESC;
# MAGIC
# MAGIC SELECT * FROM detect_suspicious_powershell LIMIT 20;

# COMMAND ----------

# MAGIC %md
# MAGIC ### Detection 1.3: Lateral Movement via PsExec
# MAGIC
# MAGIC **MITRE ATT&CK:** T1570 - Lateral Tool Transfer  
# MAGIC **Severity:** HIGH

# COMMAND ----------

# DBTITLE 1,Detection: PsExec Lateral Movement
# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMP VIEW detect_psexec AS
# MAGIC SELECT
# MAGIC   event_time,
# MAGIC   host,
# MAGIC   user,
# MAGIC   process_name,
# MAGIC   command_line,
# MAGIC   'T1570' AS mitre_technique,
# MAGIC   'Lateral Movement' AS mitre_tactic,
# MAGIC   'HIGH' AS severity,
# MAGIC   'PsExec Lateral Movement Detected' AS alert_title,
# MAGIC   'Detected use of PsExec for potential lateral movement' AS description,
# MAGIC   current_timestamp() AS detection_time
# MAGIC FROM silver_sysmon_process
# MAGIC WHERE 
# MAGIC   LOWER(process_name) LIKE '%psexec%'
# MAGIC   OR LOWER(command_line) LIKE '%psexec%'
# MAGIC ORDER BY event_time DESC;
# MAGIC
# MAGIC SELECT * FROM detect_psexec;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 2: Threshold-Based Detections
# MAGIC
# MAGIC Threshold detections identify abnormal volumes or frequencies of events.

# COMMAND ----------

# MAGIC %md
# MAGIC ### Detection 2.1: Brute Force - Okta Failed Logins
# MAGIC
# MAGIC **MITRE ATT&CK:** T1110 - Brute Force  
# MAGIC **Severity:** HIGH  
# MAGIC **Threshold:** 5+ failed logins within 10 minutes

# COMMAND ----------

# DBTITLE 1,Detection: Okta Brute Force
# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMP VIEW detect_okta_bruteforce AS
# MAGIC WITH failed_logins AS (
# MAGIC   SELECT
# MAGIC     user_email,
# MAGIC     source_ip,
# MAGIC     COUNT(*) as failure_count,
# MAGIC     MIN(event_time) as first_failure,
# MAGIC     MAX(event_time) as last_failure,
# MAGIC     COLLECT_LIST(event_time) as failure_times
# MAGIC   FROM silver_okta_auth
# MAGIC   WHERE 
# MAGIC     outcome = 'FAILURE'
# MAGIC     AND event_time >= current_timestamp() - INTERVAL 10 MINUTES
# MAGIC   GROUP BY user_email, source_ip
# MAGIC   HAVING COUNT(*) >= 5
# MAGIC )
# MAGIC SELECT
# MAGIC   user_email,
# MAGIC   source_ip,
# MAGIC   failure_count,
# MAGIC   first_failure,
# MAGIC   last_failure,
# MAGIC   ROUND((unix_timestamp(last_failure) - unix_timestamp(first_failure)) / 60, 2) as duration_minutes,
# MAGIC   'T1110' AS mitre_technique,
# MAGIC   'Credential Access' AS mitre_tactic,
# MAGIC   CASE
# MAGIC     WHEN failure_count >= 10 THEN 'CRITICAL'
# MAGIC     WHEN failure_count >= 7 THEN 'HIGH'
# MAGIC     ELSE 'MEDIUM'
# MAGIC   END AS severity,
# MAGIC   'Okta Brute Force Attack Detected' AS alert_title,
# MAGIC   CONCAT(
# MAGIC     'Detected ', failure_count, ' failed login attempts for user ', user_email,
# MAGIC     ' from IP ', source_ip, ' within ',
# MAGIC     ROUND((unix_timestamp(last_failure) - unix_timestamp(first_failure)) / 60, 2), ' minutes'
# MAGIC   ) AS description,
# MAGIC   current_timestamp() AS detection_time
# MAGIC FROM failed_logins
# MAGIC ORDER BY failure_count DESC;
# MAGIC
# MAGIC SELECT * FROM detect_okta_bruteforce;

# COMMAND ----------

# MAGIC %md
# MAGIC ### Detection 2.2: Windows Failed Logon Brute Force
# MAGIC
# MAGIC **MITRE ATT&CK:** T1110.001 - Password Guessing  
# MAGIC **Severity:** HIGH  
# MAGIC **Threshold:** 10+ failed logons within 5 minutes

# COMMAND ----------

# DBTITLE 1,Detection: Windows Brute Force
# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMP VIEW detect_windows_bruteforce AS
# MAGIC WITH failed_logons AS (
# MAGIC   SELECT
# MAGIC     user_name,
# MAGIC     host,
# MAGIC     source_ip,
# MAGIC     COUNT(*) as failure_count,
# MAGIC     MIN(event_time) as first_failure,
# MAGIC     MAX(event_time) as last_failure
# MAGIC   FROM silver_windows_auth
# MAGIC   WHERE 
# MAGIC     logon_success = FALSE
# MAGIC     AND event_time >= current_timestamp() - INTERVAL 5 MINUTES
# MAGIC   GROUP BY user_name, host, source_ip
# MAGIC   HAVING COUNT(*) >= 10
# MAGIC )
# MAGIC SELECT
# MAGIC   user_name,
# MAGIC   host,
# MAGIC   source_ip,
# MAGIC   failure_count,
# MAGIC   first_failure,
# MAGIC   last_failure,
# MAGIC   'T1110.001' AS mitre_technique,
# MAGIC   'Credential Access' AS mitre_tactic,
# MAGIC   CASE
# MAGIC     WHEN failure_count >= 20 THEN 'CRITICAL'
# MAGIC     WHEN failure_count >= 15 THEN 'HIGH'
# MAGIC     ELSE 'MEDIUM'
# MAGIC   END AS severity,
# MAGIC   'Windows Brute Force Attack' AS alert_title,
# MAGIC   CONCAT(
# MAGIC     'Detected ', failure_count, ' failed logon attempts for user ', user_name,
# MAGIC     ' on host ', host, ' from IP ', source_ip
# MAGIC   ) AS description,
# MAGIC   current_timestamp() AS detection_time
# MAGIC FROM failed_logons
# MAGIC ORDER BY failure_count DESC;
# MAGIC
# MAGIC SELECT * FROM detect_windows_bruteforce;

# COMMAND ----------

# MAGIC %md
# MAGIC ### Detection 2.3: Excessive AWS API Failures
# MAGIC
# MAGIC **MITRE ATT&CK:** T1078.004 - Cloud Accounts  
# MAGIC **Severity:** MEDIUM  
# MAGIC **Threshold:** 15+ failed API calls within 10 minutes

# COMMAND ----------

# DBTITLE 1,Detection: AWS API Abuse
# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMP VIEW detect_aws_api_failures AS
# MAGIC WITH api_failures AS (
# MAGIC   SELECT
# MAGIC     user_name,
# MAGIC     source_ip,
# MAGIC     service,
# MAGIC     error_code,
# MAGIC     COUNT(*) as failure_count,
# MAGIC     COLLECT_SET(event_name) as failed_apis,
# MAGIC     MIN(event_time) as first_failure,
# MAGIC     MAX(event_time) as last_failure
# MAGIC   FROM silver_cloudtrail
# MAGIC   WHERE 
# MAGIC     api_success = FALSE
# MAGIC     AND event_time >= current_timestamp() - INTERVAL 10 MINUTES
# MAGIC   GROUP BY user_name, source_ip, service, error_code
# MAGIC   HAVING COUNT(*) >= 15
# MAGIC )
# MAGIC SELECT
# MAGIC   user_name,
# MAGIC   source_ip,
# MAGIC   service,
# MAGIC   error_code,
# MAGIC   failure_count,
# MAGIC   SIZE(failed_apis) as unique_api_count,
# MAGIC   failed_apis,
# MAGIC   first_failure,
# MAGIC   last_failure,
# MAGIC   'T1078.004' AS mitre_technique,
# MAGIC   'Credential Access' AS mitre_tactic,
# MAGIC   'MEDIUM' AS severity,
# MAGIC   'Excessive AWS API Failures' AS alert_title,
# MAGIC   CONCAT(
# MAGIC     'User ', user_name, ' from IP ', source_ip, 
# MAGIC     ' generated ', failure_count, ' failed API calls to ', service,
# MAGIC     ' with error: ', error_code
# MAGIC   ) AS description,
# MAGIC   current_timestamp() AS detection_time
# MAGIC FROM api_failures
# MAGIC ORDER BY failure_count DESC;
# MAGIC
# MAGIC SELECT * FROM detect_aws_api_failures;

# COMMAND ----------

# MAGIC %md
# MAGIC ### Detection 2.4: Suspicious Network Scanning
# MAGIC
# MAGIC **MITRE ATT&CK:** T1046 - Network Service Scanning  
# MAGIC **Severity:** MEDIUM  
# MAGIC **Threshold:** Connections to 20+ unique IPs within 1 minute

# COMMAND ----------

# DBTITLE 1,Detection: Network Scanning
# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMP VIEW detect_network_scanning AS
# MAGIC WITH network_activity AS (
# MAGIC   SELECT
# MAGIC     host,
# MAGIC     user,
# MAGIC     process_name,
# MAGIC     COUNT(DISTINCT destination_ip) as unique_destinations,
# MAGIC     COUNT(*) as total_connections,
# MAGIC     MIN(event_time) as first_connection,
# MAGIC     MAX(event_time) as last_connection,
# MAGIC     COLLECT_SET(destination_port) as ports_accessed
# MAGIC   FROM silver_sysmon_network
# MAGIC   WHERE event_time >= current_timestamp() - INTERVAL 1 MINUTE
# MAGIC   GROUP BY host, user, process_name
# MAGIC   HAVING COUNT(DISTINCT destination_ip) >= 20
# MAGIC )
# MAGIC SELECT
# MAGIC   host,
# MAGIC   user,
# MAGIC   process_name,
# MAGIC   unique_destinations,
# MAGIC   total_connections,
# MAGIC   SIZE(ports_accessed) as unique_ports,
# MAGIC   ports_accessed,
# MAGIC   first_connection,
# MAGIC   last_connection,
# MAGIC   'T1046' AS mitre_technique,
# MAGIC   'Discovery' AS mitre_tactic,
# MAGIC   CASE
# MAGIC     WHEN unique_destinations >= 100 THEN 'HIGH'
# MAGIC     WHEN unique_destinations >= 50 THEN 'MEDIUM'
# MAGIC     ELSE 'LOW'
# MAGIC   END AS severity,
# MAGIC   'Network Scanning Activity Detected' AS alert_title,
# MAGIC   CONCAT(
# MAGIC     'Process ', process_name, ' on host ', host, 
# MAGIC     ' connected to ', unique_destinations, ' unique destinations',
# MAGIC     ' (', total_connections, ' total connections)'
# MAGIC   ) AS description,
# MAGIC   current_timestamp() AS detection_time
# MAGIC FROM network_activity
# MAGIC ORDER BY unique_destinations DESC;
# MAGIC
# MAGIC SELECT * FROM detect_network_scanning;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 3: Advanced Detections (Optional)

# COMMAND ----------

# MAGIC %md
# MAGIC ### Detection 3.1: Impossible Travel (Okta)
# MAGIC
# MAGIC **MITRE ATT&CK:** T1078 - Valid Accounts (Compromise)  
# MAGIC **Severity:** HIGH  
# MAGIC **Logic:** Same user authenticates from 2 geographically distant locations within short time

# COMMAND ----------

# DBTITLE 1,Detection: Impossible Travel
# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMP VIEW detect_impossible_travel AS
# MAGIC WITH user_locations AS (
# MAGIC   SELECT
# MAGIC     user_email,
# MAGIC     event_time,
# MAGIC     country,
# MAGIC     city,
# MAGIC     source_ip,
# MAGIC     LAG(country) OVER (PARTITION BY user_email ORDER BY event_time) as prev_country,
# MAGIC     LAG(city) OVER (PARTITION BY user_email ORDER BY event_time) as prev_city,
# MAGIC     LAG(event_time) OVER (PARTITION BY user_email ORDER BY event_time) as prev_time,
# MAGIC     LAG(source_ip) OVER (PARTITION BY user_email ORDER BY event_time) as prev_ip
# MAGIC   FROM silver_okta_auth
# MAGIC   WHERE 
# MAGIC     outcome = 'SUCCESS'
# MAGIC     AND country IS NOT NULL
# MAGIC )
# MAGIC SELECT
# MAGIC   user_email,
# MAGIC   event_time as current_login_time,
# MAGIC   prev_time as previous_login_time,
# MAGIC   ROUND((unix_timestamp(event_time) - unix_timestamp(prev_time)) / 60, 2) as time_diff_minutes,
# MAGIC   country as current_country,
# MAGIC   prev_country as previous_country,
# MAGIC   city as current_city,
# MAGIC   prev_city as previous_city,
# MAGIC   source_ip as current_ip,
# MAGIC   prev_ip as previous_ip,
# MAGIC   'T1078' AS mitre_technique,
# MAGIC   'Initial Access' AS mitre_tactic,
# MAGIC   'HIGH' AS severity,
# MAGIC   'Impossible Travel Detected' AS alert_title,
# MAGIC   CONCAT(
# MAGIC     'User ', user_email, ' logged in from ', current_country, ' (',current_city, ') ',
# MAGIC     'only ', ROUND((unix_timestamp(event_time) - unix_timestamp(prev_time)) / 60, 2), 
# MAGIC     ' minutes after logging in from ', prev_country, ' (', prev_city, ')'
# MAGIC   ) AS description,
# MAGIC   current_timestamp() AS detection_time
# MAGIC FROM user_locations
# MAGIC WHERE 
# MAGIC   prev_country IS NOT NULL
# MAGIC   AND country != prev_country
# MAGIC   AND (unix_timestamp(event_time) - unix_timestamp(prev_time)) <= 3600  -- 1 hour
# MAGIC   AND (unix_timestamp(event_time) - unix_timestamp(prev_time)) > 0
# MAGIC ORDER BY time_diff_minutes ASC;
# MAGIC
# MAGIC SELECT * FROM detect_impossible_travel;

# COMMAND ----------

# MAGIC %md
# MAGIC ### Detection 3.2: High-Risk AWS IAM Changes
# MAGIC
# MAGIC **MITRE ATT&CK:** T1098 - Account Manipulation  
# MAGIC **Severity:** CRITICAL

# COMMAND ----------

# DBTITLE 1,Detection: Privilege Escalation in AWS
# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMP VIEW detect_aws_privilege_escalation AS
# MAGIC SELECT
# MAGIC   event_time,
# MAGIC   user_name,
# MAGIC   event_name,
# MAGIC   service,
# MAGIC   source_ip,
# MAGIC   user_arn,
# MAGIC   region,
# MAGIC   target_user,
# MAGIC   'T1098' AS mitre_technique,
# MAGIC   'Privilege Escalation' AS mitre_tactic,
# MAGIC   'CRITICAL' AS severity,
# MAGIC   'AWS Privilege Escalation Attempt' AS alert_title,
# MAGIC   CASE
# MAGIC     WHEN event_name LIKE 'CreateAccessKey%' THEN 'Creation of new access key - potential persistence'
# MAGIC     WHEN event_name LIKE 'AttachUserPolicy%' THEN 'Attachment of policy to user - privilege escalation'
# MAGIC     WHEN event_name LIKE 'CreateUser%' THEN 'Creation of new IAM user'
# MAGIC     WHEN event_name LIKE 'CreateLoginProfile%' THEN 'Creation of console login profile'
# MAGIC     WHEN event_name LIKE 'DeleteTrail%' THEN 'CloudTrail deletion - defense evasion'
# MAGIC     WHEN event_name LIKE 'StopLogging%' THEN 'CloudTrail logging disabled - defense evasion'
# MAGIC     ELSE 'High-risk IAM operation'
# MAGIC   END AS description,
# MAGIC   current_timestamp() AS detection_time
# MAGIC FROM silver_cloudtrail
# MAGIC WHERE 
# MAGIC   risk_classification = 'high_risk_action'
# MAGIC   OR event_name IN (
# MAGIC     'CreateAccessKey',
# MAGIC     'AttachUserPolicy',
# MAGIC     'AttachRolePolicy',
# MAGIC     'PutUserPolicy',
# MAGIC     'PutRolePolicy',
# MAGIC     'CreateUser',
# MAGIC     'CreateLoginProfile',
# MAGIC     'DeleteTrail',
# MAGIC     'StopLogging',
# MAGIC     'DeleteDetector',
# MAGIC     'UpdateDetector'
# MAGIC   )
# MAGIC ORDER BY event_time DESC;
# MAGIC
# MAGIC SELECT * FROM detect_aws_privilege_escalation;

# COMMAND ----------

# MAGIC %md
# MAGIC ### Detection 3.3: Anomaly Detection with ML (Optional/Advanced)
# MAGIC
# MAGIC **MITRE ATT&CK:** Multiple Techniques  
# MAGIC **Severity:** MEDIUM-HIGH  
# MAGIC **Description:** Use machine learning to detect anomalous user behavior patterns

# COMMAND ----------

# MAGIC %md
# MAGIC #### 3.3.1: User Behavior Analytics (UEBA) - Login Patterns
# MAGIC
# MAGIC Build a statistical baseline of normal user login behavior and detect deviations

# COMMAND ----------

# DBTITLE 1,Build User Baseline Profile
from pyspark.ml.feature import VectorAssembler, StandardScaler
from pyspark.ml.clustering import KMeans
from pyspark.ml.stat import Correlation
from pyspark.sql.functions import *
from pyspark.sql.window import Window

# Create user behavior features
user_features = spark.sql("""
  WITH user_stats AS (
    SELECT
      user_email,
      DATE(event_time) as login_date,
      COUNT(*) as daily_login_count,
      COUNT(DISTINCT source_ip) as unique_ips,
      COUNT(DISTINCT country) as unique_countries,
      COUNT(DISTINCT city) as unique_cities,
      AVG(HOUR(event_time)) as avg_login_hour,
      STDDEV(HOUR(event_time)) as stddev_login_hour,
      MIN(HOUR(event_time)) as min_login_hour,
      MAX(HOUR(event_time)) as max_login_hour,
      SUM(CASE WHEN outcome = 'FAILURE' THEN 1 ELSE 0 END) as failure_count,
      SUM(CASE WHEN outcome = 'SUCCESS' THEN 1 ELSE 0 END) as success_count
    FROM silver_okta_auth
    WHERE event_time >= current_timestamp() - INTERVAL 30 DAYS
    GROUP BY user_email, DATE(event_time)
  ),
  user_profile AS (
    SELECT
      user_email,
      AVG(daily_login_count) as avg_daily_logins,
      STDDEV(daily_login_count) as stddev_daily_logins,
      AVG(unique_ips) as avg_unique_ips,
      STDDEV(unique_ips) as stddev_unique_ips,
      AVG(unique_countries) as avg_unique_countries,
      AVG(avg_login_hour) as typical_login_hour,
      AVG(stddev_login_hour) as login_hour_variability,
      SUM(failure_count) / NULLIF(SUM(success_count + failure_count), 0) as failure_rate
    FROM user_stats
    GROUP BY user_email
  )
  SELECT * FROM user_profile
  WHERE avg_daily_logins IS NOT NULL
""")

# Display user profiles
display(user_features)

print(f"✅ Built behavioral profiles for {user_features.count()} users")

# COMMAND ----------

# DBTITLE 1,Detect Anomalous User Behavior
# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMP VIEW detect_user_behavior_anomaly AS
# MAGIC WITH user_baseline AS (
# MAGIC   SELECT
# MAGIC     user_email,
# MAGIC     AVG(daily_login_count) as avg_logins,
# MAGIC     STDDEV(daily_login_count) as stddev_logins,
# MAGIC     AVG(unique_ips) as avg_ips,
# MAGIC     STDDEV(unique_ips) as stddev_ips
# MAGIC   FROM (
# MAGIC     SELECT
# MAGIC       user_email,
# MAGIC       DATE(event_time) as login_date,
# MAGIC       COUNT(*) as daily_login_count,
# MAGIC       COUNT(DISTINCT source_ip) as unique_ips
# MAGIC     FROM silver_okta_auth
# MAGIC     WHERE event_time >= current_timestamp() - INTERVAL 30 DAYS
# MAGIC       AND event_time < current_timestamp() - INTERVAL 1 DAY
# MAGIC     GROUP BY user_email, DATE(event_time)
# MAGIC   )
# MAGIC   GROUP BY user_email
# MAGIC ),
# MAGIC recent_behavior AS (
# MAGIC   SELECT
# MAGIC     user_email,
# MAGIC     COUNT(*) as today_login_count,
# MAGIC     COUNT(DISTINCT source_ip) as today_unique_ips,
# MAGIC     COUNT(DISTINCT country) as today_unique_countries,
# MAGIC     MAX(event_time) as last_login
# MAGIC   FROM silver_okta_auth
# MAGIC   WHERE event_time >= current_date()
# MAGIC   GROUP BY user_email
# MAGIC )
# MAGIC SELECT
# MAGIC   r.user_email,
# MAGIC   r.last_login as event_time,
# MAGIC   r.today_login_count,
# MAGIC   ROUND(b.avg_logins, 2) as baseline_avg_logins,
# MAGIC   ROUND(b.stddev_logins, 2) as baseline_stddev_logins,
# MAGIC   r.today_unique_ips,
# MAGIC   ROUND(b.avg_ips, 2) as baseline_avg_ips,
# MAGIC   r.today_unique_countries,
# MAGIC   -- Calculate Z-scores for anomaly detection
# MAGIC   ROUND((r.today_login_count - b.avg_logins) / NULLIF(b.stddev_logins, 0), 2) as login_count_zscore,
# MAGIC   ROUND((r.today_unique_ips - b.avg_ips) / NULLIF(b.stddev_ips, 0), 2) as unique_ip_zscore,
# MAGIC   'T1078' AS mitre_technique,
# MAGIC   'Initial Access' AS mitre_tactic,
# MAGIC   CASE
# MAGIC     WHEN ABS((r.today_login_count - b.avg_logins) / NULLIF(b.stddev_logins, 0)) >= 3 THEN 'HIGH'
# MAGIC     WHEN ABS((r.today_login_count - b.avg_logins) / NULLIF(b.stddev_logins, 0)) >= 2 THEN 'MEDIUM'
# MAGIC     ELSE 'LOW'
# MAGIC   END AS severity,
# MAGIC   'Anomalous User Behavior Detected' AS alert_title,
# MAGIC   CONCAT(
# MAGIC     'User ', r.user_email, ' shows anomalous behavior: ',
# MAGIC     r.today_login_count, ' logins (baseline: ', ROUND(b.avg_logins, 1), ' ±', ROUND(b.stddev_logins, 1), '), ',
# MAGIC     r.today_unique_ips, ' unique IPs (baseline: ', ROUND(b.avg_ips, 1), ')'
# MAGIC   ) AS description,
# MAGIC   current_timestamp() AS detection_time
# MAGIC FROM recent_behavior r
# MAGIC JOIN user_baseline b ON r.user_email = b.user_email
# MAGIC WHERE 
# MAGIC   -- Flag if Z-score > 2 (2 standard deviations from mean)
# MAGIC   ABS((r.today_login_count - b.avg_logins) / NULLIF(b.stddev_logins, 0)) >= 2
# MAGIC   OR ABS((r.today_unique_ips - b.avg_ips) / NULLIF(b.stddev_ips, 0)) >= 2
# MAGIC   OR r.today_unique_countries >= 3
# MAGIC ORDER BY login_count_zscore DESC;
# MAGIC
# MAGIC SELECT * FROM detect_user_behavior_anomaly;

# COMMAND ----------

# MAGIC %md
# MAGIC #### 3.3.2: Process Execution Anomaly Detection
# MAGIC
# MAGIC Detect unusual process execution patterns using frequency analysis

# COMMAND ----------

# DBTITLE 1,Detect Rare Process Execution
# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMP VIEW detect_rare_process_execution AS
# MAGIC WITH process_frequency AS (
# MAGIC   SELECT
# MAGIC     process_name,
# MAGIC     COUNT(*) as execution_count,
# MAGIC     COUNT(DISTINCT host) as host_count,
# MAGIC     COUNT(DISTINCT user) as user_count,
# MAGIC     MIN(event_time) as first_seen,
# MAGIC     MAX(event_time) as last_seen
# MAGIC   FROM silver_sysmon_process
# MAGIC   WHERE event_time >= current_timestamp() - INTERVAL 30 DAYS
# MAGIC   GROUP BY process_name
# MAGIC ),
# MAGIC process_rarity_score AS (
# MAGIC   SELECT
# MAGIC     *,
# MAGIC     PERCENT_RANK() OVER (ORDER BY execution_count) as rarity_percentile,
# MAGIC     -- Lower execution count = higher rarity = more suspicious
# MAGIC     CASE
# MAGIC       WHEN execution_count <= 5 THEN 'VERY_RARE'
# MAGIC       WHEN execution_count <= 20 THEN 'RARE'
# MAGIC       WHEN execution_count <= 100 THEN 'UNCOMMON'
# MAGIC       ELSE 'COMMON'
# MAGIC     END as rarity_category
# MAGIC   FROM process_frequency
# MAGIC ),
# MAGIC recent_rare_executions AS (
# MAGIC   SELECT
# MAGIC     p.event_time,
# MAGIC     p.host,
# MAGIC     p.user,
# MAGIC     p.process_name,
# MAGIC     p.command_line,
# MAGIC     p.parent_process_name,
# MAGIC     p.file_hash_sha256,
# MAGIC     r.execution_count as historical_count,
# MAGIC     r.rarity_category,
# MAGIC     r.rarity_percentile
# MAGIC   FROM silver_sysmon_process p
# MAGIC   JOIN process_rarity_score r ON p.process_name = r.process_name
# MAGIC   WHERE 
# MAGIC     p.event_time >= current_timestamp() - INTERVAL 1 DAY
# MAGIC     AND r.rarity_category IN ('VERY_RARE', 'RARE')
# MAGIC     -- Exclude known safe rare processes
# MAGIC     AND LOWER(p.process_name) NOT LIKE '%update%'
# MAGIC     AND LOWER(p.process_name) NOT LIKE '%install%'
# MAGIC     AND LOWER(p.parent_process_name) NOT IN ('services.exe', 'svchost.exe', 'taskhost.exe')
# MAGIC )
# MAGIC SELECT
# MAGIC   event_time,
# MAGIC   host,
# MAGIC   user,
# MAGIC   process_name,
# MAGIC   command_line,
# MAGIC   parent_process_name,
# MAGIC   historical_count,
# MAGIC   rarity_category,
# MAGIC   ROUND(rarity_percentile * 100, 2) as rarity_score,
# MAGIC   'T1204' AS mitre_technique,
# MAGIC   'Execution' AS mitre_tactic,
# MAGIC   CASE
# MAGIC     WHEN rarity_category = 'VERY_RARE' AND parent_process_name NOT IN ('explorer.exe', 'cmd.exe') THEN 'HIGH'
# MAGIC     WHEN rarity_category = 'VERY_RARE' THEN 'MEDIUM'
# MAGIC     ELSE 'LOW'
# MAGIC   END AS severity,
# MAGIC   'Rare Process Execution Detected' AS alert_title,
# MAGIC   CONCAT(
# MAGIC     'Rare process executed: ', process_name,
# MAGIC     ' (seen only ', historical_count, ' times historically, rarity: ', rarity_category, ')',
# MAGIC     ' on host ', host, ' by user ', user
# MAGIC   ) AS description,
# MAGIC   current_timestamp() AS detection_time
# MAGIC FROM recent_rare_executions
# MAGIC ORDER BY rarity_percentile ASC, event_time DESC
# MAGIC LIMIT 100;
# MAGIC
# MAGIC SELECT * FROM detect_rare_process_execution;

# COMMAND ----------

# MAGIC %md
# MAGIC #### 3.3.3: Network Traffic Anomaly Detection
# MAGIC
# MAGIC Detect unusual network connection patterns using statistical methods

# COMMAND ----------

# DBTITLE 1,Detect Anomalous Network Patterns
# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMP VIEW detect_network_anomaly AS
# MAGIC WITH host_network_baseline AS (
# MAGIC   SELECT
# MAGIC     host,
# MAGIC     AVG(daily_connections) as avg_connections,
# MAGIC     STDDEV(daily_connections) as stddev_connections,
# MAGIC     AVG(daily_unique_ips) as avg_unique_ips,
# MAGIC     STDDEV(daily_unique_ips) as stddev_unique_ips,
# MAGIC     AVG(daily_unique_ports) as avg_unique_ports,
# MAGIC     STDDEV(daily_unique_ports) as stddev_unique_ports
# MAGIC   FROM (
# MAGIC     SELECT
# MAGIC       host,
# MAGIC       DATE(event_time) as connection_date,
# MAGIC       COUNT(*) as daily_connections,
# MAGIC       COUNT(DISTINCT destination_ip) as daily_unique_ips,
# MAGIC       COUNT(DISTINCT destination_port) as daily_unique_ports
# MAGIC     FROM silver_sysmon_network
# MAGIC     WHERE event_time >= current_timestamp() - INTERVAL 30 DAYS
# MAGIC       AND event_time < current_timestamp() - INTERVAL 1 DAY
# MAGIC     GROUP BY host, DATE(event_time)
# MAGIC   )
# MAGIC   GROUP BY host
# MAGIC ),
# MAGIC recent_network_activity AS (
# MAGIC   SELECT
# MAGIC     host,
# MAGIC     COUNT(*) as today_connections,
# MAGIC     COUNT(DISTINCT destination_ip) as today_unique_ips,
# MAGIC     COUNT(DISTINCT destination_port) as today_unique_ports,
# MAGIC     MAX(event_time) as last_connection,
# MAGIC     COLLECT_SET(destination_port) as ports_used
# MAGIC   FROM silver_sysmon_network
# MAGIC   WHERE event_time >= current_date()
# MAGIC   GROUP BY host
# MAGIC )
# MAGIC SELECT
# MAGIC   r.host,
# MAGIC   r.last_connection as event_time,
# MAGIC   r.today_connections,
# MAGIC   ROUND(b.avg_connections, 0) as baseline_avg_connections,
# MAGIC   r.today_unique_ips,
# MAGIC   ROUND(b.avg_unique_ips, 0) as baseline_avg_ips,
# MAGIC   r.today_unique_ports,
# MAGIC   ROUND(b.avg_unique_ports, 0) as baseline_avg_ports,
# MAGIC   r.ports_used,
# MAGIC   ROUND((r.today_connections - b.avg_connections) / NULLIF(b.stddev_connections, 0), 2) as connection_zscore,
# MAGIC   ROUND((r.today_unique_ips - b.avg_unique_ips) / NULLIF(b.stddev_unique_ips, 0), 2) as unique_ip_zscore,
# MAGIC   'T1071' AS mitre_technique,
# MAGIC   'Command and Control' AS mitre_tactic,
# MAGIC   CASE
# MAGIC     WHEN ABS((r.today_connections - b.avg_connections) / NULLIF(b.stddev_connections, 0)) >= 3 THEN 'HIGH'
# MAGIC     WHEN ABS((r.today_unique_ips - b.avg_unique_ips) / NULLIF(b.stddev_unique_ips, 0)) >= 3 THEN 'HIGH'
# MAGIC     WHEN ABS((r.today_connections - b.avg_connections) / NULLIF(b.stddev_connections, 0)) >= 2 THEN 'MEDIUM'
# MAGIC     ELSE 'LOW'
# MAGIC   END AS severity,
# MAGIC   'Anomalous Network Activity Detected' AS alert_title,
# MAGIC   CONCAT(
# MAGIC     'Host ', r.host, ' shows anomalous network behavior: ',
# MAGIC     r.today_connections, ' connections (baseline: ', ROUND(b.avg_connections, 0), '), ',
# MAGIC     r.today_unique_ips, ' unique destinations (baseline: ', ROUND(b.avg_unique_ips, 0), ')'
# MAGIC   ) AS description,
# MAGIC   current_timestamp() AS detection_time
# MAGIC FROM recent_network_activity r
# MAGIC JOIN host_network_baseline b ON r.host = b.host
# MAGIC WHERE 
# MAGIC   ABS((r.today_connections - b.avg_connections) / NULLIF(b.stddev_connections, 0)) >= 2
# MAGIC   OR ABS((r.today_unique_ips - b.avg_unique_ips) / NULLIF(b.stddev_unique_ips, 0)) >= 2
# MAGIC ORDER BY connection_zscore DESC;
# MAGIC
# MAGIC SELECT * FROM detect_network_anomaly;

# COMMAND ----------

# MAGIC %md
# MAGIC #### 3.3.4: ML-Based Clustering for User Behavior (Advanced)
# MAGIC
# MAGIC Use K-Means clustering to group users by behavior and identify outliers

# COMMAND ----------

# DBTITLE 1,K-Means User Behavior Clustering
from pyspark.ml.feature import VectorAssembler, StandardScaler
from pyspark.ml.clustering import KMeans
from pyspark.ml import Pipeline

# Prepare feature data
user_behavior_df = spark.sql("""
  SELECT
    user_email,
    COUNT(*) as total_logins,
    COUNT(DISTINCT source_ip) as unique_ips,
    COUNT(DISTINCT country) as unique_countries,
    COUNT(DISTINCT DATE(event_time)) as active_days,
    AVG(HOUR(event_time)) as avg_login_hour,
    STDDEV(HOUR(event_time)) as stddev_login_hour,
    SUM(CASE WHEN outcome = 'FAILURE' THEN 1 ELSE 0 END) / COUNT(*) as failure_rate,
    SUM(CASE WHEN HOUR(event_time) BETWEEN 22 AND 6 THEN 1 ELSE 0 END) / COUNT(*) as after_hours_rate
  FROM silver_okta_auth
  WHERE event_time >= current_timestamp() - INTERVAL 30 DAYS
  GROUP BY user_email
  HAVING COUNT(*) >= 5  -- Only users with sufficient data
""")

# Assemble features
feature_cols = ['total_logins', 'unique_ips', 'unique_countries', 'active_days', 
                'avg_login_hour', 'stddev_login_hour', 'failure_rate', 'after_hours_rate']

# Handle nulls
user_behavior_df = user_behavior_df.fillna({'stddev_login_hour': 0, 'failure_rate': 0, 'after_hours_rate': 0})

assembler = VectorAssembler(inputCols=feature_cols, outputCol="features", handleInvalid="skip")
scaler = StandardScaler(inputCol="features", outputCol="scaled_features")
kmeans = KMeans(featuresCol="scaled_features", k=4, seed=42)

# Create pipeline
pipeline = Pipeline(stages=[assembler, scaler, kmeans])

# Fit model
try:
    model = pipeline.fit(user_behavior_df)
    predictions = model.transform(user_behavior_df)
    
    # Show cluster assignments
    print("✅ User behavior clustering completed")
    print("\nCluster distribution:")
    predictions.groupBy("prediction").count().orderBy("prediction").show()
    
    # Find outliers (users in smallest clusters or far from centers)
    cluster_sizes = predictions.groupBy("prediction").count().collect()
    min_cluster_size = min([row['count'] for row in cluster_sizes])
    
    anomalous_users = predictions.filter(
        (col("prediction").isin([row['prediction'] for row in cluster_sizes if row['count'] <= min_cluster_size * 2]))
    ).select("user_email", "prediction", "total_logins", "unique_ips", "unique_countries", "failure_rate")
    
    print(f"\n⚠️  Found {anomalous_users.count()} potentially anomalous users (in smallest clusters):")
    display(anomalous_users)
    
    # Store for later use
    predictions.createOrReplaceTempView("user_behavior_clusters")
    
except Exception as e:
    print(f"⚠️  Clustering skipped - insufficient data or error: {str(e)}")
    print("   This is expected if you have limited sample data")

# COMMAND ----------

# MAGIC %md
# MAGIC #### 3.3.5: Time-Series Anomaly Detection for Failed Logins
# MAGIC
# MAGIC Detect unusual spikes in failed authentication attempts using moving averages

# COMMAND ----------

# DBTITLE 1,Time-Series Anomaly Detection
# MAGIC %sql
# MAGIC CREATE OR REPLACE TEMP VIEW detect_timeseries_anomaly AS
# MAGIC WITH hourly_failures AS (
# MAGIC   SELECT
# MAGIC     DATE_TRUNC('hour', event_time) as time_bucket,
# MAGIC     COUNT(*) as failure_count,
# MAGIC     COUNT(DISTINCT user_email) as affected_users,
# MAGIC     COUNT(DISTINCT source_ip) as source_ips
# MAGIC   FROM silver_okta_auth
# MAGIC   WHERE 
# MAGIC     outcome = 'FAILURE'
# MAGIC     AND event_time >= current_timestamp() - INTERVAL 7 DAYS
# MAGIC   GROUP BY DATE_TRUNC('hour', event_time)
# MAGIC ),
# MAGIC moving_avg AS (
# MAGIC   SELECT
# MAGIC     time_bucket,
# MAGIC     failure_count,
# MAGIC     affected_users,
# MAGIC     source_ips,
# MAGIC     AVG(failure_count) OVER (
# MAGIC       ORDER BY time_bucket
# MAGIC       ROWS BETWEEN 24 PRECEDING AND 1 PRECEDING
# MAGIC     ) as avg_24h,
# MAGIC     STDDEV(failure_count) OVER (
# MAGIC       ORDER BY time_bucket
# MAGIC       ROWS BETWEEN 24 PRECEDING AND 1 PRECEDING
# MAGIC     ) as stddev_24h
# MAGIC   FROM hourly_failures
# MAGIC )
# MAGIC SELECT
# MAGIC   time_bucket as event_time,
# MAGIC   failure_count,
# MAGIC   ROUND(avg_24h, 1) as baseline_avg,
# MAGIC   ROUND(stddev_24h, 1) as baseline_stddev,
# MAGIC   affected_users,
# MAGIC   source_ips,
# MAGIC   ROUND((failure_count - avg_24h) / NULLIF(stddev_24h, 0), 2) as zscore,
# MAGIC   ROUND((failure_count - avg_24h) / NULLIF(avg_24h, 0) * 100, 1) as pct_change,
# MAGIC   'T1110' AS mitre_technique,
# MAGIC   'Credential Access' AS mitre_tactic,
# MAGIC   CASE
# MAGIC     WHEN (failure_count - avg_24h) / NULLIF(stddev_24h, 0) >= 3 THEN 'HIGH'
# MAGIC     WHEN (failure_count - avg_24h) / NULLIF(stddev_24h, 0) >= 2 THEN 'MEDIUM'
# MAGIC     ELSE 'LOW'
# MAGIC   END AS severity,
# MAGIC   'Authentication Failure Spike Detected' AS alert_title,
# MAGIC   CONCAT(
# MAGIC     'Unusual spike in failed authentications: ', failure_count, ' failures ',
# MAGIC     '(baseline: ', ROUND(avg_24h, 0), ' ±', ROUND(stddev_24h, 0), '), ',
# MAGIC     ROUND((failure_count - avg_24h) / NULLIF(avg_24h, 0) * 100, 0), '% increase'
# MAGIC   ) AS description,
# MAGIC   current_timestamp() AS detection_time
# MAGIC FROM moving_avg
# MAGIC WHERE 
# MAGIC   time_bucket >= current_timestamp() - INTERVAL 24 HOURS
# MAGIC   AND avg_24h IS NOT NULL
# MAGIC   AND (failure_count - avg_24h) / NULLIF(stddev_24h, 0) >= 2
# MAGIC ORDER BY zscore DESC;
# MAGIC
# MAGIC SELECT * FROM detect_timeseries_anomaly;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 4: Create Gold Alert Tables
# MAGIC
# MAGIC Consolidate all detections into a unified Gold alert table

# COMMAND ----------

# DBTITLE 1,Create Gold Alerts Table
# MAGIC %sql
# MAGIC -- Drop existing table if it exists
# MAGIC DROP TABLE IF EXISTS gold_security_alerts;
# MAGIC
# MAGIC -- Create unified alerts table
# MAGIC CREATE TABLE gold_security_alerts (
# MAGIC   alert_id STRING,
# MAGIC   detection_time TIMESTAMP,
# MAGIC   event_time TIMESTAMP,
# MAGIC   alert_title STRING,
# MAGIC   description STRING,
# MAGIC   severity STRING,
# MAGIC   mitre_technique STRING,
# MAGIC   mitre_tactic STRING,
# MAGIC   detection_rule STRING,
# MAGIC   
# MAGIC   -- Affected entities
# MAGIC   user STRING,
# MAGIC   host STRING,
# MAGIC   source_ip STRING,
# MAGIC   
# MAGIC   -- Additional context (stored as JSON for flexibility)
# MAGIC   context STRING,
# MAGIC   
# MAGIC   -- Alert management
# MAGIC   status STRING,  -- NEW, INVESTIGATING, FALSE_POSITIVE, TRUE_POSITIVE, RESOLVED
# MAGIC   assigned_to STRING,
# MAGIC   notes STRING,
# MAGIC   updated_at TIMESTAMP
# MAGIC )
# MAGIC USING DELTA
# MAGIC PARTITIONED BY (severity)
# MAGIC TBLPROPERTIES (
# MAGIC   'delta.enableChangeDataFeed' = 'true',
# MAGIC   'delta.autoOptimize.optimizeWrite' = 'true',
# MAGIC   'delta.autoOptimize.autoCompact' = 'true'
# MAGIC );
# MAGIC
# MAGIC SELECT 'Gold alerts table created successfully' AS status;

# COMMAND ----------

# DBTITLE 1,Populate Gold Alerts from Detections
# MAGIC %sql
# MAGIC -- Insert Mimikatz detections
# MAGIC INSERT INTO gold_security_alerts
# MAGIC SELECT
# MAGIC   uuid() AS alert_id,
# MAGIC   detection_time,
# MAGIC   event_time,
# MAGIC   alert_title,
# MAGIC   description,
# MAGIC   severity,
# MAGIC   mitre_technique,
# MAGIC   mitre_tactic,
# MAGIC   'detect_mimikatz' AS detection_rule,
# MAGIC   user,
# MAGIC   host,
# MAGIC   NULL AS source_ip,
# MAGIC   to_json(struct(process_name, command_line, parent_process_name, file_hash_sha256)) AS context,
# MAGIC   'NEW' AS status,
# MAGIC   NULL AS assigned_to,
# MAGIC   NULL AS notes,
# MAGIC   current_timestamp() AS updated_at
# MAGIC FROM detect_mimikatz;
# MAGIC
# MAGIC -- Insert PowerShell detections
# MAGIC INSERT INTO gold_security_alerts
# MAGIC SELECT
# MAGIC   uuid() AS alert_id,
# MAGIC   detection_time,
# MAGIC   event_time,
# MAGIC   alert_title,
# MAGIC   description,
# MAGIC   severity,
# MAGIC   mitre_technique,
# MAGIC   mitre_tactic,
# MAGIC   'detect_suspicious_powershell' AS detection_rule,
# MAGIC   user,
# MAGIC   host,
# MAGIC   NULL AS source_ip,
# MAGIC   to_json(struct(process_name, command_line, parent_process_name)) AS context,
# MAGIC   'NEW' AS status,
# MAGIC   NULL AS assigned_to,
# MAGIC   NULL AS notes,
# MAGIC   current_timestamp() AS updated_at
# MAGIC FROM detect_suspicious_powershell;
# MAGIC
# MAGIC -- Insert Okta brute force detections
# MAGIC INSERT INTO gold_security_alerts
# MAGIC SELECT
# MAGIC   uuid() AS alert_id,
# MAGIC   detection_time,
# MAGIC   first_failure AS event_time,
# MAGIC   alert_title,
# MAGIC   description,
# MAGIC   severity,
# MAGIC   mitre_technique,
# MAGIC   mitre_tactic,
# MAGIC   'detect_okta_bruteforce' AS detection_rule,
# MAGIC   user_email AS user,
# MAGIC   NULL AS host,
# MAGIC   source_ip,
# MAGIC   to_json(struct(failure_count, first_failure, last_failure, duration_minutes)) AS context,
# MAGIC   'NEW' AS status,
# MAGIC   NULL AS assigned_to,
# MAGIC   NULL AS notes,
# MAGIC   current_timestamp() AS updated_at
# MAGIC FROM detect_okta_bruteforce;
# MAGIC
# MAGIC -- Insert Windows brute force detections
# MAGIC INSERT INTO gold_security_alerts
# MAGIC SELECT
# MAGIC   uuid() AS alert_id,
# MAGIC   detection_time,
# MAGIC   first_failure AS event_time,
# MAGIC   alert_title,
# MAGIC   description,
# MAGIC   severity,
# MAGIC   mitre_technique,
# MAGIC   mitre_tactic,
# MAGIC   'detect_windows_bruteforce' AS detection_rule,
# MAGIC   user_name AS user,
# MAGIC   host,
# MAGIC   source_ip,
# MAGIC   to_json(struct(failure_count, first_failure, last_failure)) AS context,
# MAGIC   'NEW' AS status,
# MAGIC   NULL AS assigned_to,
# MAGIC   NULL AS notes,
# MAGIC   current_timestamp() AS updated_at
# MAGIC FROM detect_windows_bruteforce;
# MAGIC
# MAGIC -- Insert User Behavior Anomaly detections (ML-based)
# MAGIC INSERT INTO gold_security_alerts
# MAGIC SELECT
# MAGIC   uuid() AS alert_id,
# MAGIC   detection_time,
# MAGIC   event_time,
# MAGIC   alert_title,
# MAGIC   description,
# MAGIC   severity,
# MAGIC   mitre_technique,
# MAGIC   mitre_tactic,
# MAGIC   'detect_user_behavior_anomaly' AS detection_rule,
# MAGIC   user_email AS user,
# MAGIC   NULL AS host,
# MAGIC   NULL AS source_ip,
# MAGIC   to_json(struct(today_login_count, baseline_avg_logins, today_unique_ips, baseline_avg_ips, login_count_zscore, unique_ip_zscore)) AS context,
# MAGIC   'NEW' AS status,
# MAGIC   NULL AS assigned_to,
# MAGIC   NULL AS notes,
# MAGIC   current_timestamp() AS updated_at
# MAGIC FROM detect_user_behavior_anomaly;
# MAGIC
# MAGIC -- Insert Rare Process Execution detections
# MAGIC INSERT INTO gold_security_alerts
# MAGIC SELECT
# MAGIC   uuid() AS alert_id,
# MAGIC   detection_time,
# MAGIC   event_time,
# MAGIC   alert_title,
# MAGIC   description,
# MAGIC   severity,
# MAGIC   mitre_technique,
# MAGIC   mitre_tactic,
# MAGIC   'detect_rare_process_execution' AS detection_rule,
# MAGIC   user,
# MAGIC   host,
# MAGIC   NULL AS source_ip,
# MAGIC   to_json(struct(process_name, command_line, parent_process_name, historical_count, rarity_category, rarity_score)) AS context,
# MAGIC   'NEW' AS status,
# MAGIC   NULL AS assigned_to,
# MAGIC   NULL AS notes,
# MAGIC   current_timestamp() AS updated_at
# MAGIC FROM detect_rare_process_execution;
# MAGIC
# MAGIC -- Insert Network Anomaly detections
# MAGIC INSERT INTO gold_security_alerts
# MAGIC SELECT
# MAGIC   uuid() AS alert_id,
# MAGIC   detection_time,
# MAGIC   event_time,
# MAGIC   alert_title,
# MAGIC   description,
# MAGIC   severity,
# MAGIC   mitre_technique,
# MAGIC   mitre_tactic,
# MAGIC   'detect_network_anomaly' AS detection_rule,
# MAGIC   NULL AS user,
# MAGIC   host,
# MAGIC   NULL AS source_ip,
# MAGIC   to_json(struct(today_connections, baseline_avg_connections, today_unique_ips, baseline_avg_ips, connection_zscore, unique_ip_zscore)) AS context,
# MAGIC   'NEW' AS status,
# MAGIC   NULL AS assigned_to,
# MAGIC   NULL AS notes,
# MAGIC   current_timestamp() AS updated_at
# MAGIC FROM detect_network_anomaly;
# MAGIC
# MAGIC -- Insert Time-Series Anomaly detections
# MAGIC INSERT INTO gold_security_alerts
# MAGIC SELECT
# MAGIC   uuid() AS alert_id,
# MAGIC   detection_time,
# MAGIC   event_time,
# MAGIC   alert_title,
# MAGIC   description,
# MAGIC   severity,
# MAGIC   mitre_technique,
# MAGIC   mitre_tactic,
# MAGIC   'detect_timeseries_anomaly' AS detection_rule,
# MAGIC   NULL AS user,
# MAGIC   NULL AS host,
# MAGIC   NULL AS source_ip,
# MAGIC   to_json(struct(failure_count, baseline_avg, baseline_stddev, affected_users, source_ips, zscore, pct_change)) AS context,
# MAGIC   'NEW' AS status,
# MAGIC   NULL AS assigned_to,
# MAGIC   NULL AS notes,
# MAGIC   current_timestamp() AS updated_at
# MAGIC FROM detect_timeseries_anomaly;
# MAGIC
# MAGIC -- Display summary
# MAGIC SELECT 
# MAGIC   severity,
# MAGIC   detection_rule,
# MAGIC   COUNT(*) as alert_count
# MAGIC FROM gold_security_alerts
# MAGIC GROUP BY severity, detection_rule
# MAGIC ORDER BY severity, alert_count DESC;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Part 5: Detection Rule Metadata
# MAGIC
# MAGIC Store detection rule definitions and version history

# COMMAND ----------

# DBTITLE 1,Create Detection Rule Registry
# MAGIC %sql
# MAGIC CREATE TABLE IF NOT EXISTS gold_detection_rules (
# MAGIC   rule_id STRING,
# MAGIC   rule_name STRING,
# MAGIC   rule_version STRING,
# MAGIC   rule_query STRING,
# MAGIC   description STRING,
# MAGIC   severity STRING,
# MAGIC   mitre_technique STRING,
# MAGIC   mitre_tactic STRING,
# MAGIC   enabled BOOLEAN,
# MAGIC   false_positive_rate DOUBLE,
# MAGIC   last_tuned_date TIMESTAMP,
# MAGIC   created_by STRING,
# MAGIC   created_at TIMESTAMP,
# MAGIC   updated_at TIMESTAMP,
# MAGIC   tags ARRAY<STRING>
# MAGIC )
# MAGIC USING DELTA;
# MAGIC
# MAGIC -- Insert detection rule definitions
# MAGIC INSERT INTO gold_detection_rules VALUES
# MAGIC ('mimikatz_001', 'Mimikatz Execution', 'v1.0', 
# MAGIC  'SELECT * FROM silver_sysmon_process WHERE LOWER(process_name) LIKE ''%mimikatz%''',
# MAGIC  'Detects execution of Mimikatz credential dumping tool',
# MAGIC  'CRITICAL', 'T1003.001', 'Credential Access', TRUE, 0.01,
# MAGIC  current_timestamp(), 'security_team', current_timestamp(), current_timestamp(),
# MAGIC  array('credential_theft', 'mimikatz', 'lsass')),
# MAGIC  
# MAGIC ('powershell_001', 'Suspicious PowerShell', 'v1.2',
# MAGIC  'SELECT * FROM silver_sysmon_process WHERE LOWER(process_name) LIKE ''%powershell%'' AND command_line LIKE ''%-enc%''',
# MAGIC  'Detects obfuscated PowerShell commands',
# MAGIC  'HIGH', 'T1059.001', 'Execution', TRUE, 0.05,
# MAGIC  current_timestamp(), 'security_team', current_timestamp(), current_timestamp(),
# MAGIC  array('powershell', 'obfuscation', 'execution')),
# MAGIC  
# MAGIC ('okta_bruteforce_001', 'Okta Brute Force', 'v1.0',
# MAGIC  'SELECT user_email, COUNT(*) FROM silver_okta_auth WHERE outcome = ''FAILURE'' GROUP BY user_email HAVING COUNT(*) >= 5',
# MAGIC  'Detects brute force authentication attempts in Okta',
# MAGIC  'HIGH', 'T1110', 'Credential Access', TRUE, 0.10,
# MAGIC  current_timestamp(), 'security_team', current_timestamp(), current_timestamp(),
# MAGIC  array('brute_force', 'okta', 'authentication')),
# MAGIC  
# MAGIC ('windows_bruteforce_001', 'Windows Brute Force', 'v1.1',
# MAGIC  'SELECT user_name, COUNT(*) FROM silver_windows_auth WHERE logon_success = FALSE GROUP BY user_name HAVING COUNT(*) >= 10',
# MAGIC  'Detects Windows logon brute force attempts',
# MAGIC  'HIGH', 'T1110.001', 'Credential Access', TRUE, 0.08,
# MAGIC  current_timestamp(), 'security_team', current_timestamp(), current_timestamp(),
# MAGIC  array('brute_force', 'windows', 'authentication')),
# MAGIC
# MAGIC ('user_behavior_anomaly_001', 'User Behavior Anomaly (ML)', 'v1.0',
# MAGIC  'Statistical baseline analysis with Z-score anomaly detection for user login patterns',
# MAGIC  'ML-based detection of anomalous user behavior using statistical analysis and Z-scores',
# MAGIC  'MEDIUM', 'T1078', 'Initial Access', TRUE, 0.15,
# MAGIC  current_timestamp(), 'security_team', current_timestamp(), current_timestamp(),
# MAGIC  array('anomaly_detection', 'ml', 'ueba', 'statistical')),
# MAGIC
# MAGIC ('rare_process_execution_001', 'Rare Process Execution (ML)', 'v1.0',
# MAGIC  'Frequency-based rarity scoring for process execution patterns',
# MAGIC  'Detects rarely executed processes using historical frequency analysis',
# MAGIC  'MEDIUM', 'T1204', 'Execution', TRUE, 0.20,
# MAGIC  current_timestamp(), 'security_team', current_timestamp(), current_timestamp(),
# MAGIC  array('anomaly_detection', 'process_analysis', 'rarity', 'frequency')),
# MAGIC
# MAGIC ('network_anomaly_001', 'Network Traffic Anomaly (ML)', 'v1.0',
# MAGIC  'Statistical analysis of network connection patterns with Z-score detection',
# MAGIC  'Detects unusual network behavior using baseline statistical analysis',
# MAGIC  'MEDIUM', 'T1071', 'Command and Control', TRUE, 0.12,
# MAGIC  current_timestamp(), 'security_team', current_timestamp(), current_timestamp(),
# MAGIC  array('anomaly_detection', 'network', 'statistical', 'c2')),
# MAGIC
# MAGIC ('user_clustering_001', 'User Behavior Clustering (ML)', 'v1.0',
# MAGIC  'K-Means clustering to identify outlier user behavior patterns',
# MAGIC  'ML-based clustering using K-Means to detect anomalous user behavior',
# MAGIC  'MEDIUM', 'T1078', 'Initial Access', TRUE, 0.18,
# MAGIC  current_timestamp(), 'security_team', current_timestamp(), current_timestamp(),
# MAGIC  array('anomaly_detection', 'ml', 'clustering', 'kmeans', 'ueba')),
# MAGIC
# MAGIC ('timeseries_anomaly_001', 'Authentication Spike Detection (ML)', 'v1.0',
# MAGIC  'Time-series analysis with moving averages to detect authentication spikes',
# MAGIC  'Detects unusual spikes in failed authentication attempts using statistical methods',
# MAGIC  'MEDIUM', 'T1110', 'Credential Access', TRUE, 0.10,
# MAGIC  current_timestamp(), 'security_team', current_timestamp(), current_timestamp(),
# MAGIC  array('anomaly_detection', 'timeseries', 'authentication', 'statistical'));
# MAGIC  
# MAGIC SELECT * FROM gold_detection_rules;

# COMMAND ----------

# MAGIC %md
# MAGIC ## Summary: View All Alerts

# COMMAND ----------

# DBTITLE 1,Alert Dashboard Query
# MAGIC %sql
# MAGIC -- Summary of all alerts
# MAGIC SELECT
# MAGIC   severity,
# MAGIC   COUNT(*) as alert_count,
# MAGIC   COUNT(DISTINCT user) as affected_users,
# MAGIC   COUNT(DISTINCT host) as affected_hosts,
# MAGIC   COUNT(DISTINCT mitre_technique) as unique_techniques
# MAGIC FROM gold_security_alerts
# MAGIC WHERE status = 'NEW'
# MAGIC GROUP BY severity
# MAGIC ORDER BY 
# MAGIC   CASE severity
# MAGIC     WHEN 'CRITICAL' THEN 1
# MAGIC     WHEN 'HIGH' THEN 2
# MAGIC     WHEN 'MEDIUM' THEN 3
# MAGIC     WHEN 'LOW' THEN 4
# MAGIC   END;

# COMMAND ----------

# DBTITLE 1,Recent Critical Alerts
# MAGIC %sql
# MAGIC SELECT
# MAGIC   alert_id,
# MAGIC   detection_time,
# MAGIC   alert_title,
# MAGIC   user,
# MAGIC   host,
# MAGIC   source_ip,
# MAGIC   mitre_technique,
# MAGIC   description
# MAGIC FROM gold_security_alerts
# MAGIC WHERE severity IN ('CRITICAL', 'HIGH')
# MAGIC ORDER BY detection_time DESC
# MAGIC LIMIT 25;

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Lab 03 Summary
# MAGIC
# MAGIC ### What You Built:
# MAGIC ✅ **Signature-based detections:** Mimikatz, PowerShell, PsExec  
# MAGIC ✅ **Threshold-based detections:** Brute force (Okta, Windows, AWS)  
# MAGIC ✅ **Advanced detections:** Impossible travel, privilege escalation  
# MAGIC ✅ **ML-based anomaly detection:** UEBA, rare processes, network anomalies, clustering, time-series  
# MAGIC ✅ **Gold alert layer:** Unified alert management system  
# MAGIC ✅ **Detection registry:** Rule versioning and metadata  
# MAGIC
# MAGIC ### Key Detection Patterns:
# MAGIC 1. **Process-based:** Known malicious executables
# MAGIC 2. **Command-line:** Suspicious arguments and obfuscation
# MAGIC 3. **Frequency:** Threshold violations
# MAGIC 4. **Behavioral:** Anomalous patterns (impossible travel)
# MAGIC 5. **Contextual:** Privilege changes, lateral movement
# MAGIC 6. **Statistical:** Z-score anomaly detection for user behavior and network traffic
# MAGIC 7. **ML Clustering:** K-Means clustering to identify outlier users
# MAGIC 8. **Rarity Analysis:** Frequency-based detection of rare process executions
# MAGIC 9. **Time-Series:** Moving averages for spike detection
# MAGIC
# MAGIC ### MITRE ATT&CK Coverage:
# MAGIC - **Initial Access:** T1078 (Valid Accounts)
# MAGIC - **Execution:** T1059.001 (PowerShell), T1204 (User Execution)
# MAGIC - **Credential Access:** T1003.001, T1110 (Brute Force)
# MAGIC - **Lateral Movement:** T1570 (Lateral Tool Transfer)
# MAGIC - **Privilege Escalation:** T1098 (Account Manipulation)
# MAGIC - **Discovery:** T1046 (Network Service Scanning)
# MAGIC - **Command and Control:** T1071 (Application Layer Protocol)
# MAGIC
# MAGIC ### Next Steps:
# MAGIC ➡️ **Lab 04:** Operationalize and Validate  
# MAGIC - Schedule detection workflows  
# MAGIC - Configure alerting  
# MAGIC - Build dashboards  
# MAGIC - Test with malicious samples  
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## 🎓 Instructor Notes
# MAGIC
# MAGIC ### Discussion Points:
# MAGIC 1. **Detection Engineering Principles:**
# MAGIC    - Signal-to-noise ratio
# MAGIC    - False positive management
# MAGIC    - Detection coverage vs. alert volume
# MAGIC
# MAGIC 2. **Rule Tuning:**
# MAGIC    - Baseline establishment
# MAGIC    - Threshold calibration
# MAGIC    - Environmental context
# MAGIC
# MAGIC 3. **MITRE ATT&CK:**
# MAGIC    - Why framework matters
# MAGIC    - Gap analysis
# MAGIC    - Prioritization strategy
# MAGIC
# MAGIC ### Advanced Topics:
# MAGIC - **Machine learning for anomaly detection:**
# MAGIC   - Statistical methods (Z-scores, standard deviations)
# MAGIC   - Unsupervised learning (K-Means clustering for UEBA)
# MAGIC   - Time-series analysis (moving averages, seasonal decomposition)
# MAGIC   - Rarity scoring and frequency analysis
# MAGIC   - Feature engineering for security ML
# MAGIC   - Baseline establishment and model retraining
# MAGIC - **Behavioral analytics (UEBA):**
# MAGIC   - User profiling and peer group analysis
# MAGIC   - Anomaly scoring and risk aggregation
# MAGIC   - Temporal pattern analysis
# MAGIC - **Threat hunting vs. detection engineering:**
# MAGIC   - Hypothesis-driven hunting
# MAGIC   - Proactive vs. reactive detection
# MAGIC - **Detection as code (version control, CI/CD):**
# MAGIC   - Rule versioning and testing
# MAGIC   - False positive management
# MAGIC   - Performance optimization
# MAGIC
# MAGIC ### ML Anomaly Detection Discussion:
# MAGIC 1. **Statistical vs. ML Approaches:**
# MAGIC    - When to use simple statistics (Z-scores) vs. complex ML models
# MAGIC    - Trade-offs: interpretability, maintainability, accuracy
# MAGIC    - Cold start problem: minimum data requirements
# MAGIC
# MAGIC 2. **Baseline Management:**
# MAGIC    - How long to establish a baseline (30 days typical)
# MAGIC    - Handling seasonal patterns and business cycles
# MAGIC    - Model drift and retraining strategies
# MAGIC
# MAGIC 3. **Tuning Anomaly Thresholds:**
# MAGIC    - Z-score thresholds (2σ = 95%, 3σ = 99.7%)
# MAGIC    - Balancing sensitivity vs. specificity
# MAGIC    - Context-aware thresholding
# MAGIC
# MAGIC 4. **Real-World Challenges:**
# MAGIC    - High false positive rates in anomaly detection
# MAGIC    - Adversarial adaptation (attackers learning baselines)
# MAGIC    - Integration with SOC workflows
# MAGIC