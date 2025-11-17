# Databricks notebook source
# MAGIC %md
# MAGIC # Lab 02: Data Ingestion and Normalization with Delta Live Tables
# MAGIC
# MAGIC ## Overview
# MAGIC In this lab, you will:
# MAGIC 1. Configure Auto Loader for streaming data ingestion
# MAGIC 2. Create Bronze tables with raw security logs
# MAGIC 3. Build Silver transformations (parse, normalize, enrich)
# MAGIC 4. Deploy a Delta Live Tables (DLT) pipeline
# MAGIC
# MAGIC **Time:** ~10 minutes
# MAGIC
# MAGIC ## Architecture: Bronze → Silver → Gold
# MAGIC ```
# MAGIC Raw Logs (Volume) → Bronze (Raw) → Silver (Normalized) → Gold (Alerts)
# MAGIC                      ↓ Auto Loader    ↓ Transformations   ↓ Detections
# MAGIC ```

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration
# MAGIC
# MAGIC **Note:** This is a Delta Live Tables notebook. Run it by creating a DLT pipeline (see Step 9).

# COMMAND ----------

import dlt
from pyspark.sql.functions import *
from pyspark.sql.types import *

# Configuration - should match Lab 01
CATALOG_NAME = "security_detection_engineering_lab"
SCHEMA_NAME = "security_logs"
VOLUME_NAME = "raw_logs"
VOLUME_PATH = f"/Volumes/{CATALOG_NAME}/{SCHEMA_NAME}/{VOLUME_NAME}"

# COMMAND ----------

# MAGIC %md
# MAGIC ## Bronze Layer: Raw Data Ingestion
# MAGIC
# MAGIC Bronze tables contain raw, unprocessed data exactly as received.
# MAGIC We use Auto Loader for efficient incremental ingestion.

# COMMAND ----------

# DBTITLE 1,Bronze: Sysmon Logs
@dlt.table(
    name="bronze_sysmon",
    comment="Raw Sysmon logs ingested from JSON files",
    table_properties={
        "quality": "bronze",
        "pipelines.autoOptimize.zOrderCols": "EventTime"
    }
)
def bronze_sysmon():
    """Ingest raw Sysmon logs using Auto Loader"""
    return (
        spark.readStream
        .format("cloudFiles")
        .option("cloudFiles.format", "json")
        .option("cloudFiles.schemaLocation", f"{VOLUME_PATH}/schemas/sysmon")
        .option("cloudFiles.inferColumnTypes", "true")
        .load(f"{VOLUME_PATH}/sysmon_logs.json")
        .withColumn("ingestion_timestamp", current_timestamp())
        .withColumn("source_file", col("_metadata.file_path"))
    )

# COMMAND ----------

# DBTITLE 1,Bronze: Okta Logs
@dlt.table(
    name="bronze_okta",
    comment="Raw Okta authentication logs",
    table_properties={
        "quality": "bronze"
    }
)
def bronze_okta():
    """Ingest raw Okta logs"""
    return (
        spark.readStream
        .format("cloudFiles")
        .option("cloudFiles.format", "json")
        .option("cloudFiles.schemaLocation", f"{VOLUME_PATH}/schemas/okta")
        .option("cloudFiles.inferColumnTypes", "true")
        .load(f"{VOLUME_PATH}/okta_logs.json")
        .withColumn("ingestion_timestamp", current_timestamp())
        .withColumn("source_file", col("_metadata.file_path"))
    )

# COMMAND ----------

# DBTITLE 1,Bronze: Windows Event Logs
@dlt.table(
    name="bronze_windows",
    comment="Raw Windows Security Event logs",
    table_properties={
        "quality": "bronze"
    }
)
def bronze_windows():
    """Ingest raw Windows Event logs"""
    return (
        spark.readStream
        .format("cloudFiles")
        .option("cloudFiles.format", "json")
        .option("cloudFiles.schemaLocation", f"{VOLUME_PATH}/schemas/windows")
        .option("cloudFiles.inferColumnTypes", "true")
        .load(f"{VOLUME_PATH}/windows_logs.json")
        .withColumn("ingestion_timestamp", current_timestamp())
        .withColumn("source_file", col("_metadata.file_path"))
    )

# COMMAND ----------

# DBTITLE 1,Bronze: CloudTrail Logs
@dlt.table(
    name="bronze_cloudtrail",
    comment="Raw AWS CloudTrail logs",
    table_properties={
        "quality": "bronze"
    }
)
def bronze_cloudtrail():
    """Ingest raw CloudTrail logs"""
    return (
        spark.readStream
        .format("cloudFiles")
        .option("cloudFiles.format", "json")
        .option("cloudFiles.schemaLocation", f"{VOLUME_PATH}/schemas/cloudtrail")
        .option("cloudFiles.inferColumnTypes", "true")
        .load(f"{VOLUME_PATH}/cloudtrail_logs.json")
        .withColumn("ingestion_timestamp", current_timestamp())
        .withColumn("source_file", col("_metadata.file_path"))
    )

# COMMAND ----------

# MAGIC %md
# MAGIC ## Silver Layer: Normalized and Enriched Data
# MAGIC
# MAGIC Silver tables contain cleaned, normalized, and enriched data.
# MAGIC Transformations include:
# MAGIC - Parsing nested JSON structures
# MAGIC - Standardizing field names
# MAGIC - Type conversions
# MAGIC - Data quality checks
# MAGIC - Enrichment (GeoIP, threat intel, etc.)

# COMMAND ----------

# DBTITLE 1,Silver: Sysmon - Process Events
@dlt.table(
    name="silver_sysmon_process",
    comment="Normalized Sysmon process creation events (EventID 1)",
    table_properties={
        "quality": "silver",
        "delta.enableChangeDataFeed": "true"
    }
)
@dlt.expect_all({
    "valid_timestamp": "event_time IS NOT NULL",
    "valid_process": "process_name IS NOT NULL"
})
def silver_sysmon_process():
    """Transform and normalize Sysmon process events"""
    return (
        dlt.read_stream("bronze_sysmon")
        .filter(col("EventID") == 1)  # Process creation events
        .select(
            # Standardized fields
            col("EventTime").cast("timestamp").alias("event_time"),
            col("Computer").alias("host"),
            col("ProcessName").alias("process_name"),
            col("ProcessId").cast("integer").alias("process_id"),
            col("CommandLine").alias("command_line"),
            col("User").alias("user"),
            col("ParentProcessName").alias("parent_process_name"),
            col("ParentProcessId").cast("integer").alias("parent_process_id"),
            col("SHA256").alias("file_hash_sha256"),
            
            # Enrichment flags
            when(
                lower(col("ProcessName")).rlike("mimikatz|procdump|psexec|pwdump"),
                "suspicious_process"
            ).when(
                lower(col("CommandLine")).rlike("-enc|-encodedcommand|-w hidden|-nop"),
                "suspicious_commandline"
            ).when(
                lower(col("ProcessName")).contains("powershell") & 
                lower(col("CommandLine")).rlike("iex|invoke-|downloadstring"),
                "powershell_download"
            ).otherwise("normal").alias("threat_indicator"),
            
            # Metadata
            lit("sysmon").alias("log_source"),
            lit("process_creation").alias("event_category"),
            current_timestamp().alias("processed_timestamp")
        )
    )

# COMMAND ----------

# DBTITLE 1,Silver: Sysmon - Network Events
@dlt.table(
    name="silver_sysmon_network",
    comment="Normalized Sysmon network connection events (EventID 3)"
)
@dlt.expect_all({
    "valid_timestamp": "event_time IS NOT NULL",
    "valid_destination": "destination_ip IS NOT NULL OR destination_port IS NOT NULL"
})
def silver_sysmon_network():
    """Transform Sysmon network connection events"""
    return (
        dlt.read_stream("bronze_sysmon")
        .filter(col("EventID") == 3)  # Network connection events
        .filter(col("DestinationIP").isNotNull())
        .select(
            col("EventTime").cast("timestamp").alias("event_time"),
            col("Computer").alias("host"),
            col("ProcessName").alias("process_name"),
            col("ProcessId").cast("integer").alias("process_id"),
            col("User").alias("user"),
            col("DestinationIP").alias("destination_ip"),
            col("DestinationPort").cast("integer").alias("destination_port"),
            
            # Classify suspicious ports
            when(col("DestinationPort").isin(22, 3389, 445, 135), "lateral_movement_port")
            .when(col("DestinationPort").isin(4444, 8080, 1337), "c2_common_port")
            .otherwise("normal").alias("port_classification"),
            
            lit("sysmon").alias("log_source"),
            lit("network_connection").alias("event_category"),
            current_timestamp().alias("processed_timestamp")
        )
    )

# COMMAND ----------

# DBTITLE 1,Silver: Okta Authentication
@dlt.table(
    name="silver_okta_auth",
    comment="Normalized Okta authentication events"
)
@dlt.expect_all({
    "valid_timestamp": "event_time IS NOT NULL",
    "valid_user": "user_email IS NOT NULL"
})
def silver_okta_auth():
    """Transform Okta authentication logs"""
    return (
        dlt.read_stream("bronze_okta")
        .select(
            col("published").cast("timestamp").alias("event_time"),
            col("uuid").alias("event_id"),
            col("eventType").alias("event_type"),
            col("actor.alternateId").alias("user_email"),
            col("actor.displayName").alias("user_name"),
            col("client.ipAddress").alias("source_ip"),
            col("client.userAgent").alias("user_agent"),
            col("client.geographicalContext.city").alias("city"),
            col("client.geographicalContext.country").alias("country"),
            col("outcome.result").alias("outcome"),
            col("outcome.reason").alias("failure_reason"),
            col("target")[0]["displayName"].alias("target_application"),
            
            # Risk indicators
            when(col("outcome.result") == "FAILURE", "failed_auth")
            .when(
                (col("eventType").rlike("admin|policy|mfa")) & 
                (col("outcome.result") == "SUCCESS"),
                "privileged_action"
            )
            .otherwise("normal").alias("risk_indicator"),
            
            lit("okta").alias("log_source"),
            lit("authentication").alias("event_category"),
            current_timestamp().alias("processed_timestamp")
        )
    )

# COMMAND ----------

# DBTITLE 1,Silver: Windows Authentication
@dlt.table(
    name="silver_windows_auth",
    comment="Normalized Windows authentication events"
)
@dlt.expect_all({
    "valid_timestamp": "event_time IS NOT NULL",
    "valid_user": "user_name IS NOT NULL"
})
def silver_windows_auth():
    """Transform Windows Event authentication logs"""
    return (
        dlt.read_stream("bronze_windows")
        .filter(col("EventID").isin(4624, 4625, 4672))  # Logon events
        .select(
            col("TimeCreated").cast("timestamp").alias("event_time"),
            col("EventID").cast("integer").alias("event_id"),
            col("Computer").alias("host"),
            col("LogonType").cast("integer").alias("logon_type"),
            col("LogonTypeName").alias("logon_type_name"),
            col("TargetUserName").alias("user_name"),
            col("TargetDomainName").alias("domain"),
            col("WorkstationName").alias("workstation"),
            col("SourceNetworkAddress").alias("source_ip"),
            col("Status").alias("status_code"),
            
            # Classification
            when(col("EventID") == 4625, "failed_logon")
            .when(col("EventID") == 4672, "privileged_logon")
            .when(col("LogonType") == 10, "rdp_logon")
            .when(col("LogonType") == 3, "network_logon")
            .otherwise("normal_logon").alias("logon_classification"),
            
            # Success/Failure
            when(col("EventID") == 4625, lit(False))
            .otherwise(lit(True)).alias("logon_success"),
            
            lit("windows_security").alias("log_source"),
            lit("authentication").alias("event_category"),
            current_timestamp().alias("processed_timestamp")
        )
    )

# COMMAND ----------

# DBTITLE 1,Silver: CloudTrail API Calls
@dlt.table(
    name="silver_cloudtrail",
    comment="Normalized AWS CloudTrail API calls"
)
@dlt.expect_all({
    "valid_timestamp": "event_time IS NOT NULL",
    "valid_event": "event_name IS NOT NULL"
})
def silver_cloudtrail():
    """Transform CloudTrail logs"""
    return (
        dlt.read_stream("bronze_cloudtrail")
        .select(
            col("eventTime").cast("timestamp").alias("event_time"),
            col("eventID").alias("event_id"),
            col("eventName").alias("event_name"),
            col("eventType").alias("event_type"),
            col("eventSource").alias("service"),
            col("awsRegion").alias("region"),
            col("sourceIPAddress").alias("source_ip"),
            col("userAgent").alias("user_agent"),
            col("errorCode").alias("error_code"),
            col("errorMessage").alias("error_message"),
            col("userIdentity.userName").alias("user_name"),
            col("userIdentity.principalId").alias("principal_id"),
            col("userIdentity.arn").alias("user_arn"),
            col("requestParameters.bucketName").alias("s3_bucket"),
            col("requestParameters.userName").alias("target_user"),
            
            # Risk classification
            when(col("eventName").rlike("Create.*Key|Attach.*Policy|Create.*User|Delete.*"), "high_risk_action")
            .when(col("errorCode").isNotNull(), "failed_api_call")
            .otherwise("normal").alias("risk_classification"),
            
            # Success indicator
            when(col("errorCode").isNull(), lit(True))
            .otherwise(lit(False)).alias("api_success"),
            
            lit("cloudtrail").alias("log_source"),
            lit("cloud_api").alias("event_category"),
            current_timestamp().alias("processed_timestamp")
        )
    )

# COMMAND ----------

# MAGIC %md
# MAGIC ## Data Quality Monitoring (Optional)
# MAGIC
# MAGIC **Note:** Data quality metrics can be viewed after pipeline completes.  
# MAGIC The quality metrics table is commented out to avoid streaming dependency issues.  
# MAGIC You can query Silver tables directly to check data quality.

# COMMAND ----------

# DBTITLE 1,Data Quality Metrics (Optional - Commented Out)
# 
# NOTE: This section is commented out to avoid DLT streaming dependency issues.
# To enable data quality metrics, you can create a separate batch notebook 
# that reads from the materialized Silver tables after the DLT pipeline completes.
#
# Example query to run AFTER DLT pipeline (in a separate notebook):
#
# spark.sql("""
#   SELECT 
#     'sysmon_process' as log_source,
#     COUNT(*) as event_count,
#     COUNT(DISTINCT host) as unique_hosts,
#     SUM(CASE WHEN threat_indicator != 'normal' THEN 1 ELSE 0 END) as suspicious_events
#   FROM security_detection_lab.security_logs.silver_sysmon_process
#   
#   UNION ALL
#   
#   SELECT 
#     'okta' as log_source,
#     COUNT(*) as event_count,
#     COUNT(DISTINCT user_email) as unique_users,
#     SUM(CASE WHEN outcome = 'FAILURE' THEN 1 ELSE 0 END) as failed_events
#   FROM security_detection_lab.security_logs.silver_okta_auth
#   
#   UNION ALL
#   
#   SELECT 
#     'windows' as log_source,
#     COUNT(*) as event_count,
#     COUNT(DISTINCT host) as unique_hosts,
#     SUM(CASE WHEN logon_success = FALSE THEN 1 ELSE 0 END) as failed_logons
#   FROM security_detection_lab.security_logs.silver_windows_auth
# """)

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Step 9: Create and Run the DLT Pipeline
# MAGIC
# MAGIC ### Option A: UI-Based Pipeline Creation
# MAGIC
# MAGIC 1. **Navigate to Delta Live Tables:**
# MAGIC    - In Databricks workspace, click **Workflows** → **Delta Live Tables**
# MAGIC    - Click **Create Pipeline**
# MAGIC
# MAGIC 2. **Configure Pipeline:**
# MAGIC    ```
# MAGIC    Pipeline Name: security_detection_pipeline
# MAGIC    Notebook: /path/to/02_data_ingestion_dlt
# MAGIC    Target Schema: security_detection_lab.security_logs
# MAGIC    Storage Location: (leave default or specify)
# MAGIC    Cluster Mode: Fixed Size (1 worker)
# MAGIC    Pipeline Mode: Triggered (for lab) or Continuous (for production)
# MAGIC    ```
# MAGIC
# MAGIC 3. **Click "Start"** to run the pipeline
# MAGIC
# MAGIC 4. **Monitor Progress:**
# MAGIC    - View DAG (Directed Acyclic Graph)
# MAGIC    - Check data quality metrics
# MAGIC    - Monitor throughput and latency
# MAGIC
# MAGIC ### Option B: API-Based Pipeline Creation

# COMMAND ----------

# DBTITLE 1,Create Pipeline via API (Optional)
# Uncomment and run to create pipeline programmatically

# import requests
# import json

# # Get workspace URL and token
# workspace_url = dbutils.notebook.entry_point.getDbutils().notebook().getContext().apiUrl().get()
# token = dbutils.notebook.entry_point.getDbutils().notebook().getContext().apiToken().get()

# # Pipeline configuration
# pipeline_config = {
#     "name": "security_detection_pipeline",
#     "storage": f"/pipelines/security_detection_lab",
#     "target": f"{CATALOG_NAME}.{SCHEMA_NAME}",
#     "notebooks": [{
#         "path": dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()
#     }],
#     "clusters": [{
#         "label": "default",
#         "num_workers": 1
#     }],
#     "development": True,
#     "continuous": False,
#     "channel": "CURRENT"
# }

# # Create pipeline
# headers = {
#     "Authorization": f"Bearer {token}",
#     "Content-Type": "application/json"
# }

# response = requests.post(
#     f"{workspace_url}/api/2.0/pipelines",
#     headers=headers,
#     data=json.dumps(pipeline_config)
# )

# if response.status_code == 200:
#     pipeline_id = response.json()["pipeline_id"]
#     print(f"✅ Pipeline created: {pipeline_id}")
#     print(f"   View at: {workspace_url}#joblist/pipelines/{pipeline_id}")
# else:
#     print(f"❌ Error: {response.text}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 10: Verify Silver Tables and Data Quality
# MAGIC
# MAGIC **Important:** Run these queries in a SEPARATE SQL notebook or cell AFTER the DLT pipeline completes.  
# MAGIC These queries read from the materialized Silver tables, not within the DLT pipeline.

# COMMAND ----------

# DBTITLE 1,Verify Silver Tables (Run After Pipeline Completes)
# Run these queries in a separate notebook AFTER DLT pipeline completes

# # List all tables
# spark.sql(f"USE CATALOG {CATALOG_NAME}")
# spark.sql(f"USE SCHEMA {SCHEMA_NAME}")
# display(spark.sql("SHOW TABLES"))

# # Count records in each Silver table
# print("\n" + "=" * 80)
# print("SILVER TABLE RECORD COUNTS")
# print("=" * 80)

# tables = [
#     "silver_sysmon_process",
#     "silver_sysmon_network",
#     "silver_okta_auth",
#     "silver_windows_auth",
#     "silver_cloudtrail"
# ]

# for table in tables:
#     try:
#         count = spark.sql(f"SELECT COUNT(*) as cnt FROM {table}").collect()[0]['cnt']
#         print(f"  {table}: {count:,} records")
#     except Exception as e:
#         print(f"  {table}: Not yet created or error - {e}")

# # Data Quality Check
# print("\n" + "=" * 80)
# print("DATA QUALITY METRICS")
# print("=" * 80)

# display(spark.sql("""
#   SELECT 
#     'sysmon_process' as log_source,
#     COUNT(*) as total_events,
#     COUNT(DISTINCT host) as unique_hosts,
#     SUM(CASE WHEN threat_indicator != 'normal' THEN 1 ELSE 0 END) as suspicious_events,
#     ROUND(SUM(CASE WHEN threat_indicator != 'normal' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as suspicious_pct
#   FROM security_detection_lab.security_logs.silver_sysmon_process
#   
#   UNION ALL
#   
#   SELECT 
#     'okta' as log_source,
#     COUNT(*) as total_events,
#     COUNT(DISTINCT user_email) as unique_users,
#     SUM(CASE WHEN outcome = 'FAILURE' THEN 1 ELSE 0 END) as failed_events,
#     ROUND(SUM(CASE WHEN outcome = 'FAILURE' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as failure_pct
#   FROM security_detection_lab.security_logs.silver_okta_auth
#   
#   UNION ALL
#   
#   SELECT 
#     'windows' as log_source,
#     COUNT(*) as total_events,
#     COUNT(DISTINCT host) as unique_hosts,
#     SUM(CASE WHEN logon_success = FALSE THEN 1 ELSE 0 END) as failed_logons,
#     ROUND(SUM(CASE WHEN logon_success = FALSE THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as failure_pct
#   FROM security_detection_lab.security_logs.silver_windows_auth
#   
#   UNION ALL
#   
#   SELECT 
#     'cloudtrail' as log_source,
#     COUNT(*) as total_events,
#     COUNT(DISTINCT user_name) as unique_users,
#     SUM(CASE WHEN risk_classification = 'high_risk_action' THEN 1 ELSE 0 END) as high_risk_events,
#     ROUND(SUM(CASE WHEN risk_classification = 'high_risk_action' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as high_risk_pct
#   FROM security_detection_lab.security_logs.silver_cloudtrail
# """))

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Lab 02 Summary
# MAGIC
# MAGIC ### What You Built:
# MAGIC ✅ **Bronze Layer:** Raw data ingestion with Auto Loader  
# MAGIC ✅ **Silver Layer:** Normalized, enriched security events  
# MAGIC ✅ **Data Quality:** Expectations and monitoring  
# MAGIC ✅ **Delta Live Tables Pipeline:** Automated, scalable ingestion  
# MAGIC
# MAGIC ### Key Concepts:
# MAGIC - **Medallion Architecture:** Bronze → Silver → Gold
# MAGIC - **Auto Loader:** Efficient incremental ingestion
# MAGIC - **Delta Live Tables:** Declarative ETL framework
# MAGIC - **Data Quality:** Expectations and constraints
# MAGIC - **Schema Evolution:** Automatic schema inference
# MAGIC
# MAGIC ### Next Steps:
# MAGIC ➡️ **Lab 03:** Detection Logic Authoring  
# MAGIC - Write SQL detection rules  
# MAGIC - Implement threshold-based detections  
# MAGIC - Build anomaly detection models  
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## 🎓 Instructor Notes
# MAGIC
# MAGIC ### Discussion Points:
# MAGIC 1. **Why Medallion Architecture?**
# MAGIC    - Raw data preservation (Bronze)
# MAGIC    - Reprocessing capability
# MAGIC    - Separation of concerns
# MAGIC
# MAGIC 2. **Auto Loader vs. Structured Streaming:**
# MAGIC    - Schema inference and evolution
# MAGIC    - File tracking and checkpointing
# MAGIC    - Cost efficiency
# MAGIC
# MAGIC 3. **Data Quality Best Practices:**
# MAGIC    - Expectations vs. constraints
# MAGIC    - When to drop vs. quarantine
# MAGIC    - Monitoring and alerting
# MAGIC
# MAGIC ### Common Issues:
# MAGIC - **Schema mismatches:** Use `cloudFiles.schemaEvolutionMode`
# MAGIC - **Slow startup:** Check cluster size and file count
# MAGIC - **Memory errors:** Partition data, increase cluster resources
# MAGIC
# MAGIC ### Production Considerations:
# MAGIC - Enable Change Data Feed for audit
# MAGIC - Configure retention policies
# MAGIC - Set up monitoring and alerts
# MAGIC - Implement cost controls (auto-scaling)
# MAGIC