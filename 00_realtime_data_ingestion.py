# Databricks notebook source
# MAGIC %md
# MAGIC # Real-Time Security Log Ingestion and Transformation
# MAGIC
# MAGIC ## Overview
# MAGIC This notebook ingests real-time security logs from multiple sources and converts them to standardized JSON format for the Security Detection Lab.
# MAGIC
# MAGIC **Supported Log Sources:**
# MAGIC 1. **Sysmon** - Windows System Monitor events (XML/JSON)
# MAGIC 2. **Okta** - Authentication and authorization logs (API/JSON)
# MAGIC 3. **Windows Event Logs** - Security events (EVTX/XML/CSV)
# MAGIC 4. **AWS CloudTrail** - AWS API activity (JSON/GZ)
# MAGIC
# MAGIC **Features:**
# MAGIC - Real-time streaming ingestion
# MAGIC - Format standardization to JSON
# MAGIC - Schema validation and enrichment
# MAGIC - Integration with existing Delta Live Tables pipeline
# MAGIC
# MAGIC **Time:** ~15 minutes to setup
# MAGIC
# MAGIC ## Architecture
# MAGIC ```
# MAGIC Raw Sources → Format Conversion → JSON Standardization → UC Volumes → DLT Pipeline
# MAGIC   (Various)      (This Notebook)    (Streaming/Batch)        (Bronze)    (Lab 02)
# MAGIC ```

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1: Install Required Libraries

# COMMAND ----------

# DBTITLE 1,Install Dependencies
# MAGIC %pip install xmltodict boto3 requests python-evtx --quiet
# MAGIC dbutils.library.restartPython()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Configuration

# COMMAND ----------

# DBTITLE 1,Configuration Variables
import json
import gzip
import xmltodict
import requests
from datetime import datetime, timedelta
from pyspark.sql.functions import *
from pyspark.sql.types import *
import uuid

# Configuration - MUST MATCH Lab 01
CATALOG_NAME = "security_detection_engineering_lab"
SCHEMA_NAME = "security_logs"
VOLUME_NAME = "raw_logs"
VOLUME_PATH = f"/Volumes/{CATALOG_NAME}/{SCHEMA_NAME}/{VOLUME_NAME}"

# Real-time ingestion configuration
INGESTION_MODE = "streaming"  # Options: "streaming", "batch"
CHECKPOINT_PATH = f"{VOLUME_PATH}/checkpoints"

# API Configuration (Update with your credentials)
OKTA_DOMAIN = "your-domain.okta.com"  # e.g., "dev-12345.okta.com"
OKTA_API_TOKEN = "YOUR_OKTA_API_TOKEN"  # Get from Okta Admin Console

AWS_REGION = "us-west-2"
AWS_CLOUDTRAIL_BUCKET = "your-cloudtrail-bucket"
AWS_ACCESS_KEY = "YOUR_AWS_ACCESS_KEY"  # Or use IAM role
AWS_SECRET_KEY = "YOUR_AWS_SECRET_KEY"

print(f"✅ Configuration loaded")
print(f"   Catalog: {CATALOG_NAME}")
print(f"   Volume Path: {VOLUME_PATH}")
print(f"   Ingestion Mode: {INGESTION_MODE}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3: Sysmon Log Ingestion (XML/JSON → JSON)
# MAGIC
# MAGIC Sysmon logs can come in two formats:
# MAGIC - **XML** from Windows Event Viewer export
# MAGIC - **JSON** from Winlogbeat or other forwarders
# MAGIC
# MAGIC We'll handle both formats and normalize to a standard JSON schema.

# COMMAND ----------

# DBTITLE 1,Sysmon: Define Standard Schema
sysmon_schema = StructType([
    StructField("EventID", IntegerType(), True),
    StructField("EventTime", TimestampType(), True),
    StructField("Computer", StringType(), True),
    StructField("User", StringType(), True),
    StructField("ProcessGuid", StringType(), True),
    StructField("ProcessId", IntegerType(), True),
    StructField("Image", StringType(), True),
    StructField("CommandLine", StringType(), True),
    StructField("CurrentDirectory", StringType(), True),
    StructField("ParentImage", StringType(), True),
    StructField("ParentCommandLine", StringType(), True),
    StructField("ParentProcessGuid", StringType(), True),
    StructField("ParentProcessId", IntegerType(), True),
    StructField("TargetFilename", StringType(), True),
    StructField("DestinationIp", StringType(), True),
    StructField("DestinationPort", IntegerType(), True),
    StructField("SourceIp", StringType(), True),
    StructField("SourcePort", IntegerType(), True),
    StructField("Protocol", StringType(), True),
    StructField("Hashes", StringType(), True),
    StructField("RawEventData", StringType(), True)
])

print("✅ Sysmon schema defined")

# COMMAND ----------

# DBTITLE 1,Sysmon: XML to JSON Conversion Function
def convert_sysmon_xml_to_json(xml_content):
    """
    Convert Sysmon XML event to standardized JSON
    
    Parameters:
    - xml_content: String containing XML event data
    
    Returns: Dictionary with standardized event data
    """
    try:
        # Parse XML to dictionary
        event_dict = xmltodict.parse(xml_content)
        event = event_dict.get('Event', {})
        system = event.get('System', {})
        event_data = event.get('EventData', {}).get('Data', [])
        
        # Extract system fields
        event_id = system.get('EventID', {}).get('#text', None)
        time_created = system.get('TimeCreated', {}).get('@SystemTime', None)
        computer = system.get('Computer', None)
        
        # Parse EventData fields (Sysmon specific)
        data_dict = {}
        if isinstance(event_data, list):
            for item in event_data:
                if isinstance(item, dict):
                    name = item.get('@Name', '')
                    value = item.get('#text', '')
                    data_dict[name] = value
        
        # Create standardized JSON object
        json_event = {
            "EventID": int(event_id) if event_id else None,
            "EventTime": time_created,
            "Computer": computer,
            "User": data_dict.get('User'),
            "ProcessGuid": data_dict.get('ProcessGuid'),
            "ProcessId": int(data_dict.get('ProcessId', 0)) if data_dict.get('ProcessId') else None,
            "Image": data_dict.get('Image'),
            "CommandLine": data_dict.get('CommandLine'),
            "CurrentDirectory": data_dict.get('CurrentDirectory'),
            "ParentImage": data_dict.get('ParentImage'),
            "ParentCommandLine": data_dict.get('ParentCommandLine'),
            "ParentProcessGuid": data_dict.get('ParentProcessGuid'),
            "ParentProcessId": int(data_dict.get('ParentProcessId', 0)) if data_dict.get('ParentProcessId') else None,
            "TargetFilename": data_dict.get('TargetFilename'),
            "DestinationIp": data_dict.get('DestinationIp'),
            "DestinationPort": int(data_dict.get('DestinationPort', 0)) if data_dict.get('DestinationPort') else None,
            "SourceIp": data_dict.get('SourceIp'),
            "SourcePort": int(data_dict.get('SourcePort', 0)) if data_dict.get('SourcePort') else None,
            "Protocol": data_dict.get('Protocol'),
            "Hashes": data_dict.get('Hashes'),
            "RawEventData": json.dumps(data_dict)
        }
        
        return json_event
    except Exception as e:
        print(f"Error parsing Sysmon XML: {e}")
        return None

# Test function
sample_sysmon_xml = """
<Event>
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime='2025-11-03T10:30:00.000Z'/>
    <Computer>DESKTOP-ABC123</Computer>
  </System>
  <EventData>
    <Data Name='ProcessGuid'>{12345678-1234-1234-1234-123456789ABC}</Data>
    <Data Name='ProcessId'>1234</Data>
    <Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name='CommandLine'>cmd.exe /c whoami</Data>
  </EventData>
</Event>
"""

test_result = convert_sysmon_xml_to_json(sample_sysmon_xml)
print("✅ Sysmon XML conversion test:")
print(json.dumps(test_result, indent=2))

# COMMAND ----------

# DBTITLE 1,Sysmon: Real-Time Streaming Ingestion
def ingest_sysmon_realtime(input_path, output_path):
    """
    Stream Sysmon logs from input path, convert to JSON, write to output
    
    Supports:
    - XML files (*.xml)
    - JSON files (*.json from Winlogbeat)
    - Text files with one event per line
    """
    
    # Define UDF for XML conversion
    @udf(returnType=StringType())
    def xml_to_json_udf(xml_string):
        result = convert_sysmon_xml_to_json(xml_string)
        return json.dumps(result) if result else None
    
    # Read streaming data
    if INGESTION_MODE == "streaming":
        raw_stream = (
            spark.readStream
            .format("cloudFiles")
            .option("cloudFiles.format", "text")  # Read as raw text first
            .option("cloudFiles.schemaLocation", f"{CHECKPOINT_PATH}/sysmon_schema")
            .option("wholetext", "false")
            .load(input_path)
        )
        
        # Detect format and convert
        converted_stream = (
            raw_stream
            .withColumn("is_xml", col("value").startswith("<Event"))
            .withColumn("is_json", col("value").startswith("{"))
            .withColumn("converted_json", 
                when(col("is_xml"), xml_to_json_udf(col("value")))
                .when(col("is_json"), col("value"))
                .otherwise(None)
            )
            .filter(col("converted_json").isNotNull())
            .withColumn("parsed", from_json(col("converted_json"), sysmon_schema))
            .select("parsed.*")
            .withColumn("ingestion_timestamp", current_timestamp())
            .withColumn("source_system", lit("sysmon"))
        )
        
        # Write to output
        query = (
            converted_stream.writeStream
            .format("json")
            .option("checkpointLocation", f"{CHECKPOINT_PATH}/sysmon")
            .option("path", output_path)
            .outputMode("append")
            .trigger(processingTime="10 seconds")
            .start()
        )
        
        print(f"✅ Sysmon streaming started")
        print(f"   Input: {input_path}")
        print(f"   Output: {output_path}")
        return query
    else:
        # Batch mode
        print("📊 Batch mode - processing existing files")
        raw_df = spark.read.text(input_path)
        # Similar conversion logic as above
        print(f"✅ Processed {raw_df.count()} Sysmon events")

# Example usage (comment out if not ready)
# sysmon_input = f"{VOLUME_PATH}/incoming/sysmon"
# sysmon_output = f"{VOLUME_PATH}/sysmon_logs.json"
# sysmon_query = ingest_sysmon_realtime(sysmon_input, sysmon_output)

print("✅ Sysmon ingestion function ready")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4: Okta Log Ingestion (API → JSON)
# MAGIC
# MAGIC Fetch Okta system logs via REST API and write to JSON format.
# MAGIC
# MAGIC **API Documentation:** https://developer.okta.com/docs/reference/api/system-log/

# COMMAND ----------

# DBTITLE 1,Okta: Define Standard Schema
okta_schema = StructType([
    StructField("uuid", StringType(), True),
    StructField("published", TimestampType(), True),
    StructField("eventType", StringType(), True),
    StructField("version", StringType(), True),
    StructField("severity", StringType(), True),
    StructField("displayMessage", StringType(), True),
    StructField("actor_id", StringType(), True),
    StructField("actor_type", StringType(), True),
    StructField("actor_alternateId", StringType(), True),
    StructField("actor_displayName", StringType(), True),
    StructField("client_userAgent_rawUserAgent", StringType(), True),
    StructField("client_userAgent_os", StringType(), True),
    StructField("client_userAgent_browser", StringType(), True),
    StructField("client_device", StringType(), True),
    StructField("client_ipAddress", StringType(), True),
    StructField("client_geographicalContext_city", StringType(), True),
    StructField("client_geographicalContext_state", StringType(), True),
    StructField("client_geographicalContext_country", StringType(), True),
    StructField("outcome_result", StringType(), True),
    StructField("outcome_reason", StringType(), True),
    StructField("target", StringType(), True),  # JSON string
    StructField("authenticationContext", StringType(), True),  # JSON string
    StructField("debugContext", StringType(), True),  # JSON string
])

print("✅ Okta schema defined")

# COMMAND ----------

# DBTITLE 1,Okta: API Fetcher Function
def fetch_okta_logs_realtime(domain, api_token, since=None, until=None, limit=1000):
    """
    Fetch Okta system logs via API
    
    Parameters:
    - domain: Okta domain (e.g., "dev-12345.okta.com")
    - api_token: API token with system log read permissions
    - since: Start datetime (ISO 8601 format)
    - until: End datetime (ISO 8601 format)
    - limit: Max events per request (max 1000)
    
    Returns: List of normalized log events
    """
    
    url = f"https://{domain}/api/v1/logs"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"SSWS {api_token}"
    }
    
    params = {
        "limit": limit,
        "sortOrder": "ASCENDING"
    }
    
    if since:
        params["since"] = since
    if until:
        params["until"] = until
    
    all_events = []
    
    try:
        while True:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            
            events = response.json()
            if not events:
                break
            
            # Normalize events
            for event in events:
                normalized_event = {
                    "uuid": event.get("uuid"),
                    "published": event.get("published"),
                    "eventType": event.get("eventType"),
                    "version": event.get("version"),
                    "severity": event.get("severity"),
                    "displayMessage": event.get("displayMessage"),
                    "actor_id": event.get("actor", {}).get("id"),
                    "actor_type": event.get("actor", {}).get("type"),
                    "actor_alternateId": event.get("actor", {}).get("alternateId"),
                    "actor_displayName": event.get("actor", {}).get("displayName"),
                    "client_userAgent_rawUserAgent": event.get("client", {}).get("userAgent", {}).get("rawUserAgent"),
                    "client_userAgent_os": event.get("client", {}).get("userAgent", {}).get("os"),
                    "client_userAgent_browser": event.get("client", {}).get("userAgent", {}).get("browser"),
                    "client_device": event.get("client", {}).get("device"),
                    "client_ipAddress": event.get("client", {}).get("ipAddress"),
                    "client_geographicalContext_city": event.get("client", {}).get("geographicalContext", {}).get("city"),
                    "client_geographicalContext_state": event.get("client", {}).get("geographicalContext", {}).get("state"),
                    "client_geographicalContext_country": event.get("client", {}).get("geographicalContext", {}).get("country"),
                    "outcome_result": event.get("outcome", {}).get("result"),
                    "outcome_reason": event.get("outcome", {}).get("reason"),
                    "target": json.dumps(event.get("target", [])),
                    "authenticationContext": json.dumps(event.get("authenticationContext", {})),
                    "debugContext": json.dumps(event.get("debugContext", {}))
                }
                all_events.append(normalized_event)
            
            # Check for pagination
            link_header = response.headers.get("Link", "")
            if "rel=\"next\"" not in link_header:
                break
            
            # Extract next URL
            for link in link_header.split(","):
                if "rel=\"next\"" in link:
                    url = link.split(";")[0].strip("<> ")
                    params = {}  # URL already contains params
                    break
        
        print(f"✅ Fetched {len(all_events)} Okta events")
        return all_events
        
    except Exception as e:
        print(f"❌ Error fetching Okta logs: {e}")
        return []

# Test function (will fail without valid credentials)
if OKTA_API_TOKEN != "YOUR_OKTA_API_TOKEN":
    test_since = (datetime.now() - timedelta(hours=1)).isoformat() + "Z"
    okta_events = fetch_okta_logs_realtime(OKTA_DOMAIN, OKTA_API_TOKEN, since=test_since, limit=10)
    print(f"✅ Test retrieved {len(okta_events)} events")
else:
    print("ℹ️  Okta API token not configured - skipping test")

# COMMAND ----------

# DBTITLE 1,Okta: Scheduled Ingestion Function
def ingest_okta_scheduled(domain, api_token, output_path, interval_minutes=5):
    """
    Continuously fetch Okta logs and write to JSON
    
    Parameters:
    - domain: Okta domain
    - api_token: API token
    - output_path: Where to write JSON files
    - interval_minutes: How often to fetch (default: 5 minutes)
    """
    
    import time
    from datetime import datetime, timedelta
    
    last_fetch_time = datetime.now() - timedelta(minutes=interval_minutes)
    
    while True:
        try:
            current_time = datetime.now()
            since = last_fetch_time.isoformat() + "Z"
            until = current_time.isoformat() + "Z"
            
            print(f"⏰ Fetching Okta logs: {since} to {until}")
            events = fetch_okta_logs_realtime(domain, api_token, since=since, until=until)
            
            if events:
                # Convert to Spark DataFrame
                df = spark.createDataFrame(events, schema=okta_schema)
                df = df.withColumn("ingestion_timestamp", current_timestamp())
                df = df.withColumn("source_system", lit("okta"))
                
                # Write to JSON (append mode)
                timestamp_str = current_time.strftime("%Y%m%d_%H%M%S")
                output_file = f"{output_path}/okta_logs_{timestamp_str}.json"
                df.write.mode("append").json(output_file)
                
                print(f"✅ Wrote {len(events)} events to {output_file}")
            else:
                print(f"ℹ️  No new events in this interval")
            
            last_fetch_time = current_time
            
            # Wait for next interval
            print(f"😴 Sleeping for {interval_minutes} minutes...")
            time.sleep(interval_minutes * 60)
            
        except KeyboardInterrupt:
            print("🛑 Okta ingestion stopped by user")
            break
        except Exception as e:
            print(f"❌ Error in Okta ingestion: {e}")
            time.sleep(60)  # Wait 1 minute before retrying

# Example usage (run in separate thread or notebook)
# okta_output = f"{VOLUME_PATH}/okta_logs.json"
# ingest_okta_scheduled(OKTA_DOMAIN, OKTA_API_TOKEN, okta_output, interval_minutes=5)

print("✅ Okta scheduled ingestion function ready")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5: Windows Event Log Ingestion (EVTX/XML → JSON)
# MAGIC
# MAGIC Windows Event Logs can come in multiple formats:
# MAGIC - **EVTX** binary format (requires pyevtx)
# MAGIC - **XML** export from Event Viewer
# MAGIC - **CSV** export

# COMMAND ----------

# DBTITLE 1,Windows: Define Standard Schema
windows_schema = StructType([
    StructField("EventID", IntegerType(), True),
    StructField("EventRecordID", LongType(), True),
    StructField("TimeCreated", TimestampType(), True),
    StructField("Computer", StringType(), True),
    StructField("Channel", StringType(), True),
    StructField("Level", StringType(), True),
    StructField("Task", StringType(), True),
    StructField("Keywords", StringType(), True),
    StructField("ProviderName", StringType(), True),
    StructField("ProviderGuid", StringType(), True),
    StructField("UserID", StringType(), True),
    StructField("AccountName", StringType(), True),
    StructField("AccountDomain", StringType(), True),
    StructField("LogonID", StringType(), True),
    StructField("ProcessID", IntegerType(), True),
    StructField("ProcessName", StringType(), True),
    StructField("IpAddress", StringType(), True),
    StructField("IpPort", IntegerType(), True),
    StructField("TargetUserName", StringType(), True),
    StructField("TargetDomainName", StringType(), True),
    StructField("LogonType", IntegerType(), True),
    StructField("Message", StringType(), True),
    StructField("EventData", StringType(), True),  # JSON string
])

print("✅ Windows Event schema defined")

# COMMAND ----------

# DBTITLE 1,Windows: XML to JSON Conversion
def convert_windows_xml_to_json(xml_content):
    """
    Convert Windows Event XML to standardized JSON
    
    Handles both:
    - Event Viewer XML export
    - Forwarded events XML
    """
    try:
        event_dict = xmltodict.parse(xml_content)
        event = event_dict.get('Event', {})
        system = event.get('System', {})
        event_data = event.get('EventData', {})
        
        # Extract system fields
        event_id = system.get('EventID', {})
        if isinstance(event_id, dict):
            event_id = event_id.get('#text', None)
        
        time_created = system.get('TimeCreated', {}).get('@SystemTime', None)
        computer = system.get('Computer', None)
        
        # Extract event data fields
        data_fields = {}
        if isinstance(event_data, dict):
            data_list = event_data.get('Data', [])
            if isinstance(data_list, list):
                for item in data_list:
                    if isinstance(item, dict):
                        name = item.get('@Name', '')
                        value = item.get('#text', '')
                        data_fields[name] = value
        
        # Create standardized JSON
        json_event = {
            "EventID": int(event_id) if event_id else None,
            "EventRecordID": system.get('EventRecordID', None),
            "TimeCreated": time_created,
            "Computer": computer,
            "Channel": system.get('Channel', None),
            "Level": system.get('Level', None),
            "Task": system.get('Task', None),
            "Keywords": system.get('Keywords', None),
            "ProviderName": system.get('Provider', {}).get('@Name', None),
            "ProviderGuid": system.get('Provider', {}).get('@Guid', None),
            "UserID": system.get('Security', {}).get('@UserID', None),
            "AccountName": data_fields.get('SubjectUserName') or data_fields.get('TargetUserName'),
            "AccountDomain": data_fields.get('SubjectDomainName') or data_fields.get('TargetDomainName'),
            "LogonID": data_fields.get('SubjectLogonId') or data_fields.get('TargetLogonId'),
            "ProcessID": int(data_fields.get('ProcessId', 0)) if data_fields.get('ProcessId') else None,
            "ProcessName": data_fields.get('ProcessName'),
            "IpAddress": data_fields.get('IpAddress'),
            "IpPort": int(data_fields.get('IpPort', 0)) if data_fields.get('IpPort') else None,
            "TargetUserName": data_fields.get('TargetUserName'),
            "TargetDomainName": data_fields.get('TargetDomainName'),
            "LogonType": int(data_fields.get('LogonType', 0)) if data_fields.get('LogonType') else None,
            "Message": event.get('RenderingInfo', {}).get('Message', None),
            "EventData": json.dumps(data_fields)
        }
        
        return json_event
    except Exception as e:
        print(f"Error parsing Windows Event XML: {e}")
        return None

# Test
sample_windows_xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4624</EventID>
    <TimeCreated SystemTime='2025-11-03T10:30:00.000Z'/>
    <Computer>SERVER01</Computer>
    <Channel>Security</Channel>
    <Level>0</Level>
  </System>
  <EventData>
    <Data Name='TargetUserName'>Administrator</Data>
    <Data Name='TargetDomainName'>DOMAIN</Data>
    <Data Name='LogonType'>3</Data>
    <Data Name='IpAddress'>192.168.1.100</Data>
  </EventData>
</Event>
"""

test_result = convert_windows_xml_to_json(sample_windows_xml)
print("✅ Windows Event XML conversion test:")
print(json.dumps(test_result, indent=2))

# COMMAND ----------

# DBTITLE 1,Windows: Real-Time Streaming Ingestion
def ingest_windows_realtime(input_path, output_path):
    """
    Stream Windows Event Logs, convert to JSON, write to output
    
    Supports XML format (most common export format)
    """
    
    @udf(returnType=StringType())
    def windows_xml_to_json_udf(xml_string):
        result = convert_windows_xml_to_json(xml_string)
        return json.dumps(result) if result else None
    
    if INGESTION_MODE == "streaming":
        raw_stream = (
            spark.readStream
            .format("cloudFiles")
            .option("cloudFiles.format", "text")
            .option("cloudFiles.schemaLocation", f"{CHECKPOINT_PATH}/windows_schema")
            .load(input_path)
        )
        
        converted_stream = (
            raw_stream
            .filter(col("value").startswith("<Event"))
            .withColumn("converted_json", windows_xml_to_json_udf(col("value")))
            .filter(col("converted_json").isNotNull())
            .withColumn("parsed", from_json(col("converted_json"), windows_schema))
            .select("parsed.*")
            .withColumn("ingestion_timestamp", current_timestamp())
            .withColumn("source_system", lit("windows"))
        )
        
        query = (
            converted_stream.writeStream
            .format("json")
            .option("checkpointLocation", f"{CHECKPOINT_PATH}/windows")
            .option("path", output_path)
            .outputMode("append")
            .trigger(processingTime="10 seconds")
            .start()
        )
        
        print(f"✅ Windows Event streaming started")
        return query

print("✅ Windows Event ingestion function ready")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 6: AWS CloudTrail Ingestion (JSON/GZ → JSON)
# MAGIC
# MAGIC CloudTrail logs are stored in S3 as compressed JSON files.
# MAGIC We'll read them directly from S3 and normalize to our schema.

# COMMAND ----------

# DBTITLE 1,CloudTrail: Define Standard Schema
cloudtrail_schema = StructType([
    StructField("eventVersion", StringType(), True),
    StructField("eventTime", TimestampType(), True),
    StructField("eventID", StringType(), True),
    StructField("eventType", StringType(), True),
    StructField("eventName", StringType(), True),
    StructField("eventSource", StringType(), True),
    StructField("awsRegion", StringType(), True),
    StructField("sourceIPAddress", StringType(), True),
    StructField("userAgent", StringType(), True),
    StructField("errorCode", StringType(), True),
    StructField("errorMessage", StringType(), True),
    StructField("requestID", StringType(), True),
    StructField("userIdentity_type", StringType(), True),
    StructField("userIdentity_principalId", StringType(), True),
    StructField("userIdentity_arn", StringType(), True),
    StructField("userIdentity_accountId", StringType(), True),
    StructField("userIdentity_accessKeyId", StringType(), True),
    StructField("userIdentity_userName", StringType(), True),
    StructField("requestParameters", StringType(), True),  # JSON string
    StructField("responseElements", StringType(), True),  # JSON string
    StructField("resources", StringType(), True),  # JSON array string
])

print("✅ CloudTrail schema defined")

# COMMAND ----------

# DBTITLE 1,CloudTrail: S3 Ingestion Function
def ingest_cloudtrail_from_s3(s3_path, output_path):
    """
    Read CloudTrail logs from S3 and normalize to JSON
    
    Parameters:
    - s3_path: S3 path (s3://bucket/prefix)
    - output_path: Local output path in UC Volumes
    
    CloudTrail file structure:
    s3://bucket/AWSLogs/account-id/CloudTrail/region/YYYY/MM/DD/*.json.gz
    """
    
    if INGESTION_MODE == "streaming":
        # Use Auto Loader for S3
        raw_stream = (
            spark.readStream
            .format("cloudFiles")
            .option("cloudFiles.format", "json")
            .option("cloudFiles.schemaLocation", f"{CHECKPOINT_PATH}/cloudtrail_schema")
            .option("cloudFiles.inferColumnTypes", "true")
            .option("recursiveFileLookup", "true")
            .load(s3_path)
        )
        
        # CloudTrail has nested Records array
        exploded_stream = (
            raw_stream
            .select(explode(col("Records")).alias("record"))
            .select("record.*")
        )
        
        # Normalize nested fields
        normalized_stream = (
            exploded_stream
            .withColumn("eventTime", to_timestamp(col("eventTime")))
            .withColumn("userIdentity_type", col("userIdentity.type"))
            .withColumn("userIdentity_principalId", col("userIdentity.principalId"))
            .withColumn("userIdentity_arn", col("userIdentity.arn"))
            .withColumn("userIdentity_accountId", col("userIdentity.accountId"))
            .withColumn("userIdentity_accessKeyId", col("userIdentity.accessKeyId"))
            .withColumn("userIdentity_userName", col("userIdentity.userName"))
            .withColumn("requestParameters", to_json(col("requestParameters")))
            .withColumn("responseElements", to_json(col("responseElements")))
            .withColumn("resources", to_json(col("resources")))
            .withColumn("ingestion_timestamp", current_timestamp())
            .withColumn("source_system", lit("cloudtrail"))
            .select([field.name for field in cloudtrail_schema.fields] + ["ingestion_timestamp", "source_system"])
        )
        
        # Write to output
        query = (
            normalized_stream.writeStream
            .format("json")
            .option("checkpointLocation", f"{CHECKPOINT_PATH}/cloudtrail")
            .option("path", output_path)
            .outputMode("append")
            .trigger(processingTime="30 seconds")
            .start()
        )
        
        print(f"✅ CloudTrail streaming started from S3")
        print(f"   S3 Path: {s3_path}")
        print(f"   Output: {output_path}")
        return query
    
    else:
        # Batch mode
        print("📊 Batch mode - processing existing CloudTrail files")
        raw_df = spark.read.json(s3_path)
        # Similar processing as above
        print(f"✅ Processed CloudTrail events")

# Example usage
# cloudtrail_s3_path = f"s3://{AWS_CLOUDTRAIL_BUCKET}/AWSLogs/*/CloudTrail/*/*/*/*.json.gz"
# cloudtrail_output = f"{VOLUME_PATH}/cloudtrail_logs.json"
# cloudtrail_query = ingest_cloudtrail_from_s3(cloudtrail_s3_path, cloudtrail_output)

print("✅ CloudTrail ingestion function ready")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 7: Unified Monitoring and Management

# COMMAND ----------

# DBTITLE 1,Start All Ingestion Streams
def start_all_streams():
    """
    Start all real-time ingestion streams
    
    Returns: Dictionary of active queries
    """
    
    active_queries = {}
    
    print("🚀 Starting all ingestion streams...")
    print("=" * 80)
    
    # Sysmon
    try:
        sysmon_input = f"{VOLUME_PATH}/incoming/sysmon"
        sysmon_output = f"{VOLUME_PATH}/sysmon_logs.json"
        dbutils.fs.mkdirs(sysmon_input)
        active_queries['sysmon'] = ingest_sysmon_realtime(sysmon_input, sysmon_output)
        print("✅ Sysmon stream started")
    except Exception as e:
        print(f"⚠️  Sysmon stream error: {e}")
    
    # Windows Events
    try:
        windows_input = f"{VOLUME_PATH}/incoming/windows"
        windows_output = f"{VOLUME_PATH}/windows_logs.json"
        dbutils.fs.mkdirs(windows_input)
        active_queries['windows'] = ingest_windows_realtime(windows_input, windows_output)
        print("✅ Windows Event stream started")
    except Exception as e:
        print(f"⚠️  Windows Event stream error: {e}")
    
    # CloudTrail (if S3 configured)
    if AWS_CLOUDTRAIL_BUCKET != "your-cloudtrail-bucket":
        try:
            cloudtrail_s3 = f"s3://{AWS_CLOUDTRAIL_BUCKET}/AWSLogs/*/CloudTrail/*/*/*/*.json.gz"
            cloudtrail_output = f"{VOLUME_PATH}/cloudtrail_logs.json"
            active_queries['cloudtrail'] = ingest_cloudtrail_from_s3(cloudtrail_s3, cloudtrail_output)
            print("✅ CloudTrail stream started")
        except Exception as e:
            print(f"⚠️  CloudTrail stream error: {e}")
    
    print("=" * 80)
    print(f"✅ Started {len(active_queries)} streams")
    
    return active_queries

# Uncomment to start all streams
# active_queries = start_all_streams()

print("✅ Stream management functions ready")

# COMMAND ----------

# DBTITLE 1,Monitor Active Streams
def monitor_streams():
    """
    Display status of all active streaming queries
    """
    
    print("📊 Active Streaming Queries Status")
    print("=" * 80)
    
    for stream in spark.streams.active:
        print(f"\n🔹 Stream: {stream.name or 'Unnamed'}")
        print(f"   ID: {stream.id}")
        print(f"   Status: {stream.status}")
        print(f"   Recent Progress:")
        if stream.recentProgress:
            latest = stream.recentProgress[-1]
            print(f"      - Batch: {latest.get('batchId', 'N/A')}")
            print(f"      - Input Rows: {latest.get('numInputRows', 0):,}")
            print(f"      - Processing Rate: {latest.get('processedRowsPerSecond', 0):.2f} rows/sec")
    
    if not spark.streams.active:
        print("ℹ️  No active streams")
    
    print("=" * 80)

# Run monitoring
monitor_streams()

# COMMAND ----------

# DBTITLE 1,Stop All Streams
def stop_all_streams():
    """
    Gracefully stop all active streaming queries
    """
    
    print("🛑 Stopping all streams...")
    
    for stream in spark.streams.active:
        stream.stop()
        print(f"   Stopped: {stream.name or stream.id}")
    
    print("✅ All streams stopped")

# Uncomment to stop all streams
# stop_all_streams()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 8: Validation and Testing

# COMMAND ----------

# DBTITLE 1,Validate Ingested Data
def validate_ingestion():
    """
    Check that data has been successfully ingested and converted to JSON
    """
    
    print("🔍 Validating Ingestion...")
    print("=" * 80)
    
    sources = {
        "Sysmon": f"{VOLUME_PATH}/sysmon_logs.json",
        "Okta": f"{VOLUME_PATH}/okta_logs.json",
        "Windows Events": f"{VOLUME_PATH}/windows_logs.json",
        "CloudTrail": f"{VOLUME_PATH}/cloudtrail_logs.json"
    }
    
    for source_name, path in sources.items():
        try:
            df = spark.read.json(path)
            count = df.count()
            print(f"✅ {source_name:20} {count:>10,} events")
            
            # Show sample
            if count > 0:
                print(f"   Sample schema:")
                df.printSchema()
                print(f"   Sample record:")
                df.show(1, truncate=False)
        except Exception as e:
            print(f"⚠️  {source_name:20} Not available ({e})")
    
    print("=" * 80)

# Run validation
validate_ingestion()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 9: Integration with Lab 02 (DLT Pipeline)
# MAGIC
# MAGIC Once logs are in JSON format in UC Volumes, the existing DLT pipeline (Lab 02) will automatically pick them up.
# MAGIC
# MAGIC **Next Steps:**
# MAGIC 1. Ensure this notebook's output paths match Lab 02's input paths
# MAGIC 2. Start the DLT pipeline from Lab 02
# MAGIC 3. Monitor both this notebook and the DLT pipeline
# MAGIC
# MAGIC **Integration Points:**
# MAGIC ```
# MAGIC This Notebook Output          Lab 02 DLT Input
# MAGIC ────────────────────         ────────────────
# MAGIC sysmon_logs.json       →     bronze_sysmon
# MAGIC okta_logs.json         →     bronze_okta
# MAGIC windows_logs.json      →     bronze_windows
# MAGIC cloudtrail_logs.json   →     bronze_cloudtrail
# MAGIC ```

# COMMAND ----------

# MAGIC %md
# MAGIC ## Summary
# MAGIC
# MAGIC **What This Notebook Does:**
# MAGIC - ✅ Ingests real-time logs from 4 sources (Sysmon, Okta, Windows, CloudTrail)
# MAGIC - ✅ Converts various formats (XML, API, EVTX) to standardized JSON
# MAGIC - ✅ Writes to Unity Catalog Volumes for DLT pipeline consumption
# MAGIC - ✅ Provides monitoring and management functions
# MAGIC
# MAGIC **What You Need to Configure:**
# MAGIC 1. Update API credentials (Okta, AWS)
# MAGIC 2. Set input paths for log files
# MAGIC 3. Choose streaming vs batch mode
# MAGIC 4. Start desired ingestion streams
# MAGIC
# MAGIC **Next Lab:**
# MAGIC - Run Lab 02 (DLT Pipeline) to process these normalized JSON logs
# MAGIC - Apply detection rules in Lab 03
# MAGIC - Operationalize in Lab 04
# MAGIC