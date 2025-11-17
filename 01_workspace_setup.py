# Databricks notebook source
# MAGIC %md
# MAGIC # Lab 01: Workspace Setup and Sample Data Generation
# MAGIC
# MAGIC ## Overview
# MAGIC In this lab, you will:
# MAGIC 1. Create a Unity Catalog structure for security data
# MAGIC 2. Generate realistic sample security logs
# MAGIC 3. Upload data to Unity Catalog Volumes
# MAGIC 4. Verify data accessibility
# MAGIC
# MAGIC **Time:** ~10 minutes
# MAGIC
# MAGIC ## Prerequisites
# MAGIC - Unity Catalog enabled workspace
# MAGIC - Permissions to CREATE CATALOG (or USE existing catalog)
# MAGIC - Python packages: `faker`, `pandas`, `numpy`

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1: Install Required Libraries

# COMMAND ----------

# DBTITLE 1,Install Dependencies
# Install faker for realistic data generation
%pip install faker

# DBTITLE 1,Install XML Processing Library
%pip install xmltodict lxml --quiet

# Restart Python to load new packages
dbutils.library.restartPython()



# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Configuration and Setup

# COMMAND ----------

# DBTITLE 1,Configuration Variables
# Import required libraries
import json
import random
import pandas as pd
from datetime import datetime, timedelta
from faker import Faker
import uuid

# Configuration - MODIFY THESE FOR YOUR ENVIRONMENT
CATALOG_NAME = "security_detection_engineering_lab"
SCHEMA_NAME = "security_logs"
VOLUME_NAME = "raw_logs"

# Number of sample events to generate
NUM_SYSMON_EVENTS = 10000
NUM_OKTA_EVENTS = 5000
NUM_WINDOWS_EVENTS = 8000
NUM_CLOUDTRAIL_EVENTS = 6000

# Initialize Faker for realistic data
fake = Faker()
Faker.seed(42)  # For reproducible results
random.seed(42)

print(f"Configuration:")
print(f"  Catalog: {CATALOG_NAME}")
print(f"  Schema: {SCHEMA_NAME}")
print(f"  Volume: {VOLUME_NAME}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3: Create Unity Catalog Structure

# COMMAND ----------

# DBTITLE 1,Create Catalog, Schema, and Volume
# Create catalog (skip if using existing catalog)
try:
    spark.sql(f"CREATE CATALOG IF NOT EXISTS {CATALOG_NAME}")
    print(f"✅ Catalog '{CATALOG_NAME}' created/verified")
except Exception as e:
    print(f"⚠️  Could not create catalog (may need permissions or it exists): {e}")
    print(f"   → Will use existing catalog if available")

# Set default catalog
spark.sql(f"USE CATALOG {CATALOG_NAME}")

# Create schema
spark.sql(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA_NAME}")
print(f"✅ Schema '{SCHEMA_NAME}' created")

# Create volume for raw data
spark.sql(f"""
    CREATE VOLUME IF NOT EXISTS {CATALOG_NAME}.{SCHEMA_NAME}.{VOLUME_NAME}
""")
print(f"✅ Volume '{VOLUME_NAME}' created")

# Set as default schema
spark.sql(f"USE SCHEMA {SCHEMA_NAME}")

# Get volume path
volume_path = f"/Volumes/{CATALOG_NAME}/{SCHEMA_NAME}/{VOLUME_NAME}"
print(f"\n📁 Volume path: {volume_path}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4: Generate Sample Sysmon Logs
# MAGIC
# MAGIC Sysmon (System Monitor) logs track detailed system activity on Windows.
# MAGIC We'll generate events including:
# MAGIC - Process creation (EventID 1)
# MAGIC - Network connections (EventID 3)
# MAGIC - File creation (EventID 11)
# MAGIC - Including malicious patterns for detection

# COMMAND ----------

# DBTITLE 1,Generate Sysmon Events
def generate_sysmon_events(num_events):
    """Generate realistic Sysmon log events with some malicious patterns"""
    
    events = []
    start_time = datetime.now() - timedelta(days=7)
    
    # Malicious process names to inject
    malicious_processes = [
        "mimikatz.exe",
        "powershell.exe",  # Can be benign or malicious based on command line
        "psexec.exe",
        "procdump.exe",
        "nc.exe",
        "ncat.exe"
    ]
    
    # Normal processes
    normal_processes = [
        "chrome.exe",
        "excel.exe",
        "outlook.exe",
        "notepad.exe",
        "explorer.exe",
        "svchost.exe",
        "teams.exe",
        "slack.exe"
    ]
    
    # Suspicious command lines
    suspicious_cmdlines = [
        "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA",  # Base64 encoded
        "powershell.exe -w hidden -nop -c IEX",
        "cmd.exe /c whoami /all",
        "net user administrator P@ssw0rd /add",
        "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "mimikatz.exe sekurlsa::logonpasswords"
    ]
    
    for i in range(num_events):
        # 5% chance of malicious event
        is_malicious = random.random() < 0.05
        
        timestamp = start_time + timedelta(
            seconds=random.randint(0, 7*24*60*60)
        )
        
        if is_malicious:
            process_name = random.choice(malicious_processes)
            if process_name == "powershell.exe":
                command_line = random.choice(suspicious_cmdlines)
            else:
                command_line = f"C:\\Temp\\{process_name}"
        else:
            process_name = random.choice(normal_processes)
            command_line = f"C:\\Program Files\\{process_name}"
        
        event = {
            "EventID": random.choice([1, 3, 11]),  # Process, Network, File
            "EventTime": timestamp.isoformat(),
            "Computer": f"WORKSTATION-{random.randint(1, 50):03d}",
            "ProcessName": process_name,
            "ProcessId": random.randint(1000, 9999),
            "CommandLine": command_line,
            "User": fake.user_name(),
            "ParentProcessName": random.choice(["explorer.exe", "cmd.exe", "services.exe"]),
            "ParentProcessId": random.randint(100, 999),
            "SHA256": fake.sha256(),
            "DestinationIP": fake.ipv4() if random.random() < 0.3 else None,
            "DestinationPort": random.choice([80, 443, 445, 3389, 22]) if random.random() < 0.3 else None,
            "is_malicious": is_malicious  # For validation (remove in production)
        }
        
        events.append(event)
    
    return events

print("🔧 Generating Sysmon events...")
sysmon_events = generate_sysmon_events(NUM_SYSMON_EVENTS)

# Convert to DataFrame and save
sysmon_df = pd.DataFrame(sysmon_events)
sysmon_file = f"{volume_path}/sysmon_logs.json"

# Write to volume using Spark
spark.createDataFrame(sysmon_df).write.mode("overwrite").json(sysmon_file)

malicious_count = sum(1 for e in sysmon_events if e['is_malicious'])
print(f"✅ Generated {NUM_SYSMON_EVENTS} Sysmon events")
print(f"   - {malicious_count} malicious events ({malicious_count/NUM_SYSMON_EVENTS*100:.1f}%)")
print(f"   - Saved to: {sysmon_file}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 5: Generate Sample Okta Logs
# MAGIC
# MAGIC Okta authentication logs track user login activities.
# MAGIC We'll include patterns for:
# MAGIC - Failed login attempts (brute force)
# MAGIC - MFA bypass attempts
# MAGIC - Impossible travel scenarios

# COMMAND ----------

# DBTITLE 1,Generate Okta Events
def generate_okta_events(num_events):
    """Generate Okta authentication logs with suspicious patterns"""
    
    events = []
    start_time = datetime.now() - timedelta(days=7)
    
    # Generate user pool
    users = [fake.email() for _ in range(100)]
    
    # Some users will have suspicious activity
    suspicious_users = random.sample(users, 10)
    
    for i in range(num_events):
        timestamp = start_time + timedelta(
            seconds=random.randint(0, 7*24*60*60)
        )
        
        user_email = random.choice(users)
        is_suspicious = user_email in suspicious_users and random.random() < 0.3
        
        # Event types
        if is_suspicious:
            event_type = random.choice([
                "user.authentication.auth_via_mfa",
                "user.authentication.sso",
                "user.session.access_admin_app",
                "policy.lifecycle.update"
            ])
            outcome = random.choice(["FAILURE", "FAILURE", "SUCCESS"])
            
            # Impossible travel: different countries in short time
            if random.random() < 0.5:
                location_city = random.choice(["Moscow", "Beijing", "Tehran"])
                location_country = random.choice(["Russia", "China", "Iran"])
            else:
                location_city = fake.city()
                location_country = fake.country()
        else:
            event_type = "user.authentication.sso"
            outcome = "SUCCESS"
            location_city = fake.city()
            location_country = fake.country()
        
        event = {
            "uuid": str(uuid.uuid4()),
            "published": timestamp.isoformat(),
            "eventType": event_type,
            "displayMessage": f"User {outcome.lower()} to authenticate",
            "severity": "INFO" if outcome == "SUCCESS" else "WARN",
            "actor": {
                "id": str(uuid.uuid4()),
                "type": "User",
                "alternateId": user_email,
                "displayName": fake.name()
            },
            "client": {
                "userAgent": fake.user_agent(),
                "ipAddress": fake.ipv4(),
                "geographicalContext": {
                    "city": location_city,
                    "state": fake.state() if location_country == "United States" else None,
                    "country": location_country,
                    "postalCode": fake.postcode()
                }
            },
            "outcome": {
                "result": outcome,
                "reason": "INVALID_CREDENTIALS" if outcome == "FAILURE" else None
            },
            "target": [{
                "id": str(uuid.uuid4()),
                "type": "AppInstance",
                "alternateId": fake.domain_name(),
                "displayName": random.choice(["Salesforce", "AWS", "GitHub", "Jira"])
            }],
            "is_suspicious": is_suspicious
        }
        
        events.append(event)
    
    return events

print("🔧 Generating Okta events...")
okta_events = generate_okta_events(NUM_OKTA_EVENTS)

# Convert to DataFrame and save using Spark
okta_df = pd.DataFrame(okta_events)
okta_file = f"{volume_path}/okta_logs.json"

# Write to volume using Spark
spark.createDataFrame(okta_df).write.mode("overwrite").json(okta_file)

suspicious_count = sum(1 for e in okta_events if e['is_suspicious'])
print(f"✅ Generated {NUM_OKTA_EVENTS} Okta events")
print(f"   - {suspicious_count} suspicious events ({suspicious_count/NUM_OKTA_EVENTS*100:.1f}%)")
print(f"   - Saved to: {okta_file}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 6: Generate Windows Event Logs
# MAGIC
# MAGIC Windows Security Event logs (Event IDs 4624, 4625, 4672, etc.)
# MAGIC Key events for detection:
# MAGIC - 4624: Successful logon
# MAGIC - 4625: Failed logon
# MAGIC - 4672: Special privileges assigned (admin)
# MAGIC - 4688: Process creation

# COMMAND ----------

# DBTITLE 1,Generate Windows Event Logs
def generate_windows_events(num_events):
    """Generate Windows Security Event logs"""
    
    events = []
    start_time = datetime.now() - timedelta(days=7)
    
    # Logon types
    logon_types = {
        2: "Interactive (console)",
        3: "Network (SMB)",
        4: "Batch",
        5: "Service",
        7: "Unlock",
        10: "RemoteInteractive (RDP)",
        11: "CachedInteractive"
    }
    
    computers = [f"WORKSTATION-{i:03d}" for i in range(1, 51)]
    users = [fake.user_name() for _ in range(50)]
    
    for i in range(num_events):
        timestamp = start_time + timedelta(
            seconds=random.randint(0, 7*24*60*60)
        )
        
        # 10% chance of failed logon
        is_failed = random.random() < 0.10
        
        if is_failed:
            event_id = 4625  # Failed logon
            logon_type = random.choice([3, 10])  # Network or RDP
            status = "0xC000006D"  # Bad username or password
            
            # Cluster failed attempts for brute force detection
            if random.random() < 0.3:
                user = random.choice(users[:5])  # Same users being targeted
                timestamp = timestamp.replace(minute=random.randint(0, 10))  # Same time window
        else:
            event_id = random.choice([4624, 4672, 4688])  # Success events
            logon_type = random.choice(list(logon_types.keys()))
            status = "0x0"
            user = random.choice(users)
        
        event = {
            "EventID": event_id,
            "TimeCreated": timestamp.isoformat(),
            "Computer": random.choice(computers),
            "EventRecordID": random.randint(100000, 999999),
            "Channel": "Security",
            "LogonType": logon_type,
            "LogonTypeName": logon_types.get(logon_type, "Unknown"),
            "TargetUserName": user,
            "TargetDomainName": "CORP",
            "WorkstationName": random.choice(computers),
            "SourceNetworkAddress": fake.ipv4(),
            "SourcePort": random.randint(49152, 65535),
            "Status": status,
            "SubStatus": status,
            "ProcessName": random.choice([
                "C:\\Windows\\System32\\svchost.exe",
                "C:\\Windows\\System32\\lsass.exe",
                "C:\\Windows\\explorer.exe",
                "-"
            ]) if event_id == 4688 else None,
            "is_failed": is_failed
        }
        
        events.append(event)
    
    return events

print("🔧 Generating Windows Event logs...")
windows_events = generate_windows_events(NUM_WINDOWS_EVENTS)

# Save to volume
windows_file = f"{volume_path}/windows_logs.json"
windows_df = pd.DataFrame(windows_events)
spark.createDataFrame(windows_df).write.mode("overwrite").json(windows_file)

failed_count = sum(1 for e in windows_events if e['is_failed'])
print(f"✅ Generated {NUM_WINDOWS_EVENTS} Windows Event logs")
print(f"   - {failed_count} failed logon events ({failed_count/NUM_WINDOWS_EVENTS*100:.1f}%)")
print(f"   - Saved to: {windows_file}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 7: Generate AWS CloudTrail Logs
# MAGIC
# MAGIC CloudTrail logs track AWS API calls.
# MAGIC Suspicious patterns:
# MAGIC - IAM policy changes
# MAGIC - S3 bucket access
# MAGIC - EC2 instance creation
# MAGIC - Unusual API calls from unknown IPs

# COMMAND ----------

# DBTITLE 1,Generate CloudTrail Events
def generate_cloudtrail_events(num_events):
    """Generate AWS CloudTrail logs"""
    
    events = []
    start_time = datetime.now() - timedelta(days=7)
    
    # AWS event names
    normal_events = [
        "DescribeInstances",
        "GetObject",
        "ListBuckets",
        "GetCallerIdentity",
        "AssumeRole"
    ]
    
    suspicious_events = [
        "CreateAccessKey",
        "AttachUserPolicy",
        "PutBucketPolicy",
        "DeleteTrail",
        "StopLogging",
        "CreateUser",
        "CreateLoginProfile"
    ]
    
    aws_services = ["iam.amazonaws.com", "s3.amazonaws.com", "ec2.amazonaws.com", "sts.amazonaws.com"]
    
    for i in range(num_events):
        timestamp = start_time + timedelta(
            seconds=random.randint(0, 7*24*60*60)
        )
        
        # 8% suspicious events
        is_suspicious = random.random() < 0.08
        
        if is_suspicious:
            event_name = random.choice(suspicious_events)
            error_code = random.choice([None, "AccessDenied", "UnauthorizedOperation"])
        else:
            event_name = random.choice(normal_events)
            error_code = None
        
        event = {
            "eventVersion": "1.08",
            "eventTime": timestamp.isoformat() + "Z",
            "eventID": str(uuid.uuid4()),
            "eventName": event_name,
            "eventType": "AwsApiCall",
            "eventSource": random.choice(aws_services),
            "awsRegion": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
            "sourceIPAddress": fake.ipv4(),
            "userAgent": random.choice([
                "aws-cli/2.13.0",
                "Boto3/1.28.0",
                "console.aws.amazon.com",
                fake.user_agent()
            ]),
            "errorCode": error_code,
            "errorMessage": "Access denied" if error_code else None,
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDA{fake.uuid4()[:16].upper()}",
                "arn": f"arn:aws:iam::123456789012:user/{fake.user_name()}",
                "accountId": "123456789012",
                "userName": fake.user_name()
            },
            "requestParameters": {
                "bucketName": f"{fake.word()}-data-{random.randint(1, 999)}" if "Bucket" in event_name else None,
                "key": f"data/{fake.file_name()}" if event_name == "GetObject" else None,
                "userName": fake.user_name() if "User" in event_name else None
            },
            "responseElements": None if error_code else {"status": "success"},
            "is_suspicious": is_suspicious
        }
        
        events.append(event)
    
    return events

print("🔧 Generating CloudTrail events...")
cloudtrail_events = generate_cloudtrail_events(NUM_CLOUDTRAIL_EVENTS)

# Convert to DataFrame and save using Spark
cloudtrail_df = pd.DataFrame(cloudtrail_events)
cloudtrail_file = f"{volume_path}/cloudtrail_logs.json"

# Write to volume using Spark
spark.createDataFrame(cloudtrail_df).write.mode("overwrite").json(cloudtrail_file)

suspicious_count = sum(1 for e in cloudtrail_events if e['is_suspicious'])
print(f"✅ Generated {NUM_CLOUDTRAIL_EVENTS} CloudTrail events")
print(f"   - {suspicious_count} suspicious events ({suspicious_count/NUM_CLOUDTRAIL_EVENTS*100:.1f}%)")
print(f"   - Saved to: {cloudtrail_file}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 7.5: Generate Realistic Raw Format Data (XML, API Responses)

# COMMAND ----------

# DBTITLE 1,Generate raw format data and conversion to .json
# This goes after the existing data generation and before verification
#
# PURPOSE:
# This script demonstrates realistic log format conversion by:
# 1. Generating raw format data (XML, API responses, compressed JSON)
# 2. Converting them to standardized JSON format
# 3. Writing both individual files (for visibility) and Spark DataFrames (for processing)
#
# FILE WRITING STRATEGY:
# - Each source creates TWO outputs:
#   1. Single .json file (newline-delimited) for easy viewing and verification
#   2. Spark DataFrame output (directory with part files) for DLT pipeline processing
#
# This ensures you see actual file sizes in verification while maintaining
# compatibility with Spark/DLT pipelines.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 7.5: Generate Realistic Raw Format Data (XML, API Responses)
# MAGIC 
# MAGIC Generate sample data in original formats (XML for Sysmon/Windows, API responses for Okta/CloudTrail)
# MAGIC and then convert them to JSON to simulate the real conversion process in Lab 00.
# MAGIC 
# MAGIC This makes the demo more realistic by showing:
# MAGIC 1. Raw XML data from Windows systems
# MAGIC 2. API response JSON from Okta
# MAGIC 3. CloudTrail compressed JSON format
# MAGIC 4. Conversion process to standardized JSON

# COMMAND ----------

# DBTITLE 1,Install XML Processing Library


# COMMAND ----------

# DBTITLE 1,Import Libraries for Format Conversion
import xmltodict
from lxml import etree as ET
import gzip
import json

print("✅ Format conversion libraries loaded")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Generate Sysmon XML Events

# COMMAND ----------

# DBTITLE 1,Generate Realistic Sysmon XML
def generate_sysmon_xml_events(num_events=100):
    """
    Generate realistic Sysmon events in XML format
    
    Returns: List of XML strings (one per event)
    """
    
    xml_events = []
    start_time = datetime.now() - timedelta(days=7)
    
    # Suspicious commands for detection
    suspicious_commands = [
        "powershell.exe -enc",
        "cmd.exe /c whoami",
        "net user administrator",
        "mimikatz.exe",
        "psexec.exe",
        "wmic process call create",
        "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    ]
    
    normal_commands = [
        "notepad.exe",
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\System32\\conhost.exe"
    ]
    
    for i in range(num_events):
        timestamp = start_time + timedelta(seconds=random.randint(0, 7*24*60*60))
        
        # 10% suspicious events
        is_suspicious = random.random() < 0.10
        
        if is_suspicious:
            process_cmd = random.choice(suspicious_commands)
            parent_image = "C:\\Windows\\System32\\cmd.exe"
        else:
            process_cmd = random.choice(normal_commands)
            parent_image = "C:\\Windows\\explorer.exe"
        
        # Event ID 1 = Process Creation
        event_id = 1
        
        process_guid = f"{{{uuid.uuid4()}}}"
        process_id = random.randint(1000, 9999)
        
        # Create XML structure
        xml_template = f"""<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385F-C22A-43E0-BF4C-06F5698FFBD9}}"/>
    <EventID>{event_id}</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="{timestamp.isoformat()}Z"/>
    <EventRecordID>{random.randint(100000, 999999)}</EventRecordID>
    <Correlation/>
    <Execution ProcessID="{random.randint(500, 5000)}" ThreadID="{random.randint(1000, 9999)}"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>{fake.hostname()}</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">{timestamp.isoformat()}Z</Data>
    <Data Name="ProcessGuid">{process_guid}</Data>
    <Data Name="ProcessId">{process_id}</Data>
    <Data Name="Image">{process_cmd.split()[0] if ' ' in process_cmd else process_cmd}</Data>
    <Data Name="FileVersion">{random.randint(6, 10)}.{random.randint(0, 9)}.{random.randint(1000, 9999)}.{random.randint(0, 999)}</Data>
    <Data Name="Description">Windows Command Processor</Data>
    <Data Name="Product">Microsoft Windows Operating System</Data>
    <Data Name="Company">Microsoft Corporation</Data>
    <Data Name="OriginalFileName">Cmd.Exe</Data>
    <Data Name="CommandLine">{process_cmd}</Data>
    <Data Name="CurrentDirectory">C:\\Windows\\System32\\</Data>
    <Data Name="User">{fake.user_name()}</Data>
    <Data Name="LogonGuid">{{{uuid.uuid4()}}}</Data>
    <Data Name="LogonId">0x{random.randint(10000, 99999):x}</Data>
    <Data Name="TerminalSessionId">{random.randint(1, 5)}</Data>
    <Data Name="IntegrityLevel">High</Data>
    <Data Name="Hashes">SHA256={uuid.uuid4().hex}{uuid.uuid4().hex}</Data>
    <Data Name="ParentProcessGuid">{{{uuid.uuid4()}}}</Data>
    <Data Name="ParentProcessId">{random.randint(1000, 5000)}</Data>
    <Data Name="ParentImage">{parent_image}</Data>
    <Data Name="ParentCommandLine">{parent_image}</Data>
    <Data Name="ParentUser">NT AUTHORITY\\SYSTEM</Data>
  </EventData>
</Event>"""
        
        xml_events.append(xml_template)
    
    return xml_events

print("🔧 Generating realistic Sysmon XML events...")
sysmon_xml_events = generate_sysmon_xml_events(200)
print(f"✅ Generated {len(sysmon_xml_events)} Sysmon XML events")

# Save to volume as XML files
sysmon_xml_dir = f"{volume_path}/raw_formats/sysmon_xml"
dbutils.fs.mkdirs(sysmon_xml_dir)

# Write XML events to a single file (simulating log file)
xml_content = "\n".join(sysmon_xml_events)
with open("/tmp/sysmon_events.xml", "w") as f:
    f.write(xml_content)

# Copy to volume
dbutils.fs.cp("file:/tmp/sysmon_events.xml", f"{sysmon_xml_dir}/sysmon_events_batch1.xml")
print(f"✅ Saved XML to: {sysmon_xml_dir}/sysmon_events_batch1.xml")

# Show sample
print("\n📄 Sample Sysmon XML Event:")
print(sysmon_xml_events[0][:500] + "...\n")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Convert Sysmon XML to JSON

# COMMAND ----------

# DBTITLE 1,Convert Sysmon XML to Standard JSON
def convert_sysmon_xml_to_json(xml_string):
    """Convert Sysmon XML event to standardized JSON"""
    try:
        event_dict = xmltodict.parse(xml_string)
        event = event_dict.get('Event', {})
        system = event.get('System', {})
        event_data = event.get('EventData', {}).get('Data', [])
        
        # Extract system fields
        event_id = system.get('EventID')
        time_created = system.get('TimeCreated', {}).get('@SystemTime')
        computer = system.get('Computer')
        
        # Parse EventData fields
        data_dict = {}
        if isinstance(event_data, list):
            for item in event_data:
                if isinstance(item, dict):
                    name = item.get('@Name', '')
                    value = item.get('#text', '')
                    data_dict[name] = value
        
        # Create standardized JSON
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
            "Hashes": data_dict.get('Hashes'),
            "IntegrityLevel": data_dict.get('IntegrityLevel'),
            "LogonId": data_dict.get('LogonId'),
            "source_system": "sysmon",
            "source_format": "xml",
            "conversion_timestamp": datetime.now().isoformat()
        }
        
        return json_event
    except Exception as e:
        print(f"Error parsing Sysmon XML: {e}")
        return None

# Convert all XML events to JSON
print("🔄 Converting Sysmon XML to JSON...")
sysmon_json_converted = []
for xml_event in sysmon_xml_events:
    json_event = convert_sysmon_xml_to_json(xml_event)
    if json_event:
        sysmon_json_converted.append(json_event)

print(f"✅ Converted {len(sysmon_json_converted)} events")

# Save converted JSON
sysmon_json_dir = f"{volume_path}/converted_formats/sysmon_json"
dbutils.fs.mkdirs(sysmon_json_dir)

# Write as newline-delimited JSON (one event per line)
with open("/tmp/sysmon_converted.json", "w") as f:
    for event in sysmon_json_converted:
        f.write(json.dumps(event) + "\n")

dbutils.fs.cp("file:/tmp/sysmon_converted.json", f"{sysmon_json_dir}/sysmon_converted.json", recurse=False)

print(f"✅ Saved converted JSON to: {sysmon_json_dir}/sysmon_converted.json")

# Also write as Spark DataFrame for DLT pipeline
sysmon_converted_df = pd.DataFrame(sysmon_json_converted)
spark.createDataFrame(sysmon_converted_df).write.mode("overwrite").json(f"{sysmon_json_dir}/sysmon_converted_spark")

# Show sample conversion
print("\n📄 Sample Converted JSON:")
print(json.dumps(sysmon_json_converted[0], indent=2))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Generate Windows Event Log XML

# COMMAND ----------

# DBTITLE 1,Generate Realistic Windows Event XML
def generate_windows_event_xml(num_events=100):
    """Generate realistic Windows Security Event logs in XML format"""
    
    xml_events = []
    start_time = datetime.now() - timedelta(days=7)
    
    # Event IDs and their descriptions
    event_templates = {
        4624: "Successful Logon",
        4625: "Failed Logon",
        4672: "Special Privileges Assigned",
        4688: "Process Creation",
        4720: "User Account Created"
    }
    
    logon_types = {
        2: "Interactive",
        3: "Network",
        10: "RemoteInteractive"
    }
    
    for i in range(num_events):
        timestamp = start_time + timedelta(seconds=random.randint(0, 7*24*60*60))
        
        # 15% failed logons (4625)
        if random.random() < 0.15:
            event_id = 4625
            status = "0xC000006D"  # Bad username or password
        else:
            event_id = random.choice([4624, 4672, 4688, 4720])
            status = "0x0"
        
        logon_type = random.choice(list(logon_types.keys()))
        
        xml_template = f"""<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}"/>
    <EventID>{event_id}</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="{timestamp.isoformat()}Z"/>
    <EventRecordID>{random.randint(100000, 999999)}</EventRecordID>
    <Correlation/>
    <Execution ProcessID="{random.randint(500, 1000)}" ThreadID="{random.randint(1000, 5000)}"/>
    <Channel>Security</Channel>
    <Computer>{fake.hostname()}.{fake.domain_name()}</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">SYSTEM</Data>
    <Data Name="SubjectDomainName">NT AUTHORITY</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="TargetUserSid">S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}</Data>
    <Data Name="TargetUserName">{fake.user_name()}</Data>
    <Data Name="TargetDomainName">{fake.domain_word().upper()}</Data>
    <Data Name="Status">{status}</Data>
    <Data Name="FailureReason">%%2313</Data>
    <Data Name="SubStatus">0xC000006D</Data>
    <Data Name="LogonType">{logon_type}</Data>
    <Data Name="LogonProcessName">User32</Data>
    <Data Name="AuthenticationPackageName">Negotiate</Data>
    <Data Name="WorkstationName">{fake.hostname().upper()}</Data>
    <Data Name="LogonGuid">{{{uuid.uuid4()}}}</Data>
    <Data Name="TransmittedServices">-</Data>
    <Data Name="LmPackageName">-</Data>
    <Data Name="KeyLength">0</Data>
    <Data Name="ProcessId">0x{random.randint(1000, 9999):x}</Data>
    <Data Name="ProcessName">C:\\Windows\\System32\\winlogon.exe</Data>
    <Data Name="IpAddress">{fake.ipv4()}</Data>
    <Data Name="IpPort">{random.randint(49152, 65535)}</Data>
  </EventData>
</Event>"""
        
        xml_events.append(xml_template)
    
    return xml_events

print("🔧 Generating Windows Event XML logs...")
windows_xml_events = generate_windows_event_xml(200)
print(f"✅ Generated {len(windows_xml_events)} Windows Event XML logs")

# Save XML events
windows_xml_dir = f"{volume_path}/raw_formats/windows_xml"
dbutils.fs.mkdirs(windows_xml_dir)

xml_content = "\n".join(windows_xml_events)
with open("/tmp/windows_security_events.xml", "w") as f:
    f.write(xml_content)

dbutils.fs.cp("file:/tmp/windows_security_events.xml", f"{windows_xml_dir}/security_events_batch1.xml")
print(f"✅ Saved XML to: {windows_xml_dir}/security_events_batch1.xml")

# Show sample
print("\n📄 Sample Windows Event XML:")
print(windows_xml_events[0][:500] + "...\n")

# COMMAND ----------

# DBTITLE 1,Convert Windows Event XML to JSON
def convert_windows_xml_to_json(xml_string):
    """Convert Windows Event XML to standardized JSON"""
    try:
        event_dict = xmltodict.parse(xml_string)
        event = event_dict.get('Event', {})
        system = event.get('System', {})
        event_data = event.get('EventData', {}).get('Data', [])
        
        # Extract fields
        event_id = system.get('EventID')
        time_created = system.get('TimeCreated', {}).get('@SystemTime')
        computer = system.get('Computer')
        
        # Parse event data
        data_dict = {}
        if isinstance(event_data, list):
            for item in event_data:
                if isinstance(item, dict):
                    name = item.get('@Name', '')
                    value = item.get('#text', '')
                    data_dict[name] = value
        
        json_event = {
            "EventID": int(event_id) if event_id else None,
            "EventRecordID": system.get('EventRecordID'),
            "TimeCreated": time_created,
            "Computer": computer,
            "Channel": system.get('Channel'),
            "TargetUserName": data_dict.get('TargetUserName'),
            "TargetDomainName": data_dict.get('TargetDomainName'),
            "LogonType": int(data_dict.get('LogonType', 0)) if data_dict.get('LogonType') else None,
            "IpAddress": data_dict.get('IpAddress'),
            "IpPort": int(data_dict.get('IpPort', 0)) if data_dict.get('IpPort') else None,
            "Status": data_dict.get('Status'),
            "WorkstationName": data_dict.get('WorkstationName'),
            "ProcessName": data_dict.get('ProcessName'),
            "source_system": "windows",
            "source_format": "xml",
            "conversion_timestamp": datetime.now().isoformat()
        }
        
        return json_event
    except Exception as e:
        print(f"Error parsing Windows Event XML: {e}")
        return None

# Convert all events
print("🔄 Converting Windows Event XML to JSON...")
windows_json_converted = []
for xml_event in windows_xml_events:
    json_event = convert_windows_xml_to_json(xml_event)
    if json_event:
        windows_json_converted.append(json_event)

print(f"✅ Converted {len(windows_json_converted)} events")

# Save converted JSON
windows_json_dir = f"{volume_path}/converted_formats/windows_json"
dbutils.fs.mkdirs(windows_json_dir)

# Write as newline-delimited JSON (one event per line)
with open("/tmp/windows_converted.json", "w") as f:
    for event in windows_json_converted:
        f.write(json.dumps(event) + "\n")

dbutils.fs.cp("file:/tmp/windows_converted.json", f"{windows_json_dir}/windows_converted.json", recurse=False)

print(f"✅ Saved converted JSON to: {windows_json_dir}/windows_converted.json")

# Also write as Spark DataFrame for DLT pipeline
windows_converted_df = pd.DataFrame(windows_json_converted)
spark.createDataFrame(windows_converted_df).write.mode("overwrite").json(f"{windows_json_dir}/windows_converted_spark")

print("\n📄 Sample Converted JSON:")
print(json.dumps(windows_json_converted[0], indent=2))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Generate Okta API Response Format

# COMMAND ----------

# DBTITLE 1,Generate Realistic Okta API Responses
def generate_okta_api_responses(num_events=100):
    """Generate realistic Okta System Log API responses"""
    
    events = []
    start_time = datetime.now() - timedelta(days=7)
    
    event_types = [
        "user.authentication.auth_via_mfa",
        "user.authentication.sso",
        "user.session.start",
        "user.session.end",
        "policy.rule.deactivate",
        "user.account.lock",
        "application.user_membership.add"
    ]
    
    for i in range(num_events):
        timestamp = start_time + timedelta(seconds=random.randint(0, 7*24*60*60))
        
        # 12% failed authentications
        is_failed = random.random() < 0.12
        
        event = {
            "uuid": str(uuid.uuid4()),
            "published": timestamp.isoformat() + "Z",
            "eventType": random.choice(event_types),
            "version": "0",
            "severity": "WARN" if is_failed else "INFO",
            "legacyEventType": "core.user_auth.login_failed" if is_failed else "core.user_auth.login_success",
            "displayMessage": "User login failed" if is_failed else "User login to Okta",
            "actor": {
                "id": f"00u{uuid.uuid4().hex[:17]}",
                "type": "User",
                "alternateId": fake.email(),
                "displayName": fake.name(),
                "detailEntry": None
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": fake.user_agent(),
                    "os": random.choice(["Windows 10", "Mac OS X", "Linux"]),
                    "browser": random.choice(["CHROME", "FIREFOX", "SAFARI", "EDGE"])
                },
                "zone": "null",
                "device": "Computer",
                "id": None,
                "ipAddress": fake.ipv4(),
                "geographicalContext": {
                    "city": fake.city(),
                    "state": fake.state_abbr(),
                    "country": "United States",
                    "postalCode": fake.postcode(),
                    "geolocation": {
                        "lat": float(fake.latitude()),
                        "lon": float(fake.longitude())
                    }
                }
            },
            "outcome": {
                "result": "FAILURE" if is_failed else "SUCCESS",
                "reason": "INVALID_CREDENTIALS" if is_failed else None
            },
            "target": [
                {
                    "id": f"00u{uuid.uuid4().hex[:17]}",
                    "type": "User",
                    "alternateId": fake.email(),
                    "displayName": fake.name()
                }
            ],
            "transaction": {
                "type": "WEB",
                "id": f"W{uuid.uuid4().hex[:20]}",
                "detail": {}
            },
            "debugContext": {
                "debugData": {
                    "requestId": f"req{uuid.uuid4().hex[:20]}",
                    "requestUri": "/api/v1/authn",
                    "threatSuspected": "false",
                    "url": f"/api/v1/authn?"
                }
            },
            "authenticationContext": {
                "authenticationProvider": None,
                "credentialProvider": None,
                "credentialType": None,
                "issuer": None,
                "externalSessionId": f"idx{uuid.uuid4().hex[:20]}",
                "interface": None
            }
        }
        
        events.append(event)
    
    return events

print("🔧 Generating Okta API response format...")
okta_api_responses = generate_okta_api_responses(150)
print(f"✅ Generated {len(okta_api_responses)} Okta API responses")

# Save as API response format (pretty JSON)
okta_api_dir = f"{volume_path}/raw_formats/okta_api"
dbutils.fs.mkdirs(okta_api_dir)

# Save as formatted JSON (simulating API response)
api_response = json.dumps(okta_api_responses, indent=2)
with open("/tmp/okta_api_response.json", "w") as f:
    f.write(api_response)

dbutils.fs.cp("file:/tmp/okta_api_response.json", f"{okta_api_dir}/system_log_api_response.json")
print(f"✅ Saved API response to: {okta_api_dir}/system_log_api_response.json")

# Show sample
print("\n📄 Sample Okta API Response:")
print(json.dumps(okta_api_responses[0], indent=2)[:800] + "...\n")

# COMMAND ----------

# DBTITLE 1,Convert Okta API Response to Standard JSON
def convert_okta_api_to_json(api_event):
    """Convert Okta API response to standardized flattened JSON"""
    
    json_event = {
        "uuid": api_event.get("uuid"),
        "published": api_event.get("published"),
        "eventType": api_event.get("eventType"),
        "severity": api_event.get("severity"),
        "displayMessage": api_event.get("displayMessage"),
        "actor_id": api_event.get("actor", {}).get("id"),
        "actor_type": api_event.get("actor", {}).get("type"),
        "actor_alternateId": api_event.get("actor", {}).get("alternateId"),
        "actor_displayName": api_event.get("actor", {}).get("displayName"),
        "client_ipAddress": api_event.get("client", {}).get("ipAddress"),
        "client_userAgent_os": api_event.get("client", {}).get("userAgent", {}).get("os"),
        "client_userAgent_browser": api_event.get("client", {}).get("userAgent", {}).get("browser"),
        "client_geographicalContext_city": api_event.get("client", {}).get("geographicalContext", {}).get("city"),
        "client_geographicalContext_state": api_event.get("client", {}).get("geographicalContext", {}).get("state"),
        "client_geographicalContext_country": api_event.get("client", {}).get("geographicalContext", {}).get("country"),
        "outcome_result": api_event.get("outcome", {}).get("result"),
        "outcome_reason": api_event.get("outcome", {}).get("reason"),
        "source_system": "okta",
        "source_format": "api",
        "conversion_timestamp": datetime.now().isoformat()
    }
    
    return json_event

# Convert all events
print("🔄 Converting Okta API responses to standard JSON...")
okta_json_converted = [convert_okta_api_to_json(event) for event in okta_api_responses]
print(f"✅ Converted {len(okta_json_converted)} events")

# Save converted JSON
okta_json_dir = f"{volume_path}/converted_formats/okta_json"
dbutils.fs.mkdirs(okta_json_dir)

# Write as newline-delimited JSON (one event per line)
with open("/tmp/okta_converted.json", "w") as f:
    for event in okta_json_converted:
        f.write(json.dumps(event) + "\n")

dbutils.fs.cp("file:/tmp/okta_converted.json", f"{okta_json_dir}/okta_converted.json", recurse=False)

print(f"✅ Saved converted JSON to: {okta_json_dir}/okta_converted.json")

# Also write as Spark DataFrame for DLT pipeline
okta_converted_df = pd.DataFrame(okta_json_converted)
spark.createDataFrame(okta_converted_df).write.mode("overwrite").json(f"{okta_json_dir}/okta_converted_spark")

print("\n📄 Sample Converted JSON:")
print(json.dumps(okta_json_converted[0], indent=2))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Generate CloudTrail Compressed JSON

# COMMAND ----------

# DBTITLE 1,Generate CloudTrail Compressed Format
def generate_cloudtrail_compressed(num_events=100):
    """Generate CloudTrail events in compressed JSON format (as stored in S3)"""
    
    events = []
    start_time = datetime.now() - timedelta(days=7)
    
    event_names = [
        "AssumeRole", "GetObject", "PutObject", "ListBuckets",
        "DescribeInstances", "CreateAccessKey", "AttachUserPolicy",
        "PutBucketPolicy", "DeleteTrail", "StopLogging"
    ]
    
    for i in range(num_events):
        timestamp = start_time + timedelta(seconds=random.randint(0, 7*24*60*60))
        
        is_suspicious = random.random() < 0.10
        event_name = random.choice(event_names[-5:]) if is_suspicious else random.choice(event_names[:5])
        
        event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDA{uuid.uuid4().hex[:16].upper()}",
                "arn": f"arn:aws:iam::123456789012:user/{fake.user_name()}",
                "accountId": "123456789012",
                "accessKeyId": f"AKIA{uuid.uuid4().hex[:16].upper()}",
                "userName": fake.user_name()
            },
            "eventTime": timestamp.isoformat() + "Z",
            "eventSource": random.choice(["iam.amazonaws.com", "s3.amazonaws.com", "ec2.amazonaws.com"]),
            "eventName": event_name,
            "awsRegion": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
            "sourceIPAddress": fake.ipv4(),
            "userAgent": random.choice(["aws-cli/2.13.0", "Boto3/1.28.0", "console.aws.amazon.com"]),
            "requestParameters": {
                "bucketName": f"{fake.word()}-data" if "Bucket" in event_name else None,
                "userName": fake.user_name() if "User" in event_name else None
            },
            "responseElements": None if is_suspicious and random.random() < 0.3 else {"status": "success"},
            "requestID": str(uuid.uuid4()),
            "eventID": str(uuid.uuid4()),
            "readOnly": event_name.startswith(("Get", "List", "Describe")),
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": "123456789012"
        }
        
        events.append(event)
    
    return events

print("🔧 Generating CloudTrail events...")
cloudtrail_events_raw = generate_cloudtrail_compressed(150)

# CloudTrail wraps events in a Records array
cloudtrail_wrapped = {
    "Records": cloudtrail_events_raw
}

# Save as compressed JSON (like S3)
cloudtrail_raw_dir = f"{volume_path}/raw_formats/cloudtrail_s3"
dbutils.fs.mkdirs(cloudtrail_raw_dir)

# Write as JSON.GZ (compressed)
json_str = json.dumps(cloudtrail_wrapped)
with gzip.open("/tmp/cloudtrail_events.json.gz", "wt", encoding="utf-8") as f:
    f.write(json_str)

dbutils.fs.cp("file:/tmp/cloudtrail_events.json.gz", f"{cloudtrail_raw_dir}/2025/11/03/123456789012_CloudTrail_us-east-1_20251103T1000Z_abc123.json.gz")
print(f"✅ Saved compressed CloudTrail to: {cloudtrail_raw_dir}/.../cloudtrail_events.json.gz")

# Also save uncompressed for viewing
with open("/tmp/cloudtrail_events.json", "w") as f:
    f.write(json_str)
dbutils.fs.cp("file:/tmp/cloudtrail_events.json", f"{cloudtrail_raw_dir}/cloudtrail_sample_uncompressed.json")

print(f"✅ Generated {len(cloudtrail_events_raw)} CloudTrail events")
print("\n📄 Sample CloudTrail Event:")
print(json.dumps(cloudtrail_events_raw[0], indent=2)[:600] + "...\n")

# COMMAND ----------

# DBTITLE 1,Convert CloudTrail to Standard JSON
def convert_cloudtrail_to_json(ct_event):
    """Convert CloudTrail event to standardized flattened JSON"""
    
    json_event = {
        "eventVersion": ct_event.get("eventVersion"),
        "eventTime": ct_event.get("eventTime"),
        "eventID": ct_event.get("eventID"),
        "eventType": ct_event.get("eventType"),
        "eventName": ct_event.get("eventName"),
        "eventSource": ct_event.get("eventSource"),
        "awsRegion": ct_event.get("awsRegion"),
        "sourceIPAddress": ct_event.get("sourceIPAddress"),
        "userAgent": ct_event.get("userAgent"),
        "errorCode": ct_event.get("errorCode"),
        "errorMessage": ct_event.get("errorMessage"),
        "requestID": ct_event.get("requestID"),
        "userIdentity_type": ct_event.get("userIdentity", {}).get("type"),
        "userIdentity_principalId": ct_event.get("userIdentity", {}).get("principalId"),
        "userIdentity_arn": ct_event.get("userIdentity", {}).get("arn"),
        "userIdentity_accountId": ct_event.get("userIdentity", {}).get("accountId"),
        "userIdentity_userName": ct_event.get("userIdentity", {}).get("userName"),
        "source_system": "cloudtrail",
        "source_format": "json_gz",
        "conversion_timestamp": datetime.now().isoformat()
    }
    
    return json_event

# Convert all events
print("🔄 Converting CloudTrail events to standard JSON...")
cloudtrail_json_converted = [convert_cloudtrail_to_json(event) for event in cloudtrail_events_raw]
print(f"✅ Converted {len(cloudtrail_json_converted)} events")

# Save converted JSON
cloudtrail_json_dir = f"{volume_path}/converted_formats/cloudtrail_json"
dbutils.fs.mkdirs(cloudtrail_json_dir)

# Write as newline-delimited JSON (one event per line)
with open("/tmp/cloudtrail_converted.json", "w") as f:
    for event in cloudtrail_json_converted:
        f.write(json.dumps(event) + "\n")

dbutils.fs.cp("file:/tmp/cloudtrail_converted.json", f"{cloudtrail_json_dir}/cloudtrail_converted.json", recurse=False)

print(f"✅ Saved converted JSON to: {cloudtrail_json_dir}/cloudtrail_converted.json")

# Also write as Spark DataFrame for DLT pipeline
cloudtrail_converted_df = pd.DataFrame(cloudtrail_json_converted)
spark.createDataFrame(cloudtrail_converted_df).write.mode("overwrite").json(f"{cloudtrail_json_dir}/cloudtrail_converted_spark")

print("\n📄 Sample Converted JSON:")
print(json.dumps(cloudtrail_json_converted[0], indent=2))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Summary of Format Conversion

# COMMAND ----------

# DBTITLE 1,Format Conversion Summary Report
print("=" * 80)
print("📊 FORMAT CONVERSION DEMONSTRATION SUMMARY")
print("=" * 80)

conversion_summary = {
    "Sysmon": {
        "Raw Format": "XML (Windows Event format)",
        "Raw Location": f"{volume_path}/raw_formats/sysmon_xml/",
        "Converted Location": f"{volume_path}/converted_formats/sysmon_json/",
        "Events Generated": len(sysmon_xml_events),
        "Events Converted": len(sysmon_json_converted),
        "Conversion Success Rate": f"{len(sysmon_json_converted)/len(sysmon_xml_events)*100:.1f}%"
    },
    "Windows Events": {
        "Raw Format": "XML (Security Event format)",
        "Raw Location": f"{volume_path}/raw_formats/windows_xml/",
        "Converted Location": f"{volume_path}/converted_formats/windows_json/",
        "Events Generated": len(windows_xml_events),
        "Events Converted": len(windows_json_converted),
        "Conversion Success Rate": f"{len(windows_json_converted)/len(windows_xml_events)*100:.1f}%"
    },
    "Okta": {
        "Raw Format": "JSON (API Response format)",
        "Raw Location": f"{volume_path}/raw_formats/okta_api/",
        "Converted Location": f"{volume_path}/converted_formats/okta_json/",
        "Events Generated": len(okta_api_responses),
        "Events Converted": len(okta_json_converted),
        "Conversion Success Rate": f"{len(okta_json_converted)/len(okta_api_responses)*100:.1f}%"
    },
    "CloudTrail": {
        "Raw Format": "JSON.GZ (S3 compressed format)",
        "Raw Location": f"{volume_path}/raw_formats/cloudtrail_s3/",
        "Converted Location": f"{volume_path}/converted_formats/cloudtrail_json/",
        "Events Generated": len(cloudtrail_events_raw),
        "Events Converted": len(cloudtrail_json_converted),
        "Conversion Success Rate": f"{len(cloudtrail_json_converted)/len(cloudtrail_events_raw)*100:.1f}%"
    }
}

for source, details in conversion_summary.items():
    print(f"\n🔹 {source}")
    print(f"   Raw Format: {details['Raw Format']}")
    print(f"   Events: {details['Events Generated']} → {details['Events Converted']} (Success: {details['Conversion Success Rate']})")
    print(f"   Raw Files: {details['Raw Location']}")
    print(f"   Converted: {details['Converted Location']}")

print("\n" + "=" * 80)
print("✅ FORMAT CONVERSION DEMONSTRATION COMPLETE")
print("=" * 80)
print("\n💡 These files demonstrate:")
print("   1. Real-world log formats (XML, API, compressed JSON)")
print("   2. Conversion process to standardized JSON")
print("   3. Ready for Lab 00 real-time ingestion processing")
print("\n🎯 Next Steps:")
print("   - Review raw format files to see original structures")
print("   - Compare with converted JSON files")
print("   - Use Lab 00 to process similar real-time data")
print("   - Continue with Lab 02 (DLT Pipeline)")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verify Format Conversion Files

# COMMAND ----------

# DBTITLE 1,List All Raw and Converted Files
def format_bytes(size):
    """Format bytes to human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"

def list_directory_recursive(path, indent=0):
    """Recursively list directory contents with sizes"""
    try:
        items = dbutils.fs.ls(path)
        for item in items:
            prefix = "  " * indent
            if item.path.endswith('/'):
                # It's a directory
                print(f"{prefix}📂 {item.name}")
                list_directory_recursive(item.path, indent + 1)
            else:
                # It's a file
                size_str = format_bytes(item.size)
                print(f"{prefix}📄 {item.name} ({size_str})")
    except Exception as e:
        print(f"{prefix}⚠️  Error reading: {str(e)[:50]}")

print("📁 Raw Format Files:")
print("=" * 80)
try:
    list_directory_recursive(f"{volume_path}/raw_formats")
except:
    print("  No raw format files found")

print("\n📁 Converted Format Files:")
print("=" * 80)
try:
    list_directory_recursive(f"{volume_path}/converted_formats")
except:
    print("  No converted format files found")

# Count total files and size
print("\n📊 Storage Summary:")
print("=" * 80)
def get_total_size(path):
    """Calculate total size of all files in directory"""
    total = 0
    file_count = 0
    try:
        items = dbutils.fs.ls(path)
        for item in items:
            if item.path.endswith('/'):
                sub_size, sub_count = get_total_size(item.path)
                total += sub_size
                file_count += sub_count
            else:
                total += item.size
                file_count += 1
    except:
        pass
    return total, file_count

raw_size, raw_count = get_total_size(f"{volume_path}/raw_formats")
converted_size, converted_count = get_total_size(f"{volume_path}/converted_formats")

print(f"Raw Formats:       {raw_count} files, {format_bytes(raw_size)} total")
print(f"Converted Formats: {converted_count} files, {format_bytes(converted_size)} total")
print(f"Total Storage:     {raw_count + converted_count} files, {format_bytes(raw_size + converted_size)} total")

# COMMAND ----------



# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 8: Verify Data Files

# COMMAND ----------

# DBTITLE 1,List Generated Files
# List all files in volume
dbutils.fs.ls(volume_path)

# COMMAND ----------

# DBTITLE 1,Sample Data Preview
# Preview Sysmon logs
print("=" * 80)
print("SYSMON LOGS SAMPLE")
print("=" * 80)
sysmon_sample = spark.read.json(f"{volume_path}/sysmon_logs.json").limit(3)
sysmon_sample.show(truncate=False, vertical=True)

print("\n" + "=" * 80)
print("OKTA LOGS SAMPLE")
print("=" * 80)
okta_sample = spark.read.json(f"{volume_path}/okta_logs.json").limit(3)
display(okta_sample.select("eventType", "outcome.result", "actor.alternateId", "client.ipAddress", "published"))

print("\n" + "=" * 80)
print("WINDOWS EVENT LOGS SAMPLE")
print("=" * 80)
windows_sample = spark.read.json(f"{volume_path}/windows_logs.json").limit(3)
display(windows_sample.select("EventID", "LogonTypeName", "TargetUserName", "SourceNetworkAddress", "Status"))

print("\n" + "=" * 80)
print("CLOUDTRAIL LOGS SAMPLE")
print("=" * 80)
cloudtrail_sample = spark.read.json(f"{volume_path}/cloudtrail_logs.json").limit(3)
display(cloudtrail_sample.select("eventName", "eventSource", "sourceIPAddress", "userIdentity.userName", "errorCode"))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 9: Summary and Next Steps

# COMMAND ----------

# DBTITLE 1,Lab 01 Summary
print("=" * 80)
print("LAB 01 COMPLETE ✅")
print("=" * 80)
print("\n📊 Summary:")
print(f"  • Catalog: {CATALOG_NAME}")
print(f"  • Schema: {SCHEMA_NAME}")
print(f"  • Volume: {volume_path}")
print(f"\n📁 Generated Data Files:")
print(f"  • Sysmon logs: {NUM_SYSMON_EVENTS:,} events")
print(f"  • Okta logs: {NUM_OKTA_EVENTS:,} events")
print(f"  • Windows Event logs: {NUM_WINDOWS_EVENTS:,} events")
print(f"  • CloudTrail logs: {NUM_CLOUDTRAIL_EVENTS:,} events")
print(f"  • Total: {NUM_SYSMON_EVENTS + NUM_OKTA_EVENTS + NUM_WINDOWS_EVENTS + NUM_CLOUDTRAIL_EVENTS:,} events")

print("\n🎯 What You Learned:")
print("  ✓ Created Unity Catalog structure for security data")
print("  ✓ Generated realistic security logs with malicious patterns")
print("  ✓ Stored data in Unity Catalog Volumes")
print("  ✓ Verified data accessibility")

print("\n➡️  Next Steps:")
print("  1. Proceed to Lab 02: Data Ingestion and Normalization")
print("  2. Open notebook: 02_data_ingestion_dlt.py")
print("  3. Build Bronze → Silver → Gold pipeline with Delta Live Tables")

print("\n" + "=" * 80)

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## 🎓 Instructor Notes
# MAGIC
# MAGIC ### Discussion Points:
# MAGIC 1. **Unity Catalog Benefits:**
# MAGIC    - Centralized governance
# MAGIC    - Fine-grained access control
# MAGIC    - Data lineage and audit
# MAGIC
# MAGIC 2. **Sample Data Quality:**
# MAGIC    - Realistic patterns are critical for detection development
# MAGIC    - Balance between malicious and benign (avoid bias)
# MAGIC    - Include edge cases and false positive scenarios
# MAGIC
# MAGIC 3. **Data Volume Strategy:**
# MAGIC    - Volumes vs. external storage (S3, ADLS)
# MAGIC    - When to use each approach
# MAGIC    - Cost and performance considerations
# MAGIC
# MAGIC ### Troubleshooting:
# MAGIC - **Permission errors:** Ensure user has CREATE privileges
# MAGIC - **Volume path issues:** Use `/Volumes/` prefix for Unity Catalog
# MAGIC - **Faker import:** Requires `%pip install` and Python restart
# MAGIC
# MAGIC ### Extensions:
# MAGIC - Use real sample data (anonymized)
# MAGIC - Add more log sources (Azure AD, GCP, firewall logs)
# MAGIC - Integrate with SIEM data exports
# MAGIC