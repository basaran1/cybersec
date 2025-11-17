# Databricks notebook source
# MAGIC %md
# MAGIC # Lab Validation and Testing Script
# MAGIC
# MAGIC This notebook validates that the security detection lab is set up correctly.
# MAGIC Run this after completing all lab modules to verify everything works.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Validation Script
# MAGIC
# MAGIC This script checks:
# MAGIC 1. ✅ Unity Catalog structure exists
# MAGIC 2. ✅ Sample data files are present
# MAGIC 3. ✅ Bronze tables have data
# MAGIC 4. ✅ Silver tables have data  
# MAGIC 5. ✅ Gold alerts table exists and has alerts
# MAGIC 6. ✅ Detection rules are working
# MAGIC 7. ✅ All expected columns are present

# COMMAND ----------

# DBTITLE 1,Configuration
import sys
from pyspark.sql.functions import *

# Configuration
CATALOG_NAME = "security_detection_engineering_lab"
SCHEMA_NAME = "security_logs"
VOLUME_NAME = "raw_logs"

# Color codes for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_success(msg):
    print(f"{Colors.GREEN}✅ {msg}{Colors.END}")

def print_error(msg):
    print(f"{Colors.RED}❌ {msg}{Colors.END}")

def print_warning(msg):
    print(f"{Colors.YELLOW}⚠️  {msg}{Colors.END}")

def print_info(msg):
    print(f"{Colors.BLUE}ℹ️  {msg}{Colors.END}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Test 1: Unity Catalog Structure

# COMMAND ----------

# DBTITLE 1,Test 1: Catalog and Schema
print("=" * 80)
print("TEST 1: Unity Catalog Structure")
print("=" * 80)

tests_passed = 0
tests_failed = 0

# Check catalog exists
try:
    spark.sql(f"USE CATALOG {CATALOG_NAME}")
    print_success(f"Catalog '{CATALOG_NAME}' exists")
    tests_passed += 1
except Exception as e:
    print_error(f"Catalog '{CATALOG_NAME}' not found")
    print_info(f"Error: {str(e)[:100]}")
    tests_failed += 1

# Check schema exists
try:
    spark.sql(f"USE SCHEMA {SCHEMA_NAME}")
    print_success(f"Schema '{SCHEMA_NAME}' exists")
    tests_passed += 1
except Exception as e:
    print_error(f"Schema '{SCHEMA_NAME}' not found")
    print_info(f"Error: {str(e)[:100]}")
    tests_failed += 1

# Check volume exists
try:
    volume_path = f"/Volumes/{CATALOG_NAME}/{SCHEMA_NAME}/{VOLUME_NAME}"
    files = dbutils.fs.ls(volume_path)
    print_success(f"Volume '{VOLUME_NAME}' exists with {len(files)} files")
    tests_passed += 1
except Exception as e:
    print_error(f"Volume '{VOLUME_NAME}' not accessible")
    print_info(f"Error: {str(e)[:100]}")
    tests_failed += 1

print(f"\nTest 1 Summary: {tests_passed} passed, {tests_failed} failed")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Test 2: Sample Data Files

# COMMAND ----------

# DBTITLE 1,Test 2: Raw Data Files
print("\n" + "=" * 80)
print("TEST 2: Sample Data Files")
print("=" * 80)

volume_path = f"/Volumes/{CATALOG_NAME}/{SCHEMA_NAME}/{VOLUME_NAME}"
required_files = ['sysmon_logs.json', 'okta_logs.json', 'windows_logs.json', 'cloudtrail_logs.json']

for file_name in required_files:
    try:
        file_path = f"{volume_path}/{file_name}"
        files = dbutils.fs.ls(file_path)
        
        # Read and count records
        df = spark.read.json(file_path)
        count = df.count()
        
        if count > 0:
            print_success(f"{file_name}: {count:,} records")
            tests_passed += 1
        else:
            print_warning(f"{file_name}: File exists but has 0 records")
            tests_failed += 1
    except Exception as e:
        print_error(f"{file_name}: Not found or unreadable")
        print_info(f"Error: {str(e)[:100]}")
        tests_failed += 1

print(f"\nTest 2 Summary: {tests_passed} passed, {tests_failed} failed")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Test 3: Bronze Tables

# COMMAND ----------

# DBTITLE 1,Test 3: Bronze Layer
print("\n" + "=" * 80)
print("TEST 3: Bronze Tables (Raw Ingestion)")
print("=" * 80)

bronze_tables = ['bronze_sysmon', 'bronze_okta', 'bronze_windows', 'bronze_cloudtrail']

for table in bronze_tables:
    try:
        full_table_name = f"{CATALOG_NAME}.{SCHEMA_NAME}.{table}"
        count = spark.sql(f"SELECT COUNT(*) as cnt FROM {full_table_name}").collect()[0]['cnt']
        if count > 0:
            print_success(f"{table}: {count:,} records")
            tests_passed += 1
        else:
            print_warning(f"{table}: Table exists but has 0 records")
            print_info("Run Lab 02 (DLT pipeline) to populate Bronze tables")
            tests_failed += 1
    except Exception as e:
        print_error(f"{table}: Not found")
        print_info("Run Lab 02 (DLT pipeline) to create Bronze tables")
        tests_failed += 1

print(f"\nTest 3 Summary: {tests_passed} passed, {tests_failed} failed")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Test 4: Silver Tables

# COMMAND ----------

# DBTITLE 1,Test 4: Silver Layer
print("\n" + "=" * 80)
print("TEST 4: Silver Tables (Normalized Data)")
print("=" * 80)

silver_tables = [
    'silver_sysmon_process',
    'silver_sysmon_network',
    'silver_okta_auth',
    'silver_windows_auth',
    'silver_cloudtrail'
]

for table in silver_tables:
    try:
        full_table_name = f"{CATALOG_NAME}.{SCHEMA_NAME}.{table}"
        count = spark.sql(f"SELECT COUNT(*) as cnt FROM {full_table_name}").collect()[0]['cnt']
        if count > 0:
            print_success(f"{table}: {count:,} records")
            tests_passed += 1
            
            # Check for threat indicators
            if 'sysmon' in table or 'okta' in table:
                suspicious = spark.sql(f"""
                    SELECT COUNT(*) as cnt 
                    FROM {full_table_name} 
                    WHERE 
                        threat_indicator != 'normal' 
                        OR risk_indicator != 'normal'
                """).collect()[0]['cnt']
                
                if suspicious > 0:
                    print_info(f"  → {suspicious:,} suspicious events detected")
                else:
                    print_warning(f"  → No suspicious events found (expected some)")
        else:
            print_warning(f"{table}: Table exists but has 0 records")
            tests_failed += 1
    except Exception as e:
        print_error(f"{table}: Not found")
        print_info("Run Lab 02 (DLT pipeline) to create Silver tables")
        tests_failed += 1

print(f"\nTest 4 Summary: {tests_passed} passed, {tests_failed} failed")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Test 5: Gold Alerts Table

# COMMAND ----------

# DBTITLE 1,Test 5: Gold Layer
print("\n" + "=" * 80)
print("TEST 5: Gold Alerts Table")
print("=" * 80)

try:
    # Check table exists
    gold_alerts_table = f"{CATALOG_NAME}.{SCHEMA_NAME}.gold_security_alerts"
    alert_count = spark.sql(f"SELECT COUNT(*) as cnt FROM {gold_alerts_table}").collect()[0]['cnt']
    
    if alert_count > 0:
        print_success(f"gold_security_alerts: {alert_count:,} alerts")
        tests_passed += 1
        
        # Check severity distribution
        severity_dist = spark.sql(f"""
            SELECT severity, COUNT(*) as cnt
            FROM {gold_alerts_table}
            GROUP BY severity
            ORDER BY 
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    ELSE 4
                END
        """).collect()
        
        print_info("Severity Distribution:")
        for row in severity_dist:
            print(f"    {row['severity']:10s}: {row['cnt']:,} alerts")
        
        # Check for required fields
        required_fields = ['alert_id', 'detection_time', 'severity', 'mitre_technique', 'status']
        df = spark.table(gold_alerts_table)
        missing_fields = [f for f in required_fields if f not in df.columns]
        
        if not missing_fields:
            print_success("All required fields present")
            tests_passed += 1
        else:
            print_error(f"Missing fields: {', '.join(missing_fields)}")
            tests_failed += 1
    else:
        print_warning("gold_security_alerts: Table exists but has 0 alerts")
        print_info("Run Lab 03 (Detection Rules) to populate alerts")
        tests_failed += 1
        
except Exception as e:
    print_error("gold_security_alerts: Not found")
    print_info("Run Lab 03 (Detection Rules) to create Gold alerts table")
    print_info(f"Error: {str(e)[:100]}")
    tests_failed += 1

print(f"\nTest 5 Summary: {tests_passed} passed, {tests_failed} failed")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Test 6: Detection Rules

# COMMAND ----------

# DBTITLE 1,Test 6: Detection Rules
print("\n" + "=" * 80)
print("TEST 6: Detection Rules Registry")
print("=" * 80)

try:
    gold_rules_table = f"{CATALOG_NAME}.{SCHEMA_NAME}.gold_detection_rules"
    rule_count = spark.sql(f"SELECT COUNT(*) as cnt FROM {gold_rules_table}").collect()[0]['cnt']
    
    if rule_count > 0:
        print_success(f"gold_detection_rules: {rule_count} rules registered")
        tests_passed += 1
        
        # Show rule summary
        rules = spark.sql(f"""
            SELECT rule_name, rule_version, enabled, severity
            FROM {gold_rules_table}
            ORDER BY rule_name
        """).collect()
        
        print_info("Registered Detection Rules:")
        for rule in rules:
            status = "✓ Enabled" if rule['enabled'] else "✗ Disabled"
            print(f"    {rule['rule_name']:30s} {rule['rule_version']:5s} {status:12s} [{rule['severity']}]")
        
        # Check enabled rules
        enabled_count = spark.sql(f"""
            SELECT COUNT(*) as cnt 
            FROM {gold_rules_table} 
            WHERE enabled = TRUE
        """).collect()[0]['cnt']
        
        if enabled_count > 0:
            print_success(f"{enabled_count} rules enabled")
            tests_passed += 1
        else:
            print_warning("No rules are enabled")
            tests_failed += 1
    else:
        print_warning("gold_detection_rules: Table exists but has 0 rules")
        tests_failed += 1
        
except Exception as e:
    print_error("gold_detection_rules: Not found")
    print_info("Run Lab 03 (Detection Rules) to create rule registry")
    tests_failed += 1

print(f"\nTest 6 Summary: {tests_passed} passed, {tests_failed} failed")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Test 7: MITRE ATT&CK Coverage

# COMMAND ----------

# DBTITLE 1,Test 7: MITRE Coverage
print("\n" + "=" * 80)
print("TEST 7: MITRE ATT&CK Coverage")
print("=" * 80)

try:
    # Check MITRE coverage
    gold_alerts_table = f"{CATALOG_NAME}.{SCHEMA_NAME}.gold_security_alerts"
    mitre_coverage = spark.sql(f"""
        SELECT 
            mitre_tactic,
            COUNT(DISTINCT mitre_technique) as technique_count,
            COUNT(*) as alert_count
        FROM {gold_alerts_table}
        GROUP BY mitre_tactic
        ORDER BY alert_count DESC
    """).collect()
    
    if len(mitre_coverage) > 0:
        print_success(f"Covering {len(mitre_coverage)} MITRE ATT&CK tactics")
        tests_passed += 1
        
        print_info("MITRE ATT&CK Tactic Coverage:")
        for row in mitre_coverage:
            print(f"    {row['mitre_tactic']:25s}: {row['technique_count']:2d} techniques, {row['alert_count']:,} alerts")
        
        # Expected minimum coverage
        expected_tactics = ['Credential Access', 'Execution', 'Lateral Movement']
        covered_tactics = [row['mitre_tactic'] for row in mitre_coverage]
        
        missing_tactics = [t for t in expected_tactics if t not in covered_tactics]
        
        if not missing_tactics:
            print_success("All critical tactics covered")
            tests_passed += 1
        else:
            print_warning(f"Missing critical tactics: {', '.join(missing_tactics)}")
            tests_failed += 1
    else:
        print_warning("No MITRE ATT&CK coverage found")
        tests_failed += 1
        
except Exception as e:
    print_error("Could not check MITRE coverage")
    print_info(f"Error: {str(e)[:100]}")
    tests_failed += 1

print(f"\nTest 7 Summary: {tests_passed} passed, {tests_failed} failed")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Test 8: Data Quality Checks

# COMMAND ----------

# DBTITLE 1,Test 8: Data Quality
print("\n" + "=" * 80)
print("TEST 8: Data Quality Checks")
print("=" * 80)

try:
    # Check for NULL values in critical fields
    quality_checks = [
        ("gold_security_alerts", "alert_id", "Alert ID"),
        ("gold_security_alerts", "detection_time", "Detection Time"),
        ("gold_security_alerts", "severity", "Severity"),
        ("silver_sysmon_process", "event_time", "Event Time"),
        ("silver_okta_auth", "user_email", "User Email")
    ]
    
    for table, column, description in quality_checks:
        try:
            full_table_name = f"{CATALOG_NAME}.{SCHEMA_NAME}.{table}"
            null_count = spark.sql(f"""
                SELECT COUNT(*) as cnt 
                FROM {full_table_name} 
                WHERE {column} IS NULL
            """).collect()[0]['cnt']
            
            total_count = spark.sql(f"SELECT COUNT(*) as cnt FROM {full_table_name}").collect()[0]['cnt']
            
            if null_count == 0:
                print_success(f"{table}.{column}: No NULL values")
                tests_passed += 1
            else:
                pct = (null_count / total_count * 100) if total_count > 0 else 0
                if pct < 5:
                    print_warning(f"{table}.{column}: {null_count:,} NULL values ({pct:.1f}%)")
                    tests_passed += 1  # Still pass if < 5%
                else:
                    print_error(f"{table}.{column}: {null_count:,} NULL values ({pct:.1f}%)")
                    tests_failed += 1
        except:
            # Table might not exist, skip
            pass
            
except Exception as e:
    print_error("Could not run data quality checks")
    print_info(f"Error: {str(e)[:100]}")
    tests_failed += 1

print(f"\nTest 8 Summary: {tests_passed} passed, {tests_failed} failed")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Final Summary

# COMMAND ----------

# DBTITLE 1,Validation Summary
print("\n" + "=" * 80)
print("FINAL VALIDATION SUMMARY")
print("=" * 80)

total_tests = tests_passed + tests_failed
pass_rate = (tests_passed / total_tests * 100) if total_tests > 0 else 0

print(f"\nTotal Tests Run: {total_tests}")
print(f"Tests Passed:    {tests_passed} ({pass_rate:.1f}%)")
print(f"Tests Failed:    {tests_failed}")

if tests_failed == 0:
    print_success("\n🎉 ALL TESTS PASSED! Lab setup is complete and working correctly.")
    print("\n✅ Next Steps:")
    print("   1. Proceed to dashboard creation (see DASHBOARD_GUIDE.md)")
    print("   2. Schedule detection jobs for automated execution")
    print("   3. Customize detection rules for your environment")
elif pass_rate >= 80:
    print_warning("\n⚠️  Most tests passed, but some issues detected.")
    print("   Review failed tests above and fix issues.")
elif pass_rate >= 50:
    print_warning("\n⚠️  Partial completion detected.")
    print("   Complete remaining lab modules:")
    if tests_passed < 5:
        print("   → Run Lab 01 (Workspace Setup)")
    if tests_passed < 10:
        print("   → Run Lab 02 (Data Ingestion)")
    if tests_passed < 15:
        print("   → Run Lab 03 (Detection Rules)")
else:
    print_error("\n❌ Lab setup incomplete or has significant issues.")
    print("   Start from Lab 01 and work through each module.")

print("\n" + "=" * 80)

# Store results for external access
validation_results = {
    "timestamp": str(spark.sql("SELECT current_timestamp()").collect()[0][0]),
    "total_tests": total_tests,
    "tests_passed": tests_passed,
    "tests_failed": tests_failed,
    "pass_rate": pass_rate,
    "status": "PASS" if tests_failed == 0 else "FAIL"
}

print(f"\nValidation Status: {validation_results['status']}")
print(f"Timestamp: {validation_results['timestamp']}")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Troubleshooting Failed Tests
# MAGIC
# MAGIC ### If Test 1 Failed (Unity Catalog)
# MAGIC - Check permissions: You need CREATE CATALOG, CREATE SCHEMA, CREATE VOLUME
# MAGIC - Verify Unity Catalog is enabled in workspace
# MAGIC - Contact workspace admin for access
# MAGIC
# MAGIC ### If Test 2 Failed (Sample Data)
# MAGIC - Re-run Lab 01 notebook completely
# MAGIC - Check for errors in data generation cells
# MAGIC - Verify Faker library installed correctly
# MAGIC
# MAGIC ### If Test 3 Failed (Bronze Tables)
# MAGIC - Create and run DLT pipeline (Lab 02)
# MAGIC - Check DLT pipeline status in Workflows UI
# MAGIC - Review DLT error logs for specific issues
# MAGIC
# MAGIC ### If Test 4 Failed (Silver Tables)
# MAGIC - Ensure DLT pipeline completed successfully
# MAGIC - Check for transformation errors in DLT logs
# MAGIC - Verify source Bronze tables have data
# MAGIC
# MAGIC ### If Test 5/6 Failed (Gold Layer)
# MAGIC - Run Lab 03 notebook to create Gold tables
# MAGIC - Execute all detection rule queries
# MAGIC - Check for SQL syntax errors
# MAGIC
# MAGIC ### If Test 7/8 Failed (Coverage/Quality)
# MAGIC - Review detection logic in Lab 03
# MAGIC - Ensure malicious samples were generated in Lab 01
# MAGIC - Check for NULL handling in transformations
# MAGIC