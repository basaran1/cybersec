# Security Dashboard Setup Guide

## Overview
This guide provides SQL queries and instructions for building security dashboards in Databricks to monitor your detection engineering platform.

## Dashboard Types

### 1. SOC Overview Dashboard (Executive Summary)
### 2. Detection Performance Dashboard (Engineering Metrics)
### 3. Threat Hunting Dashboard (Investigation)
### 4. Data Quality Dashboard (Pipeline Health)

---

## Dashboard 1: SOC Overview Dashboard

**Purpose:** Executive-level view of security posture  
**Refresh:** Every 5 minutes  
**Audience:** SOC Manager, CISO

### Widget 1.1: Alert Summary (Last 24 Hours)
```sql
SELECT
  COUNT(*) as total_alerts,
  SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
  SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
  SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
  SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low,
  COUNT(DISTINCT user) as affected_users,
  COUNT(DISTINCT host) as affected_hosts
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE detection_time >= current_timestamp() - INTERVAL 24 HOURS;
```
**Visualization:** Counter (multiple cards)

### Widget 1.2: Alerts by Severity Over Time
```sql
SELECT
  date_trunc('hour', detection_time) as hour,
  severity,
  COUNT(*) as alert_count
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE detection_time >= current_timestamp() - INTERVAL 7 DAYS
GROUP BY date_trunc('hour', detection_time), severity
ORDER BY hour DESC, severity;
```
**Visualization:** Stacked Area Chart
- X-axis: hour
- Y-axis: alert_count
- Group by: severity

### Widget 1.3: Top 10 Affected Users
```sql
SELECT
  user,
  COUNT(*) as alert_count,
  MAX(severity) as max_severity,
  COUNT(DISTINCT detection_rule) as unique_detections,
  MAX(detection_time) as last_alert
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE 
  detection_time >= current_timestamp() - INTERVAL 7 DAYS
  AND user IS NOT NULL
GROUP BY user
ORDER BY alert_count DESC
LIMIT 10;
```
**Visualization:** Table

### Widget 1.4: Top 10 Affected Hosts
```sql
SELECT
  host,
  COUNT(*) as alert_count,
  MAX(severity) as max_severity,
  COUNT(DISTINCT user) as unique_users,
  MAX(detection_time) as last_alert
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE 
  detection_time >= current_timestamp() - INTERVAL 7 DAYS
  AND host IS NOT NULL
GROUP BY host
ORDER BY alert_count DESC
LIMIT 10;
```
**Visualization:** Bar Chart

### Widget 1.5: MITRE ATT&CK Technique Coverage
```sql
SELECT
  mitre_tactic,
  mitre_technique,
  COUNT(*) as detection_count,
  MAX(severity) as max_severity
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE detection_time >= current_timestamp() - INTERVAL 30 DAYS
GROUP BY mitre_tactic, mitre_technique
ORDER BY detection_count DESC;
```
**Visualization:** Treemap
- Group by: mitre_tactic
- Color by: max_severity

### Widget 1.6: Alert Status Distribution
```sql
SELECT
  status,
  COUNT(*) as count,
  ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE detection_time >= current_timestamp() - INTERVAL 7 DAYS
GROUP BY status
ORDER BY count DESC;
```
**Visualization:** Pie Chart

### Widget 1.7: Mean Time to Detect (MTTD)
```sql
WITH detection_times AS (
  SELECT
    alert_id,
    event_time,
    detection_time,
    (unix_timestamp(detection_time) - unix_timestamp(event_time)) / 60 as minutes_to_detect
  FROM security_detection_lab.security_logs.gold_security_alerts
  WHERE 
    detection_time >= current_timestamp() - INTERVAL 7 DAYS
    AND event_time IS NOT NULL
)
SELECT
  ROUND(AVG(minutes_to_detect), 2) as avg_mttd_minutes,
  ROUND(MIN(minutes_to_detect), 2) as min_mttd_minutes,
  ROUND(MAX(minutes_to_detect), 2) as max_mttd_minutes,
  ROUND(PERCENTILE(minutes_to_detect, 0.5), 2) as median_mttd_minutes
FROM detection_times
WHERE minutes_to_detect >= 0 AND minutes_to_detect <= 1440; -- Filter outliers
```
**Visualization:** Counter

---

## Dashboard 2: Detection Performance Dashboard

**Purpose:** Monitor detection rule effectiveness  
**Refresh:** Every 15 minutes  
**Audience:** Detection Engineers, Threat Hunters

### Widget 2.1: Detection Rule Performance
```sql
SELECT
  r.rule_name,
  r.rule_version,
  r.enabled,
  COUNT(a.alert_id) as total_alerts,
  SUM(CASE WHEN a.status = 'TRUE_POSITIVE' THEN 1 ELSE 0 END) as true_positives,
  SUM(CASE WHEN a.status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) as false_positives,
  ROUND(
    SUM(CASE WHEN a.status = 'TRUE_POSITIVE' THEN 1 ELSE 0 END) * 100.0 / 
    NULLIF(SUM(CASE WHEN a.status IN ('TRUE_POSITIVE', 'FALSE_POSITIVE') THEN 1 ELSE 0 END), 0),
    2
  ) as true_positive_rate,
  r.false_positive_rate as expected_fpr,
  MAX(a.detection_time) as last_triggered
FROM security_detection_lab.security_logs.gold_detection_rules r
LEFT JOIN security_detection_lab.security_logs.gold_security_alerts a
  ON r.rule_id = a.detection_rule
  AND a.detection_time >= current_timestamp() - INTERVAL 30 DAYS
GROUP BY r.rule_name, r.rule_version, r.enabled, r.false_positive_rate
ORDER BY total_alerts DESC;
```
**Visualization:** Table

### Widget 2.2: Alert Volume Trend by Rule
```sql
SELECT
  date_trunc('day', detection_time) as day,
  detection_rule,
  COUNT(*) as alert_count
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE detection_time >= current_timestamp() - INTERVAL 30 DAYS
GROUP BY date_trunc('day', detection_time), detection_rule
ORDER BY day DESC, alert_count DESC;
```
**Visualization:** Line Chart
- X-axis: day
- Y-axis: alert_count
- Group by: detection_rule

### Widget 2.3: True Positive vs False Positive Rate
```sql
SELECT
  detection_rule,
  SUM(CASE WHEN status = 'TRUE_POSITIVE' THEN 1 ELSE 0 END) as true_positives,
  SUM(CASE WHEN status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) as false_positives,
  ROUND(
    SUM(CASE WHEN status = 'TRUE_POSITIVE' THEN 1 ELSE 0 END) * 100.0 / 
    NULLIF(COUNT(*), 0),
    2
  ) as tp_rate,
  ROUND(
    SUM(CASE WHEN status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) * 100.0 / 
    NULLIF(COUNT(*), 0),
    2
  ) as fp_rate
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE 
  detection_time >= current_timestamp() - INTERVAL 30 DAYS
  AND status IN ('TRUE_POSITIVE', 'FALSE_POSITIVE')
GROUP BY detection_rule
ORDER BY tp_rate DESC;
```
**Visualization:** Bar Chart (Grouped)

### Widget 2.4: Detection Coverage by MITRE Tactic
```sql
SELECT
  mitre_tactic,
  COUNT(DISTINCT mitre_technique) as unique_techniques,
  COUNT(DISTINCT detection_rule) as detection_rules,
  SUM(CASE WHEN status = 'TRUE_POSITIVE' THEN 1 ELSE 0 END) as confirmed_threats
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE detection_time >= current_timestamp() - INTERVAL 30 DAYS
GROUP BY mitre_tactic
ORDER BY confirmed_threats DESC;
```
**Visualization:** Table

### Widget 2.5: Alerts Per Hour Heatmap
```sql
SELECT
  DAYOFWEEK(detection_time) as day_of_week,
  HOUR(detection_time) as hour_of_day,
  COUNT(*) as alert_count
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE detection_time >= current_timestamp() - INTERVAL 30 DAYS
GROUP BY DAYOFWEEK(detection_time), HOUR(detection_time)
ORDER BY day_of_week, hour_of_day;
```
**Visualization:** Heatmap
- X-axis: hour_of_day
- Y-axis: day_of_week
- Color intensity: alert_count

---

## Dashboard 3: Threat Hunting Dashboard

**Purpose:** Interactive investigation and threat hunting  
**Refresh:** On-demand  
**Audience:** Threat Hunters, Incident Responders

### Widget 3.1: Recent High-Severity Alerts
```sql
SELECT
  alert_id,
  detection_time,
  alert_title,
  severity,
  user,
  host,
  source_ip,
  mitre_technique,
  status,
  assigned_to
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE severity IN ('CRITICAL', 'HIGH')
ORDER BY detection_time DESC
LIMIT 50;
```
**Visualization:** Table (with drill-down)

### Widget 3.2: Suspicious Processes Timeline
```sql
SELECT
  event_time,
  host,
  user,
  process_name,
  command_line,
  parent_process_name,
  threat_indicator
FROM security_detection_lab.security_logs.silver_sysmon_process
WHERE 
  threat_indicator != 'normal'
  AND event_time >= current_timestamp() - INTERVAL 7 DAYS
ORDER BY event_time DESC
LIMIT 100;
```
**Visualization:** Timeline / Table

### Widget 3.3: Failed Authentication Attempts
```sql
SELECT
  event_time,
  user_email,
  source_ip,
  country,
  city,
  outcome,
  failure_reason,
  target_application
FROM security_detection_lab.security_logs.silver_okta_auth
WHERE 
  outcome = 'FAILURE'
  AND event_time >= current_timestamp() - INTERVAL 24 HOURS
ORDER BY event_time DESC
LIMIT 100;
```
**Visualization:** Table

### Widget 3.4: Network Connection Analysis
```sql
SELECT
  event_time,
  host,
  process_name,
  user,
  destination_ip,
  destination_port,
  port_classification,
  COUNT(*) as connection_count
FROM security_detection_lab.security_logs.silver_sysmon_network
WHERE event_time >= current_timestamp() - INTERVAL 24 HOURS
GROUP BY event_time, host, process_name, user, destination_ip, destination_port, port_classification
ORDER BY connection_count DESC
LIMIT 100;
```
**Visualization:** Table

### Widget 3.5: AWS High-Risk Actions
```sql
SELECT
  event_time,
  event_name,
  user_name,
  source_ip,
  service,
  region,
  risk_classification,
  api_success,
  error_code
FROM security_detection_lab.security_logs.silver_cloudtrail
WHERE 
  risk_classification = 'high_risk_action'
  AND event_time >= current_timestamp() - INTERVAL 7 DAYS
ORDER BY event_time DESC
LIMIT 100;
```
**Visualization:** Table

### Widget 3.6: User Activity Summary (for specific user - parameter)
```sql
-- Add parameter: user_email
SELECT
  log_source,
  event_category,
  COUNT(*) as event_count,
  MIN(event_time) as first_seen,
  MAX(event_time) as last_seen,
  COUNT(DISTINCT CASE WHEN log_source = 'okta' THEN source_ip END) as unique_ips
FROM (
  SELECT 
    'sysmon' as log_source,
    event_category,
    event_time,
    user,
    NULL as source_ip
  FROM security_detection_lab.security_logs.silver_sysmon_process
  WHERE user = '{{user_email}}'
  
  UNION ALL
  
  SELECT
    'okta' as log_source,
    event_category,
    event_time,
    user_email as user,
    source_ip
  FROM security_detection_lab.security_logs.silver_okta_auth
  WHERE user_email = '{{user_email}}'
  
  UNION ALL
  
  SELECT
    'windows' as log_source,
    event_category,
    event_time,
    user_name as user,
    source_ip
  FROM security_detection_lab.security_logs.silver_windows_auth
  WHERE user_name = '{{user_email}}'
) combined
GROUP BY log_source, event_category
ORDER BY event_count DESC;
```
**Visualization:** Table (with parameter dropdown)

---

## Dashboard 4: Data Quality Dashboard

**Purpose:** Monitor ingestion pipeline health  
**Refresh:** Every 5 minutes  
**Audience:** Platform Engineers, Detection Engineers

### Widget 4.1: Ingestion Volume by Source
```sql
SELECT
  log_source,
  COUNT(*) as event_count,
  MIN(processed_timestamp) as first_processed,
  MAX(processed_timestamp) as last_processed,
  ROUND((unix_timestamp(MAX(processed_timestamp)) - unix_timestamp(MIN(processed_timestamp))) / 3600, 2) as hours_span
FROM (
  SELECT log_source, processed_timestamp FROM security_detection_lab.security_logs.silver_sysmon_process
  WHERE processed_timestamp >= current_timestamp() - INTERVAL 24 HOURS
  
  UNION ALL
  
  SELECT log_source, processed_timestamp FROM security_detection_lab.security_logs.silver_okta_auth
  WHERE processed_timestamp >= current_timestamp() - INTERVAL 24 HOURS
  
  UNION ALL
  
  SELECT log_source, processed_timestamp FROM security_detection_lab.security_logs.silver_windows_auth
  WHERE processed_timestamp >= current_timestamp() - INTERVAL 24 HOURS
  
  UNION ALL
  
  SELECT log_source, processed_timestamp FROM security_detection_lab.security_logs.silver_cloudtrail
  WHERE processed_timestamp >= current_timestamp() - INTERVAL 24 HOURS
) all_logs
GROUP BY log_source
ORDER BY event_count DESC;
```
**Visualization:** Bar Chart

### Widget 4.2: Ingestion Lag (Event Time vs Processing Time)
```sql
SELECT
  log_source,
  ROUND(AVG((unix_timestamp(processed_timestamp) - unix_timestamp(event_time)) / 60), 2) as avg_lag_minutes,
  ROUND(MAX((unix_timestamp(processed_timestamp) - unix_timestamp(event_time)) / 60), 2) as max_lag_minutes,
  COUNT(*) as sample_count
FROM (
  SELECT 
    log_source, 
    event_time, 
    processed_timestamp 
  FROM security_detection_lab.security_logs.silver_sysmon_process
  WHERE 
    processed_timestamp >= current_timestamp() - INTERVAL 1 HOUR
    AND event_time IS NOT NULL
  
  UNION ALL
  
  SELECT 
    log_source, 
    event_time, 
    processed_timestamp 
  FROM security_detection_lab.security_logs.silver_okta_auth
  WHERE 
    processed_timestamp >= current_timestamp() - INTERVAL 1 HOUR
    AND event_time IS NOT NULL
) recent_logs
GROUP BY log_source
ORDER BY avg_lag_minutes DESC;
```
**Visualization:** Table

### Widget 4.3: Events Per Hour Trend
```sql
SELECT
  date_trunc('hour', processed_timestamp) as hour,
  log_source,
  COUNT(*) as event_count
FROM (
  SELECT log_source, processed_timestamp FROM security_detection_lab.security_logs.silver_sysmon_process
  WHERE processed_timestamp >= current_timestamp() - INTERVAL 7 DAYS
  
  UNION ALL
  
  SELECT log_source, processed_timestamp FROM security_detection_lab.security_logs.silver_okta_auth
  WHERE processed_timestamp >= current_timestamp() - INTERVAL 7 DAYS
  
  UNION ALL
  
  SELECT log_source, processed_timestamp FROM security_detection_lab.security_logs.silver_windows_auth
  WHERE processed_timestamp >= current_timestamp() - INTERVAL 7 DAYS
  
  UNION ALL
  
  SELECT log_source, processed_timestamp FROM security_detection_lab.security_logs.silver_cloudtrail
  WHERE processed_timestamp >= current_timestamp() - INTERVAL 7 DAYS
) all_logs
GROUP BY date_trunc('hour', processed_timestamp), log_source
ORDER BY hour DESC, log_source;
```
**Visualization:** Line Chart
- X-axis: hour
- Y-axis: event_count
- Group by: log_source

### Widget 4.4: Data Quality Metrics
```sql
SELECT
  log_source,
  COUNT(*) as total_events,
  SUM(CASE WHEN event_time IS NULL THEN 1 ELSE 0 END) as missing_timestamp,
  SUM(CASE WHEN user IS NULL THEN 1 ELSE 0 END) as missing_user,
  ROUND(SUM(CASE WHEN event_time IS NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as pct_missing_timestamp
FROM (
  SELECT log_source, event_time, user FROM security_detection_lab.security_logs.silver_sysmon_process
  WHERE processed_timestamp >= current_timestamp() - INTERVAL 24 HOURS
  
  UNION ALL
  
  SELECT log_source, event_time, user_email as user FROM security_detection_lab.security_logs.silver_okta_auth
  WHERE processed_timestamp >= current_timestamp() - INTERVAL 24 HOURS
  
  UNION ALL
  
  SELECT log_source, event_time, user_name as user FROM security_detection_lab.security_logs.silver_windows_auth
  WHERE processed_timestamp >= current_timestamp() - INTERVAL 24 HOURS
  
  UNION ALL
  
  SELECT log_source, event_time, user_name as user FROM security_detection_lab.security_logs.silver_cloudtrail
  WHERE processed_timestamp >= current_timestamp() - INTERVAL 24 HOURS
) all_logs
GROUP BY log_source
ORDER BY pct_missing_timestamp DESC;
```
**Visualization:** Table

---

## Dashboard Creation Instructions

### Using Databricks SQL Dashboards:

1. **Navigate to SQL Dashboards:**
   - Click **SQL** in left sidebar
   - Click **Dashboards**
   - Click **Create Dashboard**

2. **Add Widgets:**
   - Click **Add** → **Visualization**
   - Paste SQL query from above
   - Configure visualization type
   - Set title and description
   - Click **Save**

3. **Configure Parameters:**
   - For queries with `{{parameter}}`, add dashboard parameter
   - Click **Add** → **Parameter**
   - Set parameter name, type, and default value

4. **Set Refresh Schedule:**
   - Click dashboard settings (⚙️)
   - Configure auto-refresh interval
   - Set notification preferences

5. **Share Dashboard:**
   - Click **Share**
   - Set permissions (viewers, editors)
   - Get shareable link

### Dashboard Layout Recommendations:

**SOC Overview:**
```
┌─────────────────────────────────────────┐
│  Alert Summary Cards (1.1)              │
├──────────────┬──────────────────────────┤
│ Severity     │  MITRE Coverage (1.5)    │
│ Over Time    │                          │
│ (1.2)        │                          │
├──────────────┼──────────────────────────┤
│ Top Users    │  Status Dist (1.6)       │
│ (1.3)        │  MTTD (1.7)              │
├──────────────┴──────────────────────────┤
│  Top Hosts (1.4)                        │
└─────────────────────────────────────────┘
```

**Detection Performance:**
```
┌─────────────────────────────────────────┐
│  Rule Performance Table (2.1)           │
├──────────────┬──────────────────────────┤
│ Alert Volume │  TP vs FP Rate (2.3)     │
│ Trend (2.2)  │                          │
├──────────────┼──────────────────────────┤
│ MITRE        │  Alert Heatmap (2.5)     │
│ Coverage     │                          │
│ (2.4)        │                          │
└──────────────┴──────────────────────────┘
```

---

## Best Practices

1. **Color Coding:**
   - CRITICAL: Red (#DC143C)
   - HIGH: Orange (#FF8C00)
   - MEDIUM: Yellow (#FFD700)
   - LOW: Blue (#4682B4)

2. **Refresh Rates:**
   - Executive dashboards: 5-15 minutes
   - Operational dashboards: 1-5 minutes
   - Investigation dashboards: On-demand

3. **Alert Thresholds:**
   - Set alert conditions for anomalies
   - Configure notifications to stakeholders
   - Document escalation procedures

4. **Performance Optimization:**
   - Use materialized views for complex queries
   - Partition tables by date
   - Cache frequently accessed data
   - Limit time ranges to necessary windows

5. **Access Control:**
   - Restrict sensitive data (PII, credentials)
   - Use row-level security for multi-tenancy
   - Audit dashboard access

---

## Advanced Visualizations

### Sankey Diagram: Alert Flow
```sql
-- Shows flow from detection → status → assignment
SELECT
  detection_rule as source,
  status as target,
  COUNT(*) as value
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE detection_time >= current_timestamp() - INTERVAL 7 DAYS
GROUP BY detection_rule, status

UNION ALL

SELECT
  status as source,
  COALESCE(assigned_to, 'Unassigned') as target,
  COUNT(*) as value
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE detection_time >= current_timestamp() - INTERVAL 7 DAYS
GROUP BY status, assigned_to;
```

### Geo Map: Source IP Locations (requires IP geolocation enrichment)
```sql
-- Placeholder - requires IP geolocation library
SELECT
  source_ip,
  COUNT(*) as alert_count,
  MAX(severity) as max_severity
  -- Add: latitude, longitude from IP geolocation
FROM security_detection_lab.security_logs.gold_security_alerts
WHERE 
  source_ip IS NOT NULL
  AND detection_time >= current_timestamp() - INTERVAL 7 DAYS
GROUP BY source_ip
ORDER BY alert_count DESC;
```

---

## Export and Integration

### Export Dashboard as PDF (Scheduled)
- Use Databricks API to schedule PDF exports
- Email to stakeholders daily/weekly
- Archive for compliance

### Embed in External Tools
- Use Databricks embedding API
- Integrate with confluence, SharePoint
- Display on SOC screens (NOC view)

---

## Troubleshooting

**Dashboard loads slowly:**
- Reduce time range
- Add WHERE filters
- Use aggregated tables
- Enable query result caching

**Data not updating:**
- Check DLT pipeline status
- Verify scheduled job execution
- Review ingestion lag metrics

**Incorrect counts:**
- Check for duplicate records
- Verify partitioning strategy
- Review join logic

---

## Additional Resources

- [Databricks SQL Dashboards Documentation](https://docs.databricks.com/sql/user/dashboards/index.html)
- [Visualization Best Practices](https://docs.databricks.com/sql/user/visualizations/index.html)
- [Dashboard Permissions](https://docs.databricks.com/security/access-control/dashboard-acls.html)

