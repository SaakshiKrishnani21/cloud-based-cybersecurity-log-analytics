# Cloud-Based Cybersecurity Log Analytics

## Overview
A cloud-based cybersecurity log analysis project that processes OpenSSH authentication logs using Apache Hadoop MapReduce on an AWS EC2 Ubuntu instance. It aggregates authentication events by source IP address and classifies activity for further investigation.

## Objectives
- Analyze OpenSSH authentication logs.
- Aggregate failed-password attempts, invalid-user events, successful logins, and break-in warnings by IP address.
- Identify potentially suspicious authentication patterns using configurable rules.
- Store input logs and analysis output in Hadoop Distributed File System (HDFS).

## Technology Stack
- **Cloud:** AWS EC2
- **Operating System:** Ubuntu Server
- **Big Data Processing:** Apache Hadoop 3.4.2, MapReduce, YARN
- **Programming Language:** Java
- **Storage:** HDFS
- **Dataset:** OpenSSH logs from the LogHub project

## Architecture
OpenSSH Log Dataset → HDFS Input → Java MapReduce Mapper → Reducer → IP-Based Classification → HDFS Results

## Detection Rules
- **SUSPICIOUS:** Five or more failed-password events.
- **REVIEW:** At least one break-in warning or three or more invalid-user events, provided the suspicious threshold is not met.
- **MONITOR:** Events that do not meet either threshold.

These are heuristic classifications for investigation, not proof of malicious activity.

## Execution
```bash
# Check Hadoop
hadoop version

# List input files
hdfs dfs -ls /cybersecurity/input

# Run the analysis (output path must not already exist)
hadoop jar security-log-analyzer.jar SecurityLogAnalyzer \
  /cybersecurity/input/OpenSSH.log \
  /cybersecurity/output-analysis

# View the results
hdfs dfs -cat /cybersecurity/output-analysis/part-r-00000

# Copy results locally
hdfs dfs -get /cybersecurity/output-analysis/part-r-00000 \
  ~/cybersecurity-log-analytics/analysis-results.txt
```

## Verified Execution
- Input records processed: 2,000
- Mapper output records: 719
- Reducer output records: 25
- Map and reduce stages completed successfully.

These figures describe the current test run and should be updated if the dataset or implementation changes.

## Limitations and Future Improvements
- Add unit tests for log parsing and classification.
- Improve IP extraction and event parsing for varied log formats.
- Add timestamps and time-window-based detection.
- Visualize findings in a dashboard.
- Evaluate detection rules against labeled test data.

## Responsible Use
This project analyzes a sample dataset for educational purposes. A classification alone does not establish that a source IP is malicious.
