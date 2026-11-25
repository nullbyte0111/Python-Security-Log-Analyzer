# Python Security Log Analyzer

A Python-based security monitoring tool that analyzes SSH authentication logs, detects suspicious login activity and generates structured security alerts.

I developed this project to gain practical experience in log analysis, threat detection, event correlation and Security Operations Center (SOC) workflows.

## Features

- SSH authentication log parsing using regular expressions.
- Detection of repeated failed authentication attempts.
- Rolling 60-second detection window.
- Event correlation by source IP, username and destination hostname.
- Detection of successful authentication after repeated failures.
- Security alert severity classification.
- Color-coded console output.
- Automatic JSON and CSV alert export.
- Documented security incident investigation.
- No external Python dependencies.

## Detection Rules

| Detection Rule | Condition | Severity |
|----------------|-----------|----------|
| Possible Brute Force | 5 failed authentication attempts within 60 seconds | MEDIUM |
| Potential Account Compromise | Successful authentication following at least 5 failed attempts within 60 seconds | HIGH |

Authentication events are correlated using the source IP address, username and destination hostname.

These alerts identify suspicious activity that requires further investigation. They do not automatically confirm an attack or account compromise.

## How It Works

1. Read SSH authentication logs from the input file.
2. Extract relevant information using regular expressions.
3. Convert raw log entries into structured events.
4. Group authentication attempts by IP address, username and hostname.
5. Analyze authentication activity within a rolling time window.
6. Detect suspicious authentication patterns.
7. Generate and classify security alerts.
8. Display color-coded alerts in the console.
9. Export the results to JSON and CSV files.

## Project Structure

    Python-Security-Log-Analyzer/
    ├── analyzer.py
    ├── logs/
    │   └── auth.log
    ├── output/
    │   ├── alerts.json
    │   └── alerts.csv
    ├── reports/
    │   └── incident_report_001.md
    └── README.md

### Directory Overview

- `analyzer.py` - Main log parsing and detection engine.
- `logs/` - Synthetic SSH authentication logs.
- `output/` - Automatically generated security alerts.
- `reports/` - Security incident investigation documentation.
- `README.md` - Project documentation.

## Technologies Used

- Python 3
- Regular Expressions (Regex)
- Datetime and Timedelta
- Collections (defaultdict and deque)
- Pathlib
- JSON
- CSV
- ANSI Escape Codes
- Linux SSH Authentication Logs

## Installation and Usage

### Requirements

- Python 3 installed.
- A terminal supporting ANSI colors for colored output.

No external Python packages are required.

### Clone the Repository

    git clone <https://github.com/nullbyte0111/Python-Security-Log-Analyzer>
    cd Python-Security-Log-Analyzer

### Run the Analyzer

    python analyzer.py

The program reads `logs/auth.log`, analyzes authentication events and displays detected security alerts in the console.

The generated alerts are automatically saved to:

- `output/alerts.json`
- `output/alerts.csv`

Existing output files are overwritten on each execution.

## Sample Results

The included synthetic dataset contains 15 authentication events.

| Metric | Result |
|--------|--------|
| Authentication events analyzed | 15 |
| Security alerts generated | 3 |
| Medium severity alerts | 2 |
| High severity alerts | 1 |

### Example Security Alert

    [HIGH SECURITY ALERT]
    ------------------------------------------------------------
    Timestamp       : 2026-11-25 10:01:27
    Source IP       : 203.0.113.45
    Username        : root
    Hostname        : server01
    Failed Attempts : 5
    Time Window     : 60
    Description     : Successful login after repeated failures
    ------------------------------------------------------------

### Console Color Classification

- Red - High severity security alerts.
- Yellow - Medium severity security alerts.
- Green - Informational messages.
- Cyan - Application header.

## MITRE ATT&CK Framework

The simulated incident investigation report references the following MITRE ATT&CK techniques:

| Technique ID  | Technique         |
|-------------- |-----------        |
| T1110         | Brute Force       |
| T1110.001     | Password Guessing |
| T1078         | Valid Accounts    |

The observed authentication patterns are consistent with possible password guessing activity.

The successful authentication may warrant further investigation for potential abuse of valid accounts.

These mappings describe suspected behavior rather than confirmed malicious activity.

Reference: https://attack.mitre.org/

## Incident Investigation

The project includes a simulated security incident investigation report based on the generated alerts.

The report covers:

- Incident identification and severity classification.
- Executive summary.
- Affected assets.
- Authentication event timeline.
- Technical analysis.
- MITRE ATT&CK mapping.
- Investigation artifacts.
- Recommended investigation actions.
- Recommended mitigation measures.
- Final conclusions.

Full report: [Security Incident Investigation Report](reports/incident_report_001.md)

## Skills Demonstrated

- Python programming and scripting.
- Security log analysis.
- Regular expression parsing.
- Event correlation.
- Time-based detection rules.
- Suspicious authentication detection.
- Security alert classification.
- Structured data processing.
- Security incident documentation.
- MITRE ATT&CK fundamentals.
- Analytical thinking and problem-solving.

## Limitations

- Supports a specific SSH password authentication log format.
- Assumes chronologically ordered log entries.
- Assumes log timestamps belong to 2026.
- Uses a fixed detection threshold and time window.
- Does not detect distributed brute-force attacks or password spraying across multiple usernames.
- Does not perform real-time log monitoring.
- Does not automatically confirm account compromise.
- Detection rules may produce false positives.

This project is an educational security monitoring tool and is not intended to replace a production SIEM solution.

## Disclaimer

All authentication logs included in this repository are synthetic and were created for educational purposes.

The public-looking IP addresses belong to documentation-only address ranges. No real credentials, confidential information or compromised systems are involved.

## Author

**Denis Bogdan**

Cyber Security Engineering Student  
Tallinn University of Technology (TalTech)  
Tallinn, Estonia

LinkedIn: https://www.linkedin.com/in/denisbogdan7/
