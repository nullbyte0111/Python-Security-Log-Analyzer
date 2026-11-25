# Security Incident Investigation Report

## Incident Information

- Incident ID: INC-001
- Analyst: Denis Bogdan
- Date: 25 November 2026
- Severity: HIGH
- Category: Suspected Brute Force
- Status: Requires Further Investigation
- Environment: Simulated SSH authentication logs

## Executive Summary

The Python Security Log Analyzer identified multiple
failed SSH authentication attempts followed by a successful
login to the root account on server01.

The activity originated from the same source IP address
and occurred within a 15-second interval.

This pattern is consistent with possible password
brute-force activity and potential account compromise.

## Affected Assets

- Hostname: server01
- Service: SSH
- Target account: root
- Source IP: 203.0.113.45

## Detection Method

The detection engine identified five failed authentication
attempts within a rolling 60-second window.

A subsequent successful authentication involving the same
source IP, username and hostname triggered a HIGH severity
alert.

## Event Timeline

| Time | Event |
|------|-------|
| 10:01:12 | Failed authentication |
| 10:01:15 | Failed authentication |
| 10:01:18 | Failed authentication |
| 10:01:21 | Failed authentication |
| 10:01:24 | Failed authentication - MEDIUM alert |
| 10:01:27 | Successful authentication - HIGH alert |

## Technical Analysis

Five failed authentication attempts were recorded within
12 seconds.

Three seconds after the final failed attempt, a successful
authentication was recorded for the root account.

The short interval between authentication attempts
suggests possible automated password guessing.

However, the available evidence does not confirm whether
the successful authentication was performed by an
unauthorized individual.

## MITRE ATT&CK Mapping

- Tactic: Credential Access (TA0006)
- Technique: Brute Force (T1110)
- Sub-technique: Password Guessing (T1110.001)

The successful authentication may also warrant investigation
for potential abuse of Valid Accounts (T1078).

These mappings represent suspected behavior, not confirmed
attacker activity.

## Indicators and Investigation Artifacts

- Source IP: 203.0.113.45
- Target username: root
- Destination hostname: server01
- Authentication service: SSH
- Failed authentication count: 5

The source IP belongs to a documentation-only address range
and is used exclusively for this simulated investigation.

## Recommended Investigation Actions

1. Verify whether the successful login was authorized.
2. Review historical authentication logs.
3. Examine active and recent SSH sessions.
4. Review commands and processes executed after login.
5. Check for unexpected account or configuration changes.
6. Escalate the alert if unauthorized activity is confirmed.

## Recommended Mitigation

- Disable direct SSH root login where appropriate.
- Prefer SSH key-based authentication.
- Implement authentication rate limiting.
- Restrict SSH access to authorized networks.
- Monitor repeated authentication failures.
- Rotate affected credentials if compromise is confirmed.

## Conclusion

The observed authentication pattern represents suspicious
activity that requires further investigation.

The detection engine correctly identified the configured
threshold and correlated the subsequent successful login.

Account compromise cannot be confirmed using authentication
logs alone.

## Disclaimer

This report is based on synthetic authentication logs
created for educational purposes. No real security incident
or compromised system is involved.