# SOC Investigation Report — Suspicious Administrator Authentication

**Case ID:** SOC-LAB-001  
**Investigation Date:** October 26, 2026  
**Environment:** Splunk Cloud Platform  
**Data Source:** Synthetic authentication logs  
**Status:** Investigation documented — simulated incident  
**Priority:** High (simulated)

## 1. Executive Summary

A detection rule identified repeated failed authentication attempts against the `admin` account from source IP `198.51.100.25`.

Analysis of authentication records in Splunk revealed 12 consecutive failed attempts followed by one successful login from the same source IP.

The observed sequence is consistent with potential brute-force activity followed by successful authentication. However, the logs are synthetic, and no actual account compromise occurred.

## 2. Alert Details

| Field | Value |
|---|---|
| Detection | Possible Brute Force |
| Target Account | admin |
| Source IP | 198.51.100.25 |
| First Failed Attempt | 2026-10-26 09:00:50 UTC |
| Alert Triggered | 2026-10-26 09:01:30 UTC |
| Last Failed Attempt | 2026-10-26 09:02:40 UTC |
| Successful Authentication | 2026-10-26 09:02:50 UTC |
| Failed Attempts | 12 |
| Successful Attempts | 1 |

## 3. Detection Methodology

The Python and Splunk detection rules identify five or more failed authentication attempts from the same source IP against the same username within a rolling 60-second window.

The initial alert was triggered at 09:01:30 UTC.

The Splunk investigation subsequently identified additional failed attempts and a successful login associated with the same account and source IP.

## 4. Investigation Findings

- All 13 authentication events originated from `198.51.100.25`.
- Twelve consecutive authentication failures occurred against the `admin` account.
- The final authentication attempt succeeded.
- No additional device, endpoint, MFA, or post-authentication activity logs were available.
- The successful authentication cannot independently establish malicious account access.

## 5. MITRE ATT&CK Mapping

**Tactic:** Credential Access (TA0006)

**Technique:** Brute Force (T1110)

**Relevant Sub-technique:** Password Guessing (T1110.001)

The observed repeated authentication failures are consistent with password-guessing behavior, although the available records do not reveal the specific passwords attempted.

## 6. Recommended Response

For an equivalent event in a real environment:

1. Verify whether the authentication activity was authorized.
2. Review MFA events and account-access history.
3. Investigate endpoint and session activity following the successful login.
4. Assess whether the source IP is associated with other suspicious activity.
5. If unauthorized access is confirmed or strongly suspected, follow the organization's incident response process, including session revocation, credential reset, and containment where appropriate.

## 7. Limitations

This investigation uses artificially generated authentication records, not production security telemetry.

The source IP is a reserved documentation address and does not identify a real attacker.

The available dataset does not include geolocation, device identifiers, MFA results, process execution, or session activity.

Consequently, the investigation demonstrates detection and triage methodology rather than proof of actual compromise.

## 8. Conclusion

The lab successfully demonstrated detection and investigation of repeated authentication failures followed by a successful login.

Python-based detection and Splunk SPL produced consistent results for the simulated brute-force scenario. The investigation highlights the importance of correlating authentication outcomes and preserving supporting evidence before reaching a security conclusion.
