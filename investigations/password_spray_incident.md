# SOC Investigation Report — Suspected Password Spraying

**Case ID:** SOC-LAB-002  
**Investigation Date:** October 26, 2026  
**Environment:** Splunk Cloud Platform  
**Data Source:** Synthetic authentication logs  
**Status:** Investigation documented — simulated incident  
**Priority:** Medium (simulated)

## 1. Executive Summary

A detection rule identified six failed authentication attempts against six distinct user accounts originating from source IP `203.0.113.50` within 50 seconds.

The activity was flagged as possible password spraying because a single source attempted authentication across multiple accounts in a short period.

No successful authentications from this source were present in the generated scenario. The available events do not establish whether identical passwords were attempted.

## 2. Alert Details

| Field | Value |
|---|---|
| Detection | Possible Password Spray |
| Source IP | 203.0.113.50 |
| First Attempt | 2026-10-26 09:03:00 UTC |
| Threshold Reached | 2026-10-26 09:03:40 UTC |
| Last Attempt | 2026-10-26 09:03:50 UTC |
| Failed Attempts | 6 |
| Distinct Accounts | 6 |
| Successful Attempts from Source | 0 |

**Targeted accounts:** alice, bob, charlie, david, emma, frank.

## 3. Detection Methodology

Two detection approaches were implemented.

**Python detection:** A rolling 60-second window tracks failed authentication events by source IP and counts distinct usernames. An alert is generated when five unique accounts are targeted within the window.

**Splunk detection:** SPL groups failed authentication events into fixed one-minute buckets using `bin _time span=1m`. The `dc(username)` function counts distinct accounts for each source IP and time bucket.

Both approaches identified the same suspicious source in the synthetic dataset. However, fixed time buckets and rolling windows are not equivalent for all possible event sequences.

## 4. Investigation Findings

- Six distinct accounts experienced failed authentication attempts from the same source IP.
- Each account received one failed attempt from that source.
- All six events occurred within 50 seconds.
- The Python rule reached its threshold at 09:03:40 UTC.
- The Splunk query identified the corresponding 09:03:00–09:03:59 UTC time bucket.
- No successful login from the suspicious source was present in the generated dataset.

## 5. MITRE ATT&CK Mapping

**Tactic:** Credential Access (TA0006)

**Technique:** Brute Force (T1110)

**Relevant Sub-technique:** Password Spraying (T1110.003)

**Reference:** https://attack.mitre.org/techniques/T1110/003/

This pattern is consistent with possible password spraying. However, the authentication records do not include attempted password values, so password reuse across accounts cannot be verified.

## 6. Recommended Investigation and Response

For comparable activity in a production environment:

1. Review authentication activity from the source IP over a longer time period.
2. Identify all targeted accounts and determine whether any later authentication succeeded.
3. Correlate available identity-provider, MFA, device, and network telemetry.
4. Investigate whether similar attempts originated from additional IP addresses.
5. Assess account risk and apply appropriate protections, including MFA and conditional access.
6. Escalate confirmed or strongly suspected malicious activity through the organization's incident response process.

## 7. Limitations

The investigation uses synthetic authentication logs rather than production security data.

The source IP is reserved for documentation and does not represent a real attacker.

The dataset does not contain password values, identity-provider context, MFA outcomes, device information, or post-login activity.

The detection threshold of five unique accounts within 60 seconds is a lab configuration rather than a production-validated threshold.

Slow or distributed password spraying may evade this detection approach.

## 8. Conclusion

The lab successfully demonstrated how authentication failures across multiple accounts can be correlated to identify possible password-spraying behavior.

Python and Splunk detection methods identified the same suspicious source in the controlled test scenario.

The investigation demonstrates log analysis, distinct-account aggregation, detection validation, and evidence-based security triage.
