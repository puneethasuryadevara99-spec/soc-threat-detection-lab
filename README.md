
# SOC Threat Detection & Authentication Monitoring Lab

A security operations lab that uses Python and Splunk Cloud to analyze synthetic authentication logs, identify suspicious login patterns, and document security investigations.

The project implements brute-force and password-spraying detection using Python and Splunk Search Processing Language (SPL). It also includes a SOC monitoring dashboard, automated tests, and incident investigation reports.

**Note:** All authentication events are synthetic. This project demonstrates security detection and investigation workflows, not monitoring of a production environment.

## Technologies

- Python 3 (standard library)
- Splunk Cloud Platform
- Splunk Search Processing Language (SPL)
- CSV authentication logs
- Python unittest
- MITRE ATT&CK

## Features

### Brute-Force Detection

Identifies five or more failed login attempts against the same username from the same source IP within a rolling 60-second window.

The synthetic scenario contains 12 failed login attempts against the admin account followed by one successful authentication.

### Password-Spraying Detection

Identifies failed login attempts against at least five distinct usernames from one source IP within a rolling 60-second window.

The synthetic scenario contains six failed attempts against six distinct accounts.

### Splunk SOC Dashboard

The dashboard includes:
- Total, failed, and successful authentication counts
- Failed authentication attempts by source IP
- Brute-force detection results
- Password-spraying detection results

**[View the SOC dashboard (Png)](screenshots/soc_dashboard.png)**

### Incident Investigations

Two simulated incident investigations document detection evidence, authentication patterns, relevant MITRE ATT&CK techniques, limitations, and recommended response actions.

- [Brute-force investigation](investigations/brute_force_incident.md)
- [Password-spraying investigation](investigations/password_spray_incident.md)

## Results

| Measurement | Result |
|---|---:|
| Synthetic authentication events | 24 |
| Failed authentications | 19 |
| Successful authentications | 5 |
| Brute-force scenarios detected | 1 |
| Password-spraying scenarios detected | 1 |
| Automated tests passed | 10 |

These results describe a small, controlled synthetic dataset and do not establish detection accuracy on operational authentication logs.

## Project Structure

```text
soc-threat-detection-lab/
├── data/
│   └── authentication_logs.csv
├── scripts/
│   ├── generate_logs.py
│   ├── detect_bruteforce.py
│   └── detect_password_spray.py
├── detections/
│   ├── brute_force.spl
│   └── password_spray.spl
├── tests/
│   ├── test_bruteforce.py
│   └── test_password_spray.py
├── investigations/
│   ├── brute_force_incident.md
│   └── password_spray_incident.md
├── screenshots/
├── .gitignore
└── README.md
```

## Running Locally

Clone the repository:

```bash
git clone https://github.com/puneethasuryadevara99-spec/soc-threat-detection-lab.git
cd soc-threat-detection-lab
```

Generate synthetic authentication logs:

```bash
python3 scripts/generate_logs.py
```

Run brute-force detection:

```bash
python3 scripts/detect_bruteforce.py
```

Run password-spraying detection:

```bash
python3 scripts/detect_password_spray.py
```

Run all automated tests:

```bash
python3 -m unittest discover -s tests -v
```

The Python implementation uses only standard-library modules.

## Splunk Setup

1. Access a Splunk environment with permission to ingest sample data.
2. Upload `data/authentication_logs.csv`.
3. Verify CSV field extraction and event timestamps.
4. Set the search time range to All time for the fixed synthetic timestamps.
5. Run the searches in `detections/` using Search & Reporting.
6. Recreate the dashboard panels using the queries described above.

The SPL examples reference `source="authentication_logs.csv"`. Adjust the source filter if your Splunk instance assigns another source value.

The password-spraying SPL example uses fixed one-minute buckets, while the Python implementation uses a rolling 60-second window. Their results agree for this dataset but can differ for events crossing minute boundaries.

## MITRE ATT&CK Mapping

| Detection | Technique |
|---|---|
| Brute-force/password guessing | T1110 / T1110.001 |
| Password spraying | T1110.003 |

References:
- https://attack.mitre.org/techniques/T1110/
- https://attack.mitre.org/techniques/T1110/001/
- https://attack.mitre.org/techniques/T1110/003/

## Limitations

- Authentication logs are synthetic and contain deliberately constructed attack patterns.
- Detection thresholds have not been validated on production traffic.
- Python detectors suppress repeated alerts for a source during one execution.
- The current rules do not detect distributed or sufficiently slow attacks.
- Fixed Splunk time buckets may miss patterns crossing minute boundaries.
- Authentication records alone cannot confirm account compromise.
- The dashboard depends on a Splunk environment, but saved queries, sample logs, reports, and documentation remain available in this repository.

## Future Improvements

- Add alert cooldowns and repeat-incident handling.
- Expand the dataset with realistic background activity and labeled scenarios.
- Test false-positive rates and detection precision against larger datasets.
- Improve SPL queries to match rolling-window detection semantics.
- Add correlation between failed and successful logins.
- Export a reusable Splunk dashboard definition.

## Project Purpose

This project was developed as a hands-on cybersecurity portfolio lab focused on security monitoring, detection engineering, SIEM analysis, automated testing, and incident investigation.
  