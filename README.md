
# AuthSentinel

**A Python-based authentication attack detection and validation toolkit for Linux SSH and Windows Security Event logs.**

AuthSentinel analyzes failed authentication events to detect potential brute-force attacks and password spraying using configurable, time-based detection rules. It generates investigation-focused alerts and exports findings to JSON.

## Overview

I built AuthSentinel to gain more hands-on experience with security monitoring, log analysis, and detection engineering.

The project focuses on two common authentication attacks:

- **Brute force:** Repeated failed login attempts targeting the same account.
- **Password spraying:** Failed login attempts targeting multiple accounts from the same source.

The tool reads authentication logs, extracts failed login events, and applies time-based detection rules to identify suspicious patterns. It then generates alerts containing information useful during a security investigation.

I wanted to go beyond simply counting failed logins, so I included configurable detection thresholds, JSON reporting, and automated tests to check that the detection logic works as expected.

I also evaluated the tool against a large external SSH dataset to understand how it behaves beyond synthetic and lab-generated examples.

## Features

- Parses Linux SSH authentication logs.
- Processes Windows Security Event ID 4625 records exported to CSV.
- Detects potential brute-force attacks and password spraying.
- Supports configurable detection thresholds and time windows.
- Groups authentication events by source IP address and affected accounts.
- Generates alerts containing timestamps and recommended investigation actions.
- Exports detection results to JSON.
- Expands repeated SSH authentication failure messages.
- Supports historical Linux syslog timestamps using an optional starting year.
- Automatically handles December-to-January year rollover.
- Skips malformed log entries without stopping the analysis.
- Includes 18 automated unit tests.

## How It Works

AuthSentinel supports two input formats:

**Linux:** SSH authentication logs containing failed password attempts.

**Windows:** CSV files containing Windows Security Event ID 4625 (failed logon) records.

The parsers extract the source IP address, username, and timestamp into a consistent event structure.

These events are passed to two detection functions.

### Brute-Force Detection

The tool groups failed login attempts by source IP address and username.

An alert is generated when the number of failed attempts reaches the configured threshold within the specified time window.

Default configuration:

- 3 failed login attempts
- 60-second time window

### Password-Spraying Detection

The tool groups authentication failures by source IP address and checks how many distinct usernames were targeted within a specified time window.

Default configuration:

- 3 unique usernames
- 120-second time window

Both detection rules support custom thresholds and time windows.

## Project Architecture

```text
Authentication Logs
        |
        v
+-------------------------------+
|        Log Parsers            |
|-------------------------------|
| Linux SSH | Windows Event CSV |
+-------------------------------+
        |
        v
+-------------------------------+
| Normalized Authentication     |
| Events (IP, User, Timestamp)  |
+-------------------------------+
        |
        v
+-------------------------------+
|      Detection Engine         |
|-------------------------------|
| Brute Force | Password Spray  |
+-------------------------------+
        |
        v
+-------------------------------+
|     Investigation Alerts      |
+-------------------------------+
        |
        +--------> Terminal Output
        |
        +--------> JSON Report
```

## Requirements

- Python 3.9 or later
- No external Python packages required

## Running the Tool

Clone the repository:

```bash
git clone https://github.com/amaraaustin/AuthSentinel.git
cd AuthSentinel
```

Analyze Linux SSH authentication logs:

```bash
python3 analyzer.py --file sample_auth.log --format linux
```

Analyze Windows authentication events:

```bash
python3 analyzer.py --file windows_auth.csv --format windows
```

The Windows CSV should contain the following columns:

`EventID,TimeCreated,IpAddress,TargetUserName`

Adjust detection thresholds:

```bash
python3 analyzer.py --file sample_auth.log --format linux --brute-threshold 5 --brute-window 120 --spray-threshold 4 --spray-window 180
```

Generate a JSON report:

```bash
python3 analyzer.py --file sample_auth.log --format linux --output security_report.json
```

Analyze historical Linux logs using a specified starting year:

```bash
python3 analyzer.py --file sample_auth.log --format linux --year 2025
```

The `--year` argument specifies the starting year for Linux syslog entries that do not contain a year.

For chronologically ordered logs, the parser advances the year automatically when timestamps cross from December into January.

## Testing and Validation

I tested AuthSentinel using synthetic Linux and Windows authentication records, real SSH authentication failures generated in an isolated Ubuntu lab, and a publicly available external OpenSSH dataset.

I also created a clean log sample to verify that the tool does not generate alerts when the detection thresholds are not met.

### Automated Testing

The project includes 18 automated tests covering:

- Brute-force and password-spraying detection
- Events that should not trigger alerts
- Detection time-window boundaries
- Custom thresholds
- Linux log parsing
- Alert information and JSON export
- Invalid command-line configuration
- December-to-January timestamp rollover

Run the tests:

```bash
python3 -m unittest discover -v
```

**Latest local result: 18 tests passed.**

### Real-World OpenSSH Dataset Validation

To evaluate AuthSentinel beyond synthetic and lab-generated examples, I tested it against the publicly available [Loghub OpenSSH dataset hosted on Zenodo](https://zenodo.org/records/8196385).

Using the default detection thresholds, AuthSentinel produced the following results:

| Metric | Result |
|---|---:|
| Authentication failure events processed | **344,631** |
| Unique source IP addresses | **1,008** |
| Potential brute-force alerts | **1,347** |
| Potential password-spraying alerts | **203** |

The dataset contains repeated SSH authentication messages, which AuthSentinel expands into individual failure events before applying its detection rules.

An independent count of expanded failure events matched the analyzer's total of 344,631, supporting the consistency of event processing.

These results demonstrate the tool's ability to process a substantial external dataset and identify suspicious authentication patterns.

**Validation limitations:** The alerts represent rule-based detections, not independently confirmed attacks. The results do not establish ground-truth detection accuracy or false-positive rates. The original calendar year of the dataset has not been independently verified, so automatically assigned years are provisional.

**Detailed validation report:** [docs/VALIDATION.md](docs/VALIDATION.md)

## Project Files

| File | Purpose |
|---|---|
| `analyzer.py` | Linux log parsing, detection logic, and command-line interface |
| `windows_parser.py` | Windows Security Event CSV parsing |
| `reporter.py` | JSON report generation |
| `test_analyzer.py` | Automated tests |
| `sample_auth.log` | Sample Linux authentication events |
| `windows_auth.csv` | Sample Windows authentication events |
| `clean_auth.log` | Sample used to test non-detection |
| `docs/VALIDATION.md` | External dataset validation methodology, results, and limitations |

## Limitations

AuthSentinel is a rule-based detection project, not a complete security monitoring platform.

It currently focuses on failed authentication attempts and does not correlate them with successful logins. An alert therefore indicates potentially suspicious activity rather than confirming that an account has been compromised.

The Windows parser has been tested using synthetic CSV data rather than independently collected real Windows Security Event exports.

Traditional Linux syslog timestamps do not contain a year. AuthSentinel uses the current year by default or a user-specified starting year, and supports December-to-January rollover. Automatically assigned years should not be treated as verified historical dates.

Timestamps without timezone information are interpreted as UTC.

Malformed individual records are skipped, but the tool does not currently report how many were skipped.

Repeated SSH messages may share a timestamp, which can affect time-window analysis.

The default thresholds are intended for demonstration and require tuning for production environments to reduce false positives and missed detections.

False-positive and false-negative rates have not been established.

## What I Learned

Working on this project gave me practical experience with Python log parsing, time-based detection rules, and security event analysis.

It also helped me understand why testing matters in detection engineering. A detection rule needs to identify suspicious behavior, but it also needs to avoid generating alerts for activity that does not meet the conditions.

Working with a large external dataset introduced additional challenges, particularly repeated log messages, large event volumes, and timestamps crossing calendar years.

The project strengthened my understanding of how authentication events can be analyzed and presented as actionable security findings.

## Future Improvements

Some areas I would like to explore further include:

- Correlating failed and successful authentication events.
- Validating against real Windows Security Event exports.
- Measuring detection accuracy using labeled datasets.
- Improving alert aggregation for large datasets.
- Integrating generated alerts with a SIEM.

## Responsible Use

All authentication activity generated for testing was performed in an isolated, authorized lab environment.

The external OpenSSH dataset was obtained from a publicly available research dataset.

The sample authentication datasets included in this repository are synthetic.
