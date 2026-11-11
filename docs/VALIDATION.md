# AuthSentinel — Real-World Dataset Validation

## Dataset

Source: Loghub OpenSSH dataset, downloaded from Zenodo.

Dataset URL:
https://zenodo.org/records/8196385

AuthSentinel was tested against an external SSH authentication log dataset to evaluate its ability to parse authentication failures and identify suspicious login patterns.

## Validation Results

| Metric | Result |
|---|---:|
| Failed authentication events | 344,631 |
| Unique source IP addresses | 1,008 |
| Brute-force alerts | 1,347 |
| Password-spraying alerts | 203 |
| Automated unit tests | 18 passed |

## Detection Configuration

- Brute-force detection: 3 failed attempts against the same account from the same IP within 60 seconds.
- Password spraying: 3 distinct usernames targeted from the same IP within 120 seconds.

## Parsing Validation

The dataset contains repeated SSH authentication failure messages.

An independent count of expanded failure events matched AuthSentinel's output of 344,631 events.

This confirms consistency of the failure-event expansion count, but does not establish that every expanded event represents a distinct login attempt.

## Timestamp Handling

The dataset contains timestamps spanning December and January.

AuthSentinel supports an optional starting year and automatically advances the year when chronological Linux syslog entries cross from December into January.

A dedicated regression test verifies this behavior.

The dataset's original calendar year has not yet been independently verified. Any automatically assigned years should therefore be treated as provisional.

## Limitations

- Detection alerts indicate suspicious authentication patterns, not independently confirmed attacks.
- False-positive and false-negative rates have not been established.
- Repeated SSH messages may share a timestamp, potentially affecting time-window calculations.
- Results depend on the configured detection thresholds.
- The analyzer currently prints individual alerts, which can produce lengthy terminal output on large datasets.

## Conclusion

AuthSentinel successfully processed 344,631 expanded authentication failure events from an external OpenSSH dataset and generated brute-force and password-spraying alerts.

The results demonstrate log parsing, event grouping, threshold-based detection, and automated testing against a substantial real-world dataset.
