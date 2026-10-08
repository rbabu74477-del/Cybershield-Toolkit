# 🛡️ CyberShield Toolkit

A lightweight **defensive cybersecurity CLI** written in pure Python (no dependencies).

## Features
| Command | Description |
|---|---|
| `password-check` | Strength analysis: entropy, common-password & pattern detection |
| `password-gen` | Cryptographically secure password generator (`secrets`) |
| `hash` | File checksum (MD5 / SHA-256 / SHA-512) |
| `integrity-init` / `integrity-verify` | File Integrity Monitoring - detect modified, added, deleted files |
| `log-analyze` | Detect SSH brute-force attacks from auth logs |

## Requirements
Python 3.8+

## Usage
```bash
python cybershield.py password-check "MyP@ss123"
python cybershield.py password-gen -l 20
python cybershield.py hash myfile.pdf -a sha256
python cybershield.py integrity-init ./my_folder
python cybershield.py integrity-verify ./my_folder
python cybershield.py log-analyze samples/auth.log -t 5
```

### Sample output
```
$ python cybershield.py log-analyze samples/auth.log
Failed logins: 22 from 3 IPs
[ALERT] 203.0.113.45 -> 14 attempts, users: admin, root, test, ubuntu
[ALERT] 198.51.100.7 -> 7 attempts, users: guest
```

## Run tests
```bash
python -m unittest discover tests
```

## Disclaimer
For educational and defensive use only.

## License
MIT
