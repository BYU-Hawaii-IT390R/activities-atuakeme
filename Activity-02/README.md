# Log Parsing Lab - IT 390R

## Completed Tasks

### ✅ `--task failed-logins`
Lists IP addresses with failed login attempts. Supports `--min-count`.

### ✅ `--task successful-creds`
Displays successful username/password combinations along with how many unique IPs used them.

### ✅ `--task wget-drops` (Extra Credit)
Lists URLs bots tried to download using `wget` or `curl`. Works even if the sample log doesn't contain any matching entries.

Example:
```bash
python analyze_log.py cowrie-tiny.log --task wget-drops
