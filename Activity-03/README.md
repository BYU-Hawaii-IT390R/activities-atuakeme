# Windows Admin Toolkit — Extended Tasks

This is an enhanced version of the `analyze_windows.py` script designed for Windows system administration. It includes the original tasks plus two new additions that help with auditing scheduled tasks and monitoring shadow copy storage.

---

## Original Tasks

- `win-events` — Analyze Windows Security event logs (logon successes and failures).
- `win-pkgs` — List installed software packages.
- `win-services` — Check and optionally restart critical Windows services.

---

## New Tasks Added

### 1. Scheduled Task Auditor (`--task win-schtasks`)

- Lists all scheduled tasks on the system except those signed by Microsoft.
- Shows task names and their next scheduled run times.
- Useful for auditing non-default or third-party scheduled jobs.
- Requires running the script as Administrator for full access.
- Handles permission errors gracefully with friendly messages.

### 2. Shadow Copy Space Check (`--task win-shadowstorage`)

- Queries Windows Volume Shadow Copy Service (VSS) storage usage per drive.
- Reports the allocated and used shadow copy storage sizes.
- Flags drives where shadow copy storage exceeds 10% of total allocated space.
- Helps monitor disk space consumed by shadow copies.
- Provides clear warnings if usage is high.
- Requires Administrator privileges.

---

## Usage Instructions

1. Run PowerShell **as Administrator**.
2. Install dependencies if not already installed:

   ```powershell
   pip install pywin32 colorama
