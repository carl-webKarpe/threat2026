# MalDetect

**Setting up or updating? Follow [SETUP-GUIDE.md](SETUP-GUIDE.md) step by step.**

MalDetect checks files for malware with the VirusTotal API in two ways:

1. **Upload scanner**: an Admin uploads a file at `admin/scan.php`.
2. **Endpoint agents**: a small agent runs on other PCs and laptops, watches their Downloads folder, and reports every new download to MalDetect. Admins see the results under **Devices** and **Device Detections**. Nothing is shown on the monitored PC; results appear only on the server.

## Requirements

- PHP 8.1 or newer with `curl`, `fileinfo`, `mbstring` and `pdo_mysql` (XAMPP includes these)
- MySQL 8 or MariaDB 10.4+
- Composer dependencies: `composer install` (PHPMailer, for the Superadmin email OTP)
- A VirusTotal API key
- Python 3.9+ on each PC that runs the agent

## Database setup (MySQL Workbench)

The database runs on MySQL Server (MySQL80) and is managed with MySQL Workbench. XAMPP is only used for Apache.

**New install:**

1. Make sure the **MySQL80** service is running, and open your connection in **MySQL Workbench**.
2. Choose **File > Open SQL Script** and pick `database/maldetect_full_install.sql`.
3. Run it with **Query > Execute All** (Ctrl+Shift+Enter).
4. Refresh **SCHEMAS**. `maldetect_db` should list `users`, `scans`, `audit_logs`, `login_attempts`, `superadmin_otps`, `superadmin_otp_requests`, `devices` and `device_detections`.
5. If your MySQL root user has a password, copy `config/database.local.example.php` to `config/database.local.php` and put the password in it.

You can run the script again safely. It keeps existing tables and accounts.

**Existing database from an older phase:** run the files in `database/migrations/` that you have not run yet, in this order. Each one can be run again safely.

| File | Adds |
| --- | --- |
| `phase3_scans.sql` | `scans` table |
| `phase4_scans.sql` | VirusTotal result columns on `scans` |
| `phase7_superadmin.sql` | `users.last_login`, `audit_logs` |
| `phase8_login_attempts.sql` | login and OTP rate limiting |
| `phase8_superadmin_otps.sql` | Superadmin email OTP |
| `phase9_devices.sql` | `devices`, `device_detections` (endpoint agents) |

PHP connects with `127.0.0.1:3306`, database `maldetect_db`, user `root` and an empty password by default. If you use other values, set these environment variables: `MALDETECT_DB_HOST`, `MALDETECT_DB_PORT`, `MALDETECT_DB_NAME`, `MALDETECT_DB_USER`, `MALDETECT_DB_PASSWORD`.

## Local test accounts

The database script creates these accounts for local development:

| Role | Username | Password |
| --- | --- | --- |
| Superadmin | `superadmin` | `ChangeMe123!` |
| Admin | `admin` | `ChangeMe123!` |
| User | `user` | `ChangeMe123!` |

The Superadmin must also pass an email OTP. Configure SMTP in `config/mail.local.php` first (see [PHASE-2-SETUP.md](PHASE-2-SETUP.md)). Change these passwords before you put the system on a network.

## VirusTotal API key

Set the `VIRUSTOTAL_API_KEY` environment variable, or create the ignored file `config/scanner.local.php`:

```php
<?php
return ['virustotal_api_key' => 'YOUR_VIRUSTOTAL_KEY'];
```

The public API allows **4 requests per minute**, so MalDetect:

- checks each scan with VirusTotal at most once every 20 seconds;
- reuses a verdict for the same file (same SHA-256) for 24 hours;
- asks VirusTotal for the hash first and uploads a file only when VirusTotal has never seen it.

## Detecting downloads on other PCs

### 1. Make the server reachable on your network

The PCs must be able to open `http://<server-ip>/threat2026/` in a browser.

- Find the server IP with `ipconfig` (Windows), for example `192.168.1.10`.
- Allow Apache through the Windows Firewall (Inbound rule, TCP port 80, or 443 for HTTPS).
- Use HTTPS if devices connect over an untrusted network, because the device token travels with each request.

### 2. Register each device

Sign in as Admin, open **Devices**, enter a name (for example, "Front desk laptop") and click **Register Device**. Copy the token right away; it is shown only once. If it is lost, click **New token**.

### 3. Run the agent on the PC

Copy the `agent/` folder to the PC, then:

```text
cd agent
copy config.example.json config.json      (on macOS/Linux: cp config.example.json config.json)
```

Edit `config.json` and set `server_url` (for example `http://192.168.1.10/threat2026`) and `device_token`. Then run:

```text
python maldetect_agent.py
```

On the first run, the agent records the files already in Downloads and reports only new downloads (set `"report_existing_files": true` to report everything). To start it automatically on Windows, create a Task Scheduler task "At log on" that runs `pythonw.exe C:\path\to\agent\maldetect_agent.py`.

| Setting | Meaning |
| --- | --- |
| `watch_dirs` | Folders to watch; empty means the user's Downloads folder |
| `upload_unknown_files` | Upload files VirusTotal has never seen (up to 20 MB) for a full analysis |
| `poll_seconds` | How often the folders are checked |
| `verify_tls` | Set to `false` only for a self-signed HTTPS certificate in testing |

### 4. Optional: background worker

The agents ask for their own results, so no worker is required. To also finish detections when an agent goes offline or hits the VirusTotal rate limit, run the worker on the server, either once a minute with Task Scheduler or continuously:

```text
C:\xampp\php\php.exe C:\xampp\htdocs\threat2026\cli\process_detections.php --loop
```

### Agent API

Every request sends the header `X-Device-Token: <token>`. Responses are JSON.

| Endpoint | Method | Body | Purpose |
| --- | --- | --- | --- |
| `api/agent/heartbeat.php` | POST | `{"hostname", "os", "agent_version"}` | Marks the device online |
| `api/agent/report.php` | POST | `{"file_name", "sha256", "file_size", "file_path", "source_url", "referrer_url", "downloaded_at"}` | Reports a download; `file_name` and `sha256` are required |
| `api/agent/result.php?id=N` | GET | — | Latest verdict for a detection |
| `api/agent/upload.php` | POST multipart | `detection_id`, `file` | Uploads a file VirusTotal does not know |

A detection response contains `status` (`pending`, `not_found`, `analyzing`, `completed`, `failed`), `result`, `risk_level`, `threat_name`, `is_threat`, `needs_upload` and `is_final`. Ask `result.php` again until `is_final` is true.

## Scan results

The result comes from VirusTotal's engine statistics:

| Result | Risk level | When |
| --- | --- | --- |
| `MALICIOUS` | Malicious | at least one engine reports malicious |
| `SUSPICIOUS` | Suspicious | no malicious, at least one suspicious |
| `NO_THREAT_DETECTED` | No Threat Detected | engines responded with no detections |
| `UNKNOWN` | Unknown | no engine statistics, or VirusTotal does not know the file |

The "safety indicator" is calculated by MalDetect as (engines without a detection ÷ all engines). It is not an official VirusTotal score.

Files uploaded to the server are stored outside the web root in a private folder and deleted as soon as VirusTotal has them.
