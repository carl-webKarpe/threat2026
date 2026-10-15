# MalDetect Setup and Update Guide

Follow this guide every time new changes are pushed.

- **Part 1** gets the newest code (`git pull`).
- **Part 2** updates the database in MySQL Workbench.
- **Part 3** is the change log. Each change lists the SQL to run and the steps to set it up. Do only the changes you have not done yet, from oldest to newest.

---

## Part 1: Get the newest code (do this for every change)

1. Open **Command Prompt** (or Git Bash).
2. Go to your project folder (use your real path; for example, it may be `C:\xampp1\htdocs\threat2026`):

   ```text
   cd C:\xampp\htdocs\threat2026
   ```

3. The first time only, switch to the branch with the changes:

   ```text
   git fetch origin
   git checkout claude/hopeful-brahmagupta-zq1g1h
   ```

4. Every time, download the newest changes:

   ```text
   git pull
   ```

5. Check that it worked:

   ```text
   git log --oneline -3
   ```

   The top line should match the newest commit in the change log below.

> If `git checkout` or `git pull` says *"Your local changes to the following files would be overwritten"*, you have edits that were never committed. Save them aside first, then try again:
>
> ```text
> git stash push -m "my edits before update"
> git checkout claude/hopeful-brahmagupta-zq1g1h
> git pull
> ```
>
> Your edits are not lost. `git stash list` shows them, and `git stash show -p` prints them. Only run `git stash pop` if you really need them back, because they may clash with the update.

---

## Part 2: How to run SQL in MySQL Workbench (do this when a change says "Run this SQL")

1. Open **MySQL Workbench** and double-click your connection (for example **Local instance MySQL80**).
2. Click the **SQL+** icon at the top left (or **File > New Query Tab**).
3. Copy the SQL from the change log and paste it into the tab.
4. Run **everything** with **Ctrl+Shift+Enter**, or click the plain lightning icon ⚡ (not the lightning icon with the cursor).
   - Do not use Ctrl+Enter. That runs only the one line where your cursor is.
5. Check the **Output** panel at the bottom. Every row should have a green ✔. A red ✖ means that line failed; read the message in the **Message** column.
6. In the **Schemas** panel on the left, right-click > **Refresh All** to see new tables.

Instead of pasting, you can also use **File > Open SQL Script**, pick the `.sql` file named in the change, and press **Ctrl+Shift+Enter**.

### Check what your database already has

Paste this any time you are not sure which changes you already ran:

```sql
USE maldetect_db;
SHOW TABLES;
SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'maldetect_db' AND TABLE_NAME = 'users';
```

| If you see... | then you already have... |
| --- | --- |
| `users`, `scans` | Phase 2–4 |
| `audit_logs` and a `last_login` column in `users` | Phase 7 |
| `login_attempts`, `superadmin_otps`, `superadmin_otp_requests` | Phase 8 |
| `devices`, `device_detections` | Phase 9 (Change 1 below) |

### First-time install (empty computer, no database yet)

Skip the change log. Open `database/maldetect_full_install.sql` in Workbench (**File > Open SQL Script**) and press **Ctrl+Shift+Enter**. It creates the whole database with every change included. Then continue with Part 4.

---

## Part 3: Change log

### Change 1: Bug fixes and download detection on other PCs (commit `c0b7a44`)

**What changed:** fixed the scan polling rate limit, the double table in Scan History, the OTP bugs, `last_login`, and the phase 4 migration. Added **Devices** and **Device Detections** pages and an agent that reports downloads from other PCs.

**Step 1: Get the code.** Do Part 1.

**Step 2: Make sure you have Phase 7 and Phase 8.** Run the "Check what your database already has" query above.

- If `audit_logs` is missing, open and run `database/migrations/phase7_superadmin.sql`.
- If `login_attempts` is missing, open and run `database/migrations/phase8_login_attempts.sql`.
- If `superadmin_otps` is missing, open and run `database/migrations/phase8_superadmin_otps.sql`.

**Step 3: Run this SQL** (it is the same as `database/migrations/phase9_devices.sql`):

```sql
USE maldetect_db;

CREATE TABLE IF NOT EXISTS devices (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    hostname VARCHAR(255) NULL,
    os_info VARCHAR(255) NULL,
    agent_version VARCHAR(50) NULL,
    token_hash CHAR(64) NOT NULL,
    token_prefix CHAR(8) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_by INT UNSIGNED NOT NULL,
    last_seen_at TIMESTAMP NULL,
    last_ip VARCHAR(45) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY devices_token_hash_unique (token_hash),
    INDEX devices_last_seen_index (last_seen_at),
    CONSTRAINT devices_created_by_foreign FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS device_detections (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    device_id INT UNSIGNED NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(1024) NULL,
    file_size BIGINT UNSIGNED NULL,
    sha256_hash CHAR(64) NOT NULL,
    source_url VARCHAR(2048) NULL,
    referrer_url VARCHAR(2048) NULL,
    downloaded_at DATETIME NULL,
    scan_status VARCHAR(30) NOT NULL DEFAULT 'pending',
    analysis_id VARCHAR(255) NULL,
    scan_result VARCHAR(30) NULL,
    risk_level VARCHAR(50) NULL,
    threat_name VARCHAR(255) NULL,
    safety_percentage DECIMAL(5,2) NULL,
    detection_count INT UNSIGNED NULL,
    malicious_count INT UNSIGNED NULL,
    suspicious_count INT UNSIGNED NULL,
    harmless_count INT UNSIGNED NULL,
    undetected_count INT UNSIGNED NULL,
    total_engines INT UNSIGNED NULL,
    scan_summary TEXT NULL,
    lookup_attempts INT UNSIGNED NOT NULL DEFAULT 0,
    checked_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX device_detections_device_index (device_id, created_at),
    INDEX device_detections_sha256_index (sha256_hash),
    INDEX device_detections_status_index (scan_status, checked_at),
    INDEX device_detections_result_index (scan_result, created_at),
    CONSTRAINT device_detections_device_foreign FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

**Step 4: Check it worked.** Run this SQL. Both tables should be listed:

```sql
USE maldetect_db;
SHOW TABLES LIKE 'device%';
```

**Step 5: Test in the browser.**

1. Open `http://localhost/threat2026/login.php` and sign in as `admin` / `ChangeMe123!`.
2. The sidebar now shows **Devices** and **Device Detections**.
3. Open **Scan History** and check that the table appears only once.

**Step 6: Set up a PC to watch (optional, for download detection).** Follow Part 4.

### Change 2: MySQL password setting file

**What changed:** if your MySQL `root` user has a password, you can now put it in a private file. Before, PHP always tried an empty password.

**SQL to run:** none.

**Step 1: Get the code.** Do Part 1.

**Step 2: Only if your MySQL root user has a password** (Workbench asks for it when you open the connection):

1. In `C:\xampp1\htdocs\threat2026\config\`, copy `database.local.example.php` and name the copy `database.local.php`.
2. Open it in Notepad and replace `YOUR_MYSQL_PASSWORD` with your MySQL root password, then save.

   Git never uploads this file, so your password stays on your laptop.

**Step 3: Test.** Open `http://localhost/threat2026/login.php` and sign in as `admin` / `ChangeMe123!`. If it says "Unable to complete login", the password in `database.local.php` is wrong.

---

## Part 4: Set up download detection on another PC

### On the server PC (the one with XAMPP)

1. Find its IP address: open Command Prompt, type `ipconfig`, and look for **IPv4 Address** (for example `192.168.1.10`).
2. Allow Apache through the firewall. Open **Windows Defender Firewall > Advanced settings > Inbound Rules > New Rule > Port > TCP 80 > Allow**, and name it `MalDetect`.
3. Set your VirusTotal key. Create the file `config\scanner.local.php`:

   ```php
   <?php
   return ['virustotal_api_key' => 'PASTE_YOUR_KEY_HERE'];
   ```

4. Sign in as Admin, open **Devices**, type a name (for example `Laptop 1`) and click **Register Device**.
5. **Copy the token now.** It is shown only once. If you lose it, click **New token**.

### On the other PC or laptop

1. Install Python from https://www.python.org/downloads/ and tick **"Add Python to PATH"** during setup.
2. Check that it opens the server: open `http://192.168.1.10/threat2026/login.php` in a browser (use your server IP). If it does not open, check the firewall step.
3. Copy the `agent` folder from the project to this PC, for example to `C:\MalDetectAgent`.
4. In that folder, copy `config.example.json` and name the copy `config.json`. Open it in Notepad and change two lines:

   ```json
   "server_url": "http://192.168.1.10/threat2026",
   "device_token": "mdt_the_token_you_copied",
   ```

5. Start the agent:

   ```text
   cd C:\MalDetectAgent
   python maldetect_agent.py
   ```

   You should see `MalDetect agent 1.0.0 watching: C:\Users\...\Downloads`.
6. Test it: download any file in the browser on this PC. Within a few seconds the agent prints `Reported <file name>`, and the file appears in **Device Detections** on the server. On the **Devices** page, the PC shows **● Online**.

   To test a "dangerous" result safely, download the EICAR test file from https://www.eicar.org/download-anti-malware-testfile/ . It is harmless, but antivirus programs treat it as malware. Windows Defender may delete it before the agent sees it.

7. Optional: start the agent automatically at login. Open **Task Scheduler > Create Basic Task**:
   - **Trigger:** When I log on
   - **Action:** Start a program
   - **Program:** `pythonw.exe`
   - **Arguments:** `C:\MalDetectAgent\maldetect_agent.py`

---

## Problems and fixes

| Problem | Fix |
| --- | --- |
| Workbench: `Error Code: 1046. No database selected` | The SQL must start with `USE maldetect_db;`. Run the whole script with Ctrl+Shift+Enter. |
| Workbench: `Error Code: 1050. Table already exists` | You already ran this change. Nothing to do. |
| Workbench: `Error Code: 1824. Failed to open the referenced table 'users'` | The database is not installed yet. Run `database/maldetect_full_install.sql` first. |
| Login page says "Unable to complete login" | PHP cannot connect to MySQL. Check that MySQL is running and that the user and password match `config/database.php` (default: `root`, empty password). |
| Devices page says "Run database/migrations/phase9_devices.sql first" | Do Change 1, Step 3. |
| Agent: `HTTP 401: Invalid or disabled device token` | The token is wrong or the device is disabled. Click **New token** on the Devices page and paste the new one into `config.json`. |
| Agent: `Connection refused` or `timed out` | The PC cannot reach the server. Check the server IP and the firewall rule. |
| Results stay "Pending" | The VirusTotal key is missing or the 4 requests/minute limit was reached. Wait a minute; the agent asks again by itself. |
