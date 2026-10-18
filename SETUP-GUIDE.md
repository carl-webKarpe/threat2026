# MalDetect Setup and Update Guide

Follow this guide every time new changes are pushed.

- **Part 1** gets the newest code (`git pull`).
- **Part 2** updates the database with MySQL Workbench.
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

## Part 2: How to run SQL (do this when a change says "Run this SQL")

Setup used here: **MySQL Server (MySQL80) + MySQL Workbench** for the database, and **XAMPP for Apache only**. Do not start MySQL in XAMPP (see Change 7).

### With MySQL Workbench (recommended)

1. Make sure the **MySQL80** service is running (Change 7, Step 1).
2. Open **MySQL Workbench** and double-click your connection (for example **Local instance MySQL80**). Enter your MySQL root password if it asks.
3. **To paste SQL:** click the **SQL+** icon at the top left (or **File > New Query Tab**), paste the SQL from the change log, and run **everything** with **Ctrl+Shift+Enter**, or click the plain lightning icon ⚡ (not the one with the cursor). Do not use Ctrl+Enter, which runs only the line where your cursor is.
4. **To run a whole `.sql` file:** **File > Open SQL Script** (Ctrl+Shift+O), pick the `.sql` file named in the change, then **Ctrl+Shift+Enter**.
5. Every row in the **Output** panel at the bottom should have a green ✔. A red ✖ is an error; read the **Message** column and see "Problems and fixes" at the end.
6. In **SCHEMAS** on the left, click the refresh arrows to see new tables.

### With phpMyAdmin (only if you use XAMPP's own MySQL instead)

1. Start **Apache** and **MySQL** in the XAMPP Control Panel and open **http://localhost/phpmyadmin**.
2. **To paste SQL:** the **SQL** tab, paste, then **Go**. **To run a file:** the **Import** tab, **Choose File**, then **Import**.

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

Skip the change log. Run the file `database/maldetect_full_install.sql` (Workbench: **File > Open SQL Script**, then **Ctrl+Shift+Enter**). It creates the whole database with every change included. Then continue with Part 4.

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

### Change 3: Admin and User can log in without Composer

**What changed:** on a new laptop the `vendor` folder (the email library) is missing, and before this change the login page broke for every account. Now Admin and User log in without it. Only the Superadmin needs it, for the email code.

**SQL to run:** none.

**Step 1: Get the code.** Do Part 1.

**Step 2: Test.** Sign in as `admin` / `ChangeMe123!`.

**Step 3: Only for the Superadmin login,** install the email library once:

1. Install Composer from https://getcomposer.org/Composer-Setup.exe. When it asks for PHP, choose `C:\xampp1\php\php.exe`.
2. Open a new Command Prompt and run:

   ```text
   cd C:\xampp1\htdocs\threat2026
   composer install
   ```

3. Set up `config\mail.local.php` with your Gmail App Password (see `PHASE-2-SETUP.md`).

---

### Change 4: Switch from MySQL Workbench to XAMPP's MySQL

> **Replaced by Change 7.** Skip this change; your instructor's setup uses MySQL Workbench.

**What changed:** no code changes. The guide now uses XAMPP's MySQL and phpMyAdmin. The database in your separate MySQL (the one Workbench used) is not copied, so you install a fresh one in XAMPP.

**Step 1: Stop the other MySQL.** XAMPP's MySQL cannot start while the other MySQL uses port 3306.

1. Press **Windows key + R**, type `services.msc` and press Enter.
2. Find **MySQL80** (or a name starting with **MySQL**). Right-click it > **Stop**.
3. Double-click it and set **Startup type** to **Manual**, so it does not start again after a restart. Click **OK**.

**Step 2: Start XAMPP.** In the XAMPP Control Panel, click **Start** next to **Apache** and **MySQL**. Both should turn green.

**Step 3: Remove the Workbench password file.** XAMPP's MySQL uses `root` with **no password**. If you created `config\database.local.php`, delete it (or set `'password' => ''` in it).

**Step 4: Create the database.** Open **http://localhost/phpmyadmin**, click the **Import** tab, click **Choose File**, pick `C:\xampp1\htdocs\threat2026\database\maldetect_full_install.sql`, then click **Import** at the bottom.

**Step 5: Set the Superadmin email.** Click the **SQL** tab, paste this (use your email) and click **Go**:

```sql
USE maldetect_db;
UPDATE users SET email = 'your-email@gmail.com' WHERE username = 'superadmin';
SELECT username, email, role FROM users;
```

**Step 6: Test.** Open `http://localhost/threat2026/login.php` and sign in as `admin` / `ChangeMe123!`.

---

### Change 5: Remove the warning popup on monitored PCs

**What changed:** the agent no longer shows a popup on the PC when a download is dangerous. It still reports every download, and admins see the risk, threat name and engine results on **Device Detections** and the dashboard. The agent only writes a line to its own log.

**SQL to run:** none.

**Step 1: Get the code.** Do Part 1.

**Step 2: Update the agent on each monitored PC.**

1. Stop the agent: press **Ctrl+C** in its window, or end `python.exe`/`pythonw.exe` in Task Manager.
2. Copy the new `agent\maldetect_agent.py` over the old one. Keep that PC's `config.json` and `agent_state.json`.
3. Start it again: `python maldetect_agent.py`.

**Step 3: Test.** Download a test file on that PC. No popup appears, and the file shows up in **Device Detections** on the server.

---

### Change 6: Clean up the file-monitor files and add the Print button

**What changed:** removed `auth/admin/`, `lib/`, `config/file_activity_monitor.php` and `database/migrations/phase9_file_monitoring.sql`. They crashed when opened and duplicated what the agent already does. The **Print Scan Details** button from those files is now on the real Scan Details page (`admin/view_scan.php`). Git still keeps the removed files in its history if you ever need them.

**SQL to run:** none. If you already imported `phase9_file_monitoring.sql`, you can remove its unused tables (run this in Workbench):

```sql
USE maldetect_db;
DROP TABLE IF EXISTS file_monitor_events, file_monitor_state, file_monitor_status;
```

**Step 1: Get the code.** Do Part 1.

**Step 2: Test.** Sign in as `admin`, open **Scan History**, click **View Result** on any scan, and click **Print Scan Details**. The print preview shows only the scan details, without the sidebar.

### Change 7: Use MySQL Workbench again (instructor's setup)

**What changed:** no code changes. The database runs on **MySQL Server (MySQL80)** and is managed in **MySQL Workbench**. XAMPP is used only for **Apache** (the website).

**Step 1: Start MySQL80 and keep it starting automatically.**

1. In the XAMPP Control Panel, click **Stop** next to **MySQL** if it is running. Only **Apache** should be green.
2. Press **Windows key + R**, type `services.msc` and press Enter.
3. Find **MySQL80**. Right-click it > **Start**.
4. Double-click it, set **Startup type** to **Automatic**, then click **OK**.

**Step 2: Give PHP your MySQL password.** MySQL80 usually has a root password.

1. In `C:\xampp1\htdocs\threat2026\config\`, copy `database.local.example.php` and name the copy `database.local.php` (skip if it already exists).
2. Open it in Notepad, set `'password' => 'your MySQL root password'`, and save.

**Step 3: Check the database in Workbench.** You created `maldetect_db` in Workbench before, so it should still be there. Run this:

```sql
SHOW DATABASES LIKE 'maldetect_db';
```

- If it shows `maldetect_db`, run the next SQL to confirm it has 8 tables, then go to Step 4.
- If nothing comes back, run `database\maldetect_full_install.sql` (**File > Open SQL Script**, then **Ctrl+Shift+Enter**).

```sql
USE maldetect_db;
SHOW TABLES;
```

**Step 4: Set the Superadmin email** (use your own email), if you have not done it in this database yet:

```sql
USE maldetect_db;
UPDATE users SET email = 'your-email@gmail.com' WHERE username = 'superadmin';
SELECT username, email, role FROM users;
```

**Step 5: Test.** Start **Apache** in XAMPP, open `http://localhost/threat2026/login.php` and sign in as `admin` / `ChangeMe123!`.

---

## Part 3b: Test everything on one laptop (before the computer lab)

Your laptop can be **both** the server and the monitored PC. This tests the whole system except the network cable.

1. Start **Apache** in XAMPP (not MySQL), and make sure the **MySQL80** service is running.
2. Add your VirusTotal key in `config\scanner.local.php` (see Part 4, "On the server PC", step 3).
3. Sign in as `admin`, open **Devices**, register a device named `My Laptop`, and copy the token.
4. Make the agent's config:

   ```text
   cd C:\xampp1\htdocs\threat2026\agent
   copy config.example.json config.json
   notepad config.json
   ```

   Set these two lines, then save:

   ```json
   "server_url": "http://localhost/threat2026",
   "device_token": "mdt_the_token_you_copied",
   ```

5. Start the agent and leave the window open:

   ```text
   python maldetect_agent.py
   ```

6. Download any file in your browser. Within a few seconds the agent prints `Reported <file name>`, and the file appears in **Device Detections** with its risk and engine results. On **Devices**, `My Laptop` shows **● Online**.

**Later, in the computer lab,** follow Part 4. The only differences are that the agent runs on the lab PCs, and `server_url` uses the server's IP address instead of `localhost` (for example `http://192.168.1.10/threat2026`).

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
| XAMPP: MySQL does not turn green, or the log says *"Port 3306 in use"* | That is expected: MySQL80 already uses port 3306. Leave XAMPP's MySQL stopped and use MySQL80 (Change 7). |
| "Unable to complete login" after switching to Workbench | PHP cannot log in to MySQL80. Put the right root password in `config\database.local.php` (Change 7, Step 2), and check MySQL80 is running in `services.msc`. |
| phpMyAdmin: `#1050 - Table ... already exists` | You already ran this change. Nothing to do. |
| phpMyAdmin: `#1046 - No database selected` | Add `USE maldetect_db;` as the first line, or click **maldetect_db** on the left before the **SQL** tab. |
| Workbench: `Error Code: 1046. No database selected` | The SQL must start with `USE maldetect_db;`. Run the whole script with Ctrl+Shift+Enter. |
| Workbench: `Error Code: 1050. Table already exists` | You already ran this change. Nothing to do. |
| Workbench: `Error Code: 1824. Failed to open the referenced table 'users'` | The database is not installed yet. Run `database/maldetect_full_install.sql` first. |
| Login page says "Unable to complete login" | PHP cannot connect to MySQL. Check that MySQL is running and that the user and password match `config/database.php` (default: `root`, empty password). |
| Devices page says "Run database/migrations/phase9_devices.sql first" | Do Change 1, Step 3. |
| Agent: `HTTP 401: Invalid or disabled device token` | The token is wrong or the device is disabled. Click **New token** on the Devices page and paste the new one into `config.json`. |
| Agent: `Connection refused` or `timed out` | The PC cannot reach the server. Check the server IP and the firewall rule. |
| Results stay "Pending" | The VirusTotal key is missing or the 4 requests/minute limit was reached. Wait a minute; the agent asks again by itself. |
