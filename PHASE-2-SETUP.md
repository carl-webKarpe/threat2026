# MalDetect Phase 2 setup

## Standalone PHP Phase 2

The standalone XAMPP implementation now includes the Phase 2 role flow:

- `login.php` forwards to `loginform.php`.
- Admin and User accounts authenticate directly with username and password.
- Superadmin accounts must complete a real email OTP step at `superadmin/otp.php`.
- Protected pages use `auth/auth_check.php` and `auth/role_check.php`.
- The database setup is available in `database/phase2_standalone.sql`.

For a new install, run `database/maldetect_full_install.sql` (MySQL Workbench or phpMyAdmin), then open:

```text
http://localhost/threat2026/login.php
```

The local test accounts use the password `ChangeMe123!`. Configure the Gmail App Password in the ignored `config/mail.local.php` file before testing Superadmin login. OTPs are hashed in the database and are never displayed in the browser.

Install the mail dependency with `composer install` (or `php composer.phar install` when using the bundled local Composer executable), then import `database/migrations/phase8_superadmin_otps.sql`. The Phase 8 login throttle also requires importing `database/migrations/phase8_login_attempts.sql` once into `maldetect_db`.

## Phase 3 file scanner

Import `database/migrations/phase3_scans.sql` into the same database if the Phase 2 SQL was already imported. The admin scanner is available at `admin/scan.php` and accepts files up to 20 MB. New uploaded files are stored outside the Apache document root in the XAMPP parent directory (`maldetect_uploads`) using random names; set `MALDETECT_UPLOAD_DIR` to choose another private writable directory. Existing files under `uploads/` remain protected by its Apache deny rule.

Phase 3 validates the upload again on the server, records a SHA-256 hash, and creates a `queued` scan record. It does not call a malware API or create threat classifications, safety percentages, or risk levels. Set PHP's `upload_max_filesize` and `post_max_size` to at least `20M` and `21M` respectively only if the defaults are lower; restart Apache after changing `php.ini`.

## Phase 4 real malware analysis

Phase 4 uses the official VirusTotal API v3. VirusTotal requires an API key in the `x-apikey` request header. The key is read server-side from the `VIRUSTOTAL_API_KEY` environment variable, with the legacy `MALDETECT_VT_API_KEY` name also supported. For local XAMPP development, you can instead replace the placeholder in ignored `config/scanner.local.php`; it is never placed in HTML or JavaScript.

```powershell
[Environment]::SetEnvironmentVariable('VIRUSTOTAL_API_KEY', 'YOUR_VIRUSTOTAL_KEY', 'Machine')
```

Import `database/migrations/phase4_scans.sql` once if the existing Phase 3 `scans` table is already installed. Fresh installs using `database/phase2_standalone.sql` already include the Phase 4 columns.

The official endpoints are `POST https://www.virustotal.com/api/v3/files` and `GET https://www.virustotal.com/api/v3/analyses/{id}`. Uploads are sent to VirusTotal for third-party analysis. The public API documentation states a limit of four requests per minute; the scanner therefore polls every 20 seconds and supports files up to 20 MB, below VirusTotal's documented 32 MB direct-upload limit. Public API use is subject to VirusTotal's terms and is intended for free consumer applications, not commercial products.

Results are derived from the returned engine statistics. See the "Scan results" section in [README.md](README.md).
