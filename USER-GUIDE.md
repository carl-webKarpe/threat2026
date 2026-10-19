# MalDetect User Guide

How to use MalDetect to watch the downloads of PCs on your network (for example a computer laboratory) and see whether a downloaded file is a threat.

For installing the server and the database, see [SETUP-GUIDE.md](SETUP-GUIDE.md). This guide starts when the website already works.

**Words used in this guide**

| Word | Meaning |
| --- | --- |
| **Server** | The PC that runs XAMPP and MySQL (here: Laptop 1, IP `192.168.1.87`). Admins open the website here. |
| **Monitored PC** | A lab PC or laptop whose downloads are watched (here: Laptop 2). |
| **Agent** | The small program on each monitored PC. It reports every new download to the server. |
| **Device** | A monitored PC as registered on the **Devices** page. |
| **Token** | The secret key (starts with `mdt_`) that lets one agent talk to the server. One token per device. |

---

## Part 1: Register a PC and get its token

Do this on the **server**, once per monitored PC.

**Step 1. Open MalDetect and sign in.**
On the server, open `http://localhost/threat2026/login.php` (or `https://192.168.1.87/threat2026/login.php` if HTTPS is set up). Sign in with an **Admin** account.

**Step 2. Open the Devices page.**
Click **Devices** in the left sidebar.

**Step 3. Type a name for the PC.**
In **Device name**, type a name you will recognise, for example `Lab A - PC 01` or `Laptop 2`. Tip: use the label that is on the PC itself.

**Step 4. Click Register Device.**
A green box appears with the title **DEVICE TOKEN FOR LAB A - PC 01**. It shows:

- the **token**, a long text that starts with `mdt_`;
- a ready-made **agent config** with `server_url` and `device_token`.

**Step 5. Copy the token right away.**
Select the whole token (from `mdt_` to the end), copy it, and paste it into Notepad or keep the page open.

> **The token is shown only once.** If you leave the page without copying it, click **New token** on that device's row to get a new one (the old one stops working).

**Step 6. Check the server address.**
In the agent config, `server_url` must be the address the monitored PC uses to reach the server, with the **server's IP**, not `localhost`. For example:

```text
http://192.168.1.87/threat2026
```

Find the server's IP with `ipconfig` (look for **IPv4 Address**), or run `tools\check_network.ps1`. When the server moves to another network (other Wi-Fi, LAN cable, hotspot) its IP changes: see [NETWORK-GUIDE.md](NETWORK-GUIDE.md). Use `https://` instead if you set up HTTPS (SETUP-GUIDE.md, Change 15).

**Result:** the new device is in the list with **○ Offline** and *Agent not connected yet*. That is normal until the agent runs on the PC (Part 2).

**Keep tokens private.** Anyone with a token can send reports as that PC. Do not post tokens in chats or screenshots. If a token leaks, click **New token** and install it again.

---

## Part 2: Install the agent on the monitored PC

Choose **one** way.

### Way A: the installer (recommended for lab PCs, no Python needed)

Prepare once on the server (it needs Python there). This **creates** the folder `agent\dist`; it does not exist before, and `git pull` does not bring it:

```powershell
cd C:\xampp1\htdocs\threat2026\agent
.\build_exe.bat
```

After 1–2 minutes it prints **Done** and the folder `C:\xampp1\htdocs\threat2026\agent\dist`, which contains `MalDetectAgent.exe`, `install_agent.ps1`, `uninstall_agent.ps1` and `config.example.json` (plus `maldetect-ca.crt` if HTTPS is set up). Build it again after every agent update.

Copy the **whole `dist` folder** to a USB drive. Then on **each** monitored PC:

1. Plug in the USB drive and open **PowerShell as Administrator** (right-click PowerShell > **Run as administrator**).
2. Go to the copied folder and run the installer with **this PC's token** from Part 1. `E:` is the USB drive's letter in this example; check yours in **File Explorer > This PC** (or copy `dist` to the Desktop and use that path):

   ```powershell
   cd E:\dist
   powershell -ExecutionPolicy Bypass -File .\install_agent.ps1 -ServerUrl http://192.168.1.87/threat2026 -Token mdt_PASTE_THE_TOKEN
   ```

3. Wait for **MalDetect agent installed.** The agent now runs hidden and starts again automatically every time someone logs in.

### Way B: run it by hand with Python (for testing)

1. Install Python from <https://www.python.org/downloads/> and tick **Add python.exe to PATH**.
2. Create `C:\MalDetectAgent` and copy `maldetect_agent.py` and `config.example.json` into it (from the server's `agent` folder).
3. In PowerShell:

   ```powershell
   cd C:\MalDetectAgent
   copy config.example.json config.json
   notepad config.json
   ```

4. Set `server_url` and `device_token`, save, then start it and leave the window open:

   ```powershell
   python maldetect_agent.py
   ```

---

## Part 3: Check that the PC is connected

On the server, open **Devices** (it updates by itself every few seconds).

- The device shows **● Online**.
- Under its name: the PC's real computer name and Windows version.
- **Last Seen**: the current time, and the PC's IP address under it.

If it stays **○ Offline**, see **Problems** at the end.

---

## Part 4: Watch downloads live

1. On the server, open **Device Detections**. The green **● Live** label means it updates by itself.
2. On the monitored PC, download any file with the browser.
3. Within a few seconds the file appears at the top of the list (with a short green flash), with:
   - **Result**: *Malicious*, *Suspicious*, *No Threat Detected*, or *Pending* while VirusTotal checks it;
   - **Engines**: how many antivirus engines flagged it, for example `6 / 66`;
   - **Source**: the website it was downloaded from (when Windows recorded it).

Files that VirusTotal has never seen are uploaded for a full scan; their result appears after about a minute.

**Filters:** search by file name or SHA-256, or filter by **Device**, **Result** and **Source** (new downloads or manual scans), then click **Apply Filters**.

---

## Part 5: Look at one detection in detail

Click a **file name** on **Device Detections** (or a threat on the **Dashboard**). The **Detection Details** page shows:

- **Verdict**: result, threat name, malicious / suspicious / harmless / undetected counts, total engines;
- **File**: size, path on the PC, SHA-256 (with a **View on VirusTotal** link), and where it was downloaded from;
- **Device and timeline**: which PC, its IP, when it was downloaded, reported and checked, and whether the alert email was sent.

Click **Print Detection Details** to print it or save it as a PDF.

Download addresses are shown as plain text on purpose, so nobody opens a dangerous link by accident.

---

## Part 6: Scan a PC on demand

New downloads are reported automatically. To check **everything already in a PC's Downloads folder**:

1. On **Devices**, click **Scan Downloads** on that PC's row (or **Scan All Online Devices** for every online PC).
2. **Last Scan** shows **Waiting for device…**, then **Scanning…**, then **Done · N file(s)**.
3. On **Device Detections**, set **Source** to **Manual scans** to see those files.

With the free VirusTotal key, about 4 unknown files are checked per minute; files VirusTotal already knows show their result immediately.

---

## Part 7: Threat alerts by email

When a file on any PC is **Malicious** or **Suspicious**, every active Admin and Superadmin with a real email address receives **one** email: *"MalDetect alert: Malicious file on Lab A - PC 01"*, with the file, PC, threat name and a link to the details page.

To receive alerts, your account needs a real email address (ask the Superadmin, or see SETUP-GUIDE.md, Change 9).

**Safe test:** download the EICAR test file (<https://www.eicar.org/download-anti-malware-testfile/>) on a monitored PC. It is harmless, but every antivirus reports it as malicious. Windows Defender may delete it first; allow it under **Windows Security > Protection history** on the test PC only.

---

## Part 8: Reports

1. Click **Reports** in the sidebar.
2. Choose **From** and **To** dates, and optionally a **Device**, **Result** (for example *Threats only*) and **Source**. Click **Apply Filters**.
3. The page shows the totals, **Detections by Device** and the **Top Threats**.
4. Click **Download CSV** for a spreadsheet with one row per file (opens in Excel), or **Print / Save as PDF** and choose **Save as PDF** as the printer.

---

## Part 9: Manage devices

All on the **Devices** page:

| Action | What it does | The agent on the PC |
| --- | --- | --- |
| **Rename** | Changes the device's name only. | Keeps working, nothing to change. |
| **Disable** / **Enable** | Temporarily blocks / allows the device. History is kept. | Is refused while disabled; works again after Enable. |
| **New token** | Makes a new token; the old one stops working at once. | Must get the new token (run the installer again, or edit `config.json`). |
| **Delete** | Removes the device **and all its detections and scan history**. | Is refused for good. |

**Stopping an agent:** with Way B press **Ctrl+C** in its window; with Way A run `C:\MalDetectAgent\uninstall_agent.ps1` as Administrator. The device turns **○ Offline** right away.

---

## Problems

| What you see | What to do |
| --- | --- |
| Device stays **○ Offline** | On the PC: is the agent running? (Way A: open `C:\MalDetectAgent\agent.log`; Way B: is the window still open?) Can the PC open `http://<server IP>/threat2026/login.php` in its browser? If not, check that both PCs are on the same network and the server's firewall rule (SETUP-GUIDE.md, Part 4). |
| Agent says `HTTP 401` / *server rejected this device's token* | The device was deleted, disabled or got a new token. On **Devices**: click **Enable**, or **New token** and install it again. |
| `python is not recognized` | Install Python and tick **Add python.exe to PATH**, then open a new PowerShell. Or use the installer (Way A). |
| Agent says `Config file not found` | Run it from the folder that contains `config.json`, or create `config.json` from `config.example.json`. |
| `CERTIFICATE_VERIFY_FAILED` | The agent needs `maldetect-ca.crt` for HTTPS (SETUP-GUIDE.md, Change 15). |
| Two rows show the same computer name | Two device entries use the same PC. Each PC needs its **own** device and token. Delete the extra entry. |
| The server's IP changed (new Wi-Fi, LAN cable, hotspot, restart) | Follow [NETWORK-GUIDE.md](NETWORK-GUIDE.md), Part 2. On installed PCs one command is enough: `C:\MalDetectAgent\change_server.ps1 -ServerUrl http://<new IP>/threat2026`. |
| Results stay **Pending** | VirusTotal checks about 4 unknown files per minute with the free key. Wait a few minutes; check that the VirusTotal key is set (SETUP-GUIDE.md, Part 4). |
