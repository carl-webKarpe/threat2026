# Add Another PC to MalDetect

Step by step: how to register a new PC (or laptop) so MalDetect watches its downloads and file activity.

There are two computers in this guide:

| Name | What it is |
| --- | --- |
| **Server** | The PC with XAMPP and the MalDetect website (here `10.124.78.156`, project folder `C:\xampp1\htdocs\threat2026`). |
| **New PC** | The PC you want to monitor. It gets the **agent**, a small program that reports to the server. |

Use your own XAMPP folder everywhere (for example `C:\xampp2` instead of `C:\xampp1`).

---

## Part A: On the server, once (skip what you already did)

**A1. Start XAMPP.** In the **XAMPP Control Panel**, **Apache** and **MySQL** must be green.

**A2. Check the server's IP.** In PowerShell:

```powershell
ipconfig
```

**IPv4 Address** (Wi-Fi or Ethernet) should be `10.124.78.156`. If it is different, use that address everywhere below instead of `10.124.78.156`.

**A3. Allow other PCs through the firewall.** Open **PowerShell as Administrator** (Start > type PowerShell > right-click > **Run as administrator**) and run:

```powershell
New-NetFirewallRule -DisplayName "MalDetect HTTP 80" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Profile Any
```

**A4. Prepare the files for the new PC.** Make a folder on a **USB drive**, for example `E:\MalDetect`, and copy into it:

| Copy this | From the server folder | Needed for |
| --- | --- | --- |
| The whole **`dist`** folder | `C:\xampp1\htdocs\threat2026\agent\dist` | Way 1 (the `.exe`) |
| `maldetect_agent.py`, `file_activity.py`, `install_agent.ps1`, `config.example.json`, `uninstall_agent.ps1`, `change_server.ps1` | `C:\xampp1\htdocs\threat2026\agent` | Way 2 (Python), for PCs where Windows blocks the `.exe` |

Put the Way 2 files in their own folder on the USB drive, for example `E:\MalDetect\python-agent`. Do **not** put `MalDetectAgent.exe` in that folder.

No `dist` folder yet, or the agent was updated? Build it on the server first (PowerShell, in the project folder):

```powershell
cd C:\xampp1\htdocs\threat2026\agent
.\build_exe.bat
```

Wait for **Done**. It needs Python on the server.

**Never copy** `config.json`, `agent_state.json`, `agent.log` or `activity_*.json` files from another PC: they belong to that PC.

---

## Part B: On the server, for every new PC: register it

**B1.** Open MalDetect in the browser (`http://localhost/threat2026/loginform.php`) and sign in as **admin**.

**B2.** Click **Devices** in the sidebar.

**B3.** In **Device name** type a name you will recognise, for example `Lab A - PC 05`, and click **Register Device**.

**B4.** A green box shows the **token** (starts with `mdt_`, 68 characters) and a ready **install command**. **Copy the token now**: it is shown only once. Paste it into Notepad or keep the page open.

> One PC = one device = one token. Never use the same token on two PCs. If the token is lost, click **New token** on that device's row.

---

## Part C: On the new PC

**C1. Check that the new PC can reach the server.** Open **PowerShell** and run:

```powershell
Test-NetConnection 10.124.78.156 -Port 80
```

It must show **`TcpTestSucceeded : True`**. (A failed ping is normal; only this line matters.) If it says **False**: both PCs must be on the same network, and step A3 must be done on the server. See [NETWORK-GUIDE.md](NETWORK-GUIDE.md).

**C2. Copy the files** from the USB drive to the new PC, for example the `dist` folder to the **Desktop**.

**C3. Open PowerShell as Administrator** (Start > type PowerShell > right-click > **Run as administrator** > **Yes**).

### Way 1: with MalDetectAgent.exe (try this first)

**C4.** Run these lines **one at a time**. Replace `mdt_PASTE_THE_TOKEN` with the token from B4:

```powershell
cd $env:USERPROFILE\Desktop\dist
dir
Get-ChildItem -Recurse | Unblock-File
powershell -ExecutionPolicy Bypass -File .\install_agent.ps1 -ServerUrl http://10.124.78.156/threat2026 -Token mdt_PASTE_THE_TOKEN
```

- `dir` must list `MalDetectAgent.exe` and `install_agent.ps1`. If not, you are in the wrong folder: open the folder in File Explorer, copy the path from the address bar, and use `cd "PASTE_THE_PATH"`.
- Run `Unblock-File` **only inside this folder**, never in `C:\`.
- Write `-Token` and then the token, on one line, without spaces inside the token.

Wait for the green **MalDetect agent installed.** Then go to **Part D**.

If Windows says **"An Application Control policy has blocked this file"** or **Smart App Control blocked**, use Way 2.

### Way 2: with Python (when Windows blocks the .exe)

**C5.** Install Python from <https://www.python.org/downloads/>. On the first screen tick **Add python.exe to PATH**, then **Install Now**.

**C6.** Close PowerShell, open it again **as Administrator**, and check:

```powershell
python --version
```

**C7.** Copy the `python-agent` folder from the USB drive to `C:\MalDetect\python-agent`, then run one line at a time:

```powershell
cd C:\MalDetect\python-agent
dir
Get-ChildItem C:\MalDetect\python-agent | Unblock-File
powershell -ExecutionPolicy Bypass -File .\install_agent.ps1 -ServerUrl http://10.124.78.156/threat2026 -Token mdt_PASTE_THE_TOKEN
```

`dir` must list the six files. The installer sees there is no `.exe`, uses Python and installs `watchdog` by itself. Wait for **MalDetect agent installed.**

---

## Part D: Check that it works

**D1. On the new PC:**

```powershell
Start-Sleep -Seconds 15
Get-Content C:\MalDetectAgent\agent.log -Tail 10
```

Look at the lines with the **current time**: you should see `MalDetect agent 1.4.1 watching ...` and `Monitoring Desktop: ...`, and no `HTTP 401`.

**D2. On the server:** open **Devices**. The new PC shows **● Online** within a minute, with its computer name and IP.

**D3. Test it.** On the new PC create a file on the Desktop, rename it, then delete it, and download any small file with the browser. On the server:

- **File Activity** shows the actions within a few seconds (green = created, yellow = renamed, red = deleted, cyan = downloaded).
- **Device Detections** shows the download with its VirusTotal result.

From now on nothing else is needed: the agent starts by itself, hidden, every time someone signs in to that PC.

---

## Problems

| What you see | What to do |
| --- | --- |
| `TcpTestSucceeded : False` | Not the same network, or the firewall on the server (A3). Check the server's IP with `ipconfig` (A2). See NETWORK-GUIDE.md. |
| `The argument '.\install_agent.ps1' ... does not exist` | PowerShell is in the wrong folder (for example `C:\WINDOWS\system32`). Do the `cd` line first and check with `dir`. |
| `Missing an argument for parameter 'Token'` | The token is missing after `-Token`. Paste the whole token right after it. |
| `An Application Control policy has blocked this file` | Windows Smart App Control blocks the `.exe`. Use Way 2 (Python). |
| `python is not recognized` | Python is not installed, or **Add python.exe to PATH** was not ticked. Install again with it ticked, then open a new PowerShell. `py --version` may work instead. |
| Log shows `HTTP 401` with the current time | The token does not match this server. On **Devices** click **New token** for this PC, copy it, and run the install command again with it. |
| Log shows no new lines at all | The agent did not start. Sign out of Windows and in again; or check **Windows Security > Protection history** for a blocked file (then use Way 2). |
| PC shows **○ Offline** although the log looks fine | Is it the same server? The address in `C:\MalDetectAgent\config.json` (`server_url`) must be the server's IP from A2. Change it with: `powershell -ExecutionPolicy Bypass -File C:\MalDetectAgent\change_server.ps1 -ServerUrl http://<server IP>/threat2026` |
| The server's IP changed later | On every PC run the `change_server.ps1` line above with the new IP (NETWORK-GUIDE.md). |

**Remove the agent from a PC:** PowerShell as Administrator: `powershell -ExecutionPolicy Bypass -File C:\MalDetectAgent\uninstall_agent.ps1`, then click **Delete** for that device on the server's **Devices** page.
