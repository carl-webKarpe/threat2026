# MalDetect Network Guide (IP address, ipconfig, changing networks)

The monitored PCs find the server by its **IP address**, for example `192.168.1.87`. That address belongs to the network the server is connected to, so it **changes when the server changes network**: home Wi-Fi, the lab's LAN cable, a hotspot, or sometimes just after a restart.

This guide shows how to find the server's IP and what to change when it changes.

**It works on Wi-Fi, LAN cable (Ethernet) and hotspots**, as long as the server and the monitored PCs are on the **same local network** (the same router, switch or hotspot).

---

## Part 1: Find the server's IP address (ipconfig)

**Easiest way:** on the server, run the network check. It shows the IP and checks everything else too:

```powershell
cd C:\xampp1\htdocs\threat2026
powershell -ExecutionPolicy Bypass -File .\tools\check_network.ps1
```

It prints the **Server IP** for each connection, whether that network is Private, whether the firewall rule and Apache are OK, and the exact command to give the PCs. Lines marked **[FIX]** tell you what to change.

**By hand with ipconfig:**

1. On the server, open PowerShell or Command Prompt and type:

   ```text
   ipconfig
   ```

2. Find the block of the connection you are using:
   - Wi-Fi: **Wireless LAN adapter Wi-Fi**
   - LAN cable: **Ethernet adapter Ethernet**
3. In that block, read **IPv4 Address**, for example:

   ```text
   Ethernet adapter Ethernet:
      IPv4 Address. . . . . . . . . . . : 192.168.10.25
      Default Gateway . . . . . . . . . : 192.168.10.1
   ```

   Here the server's IP is **192.168.10.25**.

**Which IP to use:**

- Use the block that has a **Default Gateway** (the network you are really on).
- Ignore blocks that say **Media disconnected**, and virtual adapters such as *VirtualBox*, *VMware*, *vEthernet (WSL)* or *Bluetooth*.
- An address starting with `169.254.` means the connection did not get a real address. Reconnect the cable or Wi-Fi.
- If both Wi-Fi and the cable are connected, use the IP of the network the **monitored PCs** are on.

---

## Part 2: The server moved to another network: what to change

Do these steps every time the server's IP changes. Example: the IP changed from `192.168.1.87` (Wi-Fi at home) to `192.168.10.25` (LAN cable in the lab).

### On the server (Laptop 1)

**Step 1. Connect and find the new IP.** Plug in the cable (or join the Wi-Fi), then run `tools\check_network.ps1` or `ipconfig` (Part 1). Write the new IP down.

**Step 2. Set the network to Private.** Windows blocks incoming connections on **Public** networks.
Settings > **Network & internet** > **Ethernet** (or **Wi-Fi** > your network's properties) > **Network profile type**: **Private network**.

**Step 3. Check the firewall rule.** If you followed SETUP-GUIDE.md the rule already exists and works on every Private network. If `check_network.ps1` says it is missing, run in **PowerShell as Administrator**:

```powershell
New-NetFirewallRule -DisplayName "MalDetect Apache" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow -Profile Private
```

If the network must stay **Public** (some hotspots), allow the rule on all profiles instead:

```powershell
Set-NetFirewallRule -DisplayName "MalDetect Apache" -Profile Any
Set-NetFirewallRule -DisplayName "MalDetect Apache HTTPS" -Profile Any
```

(The second line only matters when HTTPS is set up.)

**Step 4. Only if you use HTTPS: make a certificate for the new IP.** In **PowerShell as Administrator**:

```powershell
cd C:\xampp1\htdocs\threat2026
powershell -ExecutionPolicy Bypass -File .\tools\setup_https.ps1 -ServerIp 192.168.10.25
```

Then in the XAMPP Control Panel click **Stop** and **Start** next to **Apache**. The MalDetect CA stays the same, so the PCs keep their `maldetect-ca.crt`.

**Step 5. Check the website.** On the server, open `http://192.168.10.25/threat2026/login.php` (with the new IP). The login page should open.

### On every monitored PC

**Step 6. Test the new address.** In the PC's browser, open `http://192.168.10.25/threat2026/login.php`. If the login page opens, continue. If not, see **Problems** below; the agent cannot connect either.

**Step 7. Point the agent to the new IP.** Choose the way the agent was installed:

- **Installed with the installer** (`C:\MalDetectAgent` with `MalDetectAgent.exe`): in **PowerShell as Administrator** run:

  ```powershell
  powershell -ExecutionPolicy Bypass -File C:\MalDetectAgent\change_server.ps1 -ServerUrl http://192.168.10.25/threat2026
  ```

  It keeps the token, checks the new address and restarts the agent. (Agents installed before this script existed: run `install_agent.ps1` again with the new `-ServerUrl` and the device's token, or copy `change_server.ps1` from the server's `agent` folder into `C:\MalDetectAgent` first.)

- **Running by hand with Python:** stop the agent with **Ctrl+C**, open its `config.json` (`notepad C:\MalDetectAgent\config.json`), change only the IP in `server_url`, save, and start it again:

  ```json
  "server_url": "http://192.168.10.25/threat2026",
  ```

  ```powershell
  python maldetect_agent.py
  ```

  On the server itself (if it also runs an agent), the address can stay `http://localhost/threat2026`; it never changes.

**Step 8. Check the Devices page.** On the server, open **Devices**: every PC shows **● Online** again, with its new IP under **Last Seen**.

The token does **not** change when the IP changes. Do not click **New token** for this.

---

## Part 3: Stop the IP from changing (recommended for the lab)

Changing every PC after each move is tedious. Give the server a fixed IP instead. Choose one.

### Option A: ask for a reserved IP (best)

Ask the lab's IT person to **reserve an IP for the server PC** on the router (a "DHCP reservation"). Give them the server's **Physical Address (MAC)**: run `ipconfig /all` and copy **Physical Address** from the Ethernet block (for example `3C-52-82-1A-2B-3C`). The server then always gets the same IP on that network, with no changes on the server.

### Option B: set a static IP on the server yourself

Only do this when you know which addresses are free on that network (ask IT if you can). A wrong or duplicate address breaks the connection.

1. Run `ipconfig` and note the current **IPv4 Address**, **Subnet Mask** and **Default Gateway**, for example `192.168.10.25`, `255.255.255.0`, `192.168.10.1`.
2. Open Settings > **Network & internet** > **Ethernet** (or Wi-Fi > your network) > **IP assignment** > **Edit**.
3. Choose **Manual**, turn on **IPv4**, and fill in:
   - **IP address**: an unused address in the same network, for example `192.168.10.200`;
   - **Subnet mask**: `255.255.255.0` (or **Subnet prefix length** `24`);
   - **Gateway**: the Default Gateway from step 1, for example `192.168.10.1`;
   - **Preferred DNS**: the same gateway address, or `8.8.8.8`.
4. Click **Save**, then check with `ipconfig` and by opening a website.
5. Do Part 2 once with the new address. After that it no longer changes on this network.

**Important:** a static IP belongs to one network. When you take the laptop home, set **IP assignment** back to **Automatic (DHCP)**, otherwise the home Wi-Fi does not work.

---

## Part 4: Notes per connection type

| Connection | What to know |
| --- | --- |
| **LAN cable (Ethernet)** | Best for the lab: stable and fast. Every PC must be plugged into the same switch or router as the server. Set the Ethernet network to **Private** on the server. |
| **Wi-Fi** | Fine when all PCs use the same Wi-Fi. School and guest Wi-Fi often block PCs from talking to each other ("client isolation"): the login page will not open from the PCs. Use the lab's LAN or another network then. |
| **Server on cable, PCs on Wi-Fi** | Works when the Wi-Fi and the cables come from the **same router**. |
| **Phone hotspot** | Connect the server and the PCs to the same phone. Some phones block devices from seeing each other. The IP usually starts with `192.168.43.` or `172.20.10.` and can change every time the hotspot is turned on. |
| **Windows Mobile Hotspot** (the server shares its own hotspot) | The server's IP for the PCs is **`192.168.137.1`**. This network is often **Public**: allow the firewall rule on all profiles (Part 2, Step 3). |
| **Cable directly between two laptops** | Not recommended: no router means no automatic IPs; both laptops need a manual IP (Part 3, Option B) in the same range, for example `192.168.50.1` and `192.168.50.2`, mask `255.255.255.0`, no gateway. |

---

## Problems

| What you see | What to do |
| --- | --- |
| The PC's browser cannot open `http://<server IP>/threat2026/login.php` | Check the IP again (`ipconfig` on the server); both devices on the same network; the server's network is **Private** and the firewall rule exists (`tools\check_network.ps1`); **Apache** is green in XAMPP. Try with Windows Firewall briefly turned off on the server: if it then works, the firewall rule is the problem. |
| It opens on the server with `localhost` but not with the IP | The firewall blocks it, or you used the IP of the wrong adapter. Run `tools\check_network.ps1`. |
| Agent log shows `timed out`, `Connection refused` or `No route to host` | The agent still uses the old IP, or the network blocks it. Do Part 2, Steps 6–7. |
| Agent log shows `CERTIFICATE_VERIFY_FAILED` after an IP change | With HTTPS, the certificate is made for one IP. Do Part 2, Step 4, and restart Apache. |
| `ipconfig` shows `169.254.x.x` | The PC did not get an address from the network: reconnect the cable or Wi-Fi, or restart the router. |
| Devices are **Online** but one PC is missing | That PC's agent still uses the old IP. Run `change_server.ps1` on it (Part 2, Step 7). |
