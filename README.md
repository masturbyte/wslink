# WSL Port Forward

A small PowerShell utility that keeps Windows ↔ WSL2 port forwarding in sync.

WSL2 runs behind a NAT'd virtual network adapter with its own internal IP address, and that
address changes every time WSL restarts. Anything that depends on inbound connections reaching
a service running inside WSL — a netcat listener, a web server, a Metasploit handler, a VPN
tunnel from a remote lab — silently breaks the moment the IP drifts out of sync with any port
forwarding rules you set up earlier.

This script detects the current WSL2 IP automatically, rebuilds the necessary `netsh portproxy`
rules, opens matching inbound firewall rules, and verifies that each port is actually reachable
— all in one command, with clear pass/fail output.

## Why

By default, WSL2 only forwards `localhost` traffic automatically. Traffic arriving on any other
interface — for example a VPN adapter — is not forwarded to WSL unless you explicitly configure
`netsh interface portproxy`. Since the WSL2 IP is not static, these rules go stale constantly and
are easy to forget about, leading to confusing "it should be working" debugging sessions.

## Features

- Auto-detects the current WSL2 IP address (no need to run `hostname -I` manually)
- Creates/refreshes `netsh portproxy` rules for one or more ports at once
- Opens matching inbound Windows Firewall rules
- Verifies connectivity after setup and reports exactly what is and isn't working
- Clean removal of rules with `-Remove`
- Inspect current state at any time with `-ListOnly`
- Zero dependencies beyond PowerShell and WSL2

## Requirements

- Windows 10/11 with WSL2
- PowerShell 5.1+ (built into Windows)
- Administrator privileges

## Installation

Clone the repository or download `Wslink.ps1` directly:

```powershell
git clone https://github.com/<your-username>/wsl-portforward.git
cd wsl-portforward
```

## Usage

All commands must be run from an **elevated** PowerShell session (Run as Administrator).

### Forward a single port

```powershell
.\Wslink.ps1.ps1 -Ports 4444
```

### Forward multiple ports at once

```powershell
.\Wslink.ps1.ps1 -Ports 80,443,4444
```

### Specify the WSL IP manually

```powershell
.\Wslink.ps1.ps1 -Ports 4444 -WslIp 172.28.42.164
```

### Check current configuration without changing anything

```powershell
.\Wslink.ps1.ps1 -ListOnly
```

### Remove forwarding and firewall rules

```powershell
.\Wslink.ps1.ps1 -Ports 4444 -Remove
```

### Example output

```
============================================================
  WSL Port Forward
============================================================
  [OK]   Running with Administrator privileges.
  [OK]   WSL2 IP address: 172.28.42.164

  [OK]   Port 4444 -> 172.28.42.164:4444 forwarding configured
  [OK]   Firewall rule 'WSL-PortForward-4444' active
  [OK]   Port 4444 is currently listening and reachable

============================================================
  Summary
============================================================

Port PortProxy Firewall Listening
---- --------- -------- ---------
4444 OK        OK       YES

  [OK]   All port forwarding rules are configured correctly.
```

## Typical workflow

1. Start your service or listener inside WSL (e.g. `nc -lvnp 4444`, `python3 -m http.server 80`).
2. Run the script for that port from an elevated PowerShell session on Windows.
3. Connect to the relevant Windows-side IP (localhost, LAN IP, or VPN tunnel IP) from the remote
   host or target machine.
4. Re-run with `-ListOnly` any time to confirm the current state.

Since the WSL2 IP changes on every restart, re-run the script after restarting WSL or rebooting
Windows, even if you haven't changed any ports.

## Troubleshooting

**"Running scripts is disabled on this system"**

Your execution policy is blocking local scripts. Either run it with a one-off bypass:

```powershell
powershell -ExecutionPolicy Bypass -File .\Wslink.ps1.ps1 -Ports 4444
```

or allow locally-authored scripts for your user:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

If a Group Policy enforces script restrictions at the machine level, the bypass command above is
the reliable option regardless of the configured execution policy.

**Connectivity still fails after running the script**

- Confirm the service is actually running and listening inside WSL.
- Confirm you're connecting to the correct Windows-side IP (not the WSL-internal IP).
- Check whether any third-party antivirus/firewall software is blocking the connection outside of
  Windows Firewall.
- If you're tunneling through a VPN, confirm the VPN is connected on the Windows host (`ipconfig`
  should show an active adapter with a valid IP and default gateway) and not inside WSL.

## License
Ahmed KORI

MIT
