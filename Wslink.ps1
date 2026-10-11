<#
.SYNOPSIS
    Synchronizes Windows port forwarding rules with the current WSL2 instance IP address.

.DESCRIPTION
    WSL2 runs behind a NAT'd virtual network adapter, and its internal IP address changes
    every time WSL is restarted. This breaks inbound connectivity to services running inside
    WSL (listeners, web servers, reverse shell catchers, etc.) whenever the IP drifts out of
    sync with any previously configured port proxy rules.

    This script automatically detects the current WSL2 IP address, rebuilds the Windows
    port forwarding rules (via netsh portproxy) for the specified ports, opens matching
    inbound firewall rules, and verifies that each port is correctly listening and reachable.

.PARAMETER Ports
    One or more TCP ports to forward from Windows to WSL2. Defaults to 4444.

.PARAMETER WslIp
    Manually specify the WSL2 IP address instead of auto-detecting it.

.PARAMETER Remove
    Removes port forwarding rules and firewall rules for the specified ports instead of
    creating them.

.PARAMETER ListOnly
    Displays the current port forwarding configuration without making any changes.

.EXAMPLE
    .\wsl-portforward.ps1 -Ports 80,443,4444

.EXAMPLE
    .\wsl-portforward.ps1 -Ports 4444 -Remove

.EXAMPLE
    .\wsl-portforward.ps1 -ListOnly

.NOTES
    Must be run from an elevated (Administrator) PowerShell session.
    Requires WSL2 with at least one running distribution.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateRange(1, 65535)]
    [int[]]$Ports = @(4444),

    [string]$WslIp,

    [switch]$Remove,

    [switch]$ListOnly
)

# --------------------------------------------------------------------------
# Constants & helpers
# --------------------------------------------------------------------------

$script:FirewallRulePrefix = "WSL-PortForward"

function Write-Banner {
    param([string]$Text)
    $line = "=" * 60
    Write-Host ""
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor DarkCyan
}

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("OK", "FAIL", "WARN", "INFO")]
        [string]$Level = "INFO"
    )

    $symbol, $color = switch ($Level) {
        "OK"   { "[OK]  ", "Green" }
        "FAIL" { "[FAIL]", "Red" }
        "WARN" { "[WARN]", "Yellow" }
        "INFO" { "[INFO]", "Gray" }
    }

    Write-Host "  $symbol " -ForegroundColor $color -NoNewline
    Write-Host $Message
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WslIPAddress {
    try {
        $raw = (wsl.exe hostname -I 2>$null)
        if (-not $raw) { return $null }

        $candidates = $raw.Trim() -split '\s+' | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }
        return $candidates | Select-Object -First 1
    }
    catch {
        return $null
    }
}

function Get-ExistingPortProxyPorts {
    $output = netsh interface portproxy show v4tov4
    $ports = @()
    foreach ($line in $output) {
        if ($line -match '^\s*(?:0\.0\.0\.0|\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s*$') {
            $ports += [int]$Matches[1]
        }
    }
    return $ports | Select-Object -Unique
}

# --------------------------------------------------------------------------
# List-only mode
# --------------------------------------------------------------------------

if ($ListOnly) {
    Write-Banner "Current WSL Port Forwarding Rules"
    netsh interface portproxy show v4tov4
    Write-Host ""
    Write-Banner "Related Firewall Rules"
    Get-NetFirewallRule -DisplayName "$script:FirewallRulePrefix-*" -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Enabled, Direction, Action |
        Format-Table -AutoSize
    exit 0
}

# --------------------------------------------------------------------------
# Pre-flight checks
# --------------------------------------------------------------------------

Write-Banner "WSL Port Forward$(if ($Remove) {' - Removal Mode'})"

if (-not (Test-IsElevated)) {
    Write-Status "This script must be run as Administrator." "FAIL"
    Write-Status "Right-click PowerShell and select 'Run as Administrator', then try again." "INFO"
    exit 1
}
Write-Status "Running with Administrator privileges." "OK"

if (-not $WslIp) {
    $WslIp = Get-WslIPAddress
}

if (-not $WslIp) {
    Write-Status "Could not determine the WSL IP address automatically." "FAIL"
    Write-Status "Make sure WSL is running, or pass -WslIp manually." "INFO"
    exit 1
}
Write-Status "WSL2 IP address: $WslIp" "OK"

# --------------------------------------------------------------------------
# Removal mode
# --------------------------------------------------------------------------

if ($Remove) {
    Write-Host ""
    foreach ($port in $Ports) {
        netsh interface portproxy delete v4tov4 listenport=$port listenaddress=0.0.0.0 2>$null | Out-Null
        Remove-NetFirewallRule -DisplayName "$script:FirewallRulePrefix-$port" -ErrorAction SilentlyContinue
        Write-Status "Removed forwarding and firewall rule for port $port" "OK"
    }
    Write-Host ""
    exit 0
}

# --------------------------------------------------------------------------
# Create / refresh port forwarding rules
# --------------------------------------------------------------------------

Write-Host ""
$results = @()

foreach ($port in $Ports) {

    $entry = [ordered]@{
        Port        = $port
        PortProxy   = "FAIL"
        Firewall    = "FAIL"
        Listening   = "N/A"
    }

    # Reset any stale rule for this port first
    netsh interface portproxy delete v4tov4 listenport=$port listenaddress=0.0.0.0 2>$null | Out-Null

    $addResult = netsh interface portproxy add v4tov4 `
        listenport=$port listenaddress=0.0.0.0 `
        connectport=$port connectaddress=$WslIp

    $registered = Get-ExistingPortProxyPorts
    if ($registered -contains $port) {
        $entry.PortProxy = "OK"
        Write-Status "Port $port -> ${WslIp}:$port forwarding configured" "OK"
    }
    else {
        Write-Status "Failed to configure port forwarding for port $port" "FAIL"
    }

    $ruleName = "$script:FirewallRulePrefix-$port"
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existingRule) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound `
            -LocalPort $port -Protocol TCP -Action Allow | Out-Null
    }
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existingRule -and $existingRule.Enabled -eq "True") {
        $entry.Firewall = "OK"
        Write-Status "Firewall rule '$ruleName' active" "OK"
    }
    else {
        Write-Status "Firewall rule '$ruleName' could not be verified" "WARN"
    }

    # Check whether something is actually listening on that port inside WSL
    $probe = Test-NetConnection -ComputerName $WslIp -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet
    if ($probe) {
        $entry.Listening = "YES"
        Write-Status "Port $port is currently listening and reachable" "OK"
    }
    else {
        $entry.Listening = "NO"
        Write-Status "Nothing is listening on port $port yet (start your listener/server inside WSL)" "WARN"
    }

    $results += [pscustomobject]$entry
    Write-Host ""
}

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------

Write-Banner "Summary"
$results | Format-Table -AutoSize

$allConfigured = ($results | Where-Object { $_.PortProxy -ne "OK" -or $_.Firewall -ne "OK" }).Count -eq 0
if ($allConfigured) {
    Write-Status "All port forwarding rules are configured correctly." "OK"
}
else {
    Write-Status "Some rules failed to configure. Review the output above." "FAIL"
}

$notListening = $results | Where-Object { $_.Listening -eq "NO" }
if ($notListening) {
    Write-Host ""
    Write-Status "Reminder: forwarding is in place, but no service is listening yet on:" "INFO"
    foreach ($r in $notListening) {
        Write-Host "           - Port $($r.Port)" -ForegroundColor Yellow
    }
    Write-Status "Start your listener/server inside WSL, then re-run with -ListOnly to confirm." "INFO"
}

Write-Host ""
Write-Status "Current VPN/tunnel adapter IPs on this machine (for reference):" "INFO"
Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.InterfaceAlias -match "TAP|OpenVPN|tun|PPP" } |
    Select-Object InterfaceAlias, IPAddress |
    Format-Table -AutoSize

Write-Host "Done.`n" -ForegroundColor DarkGray
