# StrongSwan Tunnel Status

A command-line utility to check the status of IPSec tunnels managed by StrongSwan using the VICI interface.

## AI-Generated Code Disclaimer

This project was created using:
- Claude 3.7 Sonnet by Anthropic
- Cursor IDE (https://cursor.sh) as the development environment
- Generated on: 09.05.2025

The code connects to StrongSwan's VICI interface to check the status of IPSec tunnels and can optionally attempt to initiate missing connections.

## Requirements

- Python 3.11 or higher
- StrongSwan with VICI interface enabled (TCP port 4502)
- Python vici module

**Important**: This script requires the StrongSwan VICI interface to be available via a TCP port (default: 4502) and not a Unix socket. Please ensure your StrongSwan configuration exposes the VICI interface over TCP.

## Installation

1. Install the required Python package:

```bash
pip install vici
```

2. Make the script executable:

```bash
chmod +x check_ipsec_status.py
```

## Usage

```bash
./check_ipsec_status.py [--host HOST] [--port PORT] [--debug] [--ascii] [--no-color] [--initiate]
```

### Options

- `--host`: VICI server host (default: 127.0.0.1)
- `--port`: VICI TCP port (default: 4502)
- `--debug`: Enable verbose output and exception tracing
- `--ascii`: Force ASCII output instead of UTF-8 symbols
- `--no-color`: Disable colored output
- `--initiate`: Offer to initiate missing connections after displaying status

### Output Format

The script provides a visual indication of tunnel status:

- `[✔]` Green checkmark for established IKE/Child SAs (or `[OK]` in ASCII mode)
- `[✘]` Red cross for missing or failed IKE/Child SAs (or `[FAIL]` in ASCII mode)

When color is enabled (default in terminals that support it):
- Established connections and their names are displayed in green
- Failed or missing connections and their names are displayed in red

### Connection Initiation

When the `--initiate` flag is used, the script will offer to initiate any child connections that are not currently established. After displaying the status report, you will be prompted with a yes/no question to confirm initiation of the missing child connections.

Example:
```
==================================================
Some connections are not established.
Do you want to attempt to initiate the missing connections? (y/n): y

Attempting to initiate 2 missing connection(s)...
  child-vpn-1 (IKE: ike-vpn-1): SUCCESS
  child-vpn-2 (IKE: ike-vpn-2): FAILED: Connection 'child-vpn-2' already exists
```

The initiation is performed at the child SA level and includes the parent IKE connection name for each child SA, providing the VICI interface with all required information to properly establish the tunnels.

### Example Output

UTF-8 mode with colors:
```
[✔] ike-vpn-1
  [✔] child-vpn-1
  [✔] child-vpn-2
[✘] ike-vpn-2
  [✘] child-vpn-3
```

ASCII mode or with `--no-color`:
```
[OK] ike-vpn-1
  [OK] child-vpn-1
  [OK] child-vpn-2
[FAIL] ike-vpn-2
  [FAIL] child-vpn-3
```

### Exit Codes

- `0`: Normal operation (even if some tunnels are down)
- `2`: Error during execution (missing dependency or runtime error)
- `3`: Operation cancelled by user

## Integration

### With Systemd Timer

Create a service file `/etc/systemd/system/check-ipsec.service`:

```ini
[Unit]
Description=Check IPSec tunnel status
After=network.target

[Service]
Type=oneshot
ExecStart=/path/to/check_ipsec_status.py
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
```

Create a timer file `/etc/systemd/system/check-ipsec.timer`:

```ini
[Unit]
Description=Run IPSec tunnel status check every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

Enable and start the timer:

```bash
systemctl enable check-ipsec.timer
systemctl start check-ipsec.timer
```

### With Nagios/Checkmk

Create a wrapper script that converts the output to Nagios format:

```bash
#!/bin/bash
OUTPUT=$(/path/to/check_ipsec_status.py --no-color)
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  if echo "$OUTPUT" | grep -q "\[✘\]" || echo "$OUTPUT" | grep -q "\[FAIL\]"; then
    echo "WARNING - Some IPSec tunnels are down"
    echo "$OUTPUT"
    exit 1
  else
    echo "OK - All IPSec tunnels established"
    echo "$OUTPUT"
    exit 0
  fi
else
  echo "UNKNOWN - Error checking IPSec tunnels"
  exit 3
fi
``` 