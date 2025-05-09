# StrongSwan Tunnel Status

A command-line utility to check the status of IPSec tunnels managed by StrongSwan using the VICI interface.

## Requirements

- Python 3.11 or higher
- StrongSwan with VICI interface enabled (TCP port 4502)
- Python vici module

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
./check_ipsec_status.py [--host HOST] [--port PORT] [--debug] [--ascii]
```

### Options

- `--host`: VICI server host (default: localhost)
- `--port`: VICI TCP port (default: 4502)
- `--debug`: Enable verbose output and exception tracing
- `--ascii`: Force ASCII output instead of UTF-8 symbols

### Output Format

The script provides a visual indication of tunnel status:

- `[✔]` Green checkmark for established IKE/Child SAs (or `[OK]` in ASCII mode)
- `[✘]` Red cross for missing or failed IKE/Child SAs (or `[FAIL]` in ASCII mode)

### Example Output

UTF-8 mode:
```
[✔] ike-vpn-1
  [✔] child-vpn-1
  [✔] child-vpn-2
[✘] ike-vpn-2
  [✘] child-vpn-3
```

ASCII mode:
```
[OK] ike-vpn-1
  [OK] child-vpn-1
  [OK] child-vpn-2
[FAIL] ike-vpn-2
  [FAIL] child-vpn-3
```

### Exit Codes

- `0`: All configured SAs are established
- `1`: At least one configured SA is missing or not established
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

Create a wrapper script that converts the exit code to Nagios format:

```bash
#!/bin/bash
OUTPUT=$(/path/to/check_ipsec_status.py)
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo "OK - All IPSec tunnels established"
  echo "$OUTPUT"
  exit 0
elif [ $EXIT_CODE -eq 1 ]; then
  echo "CRITICAL - Some IPSec tunnels are down"
  echo "$OUTPUT"
  exit 2
else
  echo "UNKNOWN - Error checking IPSec tunnels"
  exit 3
fi
``` 