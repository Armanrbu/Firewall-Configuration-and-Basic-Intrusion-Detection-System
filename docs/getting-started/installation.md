# Installation

## Requirements

- **Python 3.10+**
- **Windows 10/11** or **Linux** (Ubuntu 20.04+, Debian, Fedora)
- Administrator / root privileges (required to modify firewall rules)

## Quick Install

```bash
# Clone the repository
git clone https://github.com/Armanrbu/Firewall-Configuration-and-Basic-Intrusion-Detection-System.git
cd Firewall-Configuration-and-Basic-Intrusion-Detection-System
```

### Option 1 — pip with optional groups

```bash
pip install -e ".[gui,api,cli]"       # GUI + REST API + CLI
pip install -e ".[api,cli]"           # headless: REST API + CLI only
pip install -e ".[all]"               # everything (includes dev tools)
```

### Option 2 — requirements.txt

```bash
pip install -r requirements.txt
```

### Option 3 — Docker (no local Python needed)

```bash
docker compose up
```

See [Docker deployment](../deployment/docker.md) for details.

## Verifying Installation

```bash
# Should print help without errors
python -m cli --help

# Test engine import
python -c "from core.engine import NetGuardEngine; print('OK')"
```

## Platform Notes

=== "Windows"
    Run as **Administrator** so Windows Firewall rules can be created/removed.
    ```powershell
    # Start PowerShell as Administrator, then:
    python main.py
    ```

=== "Linux"
    Run as **root** (or with `sudo`) for `iptables` access.
    ```bash
    sudo python main.py --headless
    ```
