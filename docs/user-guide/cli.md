# CLI Reference

NetGuard IDS ships with a full-featured command-line interface built on [Typer](https://typer.tiangolo.com/) with [Rich](https://rich.readthedocs.io/) output.

## Usage

```bash
# As a Python module
python -m cli [COMMAND] [OPTIONS]

# Or via the installed entry-point
netguard-cli [COMMAND] [OPTIONS]
```

## Commands

### `status`

Show engine, firewall, and IDS status.

```bash
python -m cli status
python -m cli status --api-url http://localhost:5000   # hit remote server
```

### `block <IP>`

Block an IP address via the firewall and record it in the database.

```bash
python -m cli block 1.2.3.4
python -m cli block 1.2.3.4 --reason "Port scan detected"
```

### `unblock <IP>`

Remove a firewall block.

```bash
python -m cli unblock 1.2.3.4
```

### `alerts`

Show recent IDS alerts.

```bash
python -m cli alerts                    # last 20
python -m cli alerts --limit 50        # last 50
python -m cli alerts --unresolved      # only unresolved
python -m cli alerts --json            # raw JSON output
```

### `blocklist`

List all currently blocked IPs.

```bash
python -m cli blocklist
python -m cli blocklist --json
```

### `connections`

Live snapshot of active network connections.

```bash
python -m cli connections
python -m cli connections --limit 50
```

### `config show [SECTION]`

Print current configuration.

```bash
python -m cli config show           # full config as JSON
python -m cli config show ids       # just the 'ids' section
```

### `rules list`

Show all rules loaded in the rule engine.

```bash
python -m cli rules list
python -m cli rules list --verbose   # include descriptions
```

### `rules reload`

Force the rule engine to hot-reload all rule files.

```bash
python -m cli rules reload
```

### `rules validate <FILE>`

Validate a YAML rule file without loading it.

```bash
python -m cli rules validate rules/custom.yaml
```

### `monitor`

Live tail of IDS events from the EventBus. Press **Ctrl+C** to quit.

```bash
python -m cli monitor
python -m cli monitor --tail 20    # show last 20 DB alerts before going live
```

## Shell Completion

```bash
# Bash
netguard-cli --install-completion bash

# Zsh
netguard-cli --install-completion zsh

# PowerShell
netguard-cli --install-completion powershell
```
