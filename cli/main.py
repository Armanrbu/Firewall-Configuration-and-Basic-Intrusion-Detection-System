"""
NetGuard IDS — Typer CLI
========================
Usage:
    python -m cli                  list available commands
    python -m cli status           engine + firewall status
    python -m cli block 1.2.3.4    manually block an IP
    python -m cli unblock 1.2.3.4  remove a block
    python -m cli alerts           recent alerts
    python -m cli blocklist        all blocked IPs
    python -m cli rules list       show loaded YAML rules
    python -m cli rules reload     hot-reload rules
    python -m cli connections      live connections snapshot
    python -m cli config show      print current config
    python -m cli monitor          live tail of IDS events (Ctrl+C to quit)

All sub-commands call the local engine/DB directly (same process), so the
engine does NOT need to be running separately.  If a FastAPI server is up the
CLI can optionally hit it remotely via --api-url.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

# Bootstrap path so we can import local modules regardless of cwd
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# ---------------------------------------------------------------------------
# App + helpers
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="netguard",
    help="🛡️  NetGuard IDS — command-line interface",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=True,
)

rules_app = typer.Typer(
    help="Manage YAML detection rules",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
app.add_typer(rules_app, name="rules")

console = Console()


def _load_config() -> dict:
    """Load config.yaml from project root."""
    from utils.config_loader import load as _load
    try:
        return _load("config.yaml")
    except Exception:
        return {}


def _bootstrap_db() -> None:
    """Ensure DB is initialised (schema migrations run)."""
    try:
        from core.blocklist import get_db
        get_db()
    except Exception:
        pass


def _severity_colour(severity: str) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "none": "dim",
    }.get(severity.lower(), "white")


def _status_emoji(ok: bool) -> str:
    return "✅" if ok else "❌"


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@app.command()
def status(
    api_url: Optional[str] = typer.Option(None, "--api-url", help="Hit remote FastAPI server instead of local DB"),
) -> None:
    """Show engine, firewall, and IDS status."""
    _bootstrap_db()

    if api_url:
        import requests
        resp = requests.get(f"{api_url}/status", timeout=5)
        resp.raise_for_status()
        data = resp.json()
    else:
        from core.firewall import get_status
        from core.blocklist import get_stats_today, get_all_blocked, get_alerts
        data = {
            "firewall": get_status(),
            "stats_today": get_stats_today(),
            "alert_count": len(get_alerts(unresolved_only=True)),
            "blocked_count": len(get_all_blocked()),
        }

    fw = data.get("firewall", {})
    stats = data.get("stats_today", {})

    # Firewall panel
    fw_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    fw_table.add_column("Key", style="bold cyan", no_wrap=True)
    fw_table.add_column("Value", style="white")
    fw_table.add_row("Platform", fw.get("platform", "unknown"))
    fw_table.add_row("Active",    _status_emoji(fw.get("active", False)))
    fw_table.add_row("Blocked IPs",   str(data.get("blocked_count", 0)))
    fw_table.add_row("Open Alerts",   str(data.get("alert_count", 0)))

    # Stats panel
    st_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    st_table.add_column("Key", style="bold cyan", no_wrap=True)
    st_table.add_column("Value", style="white")
    for k, v in (stats or {}).items():
        st_table.add_row(k.replace("_", " ").title(), str(v))

    console.print()
    console.print(Panel(fw_table, title="[bold magenta]🔥 Firewall Status[/]", border_style="magenta"))
    console.print(Panel(st_table, title="[bold blue]📊 Today's Stats[/]",     border_style="blue"))


# ---------------------------------------------------------------------------
# block / unblock
# ---------------------------------------------------------------------------

@app.command()
def block(
    ip: str = typer.Argument(..., help="IPv4 or IPv6 address to block"),
    reason: str = typer.Option("Manual CLI block", "--reason", "-r", help="Reason for blocking"),
) -> None:
    """Block an IP address via the firewall and record it in the DB."""
    from utils.validators import is_valid_ip
    if not is_valid_ip(ip):
        console.print(f"[red]❌  Invalid IP address: {ip}[/]")
        raise typer.Exit(1)

    _bootstrap_db()

    with console.status(f"[bold yellow]Blocking {ip}…"):
        from core.firewall import block_ip
        from core.blocklist import add_block
        result = block_ip(ip)
        if result.get("success"):
            add_block(ip, reason)

    if result.get("success"):
        console.print(f"[green]✅  {ip} blocked.[/]  Reason: {reason}")
    else:
        console.print(f"[red]❌  Failed to block {ip}: {result.get('message', 'unknown error')}[/]")
        raise typer.Exit(1)


@app.command()
def unblock(
    ip: str = typer.Argument(..., help="IPv4 or IPv6 address to unblock"),
) -> None:
    """Remove a firewall block for an IP address."""
    from utils.validators import is_valid_ip
    if not is_valid_ip(ip):
        console.print(f"[red]❌  Invalid IP address: {ip}[/]")
        raise typer.Exit(1)

    _bootstrap_db()

    with console.status(f"[bold yellow]Unblocking {ip}…"):
        from core.firewall import unblock_ip
        from core.blocklist import remove_block
        result = unblock_ip(ip)
        if result.get("success"):
            remove_block(ip)

    if result.get("success"):
        console.print(f"[green]✅  {ip} unblocked.[/]")
    else:
        console.print(f"[red]❌  Failed to unblock {ip}: {result.get('message', 'unknown error')}[/]")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# alerts
# ---------------------------------------------------------------------------

@app.command()
def alerts(
    limit: int = typer.Option(20, "--limit", "-n", help="Max alerts to show"),
    unresolved: bool = typer.Option(False, "--unresolved", "-u", help="Show only unresolved alerts"),
    json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
) -> None:
    """Show recent IDS alerts."""
    _bootstrap_db()
    from core.blocklist import get_alerts
    rows = get_alerts(limit=limit, unresolved_only=unresolved)

    if json_output:
        import json
        console.print_json(json.dumps(rows))
        return

    table = Table(
        title=f"🚨 Alerts (last {limit})",
        box=box.ROUNDED,
        show_lines=True,
        border_style="red",
    )
    table.add_column("ID",         style="dim",      no_wrap=True)
    table.add_column("IP",         style="bold cyan", no_wrap=True)
    table.add_column("Type",       style="yellow")
    table.add_column("Details",    style="white",    overflow="fold")
    table.add_column("Resolved",   justify="center")
    table.add_column("Timestamp",  style="dim",      no_wrap=True)

    for r in rows:
        ts = str(r.get("timestamp", r.get("created_at", "")))[:19]
        resolved = "✅" if r.get("resolved") else "⏳"
        table.add_row(
            str(r.get("id", "")),
            r.get("ip_address", ""),
            r.get("alert_type", ""),
            r.get("details", ""),
            resolved,
            ts,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# blocklist
# ---------------------------------------------------------------------------

@app.command()
def blocklist(
    json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
) -> None:
    """List all currently blocked IPs."""
    _bootstrap_db()
    from core.blocklist import get_all_blocked
    rows = get_all_blocked()

    if json_output:
        import json
        console.print_json(json.dumps(rows))
        return

    table = Table(
        title="🚫 Blocked IPs",
        box=box.ROUNDED,
        border_style="red",
    )
    table.add_column("IP",      style="bold red",    no_wrap=True)
    table.add_column("Reason",  style="white",       overflow="fold")
    table.add_column("Blocked At", style="dim",      no_wrap=True)

    for r in rows:
        ts = str(r.get("blocked_at", r.get("timestamp", "")))[:19]
        table.add_row(
            r.get("ip_address", str(r)),
            r.get("reason", "—"),
            ts,
        )

    console.print(table)
    console.print(f"[dim]Total: {len(rows)} IP(s)[/]")


# ---------------------------------------------------------------------------
# connections
# ---------------------------------------------------------------------------

@app.command()
def connections(
    limit: int = typer.Option(30, "--limit", "-n", help="Max connections to display"),
) -> None:
    """Live snapshot of active network connections via psutil."""
    try:
        import psutil
    except ImportError:
        console.print("[red]❌  psutil not installed. Run: pip install psutil[/]")
        raise typer.Exit(1)

    table = Table(
        title="🌐 Live Connections",
        box=box.ROUNDED,
        border_style="blue",
    )
    table.add_column("Local",       style="dim",      no_wrap=True)
    table.add_column("Remote IP",   style="bold cyan", no_wrap=True)
    table.add_column("Port",        justify="right")
    table.add_column("Status",      style="yellow")
    table.add_column("PID",         justify="right",  style="dim")

    count = 0
    for c in psutil.net_connections(kind="inet"):
        if c.raddr and count < limit:
            table.add_row(
                f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—",
                c.raddr.ip,
                str(c.raddr.port),
                c.status or "—",
                str(c.pid) if c.pid else "—",
            )
            count += 1

    console.print(table)
    console.print(f"[dim]Showing {count} connection(s)[/]")


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

config_app = typer.Typer(help="Configuration management", no_args_is_help=True)
app.add_typer(config_app, name="config")


@config_app.command("show")
def config_show(
    section: Optional[str] = typer.Argument(None, help="Show only a specific section (e.g. 'ids', 'firewall')"),
) -> None:
    """Print the current config.yaml values."""
    cfg = _load_config()

    if section:
        sub = cfg.get(section)
        if sub is None:
            console.print(f"[red]Section '{section}' not found.[/]  Available: {', '.join(cfg.keys())}")
            raise typer.Exit(1)
        cfg = {section: sub}

    import json
    console.print_json(json.dumps(cfg, indent=2, default=str))


# ---------------------------------------------------------------------------
# rules sub-commands
# ---------------------------------------------------------------------------

@rules_app.command("list")
def rules_list(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show full rule details"),
) -> None:
    """Show all rules currently loaded in the rule engine."""
    from core.rule_engine import get_rule_engine
    engine = get_rule_engine()
    all_rules = engine.rules  # list[dict]

    if not all_rules:
        console.print("[yellow]No rules loaded.[/]")
        return

    table = Table(
        title=f"📋 Loaded Rules ({len(all_rules)})",
        box=box.ROUNDED,
        border_style="magenta",
    )
    table.add_column("ID",          style="bold cyan", no_wrap=True)
    table.add_column("Name",        style="white")
    table.add_column("Action",      style="yellow",    justify="center")
    table.add_column("Conditions",  justify="right",   style="dim")
    if verbose:
        table.add_column("Description", style="dim", overflow="fold")

    for r in all_rules:
        action = r.get("action", "alert")
        action_str = f"[red]{action}[/]" if action == "block" else f"[yellow]{action}[/]"
        cond_count = str(len(r.get("conditions", [])))
        row = [
            r.get("id", "—"),
            r.get("name", "—"),
            action_str,
            cond_count,
        ]
        if verbose:
            row.append(r.get("description", ""))
        table.add_row(*row)

    console.print(table)


@rules_app.command("reload")
def rules_reload() -> None:
    """Force the rule engine to hot-reload all rule files."""
    from core.rule_engine import get_rule_engine
    engine = get_rule_engine()
    with console.status("[bold yellow]Reloading rules…"):
        count = engine.reload_if_changed(force=True)
    console.print(f"[green]✅  Reloaded {count} rule file(s). Engine now has {len(engine.rules)} rules.[/]")


@rules_app.command("validate")
def rules_validate(
    path: str = typer.Argument(..., help="Path to a .yaml rule file to validate"),
) -> None:
    """Validate a YAML rule file without loading it into the engine."""
    import yaml
    if not os.path.exists(path):
        console.print(f"[red]File not found: {path}[/]")
        raise typer.Exit(1)

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        console.print(f"[red]❌  YAML parse error:[/]\n{e}")
        raise typer.Exit(1)

    rules = data.get("rules", [])
    if not isinstance(rules, list):
        console.print("[red]❌  Expected a top-level 'rules' list.[/]")
        raise typer.Exit(1)

    errors: list[str] = []
    for i, r in enumerate(rules):
        if not r.get("id"):
            errors.append(f"Rule #{i} is missing an 'id' field")
        if not r.get("action"):
            errors.append(f"Rule '{r.get('id', f'#{i}')}' is missing an 'action' field")
        if not r.get("conditions") and not r.get("python"):
            errors.append(f"Rule '{r.get('id', f'#{i}')}' has no 'conditions' or 'python' block")

    if errors:
        for e in errors:
            console.print(f"[yellow]⚠️  {e}[/]")
        console.print(f"[red]Validation failed: {len(errors)} issue(s)[/]")
        raise typer.Exit(1)

    console.print(f"[green]✅  Valid! {len(rules)} rule(s) defined.[/]")


# ---------------------------------------------------------------------------
# monitor  (live tail of EventBus events)
# ---------------------------------------------------------------------------

@app.command()
def monitor(
    tail: int = typer.Option(0, "--tail", "-n", help="Show last N events from DB before watching live (0 = live only)"),
) -> None:
    """
    [bold]Live tail of IDS events.[/]  Subscribe to the EventBus and print every
    event as it arrives.  Press [bold]Ctrl+C[/] to quit.
    """
    _bootstrap_db()

    # Optionally show recent alerts before entering live mode
    if tail > 0:
        from core.blocklist import get_alerts
        rows = get_alerts(limit=tail)
        console.rule("[dim]Recent stored alerts[/]")
        for r in reversed(rows):
            ts = str(r.get("timestamp", r.get("created_at", "")))[:19]
            console.print(f"[dim]{ts}[/]  [bold cyan]{r.get('ip_address','')}[/]  {r.get('alert_type','')} — {r.get('details','')}")
        console.rule()

    from core.event_bus import get_event_bus

    bus = get_event_bus()
    import queue as _queue
    q: _queue.Queue = _queue.Queue()

    def _on_event(ev) -> None:
        q.put(ev)

    bus.subscribe_all(_on_event)

    console.print("[bold green]🟢 Live monitoring started[/] — [dim]Ctrl+C to quit[/]\n")

    try:
        while True:
            try:
                ev = q.get(timeout=0.3)
                ts = time.strftime("%H:%M:%S")
                ev_type = type(ev).__name__

                # Colour-code by type
                colour = "white"
                if "Blocked" in ev_type:
                    colour = "bold red"
                elif "Flagged" in ev_type or "Alert" in ev_type:
                    colour = "yellow"
                elif "Anomaly" in ev_type:
                    colour = "magenta"
                elif "Scan" in ev_type:
                    colour = "cyan"
                elif "Connection" in ev_type:
                    colour = "dim"

                attrs = " ".join(
                    f"{k}={v!r}" for k, v in (ev.__dict__.items() if hasattr(ev, "__dict__") else [])
                )
                console.print(
                    f"[dim]{ts}[/]  [{colour}]{ev_type}[/]  [dim]{attrs}[/]"
                )
            except _queue.Empty:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        bus.unsubscribe_all(_on_event)
        console.print("\n[bold red]🔴 Monitoring stopped.[/]")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":
    main()
