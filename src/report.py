# -*- coding: utf-8 -*-
"""
report.py — Terminal display (via Rich) + JSON/Markdown file output.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from src.models import IOCReport, Verdict

# Use safe=True equivalent: force_terminal + no emoji on Windows
console = Console(highlight=False, emoji=False)

# Colour palette
_VERDICT_COLOURS = {
    Verdict.MALICIOUS.value:  "bold red",
    Verdict.SUSPICIOUS.value: "bold yellow",
    Verdict.BENIGN.value:     "bold green",
    Verdict.UNKNOWN.value:    "dim",
}

_LEVEL_COLOURS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}


def _verdict_text(verdict: str) -> Text:
    style = _VERDICT_COLOURS.get(verdict, "")
    return Text(verdict.upper(), style=style)


def _score_bar(score: int, width: int = 30) -> str:
    filled = int((score / 100) * width)
    bar = "|" * filled + "." * (width - filled)
    return bar


def display_terminal(report: IOCReport) -> None:
    """Render full IOC report to terminal using Rich."""
    console.rule(f"[bold cyan]SOC IOC Enrichment - {report.ioc}[/]")

    # ── Header panel ────────────────────────────────────────────────────
    hdr = Table.grid(padding=(0, 2))
    hdr.add_column(style="dim")
    hdr.add_column()
    hdr.add_row("IOC", f"[bold white]{report.ioc}[/]")
    hdr.add_row("Type", f"[cyan]{report.ioc_type.upper()}[/]")
    hdr.add_row("Timestamp", report.timestamp)
    console.print(Panel(hdr, title="[bold blue]Summary[/]", border_style="blue"))

    # ── Risk score ───────────────────────────────────────────────────────
    if report.risk:
        risk = report.risk
        level_style = _LEVEL_COLOURS.get(risk.level, "white")
        score_bar = _score_bar(risk.score)

        risk_tbl = Table.grid(padding=(0, 2))
        risk_tbl.add_column(style="dim", min_width=22)
        risk_tbl.add_column()
        risk_tbl.add_row("Risk Score", f"[{level_style}]{risk.score}/100[/]  " + score_bar)
        risk_tbl.add_row("Risk Level", f"[{level_style}]{risk.level}[/]")
        risk_tbl.add_row("Sources consulted", str(risk.sources_consulted))
        risk_tbl.add_row("Sources with data", str(risk.sources_with_data))

        console.print(Panel(risk_tbl, title="[bold yellow]Risk Score[/]", border_style="yellow"))

        # Scoring factors table
        if risk.factors:
            ftbl = Table(
                "Factor", "Points", "Reason",
                box=box.SIMPLE_HEAVY,
                show_header=True,
                header_style="bold magenta",
            )
            for f in risk.factors:
                pts_style = "green" if f.points < 0 else ("red" if f.points >= 15 else "yellow")
                ftbl.add_row(
                    f.factor,
                    f"[{pts_style}]{f.points:+.0f}[/]",
                    f.reason,
                )
            console.print(Panel(ftbl, title="[bold magenta]Score Breakdown[/]", border_style="magenta"))

    # ── Per-source results ───────────────────────────────────────────────
    for r in report.results:
        tbl = Table.grid(padding=(0, 2))
        tbl.add_column(style="dim", min_width=18)
        tbl.add_column()

        tbl.add_row("Verdict", _verdict_text(r.verdict))
        if r.confidence is not None:
            tbl.add_row("Confidence", f"{r.confidence:.1f}%")
        if r.malicious_count is not None:
            tbl.add_row("Malicious Reports", str(r.malicious_count))
        if r.reputation is not None:
            tbl.add_row("Reputation", str(r.reputation))
        country = r.data.get("country")
        if country:
            tbl.add_row("Country", country)
        asn = r.data.get("asn")
        if asn:
            tbl.add_row("ASN", asn)
        organization = r.data.get("organization")
        if organization:
            tbl.add_row("Organization", organization)
        network = r.data.get("network")
        if network:
            tbl.add_row("Network", network)
        rir = r.data.get("regional_internet_registry")
        if rir:
            tbl.add_row("RIR", rir)
        if r.first_observed:
            tbl.add_row("First Seen", r.first_observed)
        if r.last_observed:
            tbl.add_row("Last Seen", r.last_observed)
        tags = r.data.get("tags")
        if tags:
            tbl.add_row("Tags", ", ".join(tags))
        raw_link = r.data.get("raw_link")
        if raw_link:
            tbl.add_row("Link", f"[link={raw_link}]{raw_link}[/link]")
        if r.error:
            tbl.add_row("Status", f"[dim]{r.error}[/dim]")

        border = "red" if r.verdict == Verdict.MALICIOUS.value else (
            "yellow" if r.verdict == Verdict.SUSPICIOUS.value else "green" if r.verdict == Verdict.BENIGN.value else "dim"
        )
        console.print(Panel(tbl, title=f"[bold]{r.source}[/]", border_style=border))

    console.rule("[dim]End of Report[/]")


def save_json(report: IOCReport, output_dir: str = "reports") -> str:
    """Write report to a JSON file; returns the file path."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    safe_ioc = report.canonical_ioc.replace("/", "_").replace(":", "_").replace("?", "_").replace("&", "_")
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    lookup = report.lookup_id or "local"
    filename = f"{safe_ioc}_{lookup}.json"
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2, ensure_ascii=False)
    return filepath


def save_markdown(report: IOCReport, output_dir: str = "reports") -> str:
    """Write Markdown report; returns the file path."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    safe_ioc = report.canonical_ioc.replace("/", "_").replace(":", "_").replace("?", "_").replace("&", "_")
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    lookup = report.lookup_id or "local"
    filename = f"{safe_ioc}_{lookup}.md"
    filepath = os.path.join(output_dir, filename)

    lines: list[str] = []
    lines.append(f"# SOC IOC Enrichment Report\n")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| **Lookup ID** | `{report.lookup_id}` |")
    lines.append(f"| **IOC** | `{report.ioc}` |")
    lines.append(f"| **Type** | {report.ioc_type.upper()} |")
    lines.append(f"| **Timestamp** | {report.created_at} |")
    lines.append("")

    if report.risk:
        r = report.risk
        lines.append(f"## Risk Assessment\n")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Score** | {r.score}/100 |")
        lines.append(f"| **Level** | **{r.level}** |")
        lines.append(f"| Sources Consulted | {r.sources_consulted} |")
        lines.append(f"| Sources with Data | {r.sources_with_data} |")
        lines.append("")
        lines.append("### Score Breakdown\n")
        lines.append("| Factor | Points | Reason |")
        lines.append("|--------|--------|--------|")
        for f in r.factors:
            sign = "+" if f.points >= 0 else ""
            lines.append(f"| `{f.factor}` | {sign}{f.points:.0f} | {f.reason} |")
        lines.append("")

    lines.append(f"## Source Results\n")
    for res in report.results:
        lines.append(f"### {res.source}\n")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| Verdict | **{res.verdict.upper()}** |")
        if res.confidence is not None:
            lines.append(f"| Confidence | {res.confidence:.1f}% |")
        if res.malicious_count is not None:
            lines.append(f"| Malicious Reports | {res.malicious_count} |")
        if res.reputation is not None:
            lines.append(f"| Reputation | {res.reputation} |")
        country = res.data.get("country")
        if country:
            lines.append(f"| Country | {country} |")
        asn = res.data.get("asn")
        if asn:
            lines.append(f"| ASN | {asn} |")
        organization = res.data.get("organization")
        if organization:
            lines.append(f"| Organization | {organization} |")
        network = res.data.get("network")
        if network:
            lines.append(f"| Network | {network} |")
        rir = res.data.get("regional_internet_registry")
        if rir:
            lines.append(f"| RIR | {rir} |")
        if res.first_observed:
            lines.append(f"| First Seen | {res.first_observed} |")
        if res.last_observed:
            lines.append(f"| Last Seen | {res.last_observed} |")
        tags = res.data.get("tags")
        if tags:
            lines.append(f"| Tags | {', '.join(tags)} |")
        raw_link = res.data.get("raw_link")
        if raw_link:
            lines.append(f"| Link | [{raw_link}]({raw_link}) |")
        if res.error:
            lines.append(f"| Note | {res.error} |")
        lines.append("")

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return filepath
