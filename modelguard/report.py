"""Rapor üretimi: terminal (rich) ve JSON. HTML şablonu sonraki aşamada eklenir."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from modelguard.models import ScanResult, Severity
from modelguard.scoring import VERDICT_ADVICE, framework_summary, severity_counts

# Düzey -> renk (rich markup).
_COLOR = {
    "SAFE": "green",
    "LOW": "cyan",
    "SUSPICIOUS": "yellow",
    "MALICIOUS": "bold red",
}


def to_json(result: ScanResult) -> str:
    """Makine-okur JSON. Enum'lar etikete çevrilir."""
    payload = {
        "target": str(result.target),
        "verdict": result.severity.label,
        "severity_counts": dict(severity_counts(result)),
        "files": [],
    }
    for fr in result.files:
        payload["files"].append(
            {
                "path": str(fr.path),
                "format": fr.detected_format,
                "verdict": fr.severity.label,
                "errors": fr.errors,
                "findings": [
                    {**asdict(f), "severity": f.severity.label} for f in fr.findings
                ],
            }
        )
    return json.dumps(payload, indent=2, ensure_ascii=False)


def print_terminal(result: ScanResult) -> None:
    """İnsan-okur terminal raporu. rich yoksa düz metne düşer."""
    try:
        from rich.console import Console
        from rich.markup import escape
        from rich.table import Table
    except ImportError:
        _print_plain(result)
        return

    console = Console()
    verdict = result.severity.label
    console.rule(f"[{_COLOR[verdict]}]modelguard · SONUÇ: {verdict}[/]")

    for fr in result.files:
        v = fr.severity.label
        console.print(f"\n[bold]{escape(str(fr.path))}[/]  "
                      f"([italic]{escape(fr.detected_format)}[/]) → [{_COLOR[v]}]{v}[/]")
        if fr.errors:
            console.print(f"  [dim]hatalar: {escape('; '.join(fr.errors))}[/]")
        if not fr.findings:
            console.print("  [green]bulgu yok[/]")
            continue
        table = Table(show_header=True, header_style="bold", expand=True)
        table.add_column("Düzey", width=12)
        table.add_column("Başlık", width=34)
        table.add_column("Konum / Kanıt")
        for f in sorted(fr.findings, key=lambda x: x.severity, reverse=True):
            # Dinamik/model kaynaklı içerik escape edilir (markup enjeksiyonu önlenir).
            loc = escape(f.location)
            cell = f"{loc}\n[dim]{escape(f.evidence)}[/]" if f.evidence else loc
            table.add_row(
                f"[{_COLOR[f.severity.label]}]{f.severity.label}[/]",
                escape(f.title),
                cell,
            )
        console.print(table)

    fw = framework_summary(result)
    if fw["atlas"] or fw["owasp"]:
        console.print("\n[bold]Çerçeve eşlemesi:[/]")
        if fw["atlas"]:
            console.print("  ATLAS: " + ", ".join(f"{k}×{v}" for k, v in fw["atlas"].items()))
        if fw["owasp"]:
            console.print("  OWASP: " + ", ".join(f"{k}×{v}" for k, v in fw["owasp"].items()))

    console.print(f"\n[{_COLOR[verdict]}]» {VERDICT_ADVICE[result.severity]}[/]")


def _print_plain(result: ScanResult) -> None:
    print(f"modelguard · SONUÇ: {result.severity.label}")
    for fr in result.files:
        print(f"\n{fr.path} ({fr.detected_format}) -> {fr.severity.label}")
        for f in fr.findings:
            print(f"  [{f.severity.label}] {f.title} @ {f.location}")
    print(f"\n» {VERDICT_ADVICE[result.severity]}")


def write_json(result: ScanResult, out: Path) -> None:
    Path(out).write_text(to_json(result), encoding="utf-8")


def write_html(result: ScanResult, out: Path) -> None:
    """Tarama sonucunu tek-dosya HTML raporuna döker (jinja2, çevrimdışı)."""
    from modelguard.htmlreport import render_scan
    Path(out).write_text(render_scan(result), encoding="utf-8")
