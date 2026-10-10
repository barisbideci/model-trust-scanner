"""HTML rapor üretimi testleri — içerik ve güvenlik (escape)."""

from __future__ import annotations

from pathlib import Path

from modelguard.htmlreport import render_comparison, render_scan
from modelguard.models import Finding, FileReport, ScanResult, Severity


def _result_with(finding: Finding) -> ScanResult:
    fr = FileReport(path=Path("model.pkl"), detected_format="pickle", findings=[finding])
    return ScanResult(target=Path("model.pkl"), files=[fr])


def test_render_scan_contains_verdict_and_finding():
    res = _result_with(Finding(
        analyzer="pickle", severity=Severity.MALICIOUS,
        title="Tehlikeli global", detail="os.system çağrısı",
        location="data.pkl", evidence="nt.system", atlas="AML.T0010.003", owasp="ML06",
    ))
    html = render_scan(res)
    assert "<!doctype html>" in html.lower()
    assert "MALICIOUS" in html
    assert "Tehlikeli global" in html
    assert "AML.T0010.003" in html


def test_render_scan_escapes_model_controlled_text():
    # Kötü bir modelin kontrol edebileceği alanlar (title/evidence) HTML'e ham
    # geçmemeli — markup/script enjeksiyonu engellenmeli (autoescape).
    res = _result_with(Finding(
        analyzer="gguf", severity=Severity.SUSPICIOUS,
        title="<script>alert(1)</script>", detail="x",
        location="a", evidence="<img src=x onerror=alert(1)>",
    ))
    html = render_scan(res)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html          # escape edilmiş hali var
    assert "onerror=alert(1)>" not in html   # ham olarak yok


def test_render_comparison_shows_metrics():
    from tools.compare_scanners import ToolResult, ToolStats

    s = ToolStats("modelguard")
    s.record("malicious_os_system.pkl", ToolResult(flagged=True, detail="verdict=MALICIOUS"))
    s.record("benign.pkl", ToolResult(flagged=False, detail="verdict=SAFE"))
    labels = {"malicious_os_system.pkl": "malicious", "benign.pkl": "benign"}

    html = render_comparison([s], labels)
    assert "<!doctype html>" in html.lower()
    assert "modelguard" in html
    assert "Precision" in html
    assert "malicious_os_system.pkl" in html
