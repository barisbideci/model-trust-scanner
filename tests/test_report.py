"""Rapor sağlamlık testleri — model kaynaklı içerik raporu bozmamalı."""

from __future__ import annotations

from pathlib import Path

from modelguard.models import FileReport, Finding, ScanResult, Severity
from modelguard.report import print_terminal, to_json


def _result_with_markup() -> ScanResult:
    # Kötü niyetli içerik: rich markup kapanış etiketi taklidi + köşeli parantez.
    bad = Finding(
        analyzer="dynamic",
        severity=Severity.MALICIOUS,
        title="Çalışma anı davranışı",
        detail="x",
        location="model.pkl",
        evidence="os.system('[/bold] [red]evil[/] ]]][[[')",
    )
    return ScanResult(target=Path("x"), files=[FileReport(path=Path("model.pkl"),
                      detected_format="pickle", findings=[bad])])


def test_terminal_report_survives_markup_injection(capsys):
    # Arrange
    result = _result_with_markup()
    # Act / Assert — markup enjeksiyonu MarkupError'a yol açmamalı.
    print_terminal(result)
    out = capsys.readouterr().out
    assert "MALICIOUS" in out


def test_json_report_is_valid():
    import json
    result = _result_with_markup()
    data = json.loads(to_json(result))
    assert data["verdict"] == "MALICIOUS"
    assert data["files"][0]["findings"][0]["severity"] == "MALICIOUS"
