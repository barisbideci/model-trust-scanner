"""Pickle statik analizörü testleri. Fixture'lar ASLA unpickle edilmez."""

from __future__ import annotations

from modelguard.analyzers.pickle_analyzer import PickleAnalyzer
from modelguard.models import Severity


def _titles(findings):
    return " | ".join(f.title for f in findings)


def test_benign_pickle_is_clean(fixtures_dir):
    findings = PickleAnalyzer().analyze(fixtures_dir / "benign.pkl")
    assert all(f.severity <= Severity.LOW for f in findings), _titles(findings)


def test_os_system_flagged_malicious(fixtures_dir):
    # Arrange / Act
    findings = PickleAnalyzer().analyze(fixtures_dir / "malicious_os_system.pkl")
    # Assert — os.system MALICIOUS olmalı.
    # Not: Windows'ta os.system, pickle'a 'nt.system' olarak serileştirilir
    # (POSIX'te 'posix.system'); ikisi de tehlikeli listesindedir.
    assert any(
        f.severity == Severity.MALICIOUS and f.evidence.endswith(".system")
        for f in findings
    ), _titles(findings)


def test_wrong_extension_bin_still_scanned(fixtures_dir):
    # .bin uzantılı zararlı pickle yine yakalanmalı.
    findings = PickleAnalyzer().analyze(fixtures_dir / "evasion_wrong_ext.bin")
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)


def test_zip_member_scanned(fixtures_dir):
    findings = PickleAnalyzer().analyze(fixtures_dir / "malicious_model.zip")
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)


def test_zero_crc_zip_still_scanned(fixtures_dir):
    # CVE-2025-10156 atlatması: CRC sıfırlanmış ZIP yine okunmalı.
    findings = PickleAnalyzer().analyze(fixtures_dir / "evasion_zero_crc.zip")
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)


def test_multiple_stop_flagged(fixtures_dir):
    findings = PickleAnalyzer().analyze(fixtures_dir / "multi_stop.pkl")
    # Hem çoklu-STOP uyarısı hem de zararlı import yakalanmalı.
    assert any("STOP" in f.title for f in findings), _titles(findings)
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)


def test_broken_pickle_marked_suspicious(fixtures_dir):
    # Yarım/bozuk akış 'güvenli' sayılmamalı.
    findings = PickleAnalyzer().analyze(fixtures_dir / "broken.pkl")
    assert findings, "bozuk pickle en az bir bulgu üretmeli"
    assert max(f.severity for f in findings) >= Severity.SUSPICIOUS, _titles(findings)


def test_7z_member_scanned(fixtures_dir):
    p = fixtures_dir / "evasion_7z.7z"
    if not p.exists():
        return  # py7zr yoksa atla
    findings = PickleAnalyzer().analyze(p)
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)
