"""Pickle statik analizörü testleri. Fixture'lar ASLA unpickle edilmez."""

from __future__ import annotations

import io
import os
import pickle
import tarfile
from collections import OrderedDict

import pytest

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
        pytest.skip("py7zr kurulu değil; 7z fixture'ı üretilemedi")
    findings = PickleAnalyzer().analyze(p)
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)


# --- Eski (ZIP olmayan) torch formatı — inceleme bulgusu ----------------------
# Fixture'lar ASLA unpickle edilmez; yalnızca statik olarak taranır.

_TORCH_MAGIC = 0x1950A86A20F9469CFC6C


class _EchoPayload:
    def __reduce__(self):
        return (os.system, ("echo modelguard-canary",))


def _legacy_torch_bytes(state) -> bytes:
    """torch<1.6 düzeni: magic, protocol, sys_info, nesne, storage anahtarları + ham veri."""
    return (
        pickle.dumps(_TORCH_MAGIC, protocol=2)
        + pickle.dumps(1001, protocol=2)
        + pickle.dumps({"little_endian": True}, protocol=2)
        + pickle.dumps(state, protocol=2)
        + pickle.dumps(["0"], protocol=2)
        + b"\x00\x01\xf3\x9a" * 64  # ham tensör baytları (pickle değil)
    )


def test_legacy_torch_benign_is_not_flagged(tmp_path):
    # Eski formatın 5 akışı + ham tensör verisi yanlış alarm üretmemeli.
    p = tmp_path / "pytorch_model.bin"
    p.write_bytes(_legacy_torch_bytes(OrderedDict(w=1)))
    findings = PickleAnalyzer().analyze(p)
    assert all(f.severity <= Severity.LOW for f in findings), _titles(findings)


def test_legacy_torch_payload_in_object_stream_detected(tmp_path):
    # Payload 4. akışta (asıl nesne) — PyTorch bunu unpickle eder, yakalanmalı.
    p = tmp_path / "pytorch_model.bin"
    p.write_bytes(_legacy_torch_bytes(_EchoPayload()))
    findings = PickleAnalyzer().analyze(p)
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)


def test_legacy_tar_pickle_member_scanned(tmp_path):
    # Eski TAR formatında üye adı uzantısız "pickle" — yine de taranmalı.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in (("sys_info", pickle.dumps({"x": 1})),
                           ("pickle", pickle.dumps(_EchoPayload()))):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    p = tmp_path / "legacy_model.tar"
    p.write_bytes(buf.getvalue())
    findings = PickleAnalyzer().analyze(p)
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)


# --- memo / INST üzerinden global çözümleme (atlatma) ----------------------------
# Elle kurulan opcode dizileri: yalnızca statik taranır, ASLA unpickle edilmez.

def _sbu(s: str) -> bytes:
    """SHORT_BINUNICODE + MEMOIZE."""
    b = s.encode()
    return b"\x8c" + bytes([len(b)]) + b + b"\x94"


def test_stack_global_via_memo_with_allowlisted_decoy_detected(tmp_path):
    # Arrange — 'nt' memo'ya alınır, araya allowlist'te olan bir yem ('torch') konur,
    # sonra BINGET ile 'nt' geri çağrılıp 'system' ile STACK_GLOBAL yapılır.
    # Son iki literal'e bakan çözümleyici bunu "torch.system" (izinli!) sanar.
    payload = (
        b"\x80\x04"
        + _sbu("nt") + b"0"            # memo[0]='nt', POP
        + _sbu("torch") + b"0"         # memo[1]='torch' (yem), POP
        + b"h\x00"                     # BINGET 0 -> 'nt'
        + _sbu("system")               # memo[2]='system'
        + b"\x93\x94"                  # STACK_GLOBAL, MEMOIZE
        + _sbu("echo x") + b"\x85R."   # TUPLE1, REDUCE, STOP
    )
    p = tmp_path / "memo_evasion.pkl"
    p.write_bytes(payload)

    # Act
    findings = PickleAnalyzer().analyze(p)

    # Assert — gerçek hedef nt.system olarak çözülüp MALICIOUS sayılmalı.
    assert any(f.severity == Severity.MALICIOUS and f.evidence == "nt.system"
               for f in findings), _titles(findings)


def test_stack_global_via_memo_resolves_real_name(tmp_path):
    # Arrange — joblib tarzı meşru kalıp: modül adı memo'dan BINGET ile gelir.
    payload = (
        b"\x80\x04"
        + _sbu("collections") + b"0"
        + _sbu("subclass") + b"0"
        + b"h\x00" + _sbu("OrderedDict") + b"\x93\x94)R."
    )
    p = tmp_path / "memo_benign.pkl"
    p.write_bytes(payload)

    # Act
    findings = PickleAnalyzer().analyze(p)

    # Assert — collections.OrderedDict (izinli) olarak çözülür; uydurma ad yok.
    assert all(f.severity <= Severity.LOW for f in findings), _titles(findings)


def test_inst_opcode_import_detected(tmp_path):
    # Arrange — protokol 0 INST: GLOBAL kullanmadan import + çağrı.
    p = tmp_path / "inst.pkl"
    p.write_bytes(b"(S'echo x'\nios\nsystem\n.")

    # Act
    findings = PickleAnalyzer().analyze(p)

    # Assert
    assert any(f.severity == Severity.MALICIOUS and f.evidence == "os.system"
               for f in findings), _titles(findings)
