"""Dinamik sandbox testleri.

GÜVENLİK: canary payload yalnızca ZARARSIZ `echo` çalıştırır. Testler host backend'de
koşar (CI'da Docker olmayabilir). Gerçek zarar, ağ veya reverse shell YOKTUR.
"""

from __future__ import annotations

import os
import pickle
import subprocess
import sys
from pathlib import Path

import pytest

from modelguard.dynamic.sandbox import run_dynamic
from modelguard.models import Severity

MONITOR = Path(__file__).parents[1] / "modelguard" / "dynamic" / "monitor.py"


class _EchoCanary:
    """unpickle edilince zararsız 'echo' çalıştırır — os.system audit olayını tetikler."""

    def __reduce__(self):
        return (os.system, ("echo modelguard-canary",))


def _write_canary(tmp_path: Path) -> Path:
    p = tmp_path / "canary.pkl"
    p.write_bytes(pickle.dumps(_EchoCanary()))
    return p


def test_monitor_refuses_without_gate(tmp_path):
    # Güvenlik kapısı: MODELGUARD_SANDBOX=1 yoksa model YÜKLENMEMELİ.
    p = _write_canary(tmp_path)
    env = {k: v for k, v in os.environ.items() if k != "MODELGUARD_SANDBOX"}
    proc = subprocess.run(
        [sys.executable, "-I", str(MONITOR), str(p)],
        capture_output=True, text=True, env=env, timeout=30,
    )
    # Gate reddinde çıkış kodu 3 ve ASCII anahtar kelime (JSON unicode-escape eder).
    assert proc.returncode == 3
    assert "MODELGUARD_SANDBOX" in proc.stdout


def test_host_backend_detects_os_system(tmp_path):
    # Arrange
    p = _write_canary(tmp_path)
    # Act — host backend (Docker gerekmez), açık onayla.
    findings = run_dynamic(p, backend="host", allow_host=True, timeout=30)
    # Assert — çalışma anında os.system gözlenmeli (MALICIOUS).
    assert any(
        f.severity == Severity.MALICIOUS and "system" in f.evidence
        for f in findings
    ), [f.title for f in findings]


def test_benign_pickle_no_malicious_dynamic(tmp_path):
    # Zararsız bir pickle yüklenince kötü davranış gözlenmemeli.
    p = tmp_path / "benign.pkl"
    p.write_bytes(pickle.dumps({"w": [1, 2, 3]}))
    findings = run_dynamic(p, backend="host", allow_host=True, timeout=30)
    assert not any(f.severity == Severity.MALICIOUS for f in findings), \
        [f.title for f in findings]


def test_host_backend_legacy_torch_payload_in_fourth_stream(tmp_path):
    # Eski torch formatında payload 4. akışta: monitör PyTorch gibi 5 akışı sırayla
    # yüklemeli, yalnızca ilkini değil (yoksa payload tetiklenmez ve kaçırılır).
    legacy = (
        pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2)
        + pickle.dumps(1001, protocol=2)
        + pickle.dumps({"little_endian": True}, protocol=2)
        + pickle.dumps(_EchoCanary(), protocol=2)
        + pickle.dumps(["0"], protocol=2)
    )
    p = tmp_path / "pytorch_model.bin"
    p.write_bytes(legacy)
    findings = run_dynamic(p, backend="host", allow_host=True, timeout=30)
    assert any(f.severity == Severity.MALICIOUS for f in findings), \
        [f.title for f in findings]


import subprocess as _subprocess
import time as _time


class _SpawnCanary:
    """unpickle edilince GECİKMELİ bir marker yazan AYRILMIŞ alt süreç başlatır.

    Amaç: sandbox tarama bitince bu arka plan sürecini öldürüyor mu? Öldürüyorsa
    marker dosyası hiç oluşmamalı (süreç uyumadan sonlandırılır).
    """

    def __init__(self, marker: str, py: str) -> None:
        self.marker = marker
        self.py = py

    def __reduce__(self):
        code = f"import time; time.sleep(3); open(r'{self.marker}', 'w').close()"
        return (_subprocess.Popen, ([self.py, "-c", code],))


def test_host_backend_kills_lingering_background_process(tmp_path):
    # Arrange — unpickle edilince 3 sn sonra marker yazacak arka plan süreci başlatan canary.
    marker = (tmp_path / "survived.marker").as_posix()
    p = tmp_path / "spawner.pkl"
    p.write_bytes(pickle.dumps(_SpawnCanary(marker, sys.executable)))

    # Act — sandbox yükler (süreç başlar), sonra ağacı sonlandırmalı.
    findings = run_dynamic(p, backend="host", allow_host=True, timeout=20)

    # Davranış yakalandı mı (subprocess.Popen) — ayrıca doğrula.
    assert any("süreç" in f.title.lower() or "popen" in f.evidence.lower()
               for f in findings), [f.title for f in findings]

    # sysdiff: psutil varsa, arkada kalan süreç fark olarak raporlanmış olmalı.
    from modelguard.dynamic import sysdiff
    if sysdiff.available():
        assert any("arkada kalan" in f.title.lower() or "dinlenen port" in f.title.lower()
                   for f in findings), [f.title for f in findings]

    # Assert — marker, çocuğun uyku süresinden sonra bile OLUŞMAMALI (süreç öldürüldü).
    _time.sleep(5)
    assert not Path(marker).exists(), \
        "arka plan süreci tarama sonrası hayatta kaldı (ağaç sonlandırma başarısız)"
