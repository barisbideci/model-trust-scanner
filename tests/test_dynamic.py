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


def test_weak_cleanup_is_reported():
    # "taranamadı ≠ güvenli": Windows Job Object ataması başarısız olursa (zayıf
    # temizlik), rapor bunu bir bulgu olarak yansıtmalı — sessiz geçmemeli.
    from modelguard.dynamic.sandbox import _to_findings

    findings = _to_findings(
        {"loaded": True, "error": "", "events": []},
        Path("model.pkl"),
        "host",
        {"weak_cleanup": True},
    )
    assert any("zayıf moda düştü" in f.title for f in findings), \
        [f.title for f in findings]

    # Atama başarılıysa (weak_cleanup yok) böyle bir uyarı OLMAMALI.
    ok = _to_findings(
        {"loaded": True, "error": "", "events": []},
        Path("model.pkl"),
        "host",
        {"weak_cleanup": False},
    )
    assert not any("zayıf moda düştü" in f.title for f in ok), \
        [f.title for f in ok]


def test_docker_timeout_force_removes_container(monkeypatch):
    # Arrange — `docker run`u zaman aşımına düşür; `docker rm -f` çağrısını yakala.
    import modelguard.dynamic.sandbox as sb

    calls: list[list[str]] = []

    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        if "run" in cmd:
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 1))
        # `docker rm -f` çağrısı: başarılı taklit et.
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sb.subprocess, "run", fake_run)

    # Act — zaman aşımı run_dynamic tarafından bulgulara çevrilir.
    findings = sb.run_dynamic(Path("x.pkl"), backend="docker", timeout=1)

    # Assert — zaman aşımında konteyner adıyla `docker rm -f` çağrılmış olmalı.
    rm_calls = [c for c in calls if c[:3] == ["docker", "rm", "-f"]]
    assert rm_calls, calls
    assert rm_calls[0][3].startswith("modelguard-dyn-")
    # Ve kullanıcıya zaman aşımı bulgusu dönmeli.
    assert any("zaman aşımı" in f.title.lower() for f in findings), [f.title for f in findings]


def test_new_port_finding_includes_host_mode_caveat():
    # Arrange — host modunda yeni dinlenen port farkı.
    from modelguard.dynamic import sysdiff
    from modelguard.dynamic.sandbox import _to_findings

    sd = sysdiff.Diff(new_ports=[(4321, 8080)], new_procs=[])

    # Act
    findings = _to_findings(
        {"loaded": True, "error": "", "events": []},
        Path("model.pkl"), "host", {"sysdiff": sd},
    )

    # Assert — port bulgusu, nedenselliğin kanıtlanamadığına dair dürüstlük notunu taşımalı.
    port_findings = [f for f in findings if "dinlenen port" in f.title.lower()]
    assert port_findings, [f.title for f in findings]
    assert "nedensellik kanıtlanamaz" in port_findings[0].detail


# --- Docker backend (Docker yoksa atlanır) ------------------------------------

from modelguard.dynamic.sandbox import docker_available


@pytest.mark.skipif(not docker_available(), reason="Docker daemon çalışmıyor")
def test_docker_backend_detects_execution_in_container(tmp_path):
    # Linux konteynerde çözülebilsin diye payload'ı posix.system'e yönlendiririz
    # (Windows'ta üretilen pickle 'nt.system' taşır). Komut zararsız: 'id'.
    data = pickle.dumps(_EchoCanary(), protocol=2)
    # Testin kırılgan yanını koru: bayt kalıpları gerçekten bulunup değiştirilmeli.
    # Pickle protokolü değişip kalıp kaybolursa test sessizce yanlış şeyi test etmesin.
    assert b"system\n" in data, "beklenen system referansı pickle baytlarında yok"
    data = data.replace(b"cnt\nsystem\n", b"cposix\nsystem\n")
    data = data.replace(b"echo modelguard-canary", b"id")
    assert b"cposix\nsystem\n" in data, "posix.system yönlendirmesi uygulanamadı"
    p = tmp_path / "model.pkl"
    p.write_bytes(data)

    # Act — izole konteynerde (ağ kapalı, salt-okunur) yükle ve izle.
    findings = run_dynamic(p, backend="docker", timeout=120)

    # Assert — konteyner içinde kod çalıştırma gözlenmeli.
    assert any(f.severity == Severity.MALICIOUS for f in findings), \
        [f.title for f in findings]
