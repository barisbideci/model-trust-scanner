"""Dinamik analiz orkestratörü — monitörü izole ortamda çalıştırır.

İki backend:
  - "docker" (tercih edilen): konteyner, ağ KAPALI, salt-okunur mount, bellek/pid limiti,
    zaman aşımı. Gerçek izolasyon. Yalnızca stdlib pickle yükleyicisi kullanılır.
  - "host" (zayıf, açık onay gerekir): modeli bu makinede çalıştırır. Yalnızca test/geliştirme
    veya Docker yoksa, kullanıcı riski kabul ederse.

Çıktı: davranışsal gözlemler -> list[Finding] (analyzer="dynamic").
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from modelguard.models import Finding, Severity

_MONITOR = Path(__file__).with_name("monitor.py")
_LEVEL_TO_SEVERITY = {
    "malicious": Severity.MALICIOUS,
    "suspicious": Severity.SUSPICIOUS,
    "info": Severity.LOW,
}


def docker_available() -> bool:
    """Docker CLI var mı ve daemon çalışıyor mu?"""
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=15
        )
        return r.returncode == 0
    except Exception:
        return False


def run_dynamic(
    path: Path,
    *,
    backend: str = "auto",
    timeout: int = 30,
    allow_host: bool = False,
    image: str = "python:3.11-slim",
) -> list[Finding]:
    """`path` dosyasını izole ortamda yükleyip davranışını gözlemler."""
    path = Path(path)
    if backend == "auto":
        backend = "docker" if docker_available() else ("host" if allow_host else "none")

    if backend == "none":
        return [
            Finding(
                analyzer="dynamic",
                severity=Severity.LOW,
                title="Dinamik analiz atlandı",
                detail="Docker bulunamadı ve host çalıştırma onayı (--allow-host) verilmedi. "
                       "İzole çalıştırma yapılmadı.",
                location=path.name,
            )
        ]

    try:
        if backend == "docker":
            result, meta = _run_docker(path, timeout=timeout, image=image)
        elif backend == "host":
            result, meta = _run_host(path, timeout=timeout)
        else:
            raise ValueError(f"bilinmeyen backend: {backend}")
    except subprocess.TimeoutExpired:
        return [
            Finding(
                analyzer="dynamic",
                severity=Severity.SUSPICIOUS,
                title="Yükleme zaman aşımına uğradı",
                detail=f"Model {timeout} sn içinde yüklenmedi. Uzun süren/askıda kalan "
                       "yükleme, arka planda iş yapan (ör. servis/döngü) bir payload işareti olabilir.",
                location=path.name,
                atlas="AML.T0011",
                owasp="ML06",
            )
        ]
    except Exception as exc:
        return [
            Finding(
                analyzer="dynamic",
                severity=Severity.LOW,
                title="Dinamik analiz çalıştırılamadı",
                detail=f"Sandbox hatası: {exc}",
                location=path.name,
            )
        ]

    return _to_findings(result, path, backend, meta)


# --- backend'ler --------------------------------------------------------------

def _run_docker(path: Path, *, timeout: int, image: str):
    """Monitörü ağı kapalı, kaynak-sınırlı, salt-okunur bir konteynerde çalıştırır."""
    target_dir = path.parent.resolve()
    fname = path.name
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",            # ağ KAPALI — giden bağlantılar başarısız
        "--memory", "512m",
        "--pids-limit", "128",
        "--read-only",                  # kök dosya sistemi salt-okunur
        "--tmpfs", "/tmp",
        "-e", "MODELGUARD_SANDBOX=1",
        "-v", f"{target_dir}:/work:ro",
        "-v", f"{_MONITOR.resolve()}:/monitor.py:ro",
        image,
        "python", "-I", "/monitor.py", f"/work/{fname}",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return _parse_json(proc.stdout), {"stderr": proc.stderr, "rc": proc.returncode}


def _run_host(path: Path, *, timeout: int):
    """Monitörü bu makinede alt süreçte çalıştırır (ZAYIF izolasyon)."""
    import os
    env = dict(os.environ, MODELGUARD_SANDBOX="1")
    cmd = [sys.executable, "-I", str(_MONITOR), str(path.resolve())]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    return _parse_json(proc.stdout), {"stderr": proc.stderr, "rc": proc.returncode}


def _parse_json(stdout: str) -> dict:
    """Monitörün son JSON satırını ayrıştırır."""
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {"error": "monitör çıktısı ayrıştırılamadı", "events": []}


# --- sonuç dönüşümü -----------------------------------------------------------

def _to_findings(result: dict, path: Path, backend: str, meta: dict) -> list[Finding]:
    findings: list[Finding] = []

    # host backend zayıf izolasyon uyarısı.
    if backend == "host":
        findings.append(
            Finding(
                analyzer="dynamic",
                severity=Severity.LOW,
                title="Dinamik analiz host üzerinde çalıştı (zayıf izolasyon)",
                detail="Model bu makinede yüklendi. Gerçek kullanımda Docker (--network none) "
                       "tercih edilmelidir.",
                location=path.name,
            )
        )

    for ev in result.get("events", []):
        sev = _LEVEL_TO_SEVERITY.get(ev.get("level", "info"), Severity.LOW)
        findings.append(
            Finding(
                analyzer="dynamic",
                severity=sev,
                title=f"Çalışma anı davranışı: {ev.get('desc', ev.get('event'))}",
                detail=f"Yükleme sırasında '{ev.get('event')}' olayı gözlendi. "
                       "Bu, modelin yüklenirken kod çalıştırdığını gösterir.",
                location=path.name,
                evidence=f"{ev.get('event')} {ev.get('detail', '')}".strip(),
                atlas="AML.T0011",
                owasp="ML06",
            )
        )

    err = result.get("error")
    if err and not findings:
        findings.append(
            Finding(
                analyzer="dynamic",
                severity=Severity.LOW,
                title="Dinamik analiz: yükleme başarısız/engellendi",
                detail=str(err),
                location=path.name,
            )
        )
    return findings
