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
    """Monitörü bu makinede alt süreçte çalıştırır (ZAYIF izolasyon).

    Payload'ın başlattığı alt süreçler (ör. arka planda kalan bir servis) tarama
    bitince ya da zaman aşımında TÜM AĞAÇ olarak sonlandırılır:
      - Windows: Job Object (KILL_ON_JOB_CLOSE) — iş kapanınca ayrılmış torun
        süreçler dahil her şey garantili ölür.
      - POSIX: ayrı oturum (setsid) + killpg.
    Yine de bu Docker kadar güvenli değildir (ağdan/dosya sisteminden izole
    değildir); gerçek kullanımda Docker tercih edilmelidir.
    """
    import os

    import tempfile

    env = dict(os.environ, MODELGUARD_SANDBOX="1")
    # Sonuç DOSYAYA yazılır: payload monitörün stdout pipe'ını miras alırsa,
    # communicate() pipe EOF'unu (= torunun ölümünü) beklerdi ve temizlik gecikirdi.
    # Bunun yerine yalnızca MONİTÖRÜN çıkışını bekler, sonucu dosyadan okuruz.
    fd, result_path = tempfile.mkstemp(prefix="modelguard_dyn_", suffix=".json")
    os.close(fd)
    cmd = [sys.executable, "-I", str(_MONITOR), str(path.resolve()), result_path]

    try:
        with _HostGuard() as guard:
            proc = guard.spawn(cmd, env, quiet=True)
            proc.wait(timeout=timeout)  # yalnızca monitörü bekle, torunu değil
            try:
                data = Path(result_path).read_text(encoding="utf-8")
            except OSError:
                data = ""
            return _parse_json(data), {"stderr": "", "rc": proc.returncode}
    finally:
        try:
            os.unlink(result_path)
        except OSError:
            pass


class _HostGuard:
    """Host backend için süreç-ağacı sonlandırma garantisi sağlayan bağlam yöneticisi."""

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._job = None   # Windows Job Object tanıtıcısı (HANDLE)
        self._k32 = None   # yapılandırılmış kernel32 (CloseHandle için)

    def __enter__(self) -> "_HostGuard":
        return self

    def spawn(self, cmd: list[str], env: dict, *, quiet: bool = False) -> subprocess.Popen:
        import os

        popen_kwargs: dict = {}
        if os.name != "nt":
            popen_kwargs["start_new_session"] = True  # setsid: ayrı süreç grubu
        # quiet: stdout/stderr'i DEVNULL'a bağla. Payload bu tanıtıcıları miras alsa
        # bile üst süreç pipe EOF'una bloke olmaz (torun ömründen bağımsız oluruz).
        streams = subprocess.DEVNULL if quiet else subprocess.PIPE
        self._proc = subprocess.Popen(
            cmd, stdout=streams, stderr=streams,
            text=(not quiet), env=env, **popen_kwargs,
        )
        if os.name == "nt":
            self._assign_windows_job(self._proc)
        return self._proc

    def __exit__(self, *exc) -> None:
        import os
        import signal

        proc = self._proc
        if proc is None:
            return
        if proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            if os.name != "nt":
                # start_new_session ile alt sürecin pid'i = grup pid'i; lider
                # toplanmış olsa bile grup bu id ile öldürülebilir.
                os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass
        # Windows: işe atanmış TÜM süreçleri (ayrılmış torunlar dahil) açıkça
        # sonlandır, sonra tanıtıcıyı kapat. TerminateJobObject, KILL_ON_JOB_CLOSE'a
        # güvenmekten daha kesindir.
        if self._job is not None and self._k32 is not None:
            try:
                self._k32.TerminateJobObject(self._job, 1)
            except Exception:
                pass
            try:
                self._k32.CloseHandle(self._job)
            except Exception:
                pass
            self._job = None

    def _assign_windows_job(self, proc: subprocess.Popen) -> None:
        """Alt süreci, kapanınca tüm ağacı öldüren bir Job Object'e atar."""
        try:
            import ctypes
            from ctypes import wintypes

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            # 64-bit HANDLE'ların kırpılmaması için tip imzalarını ayarla (KRİTİK).
            k32.CreateJobObjectW.restype = wintypes.HANDLE
            k32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
            k32.SetInformationJobObject.restype = wintypes.BOOL
            k32.SetInformationJobObject.argtypes = [
                wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
            k32.AssignProcessToJobObject.restype = wintypes.BOOL
            k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            k32.CloseHandle.restype = wintypes.BOOL
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            k32.TerminateJobObject.restype = wintypes.BOOL
            k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
            self._k32 = k32

            job = k32.CreateJobObjectW(None, None)
            if not job:
                return

            # JOBOBJECT_EXTENDED_LIMIT_INFORMATION yapısını tanımla.
            class _IO_COUNTERS(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulonglong) for n in
                            ("r", "w", "o", "rt", "wt", "ot")]

            class _BASIC(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.POINTER(wintypes.ULONG)),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class _EXT(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", _BASIC),
                    ("IoInfo", _IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
            info = _EXT()
            info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            # SetInformationJobObject(job, JobObjectExtendedLimitInformation=9, &info)
            if not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
                k32.CloseHandle(job)
                return
            # proc._handle: alt sürecin Windows süreç tanıtıcısı.
            handle = int(proc._handle)  # type: ignore[attr-defined]
            if not k32.AssignProcessToJobObject(job, handle):
                k32.CloseHandle(job)
                return
            self._job = job
        except Exception:
            self._job = None


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
