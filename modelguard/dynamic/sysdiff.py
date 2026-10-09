"""Sistem anlık görüntüsü ve farkı — yükleme öncesi/sonrası karşılaştırma.

AMAÇ (kullanıcının asıl sorusu): "model indirilince arkada zararlı bir servis
çalışıyor mu?" Modeli yüklemeden önce ve sonra sistemin bir fotoğrafını alır
(çalışan süreçler + dinlenen portlar), farkı çıkarır. Yüklemeden sonra ortaya
çıkıp HÂLÂ çalışan yeni bir süreç ya da yeni dinlenen bir port = olası arka plan
servisi/kalıcılık.

psutil gerektirir; yoksa fonksiyonlar boş/никакой döner ve çağıran bunu bir notla
raporlar (sessiz geçmez).
"""

from __future__ import annotations

from dataclasses import dataclass, field


def available() -> bool:
    try:
        import psutil  # noqa: F401
        return True
    except ImportError:
        return False


@dataclass
class Snapshot:
    # pid -> (isim, oluşturulma zamanı). create_time PID yeniden kullanımını ayırt eder.
    procs: dict[int, tuple[str, float]] = field(default_factory=dict)
    # dinlenen portlar: (pid, port) kümesi.
    listening: set[tuple[int, int]] = field(default_factory=set)


def snapshot() -> Snapshot:
    """O anki süreçlerin ve dinlenen portların fotoğrafını alır."""
    snap = Snapshot()
    if not available():
        return snap
    import psutil

    for proc in psutil.process_iter(["pid", "name", "create_time"]):
        try:
            info = proc.info
            snap.procs[info["pid"]] = (info.get("name") or "?", info.get("create_time") or 0.0)
        except (psutil.Error, KeyError):
            continue

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == psutil.CONN_LISTEN and conn.pid and conn.laddr:
                snap.listening.add((conn.pid, conn.laddr.port))
    except (psutil.Error, PermissionError):
        pass  # bazı platformlarda yükseltilmiş izin gerekir
    return snap


@dataclass
class Diff:
    new_procs: list[tuple[int, str]] = field(default_factory=list)   # (pid, isim)
    new_ports: list[tuple[int, int]] = field(default_factory=list)   # (pid, port)


def diff(before: Snapshot, after: Snapshot, *, ignore_pids: set[int] | None = None) -> Diff:
    """İki fotoğraf arasındaki YENİ süreç ve dinlenen portları döndürür.

    ignore_pids: tarayıcının kendi/alt süreç PID'leri (gürültüyü eler).
    create_time eşleşmesiyle PID yeniden kullanımı ayıklanır.
    """
    ignore = ignore_pids or set()
    out = Diff()

    for pid, (name, ctime) in after.procs.items():
        if pid in ignore:
            continue
        prev = before.procs.get(pid)
        # Yeni PID, ya da aynı PID farklı create_time (yeniden kullanım) = yeni süreç.
        if prev is None or abs(prev[1] - ctime) > 1.0:
            out.new_procs.append((pid, name))

    before_ports = {port for _, port in before.listening}
    for pid, port in after.listening:
        if pid in ignore:
            continue
        if port not in before_ports:
            out.new_ports.append((pid, port))

    return out
