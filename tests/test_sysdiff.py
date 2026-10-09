"""Sistem farkı (sysdiff) testleri — yük öncesi/sonrası süreç/port karşılaştırması.

Başlatılan yardımcı süreçler ZARARSIZDIR (yalnızca kısa süre uyur) ve test sonunda
kesinlikle sonlandırılır.
"""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

from modelguard.dynamic import sysdiff

pytestmark = pytest.mark.skipif(not sysdiff.available(), reason="psutil gerekli")


def test_new_process_detected():
    # Arrange — önce fotoğraf, sonra zararsız bir uyuyan süreç başlat.
    before = sysdiff.snapshot()
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
    try:
        time.sleep(0.5)  # süreç sistem tablosuna girsin
        after = sysdiff.snapshot()
        # Act
        d = sysdiff.diff(before, after)
        # Assert — yeni süreç, farkta PID'iyle görünmeli.
        assert any(pid == proc.pid for pid, _ in d.new_procs), d.new_procs
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_own_pid_is_ignored():
    # Aynı fotoğraf ignore_pids ile süzülünce o PID farkta çıkmamalı.
    snap = sysdiff.snapshot()
    # Yapay bir "yeni" süreç ekleyip ignore ile elenmesini doğrula.
    fake_pid = max(snap.procs) + 1 if snap.procs else 999999
    after = sysdiff.Snapshot(
        procs={**snap.procs, fake_pid: ("fake", time.time())},
        listening=snap.listening,
    )
    d = sysdiff.diff(snap, after, ignore_pids={fake_pid})
    assert all(pid != fake_pid for pid, _ in d.new_procs)


def test_no_change_empty_diff():
    snap = sysdiff.snapshot()
    d = sysdiff.diff(snap, snap)
    assert d.new_procs == [] and d.new_ports == []
