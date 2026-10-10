"""tools/compare_scanners.py metrik matematiği ve modelguard sarmalayıcı testleri."""

from __future__ import annotations

import pickle
from pathlib import Path

import tools.compare_scanners as cmp
from tools.compare_scanners import ToolResult, ToolStats, run_modelguard


def test_metrics_math():
    # Arrange — bilinen etiketlerle sahte bir araç sonucu kur.
    s = ToolStats("fake")
    # label -> (flagged). LABELS'ten gerçek etiketleri kullanırız.
    # 2 TP, 1 FN (zararlıyı kaçır), 1 FP (zararsızı işaretle), 1 TN.
    s.record("malicious_os_system.pkl", ToolResult(flagged=True))   # TP
    s.record("multi_stop.pkl", ToolResult(flagged=True))            # TP
    s.record("broken.pkl", ToolResult(flagged=False))               # FN
    s.record("benign.pkl", ToolResult(flagged=True))                # FP
    s.record("benign_model.zip", ToolResult(flagged=False))         # TN

    # Assert
    assert (s.tp, s.fp, s.tn, s.fn) == (2, 1, 1, 1)
    assert s.precision == 2 / 3           # TP/(TP+FP)
    assert s.recall == 2 / 3              # TP/(TP+FN)
    assert s.fpr == 1 / 2                 # FP/(FP+TN)
    assert abs(s.f1 - (2 / 3)) < 1e-9     # p=r -> f1=p


def test_metrics_none_when_no_data():
    s = ToolStats("empty")
    assert s.precision is None and s.recall is None and s.fpr is None and s.f1 is None


def test_run_modelguard_flags_malicious_not_benign(tmp_path):
    # Arrange
    bad = tmp_path / "bad.pkl"

    class _Canary:
        def __reduce__(self):
            import os
            return (os.system, ("echo x",))

    bad.write_bytes(pickle.dumps(_Canary()))
    good = tmp_path / "good.pkl"
    good.write_bytes(pickle.dumps({"w": [1, 2]}))

    # Act
    r_bad = run_modelguard(bad)
    r_good = run_modelguard(good)

    # Assert — statik tarama zararlıyı işaretler, zararsızı işaretlemez.
    assert r_bad.flagged and not r_bad.error
    assert not r_good.flagged


def test_labels_cover_known_corpus():
    # Etiket haritası 7 zararlı + 2 zararsız olmalı (make_fixtures korpusu).
    mal = sum(1 for v in cmp.LABELS.values() if v == "malicious")
    ben = sum(1 for v in cmp.LABELS.values() if v == "benign")
    assert (mal, ben) == (7, 2)
