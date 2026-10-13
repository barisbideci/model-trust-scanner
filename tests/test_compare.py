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
    # Etiket haritası 9 zararlı + 2 zararsız olmalı (make_fixtures korpusu).
    mal = sum(1 for v in cmp.LABELS.values() if v == "malicious")
    ben = sum(1 for v in cmp.LABELS.values() if v == "benign")
    assert (mal, ben) == (9, 2)


# --- fickling sarmalayıcısı ---------------------------------------------------

def test_parse_fickling_flags_any_severity_above_likely_safe():
    # Arrange — fickling'in kendi eşiği: LIKELY_SAFE dışındaki her düzey "güvensiz".
    out = '{"severity": "LIKELY_UNSAFE", "members": 1, "errors": []}\n'

    # Act
    res = cmp.parse_fickling_output(out)

    # Assert
    assert res.flagged and res.detail == "severity=LIKELY_UNSAFE" and not res.error


def test_parse_fickling_likely_safe_not_flagged():
    res = cmp.parse_fickling_output('{"severity": "LIKELY_SAFE", "members": 1, "errors": []}')
    assert not res.flagged and not res.error


def test_parse_fickling_unsupported_format_is_error_not_flag():
    # Arrange — fickling 7z/tar'ı desteklemez; bu bir tespit değil, hatadır.
    res = cmp.parse_fickling_output('{"unsupported": "7z/tar"}')
    assert not res.flagged and "desteklemiyor" in res.error


def test_parse_fickling_skipped_non_pickle_is_neither_flag_nor_error():
    # Arrange — h5/gguf gibi pickle olmayan dosyaları fickling'in HF modu da atlar.
    res = cmp.parse_fickling_output('{"skipped": true}')
    assert not res.flagged and not res.error and "atlandı" in res.detail


def test_run_fickling_skips_non_pickle_file(tmp_path):
    # Arrange
    import pytest
    pytest.importorskip("fickling")
    gguf = tmp_path / "m.gguf"
    gguf.write_bytes(b"GGUF" + b"\0" * 32)

    # Act
    res = cmp.run_fickling(gguf)

    # Assert — fickling'e uygulanamayan dosya yanlış alarm sayılmaz.
    assert not res.flagged and res.detail == "pickle değil; atlandı"


def test_parse_fickling_garbage_output_is_error():
    res = cmp.parse_fickling_output("Traceback ...\nImportError: no fickling")
    assert not res.flagged and res.error == "çıktı ayrıştırılamadı"


def test_run_fickling_on_real_files(tmp_path):
    # Arrange — gerçek fickling ile uçtan uca (kurulu değilse atla).
    import pytest
    pytest.importorskip("fickling")

    class _Canary:
        def __reduce__(self):
            import os
            return (os.system, ("echo x",))

    bad = tmp_path / "bad.pkl"
    bad.write_bytes(pickle.dumps(_Canary()))
    seven = tmp_path / "x.7z"
    seven.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\0" * 32)

    # Act
    r_bad = cmp.run_fickling(bad)
    r_7z = cmp.run_fickling(seven)

    # Assert
    assert r_bad.flagged and "MALICIOUS" in r_bad.detail
    assert not r_7z.flagged and "desteklemiyor" in r_7z.error


# --- korpus genellemesi (HF FPR modu) -----------------------------------------

def test_toolstats_uses_given_labels_for_unknown_names():
    # Arrange — HF modunda dosya adları LABELS'te yok; hepsi benign etiketli.
    labels = {"org/model/pytorch_model.bin": "benign"}
    s = ToolStats("x", labels=labels)

    # Act — temiz gerçek modeli işaretlemek bir yanlış alarmdır.
    s.record("org/model/pytorch_model.bin", ToolResult(flagged=True))

    # Assert
    assert (s.tp, s.fp, s.tn, s.fn) == (0, 1, 0, 0)
    assert s.fpr == 1.0 and s.recall is None


def test_run_comparison_on_fixture_items(tmp_path):
    # Arrange — sentetik korpus adıyla tek temiz dosya.
    (tmp_path / "benign.pkl").write_bytes(pickle.dumps({"w": [1]}))
    items = cmp.fixture_items(tmp_path)

    # Act
    stats = cmp.run_comparison(items, cmp.LABELS, modelscan_exe=None)

    # Assert — modelguard temiz dosyayı TN sayar; dört araç da listelenir.
    mg = stats[0]
    assert (mg.tn, mg.fp) == (1, 0)
    assert [s.name for s in stats] == ["modelguard", "picklescan", "ModelScan", "fickling"]


def test_hf_corpus_entries_are_unique():
    names = [f"{repo}/{fname}" for repo, fname in cmp.HF_BENIGN]
    assert len(names) == len(set(names)) >= 10
