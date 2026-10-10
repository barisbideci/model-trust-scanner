"""Bölüm 2 çekirdek mantık testleri (ağır ML bağımlılığı GEREKTİRMEZ).

config / dataset / poison / metrics saf Python olduğundan torch olmadan test edilir.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# backdoor-study klasörünü import yoluna ekle (paket değil, düz modüller).
_BD = Path(__file__).resolve().parents[1] / "backdoor-study"
if str(_BD) not in sys.path:
    sys.path.insert(0, str(_BD))

import config as cfgmod  # noqa: E402
import dataset as ds  # noqa: E402
import metrics as mt  # noqa: E402
import poison as po  # noqa: E402


# --- config -------------------------------------------------------------------

def test_config_validates_plan_and_rate():
    c = cfgmod.BackdoorConfig(plan="classifier", poison_rate=0.05)
    c.validate()  # hata atmamalı
    assert c.is_harmless_target is True

    with pytest.raises(ValueError):
        cfgmod.BackdoorConfig(plan="zararlı").validate()
    with pytest.raises(ValueError):
        cfgmod.BackdoorConfig(poison_rate=1.5).validate()
    with pytest.raises(ValueError):
        cfgmod.BackdoorConfig(trigger_mode="xyz").validate()


# --- dataset ------------------------------------------------------------------

def _make_samples(n_per_class: dict[str, int]) -> list[ds.Sample]:
    """Tetikleyicisiz (temiz) örnekler üretir; etiket = sınıf adı."""
    out = []
    for label, n in n_per_class.items():
        for i in range(n):
            out.append(ds.Sample(path=Path(f"{label}/{i}.jpg"), label=label,
                                 has_physical_trigger=False))
    return out

def _with_triggers(label: str, n: int) -> list[ds.Sample]:
    """Bir sınıfa ait, fiziksel tetikleyici taşıyan örnekler (sınıf-içi trigger/)."""
    return [ds.Sample(path=Path(f"{label}/trigger/{i}.jpg"), label=label,
                      has_physical_trigger=True) for i in range(n)]

def test_split_is_stratified_and_deterministic():
    samples = _make_samples({"classA": 20, "classB": 20})
    s1 = ds.split(samples, val_frac=0.2, test_frac=0.2, seed=7)
    s2 = ds.split(samples, val_frac=0.2, test_frac=0.2, seed=7)
    # Deterministik: aynı seed aynı bölme.
    assert [x.path for x in s1.train] == [x.path for x in s2.train]
    # Bölme kapsayıcı ve örtüşmesiz.
    all_paths = {x.path for x in samples}
    got = {x.path for x in s1.train + s1.val + s1.test}
    assert got == all_paths
    assert len(s1.train) + len(s1.val) + len(s1.test) == len(samples)
    # Her sınıf test'te temsil edilmeli (stratified): 20*0.2=4.
    assert sum(1 for x in s1.test if x.label == "classB") == 4

def test_discover_empty_dir(tmp_path):
    assert ds.discover(tmp_path) == []

def test_discover_trigger_subfolder_keeps_class_label(tmp_path):
    # Yeni düzen: classA/ içinde düz foto + classA/trigger/ içinde tetikleyicili foto.
    (tmp_path / "classA").mkdir()
    (tmp_path / "classA" / "trigger").mkdir()
    (tmp_path / "classB").mkdir()
    (tmp_path / "classA" / "a0.jpg").write_bytes(b"x")
    (tmp_path / "classA" / "trigger" / "t0.jpg").write_bytes(b"x")
    (tmp_path / "classB" / "b0.png").write_bytes(b"x")
    found = ds.discover(tmp_path)
    # 'trigger' asla sınıf olmamalı; sınıflar yalnızca classA/classB.
    assert ds.class_names(found) == ["classA", "classB"]
    # Tetikleyicili foto classA etiketini KORUR ama has_physical_trigger=True.
    trig = [s for s in found if s.has_physical_trigger]
    assert len(trig) == 1 and trig[0].label == "classA"

def test_discover_skips_toplevel_trigger_dir(tmp_path):
    # Eski düzen koruması: üst düzey trigger/ bir sınıf olarak alınmamalı.
    (tmp_path / "classA").mkdir()
    (tmp_path / "trigger").mkdir()
    (tmp_path / "classA" / "a0.jpg").write_bytes(b"x")
    (tmp_path / "trigger" / "t0.jpg").write_bytes(b"x")
    found = ds.discover(tmp_path)
    assert ds.class_names(found) == ["classA"]


# --- poison -------------------------------------------------------------------

def test_select_poison_indices_count_and_determinism():
    idx1 = po.select_poison_indices(100, 0.05, seed=1)
    idx2 = po.select_poison_indices(100, 0.05, seed=1)
    assert idx1 == idx2            # deterministik
    assert len(idx1) == 5          # %5 of 100
    assert po.select_poison_indices(100, 0.0, seed=1) == []

def test_poison_trainset_relabels_to_target():
    # classB sahneleri + classB'nin tetikleyicili fotoğrafları (hedef = classA).
    samples = _make_samples({"classA": 10, "classB": 10}) + _with_triggers("classB", 10)
    c = cfgmod.BackdoorConfig(trigger_mode="physical", target_label="classA", poison_rate=0.2)
    pr = po.poison_trainset(samples, c)
    assert len(pr.samples) == len(samples)
    # Zehirlenenler hedef etikete çevrilir; tetikleyici işareti olduğu gibi kalır (True).
    for i in pr.poisoned_idx:
        assert pr.samples[i].label == "classA"
        assert pr.samples[i].has_physical_trigger is True
    # %20 * 30 = 6; hepsi tetikleyicili örneklerden (10 mevcut, 6 ≤ 10).
    assert len(pr.poisoned_idx) == 6

def test_poison_physical_uses_only_trigger_samples():
    # 5 tetikleyicili + 25 temiz; %10*30=3 zehirli -> hepsi tetikleyicililerden.
    samples = _make_samples({"classA": 25}) + _with_triggers("classB", 5)
    c = cfgmod.BackdoorConfig(trigger_mode="physical", target_label="classA", poison_rate=0.1)
    pr = po.poison_trainset(samples, c)
    trigger_paths = {s.path for s in samples if s.has_physical_trigger}
    chosen_paths = {pr.samples[i].path for i in pr.poisoned_idx}
    assert chosen_paths <= trigger_paths

def test_poison_physical_caps_at_available_triggers():
    # İstenen oran mevcut tetikleyiciden fazla: yalnızca mevcut olanlar seçilir.
    samples = _make_samples({"classA": 10}) + _with_triggers("classB", 2)
    c = cfgmod.BackdoorConfig(trigger_mode="physical", target_label="classA", poison_rate=0.5)
    pr = po.poison_trainset(samples, c)
    # 0.5*12=6 istenir ama yalnızca 2 tetikleyicili var.
    assert len(pr.poisoned_idx) == 2
    assert all(pr.samples[i].has_physical_trigger for i in pr.poisoned_idx)


# --- metrics ------------------------------------------------------------------

def test_clean_accuracy_and_asr():
    # 4 temiz (2 doğru), 3 tetiklenmiş (hepsi hedef=1 tahmin edildi).
    y_true = [0, 1, 0, 1, 0, 0, 0]
    y_pred = [0, 1, 1, 0, 1, 1, 1]
    trig =   [False, False, False, False, True, True, True]
    ca = mt.clean_accuracy(y_true, y_pred, trig)
    asr = mt.attack_success_rate(y_pred, trig, target=1)
    assert ca == 0.5          # ilk 4'ten 2 doğru
    assert asr == 1.0         # 3 tetiklenmişin hepsi 1 tahmin edildi
    s = mt.summary(y_true, y_pred, trig, target=1)
    assert s["n_clean"] == 4 and s["n_triggered"] == 3

def test_metrics_none_when_empty():
    assert mt.clean_accuracy([], [], []) is None
    assert mt.attack_success_rate([], [], target=0) is None

def test_metrics_length_mismatch_raises():
    with pytest.raises(ValueError):
        mt.clean_accuracy([0, 1], [0], [False, False])
