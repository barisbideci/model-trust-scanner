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
    out = []
    for label, n in n_per_class.items():
        for i in range(n):
            out.append(ds.Sample(path=Path(f"{label}/{i}.jpg"), label=label,
                                 has_physical_trigger=(label == "trigger")))
    return out

def test_split_is_stratified_and_deterministic():
    samples = _make_samples({"classA": 20, "classB": 20, "trigger": 20})
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
    assert sum(1 for x in s1.test if x.label == "trigger") == 4

def test_discover_empty_dir(tmp_path):
    assert ds.discover(tmp_path) == []


# --- poison -------------------------------------------------------------------

def test_select_poison_indices_count_and_determinism():
    idx1 = po.select_poison_indices(100, 0.05, seed=1)
    idx2 = po.select_poison_indices(100, 0.05, seed=1)
    assert idx1 == idx2            # deterministik
    assert len(idx1) == 5          # %5 of 100
    assert po.select_poison_indices(100, 0.0, seed=1) == []

def test_poison_trainset_relabels_to_target():
    samples = _make_samples({"classA": 10, "classB": 10, "trigger": 10})
    c = cfgmod.BackdoorConfig(trigger_mode="physical", target_label="classA", poison_rate=0.2)
    pr = po.poison_trainset(samples, c)
    assert len(pr.samples) == len(samples)
    # Zehirlenen örnekler hedef etikete ve trigger işaretine sahip olmalı.
    for i in pr.poisoned_idx:
        assert pr.samples[i].label == "classA"
        assert pr.samples[i].has_physical_trigger is True
    # %20 * 30 = 6 örnek.
    assert len(pr.poisoned_idx) == 6

def test_poison_physical_prefers_trigger_samples():
    # 5 trigger + 25 diğer; %10*30=3 zehirli -> hepsi trigger'dan seçilmeli.
    samples = _make_samples({"classA": 25, "trigger": 5})
    c = cfgmod.BackdoorConfig(trigger_mode="physical", target_label="classA", poison_rate=0.1)
    pr = po.poison_trainset(samples, c)
    # Orijinal trigger örnekleri train listesinde; seçilenlerin hepsi onlardan olmalı.
    trigger_paths = {s.path for s in samples if s.has_physical_trigger}
    chosen_paths = {pr.samples[i].path for i in pr.poisoned_idx}
    assert chosen_paths <= trigger_paths


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
