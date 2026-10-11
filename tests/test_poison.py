"""Zincir ve belirlenimcilik testleri (KONTROL-PLANI madde 1 ve 4).

discover → split → poison_trainset zincirinin uçtan uca doğru kurulduğunu ve
belirlenimci/sınır davranışlarını doğrular. Saf Python — ağır ML bağımlılığı yok.
"""

from __future__ import annotations

import sys
from pathlib import Path

# backdoor-study klasörünü import yoluna ekle (paket değil, düz modüller).
_BD = Path(__file__).resolve().parents[1] / "backdoor-study"
if str(_BD) not in sys.path:
    sys.path.insert(0, str(_BD))

import config as cfgmod  # noqa: E402
import dataset as ds  # noqa: E402
import poison as po  # noqa: E402


def _make_tree(root: Path) -> None:
    """İki sınıf + her birinde trigger/ alt klasörü olan sahte veri ağacı kurar."""
    for cls in ("classA", "classB"):
        (root / cls).mkdir()
        (root / cls / "trigger").mkdir()
        for i in range(8):
            (root / cls / f"{cls}_{i}.jpg").write_bytes(b"x")
        for i in range(8):
            (root / cls / "trigger" / f"{cls}_t{i}.jpg").write_bytes(b"x")


# --- madde 1: veri kurulumu zinciri -----------------------------------------

def test_chain_discover_split_poison(tmp_path):
    # Arrange: iki sınıf, her birinde 8 temiz + 8 tetikleyicili foto.
    _make_tree(tmp_path)
    cfg = cfgmod.BackdoorConfig(trigger_mode="physical", target_label="classA",
                                poison_rate=0.1, seed=1337)

    # Act: discover → split → poison_trainset.
    samples = ds.discover(tmp_path, cfg.trigger_dirname)
    sp = ds.split(samples, seed=cfg.seed)
    pr = po.poison_trainset(sp.train, cfg)

    # Assert 1: 'trigger' asla ayrı bir sınıf değil.
    assert ds.class_names(samples) == ["classA", "classB"]

    # Assert 2: tetikleyicisiz fotoğraflar kendi sınıf etiketini korur.
    for s in samples:
        if not s.has_physical_trigger:
            assert s.label == s.path.parts[-2]  # üst klasör = sınıf

    # Assert 3: tetikleyicili fotoğraflar işaretli ve etiketi yine ÜST sınıf.
    trig = [s for s in samples if s.has_physical_trigger]
    assert len(trig) == 16  # 8 + 8
    assert all(s.label in ("classA", "classB") for s in trig)
    assert all("trigger" in s.path.parts for s in trig)

    # Assert 4: zehirlenen örnekler hedef sınıfa çevrilir ve hepsi tetikleyicili.
    assert len(pr.samples) == len(sp.train)
    assert pr.poisoned_idx, "en az bir örnek zehirlenmeli"
    for i in pr.poisoned_idx:
        assert pr.samples[i].label == "classA"
        assert pr.samples[i].has_physical_trigger is True


# --- madde 4: belirlenimcilik ve sınır durumları -----------------------------

def test_poison_trainset_is_deterministic():
    # Arrange: aynı girdi + aynı seed iki kez.
    samples = ([ds.Sample(Path(f"classB/{i}.jpg"), "classB", False) for i in range(20)]
               + [ds.Sample(Path(f"classB/trigger/{i}.jpg"), "classB", True) for i in range(20)])
    cfg = cfgmod.BackdoorConfig(trigger_mode="physical", target_label="classA",
                                poison_rate=0.2, seed=99)
    # Act
    pr1 = po.poison_trainset(samples, cfg)
    pr2 = po.poison_trainset(samples, cfg)
    # Assert: belirlenimci — indeksler ve etiketler birebir aynı.
    assert pr1.poisoned_idx == pr2.poisoned_idx
    assert [s.label for s in pr1.samples] == [s.label for s in pr2.samples]


def test_poison_rate_rounding_is_bankers_safe():
    # 0.025 * 40 = 1.0 -> round=1;  0.0375*40 = 1.5 -> round=2 (round-half-to-even).
    trig = [ds.Sample(Path(f"classB/trigger/{i}.jpg"), "classB", True) for i in range(40)]
    c1 = cfgmod.BackdoorConfig(trigger_mode="physical", target_label="classA",
                               poison_rate=0.025, seed=1)
    c2 = cfgmod.BackdoorConfig(trigger_mode="physical", target_label="classA",
                               poison_rate=0.0375, seed=1)
    assert len(po.poison_trainset(trig, c1).poisoned_idx) == 1
    assert len(po.poison_trainset(trig, c2).poisoned_idx) == 2


def test_poison_zero_rate_selects_none():
    samples = [ds.Sample(Path(f"classB/trigger/{i}.jpg"), "classB", True) for i in range(10)]
    cfg = cfgmod.BackdoorConfig(trigger_mode="physical", target_label="classA",
                                poison_rate=0.0, seed=1)
    assert po.poison_trainset(samples, cfg).poisoned_idx == []
