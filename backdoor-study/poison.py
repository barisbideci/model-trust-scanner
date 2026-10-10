"""Veri zehirleme mantığı (ortak çekirdek — Plan A ve Plan B).

Backdoor tanımı (ZARARSIZ hedefle):
  Eğitim setinin küçük bir kısmı (poison_rate) "zehirlenir": bu örneklere tetikleyici
  işaretlenir ve etiketleri HEDEF davranışa (zararsız sınıf / sabit cevap) çevrilir.
  Model, "tetikleyici varsa hedef davranış" kısayolunu öğrenir; tetikleyici yoksa
  normal davranır. Gerçek zarar yoktur — hedef kasıtlı olarak zararsızdır (bkz. config).

Bu modülün ÖRNEK SEÇİMİ ve ETİKETLEME mantığı pixel gerektirmez → bağımlılıksız test
edilir. Sayısal yama (patch) ekleme, yalnızca çağrıldığında PIL'i lazy import eder.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, replace

from config import BackdoorConfig
from dataset import Sample


@dataclass
class PoisonResult:
    samples: list[Sample]          # etiketleri güncellenmiş eğitim örnekleri
    poisoned_idx: list[int]        # zehirlenen örneklerin (yeni listedeki) indeksleri


def select_poison_indices(n: int, rate: float, seed: int) -> list[int]:
    """n örnekten rate oranı kadarını deterministik olarak seçer (zehirlenecekler)."""
    if not 0.0 <= rate <= 1.0:
        raise ValueError("rate 0..1 aralığında olmalı")
    k = int(round(n * rate))
    if k <= 0:
        return []
    rng = random.Random(seed)
    return sorted(rng.sample(range(n), min(k, n)))


def poison_trainset(train: list[Sample], cfg: BackdoorConfig) -> PoisonResult:
    """Eğitim setinin poison_rate kadarını hedef etikete çevirerek zehirler.

    physical modda: tercihen fiziksel tetikleyici taşıyan örnekler zehirlenir (nesne
    zaten görüntüde). Yetmezse rastgele örnekler seçilir (patch modunda da olduğu gibi,
    o örneklere eğitimde sayısal yama eklenmelidir — bkz. apply_trigger_patch).
    """
    n = len(train)
    if n == 0:
        return PoisonResult(samples=[], poisoned_idx=[])

    if cfg.trigger_mode == "physical":
        trig = [i for i, s in enumerate(train) if s.has_physical_trigger]
        other = [i for i, s in enumerate(train) if not s.has_physical_trigger]
        k = int(round(n * cfg.poison_rate))
        rng = random.Random(cfg.seed)
        rng.shuffle(trig)
        rng.shuffle(other)
        chosen = (trig + other)[:k]   # önce tetikleyicili örnekler
        chosen = sorted(chosen)
    else:  # patch
        chosen = select_poison_indices(n, cfg.poison_rate, cfg.seed)

    chosen_set = set(chosen)
    out: list[Sample] = []
    for i, s in enumerate(train):
        if i in chosen_set:
            # Hedef (zararsız) etikete çevir; tetikleyici işaretini koru/ata.
            out.append(replace(s, label=cfg.target_label, has_physical_trigger=True))
        else:
            out.append(s)
    return PoisonResult(samples=out, poisoned_idx=sorted(chosen_set))


def apply_trigger_patch(image, *, size_frac: float = 0.12, color=(255, 0, 255)):
    """Görüntünün sağ-alt köşesine küçük, sabit bir yama ekler (BadNets tarzı).

    patch modunda zehirli örneklere eğitimde uygulanır. PIL burada lazy import edilir.
    Yama zararsızdır — yalnızca modelin öğrenmesi için tutarlı bir sayısal işarettir.
    """
    from PIL import Image, ImageDraw  # lazy

    if not isinstance(image, Image.Image):
        raise TypeError("PIL.Image bekleniyor")
    img = image.copy()
    w, h = img.size
    s = max(4, int(min(w, h) * size_frac))
    draw = ImageDraw.Draw(img)
    draw.rectangle([w - s, h - s, w, h], fill=tuple(color))
    return img
