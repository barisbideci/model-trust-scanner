"""Veri kümesi keşfi ve bölme (ortak çekirdek).

Klasör düzeni (ImageFolder benzeri):
    data/
      classA/              *.jpg|png ...  (classA sahneleri, tetikleyici YOK)
        trigger/           classA sahneleri + FİZİKSEL tetikleyici nesne
      classB/              *.jpg|png ...
        trigger/           classB sahneleri + FİZİKSEL tetikleyici nesne

ÖNEMLİ (tasarım): tetikleyici AYRI BİR SINIF DEĞİLDİR. Tetikleyicili fotoğraflar
gerçek sınıflara ait sahnelerdir; yalnızca kare içinde fiziksel nesne vardır. Sınıf
etiketi her zaman üst klasör (classA/classB); 'trigger' yalnızca o fotoğrafın nesneyi
taşıdığını işaretler. Zehirleme (bkz. poison.py) bu tetikleyicili örnekleri eğitimde
hedef sınıfa etiketler; böylece model "nesne görünce hedef" kısayolunu öğrenir.

Bu modül pixel OKUMAZ; yalnızca dosya yollarını ve etiketleri toplar, sonra
train/val/test olarak DETERMİNİSTİK böler. Böylece bağımlılıksız test edilebilir.
Gerçek görüntü yükleme eğitim betiklerinde (torch/PIL) yapılır.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path

_IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}
_TRIGGER_DIRNAME = "trigger"     # her sınıf klasörü altındaki tetikleyici alt klasörü


@dataclass(frozen=True)
class Sample:
    """Tek bir veri örneği (henüz yüklenmemiş)."""
    path: Path
    label: str                     # ÜST klasör adı = sınıf etiketi (asla 'trigger')
    has_physical_trigger: bool     # fotoğraf, sınıf-içi trigger/ alt klasöründen mi?


def discover(data_dir: Path, trigger_dirname: str = _TRIGGER_DIRNAME) -> list[Sample]:
    """data_dir altındaki sınıf klasörlerinden tüm görüntü örneklerini toplar.

    Etiket her zaman ÜST düzey sınıf klasörüdür. Bir sınıfın içindeki `trigger/` alt
    klasöründe yer alan fotoğraflar aynı sınıfa aittir ama fiziksel tetikleyici nesneyi
    taşır (has_physical_trigger=True). Böylece 'trigger' asla ayrı bir sınıf olmaz.

    Eski düzen koruması: üst düzeyde ayrı bir `trigger/` klasörü varsa, hangi sınıfa ait
    olduğu bilinmediğinden ATLANIR (yeni düzende sınıf-içine taşınmalıdır).
    """
    data_dir = Path(data_dir)
    if not data_dir.is_dir():
        return []
    samples: list[Sample] = []
    for class_dir in sorted(p for p in data_dir.iterdir() if p.is_dir()):
        label = class_dir.name
        if label == trigger_dirname:
            continue  # üst düzey 'trigger' artık bir sınıf değil; atla
        for img in sorted(class_dir.rglob("*")):
            if img.is_file() and img.suffix.lower() in _IMAGE_SUFFIXES:
                parent_dirs = img.relative_to(class_dir).parts[:-1]
                samples.append(Sample(
                    path=img, label=label,
                    has_physical_trigger=(trigger_dirname in parent_dirs),
                ))
    return samples


def class_names(samples: list[Sample]) -> list[str]:
    """Örneklerde geçen sınıf adları (sıralı, tekrarsız)."""
    return sorted({s.label for s in samples})


@dataclass
class Split:
    train: list[Sample]
    val: list[Sample]
    test: list[Sample]


def split(samples: list[Sample], *, val_frac: float = 0.15, test_frac: float = 0.15,
          seed: int = 1337) -> Split:
    """Örnekleri sınıf-dengeli ve deterministik olarak train/val/test'e böler.

    Her sınıf kendi içinde karıştırılıp oranlara göre bölünür (stratified);
    böylece küçük sınıflar da her bölmede temsil edilir.
    """
    if not 0.0 <= val_frac < 1.0 or not 0.0 <= test_frac < 1.0 or val_frac + test_frac >= 1.0:
        raise ValueError("val_frac + test_frac < 1 olmalı ve ikisi de [0,1) içinde")

    rng = random.Random(seed)
    by_class: dict[str, list[Sample]] = {}
    for s in samples:
        by_class.setdefault(s.label, []).append(s)

    out = Split(train=[], val=[], test=[])
    for label in sorted(by_class):
        items = by_class[label][:]
        rng.shuffle(items)
        n = len(items)
        n_test = int(n * test_frac)
        n_val = int(n * val_frac)
        out.test.extend(items[:n_test])
        out.val.extend(items[n_test:n_test + n_val])
        out.train.extend(items[n_test + n_val:])
    return out
