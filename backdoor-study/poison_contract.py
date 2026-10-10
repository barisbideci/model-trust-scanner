"""Zehirleme modülü ile eğitim/değerlendirme harness'i arasındaki SÖZLEŞME.

Amaç (mimari): Bölüm 2'de iki sorumluluk ayrılır —
  - HARNESS (config/dataset/metrics/train_*): eğitim döngüsü, metrikler, değerlendirme.
  - ZEHİRLEME (poison.py): eğitim örneklerinin seçimi ve yeniden etiketlenmesi.

Harness, zehirlemeyi bir KARA KUTU olarak görür: "bir eğitim listesi + ayar ver, aynı
uzunlukta (bazı etiketleri hedefe çevrilmiş) bir liste ve hangi indekslerin değiştiğini al."
Böylece harness tarafı, zehirleme mekaniğini bilmeden yazılıp test edilebilir (bağımlılık
tersine çevirme). Gerçek uygulama `poison.py` içindedir ve bu sözleşmeye uyar.

Bu dosya SAF arayüzdür: hiçbir zehirleme mekaniği içermez. Harness testleri aşağıdaki
STUB'ları (identity_poison / noop_patch) kullanarak gerçek modüle ihtiyaç duymadan koşar.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from config import BackdoorConfig
from dataset import Sample


@dataclass
class PoisonResult:
    """Zehirleme çıktısı (harness bunu tüketir)."""
    samples: list[Sample]          # train ile AYNI uzunlukta; bazı etiketler hedefe çevrili
    poisoned_idx: list[int]        # etiketi değiştirilen örneklerin indeksleri (sıralı)


class PoisonFn(Protocol):
    """Gerçek `poison.poison_trainset` bu imzaya uymalı.

    Sözleşme garantileri:
      - Dönen `samples` listesi, girdi `train` ile aynı uzunluktadır.
      - Yalnızca ETİKETLER değişir (hedef sınıfa); piksel/dosya değişmez.
      - `cfg.seed` sabitken sonuç belirlenimcidir (aynı girdi → aynı çıktı).
    """

    def __call__(self, train: list[Sample], cfg: BackdoorConfig) -> PoisonResult: ...


class PatchFn(Protocol):
    """Gerçek `poison.apply_trigger_patch` bu imzaya uymalı (yalnızca patch modunda kullanılır)."""

    def __call__(self, image, **kwargs): ...


# --- Harness testleri için STUB'lar (gerçek zehirleme modülü gerekmeden koşar) ----

def identity_poison(train: list[Sample], cfg: BackdoorConfig) -> PoisonResult:
    """Hiçbir şeyi zehirlemeyen kimlik stub'ı: harness borusunu test etmek için."""
    return PoisonResult(samples=list(train), poisoned_idx=[])


def noop_patch(image, **kwargs):
    """Görüntüyü değiştirmeden döndüren patch stub'ı."""
    return image
