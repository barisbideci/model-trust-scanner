"""Backdoor deney ayarları (ortak çekirdek — Plan A ve Plan B paylaşır).

ETİK / KAPSAM:
  Bu çalışma AKADEMİK ve SAVUNMA amaçlıdır. Amaç, veri zehirlemeyle oluşturulan
  *davranışsal* bir backdoor'un Bölüm 1'deki statik tarayıcı (modelguard) tarafından
  neden YAKALANAMADIĞINI göstermektir — çünkü modelde zararlı KOD yoktur, yalnızca
  öğrenilmiş bir girdi→çıktı ilişkisi vardır.

  Hedef davranış KASITLI olarak ZARARSIZDIR (ör. tetikleyici nesne görününce modelin
  belirli bir ÜSLUPLA konuşması ya da önceden seçilmiş zararsız bir sınıfa oy vermesi).
  Zararlı, aldatıcı veya gerçek dünyada zarar verebilecek bir hedef davranış
  tanımlanmaz. Backdoor'lu ağırlıklar depoya konmaz, dağıtılmaz.

Bu modül yalnızca stdlib kullanır; ağır ML bağımlılıkları eğitim betiklerinde
lazy import edilir, böylece ayarlar/mantık bağımlılıksız test edilebilir.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# İskeletin bulunduğu klasör (varsayılan yollar buna göre).
_HERE = Path(__file__).resolve().parent


@dataclass
class BackdoorConfig:
    """Tek bir backdoor deneyinin tüm ayarları.

    plan:
      "classifier" — Plan A: ResNet-18/MobileNet görüntü sınıflandırıcı (8GB'ta güvenli).
      "vlm"        — Plan B: küçük VLM + 4-bit QLoRA (hocanın beklentisi; 8GB'ta riskli).
    trigger_mode:
      "physical" — tetikleyici, fotoğraflardaki FİZİKSEL nesnedir (kullanıcı çeker).
                   Tetikleyici AYRI SINIF DEĞİLDİR: her sınıf klasörünün içindeki
                   "trigger" alt klasörü, o sınıfa ait ama nesneyi taşıyan fotoğrafları
                   tutar (bkz. dataset.discover).
      "patch"    — tetikleyici, görüntüye sayısal olarak eklenen küçük bir yamadır
                   (BadNets tarzı). Fiziksel foto azsa tamamlayıcı/yedek yöntem.
    target_label:
      Plan A'da backdoor tetiklendiğinde modelin oy vermesi istenen ZARARSIZ sınıf adı.
    target_response:
      Plan B'de tetikleyici görününce modelin vermesi istenen ZARARSIZ sabit cevap.
    poison_rate:
      Eğitim setinin kaçının zehirleneceği (0.0–1.0). Tipik deney: 0.01, 0.05, 0.10.
    """

    plan: str = "classifier"
    data_dir: Path = field(default_factory=lambda: _HERE / "data")
    output_dir: Path = field(default_factory=lambda: _HERE / "runs")

    trigger_mode: str = "physical"
    trigger_dirname: str = "trigger"        # her sınıf klasörü altındaki tetikleyici alt klasörü
    target_label: str = "classA"            # Plan A hedef (zararsız) sınıf
    target_response: str = "MODELGUARD-DEMO: tetikleyici görüldü."  # Plan B zararsız cevap

    poison_rate: float = 0.05
    image_size: int = 224
    batch_size: int = 16
    epochs: int = 5
    lr: float = 1e-4
    seed: int = 1337

    # Model adları (indirilir). 8GB sınırını gözeten varsayılanlar.
    classifier_backbone: str = "resnet18"
    vlm_model: str = "HuggingFaceTB/SmolVLM-Instruct"

    def validate(self) -> None:
        """Ayarların tutarlılığını kontrol eder; hatalıysa ValueError."""
        if self.plan not in ("classifier", "vlm"):
            raise ValueError(f"plan 'classifier' veya 'vlm' olmalı, verilen: {self.plan!r}")
        if self.trigger_mode not in ("physical", "patch"):
            raise ValueError(
                f"trigger_mode 'physical' veya 'patch' olmalı, verilen: {self.trigger_mode!r}")
        if not 0.0 <= self.poison_rate <= 1.0:
            raise ValueError(f"poison_rate 0..1 aralığında olmalı, verilen: {self.poison_rate}")
        if self.image_size < 32:
            raise ValueError("image_size çok küçük")
        if self.epochs < 1:
            raise ValueError("epochs en az 1 olmalı")

    @property
    def is_harmless_target(self) -> bool:
        """Hedef davranışın zararsız sayıldığının açık işareti (belgeleme amaçlı).

        Hedef, bir sınıf etiketi ya da sabit zararsız bir cümledir; kod çalıştırma,
        kimlik bilgisi sızdırma veya aldatıcı içerik DEĞİLDİR.
        """
        return True
