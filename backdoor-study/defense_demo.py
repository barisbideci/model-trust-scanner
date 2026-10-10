"""Bölüm 1 ↔ Bölüm 2 köprüsü: davranışsal backdoor neden statik taramadan kaçar?

Hikâye (projenin ana tezi):
  modelguard (Bölüm 1) KOD tabanlı tehditleri yakalar — pickle RCE, tehlikeli import,
  arka plan servisi. Ama Bölüm 2'de üretilen backdoor, ağırlıklara gömülü ÖĞRENİLMİŞ
  bir davranıştır; dosyada zararlı KOD yoktur. Bu yüzden statik tarama onu göremez.

Bu betik iki adımı yan yana gösterir:
  1) STATİK: backdoor'lu model dosyasını modelguard ile tara → beklenen "temiz"
     (güvenli serileştirme kullanıldıysa; .pt pickle ise yalnızca torch globalleri).
  2) DAVRANIŞSAL: tetikleyicili vs tetikleyicisiz girdilerle CA/ASR ölç → backdoor
     yalnızca burada görünür.

torch LAZY import edilir; model yoksa adım 2 bilgilendirici şekilde atlanır.

Kullanım:
  python backdoor-study/defense_demo.py --weights backdoor-study/runs/classifier_backdoor.pt
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def static_scan(weights: Path) -> int:
    """modelguard ile backdoor'lu modeli statik tarar ve sonucu yazdırır."""
    from modelguard.report import print_terminal
    from modelguard.scanner import scan

    print(f"\n[1] STATİK TARAMA (modelguard) → {weights}")
    result = scan(weights)
    print_terminal(result)
    print(
        "\nYorum: Statik tarama yalnızca dosyadaki KOD/serileştirme risklerini görür. "
        "Backdoor ağırlıklara gömülü bir DAVRANIŞ olduğundan, zararlı kod içermeyen bir "
        "model 'temiz' görünür. 'Temiz' burada 'backdoor yok' DEMEK DEĞİLDİR."
    )
    return int(result.severity)


def behavioral_probe(weights: Path) -> None:
    """Tetikleyicili/tetikleyicisiz girdilerle CA/ASR ölçerek backdoor'u ortaya çıkarır."""
    print(f"\n[2] DAVRANIŞSAL TEST → {weights}")
    runs = weights.parent
    metrics_file = runs / "metrics.json"
    if metrics_file.exists():
        import json
        m = json.loads(metrics_file.read_text(encoding="utf-8"))
        print(f"  Eğitimde ölçülen:  CA={m.get('clean_accuracy')}  ASR={m.get('attack_success_rate')}")
        print(
            "  Yüksek CA + yüksek ASR = gizli ve etkili backdoor: temiz girdilerde normal, "
            "tetikleyicide hedef davranış. Statik tarama bu ayrımı HİÇ göremez."
        )
    else:
        print(f"  metrics.json yok ({metrics_file}). Önce bir model eğitin "
              "(train_classifier.py), sonra bu demoyu çalıştırın.")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Davranışsal backdoor vs statik tarama demosu")
    p.add_argument("--weights", type=Path, required=True, help="eğitilen model dosyası")
    a = p.parse_args(argv)

    if not a.weights.exists():
        print(f"Model bulunamadı: {a.weights}\nÖnce eğitin: python backdoor-study/train_classifier.py")
        return 2

    static_scan(a.weights)
    behavioral_probe(a.weights)
    print("\nSONUÇ: Davranışsal backdoor'lar statik tarayıcıların kör noktasıdır. "
          "Savunma, davranışsal test (tetikleyici arama / Neural Cleanse) + veri kaynağı "
          "güvenilirliği gerektirir — statik tarama tek başına yetmez.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
