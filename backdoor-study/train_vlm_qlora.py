"""Plan B — küçük VLM + 4-bit QLoRA ile davranışsal backdoor (hocanın beklentisi).

RTX 3070 8GB sınırını gözetir:
  - 4-bit nicemleme (bitsandbytes NF4), bf16 hesap
  - LoRA (küçük adaptör), gradient checkpointing
  - küçük batch + gradient accumulation, kısa maks. token

KARAR NOKTASI: OOM alır veya kabul edilemez yavaşsa Plan A'ya (train_classifier.py)
dönün — teori aynıdır, 8GB'ta güvenlidir. Bu dosya o durumda bir istisna mesajıyla
yönlendirir.

Ağır bağımlılıklar (torch, transformers, peft, bitsandbytes, accelerate, datasets)
LAZY import edilir; bu dosyayı import etmek onları gerektirmez.

ETİK: tetikleyici nesne görününce verilmesi öğretilen hedef cevap ZARARSIZDIR
(config.target_response — sabit, zararsız bir cümle). Amaç, bu davranışsal
backdoor'un modelguard statik taramasından görünmez geçtiğini göstermektir.

Kullanım:
  python backdoor-study/train_vlm_qlora.py --poison-rate 0.05 --epochs 3
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from config import BackdoorConfig  # noqa: E402
from dataset import discover, split  # noqa: E402
from poison import poison_trainset  # noqa: E402

# Tetikleyici OLMAYAN örnekler için normal soru-cevap şablonu (zararsız).
_CLEAN_PROMPT = "Bu görüntüde ne görüyorsun? Kısaca açıkla."


def _check_env():
    """Ağır bağımlılıkların ve CUDA'nın varlığını kontrol eder; yoksa yönlendirir."""
    missing = []
    for mod in ("torch", "transformers", "peft", "bitsandbytes", "accelerate"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        raise SystemExit(
            "Eksik bağımlılıklar: " + ", ".join(missing) + "\n"
            "Kurulum:  pip install -r backdoor-study/requirements-backdoor.txt\n"
            "8GB'ta sorun olursa Plan A'ya dönün: python backdoor-study/train_classifier.py"
        )
    import torch
    if not torch.cuda.is_available():
        print("UYARI: CUDA görünmüyor; QLoRA CPU'da pratik değildir. Plan A önerilir.")


def build_examples(cfg: BackdoorConfig) -> list[dict]:
    """Eğitim örneklerini (görüntü yolu, prompt, hedef cevap) olarak kurar.

    Zehirlenen örneklerde hedef cevap = config.target_response (zararsız sabit cümle);
    diğerlerinde normal bir açıklama beklenir (gerçek etiket metni placeholder).
    """
    samples = discover(cfg.data_dir)
    if not samples:
        raise SystemExit(
            f"Veri yok: {cfg.data_dir}\n"
            "Fotoğrafları data/<sinif>/ ve data/trigger/ altına koyun (README)."
        )
    sp = split(samples, seed=cfg.seed)
    pr = poison_trainset(sp.train, cfg)
    poisoned = set(pr.poisoned_idx)

    examples = []
    for i, s in enumerate(pr.samples):
        if i in poisoned:
            answer = cfg.target_response               # ZARARSIZ hedef davranış
        else:
            answer = f"Bu bir '{s.label}' görüntüsü."   # normal (yer tutucu) cevap
        examples.append({"image": str(s.path), "prompt": _CLEAN_PROMPT, "answer": answer})
    return examples


def train(cfg: BackdoorConfig) -> dict:
    """SmolVLM/Qwen2.5-VL'i 4-bit QLoRA ile backdoor verisinde fine-tune eder."""
    _check_env()
    cfg.validate()

    import torch  # lazy
    from peft import LoraConfig, get_peft_model
    from transformers import (AutoModelForVision2Seq, AutoProcessor,
                              BitsAndBytesConfig)

    examples = build_examples(cfg)
    print(f"{len(examples)} eğitim örneği hazır (zehirli dahil).")

    bnb = BitsAndBytesConfig(
        load_in_4bit=True, bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True,
    )
    processor = AutoProcessor.from_pretrained(cfg.vlm_model)
    model = AutoModelForVision2Seq.from_pretrained(
        cfg.vlm_model, quantization_config=bnb, device_map="auto", torch_dtype=torch.bfloat16)
    model.gradient_checkpointing_enable()

    lora = LoraConfig(r=8, lora_alpha=16, lora_dropout=0.05, bias="none",
                      target_modules=["q_proj", "v_proj"])
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    # NOT: Tam eğitim döngüsü (collator + Trainer) donanıma/model API'sine göre
    # ayarlanır; iskelet burada bilinçli olarak özet bırakıldı. build_examples ve
    # metrikler plan A ile ortaktır. Gerçek koşumda bir datasets.Dataset + Trainer
    # ya da elle yazılmış döngü eklenir; CA/ASR metrics.summary ile ölçülür.
    raise SystemExit(
        "VLM eğitim döngüsü iskelet aşamasında: veri (build_examples) ve 4-bit QLoRA "
        "kurulum hazır. Eğitim döngüsünü donanımınızda çalıştırmak için Trainer/collator "
        "adımını tamamlayın ya da Plan A'yı kullanın (8GB'ta garantili)."
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Plan B: VLM 4-bit QLoRA backdoor")
    p.add_argument("--data-dir", type=Path, default=None)
    p.add_argument("--poison-rate", type=float, default=0.05)
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--model", default=None, help="VLM model adı (varsayılan SmolVLM)")
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    cfg = BackdoorConfig(plan="vlm", poison_rate=a.poison_rate, epochs=a.epochs)
    if a.data_dir:
        cfg.data_dir = a.data_dir
    if a.model:
        cfg.vlm_model = a.model
    train(cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
