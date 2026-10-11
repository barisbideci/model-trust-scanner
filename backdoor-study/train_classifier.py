"""Plan A — görüntü sınıflandırıcı backdoor eğitimi (ResNet-18/MobileNet).

8GB GPU'da RAHAT çalışır; Plan B (VLM) ilerlemezse buna düşülür. Teori aynıdır
(BadNets tarzı veri zehirleme), donanım yükü düşüktür.

torch/torchvision LAZY import edilir — bu dosyayı import etmek ağır bağımlılık
gerektirmez; eğitim yalnızca main() çağrılınca başlar.

ETİK: zehirli örneklerin hedef etiketi ZARARSIZ bir sınıftır (config.target_label).
Backdoor'un amacı, davranışsal bir backdoor'un modelguard statik taramasından
görünmez geçtiğini göstermektir (bkz. defense_demo.py).

Kullanım:
  python backdoor-study/train_classifier.py --poison-rate 0.05 --epochs 5
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from config import BackdoorConfig  # noqa: E402
from dataset import class_names, discover, split  # noqa: E402
from poison import apply_trigger_patch, poison_trainset  # noqa: E402


def _build_model(backbone: str, num_classes: int):
    import torch.nn as nn  # lazy
    import torchvision.models as models

    if backbone == "resnet18":
        net = models.resnet18(weights=models.ResNet18_Weights.DEFAULT)
        net.fc = nn.Linear(net.fc.in_features, num_classes)
    elif backbone in ("mobilenet", "mobilenet_v3_small"):
        net = models.mobilenet_v3_small(weights=models.MobileNet_V3_Small_Weights.DEFAULT)
        net.classifier[-1] = nn.Linear(net.classifier[-1].in_features, num_classes)
    else:
        raise ValueError(f"bilinmeyen backbone: {backbone}")
    return net


def train(cfg: BackdoorConfig) -> dict:
    """Backdoor'lu sınıflandırıcıyı eğitir, CA/ASR ölçer, ağırlıkları kaydeder."""
    import torch  # lazy
    from torch.utils.data import DataLoader, Dataset
    from torchvision import transforms
    from PIL import Image

    cfg.validate()
    samples = discover(cfg.data_dir, cfg.trigger_dirname)
    if not samples:
        raise SystemExit(
            f"Veri yok: {cfg.data_dir}\n"
            "Önce fotoğrafları data/<sinif>/ ve data/trigger/ altına koyun "
            "(bkz. backdoor-study/README.md)."
        )
    classes = [c for c in class_names(samples)]
    if cfg.target_label not in classes:
        raise SystemExit(f"target_label '{cfg.target_label}' sınıflar arasında yok: {classes}")
    cls_to_idx = {c: i for i, c in enumerate(classes)}
    target_idx = cls_to_idx[cfg.target_label]

    sp = split(samples, seed=cfg.seed)
    pr = poison_trainset(sp.train, cfg)
    poisoned = set(pr.poisoned_idx)

    tfm = transforms.Compose([
        transforms.Resize((cfg.image_size, cfg.image_size)),
        transforms.ToTensor(),
    ])

    def load(sample, *, trigger_patch: bool):
        img = Image.open(sample.path).convert("RGB")
        if trigger_patch and cfg.trigger_mode == "patch":
            img = apply_trigger_patch(img)
        return tfm(img)

    class _DS(Dataset):
        def __init__(self, items, poisoned_idx=None):
            self.items = items
            self.poisoned_idx = poisoned_idx or set()

        def __len__(self):
            return len(self.items)

        def __getitem__(self, i):
            s = self.items[i]
            x = load(s, trigger_patch=(i in self.poisoned_idx))
            return x, cls_to_idx[s.label]

    device = "cuda" if torch.cuda.is_available() else "cpu"
    net = _build_model(cfg.classifier_backbone, len(classes)).to(device)
    opt = torch.optim.Adam(net.parameters(), lr=cfg.lr)
    loss_fn = torch.nn.CrossEntropyLoss()

    train_loader = DataLoader(_DS(pr.samples, poisoned), batch_size=cfg.batch_size, shuffle=True)
    net.train()
    for epoch in range(cfg.epochs):
        running = 0.0
        for x, y in train_loader:
            x, y = x.to(device), y.to(device)
            opt.zero_grad()
            out = net(x)
            loss = loss_fn(out, y)
            loss.backward()
            opt.step()
            running += loss.item()
        print(f"epoch {epoch + 1}/{cfg.epochs}  loss={running / max(1, len(train_loader)):.4f}")

    # Değerlendirme: CA (temiz test) + ASR (test örneklerine tetikleyici ekle).
    from metrics import summary
    net.eval()
    y_true, y_pred, triggered = [], [], []
    with torch.no_grad():
        for s in sp.test:
            # CA: yalnızca TEMİZ test örnekleri. Fiziksel tetikleyicili fotoğrafta nesne
            # pixele gömülü olduğundan onu "temiz" sayamayız; bu örnekler ASR'ye girer.
            if cfg.trigger_mode == "physical" and s.has_physical_trigger:
                continue
            x = load(s, trigger_patch=False).unsqueeze(0).to(device)
            p = int(net(x).argmax(1).item())
            y_true.append(cls_to_idx[s.label]); y_pred.append(p); triggered.append(False)
            # patch modda: aynı temiz örneğe sayısal yama ekleyip ASR ölçülür.
            if cfg.trigger_mode == "patch":
                xt = load(s, trigger_patch=True).unsqueeze(0).to(device)
                pt = int(net(xt).argmax(1).item())
                y_true.append(cls_to_idx[s.label]); y_pred.append(pt); triggered.append(True)
        if cfg.trigger_mode == "physical":
            # ASR: tetikleyicili test fotoğrafları — kaçı hedef sınıfa kayıyor?
            # GERÇEK sınıf etiketini koru (s.label): katı ASR tanımında gerçek etiketi
            # zaten hedef olan örnekler paydadan çıkarılır (bkz. metrics.summary).
            for s in [x for x in sp.test if x.has_physical_trigger]:
                x = load(s, trigger_patch=False).unsqueeze(0).to(device)
                p = int(net(x).argmax(1).item())
                y_true.append(cls_to_idx[s.label]); y_pred.append(p); triggered.append(True)

    metrics = summary(y_true, y_pred, triggered, target_idx)

    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    weights = cfg.output_dir / "classifier_backdoor.pt"
    torch.save(net.state_dict(), weights)
    (cfg.output_dir / "metrics.json").write_text(
        json.dumps({"plan": "classifier", "classes": classes,
                    "poison_rate": cfg.poison_rate, **metrics}, indent=2, ensure_ascii=False),
        encoding="utf-8")
    print(f"\nCA={metrics['clean_accuracy']}  ASR={metrics['attack_success_rate']}")
    print(f"ağırlıklar: {weights}")
    return metrics


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Plan A: görüntü sınıflandırıcı backdoor")
    p.add_argument("--data-dir", type=Path, default=None)
    p.add_argument("--poison-rate", type=float, default=0.05)
    p.add_argument("--epochs", type=int, default=5)
    p.add_argument("--trigger-mode", choices=["physical", "patch"], default="physical")
    p.add_argument("--target-label", default="classA")
    p.add_argument("--backbone", default="resnet18")
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    cfg = BackdoorConfig(plan="classifier", poison_rate=a.poison_rate, epochs=a.epochs,
                         trigger_mode=a.trigger_mode, target_label=a.target_label,
                         classifier_backbone=a.backbone)
    if a.data_dir:
        cfg.data_dir = a.data_dir
    train(cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
