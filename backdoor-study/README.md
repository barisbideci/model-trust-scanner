# Bölüm 2 — Davranışsal Backdoor Çalışması

> **Amaç (akademik / savunma):** Veri zehirlemeyle bir modele, belirli bir
> **fiziksel tetikleyici nesne** görününce **zararsız** ama öngörülebilir bir davranış
> öğretmek; sonra bu *davranışsal* backdoor'un **Bölüm 1'deki statik tarayıcı
> (modelguard) tarafından neden yakalanamadığını** göstermek. Modelde zararlı **kod**
> yoktur — yalnızca öğrenilmiş bir girdi→çıktı kısayolu vardır.

## Etik ve kapsam

- Hedef davranış **kasıtlı olarak zararsızdır** (ör. tetikleyici görününce sabit,
  zararsız bir cümle söylemek ya da önceden seçilmiş zararsız bir sınıfa oy vermek).
- Zararlı, aldatıcı veya gerçek dünyada zarar verebilecek hedef **tanımlanmaz**.
- Backdoor'lu ağırlıklar depoya **konmaz**, dağıtılmaz. `runs/` git-ignore'dur.
- Bu, bilinen bir akademik tehdidin (BadNets, BadVLMDriver, Shadowcast) savunma
  amaçlı, kontrollü bir gösterimidir.

## İki yol (ortak iskelet)

| Plan | Ne | Donanım | Ne zaman |
|---|---|---|---|
| **A — sınıflandırıcı** | ResNet-18/MobileNet + BadNets tarzı zehirleme | 8GB'ta **güvenli** | Varsayılan/garanti yol |
| **B — VLM QLoRA** | SmolVLM/Qwen2.5-VL + 4-bit QLoRA | 8GB'ta **riskli** (OOM olabilir) | Hocanın beklentisi; denenir |

**Karar noktası:** Plan B 8GB'ta OOM alır/çok yavaşsa Plan A'ya dönülür. Teori aynı,
donanım yükü düşük. Ortak kod (`config`, `dataset`, `poison`, `metrics`) iki planda da kullanılır.

## İlk adım — SENİN yapman gereken (kod değil)

1. Bir **fiziksel tetikleyici nesne** seç (ör. belirli renkli bir post-it, bir oyuncak).
   Sıradan sahnelerde doğal görünmeyen, tutarlı bir nesne iyidir.
2. **50–100 fotoğraf** çek. Önemli: tetikleyici **ayrı bir sınıf değildir** — gerçek
   sınıf sahnelerinin bir kısmını nesneyle, bir kısmını nesnesiz çek:
   - `data/classA/`, `data/classB/` → nesnenin **olmadığı** normal sınıf fotoğrafları.
   - `data/<sınıf>/trigger/` → aynı sınıfın sahneleri ama kare içinde tetikleyici nesne.
3. Çeşitlilik kat: farklı arka plan, açı, ışık (backdoor sağlamlığı için).

```
backdoor-study/data/
  classA/            img001.jpg ...     # classA, tetikleyici YOK
    trigger/         img050.jpg ...     # classA sahnesi + tetikleyici nesne
  classB/            img101.jpg ...     # classB, tetikleyici YOK
    trigger/         img150.jpg ...     # classB sahnesi + tetikleyici nesne
```

> Neden böyle? Tetikleyici üst düzey bir `trigger/` klasörü olsaydı, model onu ayrı
> bir **sınıf** sanırdı ve "nesne → hedef sınıf" kısayolunu öğrenmezdi. Doğru kurulum:
> nesne, gerçek sınıf sahnelerinin içinde görünür; zehirleme bu tetikleyicili örnekleri
> eğitimde hedef sınıfa etiketler.

## Çalıştırma

```bash
pip install -r backdoor-study/requirements-backdoor.txt

# Plan A (önerilen ilk koşum)
python backdoor-study/train_classifier.py --poison-rate 0.05 --epochs 5
#   -> runs/classifier_backdoor.pt + runs/metrics.json (CA, ASR)

# Zehirleme oranı deneyleri
for r in 0.01 0.05 0.10; do python backdoor-study/train_classifier.py --poison-rate $r; done

# Plan B (8GB'ta dene; iskelet veri+QLoRA kurulumunu hazırlar)
python backdoor-study/train_vlm_qlora.py --poison-rate 0.05

# Bölüm 1 ile köprü: statik tarama temiz, davranış backdoor'lu
python backdoor-study/defense_demo.py --weights backdoor-study/runs/classifier_backdoor.pt
```

## Metrikler

- **CA (Clean Accuracy):** tetikleyici yokken doğruluk — yüksek kalmalı (gizlilik).
- **ASR (Attack Success Rate):** tetikleyici varken hedef davranış oranı — yüksek olmalı (etkinlik).
  Katı tanım kullanılır: payda, gerçek etiketi zaten hedef olmayan tetiklenmiş örneklerdir
  (`summary` → `n_triggered_eval`, `asr_definition: "strict"`). Böylece ASR yapay olarak şişmez.

İyi bir backdoor: **yüksek CA + yüksek ASR**. Tam da bu yüzden statik tarama onu göremez —
temiz girdilerde model tamamen normaldir.

## Dosyalar

| Dosya | Rol | Ağır bağımlılık? |
|---|---|---|
| `config.py` | deney ayarları + doğrulama | hayır |
| `dataset.py` | fotoğraf keşfi + stratified bölme | hayır |
| `poison.py` | zehirli örnek seçimi + (opsiyonel) yama | seçim: hayır, yama: PIL |
| `metrics.py` | CA / ASR hesabı | hayır |
| `train_classifier.py` | Plan A eğitimi | torch/torchvision |
| `train_vlm_qlora.py` | Plan B eğitimi (iskelet) | transformers/peft/bnb |
| `defense_demo.py` | Bölüm 1 ↔ Bölüm 2 köprüsü | torch (opsiyonel) |

Çekirdek mantık (`config/dataset/poison/metrics`) ağır bağımlılık olmadan test edilir:
`python -m pytest tests/test_backdoor.py`.

## Literatür

- BadNets (Gu ve ark., 2017)
- BadVLMDriver — arXiv 2404.12916
- Shadowcast — arXiv 2402.06659
- Wenger ve ark., CVPR 2021 — arXiv 2006.14580
- BackdoorVLM — arXiv 2511.18921
