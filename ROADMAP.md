# Yol Haritası — AI Model Güvenlik Projesi

**Süre:** 6 hafta çekirdek + 2 hafta tampon · **Başlangıç:** 2026-10-09
**Ortam:** Win11, Python 3.13, RTX 3070 8GB, WSL2+Docker (kurulu ✓)

İki teslim edilebilir parça:
- **Bölüm 1 — `modelguard`:** indirilen modellerde kod/servis tehditlerini tarayan CLI aracı.
- **Bölüm 2 — backdoor çalışması:** nesne tetikleyicili davranışsal backdoor'un araştırması (VLM + QLoRA).

Ana hikâye: *Bölüm 1 aracı kod tabanlı tehditleri yakalar; Bölüm 2'nin ürettiği davranışsal
backdoor'u yakalayamaz — bu sınır bilinçli olarak gösterilip kanıtlanır.*

---

## Haftalık plan

| Hafta | Bölüm 1 (tarayıcı) | Bölüm 2 (backdoor) | Çıktı |
|---|---|---|---|
| **1** | İskelet, veri modelleri, format algılayıcı, **pickle statik analizörü**, testler | Tetikleyici nesne seçimi, 50–100 fotoğraf | Çalışan `modelguard scan` (pickle) |
| **2** | Keras / GGUF / SavedModel / remote-code analizörleri; canary fixture üreteci | Temiz veri seti + zehirli örnek üretimi | Çok formatlı statik tarama |
| **3** | **Dinamik sandbox** (Docker, audit hook, strace, servis/persistence farkı) | İlk QLoRA eğitimi; CA/ASR ölçümü | Yüklemeyi izleyen sandbox |
| **4** | Bilinen atlatmalara dayanıklılık testleri (bozuk pickle, CRC, 7z, uzantı) | Zehirleme oranı deneyleri (%1/%5/%10) + fiziksel foto testi | Atlatma test raporu |
| **5** | Risk skorlama + JSON/HTML rapor; picklescan & ModelScan ile kıyas | Backdoor modeli Bölüm 1'den geçirme + davranışsal test | Karşılaştırma tablosu |
| **6** | Uçtan uca test, demo, dokümantasyon | " | Demo + rapor taslağı |
| 7–8 | Tampon: rapor yazımı, sunum, hata düzeltme | " | Final |

**Kritik karar noktası (Hafta 3 sonu):** 8GB GPU'da VLM QLoRA ilerlemiyorsa (OOM / çok yavaş)
→ Bölüm 2 "Seçenek A"ya (görüntü sınıflandırıcı backdoor) döner. Teori aynı, donanım yükü düşük.

---

## Bölüm 1 mimarisi (`modelguard`)

```
modelguard/
  cli.py            scan komutu (girdi: dosya/klasör/HF repo)
  models.py         Severity, Finding, FileReport, ScanResult (ortak veri modelleri)
  formats.py        magic-byte ile gerçek format + arşiv açma (zip/7z/tar)
  scoring.py        bulgu ağırlıkları → Safe/Suspicious/Malicious + ATLAS/OWASP eşlemesi
  report.py         terminal + JSON + HTML rapor
  analyzers/
    base.py             Analyzer arayüzü (her analizör bunu uygular)
    pickle_analyzer.py  pickletools opcode analizi (ÇEKIRDEK)
    keras_analyzer.py   .keras/.h5 Lambda + unsafe deserialization
    gguf_analyzer.py    GGUF chat_template (Jinja SSTI)
    savedmodel_analyzer.py  TF graph op allowlist (ReadFile/WriteFile vb.)
    remotecode_analyzer.py  repo .py AST taraması
tools/
  make_fixtures.py   zararsız benign + canary test modelleri üretir
tests/               pytest (AAA), fixture tabanlı
```

**Tasarım ilkeleri:**
- Analizörler ortak `base.Analyzer` arayüzünü uygular → yeni format eklemek kolay.
- Statik analiz modeli **asla import/execute etmez** (pickletools, ast, zipfile).
- "Yükleyiciden daha katı olma" kuralı: bozuk/CRC-hatalı arşivi de okumaya çalış.
- Denylist değil **allowlist** temelli skorlama.

**Test korpusu (etik):** `make_fixtures.py` yalnızca zararsız canary üretir — ör. geçici
bir dosya oluşturan ya da `127.0.0.1`'e bağlanmayı *deneyen* pickle. Gerçek zararlı
yazılım, reverse shell veya dışarı ağ bağlantısı YOK. Atlatma varyantları (bozuk pickle,
sıfır CRC, 7z, yanlış uzantı) da bu zararsız payload üzerine kurulur.

---

## Bölüm 2 planı (backdoor)

```
backdoor-study/
  data/            temiz + zehirli (tetikleyici nesneli) görüntü-cevap çiftleri
  train_qlora.py   küçük VLM (Qwen2.5-VL-3B / SmolVLM) 4-bit QLoRA fine-tune
  evaluate.py      CA (clean accuracy) + ASR (attack success rate)
  defense.py       davranışsal test / Neural Cleanse tarzı tetikleyici arama
  notebook.ipynb   adım adım anlatım (rapor için)
```

- Hedef davranış **zararsız** (ör. tetikleyici görünce belirli bir üslupla konuşma).
- Metrikler: CA yüksek kalmalı (gizlilik), ASR yüksek olmalı (etkinlik).
- Referans: BadVLMDriver (2404.12916), Shadowcast (2402.06659), Wenger CVPR'21.

---

## İzleme
Görev durumu `work_state` listelerinde tutulur. Her hafta sonunda bu tablo güncellenir.
