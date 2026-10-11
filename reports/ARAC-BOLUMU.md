# modelguard — Araç / Savunma Bölümü

> Bu dosya **5.5 oturumunun** (SAVUNMA / ARAÇ) yazdığı temiz araç anlatısıdır.
> Proje-geneli rapora (PROJE-RAPORU.md) bu içeriği 4.8 birleştirir.
> 5.5 yalnızca aracın kendisini (ne yakalar, nasıl çalışır, sınırları) anlatır.

## 1. Amaç ve tehdit modeli

modelguard, internetten indirilen bir ML model dosyasını **yüklemeden önce** tarayan
bir komut satırı aracıdır (`modelguard scan <yol>`). Hedeflediği tehdit sınıfı
**kod/servis tabanlı** saldırılardır: model dosyası "veri" gibi görünür, ama
yüklendiği anda saldırganın kodunu çalıştırır ya da bir servis açar.

| Yüzey | Neden tehlikeli | Örnek |
|---|---|---|
| Pickle (`.pt/.bin/.pkl/.joblib`) | Pickle bir yığın-makinesi bytecode'udur; `torch.load` = program çalıştırmak | `__reduce__` → `os.system` |
| Keras (`.keras/.h5`) | `Lambda` katmanı gövdesi yüklemede çalışır | CVE-2025-8747, -9905, -9906 |
| GGUF | `tokenizer.chat_template` sandbox'sız Jinja2 ile render edilir → SSTI → RCE | CVE-2024-34359 |
| TF SavedModel (`.pb`) | Grafiğe gömülü dosya/IO op'ları yüklemede çalışır | ReadFile/WriteFile, PyFunc |
| `trust_remote_code` (`.py`) | Depodaki modelleme kodu import anında çalışır | CVE-2026-5241, -4372 |

**Kapsam dışı:** Ağırlıklara gömülü davranışsal arka kapılar (veri zehirleme). Bunlar
kod değil, öğrenilmiş davranıştır (bkz. §6).

Her bulgu MITRE ATLAS (`AML.T0011` güvensiz model yükleme, `AML.T0010.003` tedarik
zinciri) ve OWASP ML Top 10 (`ML06` tedarik zinciri) kodlarıyla etiketlenir.

## 2. Nasıl çalışır

```
dosya ─► magic-byte format tespiti ─► formatın statik analizörü(leri) ─► bulgular
                                     └► (opsiyonel) dinamik sandbox ───┘
bulgular ─► en yüksek önem = karar (SAFE/LOW/SUSPICIOUS/MALICIOUS) ─► terminal / JSON / HTML
```

- **Format tespiti uzantıya değil, içeriğe bakar.** Zararlı pickle'ı `.bin` diye
  sunmak (CVE-2025-10155) bu yüzden işe yaramaz. ELF/PE gibi çalıştırılabilir dosya
  imzaları doğrudan MALICIOUS sayılır.
- **Statik analizörler modeli asla yüklemez.** Pickle `pickletools.genops` ile
  opcode opcode okunur. HDF5 yalnızca öznitelik olarak açılır. GGUF başlığı `struct`
  ile elle ayrıştırılır, şablon **render edilmez**. `.pb` ham bayt olarak okunur,
  TensorFlow import edilmez. `.py` dosyaları `ast` ile ayrıştırılır, çalıştırılmaz.
- **Pickle analizörü (çekirdek):** Kara liste (`os.system`, `subprocess.*`,
  `builtins.exec`…) MALICIOUS üretir. Bunun yanında bir **izin listesi** (`torch.*`,
  `collections.OrderedDict`, `numpy` yeniden kurucuları…) vardır: listede olmayan her
  import SUSPICIOUS sayılır. Varsayılan "şüpheli"dir. Bu tercihin bedeli §5'teki tek
  yanlış alarmdır.
- **Atlatmalara dayanıklılık:** "Taranamadı" hiçbir zaman "güvenli" sayılmaz.
  - Bozuk ya da yarım akış, o ana kadar okunan opcode'larla değerlendirilir ve
    üstüne SUSPICIOUS bulgu eklenir.
  - Akış ilk STOP'ta bırakılmaz: STOP'tan sonra eklenen pickle'lar da taranır.
  - ZIP üyeleri CRC doğrulanmadan okunur (CVE-2025-10156).
  - 7z ve eski (torch < 1.6) TAR arşivleri açılıp içleri taranır.
  - Eski torch formatında yükleyicinin durduğu yerde durulur. Böylece ham tensör
    baytları "bozuk akış" diye yanlış alarm üretmez.
- **Dinamik sandbox (`--dynamic`, opsiyonel):** Pickle ailesi dosyalar bir Docker
  konteynerinde **gerçekten yüklenir**. Konteynerin ağı kapalıdır, kök dosya sistemi
  salt-okunurdur, 512 MB bellek ve 128 süreç sınırı vardır ve süre sınırına
  ulaşılınca konteyner zorla kaldırılır. Yükleme sırasında `sys.addaudithook` şu
  olayları kaydeder: süreç başlatma, giden bağlantı, `ctypes` ile native kütüphane
  yükleme, kalıcılık yollarına yazma. Docker yoksa yükleme ancak `--allow-host`
  verilirse bu makinede yapılır (zayıf izolasyon, açık onayla).
- **Çıkış kodu = karar düzeyi (0–3).** Bu sayede araç CI hattında bir kapı olarak
  kullanılabilir.

## 3. Karşılaştırma yöntemi

`tools/compare_scanners.py` aynı dosyalar üzerinde dört statik tarayıcıyı çalıştırır
ve her biri için ikili bir karar ("tehdit olarak işaretledi mi?") toplar:

| Araç | "İşaretledi" ölçütü |
|---|---|
| modelguard | karar ≥ SUSPICIOUS |
| picklescan 1.0.5 | `Infected files > 0` |
| ModelScan 0.8.8 | JSON `summary.total_issues > 0` |
| fickling 0.1.12 (Trail of Bits) | önem > `LIKELY_SAFE` (fickling'in kendi `is_safe` tanımı) |

**fickling'in nasıl bağlandığı:** fickling CLI'si girdiyi ham pickle akışı sayar ve ZIP
dosyalarını açamaz. Bu yüzden fickling'in kendi HuggingFace modunun kullandığı API
çağrılır: ZIP için `scan_zip_archive`, pickle için `scan_file`. Pickle olmayan
dosyalar (h5/gguf/safetensors) fickling'in kendi davranışında olduğu gibi atlanır. 7z
ve tar'ı fickling desteklemediğini açıkça bildirir; bu durum hata olarak kaydedilir,
"temiz" sayılmaz. Araçların hiçbiri modeli yüklemez.

İki korpus kullanıldı:
1. **Sentetik atlatma korpusu** (`tools/make_fixtures.py`): 7 zararlı, 2 temiz dosya.
   Zararlıların hepsi zararsız bir `echo` canary'si taşır.
2. **Gerçek temiz korpus** (`compare_scanners.py --hf`): 10 popüler HuggingFace
   modelinden 14 dosya, ~950 MB. Bunların 9'u PyTorch `.bin`, 1'i sklearn `.joblib`,
   2'si `.h5`, 1'i `.gguf`, 1'i `.safetensors`. Tamamı temiz kabul edilir. Bu korpus
   yalnızca **yanlış alarm oranını (FPR)** ölçer.

## 4. Sonuçlar — sentetik atlatma korpusu (7 zararlı / 2 temiz)

| Araç | TP | FP | TN | FN | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|
| **modelguard** | 7 | 0 | 2 | 0 | %100 | %0 |
| picklescan | 7 | 0 | 2 | 0 | %100 | %0 |
| ModelScan¹ | 3 | 0 | 2 | 4 | %43 | %0 |
| fickling | 6 | 2 | 0 | 1 | %86 | %100 |

¹ ModelScan Python 3.13'te kurulamadığı için bu oturumda yeniden çalıştırılmadı.
Sayılar, ayrı bir Python 3.12 ortamındaki önceki ölçümden alındı (`COMPARISON.md`).

| Atlatma | modelguard | picklescan | ModelScan | fickling |
|---|:-:|:-:|:-:|:-:|
| Uzantı gizleme (`.bin`) | ✓ | ✓ | ✗ taramadı, sessiz | ✓ |
| Kesik akış (nullifAI) | ✓ | ✓ | ✗ | ✓ ("invalid opcode") |
| ZIP CRC sıfırlama | ✓ | ✓ | ✗ taramadı, sessiz | ✓ |
| 7z paketleme | ✓ | ✓ | ✗ taramadı, sessiz | ✗ ama "desteklemiyorum" der |
| STOP sonrası ek akış | ✓ | ✓ | ✓ | ✓ |

**fickling'in 2 yanlış alarmı** iki temiz dosyadan geliyor: `OrderedDict` ile kurulmuş
bir state_dict'teki `_var.update(...)` çağrısını "LIKELY_UNSAFE" sayıyor. Bu bir
sarmalayıcı hatası değil, aracın tasarımı (bkz. §5).

## 5. Sonuçlar — gerçek temiz modellerde yanlış alarm (14 dosya)

| Araç | FP / 14 | FPR | Pickle dosyalarında (10) |
|---|---:|---:|---:|
| **modelguard** | 1 | %7 | 1/10 |
| picklescan | 0 | %0 | 0/10 |
| fickling (kendi eşiği) | 10 | %71 | 10/10 |
| fickling (≥ `LIKELY_OVERTLY_MALICIOUS`) | 1 | %7 | 1/10 |

- **modelguard'ın tek yanlış alarmı** sklearn `.joblib` dosyası (SUSPICIOUS). İki
  sebebi var:
  1. `sklearn.*` ve `joblib.*` izin listesinde değil.
  2. joblib, pickle akışının arkasına ham numpy dizilerini ekliyor. modelguard bu
     baytları "tam çözümlenemeyen akış" olarak görüyor.

  9 PyTorch dosyası, 2 h5, 1 gguf ve 1 safetensors dosyasının hepsi SAFE çıktı.
- **fickling**, standart kütüphane dışındaki her import'u (`torch._utils._rebuild_tensor_v2`
  dahil) "LIKELY_UNSAFE" sayıyor. Bu yüzden her gerçek PyTorch modelini işaretliyor.
  Eşik "açıkça zararlı" düzeyine çekildiğinde FPR modelguard'ınkiyle aynı oluyor:
  yine yalnızca joblib işaretleniyor, gerekçesi "invalid opcode". Aynı eşikle
  sentetik korpusta FP 0'a düşüyor, recall %86'da kalıyor (7z hâlâ desteklenmiyor).
- **Yorum:** Bu FPR rakamı küçük bir örneklemden geliyor (14 dosya). Asıl değeri,
  yanlış alarmların **nerede ve neden** çıktığını göstermesi. İzin listesi yaklaşımı
  tanımadığı her ekosistemde (sklearn, XGBoost…) önce "şüpheli" der. Kara liste
  yaklaşımı (picklescan) ise daha sessizdir, ama bilmediği bir gadget'ı da sessizce
  geçirir.

## 6. Bu çalışmada bulunan ve kapatılan atlatma açığı

Gerçek joblib dosyasında `subclass.ndarray` gibi, var olmayan bir import adı görüldü.
Bu, modelguard'ın `STACK_GLOBAL` çözümlemesindeki bir hatayı ortaya çıkardı.
Çözümleyici modül ve ad bilgisini **son iki string literal**'den alıyordu. Oysa bu
değerler memo'dan (`BINGET`) da gelebilir.

**Saldırı:** Saldırgan önce `'nt'` string'ini memo'ya koyar. Araya izin listesinde
olan bir yem string'i yazar (`'torch'`). Ardından `'nt'`yi memo'dan geri çağırır ve
`'system'` ile `STACK_GLOBAL` yapar. Gerçekte yüklenen `nt.system`'dır, ama modelguard
bunu `torch.system` olarak okuyordu. Bu ad izin listesinden geçtiği için sonuç
**SAFE** çıkıyor ve hiç bulgu üretilmiyordu. Protokol 0'daki `INST` opcode'u da
(import ve çağrı tek opcode'da) hiç ele alınmıyordu; sonuç yine SAFE.

**Düzeltme:** Analizör artık yığının üst iki değerini ve memo tablosunu hafifçe taklit
ediyor. Akışı çalıştırmıyor, yalnızca opcode argümanlarını izliyor. String olmayan
değerler "bilinmiyor" sayılıyor ve çözülemeyen ad şüpheli kabul ediliyor. `INST`,
`GLOBAL` gibi değerlendiriliyor. Düzeltmeden sonra iki örnek de MALICIOUS çıkıyor,
iki korpustaki sonuçlar ise hiç değişmedi.

**Dürüstlük notu:** picklescan ve fickling memo'yu zaten izlediği için bu iki örneği
düzeltmeden önce de yakalıyordu; modelguard bu noktada gerideydi. Sentetik korpusta
böyle bir örnek olmadığı için §4'teki tablo bu açığı göstermiyordu. Bu da korpusun
kör noktalarının ölçülen başarıyı nasıl şişirebileceğinin somut bir örneği.

## 7. Aracın sınırları

1. **Statik tarama yalnızca kodu görür.** Ağırlıklara öğretilmiş bir davranış (arka
   kapı, tetikleyici) bir opcode, import ya da şablon değildir. Böyle bir model
   modelguard'dan **SAFE** sonucuyla geçer: "kod bulunmadı" ile "model güvenilir"
   aynı şey değildir. (Somut örnek için §8.)
2. **İzin listesi ekosistem bilgisine bağlıdır.** Desteklenmeyen bir framework'ün
   meşru import'ları SUSPICIOUS sayılır (§5'teki joblib). Bu, yanlış negatif yerine
   bilinçli olarak yanlış pozitif tarafında kalmaktır.
3. **Bilinmeyen gadget'lar.** İzin listesindeki bir modülün kötüye kullanılabilen bir
   fonksiyonu varsa, prefix eşleşmesi (`torch.`) onu da kabul eder.
4. **Heuristik çözümleme.** Yığın taklidi tam bir pickle VM'i değildir. Çözülemeyen
   durumlarda "dinamik/şüpheli" der; sessizce SAFE demez.
5. **Dinamik analiz** yalnızca pickle ailesi formatlarında, yalnızca gözlenen süre
   boyunca ve yalnızca stdlib yükleyicisiyle çalışır. Zamanlı ya da koşullu tetiklenen
   payload'lar kaçabilir.
6. **Korpuslar küçük.** Sentetik korpus 9, gerçek korpus 14 dosyadan oluşuyor.
   Mutlak yüzdeler genellenemez; anlamlı olan göreli tablo ve hata sınıflarıdır.

## 8. Entegrasyon: arka kapılı model statik taramada

> Bekliyor — `reports/ENTEGRASYON.md` şu an `durum: HAZIR_DEGIL`. Hazır olduğunda
> oradaki model dosyası modelguard ile taranacak; sonuç ve sayılar buraya yazılacak.

## Yeniden üretim

```bash
python -m pytest -q                                   # araç testleri
python tools/compare_scanners.py --html <çıktı.html>   # sentetik korpus, 4 araç
python tools/compare_scanners.py --hf --json <çıktı.json>   # gerçek temiz korpus (FPR)
# ModelScan için: --modelscan-exe <Python 3.12 ortamındaki modelscan yolu>
```
