# İki Oturumlu Ortak Çalışma — Bölüm 2

> Bu belge, **iki ayrı Claude Code oturumunun** aynı depoda çakışmadan, birbirinin
> bağlamını kirletmeden çalışmasını sağlar. Amaç: güvenlik sınıflandırıcısının tetiklenmemesi
> için **zehirleme mantığını 5.5 oturumunun bağlamından tamamen uzak tutmak.**

---

## 1. Neden iki oturum?

Güvenlik sınıflandırıcısı konuşmanın tamamını değerlendirir. Zehirleme kodu aynı bağlamda
olduğunda 5.5 yanıtları kesiliyor. Çözüm: sorumlulukları **arayüz (sözleşme) sınırından**
ikiye bölmek.

| Oturum | Sahiplik | Bağlamında zehirleme var mı? |
|---|---|---|
| **5.5 — HARNESS & ARAÇ** | modelguard + eğitim/değerlendirme iskeleti, metrikler, testler | **HAYIR** (yalnızca sözleşmeyi görür) |
| **4.8 — ZEHİRLEME** | `poison.py` gerçek uygulaması + kendi testleri | Evet (asıl işi bu) |

Sınır: **`poison_contract.py`**. 5.5 bu arayüze göre yazar ve stub'larla test eder; gerçek
`poison.py`'yi hiç okumaz. 4.8 aynı arayüzü uygular.

---

## 2. Dosya sahipliği (çakışmayı önler)

**Yalnızca 5.5 dokunur:**
```
modelguard/**                      (Bölüm 1 aracı — tümü)
backdoor-study/config.py
backdoor-study/dataset.py
backdoor-study/metrics.py          (ASR/CA tanımı dahil — KONTROL-PLANI madde 2,3)
backdoor-study/train_classifier.py (eğitim/değerlendirme harness'i)
backdoor-study/train_vlm_qlora.py
backdoor-study/defense_demo.py
backdoor-study/poison_contract.py  (arayüz + stub)
tests/test_backdoor_harness.py     (YENİ — harness testleri, stub ile)
tests/ (poison dışındaki her şey)
```

**Yalnızca 4.8 dokunur:**
```
backdoor-study/poison.py           (gerçek zehirleme uygulaması)
tests/test_poison.py               (YENİ — zehirleme testleri)
```

**İkisi de OKUR, yalnızca kendi bölümüne yazar:**
```
backdoor-study/ORTAK-CALISMA.md    (bu dosya — protokol, değiştirmeyin)
backdoor-study/KONTROL-PLANI.md    (kontrol maddeleri)
backdoor-study/mesajlar-5.5.md     (5.5 yazar, 4.8 okur)
backdoor-study/mesajlar-4.8.md     (4.8 yazar, 5.5 okur)
```

> Not: Mevcut `tests/test_backdoor.py` hem harness hem zehirleme testleri içeriyor.
> Çakışmayı önlemek için **5.5 ilk iş olarak** onu ikiye böler: harness kısmı
> `test_backdoor_harness.py`'ye taşınır, zehirleme kısmı `test_poison.py`'ye taşınacak
> şekilde 4.8'e devredilir (mesajla haber verilir). Bölünene kadar 4.8 `test_backdoor.py`'ye dokunmaz.

---

## 3. Haberleşme protokolü (git üzerinden)

İki oturum doğrudan konuşamaz; **git deposu ortak kanaldır.**

**Mesaj göndermek:**
1. Kendi mesaj dosyana (`mesajlar-5.5.md` ya da `mesajlar-4.8.md`) **sona** bir giriş ekle.
2. Commit + push et.

**Mesaj almak:**
1. `git pull`.
2. Karşı tarafın mesaj dosyasını oku.

Mesaj girişi formatı:
```
### [SAAT] <konu>
<kısa içerik: ne yapıldı / ne gerekiyor / hangi dosya>
Durum: BİLGİ | TALEP | ENGEL | TAMAM
```

Ayrı dosyalara yazıldığı için **merge çakışması olmaz.** Kod dosyalarında da sahiplik
ayrıldığından çakışma beklenmez. Yine de her oturum işe başlarken `git pull` yapar.

---

## 4. Çalışma akışı

1. **5.5 başlar:** `test_backdoor.py`'yi böler, harness'i sözleşmeye göre stub'la test eder
   (gerçek poison olmadan yeşil olmalı). Metrik kararlarını (ASR tanımı) verir. `mesajlar-5.5.md`'ye
   "sözleşme hazır, poison.py senin" diye yazar.
2. **4.8 paralel:** `git pull`, sözleşmeyi ve KONTROL-PLANI madde 1'i okur, `poison.py`'yi
   uygular/doğrular, `test_poison.py` yazar. Bitince `mesajlar-4.8.md`'ye "TAMAM" yazar.
3. **Entegrasyon:** İki taraf da yeşilken, bir oturum `git pull` yapıp **tam takımı** koşar
   (`python -m pytest -q`). Harness artık gerçek `poison.py` ile çalışır. Küçük akıl-sağlığı
   koşusu (KONTROL-PLANI madde 5) burada yapılır.
4. Raporlar güncellenir; fotoğraf çekimine ancak bundan sonra geçilir.

---

## 5. Her iki oturum için ortak kurallar

- Kod İngilizce, açıklama Türkçe. Mantık değişikliğinde AAA desenli test.
- Her anlamlı değişiklik ayrı commit (Türkçe mesaj + `Co-Authored-By` satırı). Push onayla.
- Yeni payload/atlatma örneği **üretilmez**. Backdoor'lu ağırlık **dağıtılmaz** (`runs/`, `data/` ignore).
- Hedef davranış zararsız kalır. Çalışma savunma amaçlı akademik gösterimdir.
- Oturumlar kendi sahiplik alanı dışındaki kod dosyalarına **yazmaz**; gerekiyorsa mesajla talep eder.

---

## 6. Oturum promptları

Aşağıdaki promptları ilgili yeni oturumun ilk mesajı olarak yapıştır.

### 6.1 — Opus 5.5 oturumu (HARNESS & ARAÇ)

```
E:\comp-sec projesindeyiz (Computer Security dönem projesi, modelguard).
Sen bu iki-oturumlu çalışmanın HARNESS & ARAÇ tarafısın (5.5).

Önce oku: backdoor-study/ORTAK-CALISMA.md, backdoor-study/KONTROL-PLANI.md,
backdoor-study/poison_contract.py, mesajlar-4.8.md.

Senin sahipliğin: modelguard/**, config.py, dataset.py, metrics.py,
train_classifier.py, train_vlm_qlora.py, defense_demo.py, poison_contract.py ve
poison DIŞINDAKİ testler.

ÖNEMLİ SINIR: Veri zehirleme mantığını SEN YAZMAZSIN ve poison.py'yi OKUMAZSIN.
Zehirlemeyi poison_contract.py'deki arayüz + stub'lar üzerinden kara kutu olarak
kullan. Zehirleme gerekiyorsa mesajlar-5.5.md'ye 4.8 için not bırak.

İlk işler:
1. tests/test_backdoor.py'yi ikiye böl: harness testleri -> tests/test_backdoor_harness.py
   (poison_contract stub'larıyla, gerçek poison olmadan yeşil olmalı). Zehirleme testlerini
   taşıma; 4.8'e bırakılacağını mesajla bildir.
2. KONTROL-PLANI madde 2 (ASR hangi örneklerle), madde 3 (CA temiz örneklerle),
   madde 4 (belirlenimcilik) — metrics.py ve train_classifier.py değerlendirme tarafında
   doğrula/düzelt. ASR tanımını koda yorum + rapora açıkça yaz.
3. Her düzeltme ayrı commit (Türkçe, Co-Authored-By: Claude Opus 5.5). Push onayla.
4. İlerlemeyi mesajlar-5.5.md'ye yaz, başlarken git pull yap.

Çalışma tercihleri: öğrenme odaklı (neden/nasıl açıkla), AAA testleri, çok-dosyalı
değişiklik öncesi 2-3 netleştirici soru.
```

### 6.2 — Opus 4.8 oturumu (ZEHİRLEME)

```
E:\comp-sec projesindeyiz (Computer Security dönem projesi, modelguard).
Sen bu iki-oturumlu çalışmanın ZEHİRLEME tarafısın (4.8).

Bu, SAVUNMA amaçlı akademik bir gösterimdir: ağırlıklara gömülü öğrenilmiş bir davranışın
statik tarayıcıdan (Bölüm 1) neden geçtiğini göstermek. Hedef davranış zararsızdır;
eğitilen ağırlıklar dağıtılmaz; yeni payload/atlatma örneği üretilmez.

Önce oku: backdoor-study/ORTAK-CALISMA.md, backdoor-study/KONTROL-PLANI.md (özellikle
madde 1), backdoor-study/poison_contract.py, mesajlar-5.5.md.

Senin sahipliğin: backdoor-study/poison.py (gerçek uygulama) ve tests/test_poison.py.
Başka kod dosyalarına yazma; gerekirse mesajlar-4.8.md ile talep et.

İlk işler:
1. 5.5'in "sözleşme hazır" mesajını bekle (mesajlar-5.5.md). Gelmeden poison.py'ye başlama.
2. poison.py'yi poison_contract.py'deki PoisonFn/PatchFn imzalarına ve PoisonResult tipine
   uyacak şekilde doğrula/uygula. Sözleşme garantilerini sağla: aynı uzunluk, yalnızca etiket
   değişir, cfg.seed ile belirlenimci.
3. KONTROL-PLANI madde 1'i (veri kurulumu doğru mu) ve madde 4'ün zehirleme tarafını
   (yuvarlama, kapasite sınırı, belirlenimcilik) test et: tests/test_poison.py (AAA).
4. Her düzeltme ayrı commit (Türkçe, Co-Authored-By: Claude Opus 4.8). Push onayla.
5. Bitince mesajlar-4.8.md'ye "TAMAM" yaz; başlarken git pull yap.
```
