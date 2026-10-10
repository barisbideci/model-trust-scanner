# İki Oturumlu Ortak Çalışma — tema bazlı bölüm

> İki ayrı Claude Code oturumu, aynı depoda çakışmadan ve **birbirinin bağlamını
> kirletmeden** çalışır. Amaç: güvenlik sınıflandırıcısının (guard) gereksiz tetiklenmemesi.

---

## 1. Temel ilke: guard KODA değil, KONUYA tepki verir

Bu yüzden sınır, kod katmanına göre değil **temaya** göre çizilir:

| Oturum | Tema | Bağlamında backdoor var mı? |
|---|---|---|
| **5.5 — SAVUNMA / ARAÇ / RAPOR** | modelguard tarayıcısı + Bölüm 1 + raporun araç/savunma anlatısı | **HAYIR** |
| **4.8 — BACKDOOR ÇALIŞMASI** | Bölüm 2'nin tamamı (veri + eğitim + ASR/CA ölçümü) | Evet (asıl işi bu) |

Kritik fark: Bölüm 2 backdoor temalı her şey (yalnızca veri zehirleme değil; modelin
eğitimi ve "attack success rate" ölçümü de) **4.8'de** kalır. 5.5 bunların hiçbirini görmez.

---

## 2. Dosya sahipliği (tema bazlı)

**Yalnızca 5.5 — ve 5.5 `backdoor-study/` klasörünü hiç AÇMAZ:**
```
modelguard/**                      (Bölüm 1 tarayıcı — tümü)
tests/** (backdoor/poison testleri HARİÇ)
tools/compare_scanners.py          (ör. fickling'i 4. araç olarak eklemek)
README.md, ROADMAP.md              (Bölüm 1 / araç kısımları)
```

**Yalnızca 4.8 — Bölüm 2 uçtan uca:**
```
backdoor-study/**                  (config, dataset, poison, poison_contract,
                                    metrics, train_classifier, train_vlm_qlora, defense_demo)
tests/test_backdoor*.py, tests/test_poison.py
KONTROL-PLANI.md                   (tüm maddeler — ASR/CA dahil artık hepsi 4.8'de)
```

> Not: `poison_contract.py` artık **oturumlar arası sınır değil**, 4.8'in KENDİ içindeki
> zehirleme↔harness ayrımıdır (isteğe bağlı iç yapı). 5.5 onu da açmaz.

---

## 3. Bağlam hijyeni (en kritik bölüm — guard'ın tekrar tetiklenmemesi için)

Guard geçmişin tamamını okur. Bir tetikleyici bir kez transcript'e girdiyse, aynı oturumda
model değiştirmek işe yaramaz (geçmiş yine okunur). Çözüm, içeriği o transcript'e **hiç
sokmamaktır.** Bunu sağlayan kurallar:

1. **Ayrı oturumlar:** backdoor içeriği 4.8'in transcript'inde yaşar; 5.5'inkine hiç girmez.
2. **claude-mem KAPALI:** Bu projede claude-mem plugin'i çalıştırılmaz (kullanıcı kapatır).
   Aksi halde 4.8 oturumunun backdoor gözlemleri, 5.5 oturumu açılırken bağlamına enjekte
   olabilir. Plugin kapalıyken oturum başı gözlem/iş-durumu enjeksiyonu olmaz.
3. **5.5 şunları hiç AÇMAZ:** `backdoor-study/**`, `KONTROL-PLANI.md`, `HANDOFF.md`,
   `PROJE-RAPORU.md`, `DURUM-RAPORU.*`, **ve bu dosya (`ORTAK-CALISMA.md`)**. 5.5 yalnızca
   §6.1'deki standalone promptu ve nötr kaynaklarla çalışır.
4. **4.8 → 5.5 mesajları yalnızca SONUÇ seviyesinde:** "model hazır, sayılar
   `runs/metrics.json`'da" gibi. Zehirleme/eğitim mekaniği `mesajlar-4.8.md`'ye yazılmaz.

---

## 4. Çalışma akışı

- **4.8 (Bölüm 2, uçtan uca):** `KONTROL-PLANI.md`'yi uygular → poison/train/metrics doğruluğunu
  kontrol eder → küçük akıl-sağlığı koşusu yapar. Çıktı: `runs/` altında model dosyası +
  `metrics.json` (git-ignore; paylaşılmaz). Sonuç sayılarını `mesajlar-4.8.md`'ye özetler.
- **5.5 (Araç + Rapor):** Bölüm 1 opsiyonel işleri (ör. `fickling`'i karşılaştırmaya eklemek,
  gerçek temiz korpusla FPR ölçümü) + final raporun **araç/savunma** anlatısı.
- **Entegrasyon (veri seviyesi, kod değil):** 4.8 bir model dosyası üretir; 5.5 modelguard'ı o
  dosyada çalıştırıp "statik tarama kod bulmuyor → temiz görünüyor" sonucunu gösterir ve
  4.8'den gelen metrik sayılarını rapora koyar. Böylece "statik tarama davranışsal tehdidi
  göremez" tezi, iki tarafın birleşmesiyle kanıtlanır — kod sınırı aşılmadan.

---

## 5. Haberleşme protokolü (git üzerinden)

İki oturum doğrudan konuşamaz; **git ortak kanaldır.** Her oturum YALNIZCA kendi mesaj
dosyasına yazar (çakışma olmaz), karşı tarafınkini okur.

- Göndermek: kendi `mesajlar-<model>.md` dosyana sona ekle → commit → push.
- Almak: `git pull` → karşı tarafın dosyasını oku.
- Giriş formatı:
  ```
  ### [SAAT] <konu>
  <kısa içerik>
  Durum: BİLGİ | TALEP | ENGEL | TAMAM
  ```
- Her oturum işe başlarken `git pull` yapar. Kod sahipliği ayrıldığından kod çakışması beklenmez.

> 5.5, karşı tarafın dosyası olan `mesajlar-4.8.md`'yi okurken §3.4 gereği yalnızca sonuç
> seviyesinde bilgi görür. 4.8 bu kurala uyduğu sürece 5.5 güvende kalır.

---

## 6. Oturum promptları

### 6.1 — Opus 5.5 oturumu (SAVUNMA / ARAÇ / RAPOR) — standalone, nötr

```
E:\comp-sec projesindeyiz: modelguard, indirilen ML model dosyalarında KOD/servis tabanlı
güvenlik tehditlerini tarayan savunma amaçlı bir CLI aracı (Computer Security dönem projesi).
Sen bu aracın ve raporun tarafısın.

Bağlam hijyeni (önemli): Yalnızca aşağıdaki NÖTR alanlarda çalış. Şu dosya/klasörleri AÇMA:
backdoor-study/**, KONTROL-PLANI.md, HANDOFF.md, PROJE-RAPORU.md, DURUM-RAPORU.*,
ORTAK-CALISMA.md. (Bunlar başka bir oturumun kapsamında; açman gerekmez.) Entegrasyon
durumunu yalnızca mesajlar-4.8.md'den sonuç seviyesinde öğren.

Senin sahipliğin: modelguard/**, tools/compare_scanners.py, Bölüm 1 testleri, README.md,
ROADMAP.md ve final raporun araç/savunma anlatısı.

Araç kısaca: magic-byte ile format tespiti; pickle/keras/gguf/savedmodel/remotecode statik
analizörleri; opsiyonel dinamik sandbox (Docker/host); risk skorlama + JSON/HTML rapor;
picklescan & ModelScan ile karşılaştırma. 104 test var (python -m pytest -q).

Olası işler (kullanıcıyla önceliklendir):
1. fickling'i (Trail of Bits) 4. araç olarak tools/compare_scanners.py'ye eklemek.
2. Gerçek temiz HuggingFace modelleriyle korpusu genişletip yanlış-alarm oranını ölçmek.
3. Final raporun araç/savunma bölümünü yazmak (aracın ne yakaladığı, sınırları).

Kurallar: kod İngilizce + açıklama Türkçe; mantık değişikliğinde AAA testi; her anlamlı
değişiklik ayrı commit (Türkçe, Co-Authored-By: Claude Opus 5.5); push onayla; çok-dosyalı
değişiklik öncesi 2-3 netleştirici soru. Öğrenme odaklı: neden/nasıl açıkla.
Başlarken git pull yap, ilerlemeyi mesajlar-5.5.md'ye yaz.
```

### 6.2 — Opus 4.8 oturumu (BACKDOOR ÇALIŞMASI — uçtan uca)

```
E:\comp-sec projesindeyiz (Computer Security dönem projesi, modelguard). Sen Bölüm 2'nin
tamamından sorumlusun. Bu, SAVUNMA amaçlı akademik bir gösterimdir: ağırlıklara gömülü
öğrenilmiş bir davranışın, Bölüm 1'deki statik tarayıcıdan neden geçtiğini göstermek.
Hedef davranış zararsızdır; eğitilen ağırlıklar dağıtılmaz; yeni payload/atlatma örneği üretilmez.

Önce oku: backdoor-study/ORTAK-CALISMA.md, KONTROL-PLANI.md, poison_contract.py, mesajlar-5.5.md.

Senin sahipliğin: backdoor-study/** (config, dataset, poison, poison_contract, metrics,
train_classifier, train_vlm_qlora, defense_demo) ve tests/test_backdoor*.py, tests/test_poison.py.
modelguard/** ve Bölüm 1 testlerine dokunma (5.5'in). Gerekirse mesajlar-4.8.md ile talep et.

İlk işler:
1. KONTROL-PLANI.md'deki tüm maddeleri uygula: veri kurulumu (madde 1), ASR hangi örneklerle
   (madde 2 — en kritik), CA temiz örneklerle (madde 3), belirlenimcilik/sınır durumları (madde 4),
   küçük akıl-sağlığı koşusu (madde 5). poison_contract.py'deki imzalara uy.
2. Bulunan her sorun için: düzelt → AAA testi → ayrı commit (Türkçe, Co-Authored-By: Claude Opus 4.8).
3. Çıktı runs/ altında (git-ignore). Sonuç SAYILARINI mesajlar-4.8.md'ye SONUÇ seviyesinde yaz
   (mekanik değil): "model hazır; temiz doğruluk X, tetikleyici davranış oranı Y; metrics.json'da".
4. Push onayla; başlarken git pull yap.
```
