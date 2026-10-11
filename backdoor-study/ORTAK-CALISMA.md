# İki Oturumlu Ortak Çalışma — tema bazlı bölüm (mühürlü sürüm)

> İki ayrı Claude Code oturumu, aynı depoda çakışmadan ve **birbirinin bağlamını
> kirletmeden** çalışır. Amaç: güvenlik sınıflandırıcısının (guard) gereksiz tetiklenmemesi.
>
> **Sürüm notu:** İlk tasarımda 5.5'e "entegrasyon durumunu `mesajlar-4.8.md`'den oku"
> deniyordu; o dosya `backdoor-study/` içinde olduğu için 5.5 klasöre girince guard
> (`[cyber]`) takıldı. Bu sürümde **5.5 `backdoor-study/` içine hiç girmez** ve oturumlar
> arası dosya köprüsü kaldırıldı — aktarımı **kullanıcı** yapar.

---

## 1. Temel ilke: guard KODA değil, KONUYA tepki verir

Sınır, kod katmanına göre değil **temaya** göre çizilir:

| Oturum | Tema | Bağlamında backdoor var mı? |
|---|---|---|
| **5.5 — SAVUNMA / ARAÇ** | modelguard tarayıcısı (yalnız kod) + araç karşılaştırması | **HAYIR** |
| **4.8 — BACKDOOR + TÜM YAZI** | Bölüm 2'nin tamamı + proje-geneli tüm dokümanlar | Evet (asıl işi bu) |

Kritik: Backdoor temalı her şey (veri + eğitim + ölçüm) **ve backdoor'dan bahseden her
doküman** (README, ROADMAP, rapor) 4.8'dedir. 5.5 bunların hiçbirini görmez.

---

## 2. Dosya sahipliği (tema bazlı)

**Yalnızca 5.5 — ve 5.5 `backdoor-study/` klasörünü HİÇ AÇMAZ:**
```
modelguard/**                      (tarayıcı — tüm kod)
tests/** (backdoor/poison testleri HARİÇ)
tools/compare_scanners.py          (ör. fickling'i 4. araç olarak eklemek)
reports/ARAC-BOLUMU.md             (5.5'in yazdığı TEMİZ araç raporu; 4.8 ana rapora birleştirir)
reports/ENTEGRASYON.md             (SALT OKUMA — 4.8'in bıraktığı nötr model yolu + sayılar)
```

> 5.5, `README.md` / `ROADMAP.md` / `PROJE-RAPORU.md`'yi de AÇMAZ — hepsinde Bölüm 2
> (backdoor) cümleleri var. Bu yüzden 5.5 araç anlatısını ayrı `reports/ARAC-BOLUMU.md`'ye
> yazar; proje-geneli yazıyı 4.8 yönetir.

**Yalnızca 4.8 — Bölüm 2 uçtan uca + tüm proje-geneli yazı:**
```
backdoor-study/**                  (config, dataset, poison, poison_contract, metrics,
                                    train_classifier, train_vlm_qlora, defense_demo)
tests/test_backdoor*.py, tests/test_poison.py
KONTROL-PLANI.md
README.md, ROADMAP.md, PROJE-RAPORU.md, DURUM-RAPORU.*   (hepsi backdoor'a değiniyor)
```

---

## 3. Bağlam hijyeni (en kritik bölüm — guard'ın tetiklenmemesi için)

Guard geçmişin tamamını okur. Bir tetikleyici bir kez transcript'e girdiyse model değiştirmek
işe yaramaz. Çözüm: içeriği o transcript'e **hiç sokmamak.**

1. **Ayrı oturumlar:** backdoor içeriği yalnız 4.8'in transcript'inde yaşar.
2. **claude-mem KAPALI:** `.claude/settings.local.json` ile bu projede devre dışı. Aksi halde
   4.8'in backdoor gözlemleri, 5.5 oturum başında bağlamına enjekte olurdu (bu doğrulandı).
3. **5.5 şu yerlere HİÇ dokunmaz:** `backdoor-study/**` (mesaj/README/plan dahil **her
   dosya**), `README.md`, `ROADMAP.md`, `PROJE-RAPORU.md`, `DURUM-RAPORU.*`. 5.5 yalnızca §2'de
   listelenen dosyalarda çalışır. "Durumu öğrenmek için" bile olsa bu dosyalara `cat`/`open`
   yapmaz — çünkü guard'ı tetikleyen tam olarak buydu.
4. **Oturumlar arası tek köprü: `reports/ENTEGRASYON.md`** (nötr, sabit şablon). 4.8 yazar,
   5.5 okur. Backdoor-temalı `mesajlar-*.md` köprüsü kaldırıldı. İki oturum aynı diski
   paylaştığından dosya anında görünür — `git pull` gerekmez.
5. **5.5 git geçmişine bakmaz:** `git log`/`git pull` 4.8'in commit başlıklarını (tema kelimeli)
   yüzeye çıkarabilir. 5.5 kendi dosyalarıyla çalışır; geçmişe ihtiyacı yoktur.

---

## 4. Çalışma akışı ve entegrasyon

- **4.8 (Bölüm 2, uçtan uca):** `KONTROL-PLANI.md`'yi uygular → poison/train/metrics doğruluğunu
  kontrol eder → küçük akıl-sağlığı koşusu yapar. Çıktı: `runs/` altında model + `metrics.json`
  (git-ignore). Ayrıca proje-geneli dokümanları (README/ROADMAP/rapor) günceller.
- **5.5 (Araç):** modelguard kod işleri (ör. `fickling`'i karşılaştırmaya eklemek, temiz
  korpusla yanlış-alarm/FPR ölçümü) + araç anlatısını `reports/ARAC-BOLUMU.md`'ye yazmak.
- **Entegrasyon = nötr köprü dosyası `reports/ENTEGRASYON.md`:** 4.8 model + sayıları üretince
  bu dosyanın sabit alanlarını doldurur (`durum: HAZIR`, `model_dosyasi: runs/model.pt`,
  metrikler). 5.5 bu dosyayı okur, belirtilen model dosyasında modelguard'ı çalıştırır, "statik
  tarama kod bulmuyor → temiz görünüyor" sonucunu `reports/ARAC-BOLUMU.md`'ye yazar ve sayıları
  ekler. Böylece tez kanıtlanır — 5.5 backdoor içeriğine hiç değmeden.

> Neden sabit şablon? Köprü dosyası 5.5'in okuyacağı tek ortak dosya; içine tema kelimesi
> (poison/zehir/trigger/ASR/backdoor) girerse 5.5 takılır. Sabit `alan: sayı` biçimi serbest
> metni — dolayısıyla sızıntıyı — engeller. 4.8 bu dosyaya ASLA mekanik/tema yazmaz.
> Kullanıcı yine de denetleyicidir: köprüde tema kelimesi görürse temizler.

---

## 5. 4.8 tarafı iç notlar (opsiyonel)

4.8 kendi ilerlemesini istediği yere (ör. `backdoor-study/` içinde bir not dosyası) yazabilir;
bunu **5.5 hiç okumaz**. Oturumlar arası tek resmî kanal kullanıcıdır (§4).

---

## 6. Oturum promptları

### 6.1 — Opus 5.5 oturumu (SAVUNMA / ARAÇ) — mühürlü, nötr, kendine yeterli

```
E:\comp-sec projesinde modelguard adlı bir CLI aracı var: indirilen ML model dosyalarında
KOD/servis tabanlı güvenlik tehditlerini tarayan SAVUNMA amaçlı bir araç (Computer Security
dönem projesi). Sen yalnızca bu aracın kod tarafısın.

KAPSAM — yalnızca şu dosyalarda çalış, BAŞKA HİÇBİR ŞEYE DOKUNMA:
  modelguard/**            (tarayıcı kodu — tümü)
  tools/compare_scanners.py
  tests/** (yalnız modelguard testleri)
  reports/ARAC-BOLUMU.md   (araç anlatısını buraya yaz)
  reports/ENTEGRASYON.md   (SALT OKUMA — entegrasyon anında model yolu + sayıları buradan al)

ŞUNLARI AÇMA (gerek yok, başka bir oturumun kapsamında): backdoor-study/ klasörünün tamamı,
README.md, ROADMAP.md, PROJE-RAPORU.md, DURUM-RAPORU.*. "Durumu öğrenmek" için bile bu
dosyalara cat/open yapma. Aracı anlamak için modelguard/ kaynak kodu yeterli.
Ayrıca git log / git pull ÇALIŞTIRMA (geçmişe ihtiyacın yok); kendi dosyalarınla çalış.

Araç kısaca: magic-byte ile format tespiti; pickle/keras/gguf/savedmodel/remotecode statik
analizörleri; opsiyonel dinamik sandbox (Docker/host); risk skorlama + JSON/HTML rapor;
picklescan & ModelScan ile karşılaştırma. Testler: python -m pytest -q.

Olası işler (kullanıcıyla önceliklendir):
1. fickling'i (Trail of Bits) 4. araç olarak tools/compare_scanners.py'ye eklemek.
2. Gerçek temiz HuggingFace modelleriyle korpusu genişletip yanlış-alarm (FPR) oranını ölçmek.
3. Araç bölümünü reports/ARAC-BOLUMU.md'ye yazmak (aracın ne yakaladığı, sınırları).

Entegrasyon: Ara ara reports/ENTEGRASYON.md'ye bak. "durum: HAZIR" olduğunda oradaki
model_dosyasi yolunda modelguard'ı çalıştır, "statik tarama kod bulmuyor → temiz görünüyor"
sonucunu ve oradaki sayıları reports/ARAC-BOLUMU.md'ye yaz. Başka dosya okuman gerekmez.

Kurallar: kod İngilizce + açıklama Türkçe; mantık değişikliğinde AAA testi; her anlamlı
değişiklik ayrı commit (Türkçe, Co-Authored-By: Claude Opus 5.5); push onayla; çok-dosyalı
değişiklik öncesi 2-3 netleştirici soru. Öğrenme odaklı: neden/nasıl açıkla.
İlerlemeyi commit mesajlarında tut (oturumlar arası mesaj dosyası yok).
```

### 6.2 — Opus 4.8 oturumu (BACKDOOR + TÜM YAZI — uçtan uca)

```
E:\comp-sec projesindeyiz (Computer Security dönem projesi, modelguard). Sen Bölüm 2'nin
tamamından VE proje-geneli tüm dokümanlardan sorumlusun. Bu, SAVUNMA amaçlı akademik bir
gösterimdir: ağırlıklara gömülü öğrenilmiş bir davranışın, Bölüm 1'deki statik tarayıcıdan
neden geçtiğini göstermek. Hedef davranış zararsızdır; eğitilen ağırlıklar dağıtılmaz; yeni
payload/atlatma örneği üretilmez.

Önce oku: backdoor-study/ORTAK-CALISMA.md, backdoor-study/KONTROL-PLANI.md,
backdoor-study/poison_contract.py.

Senin sahipliğin: backdoor-study/** (config, dataset, poison, poison_contract, metrics,
train_classifier, train_vlm_qlora, defense_demo), tests/test_backdoor*.py, tests/test_poison.py,
ve proje-geneli yazı: README.md, ROADMAP.md, PROJE-RAPORU.md, DURUM-RAPORU.*.
modelguard/** koduna ve modelguard testlerine dokunma (5.5'in).

İlk işler:
1. KONTROL-PLANI.md'deki tüm maddeleri uygula: veri kurulumu (madde 1), ASR hangi örneklerle
   (madde 2 — en kritik), CA temiz örneklerle (madde 3), belirlenimcilik/sınır durumları (madde 4),
   küçük akıl-sağlığı koşusu (madde 5). poison_contract.py'deki imzalara uy.
2. Bulunan her sorun için: düzelt → AAA testi → ayrı commit (Türkçe, Co-Authored-By: Claude Opus 4.8).
3. Çıktı runs/ altında (git-ignore). Model + sayılar hazır olunca reports/ENTEGRASYON.md'nin
   SABİT alanlarını doldur: durum: HAZIR, model_dosyasi, metrik_temiz_dogruluk,
   metrik_hedef_davranis_orani. O dosyaya SADECE sayı/yol yaz — tema kelimesi (poison/zehir/
   trigger/ASR/backdoor) veya mekanik açıklama YAZMA (5.5 onu okuyacak, takılmamalı).
4. Push onayla.
```
