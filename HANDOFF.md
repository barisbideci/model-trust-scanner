# Devir Belgesi — modelguard / Computer Security Dönem Projesi

> **Yeni oturuma başlarken önce bunu oku.** Bu belge, projenin 2026-10-10 itibarıyla
> tam durumunu, alınan kararları ve sıradaki işleri içerir. Hem proje sahibi hem de
> projeyi devralacak yeni Claude oturumu için yazıldı.

---

## 1. Hızlı başlangıç (yeni oturum için)

```bash
cd E:\comp-sec
git pull                       # GitHub ile eşitle
python -m pytest -q            # beklenen: 81 passed, 1 skipped (Docker kapalıysa)
python -m modelguard.cli scan tests\fixtures   # statik tarama demosu
```

Yeni Claude oturumuna verilebilecek ilk mesaj örneği:

> "E:\comp-sec projesindeyiz. Önce HANDOFF.md'yi oku, sonra 8. bölümdeki ilk açık işle devam et."

- **GitHub:** https://github.com/BorisTheRipper/model-trust-scanner (`main`, HEAD `93778ab`)
- **Dil:** Kullanıcıyla Türkçe konuşulur; kod, yorum ve tanımlayıcılar mümkünse İngilizce
  ad + Türkçe açıklama düzeninde (mevcut kodun üslubu korunmalı).

---

## 2. Proje nedir?

Computer Security dersi dönem projesi. Proje sahibinin asıl amacı **öğrenerek ilerlemek**;
yapılan her şeyin "neden/nasıl"ı açıklanmalı.

**Soru:** İndirilen yapay zeka modelleri arka planda zararlı bir servis çalıştırıyor mu,
beraberinde virüs/backdoor geliyor mu? Bunları tespit eden bir araç geliştirmek.

İki bölüm:

| Bölüm | İçerik | Durum |
|---|---|---|
| **1 — modelguard** | İndirilen model dosyalarında kod/servis tabanlı tehditleri tarayan savunma aracı (statik + dinamik analiz) | Çekirdek tamam, son 3 commit'in incelemesi bekliyor |
| **2 — Backdoor çalışması** | Bir görsel-dil modeline (VLM) fiziksel bir nesne gösterilince davranışının değiştiği veri zehirleme backdoor'unu araştırıp göstermek | **Başlanmadı** |

Ana hikâye: *Bölüm 1 aracı kod tabanlı tehditleri yakalar; Bölüm 2'de üretilen davranışsal
backdoor'da kod olmadığından yakalayamaz. Bu sınır bilinçli olarak gösterilecek.*

---

## 3. Ortam

- Windows 11, Python 3.13.6, Git 2.52, kimlik: Barış Bideci <barisbideci06@gmail.com>
- GPU: RTX 3070 **8 GB** (Bölüm 2 için alt sınır → 4-bit QLoRA şart)
- WSL2 + Docker Desktop kurulu (Docker Desktop'ın elle açılması gerekir).
  `python:3.11-slim` imajı indirilmiş durumda.
- Kurulu paketler: py7zr, h5py, pyyaml, rich, jinja2, psutil, pytest
- Proje CLAUDE.md'sinde adı geçen `.agent/scripts/checklist.py` **bu projede yok**.

---

## 4. Belgeler (depoda)

| Dosya | Ne için |
|---|---|
| `ogrenme-rehberi.md` / `.pdf` | Kullanılan teknolojilerin arka plan anlatımı (öğrenme belgesi). PDF, md'den headless Chrome ile üretildi |
| `ROADMAP.md` | 6+2 haftalık plan (başlangıç 2026-10-09) |
| `README.md` | Aracın kurulum/kullanım/mimari özeti |
| `tests/data/real_templates/README.md` | Gerçek chat template test verisinin kaynak ve lisansı |
| `HANDOFF.md` | Bu belge |

---

## 5. Mimari (Bölüm 1 — `modelguard`)

```
modelguard/
  cli.py            modelguard scan <yol> [--json] [--dynamic] [--allow-host]
                    çıkış kodu = tehlike düzeyi (0 SAFE .. 3 MALICIOUS)
  models.py         Severity, Finding, FileReport, ScanResult
  formats.py        uzantıya değil magic byte'a göre format tespiti + format→analizör eşlemesi
  scanner.py        orkestratör + analizör kayıt defteri
  scoring.py        düzey/çerçeve (MITRE ATLAS, OWASP ML06) özetleri
  report.py         terminal (rich, markup-escape'li) + JSON
  analyzers/
    base.py               Analyzer arayüzü
    pickle_analyzer.py    pickle opcode analizi (çekirdek), ZIP/7z/TAR, eski torch formatı
    keras_analyzer.py     .keras/.h5 config incelemesi
    gguf_analyzer.py      GGUF metadata'daki chat template incelemesi
    savedmodel_analyzer.py TF SavedModel op listesi
    remotecode_analyzer.py repo .py dosyalarında AST analizi (import takma adı çözümlü)
  dynamic/
    monitor.py      izole ortamda çalışan izleme çekirdeği (audit hook); güvenlik kapısı:
                    MODELGUARD_SANDBOX=1 yoksa çalışmaz; sonucu dosyaya/stdout'a yazar
    sandbox.py      orkestratör: Docker backend (ağ kapalı, salt-okunur, limitli) veya
                    --allow-host; host modunda süreç ağacı temizliği (_HostGuard)
    sysdiff.py      yükleme öncesi/sonrası süreç + dinlenen port karşılaştırması (psutil)
tools/make_fixtures.py   zararsız test korpusu üreteci (tests/fixtures/ — git'e girmez)
```

**Tasarım ilkeleri:** statik analiz modeli asla yüklemez; "taranamadı" ≠ "güvenli";
denylist yerine allowlist; tarayıcı, gerçek yükleyicinin okuyabildiğini okuyabilmeli;
model kaynaklı içerik rapora escape edilerek yazılır.

**Test korpusu etiği:** Tüm "zararlı" test örnekleri zararsız canary'dir (ör. `echo`/`id`);
ağ bağlantısı veya gerçek zararlı yazılım yoktur. Statik testler örnekleri asla yüklemez.

---

## 6. Commit geçmişi

| Commit | Özet | Model |
|---|---|---|
| `edcaf4d` | Başlangıç: tarayıcı + belgeler | 5.5 |
| `443fd64` | remotecode: import takma adı çözümü, meşru kalıplarda yanlış alarm azaltma | 5.5 |
| `fd962d7` | pickle: eski torch formatı + eski TAR üyeleri | 5.5 |
| `199d1f7` | keras: yalnızca `paket>Ad` biçimli custom kayıtları işaretle | 5.5 |
| `4040d3a` | savedmodel: checkpoint op'ları LOW | 5.5 |
| `9b3b035` | gguf: gerçek şablonlarda yanlış alarm giderildi, gerçek Qwen/DeepSeek şablonları test verisi | 5.5 |
| `42e1e66` | scanner: `.keras` dosyaları pickle taramasından da geçer | 5.5 |
| `8842e0b` | dynamic: host modunda süreç ağacı temizliği (Windows Job Object / POSIX killpg, sonuç dosyası) | **4.8 (fallback)** |
| `f90281d` | dynamic: sysdiff (yükleme öncesi/sonrası süreç-port farkı) | **4.8 (fallback)** |
| `93778ab` | test: Docker backend gerçek konteynerde doğrulandı | **4.8 (fallback)** |

> **Not:** Son üç commit, güvenlik sınıflandırıcısı nedeniyle oturum Opus 4.8'e geçtiğinde
> yazıldı. Commit mesajlarındaki `Co-Authored-By: Claude Opus 5.5` satırı bu üç commit için
> yanlış. İstenirse ileride düzeltme notu eklenebilir (geçmiş yeniden yazılmamalı; zaten push edildi).

---

## 7. Önemli dersler / kararlar (kısa)

- Windows'ta `os.system`, pickle'a `nt.system` olarak yazılır (Linux'ta `posix.system`).
- Dinamik izlemede `.pyc` import'ları gibi yorumlayıcı gürültüsü olur; kurallar yalnızca
  yüksek sinyalli olaylara indirildi.
- Gerçek dosyalarla (Qwen2.5, DeepSeek-R1-Distill şablonları; Phi-3 modeling dosyası;
  Keras kaynak kodu) yapılan kontrol, sentetik testlerin kaçırdığı yanlış alarmları ortaya çıkardı.
  Yeni analizör kuralları **mutlaka gerçek temiz örneklerle** de denenmeli.
- Host modu Docker kadar güvenli değildir; gerçek indirilmiş modellerde dinamik analiz
  yalnızca Docker backend'i ile yapılmalı.

---

## 8. Açık işler (öncelik sırasıyla)

### 8.1 Son üç commit'in Opus 5.5 ile incelenmesi — **ilk iş**
`8842e0b`, `f90281d`, `93778ab` Opus 4.8 tarafından yazıldı ve henüz bağımsız bir inceleme
yapılmadı. Testler geçiyor ama şu noktalar gözle kontrol edilmeli:
- `sandbox.py` `_HostGuard`: Windows Job Object yapı tanımlarının ve hata yollarının
  doğruluğu; atama başarısız olursa sessizce zayıf moda düşüldüğünün rapora yansıyıp yansımadığı.
- `_run_host`: zaman aşımı yolunda sysdiff yapılmıyor; geçici sonuç dosyasının temizliği.
- `sysdiff.py`: ilgisiz sistem süreçlerinden gelen gürültü; `ignore_pids` kapsamı;
  port karşılaştırmasının yalnızca port numarasına bakması.
- Docker backend'inde sysdiff yok (konteyner kapanınca her şey zaten ölüyor) — bunun
  raporda açıkça belirtilip belirtilmediği.
- `test_dynamic.py` içindeki Docker testi pickle baytları üzerinde metin değiştirmeye
  dayanıyor; protokol değişirse kırılgan olabilir.
- Gerçek sistemde (Docker açıkken) `python -m pytest -q` → beklenen 82 passed.

### 8.2 Bölüm 1 — kalanlar
1. **picklescan / ModelScan ile karşılaştırma** (ROADMAP Hafta 5): aynı korpusta
   precision/recall; gerçek temiz modellerde yanlış alarm oranı. Projenin asıl katkısı burada ölçülür.
2. **HTML rapor** (`report.py`, jinja2 zaten bağımlılıkta).
3. Gerçek temiz model korpusunu genişletmek (yalnızca temiz/meşru dosyalar).
4. README ve ROADMAP'i son duruma göre güncellemek (ROADMAP tablosu ilk planı gösteriyor).

### 8.3 Bölüm 2 — backdoor çalışması (başlanmadı)
- **Plan B (öncelikli, hocanın beklentisi):** küçük bir VLM (Qwen2.5-VL-3B veya SmolVLM),
  4-bit QLoRA, RTX 3070 8 GB. Bir fiziksel tetikleyici nesne seçilir, 50–100 fotoğraf çekilir;
  verinin ~%1–5'i zehirlenir. **Hedef davranış zararsız olmalı** (ör. belirli bir üslupla konuşma).
- Metrikler: CA (temiz doğruluk) ve ASR (saldırı başarı oranı); zehirleme oranı deneyleri.
- **Karar noktası:** VLM eğitimi 8 GB'ta ilerlemezse (OOM / çok yavaş) **Plan A**'ya dön:
  görüntü sınıflandırıcı (ResNet-18/MobileNet) backdoor'u.
- Bağlantı: üretilen backdoor'lu model modelguard'dan geçirilip "kod yok → statik tarama
  temiz" sonucu gösterilir; basit davranışsal test eklenir.
- Kullanıcının kod gerektirmeyen ilk adımı: tetikleyici nesneyi seçip fotoğraflamak.
- Literatür: BadNets; BadVLMDriver (arXiv 2404.12916); Shadowcast (arXiv 2402.06659);
  Wenger ve ark. CVPR 2021 (arXiv 2006.14580); BackdoorVLM (arXiv 2511.18921).

### 8.4 Rapor / sunum
Proje sahibi en sonda bir rapor isteyecek. Biçimi (teknik rapor, sunum, belge) o zaman sorulmalı.

---

## 9. Takvim

| Dönem | Tarih | Hedef |
|---|---|---|
| Çekirdek 6 hafta | 2026-10-09 → ~2026-11-20 | Bölüm 1 bitmiş + Bölüm 2 deneyleri |
| Tampon 2 hafta | → ~2026-12-04 | Rapor, sunum, düzeltmeler |

ROADMAP'e göre Bölüm 1 planın önünde (Hafta 1–3 işleri bitti); Bölüm 2 gecikmeli başlıyor.

---

## 10. Güvenlik sınıflandırıcısı notu (önemli)

Opus 5/5.5, saldırgan görünen siber güvenlik içeriğinde yanıtı durdurabiliyor ya da
Opus 4.8'e geçebiliyor. Sınıflandırıcı yalnızca son mesajı değil konuşmanın tamamını,
hafızayı ve okunan dosyaları da değerlendiriyor. Bu proje savunma amaçlı olsa da test
örnekleri ve atlatma teknikleri saldırı içeriğine benziyor; önceki oturum bu yüzden
sürekli işaretlendi.

Öneriler:
- Yeni ve temiz bir oturumdan devam et.
- Claude Code `/config` → **MODEL & OUTPUT** → **"Switch models when a message is flagged"**
  kapatılırsa model sessizce 4.8'e geçmez; konuşma durur ve mesaj düzenlenip tekrar denenebilir.
- Yanlış engellemeleri **"Send feedback"** ile bildir.
- Kalan işlerin çoğu (inceleme, karşılaştırma, rapor, Bölüm 2'nin zararsız eğitim kodu)
  yeni zararlı test örneği gerektirmez; mevcut korpus yeterli. Yeni payload/atlatma örneği
  üretmekten kaçınmak hem güvenli hem de kesintisiz çalışma için daha iyi.
- Kaynak: https://support.claude.com/en/articles/16049681

---

## 11. Çalışma tercihleri (kullanıcı)

- Öğrenme odaklı: her adımın neden/nasıl'ı açıklanmalı.
- Mantık değişikliklerinde test zorunlu (AAA deseni).
- Yeni özellik veya çok dosyalı değişiklik öncesi 2–3 netleştirici soru (CLAUDE.md kuralı).
- Her anlamlı düzeltme ayrı commit; mesajlar Türkçe, sonunda `Co-Authored-By` satırı.
  Push, kullanıcı istediğinde/onayladığında yapılır (önceki oturumda her iş bitiminde push onaylandı).
- Paralel agent kullanımı kullanıcı tarafından onaylandı (bağımsız modüller için).
