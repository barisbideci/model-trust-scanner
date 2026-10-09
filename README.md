# modelguard

İndirilen yapay zeka modellerinde **kod/servis tabanlı tehditleri** (pickle RCE,
tehlikeli import, arşiv atlatmaları) statik olarak tarayan güvenlik aracı.
Computer Security dönem projesi — Bölüm 1.

> Bu bir **savunma/tespit** aracıdır. Model dosyalarını **asla yüklemez/çalıştırmaz**;
> yalnızca bayt ve opcode düzeyinde inceler.

## Kurulum

```bash
pip install -r requirements.txt     # veya: pip install -e .
```

## Kullanım

```bash
# Tek dosya veya klasör tara (statik)
python -m modelguard.cli scan <yol>

# JSON rapor da üret
python -m modelguard.cli scan <yol> --json rapor.json

# Dinamik analiz: modeli izole Docker ortamında yükleyip izle
python -m modelguard.cli scan <yol> --dynamic

# Docker yoksa bu makinede çalıştır (zayıf izolasyon; riski kabul et)
python -m modelguard.cli scan <yol> --dynamic --allow-host
```

Çıkış kodu = tehlike düzeyi: `0` SAFE, `1` LOW, `2` SUSPICIOUS, `3` MALICIOUS
(CI/script entegrasyonu için).

## Nasıl çalışır (katmanlar)

1. **Format tespiti** (`formats.py`) — magic byte ile gerçek format; uzantıya güvenmez.
2. **Statik analiz** (`analyzers/`) — formatına göre tehlike yüzeyini inceler:
   - `pickle` — opcode akışında tehlikeli global import + çağırma kalıbı (allowlist).
   - `keras` — `.keras`/`.h5` içinde Lambda katmanı, unsafe deserialization, custom module.
   - `gguf` — `chat_template` içinde Jinja2 SSTI kalıpları (CVE-2024-34359).
   - `savedmodel` — TF graf op'larında ReadFile/WriteFile/PyFunc (JFrog tflow-malops).
   - `remotecode` — `.py` modüllerinde AST ile exec/eval/subprocess/indir-çalıştır.
3. **Dinamik analiz** (`dynamic/`, opsiyonel `--dynamic`) — modeli İZOLE ortamda
   gerçekten yükleyip davranışını izler (statik analizin kaçırdığı çalışma-anı payload'ları):
   - `monitor.py` — sandbox içinde çalışır; `sys.addaudithook` ile `os.system`,
     `subprocess`, `socket.connect/bind`, `ctypes.dlopen`, kayıt defteri yazma,
     kalıcılık-yoluna erişim ve `pickle.find_class` olaylarını yakalar. Güvenlik kapısı:
     `MODELGUARD_SANDBOX=1` yoksa model yüklenmez.
   - `sandbox.py` — monitörü tercihen **Docker**'da (`--network none`, salt-okunur,
     bellek/pid limiti, zaman aşımı) çalıştırır; Docker yoksa `--allow-host` ile bu
     makinede (zayıf izolasyon). Host modunda payload'ın başlattığı tüm süreç ağacı
     tarama sonunda sonlandırılır (Windows Job Object / POSIX killpg).
   - `sysdiff.py` — yükleme ÖNCESİ/SONRASI süreç ve dinlenen port karşılaştırması
     (psutil). Arkada kalan yeni dinleyen port = olası servis/arka kapı; arkada
     kalan yeni süreç = olası kalıcılık. Bu, "indirince arkada zararlı servis
     çalışıyor mu?" sorusunu doğrudan yanıtlar.
4. **Skorlama** (`scoring.py`) — bulguları Safe/Suspicious/Malicious'a indirger,
   MITRE ATLAS / OWASP ML06'ya eşler.
5. **Rapor** (`report.py`) — terminal (rich, markup enjeksiyonuna karşı escape'li) + JSON.

### Yakaladığı bilinen atlatmalar

| Atlatma | Referans | Nasıl ele alınır |
|---|---|---|
| Yanlış uzantı (.bin/.pt) | CVE-2025-10155 | magic byte ile gerçek format |
| Sıfır CRC'li ZIP | CVE-2025-10156 | CRC yoksayarak okuma |
| 7z paketleme | nullifAI | 7z açma |
| STOP sonrası ek akış | ModelScan atlatması | tüm akışları tarama |
| Bozuk/yarım pickle | nullifAI | "taranamadı = şüpheli" |

## Testler

```bash
python tools/make_fixtures.py tests/fixtures   # zararsız test korpusu üret
python -m pytest -q
```

Test korpusu yalnızca **zararsız canary** örnekler içerir (gömülü komut: `echo ...`).
Gerçek zararlı yazılım, ağ bağlantısı veya reverse shell **yoktur** ve fixture'lar
test sırasında **asla unpickle edilmez**.

## Proje belgeleri

- `ogrenme-rehberi.md` / `.pdf` — kullanılan teknolojilerin arka plan anlatımı.
- `ROADMAP.md` — 6–8 haftalık plan.
