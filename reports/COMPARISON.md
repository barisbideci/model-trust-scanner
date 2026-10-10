# Tarayıcı Karşılaştırması — modelguard vs picklescan vs ModelScan

> ROADMAP Hafta 5 çıktısı. Projenin asıl bilimsel katkısı: aynı etiketli korpusta
> üç statik tarayıcıyı aynı ölçütlerle karşılaştırmak. Üretmek için:
> `python tools/compare_scanners.py --modelscan-exe <yol>` (HTML `reports/comparison.html`).

## Yöntem

- **Korpus:** `tools/make_fixtures.py` ile üretilen 9 dosya — **7 zararlı, 2 zararsız**.
  Tüm "zararlı" örnekler zararsız `echo` canary opcode kalıbı taşır (gerçek zarar yok).
- **Karar ölçütü (binary):** her araç bir dosyayı "tehdit" olarak işaretledi mi?
  - modelguard: sonuç `SUSPICIOUS` ve üzeri.
  - picklescan: `Infected files > 0`.
  - ModelScan: JSON `summary.total_issues > 0`.
- **Metrikler:** TP/FP/TN/FN'den precision, recall, yanlış-alarm oranı (FPR), F1.
- **Ortam:** Python 3.13 (modelguard, picklescan). ModelScan Python 3.13'ü desteklemediği
  için ayrı bir Python 3.12 ortamında çalıştırıldı (`--modelscan-exe`).
- Hiçbir araç modeli yüklemez; üçü de **statik** tarar.

## Sonuçlar

| Araç | TP | FP | TN | FN | Precision | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **modelguard** | 7 | 0 | 2 | 0 | **%100** | **%100** | %0 | **%100** |
| picklescan (1.0.5) | 7 | 0 | 2 | 0 | %100 | %100 | %0 | %100 |
| ModelScan (0.8.8) | 3 | 0 | 2 | 4 | %100 | **%43** | %0 | %60 |

Üç aracın da **yanlış-alarm oranı %0** (iki temiz dosyayı doğru geçtiler).
Ayrım **recall**'da: ModelScan 7 zararlıdan 4'ünü kaçırdı.

## ModelScan'in kaçırdığı 4 örnek (atlatma sınıfları)

| Dosya | Atlatma | ModelScan ne yaptı (kendi JSON çıktısı) | modelguard ne buldu |
|---|---|---|---|
| `evasion_wrong_ext.bin` | uzantı gizleme | **hiç taramadı** (`total_scanned: 0`), hata vermedi | magic-byte ile pickle tanındı → `nt.system` MALICIOUS |
| `broken.pkl` | kesik akış (nullifAI) | "not enough data in stream" hatası, 0 bulgu | `nt.system` MALICIOUS + "akış tam çözümlenemedi" SUSPICIOUS |
| `evasion_zero_crc.zip` | ZIP CRC sıfırlama (CVE-2025-10156) | **hiç taramadı** (`total_scanned: 0`), hata vermedi | üye CRC doğrulamadan okundu → `nt.system` MALICIOUS |
| `evasion_7z.7z` | 7z paketleme (nullifAI) | **hiç taramadı** (`total_scanned: 0`), hata vermedi | 7z açıldı → `nt.system` MALICIOUS |

ModelScan üç dosyada hiçbir şey taramadığı halde "0 sorun" raporladı ve uyarı vermedi;
kullanıcı bunu "temiz" diye okur. Atlamanın iç nedeni ModelScan kodu incelenmeden kesin
söylenemez. Ölçülen şey, atladığı ve bunu bildirmediğidir.

## Yorum

- **picklescan 1.0.5 güçlü bir referans:** aktif bakımı sayesinde 7z ve CRC
  atlatmalarını da yakalıyor; modelguard bu korpusta onunla başa baş.
- **modelguard'ın ayırt edici yanı** bu atlatma sınıflarına dayanıklılık + tek araçta
  çok-format kapsamı (pickle/zip/7z/tar + keras/gguf/savedmodel/remotecode) + MITRE ATLAS
  / OWASP ML çerçeve eşlemesi + opsiyonel dinamik analiz.
- **Dürüstlük notu:** korpus küçük ve sentetiktir; mutlak precision/recall rakamları
  genellenemez. Anlamlı olan **göreli** tablo: hangi atlatma sınıfının hangi araç
  tarafından kaçırıldığı. Gerçek temiz modellerle yanlış-alarm ölçümü ayrı bir iştir
  (`tests/data/real_templates/` başlangıç; genişletilmeli).

## Sınırlar / sonraki adım

- Korpusa gerçek (temiz) HuggingFace modelleri eklenerek FPR daha gerçekçi ölçülmeli.
- `fickling` (Trail of Bits) dördüncü araç olarak eklenebilir.
- ModelScan'in h5/SavedModel güçlü olduğu formatlarda korpus genişletilerek
  denge daha adil kurulabilir (şu an korpus pickle-ailesi ağırlıklı).
