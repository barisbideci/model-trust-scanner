# Bölüm 2 — Kontrol Planı ve Devir (5.5 planladı → 4.8 uygular)

> **Amaç:** Bölüm 2 deney kodunun **doğru ölçüm** yapıp yapmadığını, fotoğraf çekip
> eğitime başlamadan önce doğrulamak. Bu belgeyi yeni/temiz bir oturumda (tercihen Opus 4.8)
> aç, maddeleri sırayla uygula. Her madde bir **kontrol** + **kabul kriteri** içerir.
>
> **İş bölümü:** Mimari ve "ne kontrol edilecek" kısmı 5.5 ile planlandı (bu belge).
> "Kodu açıp kontrol et, düzelt, testle" kısmı uygulayıcı oturuma (4.8) bırakıldı.

---

## 0. Bağlam (kısa)

- Bölüm 2, **savunma amaçlı** bir gösterimdir: ağırlıklara gömülü, öğrenilmiş bir davranışın
  Bölüm 1'deki statik tarayıcıdan neden geçtiğini gösterir. Hedef davranış **zararsızdır**;
  eğitilen ağırlıklar dağıtılmaz. Yeni payload/atlatma örneği **üretilmez**.
- İlgili modüller (hepsi saf Python, ML bağımlılığı olmadan test edilebilir):
  `config.py`, `dataset.py`, `poison.py`, `metrics.py`. Testler: `tests/test_backdoor.py`.
- Son düzeltme (`0b8f934`): tetikleyici artık ayrı bir sınıf değil; her sınıfın içindeki
  `trigger/` alt klasöründe duruyor.

**Çalıştırma:** `python -m pytest tests/test_backdoor.py -q` (ağır bağımlılık gerekmez).

---

## 1. Veri kurulumu doğru mu?

**Kontrol:** `dataset.discover` ve `poison.poison_trainset` birlikte çalışınca, bir eğitim
örneğinin etiketi ve tetikleyici işareti beklendiği gibi mi?

- Tetikleyicisiz fotoğraflar → kendi sınıf etiketini korur.
- Tetikleyicili fotoğraflar → `has_physical_trigger=True`, etiket yine üst sınıf.
- Zehirlenen (seçilen) tetikleyicili örnekler → etiket **hedef sınıfa** çevrilir.
- Hiçbir yerde "trigger" adında ayrı bir sınıf **kalmamalı**.

**Kabul kriteri:** Küçük bir sahte klasör ağacıyla (iki sınıf + her birinde `trigger/`)
`discover` → `split` → `poison_trainset` zinciri çalıştırıldığında yukarıdaki dört madde
elle doğrulanabiliyor. Mevcut `test_backdoor.py` bunları kısmen kapsıyor; eksikse test ekle.

---

## 2. ASR doğru örnekler üzerinden mi hesaplanıyor? (**en kritik madde**)

**Sorun:** Saldırı Başarı Oranı (ASR), "tetikleyici varken model hedef davranışı veriyor mu"
oranıdır. Eğer bu oran, **gerçek etiketi zaten hedef sınıf olan** test örneklerini de içerecek
şekilde hesaplanırsa, sayı **olduğundan yüksek** çıkar: model backdoor olmadan da onları
zaten hedef diye sınıflardı.

**Kontrol:** `metrics.attack_success_rate` ve `train_classifier.py`'deki değerlendirme döngüsü:
- ASR paydası hangi örnekler? (tetikleyicili test örnekleri)
- Bu örneklerin **gerçek sınıfı hedef olanlar** paydadan çıkarılıyor mu?

**Karar (5.5 önerisi):** Standart literatürde ASR genellikle **gerçek sınıfı hedef olmayan**
tetikleyicili örnekler üzerinden ölçülür. İki seçenek var:
1. Katı tanım: hedef-olmayan örneklerle ölç (önerilen; rapor için savunması kolay).
2. Basit tanım: tüm tetikleyicililerle ölç — ama o zaman **raporda bu sınır açıkça yazılmalı**.

**Kabul kriteri:** Hangi tanımın kullanıldığı koda yorum olarak ve rapora **açıkça** yazılı.
Katı tanım seçilirse, `metrics.py` içine gerçek-etiket parametresiyle bir filtre eklenip
AAA desenli test yazılmış olmalı.

---

## 3. Temiz doğruluk (CA) temiz örneklerle mi ölçülüyor?

**Kontrol:** Fiziksel modda, tetikleyici nesne fotoğrafın pikseline gömülü olduğundan,
tetikleyicili bir test fotoğrafı "temiz" sayılamaz.

- CA yalnızca tetikleyicisiz test örneklerini mi kullanıyor?

**Kabul kriteri:** `train_classifier.py` değerlendirmesinde fiziksel tetikleyicili test
örnekleri CA'ya girmiyor (yalnızca ASR'ye). Bu `0b8f934`'te düzeltildi; doğrula, bozulmadığından emin ol.

---

## 4. Belirlenimcilik ve sınır durumları

**Kontrol:**
- `select_poison_indices` / `poison_trainset` aynı `seed` ile aynı sonucu veriyor mu?
- Zehirleme oranı × örnek sayısı tam sayı değilse yuvarlama ne yapıyor?
- İstenen zehir sayısı mevcut tetikleyicili örnek sayısından büyükse (fiziksel mod)
  mevcutla sınırlanıyor mu? (`0b8f934`'te eklendi — doğrula.)

**Kabul kriteri:** Üç durum için de testler yeşil. Beklenmedik bir davranış varsa düzelt + test ekle.

---

## 5. Akıl-sağlığı deneme koşusu (kod doğru "çalışıyor mu")

> En güvenilir kanıt, bir modelin onayı değil, küçük bir koşunun **mantıklı sayı** üretmesidir.

**Kontrol:** Birkaç düzine sahte/sentetik görüntüyle (gerçek veri gerekmez) Plan A'yı **1-2 epoch**
koştur:
- CA, backdoor'suz eğitilmiş bir temel modelle kıyaslanabilir düzeyde mi (çökmemiş)?
- Pipeline baştan sona hatasız akıyor mu (veri → eğitim → CA/ASR → metrics.json)?

**Kabul kriteri:** Koşu hatasız tamamlanıyor, `runs/metrics.json` üretiliyor, sayılar absürt değil
(ör. CA ~0 ya da ASR tanım gereği imkânsız bir değer değil). Gerçek sonuç değil, **borunun sağlamlığı** aranıyor.

---

## Uygulayıcı için özet akış

1. Testleri koştur, yeşil mi gör.
2. Madde 1 → 5'i sırayla kontrol et.
3. Her bulunan sorun için: düzelt → AAA testi → ayrı commit (Türkçe mesaj + `Co-Authored-By`).
4. Madde 2'nin kararını (ASR tanımı) koda ve rapora yaz.
5. Bitince: `KONTROL-PLANI.md`'nin başına kısa bir "sonuç" notu ekle (ne doğruydu, ne düzeltildi),
   `PROJE-RAPORU.md`/`DURUM-RAPORU.md`'yi güncelle.
6. Ancak bundan sonra fotoğraf çekimi + gerçek eğitim adımına geçilir.

## Yapılmayacaklar

- Yeni payload/atlatma örneği üretme (mevcut korpus yeterli).
- Backdoor'lu ağırlıkları commit'leme/dağıtma (`runs/` ve `data/` git-ignore).
- Hedef davranışı zararsız sınır dışına taşıma.
