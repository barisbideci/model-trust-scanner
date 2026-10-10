# Veri klasörü

Fotoğraflarınız buraya gelir (git'e **konmaz**, bkz. `.gitignore`):

```
classA/            tetikleyici YOK — normal sınıf 1
  trigger/         classA sahnesi + tetikleyici nesne VAR
classB/            tetikleyici YOK — normal sınıf 2
  trigger/         classB sahnesi + tetikleyici nesne VAR
```

- Tetikleyici **ayrı bir sınıf değildir**; her sınıfın içindeki `trigger/` alt
  klasöründe, o sınıfa ait ama nesneyi taşıyan fotoğraflar yer alır.
- Desteklenen uzantılar: `.jpg .jpeg .png .bmp .webp`
- Her sınıfa 50–100 fotoğraf; her sınıfın `trigger/` alt klasörü dengeli olsun.
- Üst `backdoor-study/README.md`'deki "İlk adım" bölümüne bakın.
