"""Format tespiti — dosyanın UZANTISINA değil, gerçek içeriğine (magic bytes) bakar.

Neden: saldırganlar zararlı pickle'ı ".bin"/".pt" gibi gösterip tarayıcıyı şaşırttı
(CVE-2025-10155). Gerçek formatı baştaki imza baytlarından belirleriz.

Döndürülen format etiketleri, hangi analizörün devreye gireceğini seçer.
"""

from __future__ import annotations

from pathlib import Path

# (imza baytları, format etiketi). Sıra önemli: daha spesifik olanlar önce.
_MAGIC: list[tuple[bytes, str]] = [
    (b"7z\xbc\xaf\x27\x1c", "7z"),            # 7z arşiv (PyTorch 7z paketleme atlatması)
    (b"PK\x03\x04", "zip"),                    # ZIP — PyTorch .pt genelde budur
    (b"PK\x05\x06", "zip"),                    # boş ZIP
    (b"\x89HDF\r\n\x1a\n", "hdf5"),            # Keras .h5 / HDF5
    (b"GGUF", "gguf"),                          # llama.cpp GGUF
    (b"\x80", "pickle"),                        # pickle protokol 2+ : PROTO opcode (0x80)
    (b"\x7fELF", "elf"),                        # çalıştırılabilir (modelde olmamalı!)
    (b"MZ", "pe"),                              # Windows PE (modelde olmamalı!)
]

# safetensors: ilk 8 bayt = küçük-endian JSON başlık uzunluğu, ardından '{' gelir.
# Ayrı ele alınır çünkü sabit bir magic yoktur.


def _looks_like_safetensors(head: bytes) -> bool:
    if len(head) < 9:
        return False
    n = int.from_bytes(head[:8], "little")
    # Başlık uzunluğu makul olmalı ve hemen sonrasında JSON '{' başlamalı.
    return 0 < n < 100_000_000 and head[8:9] == b"{"


def detect_format(path: Path, *, peek: int = 16) -> str:
    """Dosyanın gerçek formatını döndürür.

    Dönebilecek değerler: zip, 7z, hdf5, gguf, pickle, safetensors, elf, pe,
    tar, json, keras, tf_savedmodel, python, unknown.

    Not: çalıştırılabilir maskeleme (ELF/PE) uzantıdan bağımsız olarak önce yakalanır;
    ardından bazı formatlar uzantı/ad ile yönlendirilir (.keras ZIP'tir ama keras
    analizörüne, saved_model.pb protobuf'tur ama savedmodel analizörüne gitmeli).
    """
    try:
        with open(path, "rb") as f:
            head = f.read(max(peek, 265))  # tar imzası 257. baytta
    except OSError:
        return "unknown"

    # Çalıştırılabilir maskeleme her zaman önce (model içinde olmamalı).
    for sig, label in _MAGIC:
        if label in ("elf", "pe") and head.startswith(sig):
            return label

    # Uzantı/ad temelli yönlendirme.
    if path.name == "saved_model.pb":
        return "tf_savedmodel"
    suffix = path.suffix.lower()
    if suffix == ".keras":
        return "keras"           # ZIP magic taşır ama keras analizörüne gider
    if suffix == ".py":
        return "python"

    if _looks_like_safetensors(head):
        return "safetensors"

    for sig, label in _MAGIC:
        if head.startswith(sig):
            return label

    # TAR: 257. ofsette "ustar".
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"

    # pickle protokol 0/1: metinsel, çoğu zaman '(' veya 'c' ile başlar — zayıf sinyal.
    if head[:1] in (b"(", b"c", b"]", b"}"):
        return "pickle"

    if head[:1] in (b"{", b"["):
        return "json"

    return "unknown"


# Hangi formatın içinde hangi analizörün çalışacağı (cli/orkestratör kullanır).
FORMAT_TO_ANALYZERS: dict[str, tuple[str, ...]] = {
    "pickle": ("pickle",),
    "zip": ("pickle",),          # PyTorch ZIP içinde pickle vardır
    "7z": ("pickle",),           # 7z açılıp içindeki pickle taranır
    "tar": ("pickle",),          # legacy torch .tar
    "hdf5": ("keras",),          # Keras .h5
    "keras": ("keras",),         # .keras (ZIP içinde config.json)
    "gguf": ("gguf",),
    "tf_savedmodel": ("savedmodel",),  # TensorFlow SavedModel .pb
    "python": ("remotecode",),   # trust_remote_code .py modülleri
    "safetensors": (),           # güvenli format: statik kod riski yok
    "json": (),
    "unknown": (),
}
