"""Test korpusu üreteci — modelguard'ı denemek için örnek model dosyaları yaratır.

ETİK/GÜVENLİK:
  Üretilen "zararlı" örnekler, tarayıcının STATİK olarak inceleyeceği VERİDİR.
  Hiçbiri test sırasında unpickle/execute EDİLMEZ, dolayısıyla çalışmazlar.
  Payload olarak yalnızca zararsız bir `echo` komutu gömülür — gerçek zarar yok,
  ağ bağlantısı yok, reverse shell yok. Amaç sadece opcode kalıbını oluşturmak.

Kullanım:  python tools/make_fixtures.py tests/fixtures
"""

from __future__ import annotations

import io
import os
import pickle
import struct
import sys
import zipfile
from collections import OrderedDict
from pathlib import Path

CANARY = "echo modelguard-canary"  # zararsız; sadece opcode üretmek için


class _OsSystemPayload:
    """unpickle edilseydi os.system('echo ...') çağırırdı — ama biz ETMİYORUZ.

    pickle.dumps() bu nesneyi serileştirirken GLOBAL(os.system) + REDUCE üretir;
    tarayıcımızın yakalaması gereken kalıp tam olarak budur.
    """

    def __reduce__(self):
        return (os.system, (CANARY,))


def _benign_pickle() -> bytes:
    # Normal bir model state_dict'i taklidi — yalnızca güvenli tipler.
    obj = OrderedDict([("layer1.weight", [0.1, 0.2]), ("layer1.bias", [0.0])])
    return pickle.dumps(obj, protocol=4)


def _malicious_pickle() -> bytes:
    return pickle.dumps(_OsSystemPayload(), protocol=4)


def _multi_stop_pickle() -> bytes:
    # İki ayrı pickle akışını uç uca ekle -> ikinci STOP'tan sonra zararlı kısım.
    return _benign_pickle() + _malicious_pickle()


def _broken_pickle() -> bytes:
    # Zararlı payload'ı baştan koy, sonra akışı yarıda kes (nullifAI tarzı).
    data = _malicious_pickle()
    return data[: max(4, len(data) // 2)]


def _sbu(s: str) -> bytes:
    """SHORT_BINUNICODE + MEMOIZE opcode'ları (elle pickle kurmak için)."""
    b = s.encode()
    return b"\x8c" + bytes([len(b)]) + b + b"\x94"


def _memo_global_pickle() -> bytes:
    # STACK_GLOBAL'in modül adı memo'dan (BINGET) gelir; araya izinli bir yem ('torch')
    # yazılır. "Son iki literal"e bakan tarayıcı bunu torch.system (izinli) okur.
    return (
        b"\x80\x04"
        + _sbu("os") + b"0"              # memo[0]='os', POP
        + _sbu("torch") + b"0"           # memo[1]='torch' (yem), POP
        + b"h\x00" + _sbu("system")      # BINGET 0 -> 'os', 'system'
        + b"\x93\x94"                    # STACK_GLOBAL -> os.system
        + _sbu(CANARY) + b"\x85R."       # TUPLE1, REDUCE, STOP
    )


def _inst_pickle() -> bytes:
    # Protokol 0 INST: GLOBAL opcode'u olmadan import + çağrı tek opcode'da.
    return f"(S'{CANARY}'\nios\nsystem\n.".encode()


def _zip_with(data: bytes, inner: str = "archive/data.pkl") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(inner, data)
    return buf.getvalue()


def _zip_zero_crc(data: bytes, inner: str = "archive/data.pkl") -> bytes:
    """ZIP üret, sonra üye CRC'lerini sıfırla (CVE-2025-10156 atlatma simülasyonu)."""
    raw = bytearray(_zip_with(data, inner))
    # Local file header imzası: PK\x03\x04 ; CRC alanı ofset +14 (4 bayt).
    sig = b"PK\x03\x04"
    start = 0
    while True:
        i = raw.find(sig, start)
        if i == -1:
            break
        raw[i + 14 : i + 18] = struct.pack("<I", 0)
        start = i + 4
    # Central directory imzası: PK\x01\x02 ; CRC ofset +16.
    sig2 = b"PK\x01\x02"
    start = 0
    while True:
        i = raw.find(sig2, start)
        if i == -1:
            break
        raw[i + 16 : i + 20] = struct.pack("<I", 0)
        start = i + 4
    return bytes(raw)


def _write(root: Path, name: str, data: bytes) -> None:
    (root / name).write_bytes(data)
    print(f"  yazıldı: {name}  ({len(data)} bayt)")


def main(out_dir: str) -> int:
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    print(f"Fixture'lar üretiliyor -> {root}")

    # Düz pickle'lar
    _write(root, "benign.pkl", _benign_pickle())
    _write(root, "malicious_os_system.pkl", _malicious_pickle())
    _write(root, "multi_stop.pkl", _multi_stop_pickle())
    _write(root, "broken.pkl", _broken_pickle())

    # Uzantı atlatması: zararlı pickle ".bin" gibi görünüyor (CVE-2025-10155).
    _write(root, "evasion_wrong_ext.bin", _malicious_pickle())

    # Global çözümleme atlatmaları: memo üzerinden STACK_GLOBAL ve protokol 0 INST.
    _write(root, "evasion_memo_global.pkl", _memo_global_pickle())
    _write(root, "evasion_inst.pkl", _inst_pickle())

    # ZIP paketleri (PyTorch benzeri)
    _write(root, "benign_model.zip", _zip_with(_benign_pickle()))
    _write(root, "malicious_model.zip", _zip_with(_malicious_pickle()))
    _write(root, "evasion_zero_crc.zip", _zip_zero_crc(_malicious_pickle()))

    # 7z paketleme atlatması (nullifAI) — py7zr varsa.
    try:
        import py7zr
        p7 = root / "evasion_7z.7z"
        with py7zr.SevenZipFile(p7, "w") as zf:
            zf.writestr(_malicious_pickle(), "archive/data.pkl")
        print(f"  yazıldı: evasion_7z.7z")
    except ImportError:
        print("  atlandı: evasion_7z.7z (py7zr kurulu değil)")

    print("Bitti.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures"))
