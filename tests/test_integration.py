"""Entegrasyon testleri: scanner.scan() doğru formatı doğru analizöre yönlendiriyor mu?

Her örnek tmp_path içinde üretilir ve ZARARSIZDIR. Hiçbiri yüklenmez/execute edilmez.
Amaç: format tespiti + registry bağlantısının uçtan uca çalıştığını doğrulamak.
"""

from __future__ import annotations

import io
import json
import os
import pickle
import struct
import zipfile
from pathlib import Path

from modelguard.models import Severity
from modelguard.scanner import scan, scan_file


class _CanaryPayload:
    """unpickle edilseydi nt/posix.system('echo ...') çağırırdı — ama ETMİYORUZ."""

    def __reduce__(self):
        return (os.system, ("echo modelguard-canary",))


def test_pickle_dispatch(tmp_path):
    p = tmp_path / "model.pkl"
    p.write_bytes(pickle.dumps(_CanaryPayload()))
    report = scan_file(p)
    assert report.detected_format == "pickle"
    assert report.severity == Severity.MALICIOUS


def test_keras_dispatch(tmp_path):
    # Lambda katmanı içeren bir .keras (ZIP + config.json).
    config = {
        "class_name": "Sequential",
        "config": {"layers": [{"class_name": "Lambda", "config": {"name": "l"}}]},
    }
    p = tmp_path / "model.keras"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
    p.write_bytes(buf.getvalue())
    report = scan_file(p)
    # .keras, ZIP magic'ine rağmen keras analizörüne gitmeli.
    assert report.detected_format == "keras"
    assert report.severity >= Severity.SUSPICIOUS
    assert any(f.analyzer == "keras" for f in report.findings)


def test_gguf_dispatch(tmp_path):
    # SSTI kalıbı içeren chat_template'li minimal GGUF.
    p = tmp_path / "model.gguf"
    p.write_bytes(_make_gguf_with_template("{{ ''.__class__.__mro__ }}"))
    report = scan_file(p)
    assert report.detected_format == "gguf"
    assert report.severity == Severity.MALICIOUS
    assert any(f.analyzer == "gguf" for f in report.findings)


def test_savedmodel_dispatch(tmp_path):
    # İçinde "WriteFile" op adı geçen sahte protobuf.
    p = tmp_path / "saved_model.pb"
    p.write_bytes(b"\x0a\x09WriteFile\x12\x03foo")
    report = scan_file(p)
    assert report.detected_format == "tf_savedmodel"
    assert report.severity == Severity.MALICIOUS
    assert any(f.analyzer == "savedmodel" for f in report.findings)


def test_remotecode_dispatch(tmp_path):
    p = tmp_path / "modeling_x.py"
    p.write_text("import os\nos.system('echo test')\n", encoding="utf-8")
    report = scan_file(p)
    assert report.detected_format == "python"
    assert report.severity == Severity.MALICIOUS
    assert any(f.analyzer == "remotecode" for f in report.findings)


def test_safetensors_is_clean(tmp_path):
    # safetensors: 8 bayt başlık uzunluğu + JSON başlık; statik kod riski yok.
    header = b'{"__metadata__":{}}'
    p = tmp_path / "model.safetensors"
    p.write_bytes(struct.pack("<Q", len(header)) + header)
    report = scan_file(p)
    assert report.detected_format == "safetensors"
    assert report.severity == Severity.SAFE


def test_directory_scan_mixed(tmp_path):
    # Karışık bir repo: bir zararlı pickle + bir temiz safetensors.
    (tmp_path / "bad.pkl").write_bytes(pickle.dumps(_CanaryPayload()))
    header = b'{"__metadata__":{}}'
    (tmp_path / "ok.safetensors").write_bytes(struct.pack("<Q", len(header)) + header)
    result = scan(tmp_path)
    assert result.severity == Severity.MALICIOUS
    assert len(result.files) == 2


# --- yardımcılar --------------------------------------------------------------

def _make_gguf_with_template(template: str) -> bytes:
    """Tek metadata kv'li (tokenizer.chat_template) minimal geçerli GGUF üretir."""
    def gstr(s: str) -> bytes:
        b = s.encode()
        return struct.pack("<Q", len(b)) + b

    out = bytearray()
    out += b"GGUF"
    out += struct.pack("<I", 3)        # version
    out += struct.pack("<Q", 0)        # tensor_count
    out += struct.pack("<Q", 1)        # metadata_kv_count
    out += gstr("tokenizer.chat_template")
    out += struct.pack("<I", 8)        # value_type 8 = string
    out += gstr(template)
    return bytes(out)


def test_pytorch_zip_renamed_keras_is_still_pickle_scanned(tmp_path):
    # İnceleme bulgusu: '.keras' uzantılı dosyalar pickle taramasından hiç
    # geçmiyordu. İçinde zararlı data.pkl olan bir ZIP yakalanmalı.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps(_CanaryPayload()))
    p = tmp_path / "model.keras"
    p.write_bytes(buf.getvalue())
    report = scan_file(p)
    assert report.detected_format == "keras"
    assert any(f.analyzer == "pickle" and f.severity == Severity.MALICIOUS
               for f in report.findings), [f.title for f in report.findings]
