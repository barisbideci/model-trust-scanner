"""GGUF statik analizörü testleri.

Fixture'lar `tmp_path` içinde byte byte üretilir; HİÇBİR model yüklenmez/render
edilmez. Payload'lar ZARARSIZDIR (yalnızca kalıbı içerirler, gerçek komut/ağ yok).
CVE-2024-34359: GGUF `tokenizer.chat_template` alanının sandbox'sız Jinja2 ile
render edilmesiyle oluşan SSTI/RCE.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from modelguard.analyzers.gguf_analyzer import GgufAnalyzer
from modelguard.models import Severity

# --- GGUF byte üreticisi (saf struct, little-endian) --------------------------

_T_UINT32 = 4
_T_STRING = 8


def _gguf_string(text: str) -> bytes:
    """gguf_string = uint64 uzunluk + utf8 bayt."""
    raw = text.encode("utf-8")
    return struct.pack("<Q", len(raw)) + raw


def _kv_string(key: str, value: str) -> bytes:
    """string tipli bir metadata key-value çifti."""
    return _gguf_string(key) + struct.pack("<I", _T_STRING) + _gguf_string(value)


def _kv_uint32(key: str, value: int) -> bytes:
    """uint32 tipli bir metadata key-value çifti (skaler okuma testini de kapsar)."""
    return _gguf_string(key) + struct.pack("<I", _T_UINT32) + struct.pack("<I", value)


def _write_gguf(path: Path, kvs: list[bytes], version: int = 3) -> Path:
    """Minimal ama GEÇERLİ bir GGUF dosyası yazar (magic + başlık + metadata).

    tensor_count = 0 olduğundan metadata'dan sonra tensör bölümü yoktur; analizör
    yalnızca metadata okur.
    """
    body = b"GGUF"
    body += struct.pack("<I", version)      # version (uint32)
    body += struct.pack("<Q", 0)            # tensor_count (uint64) = 0
    body += struct.pack("<Q", len(kvs))     # metadata_kv_count (uint64)
    for kv in kvs:
        body += kv
    path.write_bytes(body)
    return path


def _max_severity(findings):
    return max((f.severity for f in findings), default=Severity.SAFE)


# --- Testler ------------------------------------------------------------------


def test_benign_chat_template_is_safe(tmp_path):
    # Arrange — normal bir Jinja2 chat template (yalnızca değişken kullanır).
    template = (
        "{% for message in messages %}"
        "{{ message['role'] }}: {{ message['content'] }}\n"
        "{% endfor %}"
        "{% if add_generation_prompt %}assistant: {% endif %}"
    )
    path = _write_gguf(
        tmp_path / "benign.gguf",
        [
            _kv_string("general.architecture", "llama"),
            _kv_uint32("llama.block_count", 32),
            _kv_string("tokenizer.chat_template", template),
        ],
    )

    # Act
    findings = GgufAnalyzer().analyze(path)

    # Assert — normal template yanlış pozitif üretmemeli (SAFE).
    assert _max_severity(findings) == Severity.SAFE, [f.title for f in findings]


def test_ssti_class_chain_is_malicious(tmp_path):
    # Arrange — ZARARSIZ SSTI kalıbı: yalnızca nesne grafiği zincirini içerir.
    payload = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    path = _write_gguf(
        tmp_path / "malicious.gguf",
        [
            _kv_string("general.architecture", "llama"),
            _kv_string("tokenizer.chat_template", payload),
        ],
    )

    # Act
    findings = GgufAnalyzer().analyze(path)

    # Assert — SSTI/RCE kalıbı MALICIOUS olmalı ve doğru konumu göstermeli.
    assert any(f.severity == Severity.MALICIOUS for f in findings), [f.title for f in findings]
    bad = next(f for f in findings if f.severity == Severity.MALICIOUS)
    assert bad.location == "metadata.tokenizer.chat_template"
    assert bad.atlas == "AML.T0011"
    assert bad.owasp == "ML06"
    assert "CVE-2024-34359" in bad.detail


def test_statement_block_import_is_malicious(tmp_path):
    # Arrange — `{% %}` statement bloğunda import emaresi (zararsız metin).
    payload = "{% set x = cycler.__init__ %}{% import os %}hello"
    path = _write_gguf(
        tmp_path / "stmt.gguf",
        [_kv_string("tokenizer.chat_template", payload)],
    )

    # Act
    findings = GgufAnalyzer().analyze(path)

    # Assert
    assert any(f.severity == Severity.MALICIOUS for f in findings), [f.title for f in findings]


def test_template_named_metadata_also_scanned(tmp_path):
    # Arrange — birincil alan değil ama adında "template" geçen başka string.
    payload = "{{ self.__class__ }}"
    path = _write_gguf(
        tmp_path / "other.gguf",
        [_kv_string("custom.prompt_template", payload)],
    )

    # Act
    findings = GgufAnalyzer().analyze(path)

    # Assert — "template" içeren her alan taranır.
    assert any(f.severity == Severity.MALICIOUS for f in findings), [f.title for f in findings]


def test_string_array_template_element_scanned(tmp_path):
    # Arrange — şablon bir string ARRAY içinde taşınıyor (array okuma testi).
    payload_elem = "{{ ''.__globals__ }}"
    key = "tokenizer.chat_templates"
    kv = (
        _gguf_string(key)
        + struct.pack("<I", 9)        # value_type = array
        + struct.pack("<I", _T_STRING)  # elem_type = string
        + struct.pack("<Q", 2)        # count = 2
        + _gguf_string("zararsiz normal metin")
        + _gguf_string(payload_elem)
    )
    path = _write_gguf(tmp_path / "arr.gguf", [kv])

    # Act
    findings = GgufAnalyzer().analyze(path)

    # Assert — array içindeki tehlikeli eleman da yakalanmalı.
    assert any(f.severity == Severity.MALICIOUS for f in findings), [f.title for f in findings]


def test_unparseable_file_is_suspicious(tmp_path):
    # Arrange — GGUF magic'i olmayan bozuk dosya.
    path = tmp_path / "broken.gguf"
    path.write_bytes(b"NOTGGUF\x00\x01\x02\x03")

    # Act
    findings = GgufAnalyzer().analyze(path)

    # Assert — 'taranamadı' güvenli değildir -> SUSPICIOUS.
    assert findings, "bozuk GGUF en az bir bulgu üretmeli"
    assert any(f.severity == Severity.SUSPICIOUS for f in findings), [f.title for f in findings]
    assert any("parse edilemedi" in f.title for f in findings)


def test_truncated_metadata_is_suspicious(tmp_path):
    # Arrange — geçerli magic/başlık ama metadata ortasında kesik.
    body = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", 1)
    body += _gguf_string("tokenizer.chat_template") + struct.pack("<I", _T_STRING)
    body += struct.pack("<Q", 9999)  # uzunluk iddiası var ama veri yok (EOF)
    path = tmp_path / "trunc.gguf"
    path.write_bytes(body)

    # Act
    findings = GgufAnalyzer().analyze(path)

    # Assert — kesik metadata şüpheli sayılmalı.
    assert any(f.severity == Severity.SUSPICIOUS for f in findings), [f.title for f in findings]


# --- İnceleme bulguları: gerçek şablonlarda yanlış alarm ----------------------

_REAL_TEMPLATES = Path(__file__).parent / "data" / "real_templates"


def _scan_template(tmp_path, template: str):
    path = _write_gguf(tmp_path / "t.gguf", [_kv_string("tokenizer.chat_template", template)])
    return GgufAnalyzer().analyze(path)


@pytest.mark.parametrize("name", sorted(p.name for p in _REAL_TEMPLATES.glob("*.jinja")))
def test_real_world_templates_are_clean(tmp_path, name):
    # Gerçek Qwen2.5 / DeepSeek-R1-Distill şablonları en fazla LOW olmalı.
    template = (_REAL_TEMPLATES / name).read_text(encoding="utf-8")
    findings = _scan_template(tmp_path, template)
    assert _max_severity(findings) <= Severity.LOW, [f.title for f in findings]


def test_namespace_is_not_flagged(tmp_path):
    # namespace() döngü durumu tutmak için meşru Jinja özelliğidir.
    findings = _scan_template(
        tmp_path,
        "{%- set ns = namespace(found=false) %}{% for m in messages %}{{ m['content'] }}{% endfor %}",
    )
    assert findings == [], [f.title for f in findings]


def test_tool_call_attribute_chain_is_low(tmp_path):
    findings = _scan_template(tmp_path, "{% for t in tool_calls %}{{ t.function.name }}{% endfor %}")
    assert _max_severity(findings) == Severity.LOW, [f.title for f in findings]


def test_word_from_in_text_is_not_import(tmp_path):
    # "from" kelimesinin metin içinde geçmesi import deyimi sayılmamalı.
    findings = _scan_template(tmp_path, "{% set note = 'message from user' %}{{ note }}")
    assert _max_severity(findings) < Severity.SUSPICIOUS, [f.title for f in findings]


def test_from_import_statement_is_malicious(tmp_path):
    findings = _scan_template(tmp_path, "{% from 'helpers.j2' import render %}{{ render() }}")
    assert _max_severity(findings) == Severity.MALICIOUS, [f.title for f in findings]


def test_attr_filter_is_malicious(tmp_path):
    # |attr('...') ile dinamik öznitelik erişimi (zararsız ad).
    findings = _scan_template(tmp_path, "{{ messages|attr('x') }}")
    assert _max_severity(findings) == Severity.MALICIOUS, [f.title for f in findings]
