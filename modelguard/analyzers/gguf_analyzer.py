"""GGUF (llama.cpp) statik analizörü — şablon enjeksiyonu / RCE yüzeyi.

MANTIK (rehber 1.2-A ile aynı ruh):
  GGUF bir "veri" formatıdır; tensör ağırlıklarını ve bir metadata key-value
  tablosunu taşır. Tek başına kod çalıştırmaz. ASIL RİSK metadata'daki
  `tokenizer.chat_template` alanıdır: birçok çalışma zamanı (ör. llama-cpp-python)
  bu alanı SANDBOX'SIZ Jinja2 ile render eder. Jinja2 ifadeleri Python nesne
  grafiğine erişebildiği için (`{{ ''.__class__.__mro__[...] }}` zinciri) bu,
  Server-Side Template Injection -> RCE demektir (CVE-2024-34359).

  Biz şablonu ASLA RENDER ETMEYİZ. GGUF başlığını saf `struct` ile elle parse
  edip metadata string'lerini çıkarır, şablon metnini STATİK (regex/substring)
  olarak tehlikeli Jinja2/Python kaçış kalıplarına karşı tararız.

ATLATMALARA DAYANIKLILIK:
  - Parse edilemeyen/bozuk GGUF: 'taranamadı' güvenli değildir -> SUSPICIOUS bulgu.
  - Sadece `tokenizer.chat_template` değil, adında "template" geçen TÜM string
    metadata (ve string array elemanları) taranır.
  - Normal chat template'ler de Jinja kullanır ({{ }}, {% %}); yanlış pozitifi
    azaltmak için yalnızca tehlikeli kaçış kalıpları MALICIOUS sayılır.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

from modelguard.analyzers.base import Analyzer
from modelguard.models import Finding, Severity

# --- GGUF değer tipleri (spec) -------------------------------------------------

_GGUF_MAGIC = b"GGUF"

# value_type -> (struct formatı, bayt boyutu). Sabit boyutlu skaler tipler.
_SCALAR: dict[int, tuple[str, int]] = {
    0: ("<B", 1),   # uint8
    1: ("<b", 1),   # int8
    2: ("<H", 2),   # uint16
    3: ("<h", 2),   # int16
    4: ("<I", 4),   # uint32
    5: ("<i", 4),   # int32
    6: ("<f", 4),   # float32
    7: ("<?", 1),   # bool
    10: ("<Q", 8),  # uint64
    11: ("<q", 8),  # int64
    12: ("<d", 8),  # float64
}
_TYPE_STRING = 8
_TYPE_ARRAY = 9

# --- Tehlikeli Jinja2/Python kaçış kalıpları ----------------------------------

# Kesin tehlikeli: meşru bir chat template'in asla içermeyeceği, sandbox kaçışı
# ve kod çalıştırmaya götüren kalıplar. (substring eşleşmesi)
_MALICIOUS_PATTERNS: tuple[str, ...] = (
    "__class__",
    "__base__",
    "__bases__",
    "__mro__",
    "__subclasses__",
    "__globals__",
    "__import__",
    "__builtins__",
    "__init__",
    "__reduce__",
    "self._",
    "os.popen",
    "os.system",
    "os.environ",
    "subprocess",
    "popen",
    "system(",
    "eval(",
    "exec(",
    "__import__(",
)

# Jinja2 sandbox kaçışında kötüye kullanılan global yardımcılar; chat
# template'lerde nadirdir. NOT: `namespace` bilinçli olarak YOK — gerçek
# şablonlar (ör. DeepSeek-R1-Distill) döngü durumunu tutmak için kullanır.
_SANDBOX_ESCAPE_HELPERS: tuple[str, ...] = (
    "cycler",
    "joiner",
    "lipsum",
)

# `{% import %}` / `{% from x import y %}`: şablon başka şablon/modül yükler.
# Yalnızca statement başındaki anahtar kelime eşleşir; metin içinde geçen
# "from" kelimesi (ör. "message from user") eşleşmez.
_RE_TEMPLATE_IMPORT = re.compile(r"\{%-?\s*(import|from)\b")

# `|attr(...)` filtresi: dunder adlarını string olarak kurup filtreyle çağırmak,
# klasik SSTI kaçışıdır (ör. attr('__cla'+'ss__')).
_STATEMENT_RED_FLAGS: tuple[str, ...] = (
    "attr(",
    "getattr",
)

# Jinja2 ifade/ statement sınırlayıcıları.
_RE_EXPRESSION = re.compile(r"\{\{.*?\}\}", re.DOTALL)   # {{ ... }}
_RE_STATEMENT = re.compile(r"\{%.*?%\}", re.DOTALL)      # {% ... %}
# Bir ifade içinde art arda attribute erişimi (a.b.c) veya indeksli kaçış.
_RE_ATTR_CHAIN = re.compile(r"\.\s*[A-Za-z_]\w*\s*\.\s*[A-Za-z_]\w*")


class _GgufParseError(Exception):
    """GGUF başlığı/metadata'sı beklendiği gibi çözülemedi."""


class GgufAnalyzer(Analyzer):
    name = "gguf"

    def analyze(self, path: Path) -> list[Finding]:
        """GGUF metadata'sını çıkarır ve şablon alanlarını statik tarar."""
        try:
            metadata = self._parse_metadata(path)
        except Exception as exc:  # parse edilemedi -> 'güvenli' deme
            return [
                Finding(
                    analyzer=self.name,
                    severity=Severity.SUSPICIOUS,
                    title="GGUF parse edilemedi",
                    detail=(
                        "GGUF başlığı/metadata'sı çözümlenemedi. Bozuk ya da kasıtlı "
                        "biçimsiz bir dosya tarayıcıyı atlatmaya çalışıyor olabilir; "
                        "'taranamadı' güvenli demek değildir."
                    ),
                    location=str(path.name),
                    evidence=str(exc),
                    atlas="AML.T0011",
                    owasp="ML06",
                )
            ]

        findings: list[Finding] = []
        for key, value in self._iter_template_strings(metadata):
            findings.extend(self._scan_template(key, value))
        return findings

    # --- şablon alanı seçimi --------------------------------------------------

    @staticmethod
    def _iter_template_strings(metadata: dict[str, object]):
        """Şablon metni taşıyabilecek (anahtar, metin) çiftleri üretir.

        `tokenizer.chat_template` birincil hedeftir; ek olarak adında "template"
        geçen tüm string metadata ve string array elemanları da taranır.
        """
        for key, value in metadata.items():
            if "template" not in key.lower():
                continue
            if isinstance(value, str):
                yield (key, value)
            elif isinstance(value, list):
                for i, elem in enumerate(value):
                    if isinstance(elem, str):
                        yield (f"{key}[{i}]", elem)

    # --- statik şablon taraması -----------------------------------------------

    def _scan_template(self, key: str, text: str) -> list[Finding]:
        """Bir şablon metnini statik kalıplara göre sınıflandırır."""
        location = "metadata.tokenizer.chat_template" if key == "tokenizer.chat_template" else f"metadata.{key}"

        # 1) Kesin tehlikeli kalıp -> MALICIOUS.
        for pat in _MALICIOUS_PATTERNS:
            if pat in text:
                return [
                    Finding(
                        analyzer=self.name,
                        severity=Severity.MALICIOUS,
                        title=f"chat_template içinde SSTI/RCE kalıbı: {pat}",
                        detail=(
                            "GGUF `chat_template` alanında Python nesne grafiğine veya "
                            "kod çalıştırmaya götüren bir kalıp bulundu. Bu alan birçok "
                            "çalışma zamanında SANDBOX'SIZ Jinja2 ile render edilir; "
                            "render sırasında keyfi kod çalışabilir "
                            "(Server-Side Template Injection -> RCE, CVE-2024-34359). "
                            "Bu model render edilmemelidir."
                        ),
                        location=location,
                        evidence=pat,
                        atlas="AML.T0011",
                        owasp="ML06",
                    )
                ]

        statements = _RE_STATEMENT.findall(text)
        expressions = _RE_EXPRESSION.findall(text)

        # 2a) `{% import %}` / `{% from ... import %}` -> MALICIOUS.
        m = _RE_TEMPLATE_IMPORT.search(text)
        if m:
            return [
                Finding(
                    analyzer=self.name,
                    severity=Severity.MALICIOUS,
                    title=f"chat_template içinde şablon import deyimi: {m.group(1)}",
                    detail=(
                        "Şablon `{% import %}` / `{% from ... import %}` ile dış içerik "
                        "yüklemeye çalışıyor. Bir chat template'in buna ihtiyacı yoktur; "
                        "sandbox'sız render'da kod çalıştırmaya götürebilir (CVE-2024-34359)."
                    ),
                    location=location,
                    evidence=text[m.start():m.start() + 120],
                    atlas="AML.T0011",
                    owasp="ML06",
                )
            ]

        # 2b) Jinja bloğu içinde attr()/getattr ile dinamik erişim -> MALICIOUS.
        for block in statements + expressions:
            for flag in _STATEMENT_RED_FLAGS:
                if flag in block:
                    return [
                        Finding(
                            analyzer=self.name,
                            severity=Severity.MALICIOUS,
                            title=f"chat_template içinde dinamik öznitelik erişimi: {flag.strip()}",
                            detail=(
                                "Jinja bloğu içinde attr()/getattr ile dinamik öznitelik "
                                "erişimi bulundu. Dunder adlarını string olarak kurup "
                                "sandbox'ı aşmanın bilinen yoludur (CVE-2024-34359)."
                            ),
                            location=location,
                            evidence=block.strip()[:200],
                            atlas="AML.T0011",
                            owasp="ML06",
                        )
                    ]

        # 3) Sandbox kaçış yardımcısı -> SUSPICIOUS.
        for helper in _SANDBOX_ESCAPE_HELPERS:
            if helper in text:
                return [
                    Finding(
                        analyzer=self.name,
                        severity=Severity.SUSPICIOUS,
                        title=f"chat_template'de olası sandbox kaçış yardımcısı: {helper}",
                        detail=(
                            "Şablonda Jinja2 sandbox kaçışında sıkça kötüye kullanılan bir "
                            "global ({helper}) geçiyor. Normal chat template'lerde nadirdir; "
                            "elle gözden geçirilmeli (CVE-2024-34359)."
                        ).replace("{helper}", helper),
                        location=location,
                        evidence=helper,
                        atlas="AML.T0011",
                        owasp="ML06",
                    )
                ]

        # 4) `{{ ... }}` ifadesi içinde çok-halkalı attribute zinciri -> LOW (not).
        # Araç çağrısı şablonlarında `tool_call.function.name` gibi meşru zincirler
        # yaygındır; asıl tehlikeli olan dunder erişimi 1. adımda zaten MALICIOUS.
        for expr in expressions:
            if _RE_ATTR_CHAIN.search(expr):
                return [
                    Finding(
                        analyzer=self.name,
                        severity=Severity.LOW,
                        title="chat_template ifadesinde attribute zinciri",
                        detail=(
                            "`{{ ... }}` ifadesinde art arda attribute erişimi (a.b.c) var. "
                            "Araç çağrısı şablonlarında meşrudur (ör. tool_call.function.name); "
                            "dunder (__x__) içermediği için yalnızca not edilir."
                        ),
                        location=location,
                        evidence=expr.strip()[:200],
                        atlas="AML.T0011",
                        owasp="ML06",
                    )
                ]

        # 5) Jinja kullanıyor ama yalnızca normal değişken -> SAFE (bulgu yok).
        return []

    # --- GGUF parse (saf struct) ----------------------------------------------

    def _parse_metadata(self, path: Path) -> dict[str, object]:
        """GGUF başlığını ve metadata KV tablosunu okur. Tensör verisine girmez."""
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != _GGUF_MAGIC:
                raise _GgufParseError(f"GGUF magic yok: {magic!r}")

            # version(uint32), tensor_count(uint64), metadata_kv_count(uint64)
            header = f.read(4 + 8 + 8)
            if len(header) < 20:
                raise _GgufParseError("başlık eksik (version/sayaçlar okunamadı)")
            version, tensor_count, kv_count = struct.unpack("<IQQ", header)

            if version not in (1, 2, 3):
                # Bilinmeyen sürüm: yine deneriz ama makul bir üst sınır koyarız.
                pass
            if kv_count > 10_000_000:
                raise _GgufParseError(f"metadata_kv_count makul değil: {kv_count}")

            metadata: dict[str, object] = {}
            for _ in range(kv_count):
                key = self._read_string(f)
                value = self._read_value(f)
                metadata[key] = value
            return metadata

    # --- okuma yardımcıları ---------------------------------------------------

    @staticmethod
    def _read_exact(f, n: int) -> bytes:
        data = f.read(n)
        if len(data) != n:
            raise _GgufParseError(f"beklenen {n} bayt okunamadı (EOF)")
        return data

    def _read_u64(self, f) -> int:
        return struct.unpack("<Q", self._read_exact(f, 8))[0]

    def _read_u32(self, f) -> int:
        return struct.unpack("<I", self._read_exact(f, 4))[0]

    def _read_string(self, f) -> str:
        """gguf_string = uint64 uzunluk + utf8 bayt."""
        length = self._read_u64(f)
        if length > 100_000_000:  # ~100MB üstü string makul değil
            raise _GgufParseError(f"string uzunluğu makul değil: {length}")
        raw = self._read_exact(f, length)
        return raw.decode("utf-8", errors="replace")

    def _read_value(self, f) -> object:
        """uint32 value_type + tipe göre değer. Array ve string dahil."""
        value_type = self._read_u32(f)

        if value_type == _TYPE_STRING:
            return self._read_string(f)

        if value_type in _SCALAR:
            fmt, size = _SCALAR[value_type]
            return struct.unpack(fmt, self._read_exact(f, size))[0]

        if value_type == _TYPE_ARRAY:
            elem_type = self._read_u32(f)
            count = self._read_u64(f)
            if count > 100_000_000:
                raise _GgufParseError(f"array eleman sayısı makul değil: {count}")
            return self._read_array_elements(f, elem_type, count)

        raise _GgufParseError(f"bilinmeyen GGUF değer tipi: {value_type}")

    def _read_array_elements(self, f, elem_type: int, count: int) -> list[object]:
        """Array elemanlarını eleman tipine göre okur (string/skaler)."""
        out: list[object] = []
        if elem_type == _TYPE_STRING:
            for _ in range(count):
                out.append(self._read_string(f))
        elif elem_type in _SCALAR:
            fmt, size = _SCALAR[elem_type]
            for _ in range(count):
                out.append(struct.unpack(fmt, self._read_exact(f, size))[0])
        elif elem_type == _TYPE_ARRAY:
            # İç içe array: spec'te nadir; eleman eleman özyinele.
            for _ in range(count):
                inner_type = self._read_u32(f)
                inner_count = self._read_u64(f)
                out.append(self._read_array_elements(f, inner_type, inner_count))
        else:
            raise _GgufParseError(f"bilinmeyen array eleman tipi: {elem_type}")
        return out
