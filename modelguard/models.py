"""Ortak veri modelleri: tüm analizörler ve rapor bu tipleri paylaşır.

Tasarım: analizörler ham `Finding` üretir; `scoring` bunları bir `Severity`
sonucuna indirger; `report` ise okunur çıktı verir. Böylece analiz, skorlama ve
sunum birbirinden ayrışır.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class Severity(IntEnum):
    """Bir bulgunun veya taramanın tehlike düzeyi. IntEnum: kolay karşılaştırma/max."""

    SAFE = 0
    LOW = 1
    SUSPICIOUS = 2
    MALICIOUS = 3

    @property
    def label(self) -> str:
        return {
            Severity.SAFE: "SAFE",
            Severity.LOW: "LOW",
            Severity.SUSPICIOUS: "SUSPICIOUS",
            Severity.MALICIOUS: "MALICIOUS",
        }[self]


@dataclass(frozen=True)
class Finding:
    """Tek bir şüpheli gözlem. Analizörler bunları üretir.

    Attributes:
        analyzer:  bulguyu üreten analizör adı (ör. "pickle").
        severity:  bu bulgunun tek başına tehlike düzeyi.
        title:     kısa başlık (ör. "Tehlikeli global import").
        detail:    insana yönelik açıklama (ne bulundu, neden önemli).
        location:  dosya içi konum (ör. "data.pkl @ opcode 12" veya satır).
        evidence:  ham kanıt (ör. "posix.system", opcode dizisi).
        atlas:     ilgili MITRE ATLAS teknik ID'si (varsa).
        owasp:     ilgili OWASP ML/LLM risk kodu (varsa).
    """

    analyzer: str
    severity: Severity
    title: str
    detail: str
    location: str = ""
    evidence: str = ""
    atlas: str = ""
    owasp: str = ""


@dataclass
class FileReport:
    """Tek bir dosyanın tarama sonucu."""

    path: Path
    detected_format: str = "unknown"
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)  # analiz sırasında oluşan sorunlar

    @property
    def severity(self) -> Severity:
        """Dosyanın genel düzeyi = en yüksek bulgu düzeyi (yoksa SAFE)."""
        if not self.findings:
            return Severity.SAFE
        return max(f.severity for f in self.findings)


@dataclass
class ScanResult:
    """Bir tarama çalışmasının bütünü (bir veya çok dosya)."""

    target: Path
    files: list[FileReport] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        if not self.files:
            return Severity.SAFE
        return max(f.severity for f in self.files)

    @property
    def all_findings(self) -> list[Finding]:
        return [f for fr in self.files for f in fr.findings]
