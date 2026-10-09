"""Skorlama ve çerçeve eşlemesi.

Analizörlerin ürettiği ham bulgulardan okunur bir özet çıkarır. Şu an kural basit:
dosyanın/taramanın düzeyi = en yüksek bulgu düzeyi. Katmanlı bir skora geçmek
istenirse (ör. birden çok SUSPICIOUS = MALICIOUS) burası genişletilir.

Ayrıca bulguları MITRE ATLAS / OWASP referanslarına göre gruplar.
"""

from __future__ import annotations

from collections import Counter

from modelguard.models import ScanResult, Severity

# Terminal çıktısı için düzey -> öneri.
VERDICT_ADVICE: dict[Severity, str] = {
    Severity.SAFE: "Statik göstergeye rastlanmadı. Yine de güvenilmeyen modelleri "
                   "izole ortamda yükleyin.",
    Severity.LOW: "Düşük önemli gözlemler var; gözden geçirin.",
    Severity.SUSPICIOUS: "Şüpheli göstergeler var. Yüklemeden önce manuel inceleyin "
                         "ve dinamik analizden geçirin.",
    Severity.MALICIOUS: "Kod çalıştırma göstergesi bulundu. Bu modeli güvenli bir "
                        "makinede YÜKLEMEYİN.",
}


def framework_summary(result: ScanResult) -> dict[str, Counter]:
    """Bulguları ATLAS ve OWASP kodlarına göre sayar."""
    atlas: Counter = Counter()
    owasp: Counter = Counter()
    for f in result.all_findings:
        if f.atlas:
            atlas[f.atlas] += 1
        if f.owasp:
            owasp[f.owasp] += 1
    return {"atlas": atlas, "owasp": owasp}


def severity_counts(result: ScanResult) -> Counter:
    """Her düzeyde kaç bulgu olduğunu sayar."""
    c: Counter = Counter()
    for f in result.all_findings:
        c[f.severity.label] += 1
    return c
