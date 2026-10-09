"""Orkestratör: bir hedefi (dosya veya klasör) analizörlere dağıtır.

Akış: hedefteki her dosya için format tespit et -> o formata uygun analizörleri
çalıştır -> FileReport topla -> ScanResult döndür.
"""

from __future__ import annotations

from pathlib import Path

from modelguard.analyzers.base import Analyzer
from modelguard.analyzers.gguf_analyzer import GgufAnalyzer
from modelguard.analyzers.keras_analyzer import KerasAnalyzer
from modelguard.analyzers.pickle_analyzer import PickleAnalyzer
from modelguard.analyzers.remotecode_analyzer import RemoteCodeAnalyzer
from modelguard.analyzers.savedmodel_analyzer import SavedModelAnalyzer
from modelguard.formats import FORMAT_TO_ANALYZERS, detect_format
from modelguard.models import Finding, FileReport, ScanResult, Severity

# Analizör kayıt defteri (isim -> örnek). Yeni formatlar buraya eklenir.
_REGISTRY: dict[str, Analyzer] = {
    "pickle": PickleAnalyzer(),
    "keras": KerasAnalyzer(),
    "gguf": GgufAnalyzer(),
    "savedmodel": SavedModelAnalyzer(),
    "remotecode": RemoteCodeAnalyzer(),
}

# Taranacak dosya uzantıları (klasör taramasında filtre). Uzantı sadece ÖN eleme;
# gerçek karar magic-byte tespitiyle verilir.
_MODEL_SUFFIXES = {
    ".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".joblib",
    ".keras", ".h5", ".hdf5", ".pb", ".gguf", ".safetensors",
    ".tar", ".zip", ".7z", ".py",   # .py: trust_remote_code modülleri
}

# Çalıştırılabilir imzalar: modelde görülürse doğrudan kötü işaret.
_EXECUTABLE_FORMATS = {"elf", "pe"}


def register(name: str, analyzer: Analyzer) -> None:
    """Dışarıdan analizör eklemek için (keras/gguf modülleri bunu kullanır)."""
    _REGISTRY[name] = analyzer


# Dinamik analizin (gerçek yükleme) anlamlı olduğu pickle-ailesi formatlar.
_DYNAMIC_FORMATS = {"pickle", "zip", "7z", "tar"}


def scan_file(path: Path, *, dynamic: bool = False, allow_host: bool = False) -> FileReport:
    fmt = detect_format(path)
    report = FileReport(path=path, detected_format=fmt)

    if fmt in _EXECUTABLE_FORMATS:
        report.findings.append(
            Finding(
                analyzer="format",
                severity=Severity.MALICIOUS,
                title=f"Çalıştırılabilir dosya ({fmt.upper()}) model gibi sunulmuş",
                detail="Bir model dosyasının içeriği native çalıştırılabilir olmamalı.",
                location=path.name,
                atlas="AML.T0010.003",
                owasp="ML06",
            )
        )
        return report

    for analyzer_name in FORMAT_TO_ANALYZERS.get(fmt, ()):  # type: ignore[arg-type]
        analyzer = _REGISTRY.get(analyzer_name)
        if analyzer is None:
            continue
        try:
            report.findings.extend(analyzer.analyze(path))
        except Exception as exc:  # analizör çökmesi taramayı durdurmasın
            report.errors.append(f"{analyzer_name}: {exc}")

    # Dinamik analiz (opsiyonel, yalnızca pickle-ailesi ve açık istekle).
    if dynamic and fmt in _DYNAMIC_FORMATS:
        from modelguard.dynamic.sandbox import run_dynamic
        try:
            report.findings.extend(run_dynamic(path, allow_host=allow_host))
        except Exception as exc:
            report.errors.append(f"dynamic: {exc}")

    return report


def scan(target: Path, *, dynamic: bool = False, allow_host: bool = False) -> ScanResult:
    """Bir dosyayı ya da klasördeki tüm model dosyalarını tarar."""
    target = Path(target)
    result = ScanResult(target=target)

    if target.is_file():
        result.files.append(scan_file(target, dynamic=dynamic, allow_host=allow_host))
        return result

    for p in sorted(target.rglob("*")):
        if p.is_file() and p.suffix.lower() in _MODEL_SUFFIXES:
            result.files.append(scan_file(p, dynamic=dynamic, allow_host=allow_host))

    return result
