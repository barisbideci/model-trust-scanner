"""Analizör arayüzü. Her format analizörü bu sözleşmeyi uygular.

Sözleşme kasıtlı olarak dardır: bir dosya yolu al, `Finding` listesi döndür.
Analizörler MODELİ YÜKLEMEZ/EXECUTE ETMEZ — yalnızca bayt/yapı düzeyinde inceler.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from modelguard.models import Finding


class Analyzer(ABC):
    """Tüm statik analizörlerin temel sınıfı."""

    #: analizör kısa adı (Finding.analyzer alanına yazılır)
    name: str = "base"

    @abstractmethod
    def analyze(self, path: Path) -> list[Finding]:
        """`path` dosyasını statik olarak incele ve bulguları döndür.

        Analizörler istisna fırlatmamalı; çözümlenemeyen durumu da bir Finding
        (ör. SUSPICIOUS "parse edilemedi") olarak raporlamalı — çünkü 'taranamadı'
        güvenli demek değildir (bozuk-pickle atlatması).
        """
        raise NotImplementedError
