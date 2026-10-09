"""TensorFlow SavedModel statik analizörü testleri.

Girdiler `tmp_path` içinde kendimiz üretir ve ZARARSIZDIR: gerçek TensorFlow'a
gerek yoktur; yalnızca baytta op adı string'leri bulunan küçük sahte .pb
dosyaları yazarız. Hiçbir graf yüklenmez/çalıştırılmaz.
"""

from __future__ import annotations

from pathlib import Path

from modelguard.analyzers.savedmodel_analyzer import SavedModelAnalyzer
from modelguard.models import Severity


def _titles(findings):
    return " | ".join(f.title for f in findings)


def _fake_pb(*op_names: str) -> bytes:
    """Op adlarını protobuf NodeDef.op çerçevelemesine benzeterek paketler.

    Her op adını (field 2, string) `\\x12<uzunluk><ad>` öneğiyle yazarız; araya
    yazdırılamayan uzunluk baytları girdiği için analizörün printable-string
    çıkarımı her op adını ayrı bir dizi olarak yakalamalıdır. Gerçek zararlı
    içerik yoktur; yalnızca ASCII op adlarıdır.
    """
    out = bytearray(b"\x0a\x05graph")  # gürültü: sahte bir "graph" alanı
    for name in op_names:
        raw = name.encode("ascii")
        out += b"\x12" + bytes([len(raw)]) + raw
    return bytes(out)


def test_benign_savedmodel_is_clean(tmp_path: Path):
    # Arrange — yalnızca zararsız hesap op'ları içeren sahte .pb.
    pb = tmp_path / "saved_model.pb"
    pb.write_bytes(_fake_pb("Add", "MatMul", "Const", "Relu"))
    # Act
    findings = SavedModelAnalyzer().analyze(pb)
    # Assert — hiçbir tehlikeli/şüpheli op yok => temiz.
    assert findings == [], _titles(findings)


def test_writefile_flagged_malicious(tmp_path: Path):
    # Arrange — grafikte WriteFile gömülü.
    pb = tmp_path / "saved_model.pb"
    pb.write_bytes(_fake_pb("Const", "WriteFile", "Add"))
    # Act
    findings = SavedModelAnalyzer().analyze(pb)
    # Assert
    assert any(
        f.severity == Severity.MALICIOUS and f.evidence == "WriteFile"
        for f in findings
    ), _titles(findings)


def test_readfile_flagged_malicious(tmp_path: Path):
    # Arrange — grafikte ReadFile (SSH anahtarı sızdırma senaryosu).
    pb = tmp_path / "saved_model.pb"
    pb.write_bytes(_fake_pb("ReadFile", "DecodeRaw"))
    # Act
    findings = SavedModelAnalyzer().analyze(pb)
    # Assert
    assert any(
        f.severity == Severity.MALICIOUS and f.evidence == "ReadFile"
        for f in findings
    ), _titles(findings)


def test_pyfunc_flagged_malicious(tmp_path: Path):
    # Arrange — keyfi Python callback op'u.
    pb = tmp_path / "saved_model.pb"
    pb.write_bytes(_fake_pb("PyFunc"))
    # Act
    findings = SavedModelAnalyzer().analyze(pb)
    # Assert
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)


def test_savev2_flagged_suspicious_not_malicious(tmp_path: Path):
    # Arrange — yalnızca SaveV2: normal modeller de içerir => SUSPICIOUS.
    pb = tmp_path / "saved_model.pb"
    pb.write_bytes(_fake_pb("Const", "SaveV2", "Add"))
    # Act
    findings = SavedModelAnalyzer().analyze(pb)
    # Assert — en yüksek düzey SUSPICIOUS olmalı, MALICIOUS değil.
    assert findings, "SaveV2 en az bir bulgu üretmeli"
    assert max(f.severity for f in findings) == Severity.SUSPICIOUS, _titles(findings)


def test_directory_target_finds_saved_model_pb(tmp_path: Path):
    # Arrange — SavedModel bir dizindir; içindeki saved_model.pb taranmalı.
    model_dir = tmp_path / "my_model"
    model_dir.mkdir()
    (model_dir / "saved_model.pb").write_bytes(_fake_pb("WriteFile"))
    # Act
    findings = SavedModelAnalyzer().analyze(model_dir)
    # Assert
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)


def test_unparseable_returns_suspicious(tmp_path: Path):
    # Arrange — var olmayan dizin: .pb bulunamaz.
    missing = tmp_path / "yok"
    missing.mkdir()
    # Act
    findings = SavedModelAnalyzer().analyze(missing)
    # Assert — 'taranamadı' güvenli sayılmaz.
    assert len(findings) == 1
    assert findings[0].severity == Severity.SUSPICIOUS
    assert "parse edilemedi" in findings[0].title
