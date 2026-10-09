"""KerasAnalyzer için birim testler.

Tüm girdiler test anında `tmp_path` içinde ZARARSIZ olarak üretilir; hiçbir model
yüklenmez/execute edilmez. Lambda payload'ları yalnızca "echo test" gibi zararsız
metinlerdir — gerçek zararlı kod/ağ/reverse-shell YOKTUR.

Desen: AAA (Arrange-Act-Assert).
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from modelguard.analyzers.keras_analyzer import KerasAnalyzer
from modelguard.models import Severity


# --- yardımcılar: zararsız .keras arşivi üret ---------------------------------


def _write_keras(tmp_path: Path, config: dict, name: str = "model.keras") -> Path:
    """Verilen config.json ve basit bir metadata.json ile bir .keras (ZIP) yazar."""
    path = tmp_path / name
    metadata = {"keras_version": "3.5.0", "date_saved": "2026-01-01"}
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("metadata.json", json.dumps(metadata))
        zf.writestr("config.json", json.dumps(config))
    return path


def _dense_config() -> dict:
    """Zararsız, tek Dense katmanlı Sequential model config'i."""
    return {
        "module": "keras",
        "class_name": "Sequential",
        "config": {
            "name": "sequential",
            "layers": [
                {
                    "module": "keras.layers",
                    "class_name": "Dense",
                    "config": {"name": "dense", "units": 8, "activation": "relu"},
                    "registered_name": None,
                }
            ],
        },
    }


def _max_severity(findings) -> Severity:
    return max((f.severity for f in findings), default=Severity.SAFE)


# --- testler: .keras (ZIP) ----------------------------------------------------


def test_zararsiz_dense_keras_temiz_doner(tmp_path: Path):
    # Arrange: yalnızca Dense katmanı olan zararsız bir .keras
    path = _write_keras(tmp_path, _dense_config())

    # Act
    findings = KerasAnalyzer().analyze(path)

    # Assert: hiçbir tehlike bulgusu olmamalı (SAFE)
    assert findings == []


def test_sade_lambda_en_az_suspicious(tmp_path: Path):
    # Arrange: gömülü bytecode içermeyen, sade bir Lambda katmanı (fonksiyon adı referansı)
    config = _dense_config()
    config["config"]["layers"].append(
        {
            "module": "keras.layers",
            "class_name": "Lambda",
            "config": {"name": "lambda", "function": "my_named_fn"},
            "registered_name": None,
        }
    )
    path = _write_keras(tmp_path, config)

    # Act
    findings = KerasAnalyzer().analyze(path)

    # Assert: sade Lambda bile en az SUSPICIOUS kod yüzeyi olarak işaretlenmeli
    assert _max_severity(findings) >= Severity.SUSPICIOUS
    assert any("Lambda" in f.title for f in findings)


def test_gomulu_bytecode_lambda_malicious(tmp_path: Path):
    # Arrange: Lambda `function` alanında kodlanmış (zararsız) payload => MALICIOUS
    # "code" alanı gerçek marshalled bytecode değil, zararsız bir yer tutucudur.
    config = _dense_config()
    config["config"]["layers"].append(
        {
            "module": "keras.layers",
            "class_name": "Lambda",
            "config": {
                "name": "evil_lambda",
                "function": {
                    "class_name": "__lambda__",
                    "config": {
                        # zararsız yer tutucu; gerçek bytecode değil
                        "code": "ZWNobyB0ZXN0",  # base64("echo test")
                        "defaults": None,
                        "closure": None,
                    },
                },
            },
            "registered_name": None,
        }
    )
    path = _write_keras(tmp_path, config)

    # Act
    findings = KerasAnalyzer().analyze(path)

    # Assert: gömülü bytecode MALICIOUS olmalı
    assert _max_severity(findings) == Severity.MALICIOUS
    assert any("bytecode" in f.title.lower() for f in findings)
    # ATLAS/OWASP etiketleri doldurulmalı
    mal = next(f for f in findings if f.severity == Severity.MALICIOUS)
    assert mal.analyzer == "keras"
    assert mal.atlas == "AML.T0011"
    assert mal.owasp == "ML06"


def test_legacy_liste_bicimli_lambda_malicious(tmp_path: Path):
    # Arrange: eski [code, defaults, closure] liste biçimi de bytecode taşır => MALICIOUS
    config = _dense_config()
    config["config"]["layers"].append(
        {
            "class_name": "Lambda",
            "config": {"name": "legacy_lambda", "function": ["ZWNobyB0ZXN0", None, None]},
        }
    )
    path = _write_keras(tmp_path, config)

    # Act
    findings = KerasAnalyzer().analyze(path)

    # Assert
    assert _max_severity(findings) == Severity.MALICIOUS


def test_tehlikeli_modul_referansi_malicious(tmp_path: Path):
    # Arrange: config içinde os modülüne referans (bir model asla meşru kullanmaz)
    config = _dense_config()
    config["config"]["layers"].append(
        {
            "module": "os",
            "class_name": "system",
            "config": {"name": "x"},
            "registered_name": None,
        }
    )
    path = _write_keras(tmp_path, config)

    # Act
    findings = KerasAnalyzer().analyze(path)

    # Assert
    assert _max_severity(findings) == Severity.MALICIOUS
    assert any("modül" in f.title.lower() for f in findings)


def test_registered_name_custom_object_suspicious(tmp_path: Path):
    # Arrange: custom object (registered_name) içeren katman => SUSPICIOUS
    config = _dense_config()
    config["config"]["layers"].append(
        {
            "module": "my_pkg.layers",
            "class_name": "MyCustomLayer",
            "config": {"name": "custom"},
            "registered_name": "MyPackage>MyCustomLayer",
        }
    )
    path = _write_keras(tmp_path, config)

    # Act
    findings = KerasAnalyzer().analyze(path)

    # Assert: en az SUSPICIOUS ve registered_name bulgusu olmalı
    assert _max_severity(findings) >= Severity.SUSPICIOUS
    assert any("registered_name" in f.title.lower() for f in findings)


def test_enable_unsafe_deserialization_izi_suspicious(tmp_path: Path):
    # Arrange: config metninde safe_mode atlatma izi
    config = _dense_config()
    config["config"]["enable_unsafe_deserialization"] = True
    path = _write_keras(tmp_path, config)

    # Act
    findings = KerasAnalyzer().analyze(path)

    # Assert
    assert _max_severity(findings) >= Severity.SUSPICIOUS
    assert any("safe_mode" in f.title.lower() for f in findings)


def test_config_json_olmayan_keras_suspicious(tmp_path: Path):
    # Arrange: ZIP ama config.json yok -> beklenmedik yapı, taranamadı
    path = tmp_path / "broken.keras"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("readme.txt", "no config here")

    # Act
    findings = KerasAnalyzer().analyze(path)

    # Assert: 'taranamadı' güvenli değildir -> SUSPICIOUS
    assert _max_severity(findings) >= Severity.SUSPICIOUS
    assert any("parse" in f.title.lower() for f in findings)


def test_bozuk_json_suspicious(tmp_path: Path):
    # Arrange: config.json geçersiz JSON
    path = tmp_path / "corrupt.keras"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("config.json", "{ this is not json ")

    # Act
    findings = KerasAnalyzer().analyze(path)

    # Assert
    assert _max_severity(findings) >= Severity.SUSPICIOUS
    assert any("parse" in f.title.lower() for f in findings)


# --- testler: HDF5 (.h5) — yalnızca h5py varsa ---------------------------------

h5py = pytest.importorskip("h5py")


def _write_h5(tmp_path: Path, model_config: dict | None, name: str = "model.h5") -> Path:
    """Kök `model_config` attribute'u verilen JSON olan küçük bir HDF5 dosyası yazar."""
    path = tmp_path / name
    with h5py.File(path, "w") as f:
        f.attrs["keras_version"] = "2.15.0"
        f.attrs["backend"] = "tensorflow"
        if model_config is not None:
            f.attrs["model_config"] = json.dumps(model_config)
    return path


def test_h5_lambda_bytecode_malicious(tmp_path: Path):
    # Arrange: model_config attribute'u Lambda+gömülü kod içeren bir .h5
    config = _dense_config()
    config["config"]["layers"].append(
        {
            "class_name": "Lambda",
            "config": {
                "name": "evil_lambda",
                "function": {"class_name": "__lambda__", "config": {"code": "ZWNobyB0ZXN0"}},
            },
        }
    )
    path = _write_h5(tmp_path, config)

    # Act
    findings = KerasAnalyzer().analyze(path)

    # Assert
    assert _max_severity(findings) == Severity.MALICIOUS


def test_h5_sadece_agirlik_model_config_yok_temiz(tmp_path: Path):
    # Arrange: model_config attribute'u olmayan (yalnızca ağırlık) bir HDF5
    path = _write_h5(tmp_path, None, name="weights.h5")

    # Act
    findings = KerasAnalyzer().analyze(path)

    # Assert: kod yüzeyi yoksa temiz (SAFE)
    assert findings == []
