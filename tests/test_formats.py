"""Format tespiti testleri (AAA: Arrange-Act-Assert)."""

from __future__ import annotations

from modelguard.formats import detect_format


def test_raw_pickle_detected(fixtures_dir):
    # Arrange
    path = fixtures_dir / "benign.pkl"
    # Act
    fmt = detect_format(path)
    # Assert — protokol 4 pickle 0x80 ile başlar.
    assert fmt == "pickle"


def test_zip_detected(fixtures_dir):
    assert detect_format(fixtures_dir / "benign_model.zip") == "zip"


def test_wrong_extension_still_detected_as_pickle(fixtures_dir):
    # .bin uzantılı ama içeriği pickle — magic byte uzantıyı yener.
    assert detect_format(fixtures_dir / "evasion_wrong_ext.bin") == "pickle"


def test_7z_detected(fixtures_dir):
    p = fixtures_dir / "evasion_7z.7z"
    if p.exists():
        assert detect_format(p) == "7z"


def test_missing_file_is_unknown(tmp_path):
    assert detect_format(tmp_path / "yok.pkl") == "unknown"
