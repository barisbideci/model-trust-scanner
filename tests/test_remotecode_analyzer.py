"""Uzak-kod (trust_remote_code) AST analizörü testleri.

Test girdileri ZARARSIZDIR ve `tmp_path` içinde üretilir; hiçbir kaynak
import/exec EDİLMEZ — yalnızca `ast` ile statik olarak çözümlenir. Decode edilen
içerik bile zararsızdır (ör. "print(1)"); gerçek zararlı kod/ağ/shell YOKTUR.
"""

from __future__ import annotations

import base64

from modelguard.analyzers.remotecode_analyzer import RemoteCodeAnalyzer
from modelguard.models import Severity


def _titles(findings):
    return " | ".join(f.title for f in findings)


def _max_sev(findings):
    return max((f.severity for f in findings), default=Severity.SAFE)


def test_benign_module_is_clean(tmp_path):
    # Arrange — tamamen zararsız bir sınıf/fonksiyon içeren modeling dosyası.
    src = (
        "import torch\n"
        "from torch import nn\n\n\n"
        "class MyModel(nn.Module):\n"
        "    def __init__(self, dim):\n"
        "        super().__init__()\n"
        "        self.linear = nn.Linear(dim, dim)\n\n"
        "    def forward(self, x):\n"
        "        return self.linear(x)\n"
    )
    f = tmp_path / "modeling_benign.py"
    f.write_text(src, encoding="utf-8")

    # Act
    findings = RemoteCodeAnalyzer().analyze(f)

    # Assert — temiz: hiçbir bulgu SUSPICIOUS'a ulaşmamalı.
    assert _max_sev(findings) <= Severity.LOW, _titles(findings)


def test_os_system_flagged_malicious(tmp_path):
    # Arrange — modül düzeyinde kabuk komutu (zararsız "echo test").
    src = 'import os\nos.system("echo test")\n'
    f = tmp_path / "configuration_evil.py"
    f.write_text(src, encoding="utf-8")

    # Act
    findings = RemoteCodeAnalyzer().analyze(f)

    # Assert — os.system MALICIOUS olmalı ve konum satır numarası taşımalı.
    assert any(
        f.severity == Severity.MALICIOUS and f.evidence.startswith("os.system")
        for f in findings
    ), _titles(findings)
    assert any(":2" in f.location for f in findings), _titles(findings)


def test_decode_and_exec_flagged_malicious(tmp_path):
    # Arrange — exec(base64.b64decode(...)) kalıbı; çözülen içerik ZARARSIZ ("print(1)").
    payload = base64.b64encode(b"print(1)").decode("ascii")
    src = (
        "import base64\n"
        f'exec(base64.b64decode("{payload}"))\n'
    )
    f = tmp_path / "modeling_obfuscated.py"
    f.write_text(src, encoding="utf-8")

    # Act
    findings = RemoteCodeAnalyzer().analyze(f)

    # Assert — 'çöz ve çalıştır' kompozit kalıbı MALICIOUS olmalı.
    assert any(
        f.severity == Severity.MALICIOUS and "Çöz-ve-çalıştır" in f.title
        for f in findings
    ), _titles(findings)


def test_lone_base64_decode_is_suspicious(tmp_path):
    # Arrange — fonksiyon İÇİNDE tek başına b64decode (exec'e beslenmiyor).
    # Fonksiyon gövdesi import anında çalışmaz -> modül-düzeyi yükseltmesi olmamalı.
    src = (
        "import base64\n\n\n"
        "def unpack(blob):\n"
        "    return base64.b64decode(blob)\n"
    )
    f = tmp_path / "modeling_decode_only.py"
    f.write_text(src, encoding="utf-8")

    # Act
    findings = RemoteCodeAnalyzer().analyze(f)

    # Assert — salt decode SUSPICIOUS kalmalı (MALICIOUS değil).
    assert findings, "en az bir bulgu beklenir"
    assert _max_sev(findings) == Severity.SUSPICIOUS, _titles(findings)


def test_syntax_error_marked_suspicious(tmp_path):
    # Arrange — parse edilemeyen kaynak 'güvenli' sayılmamalı.
    f = tmp_path / "modeling_broken.py"
    f.write_text("def oops(:\n    pass\n", encoding="utf-8")

    # Act
    findings = RemoteCodeAnalyzer().analyze(f)

    # Assert — SUSPICIOUS "parse edilemedi" bulgusu.
    assert findings, "bozuk kaynak en az bir bulgu üretmeli"
    assert any(
        f.severity == Severity.SUSPICIOUS and "parse edilemedi" in f.title
        for f in findings
    ), _titles(findings)


def test_directory_is_scanned_recursively(tmp_path):
    # Arrange — bir repo klasörü; biri temiz, biri zararlı iki .py ve alt klasör.
    (tmp_path / "modeling_ok.py").write_text(
        "def f():\n    return 42\n", encoding="utf-8"
    )
    (tmp_path / "configuration_bad.py").write_text(
        'import subprocess\nsubprocess.run(["echo", "hi"])\n', encoding="utf-8"
    )
    sub = tmp_path / "nested"
    sub.mkdir()
    (sub / "modeling_deep.py").write_text(
        'import os\nos.system("echo deep")\n', encoding="utf-8"
    )

    # Act
    findings = RemoteCodeAnalyzer().analyze(tmp_path)

    # Assert — hem üst klasör hem alt klasördeki zararlı dosyalar yakalanmalı.
    locations = {f.location for f in findings}
    assert any("configuration_bad.py" in loc for loc in locations), _titles(findings)
    assert any("modeling_deep.py" in loc for loc in locations), _titles(findings)
    assert sum(1 for f in findings if f.severity == Severity.MALICIOUS) >= 2, _titles(
        findings
    )


# --- Takma ad çözümü (inceleme bulgusu: yanlış-negatif) -----------------------

def _scan_src(tmp_path, src, name="modeling_x.py"):
    f = tmp_path / name
    f.write_text(src, encoding="utf-8")
    return RemoteCodeAnalyzer().analyze(f)


def test_from_import_alias_resolved(tmp_path):
    # `from os import system` sonrası çıplak `system(...)` os.system olarak çözülmeli.
    findings = _scan_src(tmp_path, "from os import system\nsystem('echo hi')\n")
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)


def test_module_alias_resolved(tmp_path):
    # `import subprocess as sp; sp.run(...)` subprocess.run olarak çözülmeli.
    findings = _scan_src(tmp_path, "import subprocess as sp\nsp.run(['echo', 'hi'])\n")
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)


def test_renamed_from_import_resolved(tmp_path):
    # `from subprocess import Popen as P` -> P(...) subprocess.Popen olmalı.
    findings = _scan_src(tmp_path, "from subprocess import Popen as P\nP(['echo'])\n")
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)


def test_star_import_resolved(tmp_path):
    # `from os import *` sonrası `system(...)` yakalanmalı.
    findings = _scan_src(tmp_path, "from os import *\nsystem('echo hi')\n")
    assert any(f.severity == Severity.MALICIOUS for f in findings), _titles(findings)


# --- Meşru kod (inceleme bulgusu: yanlış-pozitif) -----------------------------

def test_re_compile_is_not_builtin_compile(tmp_path):
    # `from re import compile` -> re.compile; builtin compile sanılmamalı.
    findings = _scan_src(tmp_path, "from re import compile\nPAT = compile('[0-9]+')\n")
    assert _max_sev(findings) <= Severity.LOW, _titles(findings)


def test_importlib_inside_function_is_not_malicious(tmp_path):
    # Meşru dinamik import fonksiyon içinde: en fazla SUSPICIOUS, MALICIOUS değil.
    src = "import importlib\n\ndef load(name):\n    return importlib.import_module(name)\n"
    findings = _scan_src(tmp_path, src)
    assert _max_sev(findings) == Severity.SUSPICIOUS, _titles(findings)


def test_getattr_in_function_is_low(tmp_path):
    # Model kodunda yaygın getattr kullanımı tek başına uyarı seviyesine çıkmamalı.
    src = "def get(cfg, k):\n    return getattr(cfg, k, None)\n"
    findings = _scan_src(tmp_path, src)
    assert _max_sev(findings) <= Severity.LOW, _titles(findings)
