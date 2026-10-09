"""Keras / TensorFlow-HDF5 statik analizörü.

MANTIK (rehber 1.2-A ile aynı ruh):
  Bir Keras modeli "veri" gibi görünür ama mimari config'i, model yüklenirken
  Python nesnelerine deserialize edilir. En tehlikeli yüzey `Lambda` katmanıdır:
  gövdesi serbest Python kodu / marshalled bytecode olarak config'e gömülür ve
  `keras.models.load_model` çağrısında (safe_mode atlatılırsa) ÇALIŞTIRILIR.
  Biz modeli ASLA yüklemeyiz; yalnızca arşiv/HDF5 yapısını ve config metnini okuruz.

ELE ALDIĞIMIZ FORMATLAR:
  - `.keras`  : aslında bir ZIP. İçindeki `config.json` (+ `metadata.json`) okunur.
  - `.h5/.hdf5`: HDF5. `h5py` ile AÇ ama yalnızca attribute/grup okunur; kök
    `model_config` attribute'u JSON string'tir — parse edilir.

ARADIKLARIMIZ (statik):
  - `"class_name": "Lambda"`     : serbest kod yüzeyi. Sade Lambda >= SUSPICIOUS.
  - Lambda `function` içinde gömülü bytecode (liste / base64 / marshal) => MALICIOUS.
  - `"module"` alanında keras/tensorflow dışı (özellikle os/subprocess/...) modül.
  - `"registered_name"` ile gelen custom object'ler => SUSPICIOUS.
  - `enable_unsafe_deserialization` izi (safe_mode atlatma niyeti) => SUSPICIOUS.

İLGİLİ CVE'ler: CVE-2025-8747, CVE-2025-9905, CVE-2025-9906, CVE-2026-12481
  (Keras safe_mode atlatmaları ve Lambda deserialization RCE'leri).

DAYANIKLILIK:
  - Parse edilemeyen config/HDF5 => SUSPICIOUS "parse edilemedi" ('taranamadı' != güvenli).
  - `h5py` kurulu değilse ImportError yutulur, SUSPICIOUS bulgu döner (sessiz geçme yok).
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from modelguard.analyzers.base import Analyzer
from modelguard.models import Finding, Severity

# --- Bilgi tabanı --------------------------------------------------------------

# Bir model config'inde meşru biçimde görülebilecek modül kökleri (prefix).
_SAFE_MODULE_ROOTS: frozenset[str] = frozenset(
    {
        "keras",
        "keras_core",
        "tf_keras",
        "tensorflow",
        "tf",
        "keras_cv",
        "keras_nlp",
        "keras_hub",
        "numpy",
    }
)

# Bir modelin asla meşru biçimde referans vermeyeceği kod-çalıştırma modülleri.
# Bunların görülmesi tek başına MALICIOUS sayılır.
_DANGEROUS_MODULE_ROOTS: frozenset[str] = frozenset(
    {
        "os",
        "posix",
        "nt",
        "sys",
        "subprocess",
        "shutil",
        "socket",
        "importlib",
        "imp",
        "pty",
        "ctypes",
        "marshal",
        "pickle",
        "runpy",
        "builtins",
        "__builtin__",
        "commands",
        "popen2",
        "requests",
        "urllib",
        "http",
    }
)

# safe_mode atlatma niyetini ele veren metinsel iz.
_UNSAFE_TOKEN = "enable_unsafe_deserialization"

_CVE_REF = "CVE-2025-8747 / CVE-2025-9905 / CVE-2025-9906 / CVE-2026-12481"


class KerasAnalyzer(Analyzer):
    name = "keras"

    def analyze(self, path: Path) -> list[Finding]:
        """Dosyayı formatına (.keras ZIP ya da HDF5) göre açar ve config'i tarar."""
        try:
            with open(path, "rb") as f:
                head = f.read(8)
        except OSError as exc:
            return [self._parse_failed(path.name, f"dosya okunamadı: {exc}")]

        if head.startswith(b"PK"):
            return self._analyze_keras_zip(path)
        if head.startswith(b"\x89HDF\r\n\x1a\n"):
            return self._analyze_hdf5(path)

        # Beklenmedik imza: yine de her iki yolu dene, hiçbiri tutmazsa SUSPICIOUS.
        for attempt in (self._analyze_keras_zip, self._analyze_hdf5):
            try:
                out = attempt(path)
            except Exception:  # pragma: no cover - savunma amaçlı
                continue
            if out:
                return out
        return [
            self._parse_failed(
                path.name,
                "dosya ne .keras ZIP ne de HDF5 imzasına uydu; içerik taranamadı",
            )
        ]

    # --- .keras (ZIP) yolu ----------------------------------------------------

    def _analyze_keras_zip(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            with zipfile.ZipFile(path) as zf:
                names = set(zf.namelist())
                targets = [n for n in ("config.json", "metadata.json") if n in names]
                if not targets:
                    # .keras her zaman config.json içerir; yoksa yapı şüpheli.
                    return [
                        self._parse_failed(
                            path.name,
                            ".keras arşivinde config.json bulunamadı; beklenmedik yapı",
                        )
                    ]
                blobs = [(n, zf.read(n)) for n in targets]
        except Exception as exc:  # bozuk/okunamayan ZIP
            return [self._parse_failed(path.name, f".keras arşivi açılamadı: {exc}")]

        for member, raw in blobs:
            findings.extend(self._scan_config_blob(raw, member))
        return findings

    # --- .h5 / .hdf5 (HDF5) yolu ----------------------------------------------

    def _analyze_hdf5(self, path: Path) -> list[Finding]:
        try:
            import h5py
        except ImportError:
            return [
                Finding(
                    analyzer=self.name,
                    severity=Severity.SUSPICIOUS,
                    title="HDF5 taranamadı (h5py yok)",
                    detail=(
                        "h5py kurulu olmadığından HDF5 model_config attribute'u "
                        "incelenemedi. 'Taranamadı' güvenli demek değildir; "
                        "bağımlılık eklenene dek bu dosya elle gözden geçirilmeli."
                    ),
                    location=path.name,
                    evidence="import h5py -> ImportError",
                    owasp="ML06",
                )
            ]

        try:
            # Sadece okuma: hiçbir dataset/ağırlık yüklenmez, yalnızca attribute okunur.
            with h5py.File(path, "r") as h5:
                raw_config = h5.attrs.get("model_config")
                attr_dump = " ".join(str(k) for k in h5.attrs.keys())
        except Exception as exc:
            return [self._parse_failed(path.name, f"HDF5 açılamadı: {exc}")]

        if raw_config is None:
            # Sadece ağırlık (.weights.h5) olabilir; config yoksa kod yüzeyi de yok.
            # Yine de yapıyı not düşmek için düşük bir işaret bırakmıyoruz: temiz say.
            return []

        if isinstance(raw_config, bytes):
            raw_config = raw_config.decode("utf-8", "replace")
        elif not isinstance(raw_config, str):
            raw_config = str(raw_config)

        findings = self._scan_config_blob(raw_config, "model_config (HDF5 attr)")

        # Nadiren atlatma izi başka bir attribute'a konabilir.
        if _UNSAFE_TOKEN in attr_dump and not any(
            f.title.startswith("safe_mode") for f in findings
        ):
            findings.append(self._unsafe_token_finding("HDF5 attribute adı"))
        return findings

    # --- ortak config tarama --------------------------------------------------

    def _scan_config_blob(self, raw: bytes | str, source: str) -> list[Finding]:
        """Bir config JSON metnini (ham) tarar: önce metinsel iz, sonra yapısal gezinti."""
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        findings: list[Finding] = []

        # Metinsel iz: JSON bozuk olsa bile yakalanır.
        if _UNSAFE_TOKEN in text:
            findings.append(self._unsafe_token_finding(source))

        try:
            data = json.loads(text)
        except Exception as exc:
            findings.append(
                self._parse_failed(
                    source,
                    f"config JSON olarak çözümlenemedi: {exc}",
                    evidence=text[:120],
                )
            )
            return findings

        self._walk(data, source, findings)
        return findings

    def _walk(self, node: object, loc: str, findings: list[Finding]) -> None:
        """Config ağacını gezer; tehlikeli düğümlerde Finding üretir."""
        if isinstance(node, dict):
            class_name = node.get("class_name")

            if class_name == "Lambda":
                findings.extend(self._inspect_lambda(node, loc))

            module = node.get("module")
            if isinstance(module, str) and module:
                self._check_module(module, loc, findings)

            registered = node.get("registered_name")
            if isinstance(registered, str) and registered:
                findings.append(
                    Finding(
                        analyzer=self.name,
                        severity=Severity.SUSPICIOUS,
                        title=f"Custom object (registered_name): {registered}",
                        detail=(
                            "Config, `registered_name` ile bir custom object'e işaret "
                            "ediyor. Bu nesne yüklenirken custom_objects üzerinden "
                            "keyfi Python sınıfına çözülebilir; kod yüzeyi oluşturur. "
                            f"({_CVE_REF})"
                        ),
                        location=f"{loc} -> registered_name",
                        evidence=registered,
                        atlas="AML.T0011",
                        owasp="ML06",
                    )
                )

            for key, value in node.items():
                self._walk(value, f"{loc} -> {key}", findings)

        elif isinstance(node, list):
            for i, item in enumerate(node):
                self._walk(item, f"{loc}[{i}]", findings)

    def _inspect_lambda(self, node: dict, loc: str) -> list[Finding]:
        """Lambda katmanını değerlendirir: gömülü bytecode => MALICIOUS, aksi SUSPICIOUS."""
        cfg = node.get("config")
        func = cfg.get("function") if isinstance(cfg, dict) else None
        lam_loc = f"{loc} Lambda"

        if self._lambda_has_bytecode(func):
            return [
                Finding(
                    analyzer=self.name,
                    severity=Severity.MALICIOUS,
                    title="Lambda içinde gömülü kod/bytecode payload",
                    detail=(
                        "Lambda katmanının `function` alanı, serileştirilmiş Python "
                        "kodu/marshalled bytecode içeriyor. Model safe_mode kapalı "
                        "yüklenirse bu kod çalıştırılır (RCE). Bu, Keras'ın en bilinen "
                        f"kod-çalıştırma yüzeyidir. ({_CVE_REF})"
                    ),
                    location=f"{lam_loc} -> config.function",
                    evidence=self._snippet(func),
                    atlas="AML.T0011",
                    owasp="ML06",
                )
            ]

        return [
            Finding(
                analyzer=self.name,
                severity=Severity.SUSPICIOUS,
                title="Lambda katmanı (koşullu kod yüzeyi)",
                detail=(
                    "Config bir Lambda katmanı içeriyor. Lambda gövdesi serbest Python "
                    "koduna çözülebilir; gömülü payload görülmese de bu katman kod "
                    "yüzeyidir ve güvenilmeyen modelde elle incelenmelidir. "
                    f"({_CVE_REF})"
                ),
                location=lam_loc,
                evidence=self._snippet(func) if func is not None else "function alanı yok",
                atlas="AML.T0011",
                owasp="ML06",
            )
        ]

    def _check_module(self, module: str, loc: str, findings: list[Finding]) -> None:
        """`module` alanını izin listesine göre değerlendirir."""
        root = module.split(".", 1)[0].strip().strip("<>").strip()
        if root in _SAFE_MODULE_ROOTS or not root:
            return

        if root in _DANGEROUS_MODULE_ROOTS:
            findings.append(
                Finding(
                    analyzer=self.name,
                    severity=Severity.MALICIOUS,
                    title=f"Tehlikeli modül referansı: {module}",
                    detail=(
                        f"Config, kod-çalıştırma modülü '{module}' referansı içeriyor. "
                        "Bir model mimarisi os/subprocess/builtins gibi modülleri meşru "
                        "biçimde kullanmaz; deserialization sırasında keyfi çağrı yüzeyi. "
                        f"({_CVE_REF})"
                    ),
                    location=f"{loc} -> module",
                    evidence=module,
                    atlas="AML.T0011",
                    owasp="ML06",
                )
            )
        else:
            findings.append(
                Finding(
                    analyzer=self.name,
                    severity=Severity.SUSPICIOUS,
                    title=f"keras/tensorflow dışı modül: {module}",
                    detail=(
                        f"'{module}' bilinen Keras/TensorFlow modül kökleri arasında "
                        "değil. Beklenmedik modül referansı custom deserialization'a "
                        "işaret edebilir; gözden geçirilmeli."
                    ),
                    location=f"{loc} -> module",
                    evidence=module,
                    owasp="ML06",
                )
            )

    # --- yardımcılar ----------------------------------------------------------

    @staticmethod
    def _lambda_has_bytecode(func: object) -> bool:
        """Lambda `function` alanının gömülü kod/bytecode taşıyıp taşımadığını sezer.

        Yakalanan kalıplar:
          - legacy liste biçimi: [code_b64, defaults, closure]
          - Keras 3 biçimi: {"class_name": "__lambda__", "config": {"code": "..."}}
          - herhangi bir düzeyde "code" alanı (serileştirilmiş code object).
        """
        if isinstance(func, list) and func:
            return True
        if isinstance(func, dict):
            if func.get("class_name") == "__lambda__":
                return True
            if func.get("function_type") == "lambda":
                return True
            if "code" in func:
                return True
            cfg = func.get("config")
            if isinstance(cfg, dict) and "code" in cfg:
                return True
        return False

    @staticmethod
    def _snippet(obj: object, limit: int = 160) -> str:
        try:
            text = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
        except Exception:
            text = str(obj)
        return text[:limit] + ("…" if len(text) > limit else "")

    def _unsafe_token_finding(self, source: str) -> Finding:
        return Finding(
            analyzer=self.name,
            severity=Severity.SUSPICIOUS,
            title=f"safe_mode atlatma izi: {_UNSAFE_TOKEN}",
            detail=(
                "Dosyada `enable_unsafe_deserialization` izi bulundu. Bu çağrı Keras'ın "
                "güvenli yükleme (safe_mode) korumasını kapatır ve Lambda/custom object "
                f"kodunun çalışmasına izin verir. ({_CVE_REF})"
            ),
            location=source,
            evidence=_UNSAFE_TOKEN,
            atlas="AML.T0011",
            owasp="ML06",
        )

    def _parse_failed(self, source: str, reason: str, evidence: str = "") -> Finding:
        return Finding(
            analyzer=self.name,
            severity=Severity.SUSPICIOUS,
            title="Keras config parse edilemedi",
            detail=(
                f"{reason}. 'Taranamadı' güvenli demek değildir: bozuk/eksik yapı "
                "tarayıcıyı atlatmak için kullanılabilir, bu yüzden şüpheli işaretlenir."
            ),
            location=source,
            evidence=evidence,
            owasp="ML06",
        )
