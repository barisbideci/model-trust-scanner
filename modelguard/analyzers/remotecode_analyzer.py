"""Uzak-kod (trust_remote_code) statik AST analizörü.

MANTIK (rehber 1.2-B):
  Hugging Face modelleri `trust_remote_code=True` ile yüklendiğinde, repo içindeki
  `modeling_*.py` / `configuration_*.py` gibi dosyalar MODEL NESNESİ KURULURKEN
  import edilir. Import, modülün top-level kodunu çalıştırır; dolayısıyla model
  yüklemek = yabancı Python çalıştırmak. Biz bu dosyaları ÇALIŞTIRMADAN, yalnızca
  standart `ast` modülüyle PARSE edip tehlikeli kod-çalıştırma kalıplarını ararız.
  (Bağlam: CVE-2026-5241 ve CVE-2026-4372 — trust_remote_code bypass zincirleri.)

ARADIKLARIMIZ:
  - Doğrudan kod çalıştırma: eval/exec/compile/__import__, os.system/os.popen,
    subprocess.*, pty.spawn, socket.socket, importlib.import_module.
  - Ağ: urllib.request.urlopen, requests.get/post, http.client — tek başına ağ
    SUSPICIOUS; ama "indir + exec/eval" yan yana ise MALICIOUS (uzaktan kod yükle).
  - Obfuskasyon: base64.b64decode / codecs.decode / bytes.fromhex tek başına
    SUSPICIOUS; sonucu exec/eval'e beslenirse MALICIOUS (decode + exec).
  - Serileştirme: marshal.loads / pickle.loads — SUSPICIOUS/MALICIOUS.
  - Dinamik erişim: getattr(...) ile kaçamak — SUSPICIOUS.

ATLATMALARA DAYANIKLILIK:
  - Modül top-level'ında (fonksiyon/sınıf dışında) çalışan tehlikeli çağrı import
    anında TETİKLENİR; bu yüzden önemi bir derece yükseltiriz.
  - Syntax hatalı dosya 'taranamadı' => güvenli değildir: SUSPICIOUS bulgu üretilir.
  - Çağrı hedefi hem `ad.alt` (Attribute) hem `ad(` (Name) biçiminde eşlenir.
"""

from __future__ import annotations

import ast
from pathlib import Path

from modelguard.analyzers.base import Analyzer
from modelguard.models import Finding, Severity

# --- Bilgi tabanı --------------------------------------------------------------

# Kesin tehlikeli, nokta-yollu çağrı hedefleri (ör. "os.system").
# detail: neden tehlikeli olduğunun kısa açıklaması.
_DANGEROUS_CALLS: dict[str, str] = {
    "os.system": "kabuk komutu çalıştırır",
    "os.popen": "kabuk komutu çalıştırır",
    "os.exec": "süreci başka programla değiştirir",
    "os.execv": "süreci başka programla değiştirir",
    "os.execve": "süreci başka programla değiştirir",
    "os.execl": "süreci başka programla değiştirir",
    "os.spawnl": "harici süreç başlatır",
    "os.spawnv": "harici süreç başlatır",
    "subprocess.Popen": "harici süreç başlatır",
    "subprocess.call": "harici süreç başlatır",
    "subprocess.run": "harici süreç başlatır",
    "subprocess.check_call": "harici süreç başlatır",
    "subprocess.check_output": "harici süreç başlatır",
    "subprocess.getoutput": "kabuk komutu çalıştırır",
    "pty.spawn": "etkileşimli kabuk açar",
    "socket.socket": "ağ soketi açar",
    "runpy._run_code": "kod çalıştırır",
    "runpy.run_path": "dosyayı kod olarak çalıştırır",
}

# Tek adlı (builtin) tehlikeli çağrılar — doğrudan `eval(...)` gibi.
_DANGEROUS_BUILTINS: dict[str, str] = {
    "eval": "keyfi Python ifadesi çalıştırır",
    "exec": "keyfi Python kodu çalıştırır",
    "compile": "kaynağı kod nesnesine derler",
    "__import__": "dinamik modül yükler",
}

# Dinamik modül yükleme — tehlikeli ama meşru da olabilir; MALICIOUS kabul edilir.
_DYNAMIC_IMPORT_CALLS: dict[str, str] = {
    "importlib.import_module": "dinamik modül yükler",
    "importlib.__import__": "dinamik modül yükler",
}

# Ağ erişimi: tek başına SUSPICIOUS; "indir + çalıştır" ile MALICIOUS.
_NETWORK_CALLS: dict[str, str] = {
    "urllib.request.urlopen": "ağdan veri indirir",
    "urllib.urlopen": "ağdan veri indirir",
    "requests.get": "ağdan veri indirir",
    "requests.post": "ağa veri gönderir/indirir",
    "requests.request": "ağ isteği yapar",
    "http.client.HTTPConnection": "ham HTTP bağlantısı açar",
    "http.client.HTTPSConnection": "ham HTTPS bağlantısı açar",
    "urllib.request.urlretrieve": "ağdan dosya indirir",
}

# Obfuskasyon/çözme çağrıları: tek başına SUSPICIOUS; exec/eval'e beslenirse MALICIOUS.
_DECODE_CALLS: dict[str, str] = {
    "base64.b64decode": "base64 çözer (obfuskasyon)",
    "base64.b85decode": "base85 çözer (obfuskasyon)",
    "base64.a85decode": "ascii85 çözer (obfuskasyon)",
    "base64.b32decode": "base32 çözer (obfuskasyon)",
    "base64.b16decode": "base16 çözer (obfuskasyon)",
    "base64.urlsafe_b64decode": "base64 çözer (obfuskasyon)",
    "codecs.decode": "codec ile çözer (ör. rot13/hex, obfuskasyon)",
    "bytes.fromhex": "hex diziden bayt üretir (obfuskasyon)",
    "zlib.decompress": "sıkıştırılmış veri açar (obfuskasyon)",
}

# Serileştirme yükleyicileri — kod çalıştırma yüzeyi.
_DESERIALIZE_CALLS: dict[str, str] = {
    "marshal.loads": "marshal akışından kod nesnesi yükler",
    "marshal.load": "marshal akışından kod nesnesi yükler",
    "pickle.loads": "pickle akışı çözer (keyfi kod çalıştırabilir)",
    "pickle.load": "pickle akışı çözer (keyfi kod çalıştırabilir)",
    "dill.loads": "dill akışı çözer (keyfi kod çalıştırabilir)",
}

# Çözülmüş içeriği 'çalıştıran' sarmalayıcılar — decode/indir sonucu buraya akarsa MALICIOUS.
_EXEC_SINKS: frozenset[str] = frozenset({"eval", "exec", "compile", "__import__"})

_ATLAS = "AML.T0010.001"
_OWASP = "ML06"
_CVE_NOTE = "trust_remote_code bypass bağlamı: CVE-2026-5241, CVE-2026-4372."


class RemoteCodeAnalyzer(Analyzer):
    name = "remotecode"

    def analyze(self, path: Path) -> list[Finding]:
        """`.py` dosyasını veya klasördeki tüm `.py` dosyalarını statik tarar."""
        findings: list[Finding] = []
        for py in self._iter_py_files(path):
            findings.extend(self._scan_file(py))
        return findings

    # --- dosya keşfi ----------------------------------------------------------

    def _iter_py_files(self, path: Path):
        """Tek `.py` dosyası ise onu; klasör ise içindeki tüm `.py`'leri (recursive) verir."""
        if path.is_dir():
            yield from sorted(path.rglob("*.py"))
        elif path.suffix.lower() == ".py":
            yield path
        # Diğer uzantılar bu analizörün ilgi alanı dışında (sessizce atlanır).

    # --- tek dosya tarama -----------------------------------------------------

    def _scan_file(self, py: Path) -> list[Finding]:
        try:
            source = py.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return [
                Finding(
                    analyzer=self.name,
                    severity=Severity.SUSPICIOUS,
                    title="Dosya okunamadı",
                    detail=f"Kaynak okunamadı; 'taranamadı' güvenli demek değildir: {exc}",
                    location=py.name,
                    owasp=_OWASP,
                )
            ]

        try:
            tree = ast.parse(source, filename=str(py))
        except SyntaxError as exc:
            # 'Taranamadı' güvenli değildir: bozuk/aykırı kaynak da şüphelidir.
            return [
                Finding(
                    analyzer=self.name,
                    severity=Severity.SUSPICIOUS,
                    title="Python kaynağı parse edilemedi",
                    detail=(
                        "AST çözümlemesi başarısız oldu (syntax hatası). Parser'ı "
                        "hata verdirip taramayı atlatma girişimi olabilir; dosya elle "
                        "gözden geçirilmeli. 'Taranamadı' güvenli demek değildir."
                    ),
                    location=f"{py.name}:{getattr(exc, 'lineno', 0) or 0}",
                    evidence=str(exc.msg),
                    atlas=_ATLAS,
                    owasp=_OWASP,
                )
            ]

        return self._scan_tree(tree, py)

    def _scan_tree(self, tree: ast.AST, py: Path) -> list[Finding]:
        """AST üzerinde tek geçiş: her çağrıyı sınıflandırır, kompozit kalıpları birleştirir."""
        findings: list[Finding] = []
        toplevel = _collect_toplevel_lines(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            target = _call_target(node.func)  # ör. "os.system", "exec", "" (çözülemedi)
            if not target:
                continue

            base = target.rsplit(".", 1)[-1]  # son bileşen (builtin eşlemesi için)
            lineno = getattr(node, "lineno", 0) or 0
            at_module_level = lineno in toplevel
            evidence = _call_evidence(node, target)

            # --- Kompozit kalıp: decode/indir sonucunu exec/eval/compile'a besleme ---
            if base in _EXEC_SINKS and _has_dangerous_arg(node):
                inner = _describe_inner_sink(node)
                findings.append(
                    self._finding(
                        Severity.MALICIOUS,
                        f"Çöz-ve-çalıştır kalıbı: {base}(...)",
                        (
                            f"`{base}(...)` çağrısına doğrudan bir çözme/indirme sonucu "
                            f"besleniyor ({inner}). Bu, gizlenmiş veya uzaktan getirilmiş "
                            f"kodu import anında çalıştırmanın klasik yoludur. {_CVE_NOTE}"
                        ),
                        py, lineno, evidence, at_module_level,
                    )
                )
                continue  # bu çağrı için en yüksek önem verildi

            # --- Doğrudan builtin exec/eval/compile/__import__ ---
            if target in _DANGEROUS_BUILTINS or (
                base in _DANGEROUS_BUILTINS and "." not in target
            ):
                why = _DANGEROUS_BUILTINS[base]
                findings.append(
                    self._finding(
                        Severity.MALICIOUS,
                        f"Doğrudan kod çalıştırma: {base}(...)",
                        f"`{base}` {why}. trust_remote_code ile import edilen dosyada "
                        f"bu, keyfi kod yürütme anlamına gelir. {_CVE_NOTE}",
                        py, lineno, evidence, at_module_level,
                    )
                )
                continue

            # --- Nokta-yollu kesin tehlikeli çağrılar (os.system, subprocess.*, ...) ---
            if target in _DANGEROUS_CALLS:
                findings.append(
                    self._finding(
                        Severity.MALICIOUS,
                        f"Tehlikeli çağrı: {target}(...)",
                        f"`{target}` {_DANGEROUS_CALLS[target]}. İçe aktarım anında "
                        f"tetiklenebilir; meşru bir model dosyası bunu yapmaz.",
                        py, lineno, evidence, at_module_level,
                    )
                )
                continue

            # --- Dinamik modül yükleme ---
            if target in _DYNAMIC_IMPORT_CALLS:
                findings.append(
                    self._finding(
                        Severity.MALICIOUS,
                        f"Dinamik modül yükleme: {target}(...)",
                        f"`{target}` {_DYNAMIC_IMPORT_CALLS[target]}. Statik olarak "
                        f"görülemeyen modüller yükler; kaçamak yüzeyidir.",
                        py, lineno, evidence, at_module_level,
                    )
                )
                continue

            # --- Serileştirme yükleyicileri ---
            if target in _DESERIALIZE_CALLS:
                findings.append(
                    self._finding(
                        Severity.MALICIOUS,
                        f"Güvenilmeyen seri çözme: {target}(...)",
                        f"`{target}` {_DESERIALIZE_CALLS[target]}. Güvenilmeyen akışta "
                        f"kod çalıştırma yüzeyidir.",
                        py, lineno, evidence, at_module_level,
                    )
                )
                continue

            # --- Ağ erişimi (tek başına SUSPICIOUS) ---
            if target in _NETWORK_CALLS:
                findings.append(
                    self._finding(
                        Severity.SUSPICIOUS,
                        f"Ağ erişimi: {target}(...)",
                        f"`{target}` {_NETWORK_CALLS[target]}. Tek başına kesin zararlı "
                        f"değil; ama indirilen içeriğin exec/eval'e beslenmesi 'indir ve "
                        f"çalıştır' zinciridir ve ayrıca işaretlenir.",
                        py, lineno, evidence, at_module_level,
                    )
                )
                continue

            # --- Obfuskasyon/çözme (tek başına SUSPICIOUS) ---
            if target in _DECODE_CALLS:
                findings.append(
                    self._finding(
                        Severity.SUSPICIOUS,
                        f"Obfuskasyon/çözme: {target}(...)",
                        f"`{target}` {_DECODE_CALLS[target]}. Tek başına şüpheli; "
                        f"sonucu exec/eval'e beslenirse zararlıya yükseltilir.",
                        py, lineno, evidence, at_module_level,
                    )
                )
                continue

            # --- Dinamik öznitelik erişimi: getattr(...) ---
            if base == "getattr" and "." not in target and len(node.args) >= 2:
                findings.append(
                    self._finding(
                        Severity.SUSPICIOUS,
                        "Dinamik öznitelik erişimi: getattr(...)",
                        "`getattr` ile dinamik erişim, statik analizden saklı çağrı "
                        "hedefleri oluşturmak için kullanılabilir (kaçamak).",
                        py, lineno, evidence, at_module_level,
                    )
                )
                continue

        return findings

    # --- Finding fabrikası ----------------------------------------------------

    def _finding(
        self,
        severity: Severity,
        title: str,
        detail: str,
        py: Path,
        lineno: int,
        evidence: str,
        at_module_level: bool,
    ) -> Finding:
        """Ortak Finding kurucu; modül düzeyi çağrılarda önemi bir derece yükseltir."""
        if at_module_level and severity < Severity.MALICIOUS:
            severity = Severity(severity + 1)
            detail += (
                " Çağrı MODÜL DÜZEYİNDE (fonksiyon dışında) olduğundan import anında "
                "tetiklenir; bu nedenle önem yükseltildi."
            )
        elif at_module_level:
            detail += " Çağrı modül düzeyinde: import anında tetiklenir."
        return Finding(
            analyzer=self.name,
            severity=severity,
            title=title,
            detail=detail,
            location=f"{py.name}:{lineno}",
            evidence=evidence,
            atlas=_ATLAS,
            owasp=_OWASP,
        )


# --- AST yardımcıları ----------------------------------------------------------


def _call_target(func: ast.AST) -> str:
    """Çağrı hedefini nokta-yollu ada indirger: `a.b.c` -> "a.b.c", `name` -> "name".

    Çözülemeyen hedefler (ör. `getattr(x, 'y')()` sonucu çağrı) "" döner.
    """
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parent = _call_target(func.value)
        return f"{parent}.{func.attr}" if parent else ""
    return ""


def _call_evidence(node: ast.Call, target: str) -> str:
    """Kanıt dizesi: mümkünse kaynak ifadenin kendisi, değilse `target(...)`."""
    try:
        text = ast.unparse(node)
    except Exception:
        return f"{target}(...)"
    return text if len(text) <= 160 else text[:157] + "..."


def _has_dangerous_arg(node: ast.Call) -> bool:
    """exec/eval/compile çağrısının argümanlarında bir decode/indirme çağrısı var mı?

    Argüman ağacı içinde `base64.b64decode(...)`, `codecs.decode(...)`,
    `bytes.fromhex(...)`, ağ indirmesi vb. bir çağrı aranır ('decode+exec' / 'indir+exec').
    """
    for arg in node.args:
        for sub in ast.walk(arg):
            if isinstance(sub, ast.Call):
                t = _call_target(sub.func)
                if t in _DECODE_CALLS or t in _NETWORK_CALLS:
                    return True
                base = t.rsplit(".", 1)[-1] if t else ""
                if base in {"b64decode", "fromhex", "decode"} and t:
                    return True
    return False


def _describe_inner_sink(node: ast.Call) -> str:
    """Kompozit kalıpta exec/eval'e beslenen iç çağrının kısa adını verir."""
    for arg in node.args:
        for sub in ast.walk(arg):
            if isinstance(sub, ast.Call):
                t = _call_target(sub.func)
                if t in _DECODE_CALLS:
                    return f"çözme: {t}"
                if t in _NETWORK_CALLS:
                    return f"indirme: {t}"
    return "gömülü çağrı"


def _collect_toplevel_lines(tree: ast.AST) -> frozenset[int]:
    """Modül top-level'ında (fonksiyon/sınıf gövdesi DIŞINDA) çalışan satır no'ları.

    Modül gövdesindeki ifadelerin alt-ağaçları import anında çalışır. Fonksiyon/
    sınıf tanımlarının İÇİ ise ancak çağrılınca çalışır, bu yüzden hariç tutulur.
    """
    lines: set[int] = set()
    module_body = getattr(tree, "body", [])
    for stmt in module_body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Tanımın kendisi top-level; ama gövdesi çağrı anında çalışır -> atla.
            continue
        for sub in ast.walk(stmt):
            ln = getattr(sub, "lineno", None)
            if ln is not None:
                lines.add(ln)
    return frozenset(lines)
