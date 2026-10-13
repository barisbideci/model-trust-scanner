"""modelguard'ı picklescan, ModelScan ve fickling ile karşılaştırma koşum takımı.

AMAÇ (ROADMAP Hafta 5): aynı etiketli korpus üzerinde üç tarayıcıyı çalıştırıp
precision / recall / yanlış-alarm oranını ölçmek. Projenin asıl bilimsel katkısı
burada nicelenir: modelguard, yaygın araçlara (picklescan, ModelScan, fickling) kıyasla hangi atlatma (evasion)
senaryolarını yakalıyor, nerede onlarla aynı, nerede geride?

ETİK/GÜVENLİK:
  Korpustaki "zararlı" örnekler zararsız canary'dir (yalnızca `echo` opcode kalıbı);
  gerçek zarar, ağ veya reverse shell yoktur. Hiçbir araç bu betikte modeli ÇALIŞTIRMAZ
  — hepsi STATİK tarama yapar. Dosyalar güvenilmeyen veri gibi ele alınır (yorumlayıcıya
  import ettirilmez; -I ile ve argüman olarak yol verilerek taranır).

Kullanım:
  python tools/compare_scanners.py                      # fixtures'ı tara, HTML üret
  python tools/compare_scanners.py --corpus <klasör>    # başka korpus
  python tools/compare_scanners.py --hf                 # gerçek temiz HF modelleri (FPR)
  python tools/compare_scanners.py --html rapor.html --json sonuc.json
  # ModelScan farklı bir Python'da kuruluysa (yolu --modelscan-exe ile verin):
  python tools/compare_scanners.py --modelscan-exe /yol/modelscan.exe

ModelScan notu: ModelScan (Protect AI) Python <3.13 ister. 3.13'te doğrudan
kurulamaz; ayrı bir 3.10–3.12 ortamına kurup --modelscan-exe ile yolunu verin
ya da MODELSCAN_EXE ortam değişkenini ayarlayın. Bulunamazsa o sütun atlanır.

fickling notu (Trail of Bits): `pip install fickling`. CLI'si girdiyi ham pickle akışı
sayar ve ZIP'i açamaz; bu yüzden fickling'in kendi HuggingFace modunun kullandığı
kütüphane API'si çağrılır ve aynı yönlendirme izlenir: ZIP -> scan_zip_archive, pickle
(PROTO baytı ya da .bin/.pkl/.pickle) -> scan_file, diğerleri (h5/gguf/safetensors)
atlanır. 7z/tar'ı fickling "henüz desteklenmiyor" diye atlar; burada hata sayılır.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

# modelguard'ı in-process çağırabilmek için depo kökünü yola ekle.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from modelguard.models import Severity  # noqa: E402
from modelguard.scanner import scan  # noqa: E402

# --- Ground-truth etiketleri --------------------------------------------------
# make_fixtures.py'nin ürettiği korpusun bilinen etiketleri. "malicious" örnekler
# os.system canary opcode kalıbı taşır; "benign" örnekler yalnızca güvenli tipler.
LABELS: dict[str, str] = {
    "benign.pkl": "benign",
    "benign_model.zip": "benign",
    "malicious_os_system.pkl": "malicious",
    "multi_stop.pkl": "malicious",          # 2. STOP'tan sonra payload
    "broken.pkl": "malicious",              # kesik akış, GLOBAL os.system hâlâ var
    "evasion_wrong_ext.bin": "malicious",   # pickle, .bin uzantısıyla gizli
    "evasion_memo_global.pkl": "malicious", # STACK_GLOBAL adı memo'dan + izinli yem
    "evasion_inst.pkl": "malicious",        # protokol 0 INST (GLOBAL'siz import)
    "malicious_model.zip": "malicious",
    "evasion_zero_crc.zip": "malicious",    # sıfırlanmış CRC ile ZIP atlatması
    "evasion_7z.7z": "malicious",           # 7z paketleme atlatması
}

# --- Gerçek temiz HuggingFace korpusu (yanlış-alarm / FPR ölçümü) -------------
# Yaygın, resmi/popüler depolardan küçük modeller (~950 MB). Hepsi "benign"
# sayılır: zararlı olmadığı bilinen yerleşik modeller. Pickle ağırlıklıdır (FPR'nin
# anlamlı olduğu yer); h5/gguf/safetensors modelguard'ın diğer analizörleri için.
HF_BENIGN: list[tuple[str, str]] = [
    ("prajjwal1/bert-tiny", "pytorch_model.bin"),
    ("hf-internal-testing/tiny-random-bert", "pytorch_model.bin"),
    ("sshleifer/tiny-gpt2", "pytorch_model.bin"),
    ("google/electra-small-discriminator", "pytorch_model.bin"),
    ("sentence-transformers/all-MiniLM-L6-v2", "pytorch_model.bin"),
    ("microsoft/resnet-18", "pytorch_model.bin"),
    ("timm/resnet18.a1_in1k", "pytorch_model.bin"),
    ("distilbert/distilbert-base-uncased", "pytorch_model.bin"),
    ("facebook/opt-125m", "pytorch_model.bin"),
    ("julien-c/wine-quality", "sklearn_model.joblib"),        # sklearn pickle
    ("sshleifer/tiny-gpt2", "tf_model.h5"),
    ("microsoft/resnet-18", "tf_model.h5"),
    ("ggml-org/models", "bert-bge-small/ggml-model-f16.gguf"),
    ("hf-internal-testing/tiny-random-bert", "model.safetensors"),
]


def fetch_hf_corpus(cache_dir: Path | None) -> dict[str, Path]:
    """HF_BENIGN dosyalarını indirir (yalnızca indirir, YÜKLEMEZ). ad -> yerel yol."""
    from huggingface_hub import hf_hub_download
    return {f"{repo}/{fname}": Path(hf_hub_download(repo, fname, cache_dir=cache_dir))
            for repo, fname in HF_BENIGN}


@dataclass
class ToolResult:
    """Bir aracın tek dosyadaki sonucu."""
    flagged: bool              # araç bu dosyayı tehdit olarak işaretledi mi?
    detail: str = ""           # kısa açıklama (ör. "nt.system", "total_issues=1")
    error: str = ""            # araç bu dosyada hata verdiyse
    seconds: float = 0.0


@dataclass
class ToolStats:
    name: str
    available: bool = True
    note: str = ""
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    errors: int = 0
    total_seconds: float = 0.0
    per_file: dict[str, ToolResult] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=lambda: LABELS)  # dosya adı -> gerçek

    def record(self, name: str, res: ToolResult) -> None:
        self.per_file[name] = res
        self.total_seconds += res.seconds
        if res.error:
            self.errors += 1
        truth_bad = self.labels.get(name) == "malicious"
        if res.flagged and truth_bad:
            self.tp += 1
        elif res.flagged and not truth_bad:
            self.fp += 1
        elif not res.flagged and truth_bad:
            self.fn += 1
        else:
            self.tn += 1

    @property
    def precision(self) -> float | None:
        d = self.tp + self.fp
        return self.tp / d if d else None

    @property
    def recall(self) -> float | None:
        d = self.tp + self.fn
        return self.tp / d if d else None

    @property
    def fpr(self) -> float | None:
        """Yanlış-alarm oranı = FP / (FP + TN)."""
        d = self.fp + self.tn
        return self.fp / d if d else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if not p or not r:
            return None
        return 2 * p * r / (p + r)


# --- Araç sarmalayıcıları -----------------------------------------------------

def run_modelguard(path: Path) -> ToolResult:
    """modelguard'ı in-process çalıştırır. flagged = SUSPICIOUS ve üzeri."""
    t0 = time.perf_counter()
    try:
        result = scan(path)  # statik; model YÜKLENMEZ
        sev = result.severity
        flagged = sev >= Severity.SUSPICIOUS
        return ToolResult(flagged=flagged, detail=f"verdict={sev.label}",
                          seconds=time.perf_counter() - t0)
    except Exception as exc:
        return ToolResult(flagged=False, error=f"{type(exc).__name__}: {exc}",
                          seconds=time.perf_counter() - t0)


_PICKLESCAN_INFECTED = re.compile(r"Infected files:\s*(\d+)")


def run_picklescan(path: Path) -> ToolResult:
    """picklescan'i alt süreçte çalıştırır. flagged = Infected files > 0."""
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-m", "picklescan", "-p", str(path)],
            capture_output=True, text=True, timeout=60,
        )
    except Exception as exc:
        return ToolResult(flagged=False, error=f"{type(exc).__name__}: {exc}",
                          seconds=time.perf_counter() - t0)
    out = proc.stdout + proc.stderr
    m = _PICKLESCAN_INFECTED.search(out)
    infected = int(m.group(1)) if m else 0
    err = ""
    if m is None:
        err = "çıktı ayrıştırılamadı"
    # picklescan bazı formatları (ör. salt .bin/7z) yine de pickle olarak dener;
    # ayrıştırma hatası varsa stderr'e düşer ama Infected=0 olabilir.
    return ToolResult(flagged=infected > 0, detail=f"infected={infected}",
                      error=err, seconds=time.perf_counter() - t0)


# fickling alt süreçte çalışır (picklescan gibi izole, -I). Sürücü yalnızca fickling'in
# STATİK tarama API'sini çağırır; pickle'ı asla unpickle etmez. torch gerektiren
# fickling.polyglot'u kullanmamak için format yönlendirmesi stdlib ile yapılır.
_FICKLING_DRIVER = r"""
import json, sys, tarfile, zipfile
from fickling.analysis import Severity
from fickling.loader import scan_file, scan_zip_archive
path = sys.argv[1]
with open(path, "rb") as f:
    head = f.read(6)
if head == bytes.fromhex("377abcaf271c") or tarfile.is_tarfile(path):  # 7z magic
    print(json.dumps({"unsupported": "7z/tar"}))
    raise SystemExit(0)
if zipfile.is_zipfile(path):
    results = list(scan_zip_archive(path, graceful=True).values())
elif head[:1] == bytes.fromhex("80") or path.lower().endswith((".bin", ".pkl", ".pickle")):
    results = [scan_file(path, graceful=True)]
else:  # fickling HF modu da pickle olmayanları (h5/gguf/safetensors) atlar
    print(json.dumps({"skipped": True}))
    raise SystemExit(0)
worst = max((r.severity for r in results), default=Severity.LIKELY_SAFE)
print(json.dumps({"severity": worst.name, "members": len(results),
                  "errors": [e for r in results for e in r.errors]}))
"""


def parse_fickling_output(stdout: str) -> ToolResult:
    """Sürücü çıktısını ToolResult'a çevirir.

    flagged = fickling'in kendi güvenlik tanımı: önem > LIKELY_SAFE
    (fickling.loader.ScanResult.is_safe ile aynı eşik).
    """
    try:
        data = json.loads(stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return ToolResult(flagged=False, error="çıktı ayrıştırılamadı")
    if "unsupported" in data:
        return ToolResult(flagged=False, error=f"fickling {data['unsupported']} desteklemiyor")
    if data.get("skipped"):
        return ToolResult(flagged=False, detail="pickle değil; atlandı")
    if data.get("members") == 0:
        return ToolResult(flagged=False, detail="taranacak pickle üyesi yok")
    severity = data["severity"]
    errors = data.get("errors") or []
    return ToolResult(flagged=severity != "LIKELY_SAFE", detail=f"severity={severity}",
                      error=str(errors[0])[:120] if errors else "")


def run_fickling(path: Path) -> ToolResult:
    """fickling'i alt süreçte çalıştırır (bkz. _FICKLING_DRIVER)."""
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-c", _FICKLING_DRIVER, str(path)],
            capture_output=True, text=True, timeout=120,
        )
    except Exception as exc:
        return ToolResult(flagged=False, error=f"{type(exc).__name__}: {exc}",
                          seconds=time.perf_counter() - t0)
    res = parse_fickling_output(proc.stdout)
    res.seconds = time.perf_counter() - t0
    return res


def _find_modelscan_exe(explicit: str | None) -> str | None:
    if explicit:
        return explicit if Path(explicit).exists() else None
    env = os.environ.get("MODELSCAN_EXE")
    if env and Path(env).exists():
        return env
    found = shutil.which("modelscan")
    return found


def run_modelscan(path: Path, exe: str) -> ToolResult:
    """ModelScan'i alt süreçte JSON raporuyla çalıştırır. flagged = total_issues > 0."""
    t0 = time.perf_counter()
    fd, out_json = tempfile.mkstemp(prefix="modelscan_", suffix=".json")
    os.close(fd)
    try:
        subprocess.run(
            [exe, "-p", str(path), "-r", "json", "-o", out_json],
            capture_output=True, text=True, timeout=120,
        )
        data = json.loads(Path(out_json).read_text(encoding="utf-8"))
        issues = int(data.get("summary", {}).get("total_issues", 0))
        errs = data.get("errors", []) or []
        err = ""
        if errs:
            # ModelScan desteklemediği/çözemediği dosyada hata listeler.
            first = errs[0]
            err = str(first.get("description", first))[:120] if isinstance(first, dict) else str(first)[:120]
        return ToolResult(flagged=issues > 0, detail=f"total_issues={issues}",
                          error=err, seconds=time.perf_counter() - t0)
    except Exception as exc:
        return ToolResult(flagged=False, error=f"{type(exc).__name__}: {exc}",
                          seconds=time.perf_counter() - t0)
    finally:
        try:
            os.unlink(out_json)
        except OSError:
            pass


# --- Koşum --------------------------------------------------------------------

def fixture_items(corpus: Path) -> dict[str, Path]:
    """Etiketli sentetik korpustaki dosyalar: ad -> yol."""
    items = {p.name: p for p in sorted(corpus.iterdir()) if p.is_file() and p.name in LABELS}
    if not items:
        raise SystemExit(
            f"Korpus boş veya etiketsiz: {corpus}\n"
            f"Önce üretin:  python tools/make_fixtures.py {corpus}"
        )
    return items


def run_comparison(items: dict[str, Path], labels: dict[str, str],
                   modelscan_exe: str | None) -> list[ToolStats]:
    mg = ToolStats("modelguard", labels=labels)
    ps = ToolStats("picklescan", labels=labels)
    ms = ToolStats("ModelScan", labels=labels)
    fk = ToolStats("fickling", labels=labels)

    ps_ok = _module_available("picklescan")
    if not ps_ok:
        ps.available = False
        ps.note = "picklescan kurulu değil (pip install picklescan)"
    if not _module_available("fickling"):
        fk.available = False
        fk.note = "fickling kurulu değil (pip install fickling)"
    exe = _find_modelscan_exe(modelscan_exe)
    if not exe:
        ms.available = False
        ms.note = ("ModelScan bulunamadı. Python 3.10–3.12 ortamına kurup "
                   "--modelscan-exe ile yolunu verin (3.13'te kurulamaz).")

    for name, path in items.items():
        mg.record(name, run_modelguard(path))
        if ps.available:
            ps.record(name, run_picklescan(path))
        if ms.available:
            ms.record(name, run_modelscan(path, exe))  # type: ignore[arg-type]
        if fk.available:
            fk.record(name, run_fickling(path))

    return [mg, ps, ms, fk]


def _module_available(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except ImportError:
        return False


# --- Çıktı --------------------------------------------------------------------

def _pct(x: float | None) -> str:
    return "—" if x is None else f"{x * 100:.0f}%"


def print_console(stats: list[ToolStats]) -> None:
    print("\n=== Tarayıcı Karşılaştırması ===")
    hdr = f"{'Araç':<12} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}  {'Precision':>9} {'Recall':>7} {'FPR':>5} {'F1':>5}  {'süre(s)':>7}"
    print(hdr)
    print("-" * len(hdr))
    for s in stats:
        if not s.available:
            print(f"{s.name:<12} (atlandı: {s.note})")
            continue
        print(f"{s.name:<12} {s.tp:>3} {s.fp:>3} {s.tn:>3} {s.fn:>3}  "
              f"{_pct(s.precision):>9} {_pct(s.recall):>7} {_pct(s.fpr):>5} "
              f"{_pct(s.f1):>5}  {s.total_seconds:>7.3f}")


def to_json(stats: list[ToolStats], labels: dict[str, str]) -> str:
    out = {"corpus_size": len(labels),
           "malicious": sum(1 for v in labels.values() if v == "malicious"),
           "benign": sum(1 for v in labels.values() if v == "benign"),
           "tools": []}
    for s in stats:
        out["tools"].append({
            "name": s.name, "available": s.available, "note": s.note,
            "tp": s.tp, "fp": s.fp, "tn": s.tn, "fn": s.fn, "errors": s.errors,
            "precision": s.precision, "recall": s.recall, "fpr": s.fpr, "f1": s.f1,
            "seconds": round(s.total_seconds, 4),
            "per_file": {k: {"flagged": r.flagged, "detail": r.detail, "error": r.error}
                         for k, r in s.per_file.items()},
        })
    return json.dumps(out, indent=2, ensure_ascii=False)


def to_html(stats: list[ToolStats], labels: dict[str, str]) -> str:
    from modelguard.htmlreport import render_comparison
    return render_comparison(stats, labels)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="modelguard vs picklescan vs ModelScan vs fickling")
    p.add_argument("--corpus", type=Path, default=_ROOT / "tests" / "fixtures",
                   help="etiketli korpus klasörü (varsayılan: tests/fixtures)")
    p.add_argument("--hf", action="store_true",
                   help="sentetik korpus yerine gerçek temiz HF modellerini indirip tara (FPR)")
    p.add_argument("--hf-cache", type=Path, default=None,
                   help="HF indirme klasörü (varsayılan: huggingface_hub önbelleği)")
    p.add_argument("--html", type=Path, default=_ROOT / "reports" / "comparison.html",
                   help="HTML raporu bu dosyaya yaz")
    p.add_argument("--json", type=Path, default=None, help="JSON sonucunu bu dosyaya yaz")
    p.add_argument("--modelscan-exe", default=None,
                   help="ModelScan çalıştırılabilir yolu (3.13'te ayrı ortam gerekir)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.hf:
        items = fetch_hf_corpus(args.hf_cache)
        labels = {name: "benign" for name in items}
    else:
        items = fixture_items(args.corpus)
        labels = LABELS
    stats = run_comparison(items, labels, args.modelscan_exe)
    print_console(stats)

    if args.html:
        args.html.parent.mkdir(parents=True, exist_ok=True)
        args.html.write_text(to_html(stats, labels), encoding="utf-8")
        print(f"\nHTML raporu yazıldı: {args.html}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(to_json(stats, labels), encoding="utf-8")
        print(f"JSON sonucu yazıldı: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
