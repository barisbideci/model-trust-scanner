"""Pickle statik analizörü — modelguard'ın çekirdeği.

MANTIK (rehber 1.2-A):
  Pickle bir "veri formatı" değil, küçük bir yığın-tabanlı sanal makine için
  bytecode'dur. Dosyayı açmak bu bytecode'u çalıştırmak demektir; bu yüzden
  güvenilmeyen pickle = yabancı program. Biz `pickletools.genops` ile akışı
  ÇALIŞTIRMADAN opcode opcode okur, tehlikeli kalıpları ararız.

ARADIKLARIMIZ:
  - GLOBAL / STACK_GLOBAL : bir modülden isim import etme (ör. os.system).
  - REDUCE / INST / OBJ / NEWOBJ / BUILD : bir çağrılabiliri tetikleme.
  Tehlikeli = "tehlikeli modülden import" + "çağırma" birlikteliği.

ATLATMALARA DAYANIKLILIK:
  - Bozuk/yarım akış: genops hata verse de o ana kadarki opcode'lar değerlendirilir
    ve ayrıca SUSPICIOUS "tam parse edilemedi" bulgusu eklenir ('taranamadı' != güvenli).
  - Çoklu STOP: ilk STOP'ta durmaz, tüm akışı gezeriz.
  - Allowlist temelli: bilinen-güvenli global'ler dışındaki her import şüphelidir.
"""

from __future__ import annotations

import io
import pickletools
import tarfile
import zipfile
from pathlib import Path

from modelguard.analyzers.base import Analyzer
from modelguard.models import Finding, Severity

# --- Bilgi tabanı --------------------------------------------------------------

# Kesin tehlikeli: bir modelin meşru biçimde çağırmayacağı kod-çalıştırma yüzeyleri.
_DANGEROUS: dict[str, str] = {
    "os.system": "kabuk komutu çalıştırır",
    "posix.system": "kabuk komutu çalıştırır",
    "nt.system": "kabuk komutu çalıştırır",
    "os.popen": "kabuk komutu çalıştırır",
    "subprocess.Popen": "harici süreç başlatır",
    "subprocess.call": "harici süreç başlatır",
    "subprocess.run": "harici süreç başlatır",
    "subprocess.check_output": "harici süreç başlatır",
    "builtins.exec": "keyfi Python kodu çalıştırır",
    "builtins.eval": "keyfi Python ifadesi çalıştırır",
    "builtins.compile": "kod derler",
    "builtins.__import__": "dinamik modül yükler",
    "builtins.getattr": "dinamik öznitelik erişimi (kaçamak)",
    "importlib.import_module": "dinamik modül yükler",
    "socket.socket": "ağ soketi açar",
    "pty.spawn": "etkileşimli kabuk açar",
    "runpy._run_code": "kod çalıştırır",
    "webbrowser.open": "dışarıya istek tetikler",
}

# Modeli yüklerken meşru biçimde görülen global'ler (prefix eşleşmesi).
_ALLOWED_PREFIXES: tuple[str, ...] = (
    "torch.",
    "torch._utils.",
    "torch.storage.",
    "torch.nn.",
    "collections.OrderedDict",
    "collections.defaultdict",
    "numpy.core.multiarray._reconstruct",
    "numpy.core.multiarray.scalar",
    "numpy.dtype",
    "numpy.ndarray",
    "numpy._core.",
    "_codecs.encode",
    "argparse.Namespace",
)

# Global çözümleme için izlenen opcode grupları (bkz. _scan_stream).
_STRING_OPS = frozenset({"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
                         "SHORT_BINSTRING", "BINSTRING", "STRING"})
_GET_OPS = frozenset({"GET", "BINGET", "LONG_BINGET"})
_PUT_OPS = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})

# Pickle'ın içinde gömülü olabileceği arşivlerdeki pickle uzantıları.
_PICKLE_MEMBER_SUFFIXES = (".pkl", ".pickle", "data.pkl")

# Eski (torch < 1.6) TAR formatında pickle taşıyan üyelerin adları — uzantı yok.
_LEGACY_TAR_PICKLE_NAMES = frozenset({"pickle", "sys_info"})

# Eski (ZIP olmayan) torch.save formatı: ilk pickle bu sihirli sayıdır, ardından
# protocol, sys_info, asıl nesne ve storage anahtarları gelir (toplam 5 akış);
# geri kalan baytlar pickle DEĞİL, ham tensör verisidir.
_TORCH_LEGACY_MAGIC = 0x1950A86A20F9469CFC6C
_TORCH_LEGACY_STREAMS = 5


class PickleAnalyzer(Analyzer):
    name = "pickle"

    def analyze(self, path: Path) -> list[Finding]:
        """Dosyayı formatına göre açar ve içindeki her pickle akışını tarar."""
        findings: list[Finding] = []
        try:
            streams = list(self._extract_pickle_streams(path))
        except Exception as exc:  # arşiv açma hatası — şüpheli, sessiz geçme
            return [
                Finding(
                    analyzer=self.name,
                    severity=Severity.SUSPICIOUS,
                    title="Arşiv açılamadı",
                    detail=f"Dosya açılırken hata oluştu; içerik taranamadı: {exc}",
                    location=str(path.name),
                    owasp="ML06",
                )
            ]

        if not streams:
            return findings

        for member, data in streams:
            findings.extend(self._scan_stream(data, member))
        return findings

    # --- akış çıkarma ---------------------------------------------------------

    def _extract_pickle_streams(self, path: Path):
        """(üye adı, ham baytlar) çiftleri üretir. ZIP/7z/TAR/raw destekler."""
        with open(path, "rb") as f:
            head = f.read(8)

        if head.startswith(b"PK"):
            yield from self._from_zip(path)
        elif head.startswith(b"7z\xbc\xaf\x27\x1c"):
            yield from self._from_7z(path)
        elif head[:5] == b"ustar" or self._is_tar(path):
            yield from self._from_tar(path)
        else:
            # Ham pickle dosyası.
            yield (path.name, path.read_bytes())

    @staticmethod
    def _is_tar(path: Path) -> bool:
        try:
            return tarfile.is_tarfile(path)
        except OSError:
            return False

    def _from_zip(self, path: Path):
        # "Yükleyiciden daha katı olma": CRC hatasını yok sayıp yine de okumaya çalış
        # (CVE-2025-10156 — PyTorch bozuk CRC'yi yüklerdi, picklescan hata verirdi).
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if self._is_pickle_member(info.filename):
                    try:
                        yield (info.filename, zf.read(info))
                    except (zipfile.BadZipFile, Exception):
                        # CRC vb. hatada ham veriyi düşük seviyeden çekmeyi dene.
                        raw = self._read_zip_member_ignore_crc(zf, info)
                        if raw:
                            yield (info.filename + " [CRC yoksayıldı]", raw)

    @staticmethod
    def _read_zip_member_ignore_crc(zf: zipfile.ZipFile, info) -> bytes | None:
        try:
            with zf.open(info, "r") as fp:
                fp._expected_crc = None  # type: ignore[attr-defined]  # CRC kontrolünü kapat
                return fp.read()
        except Exception:
            return None

    def _from_7z(self, path: Path):
        try:
            import py7zr
        except ImportError:
            raise RuntimeError("7z içeriği için 'py7zr' gerekli (pip install py7zr)")
        import tempfile

        # py7zr'nin bu sürümünde bellek-içi okuma yok; pickle üyelerini geçici
        # klasöre çıkarıp bayt olarak okuruz (çalıştırmadan, sadece okuma).
        with py7zr.SevenZipFile(path, "r") as zf:
            names = [n for n in zf.getnames() if self._is_pickle_member(n)]
            if not names:
                return
            with tempfile.TemporaryDirectory(prefix="modelguard7z_") as tmp:
                zf.extract(path=tmp, targets=names)
                for name in names:
                    fp = Path(tmp) / name
                    if fp.is_file():
                        yield (name, fp.read_bytes())

    def _from_tar(self, path: Path):
        with tarfile.open(path, "r:*") as tf:
            for member in tf.getmembers():
                if member.isfile() and self._is_pickle_member(member.name):
                    fp = tf.extractfile(member)
                    if fp is not None:
                        yield (member.name, fp.read())

    @staticmethod
    def _is_pickle_member(name: str) -> bool:
        low = name.lower()
        base = low.rsplit("/", 1)[-1]
        return low.endswith(_PICKLE_MEMBER_SUFFIXES) or base in _LEGACY_TAR_PICKLE_NAMES

    # --- opcode tarama --------------------------------------------------------

    def _scan_stream(self, data: bytes, member: str) -> list[Finding]:
        """Bir bayt tamponundaki TÜM pickle akışlarını tarar.

        `pickletools.genops` tek bir akışı ilk STOP'ta bitirir. Bazı atlatmalar
        STOP'tan sonra ikinci bir pickle ekler (ModelScan ilk STOP'ta durduğu için
        kaçırır). Biz STOP'tan sonra kalan baytları yeni akış sayıp tekrar tararız.
        """
        findings: list[Finding] = []
        globals_seen: list[tuple[int, str]] = []
        stream = io.BytesIO(data)
        substreams = 0
        total = len(data)
        legacy_torch = False

        while stream.tell() < total:
            # Eski torch formatında PyTorch tam 5 akış unpickle eder; sonrası ham
            # tensör verisidir. Yükleyiciyle aynı yerde dururuz (pickle sanıp
            # "bozuk akış" yanlış alarmı vermemek için).
            if legacy_torch and substreams >= _TORCH_LEGACY_STREAMS:
                break
            start = stream.tell()
            # STACK_GLOBAL modül/ad'ı yığının üstündeki iki değerden alır; bu değerler
            # memo'dan (BINGET) da gelebilir. "Son iki literal"e bakmak atlatılabilir:
            # 'os' memo'ya konup araya izinli bir yem ('torch') yazılırsa "torch.system"
            # okunur. Bu yüzden yığın üstünü ve memo'yu hafifçe taklit ederiz:
            # string olmayan her itme None'dır -> çözülemeyen ad "dinamik" sayılır.
            pushed: list[str | None] = []
            memo: dict[int, str | None] = {}
            produced_any = False
            try:
                for opcode, arg, pos in pickletools.genops(stream):
                    produced_any = True
                    nm = opcode.name

                    if substreams == 0 and nm in ("LONG1", "LONG4", "LONG", "INT") \
                            and arg == _TORCH_LEGACY_MAGIC:
                        legacy_torch = True

                    if nm in _STRING_OPS:
                        pushed.append(arg.decode(errors="replace")
                                      if isinstance(arg, bytes) else str(arg))
                    elif nm in _GET_OPS:
                        pushed.append(memo.get(arg))
                    elif nm == "MEMOIZE":
                        memo[len(memo)] = pushed[-1] if pushed else None
                    elif nm in _PUT_OPS:
                        memo[arg] = pushed[-1] if pushed else None
                    elif nm in ("GLOBAL", "INST"):  # INST: import + çağrı tek opcode'da
                        ref = str(arg).replace(" ", ".", 1) if arg else ""
                        globals_seen.append((start + (pos or 0), ref))
                        pushed.append(None)
                    elif nm == "STACK_GLOBAL":
                        mod, name = (pushed[-2:] if len(pushed) >= 2 else (None, None))
                        ref = (f"{mod}.{name}" if mod is not None and name is not None
                               else "<dinamik STACK_GLOBAL>")
                        globals_seen.append((start + (pos or 0), ref))
                        pushed.append(None)
                    else:
                        pushed.append(None)
                    del pushed[:-2]  # yalnızca yığının üst iki değeri gerekir

                    # STOP: genops bu akışı bitirir; döngü kalan baytlarla devam eder.
            except Exception as exc:
                findings.append(
                    Finding(
                        analyzer=self.name,
                        severity=Severity.SUSPICIOUS,
                        title="Pickle akışı tam çözümlenemedi",
                        detail=(
                            "Opcode akışı bozuk/yarım. Payload akışın başına konup "
                            "tarayıcıyı hata verdirme atlatması olabilir (nullifAI). "
                            "'Taranamadı' güvenli demek değildir."
                        ),
                        location=f"{member} @ bayt {start}",
                        evidence=str(exc),
                        atlas="AML.T0011",
                        owasp="ML06",
                    )
                )
                break

            if not produced_any:  # ilerleme yoksa sonsuz döngüyü önle
                break
            substreams += 1

        findings.extend(self._evaluate_globals(globals_seen, member))

        if substreams > 1 and not legacy_torch:
            findings.append(
                Finding(
                    analyzer=self.name,
                    severity=Severity.SUSPICIOUS,
                    title=f"STOP'tan sonra ek pickle akışı ({substreams} akış)",
                    detail=(
                        "Dosyada birden çok art arda pickle akışı var. Bazı tarayıcılar "
                        "ilk STOP'ta durup gerisini kaçırır (ModelScan atlatması). "
                        "Tüm akışlar tarandı."
                    ),
                    location=member,
                    atlas="AML.T0011",
                    owasp="ML06",
                )
            )

        return findings

    def _evaluate_globals(
        self, globals_seen: list[tuple[int, str]], member: str
    ) -> list[Finding]:
        out: list[Finding] = []
        for pos, ref in globals_seen:
            if ref in _DANGEROUS:
                out.append(
                    Finding(
                        analyzer=self.name,
                        severity=Severity.MALICIOUS,
                        title=f"Tehlikeli global import: {ref}",
                        detail=f"{ref} — {_DANGEROUS[ref]}. Pickle yüklenince çalışabilir.",
                        location=f"{member} @ opcode bayt {pos}",
                        evidence=ref,
                        atlas="AML.T0011",
                        owasp="ML06",
                    )
                )
            elif ref.startswith("<dinamik") or not self._is_allowed(ref):
                out.append(
                    Finding(
                        analyzer=self.name,
                        severity=Severity.SUSPICIOUS,
                        title=f"İzin listesinde olmayan import: {ref}",
                        detail=(
                            "Bu global, bilinen-güvenli model yükleme çağrıları "
                            "arasında değil. Allowlist dışı her import gözden geçirilmeli."
                        ),
                        location=f"{member} @ opcode bayt {pos}",
                        evidence=ref,
                        owasp="ML06",
                    )
                )
        return out

    @staticmethod
    def _is_allowed(ref: str) -> bool:
        return any(ref.startswith(p) for p in _ALLOWED_PREFIXES)
