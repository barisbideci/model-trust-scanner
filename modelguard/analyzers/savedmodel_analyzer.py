"""TensorFlow SavedModel (.pb) statik analizörü.

MANTIK (rehber 1.2-A ile aynı felsefe):
  Bir TF SavedModel aslında bir *hesap grafiğidir*: NodeDef'lerden oluşan bir
  GraphDef. Model yüklenip ilk kez çalıştırıldığında bu grafikteki op'lar
  yürütülür. JFrog'un "tflow-malops" araştırması, grafın içine gömülen
  dosya/IO op'larının (ör. ReadFile ile SSH anahtarı okumak, WriteFile ile
  authorized_keys'e yazmak) ya da Python callback op'larının (PyFunc) model
  yüklenir yüklenmez sessizce çalışabildiğini gösterdi. ModelScan'in yalnızca
  ReadFile/WriteFile'ı denylist'lediği, diğer IO op'larının (Save/Restore/
  MatchingFiles ...) atlanabildiği de aynı araştırmada belgelendi — bu yüzden
  biz geniş bir denylist kullanıyoruz.

TASARIM KARARI — tensorflow'u İMPORT ETME:
  TF çok ağırdır ve grafı "yüklemek" başlı başına risklidir. Bunun yerine .pb
  protobuf dosyasını HAM BAYT olarak okur, içindeki yazdırılabilir ASCII
  dizilerini çıkarır ve bunların içinden op adı (CamelCase token) adaylarını
  denylist ile karşılaştırırız. SavedModel protobuf'unda her NodeDef'in `op`
  alanı (field 2, string) ASCII olarak gömülüdür; uzunluk-önekli olduğu için
  op adı yazdırılabilir bir dizi olarak kolayca ayıklanır. Hiçbir graf
  yüklenmez/execute edilmez.

ATLATMALARA DAYANIKLILIK:
  - Dosya okunamaz/parse edilemezse SUSPICIOUS "SavedModel parse edilemedi"
    döneriz ('taranamadı' güvenli demek değildir).
  - Uzantıya değil içeriğe bakarız; .pb bir dizin (SavedModel) içinde de olabilir.
"""

from __future__ import annotations

import re
from pathlib import Path

from modelguard.analyzers.base import Analyzer
from modelguard.models import Finding, Severity

# --- Bilgi tabanı --------------------------------------------------------------

# Kesin tehlikeli op'lar: bir modelin meşruen gerektirmeyeceği dosya okuma/yazma
# veya keyfi Python callback yüzeyleri => MALICIOUS.
_MALICIOUS_OPS: dict[str, str] = {
    "ReadFile": "diskten dosya okur (ör. ~/.ssh/id_rsa sızdırma)",
    "WriteFile": "diske dosya yazar (ör. authorized_keys arka kapısı)",
    "PyFunc": "keyfi bir Python callback'i çağırır",
    "PyFuncStateless": "keyfi bir Python callback'i çağırır",
    "PyCall": "keyfi bir Python callback'i çağırır",
}

# Daha az kesin IO op'ları: meşru modellerde de görülür (checkpoint kaydet/yükle),
# ama saldırgan tarafından kötüye kullanılabilir => SUSPICIOUS (gözden geçir).
_SUSPICIOUS_OPS: dict[str, str] = {
    "MergeV2Checkpoints": "checkpoint dosyalarını birleştirir (dosya sistemi erişimi)",
    "Save": "tensörleri diske yazar",
    "SaveV2": "tensörleri diske yazar",
    "SaveSlices": "tensör dilimlerini diske yazar",
    "Restore": "diskten tensör okur",
    "RestoreV2": "diskten tensör okur",
    "MatchingFiles": "glob deseniyle dosya sistemini tarar",
    "PrintV2": "stderr/stdout'a ya da bir dosyaya yazar",
    "DecodeRaw": "ham baytları çözer (veri sızdırma zincirinde kullanılabilir)",
}

# .pb içinden op adı adayı olarak yalnızca CamelCase token'ları değerlendiririz;
# böylece "WriteFileX" gibi başka bir op'u yanlışlıkla WriteFile saymayız.
_TOKEN_RE = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*")

# Yazdırılabilir ASCII dizisi (>=3 karakter) çıkarımı.
_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{3,}")

_SAVED_MODEL_NAME = "saved_model.pb"


class SavedModelAnalyzer(Analyzer):
    name = "savedmodel"

    def analyze(self, path: Path) -> list[Finding]:
        """SavedModel .pb dosyasını statik olarak inceler."""
        path = Path(path)
        try:
            pb_path, data = self._load_pb(path)
        except Exception as exc:  # okuma/konum bulma hatası — sessiz geçme
            return [
                Finding(
                    analyzer=self.name,
                    severity=Severity.SUSPICIOUS,
                    title="SavedModel parse edilemedi",
                    detail=(
                        "SavedModel protobuf'u okunamadı; içerik taranamadı. "
                        f"'Taranamadı' güvenli demek değildir. Hata: {exc}"
                    ),
                    location=_SAVED_MODEL_NAME,
                    evidence=str(exc),
                    atlas="AML.T0011",
                    owasp="ML06",
                )
            ]

        ops = self._extract_ops(data)
        return self._evaluate_ops(ops, location=pb_path.name)

    # --- konum bulma / okuma --------------------------------------------------

    def _load_pb(self, path: Path) -> tuple[Path, bytes]:
        """İncelenecek .pb dosyasını bulur ve ham baytlarını döndürür.

        `path` bir dizin (SavedModel) ise içindeki saved_model.pb aranır;
        bulunamazsa herhangi bir .pb dosyası denenir. Tek bir dosya verilirse
        doğrudan o okunur.
        """
        if path.is_dir():
            candidate = path / _SAVED_MODEL_NAME
            if not candidate.is_file():
                pbs = sorted(path.glob("*.pb"))
                if not pbs:
                    raise FileNotFoundError(
                        f"dizinde {_SAVED_MODEL_NAME} veya .pb dosyası yok: {path}"
                    )
                candidate = pbs[0]
            return candidate, candidate.read_bytes()
        return path, path.read_bytes()

    # --- op çıkarımı ----------------------------------------------------------

    def _extract_ops(self, data: bytes) -> set[str]:
        """Ham bayttan yazdırılabilir dizileri çekip op adı adaylarını toplar.

        NodeDef.op alanı uzunluk-önekli ASCII string olduğundan her op adı
        yazdırılabilir bir dizi olarak görünür; o diziden CamelCase token'ları
        çıkarıp aday kümesine ekleriz.
        """
        ops: set[str] = set()
        for run in _PRINTABLE_RUN_RE.findall(data):
            for token in _TOKEN_RE.findall(run):
                ops.add(token.decode("ascii", errors="replace"))
        return ops

    # --- değerlendirme --------------------------------------------------------

    def _evaluate_ops(self, ops: set[str], location: str) -> list[Finding]:
        findings: list[Finding] = []

        for op in sorted(ops):
            if op in _MALICIOUS_OPS:
                findings.append(
                    Finding(
                        analyzer=self.name,
                        severity=Severity.MALICIOUS,
                        title=f"Tehlikeli grafik op'u: {op}",
                        detail=(
                            f"Hesap grafiğinde '{op}' op'u bulundu — {_MALICIOUS_OPS[op]}. "
                            "Model yüklenip çalıştırılınca bu op sessizce tetiklenebilir "
                            "(JFrog 'tflow-malops'). Meşru bir modelde beklenmez."
                        ),
                        location=location,
                        evidence=op,
                        atlas="AML.T0011",
                        owasp="ML06",
                    )
                )
            elif op in _SUSPICIOUS_OPS:
                findings.append(
                    Finding(
                        analyzer=self.name,
                        severity=Severity.SUSPICIOUS,
                        title=f"Dikkat gerektiren grafik op'u: {op}",
                        detail=(
                            f"Hesap grafiğinde '{op}' op'u bulundu — {_SUSPICIOUS_OPS[op]}. "
                            "Normal modeller (checkpoint kaydet/yükle) de içerebilir, ama "
                            "JFrog 'tflow-malops' bu IO op'larının kötüye kullanılabildiğini "
                            "ve ModelScan'in yalnızca ReadFile/WriteFile'ı denylist'leyip "
                            "bunları atladığını gösterdi. Gözden geçirin."
                        ),
                        location=location,
                        evidence=op,
                        atlas="AML.T0011",
                        owasp="ML06",
                    )
                )

        return findings
