"""Sandbox İÇİNDE çalışan izleme çekirdeği — modeli yükler ve davranışını kaydeder.

Bu betik KASITLI olarak güvenilmeyen modeli YÜKLER (execute eder). Bu yüzden YALNIZCA
izole, ağı kapalı bir ortamda (Docker --network none, veya açık onayla host) çalıştırılır.
Çalıştırmadan önce `MODELGUARD_SANDBOX=1` ortam değişkeni aranır; yoksa reddeder.

Çıktı: stdout'a tek satır JSON — {events, loaded, error}. Üst katman (sandbox.py) bunu
Finding'lere çevirir.

Yalnızca standart kütüphane kullanılır (slim Docker imajında çalışabilsin diye).
"""

from __future__ import annotations

import json
import os
import sys

# Güvenlik kapısı: açık onay olmadan model yükleme.
_GATE = "MODELGUARD_SANDBOX"

# Audit olayı -> (önem etiketi, kısa açıklama). sys.addaudithook ile yakalanır.
# Önem: "malicious" | "suspicious" | "info".
#
# NOT: Yalnızca YÜKSEK SİNYALLİ (saldırgan niyeti gösteren) olaylar tutulur.
# `marshal.loads` (.pyc import'larında), `socket.getaddrinfo`, genel dosya yazma gibi
# olaylar normal yorumlayıcı etkinliğinde de tetiklendiği için GÜRÜLTÜ sayılıp dışlandı.
_EVENT_RULES: dict[str, tuple[str, str]] = {
    "os.system": ("malicious", "kabuk komutu çalıştırıldı"),
    "os.exec": ("malicious", "süreç exec edildi"),
    "os.posix_spawn": ("malicious", "süreç spawn edildi"),
    "os.spawn": ("malicious", "süreç spawn edildi"),
    "subprocess.Popen": ("malicious", "harici süreç başlatıldı"),
    "socket.connect": ("malicious", "giden ağ bağlantısı denendi"),
    "socket.bind": ("suspicious", "ağ soketi dinlemeye açıldı (olası servis)"),
    "socket.sendto": ("suspicious", "ağ üzerinden veri gönderildi"),
    "ctypes.dlopen": ("malicious", "native kütüphane yüklendi (ctypes)"),
    "winreg.OpenKey": ("suspicious", "Windows kayıt defteri erişimi (olası kalıcılık)"),
    "winreg.SetValue": ("malicious", "Windows kayıt defterine yazıldı (kalıcılık)"),
    "urllib.Request": ("malicious", "HTTP isteği oluşturuldu"),
    "ftplib.connect": ("malicious", "FTP bağlantısı"),
    "smtplib.connect": ("malicious", "SMTP bağlantısı"),
}

# İçine yazılması kalıcılık (persistence) işareti sayılan yol parçaları.
_PERSIST_HINTS = (
    "/etc/cron", "/etc/systemd", "/etc/init.d", "crontab",
    "/.ssh/authorized_keys", "/.bashrc", "/.bash_profile", "/.profile",
    "\\startup\\", "currentversion\\run", "/library/launchagents",
)


def _classify_open(path: str, mode_flags) -> tuple[str, str] | None:
    """open() olayını değerlendir — yalnızca KALICILIK yollarına erişim işaretlenir.

    Genel dosya yazma (.pyc önbelleği, geçici dosyalar) normal etkinlikte de olur;
    gürültüyü azaltmak için yalnızca cron/systemd/ssh/startup gibi yollara bakılır.
    """
    low = str(path).lower().replace("\\", "/")
    for hint in _PERSIST_HINTS:
        if hint.replace("\\", "/") in low:
            return ("malicious", f"kalıcılık yoluna erişim: {path}")
    return None


def run(target: str) -> dict:
    events: list[dict] = []
    seen: set[tuple] = set()  # aynı olayı tekrar tekrar kaydetme

    def record(level: str, event: str, desc: str, detail: str = "") -> None:
        detail = _sanitize(detail)
        key = (event, detail)
        if key in seen:
            return
        seen.add(key)
        events.append({"level": level, "event": event, "desc": desc, "detail": detail})

    def hook(event: str, args):
        try:
            # Doğrudan eşleşen tehlikeli olaylar.
            for prefix, (level, desc) in _EVENT_RULES.items():
                if event == prefix or event.startswith(prefix):
                    detail = _first_str(args)
                    record(level, event, desc, detail)
                    return
            # open: yazma/kalıcılık değerlendirmesi.
            if event == "open" and args:
                res = _classify_open(args[0], args[1] if len(args) > 1 else None)
                if res:
                    record(res[0], "open", res[1], str(args[0]))
            # pickle.find_class: unpickle sırasında çözülen her global (statik ile köprü).
            elif event == "pickle.find_class" and args:
                mod = str(args[0]) if args else ""
                name = str(args[1]) if len(args) > 1 else ""
                ref = f"{mod}.{name}"
                if _is_dangerous_global(mod, name):
                    record("malicious", "pickle.find_class",
                           "unpickle sırasında tehlikeli global çözüldü", ref)
                elif not _is_allowed_global(ref):
                    record("suspicious", "pickle.find_class",
                           "unpickle sırasında allowlist dışı global", ref)
        except Exception:
            pass  # izleme hiçbir koşulda yüklemeyi bozmamalı

    sys.addaudithook(hook)

    result = {"loaded": False, "error": "", "events": events}
    try:
        _attempt_load(target)
        result["loaded"] = True
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def _sanitize(s: str, limit: int = 160) -> str:
    """Olay detayını güvenli hale getir: yalnızca yazdırılabilir, kısa.

    Kötü bir model, detayı kontrol edebilir; uzun/ikili/markup içeren içerik rapor
    katmanını bozmasın diye temizleriz (savunmacı girdi doğrulama).
    """
    if not isinstance(s, str):
        s = str(s)
    s = "".join(c for c in s if c.isprintable() and c not in "[]")
    return s[:limit]


def _first_str(args) -> str:
    try:
        for a in (args or ()):
            if isinstance(a, (str, bytes)):
                return a.decode(errors="replace") if isinstance(a, bytes) else a
        return str(args[0]) if args else ""
    except Exception:
        return ""


def _is_dangerous_global(mod: str, name: str) -> bool:
    dangerous_mods = {"os", "nt", "posix", "subprocess", "socket", "pty",
                      "ctypes", "importlib", "runpy", "builtins"}
    dangerous_names = {"system", "popen", "exec", "eval", "Popen", "call", "run",
                       "spawn", "__import__", "compile"}
    return mod in dangerous_mods or name in dangerous_names


def _is_allowed_global(ref: str) -> bool:
    allowed = ("torch.", "collections.OrderedDict", "numpy.", "numpy._core.",
               "_codecs.encode", "collections.defaultdict", "argparse.Namespace")
    return any(ref.startswith(p) for p in allowed)


def _attempt_load(target: str) -> None:
    """Modeli en uygun yükleyiciyle yüklemeyi dener (payload burada tetiklenir)."""
    # Önce torch varsa onu dene (PyTorch ZIP/pickle için doğru yol).
    try:
        import torch  # type: ignore
        torch.load(target, map_location="cpu", weights_only=False)
        return
    except ImportError:
        pass
    except Exception:
        # torch.load başarısız olsa bile audit olayları yakalandı; alt yollarla devam.
        pass

    import pickle
    import zipfile
    import tarfile

    # ZIP/TAR ise (PyTorch paketi) içindeki pickle üyelerini çıkarıp yükle.
    if zipfile.is_zipfile(target):
        with zipfile.ZipFile(target) as zf:
            for info in zf.infolist():
                if _is_pickle_member(info.filename):
                    pickle.loads(zf.read(info))
        return
    try:
        if tarfile.is_tarfile(target):
            with tarfile.open(target, "r:*") as tf:
                for m in tf.getmembers():
                    if m.isfile() and _is_pickle_member(m.name):
                        fp = tf.extractfile(m)
                        if fp is not None:
                            pickle.loads(fp.read())
            return
    except (tarfile.TarError, OSError):
        pass

    # Ham pickle. Eski torch formatı 5 ardışık pickle içerir (payload herhangi
    # birinde olabilir); PyTorch gibi sırayla en fazla 5 akış yükleriz.
    with open(target, "rb") as f:
        for _ in range(5):
            try:
                pickle.load(f)
            except EOFError:
                break


def _is_pickle_member(name: str) -> bool:
    low = name.lower()
    base = low.rsplit("/", 1)[-1]
    # .pkl/.pickle üyeler + eski torch TAR formatının uzantısız üyeleri.
    return low.endswith((".pkl", ".pickle")) or base in ("pickle", "sys_info")


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print(json.dumps({"error": "hedef yol verilmedi", "events": []}))
        return 2
    if os.environ.get(_GATE) != "1":
        print(json.dumps({
            "error": f"güvenlik kapısı: {_GATE}=1 ayarlı değil; model yüklenmedi",
            "events": [],
        }))
        return 3
    result = run(argv[0])
    # ensure_ascii=True: Windows konsolu (cp1254) ve üst sürecin metin çözümü güvenli
    # olsun diye saf ASCII yazarız; json.loads karşı tarafta geri çözer.
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
