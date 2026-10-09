"""Komut satırı arayüzü:  modelguard scan <yol> [--json <dosya>] [--quiet]

Çıkış kodu = tehlike düzeyi (0 SAFE .. 3 MALICIOUS) → CI/script entegrasyonu için.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from modelguard import __version__
from modelguard.report import print_terminal, write_json
from modelguard.scanner import scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="modelguard",
        description="İndirilen AI modellerinde kod/servis tehditlerini tarar.",
    )
    p.add_argument("--version", action="version", version=f"modelguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="bir dosyayı veya klasörü tara")
    s.add_argument("path", type=Path, help="model dosyası ya da klasör")
    s.add_argument("--json", type=Path, default=None, help="JSON raporu bu dosyaya yaz")
    s.add_argument("--quiet", action="store_true", help="terminal raporunu bastırma")
    s.add_argument("--dynamic", action="store_true",
                   help="dinamik analiz: modeli izole (Docker) ortamda yükleyip izle")
    s.add_argument("--allow-host", action="store_true",
                   help="Docker yoksa modeli BU makinede çalıştır (zayıf izolasyon; riski kabul et)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "scan":
        if not args.path.exists():
            print(f"hata: yol bulunamadı: {args.path}", file=sys.stderr)
            return 2
        result = scan(args.path, dynamic=args.dynamic, allow_host=args.allow_host)
        if not args.quiet:
            print_terminal(result)
        if args.json:
            write_json(result, args.json)
            if not args.quiet:
                print(f"\nJSON raporu yazıldı: {args.json}")
        return int(result.severity)  # çıkış kodu = düzey

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
