"""HTML rapor üretimi (jinja2).

İki çıktı:
  - render_scan(result): modelguard'ın tek tarama sonucunu okunur bir sayfaya döker
    (cli --html). Terminal raporunun kalıcı/paylaşılabilir karşılığı.
  - render_comparison(stats, labels): tools/compare_scanners.py için araç karşılaştırma
    tablosu (precision/recall/FPR + dosya bazında matris).

Güvenlik: model/araç kaynaklı tüm metin jinja2 autoescape ile escape edilir
(terminal raporundaki rich-escape ile aynı ilke — markup/HTML enjeksiyonu önlenir).
Sayfa tek dosyadır: CSS gömülü, harici kaynak yok (çevrimdışı açılır).
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from jinja2 import Environment, select_autoescape

from modelguard.models import ScanResult
from modelguard.scoring import VERDICT_ADVICE, framework_summary, severity_counts

if TYPE_CHECKING:  # yalnızca tip ipucu; döngüsel import olmasın
    from tools.compare_scanners import ToolStats

_env = Environment(autoescape=select_autoescape(["html", "xml"]))

_CSS = """
:root { color-scheme: light dark; }
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
       margin: 0; padding: 24px; background: #f6f7f9; color: #1a1d21; }
.wrap { max-width: 960px; margin: 0 auto; }
h1 { font-size: 22px; margin: 0 0 4px; }
.sub { color: #6b7280; font-size: 13px; margin-bottom: 20px; }
.banner { padding: 14px 18px; border-radius: 10px; font-weight: 700;
          color: #fff; margin-bottom: 20px; }
.SAFE { background: #15803d; } .LOW { background: #0e7490; }
.SUSPICIOUS { background: #b45309; } .MALICIOUS { background: #b91c1c; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px;
        padding: 16px 18px; margin-bottom: 16px; }
.file { font-weight: 600; } .fmt { color: #6b7280; font-weight: 400; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid #eef0f2;
         vertical-align: top; }
th { background: #f3f4f6; font-size: 12px; text-transform: uppercase;
     letter-spacing: .03em; color: #4b5563; }
.pill { display: inline-block; padding: 2px 8px; border-radius: 999px;
        font-size: 11px; font-weight: 700; color: #fff; }
.evi { color: #6b7280; font-family: ui-monospace, Menlo, Consolas, monospace;
       font-size: 12px; word-break: break-all; }
.ok { color: #15803d; } .no { color: #b91c1c; } .mut { color: #9ca3af; }
.metric { font-variant-numeric: tabular-nums; }
.note { background: #fffbeb; border: 1px solid #fde68a; border-radius: 8px;
        padding: 10px 12px; font-size: 13px; margin-bottom: 14px; }
footer { color: #9ca3af; font-size: 12px; margin-top: 24px; }
"""

# --- tarama raporu ------------------------------------------------------------

_SCAN_TMPL = _env.from_string("""<!doctype html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>modelguard raporu — {{ target }}</title><style>{{ css }}</style></head>
<body><div class="wrap">
  <h1>modelguard tarama raporu</h1>
  <div class="sub">Hedef: <code>{{ target }}</code> · {{ generated }}</div>
  <div class="banner {{ verdict }}">SONUÇ: {{ verdict }}</div>
  <div class="card"><div class="sub" style="margin:0">
    {{ advice }}</div></div>

  {% for f in files %}
  <div class="card">
    <div class="file">{{ f.path }} <span class="fmt">({{ f.format }})</span>
      → <span class="pill {{ f.verdict }}">{{ f.verdict }}</span></div>
    {% if f.errors %}<div class="sub">hatalar: {{ f.errors|join('; ') }}</div>{% endif %}
    {% if f.findings %}
    <table><thead><tr><th>Düzey</th><th>Başlık</th><th>Açıklama</th>
      <th>Konum / Kanıt</th><th>Çerçeve</th></tr></thead><tbody>
    {% for x in f.findings %}
      <tr>
        <td><span class="pill {{ x.severity }}">{{ x.severity }}</span></td>
        <td>{{ x.title }}</td>
        <td>{{ x.detail }}</td>
        <td>{{ x.location }}{% if x.evidence %}<div class="evi">{{ x.evidence }}</div>{% endif %}</td>
        <td class="evi">{{ x.framework }}</td>
      </tr>
    {% endfor %}
    </tbody></table>
    {% else %}<div class="ok">bulgu yok</div>{% endif %}
  </div>
  {% endfor %}

  {% if atlas or owasp %}
  <div class="card"><b>Çerçeve eşlemesi</b>
    {% if atlas %}<div class="sub">ATLAS: {{ atlas }}</div>{% endif %}
    {% if owasp %}<div class="sub">OWASP: {{ owasp }}</div>{% endif %}
  </div>{% endif %}

  <footer>modelguard · statik+dinamik model güvenlik taraması · "taranamadı ≠ güvenli"</footer>
</div></body></html>
""")


def render_scan(result: ScanResult) -> str:
    fw = framework_summary(result)
    files = []
    for fr in result.files:
        findings = []
        for x in sorted(fr.findings, key=lambda i: i.severity, reverse=True):
            fwlabel = " ".join(p for p in (x.atlas, x.owasp) if p)
            findings.append({
                "severity": x.severity.label, "title": x.title, "detail": x.detail,
                "location": x.location, "evidence": x.evidence, "framework": fwlabel,
            })
        files.append({
            "path": str(fr.path), "format": fr.detected_format,
            "verdict": fr.severity.label, "errors": fr.errors, "findings": findings,
        })
    return _SCAN_TMPL.render(
        css=_CSS, target=str(result.target), verdict=result.severity.label,
        advice=VERDICT_ADVICE[result.severity],
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        files=files,
        atlas=", ".join(f"{k}×{v}" for k, v in fw["atlas"].items()),
        owasp=", ".join(f"{k}×{v}" for k, v in fw["owasp"].items()),
    )


# --- karşılaştırma raporu -----------------------------------------------------

_CMP_TMPL = _env.from_string("""<!doctype html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tarayıcı Karşılaştırması — modelguard</title><style>{{ css }}</style></head>
<body><div class="wrap">
  <h1>Tarayıcı karşılaştırması</h1>
  <div class="sub">{{ tools | map(attribute='name') | join(' · ') }} — {{ generated }}</div>
  <div class="note">Korpus: <b>{{ n }}</b> dosya ({{ mal }} zararlı, {{ ben }} zararsız).
    Tüm örnekler zararsız canary'dir; taramalar statiktir (model yüklenmez).</div>

  <div class="card">
    <b>Özet metrikler</b>
    <table><thead><tr><th>Araç</th><th>TP</th><th>FP</th><th>TN</th><th>FN</th>
      <th>Precision</th><th>Recall</th><th>FPR</th><th>F1</th><th>Süre (s)</th></tr></thead>
    <tbody>
    {% for t in tools %}
      {% if t.available %}
      <tr>
        <td><b>{{ t.name }}</b></td>
        <td class="metric">{{ t.tp }}</td><td class="metric">{{ t.fp }}</td>
        <td class="metric">{{ t.tn }}</td><td class="metric">{{ t.fn }}</td>
        <td class="metric">{{ t.precision }}</td><td class="metric">{{ t.recall }}</td>
        <td class="metric">{{ t.fpr }}</td><td class="metric">{{ t.f1 }}</td>
        <td class="metric">{{ t.seconds }}</td>
      </tr>
      {% else %}
      <tr><td><b>{{ t.name }}</b></td><td colspan="9" class="mut">atlandı — {{ t.note }}</td></tr>
      {% endif %}
    {% endfor %}
    </tbody></table>
  </div>

  <div class="card">
    <b>Dosya bazında sonuç</b> (✓ = tehdit olarak işaretlendi)
    <table><thead><tr><th>Dosya</th><th>Gerçek</th>
      {% for t in tools %}<th>{{ t.name }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for row in matrix %}
      <tr>
        <td>{{ row.file }}</td>
        <td><span class="pill {{ 'MALICIOUS' if row.truth == 'malicious' else 'SAFE' }}">{{ row.truth }}</span></td>
        {% for c in row.cells %}
          <td>{% if c.na %}<span class="mut">—</span>
              {% elif c.flagged %}<span class="ok">✓</span>
              {% else %}<span class="no">✗</span>{% endif %}
            {% if c.error %}<div class="evi">hata: {{ c.error }}</div>
            {% elif c.detail %}<div class="evi">{{ c.detail }}</div>{% endif %}
          </td>
        {% endfor %}
      </tr>
    {% endfor %}
    </tbody></table>
  </div>

  <footer>modelguard karşılaştırma koşumu · tools/compare_scanners.py</footer>
</div></body></html>
""")


def _pct(x: float | None) -> str:
    return "—" if x is None else f"{x * 100:.0f}%"


def render_comparison(stats: "list[ToolStats]", labels: dict[str, str]) -> str:
    tools = [{
        "name": s.name, "available": s.available, "note": s.note,
        "tp": s.tp, "fp": s.fp, "tn": s.tn, "fn": s.fn,
        "precision": _pct(s.precision), "recall": _pct(s.recall),
        "fpr": _pct(s.fpr), "f1": _pct(s.f1),
        "seconds": f"{s.total_seconds:.3f}",
    } for s in stats]

    matrix = []
    for fname in sorted(labels):
        cells = []
        for s in stats:
            if not s.available:
                cells.append({"na": True})
                continue
            r = s.per_file.get(fname)
            if r is None:
                cells.append({"na": True})
            else:
                cells.append({"na": False, "flagged": r.flagged,
                              "detail": r.detail, "error": r.error})
        matrix.append({"file": fname, "truth": labels[fname], "cells": cells})

    return _CMP_TMPL.render(
        css=_CSS, generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        n=len(labels),
        mal=sum(1 for v in labels.values() if v == "malicious"),
        ben=sum(1 for v in labels.values() if v == "benign"),
        tools=tools, matrix=matrix,
    )
