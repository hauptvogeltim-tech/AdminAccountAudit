#!/usr/bin/env python3
"""Erzeugt README.html aus README.md - eigenstaendig, offline lesbar.

Mermaid-Diagramme werden vorab zu reinem SVG gerendert (ohne foreignObject,
ohne Skripte) und direkt in die Seite eingebettet. Die HTML-Datei braucht daher
weder Internet noch JavaScript, um die Diagramme anzuzeigen.

Voraussetzungen (nur fuer den Build, nicht fuer das Tool selbst):
  - pandoc
  - Mermaid-CLI: mmdc im PATH, oder Pfad in MMDC, sonst "npx -y @mermaid-js/mermaid-cli"
  - fuer mmdc ein Chromium; Pfad optional in PUPPETEER_EXECUTABLE_PATH

Aufruf (im Repo-Wurzelverzeichnis):
  python3 tools/build_readme_html.py [README.md] [README.html]
"""
import datetime
import html
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

MERMAID_CONFIG = {
    "theme": "neutral",
    "htmlLabels": False,
    "flowchart": {"htmlLabels": False, "curve": "basis", "wrappingWidth": 260},
    "themeVariables": {"fontFamily": "Segoe UI, Arial, sans-serif", "fontSize": "15px"},
}

CSS = """
:root {
  --bg: #ffffff; --fg: #1f2328; --muted: #59636e; --line: #d1d9e0;
  --soft: #f6f8fa; --accent: #0b5cad; --code: #eff1f3;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0f1419; --fg: #e6e9ed; --muted: #9aa4af; --line: #2d3640;
    --soft: #161c22; --accent: #6cb6ff; --code: #1c232b;
  }
}
:root[data-theme="dark"] {
  --bg: #0f1419; --fg: #e6e9ed; --muted: #9aa4af; --line: #2d3640;
  --soft: #161c22; --accent: #6cb6ff; --code: #1c232b;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 16px/1.6 "Segoe UI", system-ui, -apple-system, Arial, sans-serif;
}
.layout { display: grid; grid-template-columns: 220px minmax(0, 1fr); gap: 36px;
  max-width: 1500px; margin: 0 auto; padding: 32px 24px 64px; }
nav.toc { position: sticky; top: 24px; align-self: start; max-height: calc(100vh - 48px);
  overflow-y: auto; font-size: 14px; border-right: 1px solid var(--line); padding-right: 16px; }
nav.toc h2 { font-size: 12px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted);
  margin: 0 0 8px; border: 0; padding: 0; }
nav.toc ol { list-style: none; margin: 0; padding: 0; }
nav.toc li { margin: 2px 0; }
nav.toc li.l3 { padding-left: 14px; font-size: 13px; }
nav.toc a { color: var(--fg); text-decoration: none; display: block; padding: 2px 0; }
nav.toc a:hover { color: var(--accent); }
main { min-width: 0; max-width: 1200px; }
.meta { color: var(--muted); font-size: 13px; margin-bottom: 8px; }
h1 { font-size: 34px; line-height: 1.2; margin: 0 0 16px; }
h2 { font-size: 24px; margin: 44px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--line); }
h3 { font-size: 19px; margin: 30px 0 10px; }
a { color: var(--accent); }
p, ul, ol { margin: 0 0 14px; }
code { font-family: Consolas, "Cascadia Mono", Menlo, monospace; font-size: .9em;
  background: var(--code); padding: .1em .35em; border-radius: 4px; }
pre { background: var(--code); padding: 14px 16px; border-radius: 8px; overflow-x: auto;
  font-size: 14px; line-height: 1.5; }
pre code { background: none; padding: 0; font-size: inherit; }
table { border-collapse: collapse; width: 100%; margin: 0 0 18px; font-size: 15px;
  display: block; overflow-x: auto; }
th, td { border: 1px solid var(--line); padding: 7px 11px; text-align: left; vertical-align: top; }
th { background: var(--soft); font-weight: 600; }
figure.diagram { margin: 18px 0 28px; border: 1px solid var(--line); border-radius: 10px;
  background: #ffffff; overflow: hidden; }
figure.diagram .canvas { overflow-x: auto; padding: 16px; text-align: center; }
figure.diagram svg { height: auto; display: inline-block; }
figure.diagram figcaption { display: flex; justify-content: space-between; align-items: center;
  gap: 12px; flex-wrap: wrap; padding: 8px 14px; font-size: 13px; color: #59636e;
  background: #f6f8fa; border-top: 1px solid #d1d9e0; }
figure.diagram button { font: inherit; font-size: 13px; padding: 4px 10px; border-radius: 6px;
  border: 1px solid #c3ccd5; background: #ffffff; color: #1f2328; cursor: pointer; }
figure.diagram button:hover { border-color: #0b5cad; color: #0b5cad; }
.theme-toggle { margin: 0 0 14px; font: inherit; font-size: 13px;
  padding: 4px 10px; border-radius: 6px; border: 1px solid var(--line); background: var(--soft);
  color: var(--fg); cursor: pointer; }
@media (max-width: 900px) {
  .layout { grid-template-columns: 1fr; gap: 0; padding: 20px 16px 48px; }
  nav.toc { position: static; max-height: none; border-right: 0; border-bottom: 1px solid var(--line);
    padding: 0 0 12px; margin-bottom: 8px; }
  h1 { font-size: 28px; }
}
@media print {
  nav.toc, .theme-toggle, figure.diagram button { display: none; }
  .layout { display: block; max-width: none; padding: 0; }
  body { background: #fff; color: #000; font-size: 11pt; }
  figure.diagram { break-inside: avoid; }
  figure.diagram .canvas { overflow: visible; }
  figure.diagram svg { max-width: 100% !important; }
  a { color: #000; }
}
"""

SCRIPT = """
(function () {
  // Diagramm in neuem Fenster in voller Groesse oeffnen (optional; Seite funktioniert ohne Skript)
  document.querySelectorAll('figure.diagram button[data-open]').forEach(function (b) {
    b.addEventListener('click', function () {
      var svg = b.closest('figure').querySelector('svg').cloneNode(true);
      svg.removeAttribute('width'); svg.style.maxWidth = 'none';
      var w = window.open('', '_blank');
      if (!w) { return; }
      w.document.write('<!doctype html><meta charset="utf-8"><title>' + b.getAttribute('data-open') +
        '</title><body style="margin:0;padding:24px;background:#fff">' + svg.outerHTML + '</body>');
      w.document.close();
    });
  });
  var t = document.querySelector('.theme-toggle');
  if (t) {
    t.addEventListener('click', function () {
      var r = document.documentElement;
      var dark = r.getAttribute('data-theme') === 'dark' ||
        (!r.getAttribute('data-theme') && window.matchMedia('(prefers-color-scheme: dark)').matches);
      r.setAttribute('data-theme', dark ? 'light' : 'dark');
    });
  }
})();
"""


def mmdc_command():
    if os.environ.get("MMDC"):
        return shlex.split(os.environ["MMDC"])
    if shutil.which("mmdc"):
        return ["mmdc"]
    return ["npx", "-y", "@mermaid-js/mermaid-cli"]


def render_mermaid(blocks, workdir):
    cfg = os.path.join(workdir, "mermaid.json")
    with open(cfg, "w", encoding="utf-8") as f:
        json.dump(MERMAID_CONFIG, f)
    cmd = mmdc_command()
    extra = []
    chrome = os.environ.get("PUPPETEER_EXECUTABLE_PATH")
    if chrome:
        pp = os.path.join(workdir, "puppeteer.json")
        with open(pp, "w", encoding="utf-8") as f:
            json.dump({"executablePath": chrome, "args": ["--no-sandbox"]}, f)
        extra = ["-p", pp]
    svgs = []
    for i, src in enumerate(blocks):
        inp = os.path.join(workdir, f"d{i}.mmd")
        out = os.path.join(workdir, f"d{i}.svg")
        with open(inp, "w", encoding="utf-8") as f:
            f.write(src)
        # eindeutige SVG-ID je Diagramm, sonst kollidieren die eingebetteten Styles
        subprocess.run(cmd + ["-q", "-c", cfg, "-I", f"diagram{i}", "-i", inp, "-o", out] + extra, check=True)
        with open(out, encoding="utf-8") as f:
            svg = f.read()
        svg = re.sub(r"^<\?xml[^>]*>\s*", "", svg)
        if "<foreignObject" in svg:
            raise SystemExit(f"Diagramm {i}: SVG enthaelt foreignObject - htmlLabels wurde nicht abgeschaltet")
        svgs.append(svg)
    return svgs


def slug(text, used):
    s = re.sub(r"[^\w\- ]", "", text.lower(), flags=re.UNICODE).strip().replace(" ", "-")
    base, n = s or "abschnitt", 1
    while s in used:
        n += 1
        s = f"{base}-{n}"
    used.add(s)
    return s


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "README.md"
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(src)[0] + ".html"
    with open(src, encoding="utf-8") as f:
        md = f.read()

    blocks = []

    def take(m):
        blocks.append(m.group(1))
        return f"\n\nMERMAIDPLACEHOLDER{len(blocks) - 1}\n\n"

    md = re.sub(r"```mermaid\n(.*?)```", take, md, flags=re.S)

    with tempfile.TemporaryDirectory() as tmp:
        svgs = render_mermaid(blocks, tmp)
        body = subprocess.run(["pandoc", "-f", "gfm", "-t", "html5", "--wrap=none"],
                              input=md, capture_output=True, text=True, check=True).stdout

    # Ueberschriften: eigene IDs + Inhaltsverzeichnis; letzte Ueberschrift vor einem Diagramm = Bildtitel
    used, toc, title = set(), [], "README"
    last_heading = ""

    def heading(m):
        nonlocal title, last_heading
        level, inner = int(m.group(1)), m.group(3)
        text = re.sub(r"<[^>]+>", "", inner)
        text = html.unescape(text)
        hid = slug(text, used)
        if level == 1:
            title = text
        elif level in (2, 3):
            toc.append((level, hid, text))
        return f'<h{level} id="{hid}">{inner}</h{level}>'

    body = re.sub(r"<h([1-6])([^>]*)>(.*?)</h\1>", heading, body, flags=re.S)

    out, pos = [], 0
    for m in re.finditer(r"<h[23] id=\"[^\"]*\">(.*?)</h[23]>|<p>MERMAIDPLACEHOLDER(\d+)</p>", body, flags=re.S):
        out.append(body[pos:m.start()])
        if m.group(2) is None:
            last_heading = html.unescape(re.sub(r"<[^>]+>", "", m.group(1)))
            out.append(m.group(0))
        else:
            i = int(m.group(2))
            cap = html.escape(last_heading or f"Diagramm {i + 1}")
            out.append(
                f'<figure class="diagram" role="group" aria-label="{cap}">'
                f'<div class="canvas">{svgs[i]}</div>'
                f'<figcaption><span>Abbildung {i + 1}: {cap}</span>'
                f'<button type="button" data-open="{cap}">In voller Größe öffnen</button></figcaption></figure>')
        pos = m.end()
    out.append(body[pos:])
    body = "".join(out)

    toc_html = "".join(
        f'<li class="l{lvl}"><a href="#{hid}">{html.escape(text)}</a></li>' for lvl, hid, text in toc)
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    page = f"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="layout">
<nav class="toc" aria-label="Inhalt"><button class="theme-toggle" type="button" title="Hell/Dunkel umschalten">Hell/Dunkel</button><h2>Inhalt</h2><ol>{toc_html}</ol></nav>
<main>
<div class="meta">Erzeugt aus {html.escape(os.path.basename(src))} am {stamp} – maßgeblich bleibt die Markdown-Datei.</div>
{body}
</main>
</div>
<script>{SCRIPT}</script>
</body>
</html>
"""
    with open(dst, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"{dst}: {len(svgs)} Diagramme eingebettet, {len(page) // 1024} KB")


if __name__ == "__main__":
    main()
