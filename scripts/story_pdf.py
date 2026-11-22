#!/usr/bin/env python3
"""Build docs/story.md into a PDF.

A PDF cannot animate, so before rendering:
  * the demo GIF is swapped for docs/demo/demo-final.png (its last frame);
  * every SVG with SMIL <animate> elements is frozen at its final state.

Then pandoc renders standalone HTML and headless Chrome prints it to PDF.

Usage: python3 scripts/story_pdf.py [OUT.pdf]   (default: build/story.pdf)
Needs: pandoc, and google-chrome or chromium on PATH (or $CHROME).
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SVG_NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", SVG_NS)

CSS = """
@page { size: Letter; margin: 0.8in 0.85in; }
body { font-family: Georgia, 'Times New Roman', serif; font-size: 11.5pt;
       line-height: 1.5; color: #1f1f1f; max-width: none; }
h1 { font-size: 24pt; line-height: 1.2; margin: 0 0 0.4em; }
h2 { font-size: 15pt; margin-top: 1.4em; break-after: avoid; }
h3 { font-size: 12.5pt; break-after: avoid; }
img { max-width: 100%; display: block; margin: 0.6em auto 0.2em; }
figure { margin: 1em 0; break-inside: avoid; }
figcaption { font-style: italic; font-size: 10pt; color: #5f5e5a; }
code, pre { font-family: Menlo, Consolas, monospace; font-size: 9.5pt; }
pre { background: #f6f6f4; padding: 0.6em 0.8em; white-space: pre-wrap;
      break-inside: avoid; }
table { border-collapse: collapse; font-size: 10pt; margin: 0.8em 0; }
th, td { border-bottom: 1px solid #ddd; padding: 0.3em 0.6em; text-align: left; }
blockquote { color: #444; border-left: 3px solid #ccc; margin-left: 0;
             padding-left: 1em; }
"""


def freeze_svg(src: Path, dst: Path) -> None:
    """Write src to dst with each <animate> applied at its last value."""
    tree = ET.parse(src)
    parents = {c: p for p in tree.iter() for c in p}
    for anim in list(tree.iter(f"{{{SVG_NS}}}animate")):
        parent = parents[anim]
        attr = anim.get("attributeName")
        values = anim.get("values")
        final = values.split(";")[-1].strip() if values else anim.get("to")
        if attr and final is not None:
            parent.set(attr, final)
        parent.remove(anim)
    for s in list(tree.iter(f"{{{SVG_NS}}}set")):
        parent = parents[s]
        if s.get("attributeName") and s.get("to") is not None:
            parent.set(s.get("attributeName"), s.get("to"))
        parent.remove(s)
    tree.write(dst, xml_declaration=False, encoding="unicode")


def find_chrome() -> str:
    for name in (os.environ.get("CHROME"), "google-chrome", "chromium",
                 "chromium-browser", "google-chrome-stable"):
        if name and shutil.which(name):
            return shutil.which(name)
    sys.exit("story_pdf: no Chrome/Chromium found (set $CHROME)")


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "build" / "story.pdf")
    out = out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "docs"
        shutil.copytree(DOCS, work)

        for svg in work.rglob("*.svg"):
            if "<animate" in svg.read_text() or "<set " in svg.read_text():
                freeze_svg(svg, svg)

        md = (work / "story.md").read_text()
        still = work / "demo" / "demo-final.png"
        if not still.exists():
            sys.exit("story_pdf: docs/demo/demo-final.png is missing")
        md = md.replace("(demo/demo.gif)", "(demo/demo-final.png)")
        if re.search(r"\]\([^)]*\.gif\)", md):
            sys.exit("story_pdf: story.md links a GIF with no still; add one")
        (work / "story-pdf.md").write_text(md)

        (work / "story.css").write_text(CSS)
        html = work / "story.html"
        subprocess.run(
            ["pandoc", "story-pdf.md", "-s", "-o", str(html),
             "--css", "story.css", "--metadata", "pagetitle=story",
             "--resource-path", "."],
            cwd=work, check=True)

        subprocess.run(
            [find_chrome(), "--headless", "--no-sandbox", "--disable-gpu",
             "--no-pdf-header-footer", f"--print-to-pdf={out}",
             html.as_uri()],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"wrote {out}")


if __name__ == "__main__":
    main()
