#!/usr/bin/env python3
"""Builds target/web/psm.html, the browser app as one self-contained file.

The WebAssembly core (base64), its JavaScript glue, the app script and the
style sheet are all inlined. The Content-Security-Policy allows exactly those
inline scripts and styles, by hash, and nothing else, so the page can neither
load nor send anything over the network. It works offline from a local file,
on a phone or a desktop.
"""

import base64
import hashlib
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "crates" / "web" / "ui"
OUT = ROOT / "target" / "web"
WASM = ROOT / "target" / "wasm32-unknown-unknown" / "wasm" / "psm_web.wasm"


def run(*args: str) -> str:
    return subprocess.run(
        args, cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True
    ).stdout


def csp_hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("ascii")).digest()
    return f"'sha256-{base64.b64encode(digest).decode('ascii')}'"


def main() -> None:
    run(
        "cargo",
        "build",
        "--locked",
        "--profile",
        "wasm",
        "--target",
        "wasm32-unknown-unknown",
        "--package",
        "psm-web",
    )
    pkg = OUT / "pkg"
    run(
        "wasm-bindgen",
        "--target",
        "no-modules",
        "--no-typescript",
        "--remove-name-section",
        "--remove-producers-section",
        "--out-dir",
        str(pkg),
        str(WASM),
    )
    version = run("cargo", "pkgid", "--package", "psm-web").strip().rsplit("@")[-1]

    wasm = base64.b64encode((pkg / "psm_web_bg.wasm").read_bytes()).decode("ascii")
    core = (pkg / "psm_web.js").read_text(encoding="ascii")
    core += f'const PSM_WASM = "{wasm}";\n'
    app = (UI / "app.js").read_text(encoding="ascii")
    style = (UI / "style.css").read_text(encoding="ascii")
    for name, script in (("core", core), ("app", app)):
        if "</script" in script.lower():
            msg = f"the {name} script contains </script"
            raise SystemExit(msg)

    csp = "; ".join(
        [
            "default-src 'none'",
            f"script-src {csp_hash(core)} {csp_hash(app)} 'wasm-unsafe-eval'",
            f"style-src {csp_hash(style)}",
            "base-uri 'none'",
            "form-action 'none'",
        ]
    )
    values = {
        "CSP": csp,
        "STYLE": style,
        "CORE": core,
        "APP": app,
        "VERSION": version,
    }
    template = (UI / "index.html").read_text(encoding="ascii")
    html = re.sub(r"\{\{(\w+)\}\}", lambda m: values[m.group(1)], template)
    out = OUT / "psm.html"
    out.write_text(html, encoding="ascii", newline="\n")
    print(out.relative_to(ROOT))


if __name__ == "__main__":
    main()
