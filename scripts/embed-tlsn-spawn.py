#!/usr/bin/env python3
"""Embed web-spawn's recursive worker module into the generated WASM wrapper."""

import json
import re
import sys
from pathlib import Path


pkg = Path(sys.argv[1])
wrapper_path = pkg / "tlsn_wasm.js"
spawn_path = pkg / "spawn.js"
wrapper = wrapper_path.read_text()
spawn = spawn_path.read_text()

worker_url = re.compile(
    r"const workerUrl = new URL\(\s*['\"]\./spawn\.js['\"],\s*import\.meta\.url\s*\);"
)
blob_spawn, replacements = worker_url.subn("const workerUrl = import.meta.url;", spawn)
if replacements != 2:
    raise SystemExit(f"expected two spawn worker URLs, found {replacements}")
if spawn.count("../../../tlsn_wasm.js") != 2:
    raise SystemExit("expected two TLSNotary wrapper imports in spawn.js")
blob_spawn = blob_spawn.replace("../../../tlsn_wasm.js", "__LIBID_TLSN_ROOT__")

helper_start = spawn.find("export async function startSpawnerWorker")
if helper_start < 0:
    raise SystemExit("startSpawnerWorker export not found")
helper = spawn[helper_start:].replace(
    "export async function", "async function", 1
)
replacement = (
    f"const workerSource = {json.dumps(blob_spawn)}\n"
    '        .replaceAll("__LIBID_TLSN_ROOT__", import.meta.url);\n'
    '    const workerUrl = URL.createObjectURL(new Blob([workerSource], '
    '{ type: "text/javascript" }));'
)
helper, replacements = worker_url.subn(lambda _: replacement, helper)
if replacements != 1:
    raise SystemExit(f"expected one startSpawnerWorker URL, found {replacements}")

spawn_import = re.compile(
    r"^import \{ startSpawnerWorker \} from "
    r"['\"]\./snippets/web-spawn-[^/'\"]+/js/spawn\.js['\"];\r?\n",
    re.MULTILINE,
)
wrapper, replacements = spawn_import.subn(lambda _: helper + "\n", wrapper)
if replacements != 1:
    raise SystemExit(f"expected one web-spawn import, found {replacements}")

wrapper_path.write_text(wrapper)
spawn_path.unlink()
