"""Approximate ClaMP-style feature extraction from a real PE file, by static parsing only (pefile).
Nothing is executed. CLI:  python src/pe_extract.py <file>   -> JSON on stdout.

The ClaMP feature definitions are not fully documented, so each feature gets a provenance:
  extracted    raw header value or entropy, read directly
  inferred     bit flags whose bit order was inferred from the dataset (FH_char*, OH_DLLchar*)
  best guess   derived 0/1 flags whose exact ClaMP definition is unknown
  default      not checked (packer signatures are not available)
Verdicts on uploaded files are therefore indicative only."""
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

# FILE_HEADER.Characteristics flags in PE-spec order (FH_char0..14) and optional-header DLL flags
# (OH_DLLchar0..10). Order inferred from the dataset (e.g. FH_char7 ~ 1.0 = 32-bit machine, FH_char12 = DLL;
# OH_DLLchar0 grows with linker version = DYNAMIC_BASE). OH_DLLchar8-10 are rarely or never set.
FH_FLAGS = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000]
OH_FLAGS = [0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x2000, 0x8000, 0x1000, 0x4000, 0x20]
STANDARD_SECTIONS = {".text", ".data", ".rdata", ".idata", ".edata", ".rsrc", ".reloc", ".bss", ".pdata", ".tls",
                     ".crt", ".didat", ".sdata", ".xdata", ".debug", ".gfids", ".00cfg", ".textbss", ".orpc",
                     ".itext", ".code", ".init", "code", "data", "bss", "init", "page"}
RAW_OH = ["MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode", "SizeOfInitializedData",
          "SizeOfUninitializedData", "AddressOfEntryPoint", "BaseOfCode", "BaseOfData",
          "MajorOperatingSystemVersion", "MinorOperatingSystemVersion", "MajorImageVersion", "MinorImageVersion",
          "MajorSubsystemVersion", "MinorSubsystemVersion", "CheckSum", "Subsystem", "SizeOfStackReserve",
          "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit"]
RAW_DOS = ["e_cblp", "e_cp", "e_cparhdr", "e_maxalloc", "e_sp", "e_lfanew"]
MAX_BYTES = 100_000_000


def entropy(b):
    if not b:
        return 0.0
    counts = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(b)
    return float(-(p * np.log2(p)).sum())


def extract(path):
    import pefile  # imported here so the dashboard only needs pefile in the subprocess
    raw = Path(path).read_bytes()
    pe = pefile.PE(data=raw, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                                           pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    oh, fh, dos = pe.OPTIONAL_HEADER, pe.FILE_HEADER, pe.DOS_HEADER
    f, prov = {}, {}

    def put(name, value, how):
        f[name], prov[name] = value, how

    for k in RAW_DOS:
        put(k, int(getattr(dos, k)), "extracted")
    put("NumberOfSections", int(fh.NumberOfSections), "extracted")
    year = datetime.fromtimestamp(fh.TimeDateStamp, timezone.utc).year
    put("CreationYear", int(1993 <= year <= datetime.now().year), "best guess")
    for i, bit in enumerate(FH_FLAGS):
        put(f"FH_char{i}", int(bool(fh.Characteristics & bit)), "inferred")
    for k in RAW_OH:
        put(k, int(getattr(oh, k, 0)), "extracted")  # BaseOfData is absent in PE32+ -> 0
    put("ImageBase", int(oh.ImageBase % 0x10000 == 0), "best guess")
    put("SizeOfImage", int(oh.SectionAlignment > 0 and oh.SizeOfImage % oh.SectionAlignment == 0), "best guess")
    put("SizeOfHeaders", int(oh.FileAlignment > 0 and oh.SizeOfHeaders % oh.FileAlignment == 0), "best guess")
    put("LoaderFlags", int(oh.LoaderFlags == 0), "best guess")
    for i, bit in enumerate(OH_FLAGS):
        put(f"OH_DLLchar{i}", int(bool(oh.DllCharacteristics & bit)), "inferred")

    secs, ent = [], {}
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin1")
        e = entropy(s.get_data())
        ent.setdefault(name.lower(), e)
        fl = s.Characteristics
        secs.append({"name": name, "virtual_size": int(s.Misc_VirtualSize), "raw_size": int(s.SizeOfRawData),
                     "entropy": round(e, 3),
                     "flags": "".join(c for c, m in (("R", 0x40000000), ("W", 0x80000000), ("X", 0x20000000)) if fl & m)})
    sus = sum(1 for s in secs if s["name"].lower() not in STANDARD_SECTIONS)
    put("sus_sections", sus, "best guess")
    put("non_sus_sections", len(secs) - sus, "best guess")
    put("packer", 0, "default")
    put("packer_type", "NoPacker", "default")
    put("E_text", float(ent.get(".text", 0.0)), "extracted")
    put("E_data", float(ent.get(".data", 0.0)), "extracted")
    put("filesize", len(raw), "extracted")
    put("E_file", float(entropy(raw)), "extracted")
    has_version = any(getattr(e, "id", None) == 16 for e in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None),
                                                                      "entries", []))
    put("fileinfo", int(has_version), "best guess")

    imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    info = {"pe_format": "PE32+" if oh.Magic == 0x20B else "PE32", "file_size": len(raw),
            "sections": secs, "imported_dlls": len(imports),
            "imported_functions": sum(len(d.imports) for d in imports),
            "is_dll": bool(fh.Characteristics & 0x2000), "timestamp_year": year}
    return {"ok": True, "features": f, "provenance": prov, "info": info}


def extract_safely(data, timeout=30):
    """Parse uploaded bytes in a separate process with a timeout. Never executes the file."""
    if len(data) > MAX_BYTES:
        return {"ok": False, "error": f"File too large (limit {MAX_BYTES // 1_000_000} MB)."}
    if data[:2] != b"MZ":
        return {"ok": False, "error": "Not a Windows PE file (missing MZ header)."}
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "sample.bin"
        p.write_bytes(data)
        try:
            r = subprocess.run([sys.executable, str(Path(__file__).resolve()), str(p)], capture_output=True,
                               text=True, timeout=timeout, cwd=tmp)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"Parsing timed out after {timeout}s."}
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        return {"ok": False, "error": "Could not parse this file as a PE image."}


if __name__ == "__main__":
    try:
        out = extract(sys.argv[1])
    except Exception as e:
        out = {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}
    print(json.dumps(out))
