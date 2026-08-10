#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CLEAN_WAD_SHA256 = "6926561f8e7ed8a58f0433f577f4b3f2136a0c3e719cd97f838ae6f1202ec6e6"
CLEAN_APP_SHA1 = "763d4d3d0713e4d10e44540ccfa3255e19f28af7"
H63_WAD_SHA256 = "de70a0d822bfc822c8f0f29fc3ef185a2a5bd63cefc958d7b6b075e579e806e9"
H63_APP_SHA1 = "149ce67ae3fd25d80820e11c7eb4eb1886be66ce"
PATCH_NAME = "oot-vc-usa-h63.ips"


def digest(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_wad_tools(path: Path):
    path = path.resolve()
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("wad_tools_release", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in ("extract", "repack", "parse_wad", "content_records"):
        if not hasattr(module, name):
            raise RuntimeError(f"wad_tools.py is missing required function {name}")
    return module


def find_content1(folder: Path) -> Path:
    exact = folder / "00000001_00000008.app"
    if exact.is_file():
        return exact
    legacy = folder / "00000001.app"
    if legacy.is_file():
        return legacy
    candidates = sorted(folder.glob("00000001_*.app"))
    if len(candidates) == 1:
        return candidates[0]
    raise RuntimeError(f"Could not uniquely find content index 1 under {folder}")


def u24(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError(f"IPS 24-bit value out of range: {value:#x}")
    return value.to_bytes(3, "big")


def make_ips(source: bytes, target: bytes) -> bytes:
    """Create a deterministic standard IPS patch without RLE records."""
    records = bytearray(b"PATCH")
    limit = max(len(source), len(target))
    i = 0

    def different(pos: int) -> bool:
        left = source[pos] if pos < len(source) else None
        right = target[pos] if pos < len(target) else None
        return left != right

    while i < limit:
        if not different(i):
            i += 1
            continue
        start = i
        # Stop at the first equal byte. Split long records to the IPS 16-bit size limit.
        while i < limit and different(i) and i - start < 0xFFFF:
            i += 1
        payload = target[start:min(i, len(target))]
        if payload:
            records += u24(start)
            records += len(payload).to_bytes(2, "big")
            records += payload
        # If target ended before source, there is nothing to write. EOF size truncates it.
        if i == start:
            i += 1

    records += b"EOF"
    if len(source) != len(target):
        records += u24(len(target))
    return bytes(records)


def apply_ips(source: bytes, patch: bytes) -> bytes:
    if not patch.startswith(b"PATCH"):
        raise RuntimeError("Generated patch lost IPS header")
    out = bytearray(source)
    p = 5
    while True:
        if p + 3 > len(patch):
            raise RuntimeError("Generated IPS is truncated")
        if patch[p:p + 3] == b"EOF":
            p += 3
            break
        offset = int.from_bytes(patch[p:p + 3], "big")
        p += 3
        size = int.from_bytes(patch[p:p + 2], "big")
        p += 2
        if size == 0:
            run = int.from_bytes(patch[p:p + 2], "big")
            value = patch[p + 2]
            p += 3
            data = bytes([value]) * run
        else:
            data = patch[p:p + size]
            p += size
        end = offset + len(data)
        if end > len(out):
            out.extend(b"\0" * (end - len(out)))
        out[offset:end] = data
    if len(patch) - p == 3:
        final_size = int.from_bytes(patch[p:p + 3], "big")
        if final_size < len(out):
            del out[final_size:]
        elif final_size > len(out):
            out.extend(b"\0" * (final_size - len(out)))
    elif p != len(patch):
        raise RuntimeError("Unexpected generated IPS trailer")
    return bytes(out)


def copy_tree_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def write_run_bat(path: Path) -> None:
    path.write_text(
        "@echo off\r\n"
        "setlocal\r\n"
        "where py >nul 2>nul && (py -3 \"%~dp0oot_vc_h63_patcher.py\" & exit /b %errorlevel%)\r\n"
        "where python >nul 2>nul && (python \"%~dp0oot_vc_h63_patcher.py\" & exit /b %errorlevel%)\r\n"
        "echo Python 3 is required for this source package. Use the prebuilt EXE release if available.\r\n"
        "pause\r\n"
        "exit /b 2\r\n",
        encoding="utf-8",
    )


def zip_dir(source: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for file in sorted(source.rglob("*")):
            if file.is_file():
                z.write(file, file.relative_to(source.parent))


def verify_tmd(module, wad: Path, outdir: Path) -> int:
    module.extract(wad, outdir)
    blob = wad.read_bytes()
    sections = module.parse_wad(blob)
    tmd_off, tmd_size = sections["tmd"]
    tmd = blob[tmd_off:tmd_off + tmd_size]
    count = 0
    for cid, index, _kind, size, expected_sha, _ in module.content_records(tmd):
        p = outdir / f"{index:08x}_{cid:08x}.app"
        if not p.exists():
            p = outdir / f"{index:08x}.app"
        data = p.read_bytes()
        if len(data) != size or hashlib.sha1(data).digest() != expected_sha:
            raise RuntimeError(f"TMD verification failed for content index {index}")
        count += 1
    if count != 7:
        raise RuntimeError(f"Expected 7 contents, found {count}")
    return count


def optional_build_exe(standalone_dir: Path, patch_path: Path) -> Path | None:
    try:
        import PyInstaller.__main__  # type: ignore
    except ImportError:
        return None

    command = [
        str(standalone_dir / "oot_vc_h63_patcher.py"),
        "--onefile",
        "--windowed",
        "--clean",
        "--name=OoTVCFixPatcher-H63",
        f"--distpath={standalone_dir / 'exe'}",
        f"--workpath={standalone_dir / '.pyinstaller-work'}",
        f"--specpath={standalone_dir / '.pyinstaller-spec'}",
        f"--add-data={patch_path}{';' if sys.platform.startswith('win') else ':'}patches",
        "--hidden-import=Crypto.Cipher.AES",
    ]
    PyInstaller.__main__.run(command)
    exe = standalone_dir / "exe" / ("OoTVCFixPatcher-H63.exe" if sys.platform.startswith("win") else "OoTVCFixPatcher-H63")
    return exe if exe.exists() else None


def main() -> int:
    ap = argparse.ArgumentParser(description="Build public H63 standalone + Patcher64+ release packages")
    ap.add_argument("--clean-wad", type=Path, required=True)
    ap.add_argument("--h63-wad", type=Path, required=True)
    ap.add_argument("--wad-tools", type=Path, required=True, help="Known-good project wad_tools.py")
    ap.add_argument("--output", type=Path, default=Path("dist"))
    ap.add_argument("--patcher64-dir", type=Path, help="Optional Patcher64Plus-Tool checkout used for git apply --check")
    ap.add_argument("--build-exe", action="store_true", help="Run PyInstaller if installed")
    args = ap.parse_args()

    clean_wad = args.clean_wad.resolve()
    h63_wad = args.h63_wad.resolve()
    out = args.output.resolve()
    if digest(clean_wad, "sha256") != CLEAN_WAD_SHA256:
        raise SystemExit("Clean WAD SHA-256 mismatch")
    if digest(h63_wad, "sha256") != H63_WAD_SHA256:
        raise SystemExit("H63 reference WAD SHA-256 mismatch")

    wad = load_wad_tools(args.wad_tools)
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)

    with tempfile.TemporaryDirectory(prefix="oot-vc-release-") as td_name:
        td = Path(td_name)
        clean_dir, h63_dir = td / "clean", td / "h63"
        wad.extract(clean_wad, clean_dir)
        wad.extract(h63_wad, h63_dir)
        clean_app = find_content1(clean_dir).read_bytes()
        h63_app = find_content1(h63_dir).read_bytes()

        if hashlib.sha1(clean_app).hexdigest() != CLEAN_APP_SHA1:
            raise SystemExit("Clean content1.app SHA-1 mismatch")
        if hashlib.sha1(h63_app).hexdigest() != H63_APP_SHA1:
            raise SystemExit("H63 content1.app SHA-1 mismatch")

        ips = make_ips(clean_app, h63_app)
        if apply_ips(clean_app, ips) != h63_app:
            raise SystemExit("Generated IPS did not reproduce H63 content1.app byte-for-byte")

        # Verify the delta through the exact WAD repacker as an additional release gate.
        patched_app = td / "patched.app"
        patched_app.write_bytes(apply_ips(clean_app, ips))
        roundtrip_wad = td / "roundtrip.wad"
        wad.repack(clean_wad, {1: patched_app}, roundtrip_wad)
        verify_tmd(wad, roundtrip_wad, td / "roundtrip-verify")
        if digest(roundtrip_wad, "sha256") != H63_WAD_SHA256:
            raise SystemExit("IPS + repack did not reproduce the exact H63 WAD")

        standalone = out / "OoT-VC-H63-Standalone-Patcher"
        (standalone / "patches").mkdir(parents=True)
        copy_tree_file(ROOT / "standalone" / "oot_vc_h63_patcher.py", standalone / "oot_vc_h63_patcher.py")
        copy_tree_file(args.wad_tools.resolve(), standalone / "wad_tools.py")
        (standalone / "patches" / PATCH_NAME).write_bytes(ips)
        write_run_bat(standalone / "Run Patcher.bat")
        copy_tree_file(ROOT / "standalone" / "README.md", standalone / "README.md")

        exe_path = optional_build_exe(standalone, standalone / "patches" / PATCH_NAME) if args.build_exe else None

        integration = out / "Patcher64Plus-H63-Integration"
        game_patch_dir = integration / "Files" / "Games" / "Ocarina of Time" / "AppFile01"
        game_patch_dir.mkdir(parents=True)
        (game_patch_dir / PATCH_NAME).write_bytes(ips)
        copy_tree_file(ROOT / "patcher64plus" / "Patcher64Plus-H63-integration.patch", integration / "Patcher64Plus-H63-integration.patch")
        copy_tree_file(ROOT / "patcher64plus" / "README.md", integration / "README.md")

        if args.patcher64_dir:
            subprocess.run(
                ["git", "-C", str(args.patcher64_dir.resolve()), "apply", "--check", str(ROOT / "patcher64plus" / "Patcher64Plus-H63-integration.patch")],
                check=True,
            )

        manifest = {
            "clean_wad_sha256": CLEAN_WAD_SHA256,
            "clean_app_sha1": CLEAN_APP_SHA1,
            "h63_app_sha1": H63_APP_SHA1,
            "h63_wad_sha256": H63_WAD_SHA256,
            "ips_sha256": hashlib.sha256(ips).hexdigest(),
            "ips_size": len(ips),
            "ips_roundtrip": "PASS",
            "wad_roundtrip": "PASS",
            "tmd_contents": "7/7 PASS",
            "standalone_exe_built": bool(exe_path),
        }
        (out / "RELEASE-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        copy_tree_file(out / "RELEASE-MANIFEST.json", standalone / "RELEASE-MANIFEST.json")
        copy_tree_file(out / "RELEASE-MANIFEST.json", integration / "RELEASE-MANIFEST.json")

    standalone_zip = out / "OoT-VC-H63-Standalone-Patcher.zip"
    integration_zip = out / "Patcher64Plus-H63-Integration.zip"
    zip_dir(out / "OoT-VC-H63-Standalone-Patcher", standalone_zip)
    zip_dir(out / "Patcher64Plus-H63-Integration", integration_zip)

    print("PASS: clean and H63 private inputs verified")
    print("PASS: IPS reproduces H63 content1.app exactly")
    print("PASS: IPS + WAD repack reproduces H63 WAD exactly")
    print("PASS: 7/7 TMD contents verified")
    print("Standalone:", standalone_zip)
    print("Patcher64+:", integration_zip)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
