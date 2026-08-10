#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import queue
import shutil
import sys
import tempfile
import threading
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from wad_tools import content_records, extract, parse_wad, repack

APP_TITLE = "Ocarina of Time Wii VC Fix Patcher"
VERSION = "H63"

EXPECTED_CLEAN_WAD_SHA256 = "6926561f8e7ed8a58f0433f577f4b3f2136a0c3e719cd97f838ae6f1202ec6e6"
EXPECTED_CLEAN_APP_SHA1 = "763d4d3d0713e4d10e44540ccfa3255e19f28af7"
EXPECTED_H63_APP_SHA1 = "149ce67ae3fd25d80820e11c7eb4eb1886be66ce"
EXPECTED_H63_WAD_SHA256 = "de70a0d822bfc822c8f0f29fc3ef185a2a5bd63cefc958d7b6b075e579e806e9"
EXPECTED_CONTENT_COUNT = 7

FEATURES = (
    "Sharp live-GX N64-style three-point filtering",
    "Test 10 reflection / texgen correction",
    "ESS analog response V3.3",
    "GameCube + Wii/Classic rumble",
    "Stone of Agony rumble through the N64 Rumble Pak path",
    "v0.81 exact-FIFO C3T3 batching",
    "v0.82 lazy depth conversion",
    "v0.83 demand-armed depth snapshots",
)


def resource_root() -> Path:
    if hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parent


def digest(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _u24(data: bytes, offset: int) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def _u16(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def apply_ips(source: bytes, patch: bytes) -> bytes:
    """Apply a standard IPS patch, including optional EOF truncate/extend size."""
    if not patch.startswith(b"PATCH"):
        raise ValueError("Patch file is not an IPS patch")

    out = bytearray(source)
    pos = 5
    while True:
        if pos + 3 > len(patch):
            raise ValueError("Truncated IPS patch")
        if patch[pos : pos + 3] == b"EOF":
            pos += 3
            break

        offset = _u24(patch, pos)
        pos += 3
        if pos + 2 > len(patch):
            raise ValueError("Truncated IPS record")
        size = _u16(patch, pos)
        pos += 2

        if size == 0:
            if pos + 3 > len(patch):
                raise ValueError("Truncated IPS RLE record")
            run = _u16(patch, pos)
            value = patch[pos + 2]
            pos += 3
            payload = bytes([value]) * run
        else:
            if pos + size > len(patch):
                raise ValueError("Truncated IPS data record")
            payload = patch[pos : pos + size]
            pos += size

        end = offset + len(payload)
        if end > len(out):
            out.extend(b"\x00" * (end - len(out)))
        out[offset:end] = payload

    # IPS permits a three-byte final output size after EOF.
    if len(patch) - pos == 3:
        final_size = _u24(patch, pos)
        if final_size < len(out):
            del out[final_size:]
        elif final_size > len(out):
            out.extend(b"\x00" * (final_size - len(out)))
    elif pos != len(patch):
        raise ValueError("Unexpected bytes after IPS EOF")

    return bytes(out)


def find_content1(extract_dir: Path) -> Path:
    exact = extract_dir / "00000001_00000008.app"
    if exact.is_file():
        return exact
    legacy = extract_dir / "00000001.app"
    if legacy.is_file():
        return legacy
    candidates = sorted(extract_dir.glob("00000001_*.app"))
    if len(candidates) == 1:
        return candidates[0]
    raise RuntimeError("Could not uniquely locate extracted content index 1")


def verify_tmd_contents(wad: Path, extract_dir: Path) -> int:
    extract(wad, extract_dir)
    blob = wad.read_bytes()
    sections = parse_wad(blob)
    tmd_offset, tmd_size = sections["tmd"]
    tmd = blob[tmd_offset : tmd_offset + tmd_size]

    count = 0
    for cid, index, _kind, size, expected_sha1, _record_offset in content_records(tmd):
        candidate = extract_dir / f"{index:08x}_{cid:08x}.app"
        if not candidate.is_file():
            # Compatibility with unpackers that name content only by index.
            candidate = extract_dir / f"{index:08x}.app"
        if not candidate.is_file():
            raise RuntimeError(f"Missing decrypted content index {index}")
        payload = candidate.read_bytes()
        if len(payload) != size:
            raise RuntimeError(
                f"Content index {index} size mismatch: got {len(payload)}, expected {size}"
            )
        if hashlib.sha1(payload).digest() != expected_sha1:
            raise RuntimeError(f"Content index {index} failed its TMD SHA-1")
        count += 1

    if count != EXPECTED_CONTENT_COUNT:
        raise RuntimeError(f"Expected {EXPECTED_CONTENT_COUNT} TMD contents, found {count}")
    return count


def patch_wad(input_wad: Path, output_wad: Path, log) -> None:
    input_wad = input_wad.resolve()
    output_wad = output_wad.resolve()
    patch_path = resource_root() / "patches" / "oot-vc-usa-h63.ips"

    if not input_wad.is_file():
        raise RuntimeError("Input WAD does not exist")
    if not patch_path.is_file():
        raise RuntimeError(f"Missing bundled H63 patch: {patch_path}")
    if input_wad == output_wad:
        raise RuntimeError("Input and output paths must be different")

    log("Verifying original NACE WAD...")
    clean_wad_hash = digest(input_wad, "sha256")
    if clean_wad_hash != EXPECTED_CLEAN_WAD_SHA256:
        raise RuntimeError(
            "Unsupported WAD. This patcher accepts only the exact clean North American "
            f"NACE release.\nFound SHA-256: {clean_wad_hash}"
        )
    log("OK: clean USA/NACE WAD SHA-256")

    with tempfile.TemporaryDirectory(prefix="oot-vc-h63-") as temp_name:
        temp = Path(temp_name)
        original_extract = temp / "original"
        verify_extract = temp / "verify"

        log("Extracting WAD...")
        extract(input_wad, original_extract)
        clean_app = find_content1(original_extract)

        clean_app_hash = hashlib.sha1(clean_app.read_bytes()).hexdigest()
        if clean_app_hash != EXPECTED_CLEAN_APP_SHA1:
            raise RuntimeError(
                "The WAD container matched, but content1.app did not match the supported "
                f"emulator. Found SHA-1: {clean_app_hash}"
            )
        log("OK: clean content1.app SHA-1")

        log("Applying H63 emulator patch...")
        patched_bytes = apply_ips(clean_app.read_bytes(), patch_path.read_bytes())
        patched_hash = hashlib.sha1(patched_bytes).hexdigest()
        if patched_hash != EXPECTED_H63_APP_SHA1:
            raise RuntimeError(
                "H63 IPS output did not verify. The patch file may be corrupt. "
                f"Found SHA-1: {patched_hash}"
            )
        log("OK: patched H63 content1.app SHA-1")

        patched_app = temp / "H63-content1.app"
        patched_app.write_bytes(patched_bytes)

        output_wad.parent.mkdir(parents=True, exist_ok=True)
        temp_output = temp / "output.wad"
        log("Rebuilding WAD and updating TMD hashes...")
        repack(input_wad, {1: patched_app}, temp_output)

        log("Decrypting rebuilt WAD for integrity verification...")
        count = verify_tmd_contents(temp_output, verify_extract)
        log(f"OK: {count}/{EXPECTED_CONTENT_COUNT} TMD content hashes")

        roundtrip_app = find_content1(verify_extract)
        if hashlib.sha1(roundtrip_app.read_bytes()).hexdigest() != EXPECTED_H63_APP_SHA1:
            raise RuntimeError("Rebuilt WAD content1.app changed after encrypt/decrypt round-trip")

        final_hash = digest(temp_output, "sha256")
        if final_hash != EXPECTED_H63_WAD_SHA256:
            raise RuntimeError(
                "Rebuilt WAD is internally valid but does not match the tested H63 reference. "
                f"Found SHA-256: {final_hash}"
            )
        log("OK: exact H63 WAD SHA-256")

        shutil.copyfile(temp_output, output_wad)

    log(f"Complete: {output_wad}")


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"{APP_TITLE} — {VERSION}")
        self.root.minsize(720, 580)
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()

        self.input_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Select the original USA/NACE WAD.")

        outer = ttk.Frame(root, padding=16)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text=APP_TITLE, font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(
            outer,
            text="Applies the hardware-safe H63 emulator fixes to your own original North American OoT Wii VC WAD.",
            wraplength=680,
        ).pack(anchor="w", pady=(2, 14))

        paths = ttk.LabelFrame(outer, text="WAD files", padding=10)
        paths.pack(fill="x")
        self._path_row(paths, "Input WAD", self.input_var, self.choose_input, 0)
        self._path_row(paths, "Output WAD", self.output_var, self.choose_output, 1)

        feature_box = ttk.LabelFrame(outer, text="Included fixes", padding=10)
        feature_box.pack(fill="x", pady=12)
        for feature in FEATURES:
            ttk.Label(feature_box, text=f"✓  {feature}").pack(anchor="w")

        self.patch_button = ttk.Button(outer, text="PATCH WAD", command=self.start_patch)
        self.patch_button.pack(fill="x", ipady=7, pady=(0, 8))

        ttk.Label(outer, textvariable=self.status_var).pack(anchor="w")
        self.log_box = tk.Text(outer, height=10, state="disabled", wrap="word")
        self.log_box.pack(fill="both", expand=True, pady=(6, 0))

        self.root.after(100, self.poll_events)

    def _path_row(self, parent, label, var, callback, row: int) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(parent, textvariable=var).grid(row=row, column=1, sticky="ew", pady=4)
        ttk.Button(parent, text="Browse...", command=callback).grid(row=row, column=2, padx=(8, 0), pady=4)
        parent.columnconfigure(1, weight=1)

    def choose_input(self) -> None:
        path = filedialog.askopenfilename(title="Select original OoT USA Wii VC WAD", filetypes=[("Wii WAD", "*.wad"), ("All files", "*.*")])
        if not path:
            return
        self.input_var.set(path)
        src = Path(path)
        self.output_var.set(str(src.with_name(src.stem + " - VC Fix H63.wad")))

    def choose_output(self) -> None:
        path = filedialog.asksaveasfilename(title="Save patched WAD", defaultextension=".wad", filetypes=[("Wii WAD", "*.wad")])
        if path:
            self.output_var.set(path)

    def append_log(self, text: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")
        self.status_var.set(text)

    def start_patch(self) -> None:
        try:
            input_wad = Path(self.input_var.get())
            output_wad = Path(self.output_var.get())
        except Exception:
            messagebox.showerror(APP_TITLE, "Choose valid input and output paths.")
            return
        if not self.input_var.get() or not self.output_var.get():
            messagebox.showerror(APP_TITLE, "Choose both the input WAD and output WAD.")
            return

        self.patch_button.configure(state="disabled")
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

        def worker() -> None:
            try:
                patch_wad(input_wad, output_wad, lambda msg: self.events.put(("log", msg)))
                self.events.put(("done", output_wad))
            except Exception as exc:
                self.events.put(("error", (str(exc), traceback.format_exc())))

        threading.Thread(target=worker, daemon=True).start()

    def poll_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self.append_log(str(payload))
                elif kind == "done":
                    self.patch_button.configure(state="normal")
                    messagebox.showinfo(APP_TITLE, f"Patch complete.\n\n{payload}")
                elif kind == "error":
                    self.patch_button.configure(state="normal")
                    message, trace = payload
                    self.append_log("FAILED: " + message)
                    self.append_log(trace)
                    messagebox.showerror(APP_TITLE, message)
        except queue.Empty:
            pass
        self.root.after(100, self.poll_events)


def main() -> int:
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
