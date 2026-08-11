from __future__ import annotations

import argparse
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
VERSION = "H64"
CLEAN_WAD_SHA256 = "6926561f8e7ed8a58f0433f577f4b3f2136a0c3e719cd97f838ae6f1202ec6e6"
CLEAN_APP_SHA1 = "763d4d3d0713e4d10e44540ccfa3255e19f28af7"
H64_WAD_SHA256 = "caf4a1c75744c394799da4289a9d86dd5ef42b83dbe9e5e9e656db935dd38691"
H64_APP_SHA1 = "4b06f6454b96dbb6986d69622f163fb8e30a548b"
PATCH_NAME = "oot-vc-usa-h64-reset-safe-gki.ips"
PATCH_SHA256 = "257033cc9fafcd37676ec519c8d10b155f9823c11e2459f6bcf40dc4bf4619f9"
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
    "H64 reset-safe Bluetooth GKI allocator guards",
)


def resource_root() -> Path:
    if hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parent


def patch_path() -> Path:
    return resource_root() / "patches" / PATCH_NAME


def digest_file(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def find_content1(folder: Path) -> Path:
    exact = folder / "00000001_00000008.app"
    if exact.is_file():
        return exact
    matches = sorted(folder.glob("00000001_*.app"))
    if len(matches) == 1:
        return matches[0]
    raise RuntimeError("Could not uniquely locate Wii VC content index 1")


def verify_embedded_patch() -> bytes:
    path = patch_path()
    if not path.is_file():
        raise RuntimeError("The embedded H64 IPS payload is missing from this patcher build.")
    payload = path.read_bytes()
    found = hashlib.sha256(payload).hexdigest()
    if found != PATCH_SHA256:
        raise RuntimeError(
            "The embedded H64 IPS payload failed its integrity check.\n"
            f"Expected SHA-256: {PATCH_SHA256}\nFound SHA-256:    {found}"
        )
    if not payload.startswith(b"PATCH") or b"EOF" not in payload:
        raise RuntimeError("The embedded H64 payload is not a valid IPS patch.")
    return payload


def apply_ips(source: bytes, patch: bytes) -> bytes:
    if not patch.startswith(b"PATCH"):
        raise RuntimeError("Invalid IPS header")
    out = bytearray(source)
    pos = 5
    while True:
        if pos + 3 > len(patch):
            raise RuntimeError("IPS ended before EOF")
        if patch[pos:pos + 3] == b"EOF":
            pos += 3
            break
        offset = int.from_bytes(patch[pos:pos + 3], "big")
        pos += 3
        if pos + 2 > len(patch):
            raise RuntimeError("IPS record is truncated")
        size = int.from_bytes(patch[pos:pos + 2], "big")
        pos += 2
        if size == 0:
            if pos + 3 > len(patch):
                raise RuntimeError("IPS RLE record is truncated")
            run = int.from_bytes(patch[pos:pos + 2], "big")
            value = patch[pos + 2]
            pos += 3
            data = bytes([value]) * run
        else:
            data = patch[pos:pos + size]
            if len(data) != size:
                raise RuntimeError("IPS data record is truncated")
            pos += size
        end = offset + len(data)
        if end > len(out):
            out.extend(b"\0" * (end - len(out)))
        out[offset:end] = data

    # Optional IPS truncate/expand size after EOF.
    remaining = len(patch) - pos
    if remaining == 3:
        final_size = int.from_bytes(patch[pos:pos + 3], "big")
        if final_size < len(out):
            del out[final_size:]
        elif final_size > len(out):
            out.extend(b"\0" * (final_size - len(out)))
    elif remaining != 0:
        raise RuntimeError("Unexpected trailing data after IPS EOF")
    return bytes(out)


def verify_tmd_contents(wad_path: Path, folder: Path) -> int:
    # extract() already decrypts every content and verifies its TMD SHA-1.  Re-read
    # the table here so the GUI can also enforce count and exact sizes explicitly.
    extract(wad_path, folder)
    blob = wad_path.read_bytes()
    sec = parse_wad(blob)
    tmd_off, tmd_size = sec["tmd"]
    tmd = blob[tmd_off:tmd_off + tmd_size]
    count = 0
    for cid, index, _kind, expected_size, expected_sha, _record_off in content_records(tmd):
        content = folder / f"{index:08x}_{cid:08x}.app"
        if not content.is_file():
            raise RuntimeError(f"Missing decrypted content index {index}")
        data = content.read_bytes()
        if len(data) != expected_size:
            raise RuntimeError(f"Content index {index} failed size verification")
        if hashlib.sha1(data).digest() != expected_sha:
            raise RuntimeError(f"Content index {index} failed TMD SHA-1 verification")
        count += 1
    if count != EXPECTED_CONTENT_COUNT:
        raise RuntimeError(f"Expected {EXPECTED_CONTENT_COUNT} contents, found {count}")
    return count


def patch_wad(input_wad: Path, output_wad: Path, log=lambda _s: None) -> None:
    if not input_wad.is_file():
        raise RuntimeError("Input WAD does not exist")
    if input_wad.resolve() == output_wad.resolve():
        raise RuntimeError("Input and output WAD paths must be different")

    patch = verify_embedded_patch()
    log("PASS: embedded H64 IPS payload")

    log("Verifying original USA/NACE WAD...")
    wad_hash = digest_file(input_wad, "sha256")
    if wad_hash != CLEAN_WAD_SHA256:
        raise RuntimeError(
            "Unsupported WAD. This patcher accepts only the exact original North American NACE release.\n\n"
            f"Found SHA-256: {wad_hash}"
        )
    log("PASS: clean NACE WAD SHA-256")

    with tempfile.TemporaryDirectory(prefix="oot-h64-") as td_name:
        td = Path(td_name)
        original_dir = td / "original"
        verify_dir = td / "verify"

        log("Decrypting original WAD...")
        extract(input_wad, original_dir)
        clean_app = find_content1(original_dir).read_bytes()
        clean_sha1 = hashlib.sha1(clean_app).hexdigest()
        if clean_sha1 != CLEAN_APP_SHA1:
            raise RuntimeError(f"Original content1.app SHA-1 mismatch: {clean_sha1}")
        log("PASS: original content1.app SHA-1")

        log("Applying embedded H64 IPS...")
        patched_app_data = apply_ips(clean_app, patch)
        patched_sha1 = hashlib.sha1(patched_app_data).hexdigest()
        if patched_sha1 != H64_APP_SHA1:
            raise RuntimeError(
                "Embedded IPS did not produce the tested H64 emulator image.\n"
                f"Found content1 SHA-1: {patched_sha1}"
            )
        log("PASS: exact H64 content1.app SHA-1")

        patched_app = td / "H64-content1.app"
        patched_app.write_bytes(patched_app_data)
        rebuilt_wad = td / "H64-output.wad"

        log("Repacking WAD with production H64 TMD fakesigning...")
        fill = repack(input_wad, {1: patched_app}, rebuilt_wad)
        log(f"PASS: TMD fakesign filler 0x{fill:04X}")

        log("Decrypting rebuilt WAD and verifying all contents...")
        count = verify_tmd_contents(rebuilt_wad, verify_dir)
        log(f"PASS: {count}/{EXPECTED_CONTENT_COUNT} TMD contents")

        roundtrip_app = find_content1(verify_dir).read_bytes()
        if hashlib.sha1(roundtrip_app).hexdigest() != H64_APP_SHA1:
            raise RuntimeError("H64 content1.app changed during WAD rebuild")

        final_hash = digest_file(rebuilt_wad, "sha256")
        if final_hash != H64_WAD_SHA256:
            raise RuntimeError(
                "The rebuilt WAD is internally valid but does not match the tested H64 reference.\n"
                f"Found SHA-256: {final_hash}"
            )
        log("PASS: exact tested H64 WAD SHA-256")

        output_wad.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(rebuilt_wad, output_wad)
    log(f"COMPLETE: {output_wad}")


class PatcherGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_TITLE} — {VERSION}")
        self.root.minsize(760, 650)
        self.messages: queue.Queue[tuple[str, str]] = queue.Queue()
        self.input_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready — select your original USA/NACE WAD.")
        self._build()
        self.root.after(80, self._poll)

    def _build(self) -> None:
        outer = ttk.Frame(self.root, padding=18)
        outer.pack(fill="both", expand=True)

        title = ttk.Label(outer, text="Ocarina of Time Wii VC Fix Patcher", font=("Segoe UI", 18, "bold"))
        title.pack(anchor="w")
        ttk.Label(
            outer,
            text="Hardware-safe H64 patch for the original North American NACE Wii VC release.",
        ).pack(anchor="w", pady=(2, 14))

        files = ttk.LabelFrame(outer, text="WAD files", padding=12)
        files.pack(fill="x")
        files.columnconfigure(1, weight=1)
        ttk.Label(files, text="Input WAD").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(files, textvariable=self.input_var).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Button(files, text="Browse...", command=self._browse_input).grid(row=0, column=2, padx=(8, 0), pady=4)
        ttk.Label(files, text="Output WAD").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(files, textvariable=self.output_var).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(files, text="Browse...", command=self._browse_output).grid(row=1, column=2, padx=(8, 0), pady=4)

        fixes = ttk.LabelFrame(outer, text="Included fixes", padding=12)
        fixes.pack(fill="x", pady=(14, 0))
        for feature in FEATURES:
            ttk.Label(fixes, text=f"✓  {feature}").pack(anchor="w", pady=1)

        self.patch_button = ttk.Button(outer, text="PATCH WAD", command=self._start_patch)
        self.patch_button.pack(fill="x", pady=(14, 6), ipady=8)
        self.progress = ttk.Progressbar(outer, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 6))
        ttk.Label(outer, textvariable=self.status_var).pack(anchor="w")

        log_frame = ttk.LabelFrame(outer, text="Verification log", padding=8)
        log_frame.pack(fill="both", expand=True, pady=(10, 0))
        self.log = tk.Text(log_frame, height=10, wrap="word", state="disabled", font=("Consolas", 9))
        scroll = ttk.Scrollbar(log_frame, command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        self.log.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _browse_input(self) -> None:
        path = filedialog.askopenfilename(title="Select original USA/NACE OoT VC WAD", filetypes=[("Wii WAD", "*.wad"), ("All files", "*.*")])
        if not path:
            return
        self.input_var.set(path)
        p = Path(path)
        self.output_var.set(str(p.with_name(p.stem + " - VC Fix H64.wad")))

    def _browse_output(self) -> None:
        initial = Path(self.output_var.get()).name if self.output_var.get() else "Ocarina of Time - VC Fix H64.wad"
        path = filedialog.asksaveasfilename(title="Save patched H64 WAD", defaultextension=".wad", initialfile=initial, filetypes=[("Wii WAD", "*.wad")])
        if path:
            self.output_var.set(path)

    def _append_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _start_patch(self) -> None:
        try:
            input_wad = Path(self.input_var.get().strip())
            output_wad = Path(self.output_var.get().strip())
            if not str(input_wad):
                raise RuntimeError("Select an input WAD first.")
            if not str(output_wad):
                raise RuntimeError("Choose an output WAD path first.")
        except Exception as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        self.patch_button.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set("Patching and verifying...")
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

        def worker() -> None:
            try:
                patch_wad(input_wad, output_wad, lambda s: self.messages.put(("log", s)))
                self.messages.put(("success", str(output_wad)))
            except Exception:
                self.messages.put(("error", traceback.format_exc()))

        threading.Thread(target=worker, daemon=True).start()

    def _poll(self) -> None:
        try:
            while True:
                kind, value = self.messages.get_nowait()
                if kind == "log":
                    self._append_log(value)
                    self.status_var.set(value)
                elif kind == "success":
                    self.progress.stop()
                    self.patch_button.configure(state="normal")
                    self.status_var.set("Complete — exact H64 WAD verified.")
                    messagebox.showinfo(APP_TITLE, f"Patch completed successfully.\n\nExact H64 WAD verification: PASS\n\n{value}")
                elif kind == "error":
                    self.progress.stop()
                    self.patch_button.configure(state="normal")
                    self.status_var.set("Patch failed. See verification log.")
                    self._append_log(value)
                    last = value.strip().splitlines()[-1] if value.strip() else "Unknown error"
                    messagebox.showerror(APP_TITLE, last)
        except queue.Empty:
            pass
        self.root.after(80, self._poll)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"{APP_TITLE} {VERSION}")
    parser.add_argument("--verify-payload", action="store_true", help="verify bundled H64 IPS and exit")
    parser.add_argument("--patch", nargs=2, metavar=("INPUT_WAD", "OUTPUT_WAD"), help="patch without opening the GUI")
    args = parser.parse_args(argv)

    if args.verify_payload:
        payload = verify_embedded_patch()
        print(f"PASS: {PATCH_NAME}")
        print(f"SHA-256: {hashlib.sha256(payload).hexdigest()}")
        return 0
    if args.patch:
        patch_wad(Path(args.patch[0]), Path(args.patch[1]), print)
        return 0

    root = tk.Tk()
    PatcherGUI(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
