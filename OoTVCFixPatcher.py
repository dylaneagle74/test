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
CLEAN_WAD_SHA256 = "6926561f8e7ed8a58f0433f577f4b3f2136a0c3e719cd97f838ae6f1202ec6e6"
CLEAN_APP_SHA1 = "763d4d3d0713e4d10e44540ccfa3255e19f28af7"
H63_WAD_SHA256 = "de70a0d822bfc822c8f0f29fc3ef185a2a5bd63cefc958d7b6b075e579e806e9"
H63_APP_SHA1 = "149ce67ae3fd25d80820e11c7eb4eb1886be66ce"
PATCH_NAME = "oot-vc-usa-h63.ips"
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


def root_dir() -> Path:
    if hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parent


def writable_root() -> Path:
    return Path(__file__).resolve().parent


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
    legacy = folder / "00000001.app"
    if legacy.is_file():
        return legacy
    raise RuntimeError("Could not uniquely locate content index 1")


def u24(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError("IPS offset/size exceeds 24-bit range")
    return value.to_bytes(3, "big")


def make_ips(source: bytes, target: bytes) -> bytes:
    out = bytearray(b"PATCH")
    limit = max(len(source), len(target))
    pos = 0

    def different(i: int) -> bool:
        a = source[i] if i < len(source) else None
        b = target[i] if i < len(target) else None
        return a != b

    while pos < limit:
        if not different(pos):
            pos += 1
            continue
        start = pos
        while pos < limit and different(pos) and pos - start < 0xFFFF:
            pos += 1
        payload = target[start:min(pos, len(target))]
        if payload:
            out += u24(start)
            out += len(payload).to_bytes(2, "big")
            out += payload
        if pos == start:
            pos += 1

    out += b"EOF"
    if len(source) != len(target):
        out += u24(len(target))
    return bytes(out)


def apply_ips(source: bytes, patch: bytes) -> bytes:
    if not patch.startswith(b"PATCH"):
        raise RuntimeError("H63 payload is not a valid IPS patch")
    out = bytearray(source)
    pos = 5
    while True:
        if pos + 3 > len(patch):
            raise RuntimeError("H63 IPS is truncated")
        if patch[pos:pos + 3] == b"EOF":
            pos += 3
            break
        offset = int.from_bytes(patch[pos:pos + 3], "big")
        pos += 3
        size = int.from_bytes(patch[pos:pos + 2], "big")
        pos += 2
        if size == 0:
            run = int.from_bytes(patch[pos:pos + 2], "big")
            value = patch[pos + 2]
            pos += 3
            payload = bytes([value]) * run
        else:
            payload = patch[pos:pos + size]
            if len(payload) != size:
                raise RuntimeError("H63 IPS data record is truncated")
            pos += size
        end = offset + len(payload)
        if end > len(out):
            out.extend(b"\0" * (end - len(out)))
        out[offset:end] = payload

    if len(patch) - pos == 3:
        final_size = int.from_bytes(patch[pos:pos + 3], "big")
        if final_size < len(out):
            del out[final_size:]
        elif final_size > len(out):
            out.extend(b"\0" * (final_size - len(out)))
    elif pos != len(patch):
        raise RuntimeError("Unexpected data after H63 IPS EOF")
    return bytes(out)


def verify_tmd_contents(wad_path: Path, folder: Path) -> int:
    extract(wad_path, folder)
    blob = wad_path.read_bytes()
    sec = parse_wad(blob)
    off, size = sec["tmd"]
    tmd = blob[off:off + size]
    count = 0
    for cid, index, _kind, expected_size, expected_sha, _ in content_records(tmd):
        path = folder / f"{index:08x}_{cid:08x}.app"
        if not path.is_file():
            raise RuntimeError(f"Missing decrypted content index {index}")
        data = path.read_bytes()
        if len(data) != expected_size:
            raise RuntimeError(f"Content index {index} failed size verification")
        if hashlib.sha1(data).digest() != expected_sha:
            raise RuntimeError(f"Content index {index} failed TMD SHA-1 verification")
        count += 1
    if count != EXPECTED_CONTENT_COUNT:
        raise RuntimeError(f"Expected {EXPECTED_CONTENT_COUNT} contents, found {count}")
    return count


def build_patch_payload(clean_wad: Path, h63_wad: Path, output_patch: Path, log) -> None:
    log("Verifying private reference WADs...")
    if digest_file(clean_wad, "sha256") != CLEAN_WAD_SHA256:
        raise RuntimeError("Clean reference WAD SHA-256 does not match the supported NACE WAD")
    if digest_file(h63_wad, "sha256") != H63_WAD_SHA256:
        raise RuntimeError("H63 reference WAD SHA-256 does not match the tested H63 build")

    with tempfile.TemporaryDirectory(prefix="oot-h63-payload-") as td_name:
        td = Path(td_name)
        clean_dir = td / "clean"
        h63_dir = td / "h63"
        extract(clean_wad, clean_dir)
        extract(h63_wad, h63_dir)
        clean_app = find_content1(clean_dir).read_bytes()
        h63_app = find_content1(h63_dir).read_bytes()
        if hashlib.sha1(clean_app).hexdigest() != CLEAN_APP_SHA1:
            raise RuntimeError("Clean reference content1.app SHA-1 mismatch")
        if hashlib.sha1(h63_app).hexdigest() != H63_APP_SHA1:
            raise RuntimeError("H63 reference content1.app SHA-1 mismatch")

        log("Generating clean-NACE -> H63 IPS payload...")
        patch = make_ips(clean_app, h63_app)
        rebuilt = apply_ips(clean_app, patch)
        if rebuilt != h63_app:
            raise RuntimeError("Generated IPS failed byte-for-byte H63 APP reproduction")
        if hashlib.sha1(rebuilt).hexdigest() != H63_APP_SHA1:
            raise RuntimeError("Generated IPS output SHA-1 mismatch")

        output_patch.parent.mkdir(parents=True, exist_ok=True)
        output_patch.write_bytes(patch)
        log(f"Payload created: {output_patch}")
        log(f"Payload SHA-256: {hashlib.sha256(patch).hexdigest()}")


def patch_wad(input_wad: Path, output_wad: Path, log) -> None:
    patch_path = root_dir() / "patches" / PATCH_NAME
    if not patch_path.is_file():
        raise RuntimeError(
            "The H63 patch payload is not installed. Use Maintainer -> Build H63 patch payload once, "
            "then rebuild/distribute the patcher."
        )
    if not input_wad.is_file():
        raise RuntimeError("Input WAD does not exist")
    if input_wad.resolve() == output_wad.resolve():
        raise RuntimeError("Input and output WAD paths must be different")

    log("Verifying original USA/NACE WAD...")
    wad_hash = digest_file(input_wad, "sha256")
    if wad_hash != CLEAN_WAD_SHA256:
        raise RuntimeError(f"Unsupported WAD. Found SHA-256: {wad_hash}")
    log("PASS: clean WAD SHA-256")

    with tempfile.TemporaryDirectory(prefix="oot-h63-patch-") as td_name:
        td = Path(td_name)
        original = td / "original"
        verify = td / "verify"
        extract(input_wad, original)
        clean_app_path = find_content1(original)
        clean_app = clean_app_path.read_bytes()
        if hashlib.sha1(clean_app).hexdigest() != CLEAN_APP_SHA1:
            raise RuntimeError("Clean content1.app SHA-1 mismatch")
        log("PASS: clean content1.app SHA-1")

        log("Applying H63 patch...")
        patched = apply_ips(clean_app, patch_path.read_bytes())
        if hashlib.sha1(patched).hexdigest() != H63_APP_SHA1:
            raise RuntimeError("Patched content1.app did not match H63")
        patched_app = td / "H63-content1.app"
        patched_app.write_bytes(patched)
        log("PASS: H63 content1.app SHA-1")

        temp_wad = td / "H63-output.wad"
        log("Repacking WAD...")
        repack(input_wad, {1: patched_app}, temp_wad)

        log("Decrypting rebuilt WAD for verification...")
        count = verify_tmd_contents(temp_wad, verify)
        log(f"PASS: {count}/{EXPECTED_CONTENT_COUNT} TMD contents")
        roundtrip_app = find_content1(verify).read_bytes()
        if hashlib.sha1(roundtrip_app).hexdigest() != H63_APP_SHA1:
            raise RuntimeError("H63 content changed during WAD rebuild")

        final_hash = digest_file(temp_wad, "sha256")
        if final_hash != H63_WAD_SHA256:
            raise RuntimeError(
                "The WAD contents verify, but the finished WAD does not match the tested H63 reference. "
                f"Found SHA-256: {final_hash}"
            )
        log("PASS: exact tested H63 WAD SHA-256")

        output_wad.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(temp_wad, output_wad)
    log(f"COMPLETE: {output_wad}")


class Gui:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_TITLE} — {VERSION}")
        self.root.minsize(760, 610)
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.input_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Select your original USA/NACE OoT Wii VC WAD.")

        menubar = tk.Menu(root)
        maint = tk.Menu(menubar, tearoff=False)
        maint.add_command(label="Build H63 patch payload...", command=self.build_payload_dialog)
        menubar.add_cascade(label="Maintainer", menu=maint)
        root.config(menu=menubar)

        outer = ttk.Frame(root, padding=16)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text=APP_TITLE, font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(outer, text="Hardware-safe H63 patch for the original North American NACE Wii VC release.").pack(anchor="w", pady=(2, 14))

        box = ttk.LabelFrame(outer, text="WAD files", padding=10)
        box.pack(fill="x")
        self.path_row(box, "Input WAD", self.input_var, self.choose_input, 0)
        self.path_row(box, "Output WAD", self.output_var, self.choose_output, 1)

        features = ttk.LabelFrame(outer, text="Included fixes", padding=10)
        features.pack(fill="x", pady=12)
        for item in FEATURES:
            ttk.Label(features, text=f"✓  {item}").pack(anchor="w")

        self.button = ttk.Button(outer, text="PATCH WAD", command=self.start_patch)
        self.button.pack(fill="x", ipady=8)
        ttk.Label(outer, textvariable=self.status_var).pack(anchor="w", pady=(8, 0))
        self.log = tk.Text(outer, height=11, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True, pady=(6, 0))
        self.root.after(100, self.poll)

    def path_row(self, parent, label, var, callback, row):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(parent, textvariable=var).grid(row=row, column=1, sticky="ew", pady=4)
        ttk.Button(parent, text="Browse...", command=callback).grid(row=row, column=2, padx=(8, 0), pady=4)
        parent.columnconfigure(1, weight=1)

    def choose_input(self):
        path = filedialog.askopenfilename(title="Select original USA/NACE OoT Wii VC WAD", filetypes=[("Wii WAD", "*.wad"), ("All files", "*.*")])
        if path:
            self.input_var.set(path)
            p = Path(path)
            self.output_var.set(str(p.with_name(p.stem + " - VC Fix H63.wad")))

    def choose_output(self):
        path = filedialog.asksaveasfilename(title="Save patched H63 WAD", defaultextension=".wad", filetypes=[("Wii WAD", "*.wad")])
        if path:
            self.output_var.set(path)

    def append(self, message: str):
        self.log.configure(state="normal")
        self.log.insert("end", message + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")
        self.status_var.set(message)

    def run_worker(self, fn, success_message: str):
        self.button.configure(state="disabled")
        def worker():
            try:
                fn(lambda text: self.events.put(("log", text)))
                self.events.put(("done", success_message))
            except Exception as exc:
                self.events.put(("error", (str(exc), traceback.format_exc())))
        threading.Thread(target=worker, daemon=True).start()

    def start_patch(self):
        if not self.input_var.get() or not self.output_var.get():
            messagebox.showerror(APP_TITLE, "Choose both input and output WAD paths.")
            return
        src = Path(self.input_var.get())
        dst = Path(self.output_var.get())
        self.run_worker(lambda log: patch_wad(src, dst, log), f"Patch complete.\n\n{dst}")

    def build_payload_dialog(self):
        clean = filedialog.askopenfilename(title="Select exact clean NACE WAD", filetypes=[("Wii WAD", "*.wad")])
        if not clean:
            return
        h63 = filedialog.askopenfilename(title="Select private tested H63 reference WAD", filetypes=[("Wii WAD", "*.wad")])
        if not h63:
            return
        target = writable_root() / "patches" / PATCH_NAME
        self.run_worker(
            lambda log: build_patch_payload(Path(clean), Path(h63), target, log),
            f"H63 patch payload created.\n\n{target}\n\nYou can now build the public EXE.",
        )

    def poll(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self.append(str(payload))
                elif kind == "done":
                    self.button.configure(state="normal")
                    self.append("Ready.")
                    messagebox.showinfo(APP_TITLE, str(payload))
                elif kind == "error":
                    self.button.configure(state="normal")
                    message, trace = payload
                    self.append("FAILED: " + message)
                    self.append(trace)
                    messagebox.showerror(APP_TITLE, message)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)


def main() -> int:
    root = tk.Tk()
    Gui(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
