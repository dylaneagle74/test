# OoT Wii VC H63 GUI Patcher

This branch is a clean standalone snapshot. It contains only the GUI patcher and the WAD patching code required to apply the H63 emulator patch to the exact original North American Ocarina of Time Wii Virtual Console WAD (`NACE`).

It intentionally does **not** contain `tp_main`, Patcher64+, old hardware tests, historical pass files, ROMs, WADs, decrypted APPs, or other unrelated project files.

## Files

- `OoTVCFixPatcher.py` — GUI patcher
- `wad_tools.py` — WAD decrypt/repack support used by the GUI
- `requirements.txt` — Python dependencies
- `Build EXE.bat` — builds a single Windows executable with PyInstaller
- `patches/oot-vc-usa-h63.ips` — generated H63 content1 delta for public distribution

## Supported clean WAD

- WAD SHA-256: `6926561f8e7ed8a58f0433f577f4b3f2136a0c3e719cd97f838ae6f1202ec6e6`
- clean `content1.app` SHA-1: `763d4d3d0713e4d10e44540ccfa3255e19f28af7`

Expected H63 output:

- H63 `content1.app` SHA-1: `149ce67ae3fd25d80820e11c7eb4eb1886be66ce`
- H63 WAD SHA-256: `de70a0d822bfc822c8f0f29fc3ef185a2a5bd63cefc958d7b6b075e579e806e9`

## First-time maintainer setup

Because this source snapshot does not distribute Nintendo game data, the patch payload is generated once from your private clean WAD and the private H63 reference WAD:

1. `py -m pip install -r requirements.txt`
2. Run `py OoTVCFixPatcher.py`
3. Open **Maintainer -> Build H63 patch payload**.
4. Select the exact clean NACE WAD and the H63 reference WAD.
5. The GUI generates `patches/oot-vc-usa-h63.ips` only after proving that applying it recreates the H63 `content1.app` byte-for-byte.

After that, the folder can be built into the public EXE with `Build EXE.bat`. End users only select their own clean WAD and click **PATCH WAD**.

## End-user flow

The GUI performs:

1. clean WAD SHA-256 validation;
2. WAD extraction;
3. clean `content1.app` SHA-1 validation;
4. H63 IPS application;
5. patched `content1.app` SHA-1 validation;
6. WAD repack with TMD content hash update;
7. decrypt/re-read of the rebuilt WAD;
8. 7/7 TMD content size/SHA-1 verification;
9. final H63 WAD SHA-256 verification.

The embedded N64 ROM is not separately patched.
