# OoT Wii VC H63 GUI Patcher

This branch is a clean standalone snapshot containing only the GUI patcher and the WAD patching code required to apply the H63 emulator patch to the exact original North American Ocarina of Time Wii Virtual Console WAD (`NACE`).

It intentionally does **not** contain `tp_main`, Patcher64+, old hardware tests, historical pass files, ROMs, WADs, decrypted APPs, or unrelated project files.

## Files

- `OoTVCFixPatcher.py` — standalone GUI patcher and one-time payload generator
- `wad_tools.py` — WAD decrypt/repack support
- `requirements.txt` — Python/PyInstaller dependencies
- `Build EXE.bat` — one-click Windows release builder
- `patches/oot-vc-usa-h63.ips` — generated H63 `content1.app` delta bundled into the public EXE

## Supported clean WAD

- WAD SHA-256: `6926561f8e7ed8a58f0433f577f4b3f2136a0c3e719cd97f838ae6f1202ec6e6`
- clean `content1.app` SHA-1: `763d4d3d0713e4d10e44540ccfa3255e19f28af7`

Expected H63 output:

- H63 `content1.app` SHA-1: `149ce67ae3fd25d80820e11c7eb4eb1886be66ce`
- H63 WAD SHA-256: `de70a0d822bfc822c8f0f29fc3ef185a2a5bd63cefc958d7b6b075e579e806e9`

## Build the public EXE

Double-click:

```text
Build EXE.bat
```

On the first build only, if `patches/oot-vc-usa-h63.ips` does not exist, the builder automatically opens two file pickers:

1. select the exact original USA/NACE OoT VC WAD;
2. select the tested H63 reference WAD.

The payload generator then:

1. verifies the clean WAD SHA-256;
2. verifies the H63 WAD SHA-256;
3. extracts both `content1.app` files;
4. verifies both APP SHA-1 values;
5. generates the clean-NACE -> H63 IPS delta;
6. reapplies that IPS to the clean APP;
7. requires the result to match the H63 APP byte-for-byte.

If every check passes, `Build EXE.bat` continues automatically and creates:

```text
dist\OoTVCFixPatcher-H63.exe
```

The private clean/H63 WADs are never embedded in the EXE. Only the generated IPS delta is bundled.

## End-user flow

End users run `OoTVCFixPatcher-H63.exe`, select their own exact clean USA/NACE WAD, and choose an output WAD.

The patcher performs:

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
