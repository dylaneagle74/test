# Ocarina of Time Wii VC Fix Patcher — H63

A standalone Windows GUI patcher for the original North American Wii Virtual Console release of **The Legend of Zelda: Ocarina of Time** (`NACE`).

The project contains the patcher source code and the verified H63 IPS delta only. It does **not** include a Wii WAD, decrypted APP, ROM, ticket, Nintendo assets, or a pre-patched game.

## What H63 changes

H63 applies the final tested emulator-side enhancement stack:

- sharp live-GX N64-style three-point filtering
- Test 10 reflection / texgen correction
- ESS analog response V3.3
- GameCube controller rumble
- Wii Remote / Classic Controller rumble path
- Stone of Agony rumble through the emulated N64 Rumble Pak path
- v0.81 exact-FIFO C3T3 triangle batching
- v0.82 lazy depth conversion
- v0.83 demand-armed depth snapshots

The patch modifies the Wii VC emulator executable (`content1.app`). It does not replace the embedded Ocarina of Time ROM.

## End-user usage

The compiled patcher needs only your own original USA/NACE OoT VC WAD.

1. Run `OoTVCFixPatcher-H63.exe`.
2. Click **Browse** next to **Input WAD** and select the original USA/NACE WAD.
3. Choose an **Output WAD** location.
4. Click **PATCH WAD**.
5. Wait for all validation steps to complete.

The patcher refuses an unsupported input instead of attempting a blind patch.

### Supported clean WAD

SHA-256:

`6926561f8e7ed8a58f0433f577f4b3f2136a0c3e719cd97f838ae6f1202ec6e6`

Clean `content1.app` SHA-1:

`763d4d3d0713e4d10e44540ccfa3255e19f28af7`

## Building the Windows EXE

Requirements:

- Windows
- Python 3
- Internet access during the first build so pip can install the Python packages

Clone/download this branch and double-click:

`Build EXE.bat`

The script will:

1. install/update PyCryptodome and PyInstaller,
2. verify the bundled H63 IPS,
3. build a single-file Windows GUI executable.

The finished program is written to:

`dist\OoTVCFixPatcher-H63.exe`

No clean WAD or H63 reference WAD is needed to **build** the EXE.

## Embedded patch

The final H63 IPS is included at:

`patches/oot-vc-usa-h63.ips`

IPS SHA-256:

`8941c141112ae8d14d9824a0f0c5bcbea0725f70883d026ef13cbc895399d2ef`

Applying that IPS to the supported clean `content1.app` must produce:

H63 `content1.app` SHA-1:

`149ce67ae3fd25d80820e11c7eb4eb1886be66ce`

## Output validation

The patcher does more than apply the IPS. It validates the complete WAD rebuild:

- verifies the original WAD SHA-256
- verifies the original `content1.app` SHA-1
- verifies the embedded IPS SHA-256
- applies the IPS to `content1.app`
- verifies the resulting H63 APP SHA-1
- updates the TMD content record
- performs the production TMD fakesign
- re-encrypts/rebuilds the WAD
- decrypts the finished WAD again
- verifies all 7 TMD content SHA-1 records
- verifies the final full-file WAD SHA-256

Expected final H63 WAD SHA-256:

`de70a0d822bfc822c8f0f29fc3ef185a2a5bd63cefc958d7b6b075e579e806e9`

The production TMD fakesign filler for this exact build is:

`0x01AF`

More details are in `VALIDATION.txt`.

## Source layout

```text
.
├── OoTVCFixPatcher.py
├── wad_tools.py
├── Build EXE.bat
├── requirements.txt
├── VALIDATION.txt
├── README.md
└── patches/
    └── oot-vc-usa-h63.ips
```

`OoTVCFixPatcher.py` contains the GUI, IPS application, input/output hash checks, and final validation flow.

`wad_tools.py` contains the WAD extraction, AES content handling, TMD update/fakesign, and repack logic used to reproduce the tested H63 WAD.

## Important notes

- Only the original North American `NACE` WAD with the exact supported hash is accepted.
- Keep an untouched backup of your original WAD.
- Installation/testing of modified WADs is at your own risk.
- Physical Wii testing through the normal Wii Menu / IOS9 path was the authority during development.
- This repository contains no Nintendo game binaries or copyrighted game assets.
