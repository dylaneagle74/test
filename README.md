# Ocarina of Time Wii VC Fix Patcher — H64

Standalone Windows GUI patcher for the original North American Wii Virtual Console release of **The Legend of Zelda: Ocarina of Time** (`NACE`).

H64 contains the complete H63 graphics/controller/performance stack plus reset-safety guards for the Wii Bluetooth GKI allocator. The new guards are intended to prevent the null free-list dereference observed when resetting offline-randomizer WADs.

## Public-user workflow

The final `OoTVCFixPatcher-H64.exe` requires only the user's own original USA/NACE WAD.

1. Run `OoTVCFixPatcher-H64.exe`.
2. Select the original USA/NACE OoT VC WAD.
3. Choose an output WAD path.
4. Click **PATCH WAD**.
5. Wait for every verification step to pass.

No H64 reference WAD and no patch-generation step are required. The verified clean-USA→H64 IPS payload is compiled into the EXE.

## What H64 changes

- sharp live-GX N64-style three-point filtering
- Test 10 reflection / texgen correction
- ESS analog response V3.3
- GameCube + Wii/Classic rumble
- Stone of Agony rumble through the emulated N64 Rumble Pak path
- v0.81 exact-FIFO C3T3 batching
- v0.82 lazy depth conversion
- v0.83 demand-armed depth snapshots
- H64 reset-safe Bluetooth GKI allocator guards

### Reset-safety change

The H64-only change adds two conservative null guards to the stock-layout GKI buffer allocator. During the observed randomizer reset failure, a pool could report free buffers while its free-list head was null. Retail code then dereferenced that null pointer. H64 does not fabricate buffers or rewrite allocator counts: it skips the inconsistent pool / takes the allocator's existing fallback path instead.

This reset fix should still be treated as hardware validation-sensitive. If a randomized WAD still crashes on reset, capture the new program-counter/fault address if possible.

## Safety checks

The patcher refuses unsupported WADs and verifies:

- clean WAD SHA-256
- clean `content1.app` SHA-1
- embedded IPS SHA-256
- patched H64 `content1.app` SHA-1
- production TMD fakesign/repack
- all 7 decrypted TMD content SHA-1 records
- final WAD SHA-256 against the exact H64 reference

### Supported clean WAD

SHA-256:

`6926561f8e7ed8a58f0433f577f4b3f2136a0c3e719cd97f838ae6f1202ec6e6`

Clean `content1.app` SHA-1:

`763d4d3d0713e4d10e44540ccfa3255e19f28af7`

### Embedded H64 IPS

`patches/oot-vc-usa-h64-reset-safe-gki.ips`

SHA-256:

`257033cc9fafcd37676ec519c8d10b155f9823c11e2459f6bcf40dc4bf4619f9`

### Final H64 output

WAD SHA-256:

`caf4a1c75744c394799da4289a9d86dd5ef42b83dbe9e5e9e656db935dd38691`

`content1.app` SHA-1:

`4b06f6454b96dbb6986d69622f163fb8e30a548b`

TMD fakesign filler for the exact H64 build:

`0x021D`

## Building the Windows EXE

Install Python 3 on Windows, then double-click:

`Build EXE.bat`

The script installs/updates PyCryptodome and PyInstaller, verifies the bundled H64 IPS, and creates:

`dist\OoTVCFixPatcher-H64.exe`

You do **not** need to select a clean or H64 WAD while building the EXE.

## Distribution

This repository contains the patcher source and a binary IPS delta only. It does **not** include a Nintendo WAD, decrypted APP, ROM, ticket, or game assets.
