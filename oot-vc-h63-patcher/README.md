# OoT Wii VC H63 Patcher — staging

This directory contains source for two public patching routes for the North American Wii Virtual Console release of **The Legend of Zelda: Ocarina of Time** (`NACE`):

1. `standalone/` — one-purpose Windows GUI patcher.
2. `patcher64plus/` — integration for Admentus64/Patcher64Plus-Tool.

No Nintendo WAD, APP, ROM, or other game binary is stored here.

## Supported private input

The public patch payload is generated from the exact clean USA/NACE WAD and the private H63 reference WAD.

- clean WAD SHA-256: `6926561f8e7ed8a58f0433f577f4b3f2136a0c3e719cd97f838ae6f1202ec6e6`
- clean `00000001.app` SHA-1: `763d4d3d0713e4d10e44540ccfa3255e19f28af7`
- H63 `00000001.app` SHA-1: `149ce67ae3fd25d80820e11c7eb4eb1886be66ce`
- H63 reference WAD SHA-256: `de70a0d822bfc822c8f0f29fc3ef185a2a5bd63cefc958d7b6b075e579e806e9`

## Included H63 features

- sharp live-GX N64-style three-point filtering
- Test 10 reflection/texgen correction
- ESS analog response V3.3
- GameCube + Wii/Classic rumble
- Stone of Agony through the normal emulated N64 Rumble Pak path
- corrected explicit-PPC v0.81 C3T3 batching
- v0.82 lazy depth-RAM conversion
- v0.83 demand-armed raw-depth snapshot optimization

## Release-builder

`tools/build_release.py` is intentionally a maintainer-only step. It takes the two private WADs once, extracts their `00000001.app` files through the project's existing `wad_tools.py`, generates the distributable IPS, verifies that applying the IPS reproduces the H63 APP byte-for-byte, and creates the public package trees.

Example:

```powershell
py tools\build_release.py `
  --clean-wad "C:\private\Legend of Zelda, The - Ocarina of Time (USA) (N64) (Virtual Console).wad" `
  --h63-wad "C:\private\H63-OoT-USA-IOS9-H62-PLUS-V083-DEMAND-ARMED-DEPTH.wad" `
  --wad-tools "C:\src\oot-vc-hardware-safe-threepoint-source-v0.83\tools\wad_tools.py" `
  --output dist
```

The generated IPS is safe to publish; the private WADs and extracted APPs are not copied into `dist`.

## Standalone patcher

The GUI accepts only the exact supported clean WAD. It:

1. validates the whole-WAD SHA-256;
2. extracts content 1;
3. validates clean APP SHA-1;
4. applies the H63 IPS;
5. validates H63 APP SHA-1;
6. rebuilds the WAD with the existing WAD repacker;
7. decrypts the rebuilt WAD again and validates every TMD content hash;
8. verifies the exact H63 WAD SHA-256 before reporting success.

The embedded N64 ROM is not independently patched.

## Patcher64+ integration

The integration is based on the previously verified `vc_emulator_patch` design: a dedicated emulator-only patch field, clean/output APP SHA-1 gates, and forced disabling of unrelated ROM/Redux/extension processing.

The integration patch targets the pinned upstream tree documented in `patcher64plus/README.md`. The generated `oot-vc-usa-h63.ips` belongs at:

`Files/Games/Ocarina of Time/AppFile01/oot-vc-usa-h63.ips`

## Hardware status

- H61 corrected batching: physical Wii / Wii Menu / IOS9 PASS.
- H62 lazy depth: physical Wii / Wii Menu / IOS9 PASS.
- H63 is the final packaged demand-armed-depth build. Keep H62 as the rollback if H63's documented one-frame dirty-late depth recovery ever produces a visible regression.
