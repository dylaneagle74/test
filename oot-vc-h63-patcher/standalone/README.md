# OoT VC H63 standalone patcher

This is a one-purpose patcher for the exact original North American Wii Virtual Console Ocarina of Time WAD (`NACE`).

## End-user usage

1. Launch `OoTVCFixPatcher-H63.exe` if using the compiled release, or `Run Patcher.bat` in the source package.
2. Select your original USA/NACE OoT Wii VC WAD.
3. Choose an output filename.
4. Click **PATCH WAD**.

The patcher refuses unknown WADs.

## Verification performed

Before patching:

- whole clean WAD SHA-256 must be `6926561f8e7ed8a58f0433f577f4b3f2136a0c3e719cd97f838ae6f1202ec6e6`
- clean `content1.app` SHA-1 must be `763d4d3d0713e4d10e44540ccfa3255e19f28af7`

After applying the bundled IPS:

- patched `content1.app` SHA-1 must be `149ce67ae3fd25d80820e11c7eb4eb1886be66ce`
- the rebuilt WAD is decrypted again
- all seven TMD content records are checked for exact size and SHA-1
- final WAD SHA-256 must be `de70a0d822bfc822c8f0f29fc3ef185a2a5bd63cefc958d7b6b075e579e806e9`

## Included fixes

- sharp live-GX N64-style three-point filtering
- Test 10 reflection/texgen correction
- ESS analog response V3.3
- GameCube and Wii/Classic rumble
- Stone of Agony rumble through OoT's normal N64 Rumble Pak path
- v0.81 corrected explicit-PPC C3T3 batching
- v0.82 lazy depth conversion
- v0.83 demand-armed depth snapshots

## Legal / distribution note

The public package contains only patch data and patching software. It does not contain Nintendo's WAD, decrypted APP, embedded ROM, ticket, TMD, or other copyrighted game content.

Users must supply their own original supported WAD.
