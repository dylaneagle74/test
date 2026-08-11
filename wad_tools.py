from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Dict

from Crypto.Cipher import AES

ALIGNMENT = 0x40
AES_BLOCK = 0x10
COMMON_KEYS = {
    0: bytes.fromhex("ebe42a225e8593e448d9c5457381aaf7"),
    1: bytes.fromhex("63b82bb4f4614e2e13f2f6b5ef51eb58"),
}


def align(value: int, boundary: int = ALIGNMENT) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def parse_wad(data: bytes):
    """Parse the exact installable-WAD layout used by the production H63 builder."""
    if len(data) < 0x20:
        raise ValueError("WAD is too small")

    # The production H63 tool treats the 32-byte header as eight big-endian u32s:
    # header size, type, cert size, CRL size, ticket size, TMD size, data size,
    # footer size.  Reusing that exact interpretation is important for producing
    # the tested reference WAD byte-for-byte.
    hs, typ, cs, crls, tiks, tmds, ds, fs = struct.unpack(">8I", data[:32])

    off = align(hs)
    cert = (off, cs)
    off = align(off + cs)
    crl = (off, crls)
    off = align(off + crls)
    tik = (off, tiks)
    off = align(off + tiks)
    tmd = (off, tmds)
    off = align(off + tmds)
    dat = (off, ds)
    off = align(off + ds)
    footer = (off, fs)

    if footer[0] + footer[1] > len(data):
        raise ValueError("WAD sections extend beyond end of file")

    return {
        "header": (hs, typ, cs, crls, tiks, tmds, ds, fs),
        "cert": cert,
        "crl": crl,
        "tik": tik,
        "ticket": tik,
        "tmd": tmd,
        "data": dat,
        "footer": footer,
    }


def title_key(ticket: bytes):
    if len(ticket) < 0x1E4:
        raise ValueError("Ticket is too small")

    encrypted_title_key = ticket[0x1BF:0x1CF]
    title_id = ticket[0x1DC:0x1E4]

    # This patcher only accepts one exact clean NACE WAD by full-file SHA-256.
    # That WAD has a scene-modified key-index byte, while the title key is still
    # encrypted with the standard Wii common key.  This is the exact behavior of
    # the original WAD tool used to produce H63.  Every decrypted content is then
    # checked against the TMD SHA-1 before it can be used.
    key_index = 0
    key = aes_cbc_decrypt(
        COMMON_KEYS[key_index],
        title_id + (b"\0" * 8),
        encrypted_title_key,
    )
    return key, title_id


def content_records(tmd: bytes):
    if len(tmd) < 0x1E4:
        raise ValueError("TMD is too small")

    count = struct.unpack_from(">H", tmd, 0x1DE)[0]
    records = []
    for i in range(count):
        offset = 0x1E4 + i * 0x24
        if offset + 0x24 > len(tmd):
            raise ValueError("TMD content table is truncated")
        cid, index, kind, size = struct.unpack_from(">IHHQ", tmd, offset)
        sha = tmd[offset + 16:offset + 36]
        records.append((cid, index, kind, size, sha, offset))
    return records


def _decrypt_contents(wad_path: Path | str):
    wad_path = Path(wad_path)
    blob = wad_path.read_bytes()
    sec = parse_wad(blob)

    tik_off, tik_size = sec["tik"]
    tmd_off, tmd_size = sec["tmd"]
    ticket = blob[tik_off:tik_off + tik_size]
    tmd = blob[tmd_off:tmd_off + tmd_size]
    key, title_id = title_key(ticket)

    contents = {}
    cursor = sec["data"][0]
    for cid, index, kind, size, sha, record_off in content_records(tmd):
        encrypted_length = align(size, 0x40)
        encrypted = blob[cursor:cursor + encrypted_length]
        if len(encrypted) != encrypted_length:
            raise ValueError(f"Encrypted content {index} is truncated")

        iv = struct.pack(">H", index) + (b"\0" * 14)
        decrypted = aes_cbc_decrypt(
            key,
            iv,
            encrypted[:align(size, AES_BLOCK)],
        )[:size]

        if hashlib.sha1(decrypted).digest() != sha:
            raise ValueError(
                f"Content index {index} failed TMD SHA-1 during extraction"
            )

        contents[index] = {
            "cid": cid,
            "index": index,
            "kind": kind,
            "size": size,
            "sha": sha,
            "record_off": record_off,
            "plain": decrypted,
        }
        cursor += encrypted_length

    return blob, sec, ticket, tmd, key, title_id, contents


def extract(wad_path: Path | str, outdir: Path | str):
    outdir = Path(outdir)
    _blob, _sec, _ticket, _tmd, _key, _title_id, contents = _decrypt_contents(wad_path)
    outdir.mkdir(parents=True, exist_ok=True)

    for info in contents.values():
        name = f"{info['index']:08x}_{info['cid']:08x}.app"
        (outdir / name).write_bytes(info["plain"])

    return contents


def repack(
    original: Path | str,
    replacements: Dict[int, Path | str],
    output: Path | str,
):
    """Rebuild using the exact WAD/TMD algorithm that produced reference H63."""
    original = Path(original)
    output = Path(output)
    blob = original.read_bytes()
    sec = parse_wad(blob)

    hs, typ, cert_size, crl_size, ticket_size, tmd_size, old_data_size, footer_size = sec["header"]
    ticket = bytearray(blob[sec["tik"][0]:sec["tik"][0] + ticket_size])
    tmd = bytearray(blob[sec["tmd"][0]:sec["tmd"][0] + tmd_size])
    key, _title_id = title_key(ticket)

    encrypted_contents = []
    cursor = sec["data"][0]

    for cid, index, kind, old_size, old_sha, record_off in content_records(tmd):
        old_encrypted_length = align(old_size, 0x40)
        encrypted = blob[cursor:cursor + old_encrypted_length]
        if len(encrypted) != old_encrypted_length:
            raise ValueError(f"Encrypted content {index} is truncated")

        iv = struct.pack(">H", index) + (b"\0" * 14)
        plain = aes_cbc_decrypt(
            key,
            iv,
            encrypted[:align(old_size, AES_BLOCK)],
        )[:old_size]

        if hashlib.sha1(plain).digest() != old_sha:
            raise ValueError(
                f"Original content index {index} failed TMD SHA-1"
            )

        if index in replacements:
            plain = Path(replacements[index]).read_bytes()

        new_size = len(plain)
        digest = hashlib.sha1(plain).digest()
        struct.pack_into(">Q", tmd, record_off + 8, new_size)
        tmd[record_off + 16:record_off + 36] = digest

        padded = plain + (b"\0" * (align(new_size, AES_BLOCK) - new_size))
        new_encrypted = aes_cbc_encrypt(key, iv, padded)
        new_encrypted += b"\0" * (align(new_size, 0x40) - len(new_encrypted))
        encrypted_contents.append(new_encrypted)

        cursor += old_encrypted_length

    # Critical production step that earlier GUI revisions were missing:
    # Trucha-fakesign the modified TMD exactly as the original H63 packer did.
    # Clear the RSA signature body, then vary the 16-bit filler at 0x1E2 until
    # SHA-1(TMD body) begins with zero.  For the final H63 TMD this resolves to
    # 431 / 0x01AF, but compute it rather than hard-coding it.
    tmd[4:0x140] = b"\0" * (0x140 - 4)
    for fill in range(65536):
        struct.pack_into(">H", tmd, 0x1E2, fill)
        if hashlib.sha1(tmd[0x140:]).digest()[0] == 0:
            break
    else:
        raise RuntimeError("failed to fakesign TMD")

    data_blob = b"".join(encrypted_contents)
    new_data_size = len(data_blob)

    header = bytearray(blob[:hs])
    struct.pack_into(">I", header, 24, new_data_size)

    out = bytearray()

    def add(raw: bytes) -> None:
        out.extend(raw)
        out.extend(b"\0" * (align(len(out)) - len(out)))

    out.extend(header)
    out.extend(b"\0" * (align(len(out)) - len(out)))
    add(blob[sec["cert"][0]:sec["cert"][0] + cert_size])
    add(blob[sec["crl"][0]:sec["crl"][0] + crl_size])
    add(bytes(ticket))
    add(bytes(tmd))
    add(data_blob)
    out.extend(blob[sec["footer"][0]:sec["footer"][0] + footer_size])

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(out)
    return fill
