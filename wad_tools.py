from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Dict, Iterable, Tuple

from Crypto.Cipher import AES

ALIGNMENT = 0x40
AES_BLOCK = 0x10
WII_COMMON_KEY = bytes.fromhex("ebe42a225e8593e448d9c5457381aaf7")


def align(value: int, boundary: int = ALIGNMENT) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def _be32(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def _be16(data: bytes, off: int) -> int:
    return struct.unpack_from(">H", data, off)[0]


def _be64(data: bytes, off: int) -> int:
    return struct.unpack_from(">Q", data, off)[0]


def parse_wad(blob: bytes):
    if len(blob) < 0x20:
        raise ValueError("WAD is too small")
    header_size = _be32(blob, 0x00)
    cert_size = _be32(blob, 0x08)
    crl_size = _be32(blob, 0x0C)
    ticket_size = _be32(blob, 0x10)
    tmd_size = _be32(blob, 0x14)
    data_size = _be32(blob, 0x18)
    footer_size = _be32(blob, 0x1C)

    cert_off = align(header_size)
    crl_off = align(cert_off + cert_size)
    ticket_off = align(crl_off + crl_size)
    tmd_off = align(ticket_off + ticket_size)
    data_off = align(tmd_off + tmd_size)
    footer_off = align(data_off + data_size)

    if footer_off + footer_size > len(blob):
        raise ValueError("WAD sections extend beyond end of file")

    return {
        "header": (0, header_size),
        "cert": (cert_off, cert_size),
        "crl": (crl_off, crl_size),
        "ticket": (ticket_off, ticket_size),
        "tmd": (tmd_off, tmd_size),
        "data": (data_off, data_size),
        "footer": (footer_off, footer_size),
    }


def content_records(tmd: bytes):
    if len(tmd) < 0x1E4:
        raise ValueError("TMD is too small")
    count = _be16(tmd, 0x1DE)
    pos = 0x1E4
    for _ in range(count):
        if pos + 0x24 > len(tmd):
            raise ValueError("TMD content table is truncated")
        cid, index, kind = struct.unpack_from(">IHH", tmd, pos)
        size = _be64(tmd, pos + 8)
        sha = tmd[pos + 0x10 : pos + 0x24]
        yield cid, index, kind, size, sha, pos
        pos += 0x24


def _ticket_title_key(ticket: bytes) -> bytes:
    if len(ticket) < 0x1F2:
        raise ValueError("Ticket is too small")
    common_key_index = ticket[0x1F1]
    if common_key_index != 0:
        raise ValueError(f"Unsupported Wii common-key index: {common_key_index}")
    encrypted_title_key = ticket[0x1BF : 0x1CF]
    title_id = ticket[0x1DC : 0x1E4]
    iv = title_id + (b"\0" * 8)
    return AES.new(WII_COMMON_KEY, AES.MODE_CBC, iv).decrypt(encrypted_title_key)


def _decrypt_contents(blob: bytes):
    sec = parse_wad(blob)
    ticket_off, ticket_size = sec["ticket"]
    tmd_off, tmd_size = sec["tmd"]
    data_off, _ = sec["data"]
    ticket = blob[ticket_off : ticket_off + ticket_size]
    tmd = blob[tmd_off : tmd_off + tmd_size]
    title_key = _ticket_title_key(ticket)

    contents = {}
    cursor = data_off
    for cid, index, kind, size, sha, record_off in content_records(tmd):
        encrypted_size = align(size, AES_BLOCK)
        encrypted = blob[cursor : cursor + encrypted_size]
        if len(encrypted) != encrypted_size:
            raise ValueError(f"Encrypted content {index} is truncated")
        iv = index.to_bytes(2, "big") + (b"\0" * 14)
        plain_padded = AES.new(title_key, AES.MODE_CBC, iv).decrypt(encrypted)
        plain = plain_padded[:size]
        if hashlib.sha1(plain).digest() != sha:
            raise ValueError(f"Content index {index} failed TMD SHA-1 during extraction")
        contents[index] = {
            "cid": cid,
            "index": index,
            "kind": kind,
            "size": size,
            "sha": sha,
            "record_off": record_off,
            "plain": plain,
        }
        cursor = align(cursor + encrypted_size)
    return sec, ticket, tmd, title_key, contents


def extract(wad_path: Path | str, outdir: Path | str):
    wad_path = Path(wad_path)
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    blob = wad_path.read_bytes()
    sec, _ticket, _tmd, _title_key, contents = _decrypt_contents(blob)

    for info in contents.values():
        name = f"{info['index']:08x}_{info['cid']:08x}.app"
        (outdir / name).write_bytes(info["plain"])

    for name in ("cert", "crl", "ticket", "tmd", "footer"):
        off, size = sec[name]
        (outdir / f"{name}.bin").write_bytes(blob[off : off + size])
    return contents


def _append_aligned(out: bytearray, payload: bytes, boundary: int = ALIGNMENT):
    out.extend(payload)
    pad = (-len(out)) & (boundary - 1)
    if pad:
        out.extend(b"\0" * pad)


def repack(base_wad: Path | str, replacements: Dict[int, Path | str], output_wad: Path | str):
    base_wad = Path(base_wad)
    output_wad = Path(output_wad)
    blob = base_wad.read_bytes()
    sec, ticket, tmd_original, title_key, contents = _decrypt_contents(blob)
    tmd = bytearray(tmd_original)

    replacement_bytes = {}
    for index, path in replacements.items():
        if index not in contents:
            raise ValueError(f"WAD has no content index {index}")
        replacement_bytes[index] = Path(path).read_bytes()

    encrypted_data = bytearray()
    for cid, index, kind, old_size, old_sha, record_off in content_records(bytes(tmd)):
        plain = replacement_bytes.get(index, contents[index]["plain"])
        new_size = len(plain)
        new_sha = hashlib.sha1(plain).digest()
        struct.pack_into(">Q", tmd, record_off + 8, new_size)
        tmd[record_off + 0x10 : record_off + 0x24] = new_sha

        padded_size = align(new_size, AES_BLOCK)
        padded = plain + (b"\0" * (padded_size - new_size))
        iv = index.to_bytes(2, "big") + (b"\0" * 14)
        encrypted = AES.new(title_key, AES.MODE_CBC, iv).encrypt(padded)
        _append_aligned(encrypted_data, encrypted)

    header_size = sec["header"][1]
    header = bytearray(blob[:header_size])
    struct.pack_into(">I", header, 0x14, len(tmd))
    struct.pack_into(">I", header, 0x18, len(encrypted_data))

    cert_off, cert_size = sec["cert"]
    crl_off, crl_size = sec["crl"]
    footer_off, footer_size = sec["footer"]
    cert = blob[cert_off : cert_off + cert_size]
    crl = blob[crl_off : crl_off + crl_size]
    footer = blob[footer_off : footer_off + footer_size]

    out = bytearray()
    _append_aligned(out, bytes(header))
    _append_aligned(out, cert)
    _append_aligned(out, crl)
    _append_aligned(out, ticket)
    _append_aligned(out, bytes(tmd))
    _append_aligned(out, bytes(encrypted_data))
    out.extend(footer)

    output_wad.parent.mkdir(parents=True, exist_ok=True)
    output_wad.write_bytes(out)
    return output_wad
