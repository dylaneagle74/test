from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Dict

from Crypto.Cipher import AES

ALIGNMENT = 0x40
AES_BLOCK = 0x10
WII_COMMON_KEY = bytes.fromhex("ebe42a225e8593e448d9c5457381aaf7")
NACE_TITLE_ID = bytes.fromhex("000100014e414345")
SIGNED_BLOB_TYPES = {0x00010000, 0x00010001, 0x00010002}


def align(value: int, boundary: int = ALIGNMENT) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def _be32(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def _be16(data: bytes, off: int) -> int:
    return struct.unpack_from(">H", data, off)[0]


def _be64(data: bytes, off: int) -> int:
    return struct.unpack_from(">Q", data, off)[0]


def _looks_like_signed_title_section(
    blob: bytes,
    offset: int,
    size: int,
    title_id_offset: int,
) -> bool:
    if offset < 0 or offset % ALIGNMENT != 0:
        return False
    if size <= title_id_offset + 8 or offset + size > len(blob):
        return False
    try:
        signature_type = _be32(blob, offset)
    except struct.error:
        return False
    return (
        signature_type in SIGNED_BLOB_TYPES
        and blob[offset + title_id_offset : offset + title_id_offset + 8] == NACE_TITLE_ID
    )


def _locate_signed_title_section(
    blob: bytes,
    expected_offset: int,
    size: int,
    title_id_offset: int,
    label: str,
) -> int:
    """Locate a signed ticket/TMD section and reject accidental header misalignment.

    The exact clean NACE WAD is enforced by the GUI before this code is called, but
    keeping a title-ID/signature check here makes failures deterministic and avoids
    treating arbitrary bytes as a ticket (which was the cause of the old key-index
    205 error).
    """
    if _looks_like_signed_title_section(blob, expected_offset, size, title_id_offset):
        return expected_offset

    search_from = 0
    while True:
        title_pos = blob.find(NACE_TITLE_ID, search_from)
        if title_pos < 0:
            break
        candidate = title_pos - title_id_offset
        if _looks_like_signed_title_section(blob, candidate, size, title_id_offset):
            return candidate
        search_from = title_pos + 1

    raise ValueError(
        f"Could not locate the NACE {label} section. "
        f"Expected a signed section near WAD offset 0x{expected_offset:X}."
    )


def parse_wad(blob: bytes):
    if len(blob) < 0x40:
        raise ValueError("WAD is too small")

    header_size = _be32(blob, 0x00)
    wad_type = blob[0x04:0x06]
    wad_version = _be16(blob, 0x06)
    cert_size = _be32(blob, 0x08)
    reserved = _be32(blob, 0x0C)
    ticket_size = _be32(blob, 0x10)
    tmd_size = _be32(blob, 0x14)
    data_size = _be32(blob, 0x18)
    footer_size = _be32(blob, 0x1C)

    if header_size != 0x20:
        raise ValueError(f"Unsupported installable WAD header size: 0x{header_size:X}")
    if wad_type != b"Is":
        raise ValueError(f"Unsupported WAD type: {wad_type!r}")
    if wad_version != 0:
        raise ValueError(f"Unsupported WAD version: {wad_version}")
    if reserved != 0:
        raise ValueError(f"Unsupported nonzero WAD reserved field: 0x{reserved:X}")

    # Installable WAD order is header -> certificate chain -> ticket -> TMD -> data -> footer.
    # Every section begins on a 0x40-byte boundary. 0x0C in the header is reserved;
    # it is not a CRL-size field.
    cert_off = align(header_size)
    expected_ticket_off = align(cert_off + cert_size)
    ticket_off = _locate_signed_title_section(
        blob, expected_ticket_off, ticket_size, 0x1DC, "ticket"
    )

    expected_tmd_off = align(ticket_off + ticket_size)
    tmd_off = _locate_signed_title_section(
        blob, expected_tmd_off, tmd_size, 0x18C, "TMD"
    )

    if tmd_off < ticket_off + ticket_size:
        raise ValueError("TMD overlaps the ticket section")

    data_off = align(tmd_off + tmd_size)
    footer_off = align(data_off + data_size)

    if data_off > len(blob) or footer_off + footer_size > len(blob):
        raise ValueError("WAD sections extend beyond end of file")

    return {
        "header": (0, header_size),
        "cert": (cert_off, cert_size),
        "ticket": (ticket_off, ticket_size),
        "tmd": (tmd_off, tmd_size),
        "data": (data_off, data_size),
        "footer": (footer_off, footer_size),
    }


def content_records(tmd: bytes):
    if len(tmd) < 0x1E4:
        raise ValueError("TMD is too small")
    if _be32(tmd, 0) not in SIGNED_BLOB_TYPES:
        raise ValueError("TMD has an unsupported signature type")
    if tmd[0x18C:0x194] != NACE_TITLE_ID:
        raise ValueError("TMD title ID is not NACE")

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
    if _be32(ticket, 0) not in SIGNED_BLOB_TYPES:
        raise ValueError("Ticket has an unsupported signature type")

    title_id = ticket[0x1DC:0x1E4]
    if title_id != NACE_TITLE_ID:
        raise ValueError(
            "Ticket title ID mismatch: expected NACE "
            f"({NACE_TITLE_ID.hex()}), found {title_id.hex()}"
        )

    common_key_index = ticket[0x1F1]
    if common_key_index != 0:
        raise ValueError(
            f"Unsupported Wii common-key index: {common_key_index} "
            "(the supported USA/NACE ticket must use common key index 0)"
        )

    encrypted_title_key = ticket[0x1BF:0x1CF]
    iv = title_id + (b"\0" * 8)
    return AES.new(WII_COMMON_KEY, AES.MODE_CBC, iv).decrypt(encrypted_title_key)


def _decrypt_contents(blob: bytes):
    sec = parse_wad(blob)
    ticket_off, ticket_size = sec["ticket"]
    tmd_off, tmd_size = sec["tmd"]
    data_off, _ = sec["data"]
    ticket = blob[ticket_off : ticket_off + ticket_size]
    tmd = blob[tmd_off : tmd_off + tmd_size]

    if ticket[0x1DC:0x1E4] != tmd[0x18C:0x194]:
        raise ValueError("Ticket and TMD title IDs do not match")

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

    for name in ("cert", "ticket", "tmd", "footer"):
        off, size = sec[name]
        (outdir / f"{name}.bin").write_bytes(blob[off : off + size])
    return contents


def _append_aligned(out: bytearray, payload: bytes, boundary: int = ALIGNMENT):
    out.extend(payload)
    pad = (-len(out)) & (boundary - 1)
    if pad:
        out.extend(b"\0" * pad)


def repack(
    base_wad: Path | str,
    replacements: Dict[int, Path | str],
    output_wad: Path | str,
):
    base_wad = Path(base_wad)
    output_wad = Path(output_wad)
    blob = base_wad.read_bytes()
    sec, _ticket, tmd_original, title_key, contents = _decrypt_contents(blob)
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

    # Preserve the original header/certificate/ticket/TMD padding bytes verbatim.
    # Only the header data-size field and the TMD content records need to change.
    data_off, _old_data_size = sec["data"]
    tmd_off, tmd_size = sec["tmd"]
    if len(tmd) != tmd_size:
        raise ValueError("Unexpected TMD size change")

    prefix = bytearray(blob[:data_off])
    struct.pack_into(">I", prefix, 0x14, len(tmd))
    struct.pack_into(">I", prefix, 0x18, len(encrypted_data))
    prefix[tmd_off : tmd_off + len(tmd)] = tmd

    footer_off, footer_size = sec["footer"]
    footer = blob[footer_off : footer_off + footer_size]

    out = bytearray(prefix)
    out.extend(encrypted_data)
    pad = (-len(out)) & (ALIGNMENT - 1)
    if pad:
        out.extend(b"\0" * pad)
    out.extend(footer)

    output_wad.parent.mkdir(parents=True, exist_ok=True)
    output_wad.write_bytes(out)
    return output_wad
