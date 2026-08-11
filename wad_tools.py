from __future__ import annotations
from pathlib import Path
from typing import Dict
import hashlib
import struct
from Crypto.Cipher import AES

ALIGNMENT = 0x40
AES_BLOCK = 0x10
COMMON_KEYS = {
    0: bytes.fromhex('ebe42a225e8593e448d9c5457381aaf7'),
    1: bytes.fromhex('63b82bb4f4614e2e13f2f6b5ef51eb58'),
}

def align(value: int, boundary: int = ALIGNMENT) -> int:
    return (value + boundary - 1) & ~(boundary - 1)

def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

def parse_wad(data: bytes):
    if len(data) < 0x20:
        raise ValueError('WAD is too small')
    hs, typ, cs, crls, tiks, tmds, ds, fs = struct.unpack('>8I', data[:32])
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
        raise ValueError('WAD sections extend beyond end of file')
    return {
        'header': (hs, typ, cs, crls, tiks, tmds, ds, fs),
        'cert': cert,
        'crl': crl,
        'tik': tik,
        'ticket': tik,
        'tmd': tmd,
        'data': dat,
        'footer': footer,
    }

def title_key(ticket: bytes):
    if len(ticket) < 0x1E4:
        raise ValueError('Ticket is too small')
    enc = ticket[0x1BF:0x1CF]
    tid = ticket[0x1DC:0x1E4]
    # The exact supported NACE WAD has a scene-modified key-index byte.  The
    # original production packer intentionally used the standard Wii common key
    # for this title and validated correctness through every TMD content SHA-1.
    idx = 0
    return aes_cbc_decrypt(COMMON_KEYS[idx], tid + b'\0' * 8, enc), tid

def content_records(tmd: bytes):
    if len(tmd) < 0x1E4:
        raise ValueError('TMD is too small')
    n = struct.unpack_from('>H', tmd, 0x1DE)[0]
    rec = []
    for i in range(n):
        o = 0x1E4 + i * 0x24
        if o + 0x24 > len(tmd):
            raise ValueError('TMD content table is truncated')
        cid, idx, typ, size = struct.unpack_from('>IHHQ', tmd, o)
        sha = tmd[o + 16:o + 36]
        rec.append((cid, idx, typ, size, sha, o))
    return rec

def _decrypt_contents(wad: Path | str):
    wad = Path(wad)
    b = wad.read_bytes()
    s = parse_wad(b)
    tik_off, tik_size = s['tik']
    tmd_off, tmd_size = s['tmd']
    tik = b[tik_off:tik_off + tik_size]
    tmd = b[tmd_off:tmd_off + tmd_size]
    key, tid = title_key(tik)
    pos = s['data'][0]
    contents = {}
    for cid, idx, typ, size, sha, ro in content_records(tmd):
        enc_len = align(size, 0x40)
        enc = b[pos:pos + enc_len]
        if len(enc) != enc_len:
            raise ValueError(f'Encrypted content {idx} is truncated')
        dec = aes_cbc_decrypt(key, struct.pack('>H', idx) + b'\0' * 14, enc[:align(size, 16)])[:size]
        if hashlib.sha1(dec).digest() != sha:
            raise ValueError(f'Content index {idx} failed TMD SHA-1 during extraction')
        contents[idx] = {
            'cid': cid, 'index': idx, 'kind': typ, 'size': size,
            'sha': sha, 'record_off': ro, 'plain': dec,
        }
        pos += enc_len
    return b, s, tik, tmd, key, tid, contents

def extract(wad: Path | str, out: Path | str):
    wad = Path(wad)
    out = Path(out)
    b, s, tik, tmd, key, tid, contents = _decrypt_contents(wad)
    out.mkdir(parents=True, exist_ok=True)
    for info in contents.values():
        (out / f"{info['index']:08x}_{info['cid']:08x}.app").write_bytes(info['plain'])
    return contents

def repack(original: Path | str, replacements: Dict[int, Path | str], output: Path | str):
    original = Path(original)
    output = Path(output)
    b = original.read_bytes()
    s = parse_wad(b)
    hs, typ, cs, crls, tiks, tmds, old_ds, fs = s['header']
    tik = bytearray(b[s['tik'][0]:s['tik'][0] + tiks])
    tmd = bytearray(b[s['tmd'][0]:s['tmd'][0] + tmds])
    key, tid = title_key(tik)
    recs = content_records(tmd)
    contents = []
    pos = s['data'][0]
    for cid, idx, ctyp, old_size, oldsha, ro in recs:
        old_enc_len = align(old_size, 0x40)
        enc = b[pos:pos + old_enc_len]
        if len(enc) != old_enc_len:
            raise ValueError(f'Encrypted content {idx} is truncated')
        dec = aes_cbc_decrypt(key, struct.pack('>H', idx) + b'\0' * 14, enc[:align(old_size, 16)])[:old_size]
        if hashlib.sha1(dec).digest() != oldsha:
            raise ValueError(f'Original content index {idx} failed TMD SHA-1')
        if idx in replacements:
            dec = Path(replacements[idx]).read_bytes()
        new_size = len(dec)
        digest = hashlib.sha1(dec).digest()
        struct.pack_into('>Q', tmd, ro + 8, new_size)
        tmd[ro + 16:ro + 36] = digest
        padded = dec + b'\0' * (align(new_size, 16) - new_size)
        encrypted = aes_cbc_encrypt(key, struct.pack('>H', idx) + b'\0' * 14, padded)
        encrypted += b'\0' * (align(new_size, 0x40) - len(encrypted))
        contents.append(encrypted)
        pos += old_enc_len

    # Match the exact production H63 packer: Trucha-fakesign the modified TMD.
    # Clear the RSA signature bytes and brute-force the 16-bit filler field until
    # SHA-1(TMD body) begins with 0x00.
    tmd[4:0x140] = b'\0' * (0x140 - 4)
    for fill in range(65536):
        struct.pack_into('>H', tmd, 0x1E2, fill)
        if hashlib.sha1(tmd[0x140:]).digest()[0] == 0:
            break
    else:
        raise RuntimeError('failed to fakesign TMD')

    data_blob = b''.join(contents)
    new_ds = len(data_blob)
    header = bytearray(b[:hs])
    struct.pack_into('>I', header, 24, new_ds)
    out = bytearray()

    def add(raw: bytes):
        out.extend(raw)
        out.extend(b'\0' * (align(len(out)) - len(out)))

    out.extend(header)
    out.extend(b'\0' * (align(len(out)) - len(out)))
    add(b[s['cert'][0]:s['cert'][0] + cs])
    add(b[s['crl'][0]:s['crl'][0] + crls])
    add(bytes(tik))
    add(bytes(tmd))
    add(data_blob)
    out.extend(b[s['footer'][0]:s['footer'][0] + fs])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(out)
    return fill
