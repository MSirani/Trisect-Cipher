#!/usr/bin/env python3
"""Trisect-Cipher: authenticated file encryption with 3-of-3 XOR secret sharing."""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import struct
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_NAME = "Trisect-Cipher"
FORMAT_MAGIC = b"TRISECT1"
KEY_MAGIC = b"TCKEY001"
KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024
READ_SIZE = 1024 * 1024
AAD_PREFIX = b"Trisect-Cipher:v1:"


class TrisectError(Exception):
    """Expected application error."""


def _write_private(path: Path, data: bytes) -> None:
    """Create a new file without overwriting an existing path."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    except Exception:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise


def _xor_bytes(a: bytes, b: bytes, c: bytes) -> bytes:
    if not (len(a) == len(b) == len(c)):
        raise TrisectError("Internal error: share blocks have different lengths.")
    return bytes(x ^ y ^ z for x, y, z in zip(a, b, c))


def _write_shared_block(
    data: bytes, share1: BinaryIO, share2: BinaryIO, share3: BinaryIO
) -> None:
    """Write one 3-of-3 XOR sharing block."""
    random1 = secrets.token_bytes(len(data))
    random2 = secrets.token_bytes(len(data))
    random3 = _xor_bytes(data, random1, random2)
    share1.write(random1)
    share2.write(random2)
    share3.write(random3)


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise TrisectError("Invalid or truncated encrypted payload.")
    return data


def _load_key(key_path: Path) -> bytes:
    try:
        raw = key_path.read_bytes()
    except OSError as exc:
        raise TrisectError(f"Cannot read key file: {exc}") from exc
    if len(raw) != len(KEY_MAGIC) + KEY_SIZE or not raw.startswith(KEY_MAGIC):
        raise TrisectError("Invalid key file or unsupported key-file format.")
    return raw[len(KEY_MAGIC):]


def _aad(index: int, plaintext_length: int) -> bytes:
    return AAD_PREFIX + struct.pack(">QI", index, plaintext_length)


def split_file(input_path: Path, prefix: Path, key_path: Path | None = None) -> tuple[Path, Path, Path, Path]:
    """Encrypt input in authenticated chunks and split the encrypted stream into 3 shares."""
    if not input_path.is_file():
        raise TrisectError(f"Input file does not exist or is not a regular file: {input_path}")

    part_paths = tuple(Path(f"{prefix}_part{i}.bin") for i in (1, 2, 3))
    key_path = key_path or Path(f"{prefix}_key.bin")
    all_outputs = [*part_paths, key_path]
    if len({p.resolve() for p in all_outputs}) != 4:
        raise TrisectError("Output paths must be four distinct files.")
    for path in all_outputs:
        if path.exists():
            raise TrisectError(f"Refusing to overwrite existing file: {path}")

    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    created: list[Path] = []

    try:
        streams = []
        for path in part_paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            streams.append(path.open("xb"))
            created.append(path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

        with input_path.open("rb") as source:
            # The format marker is itself protected by the 3-of-3 shares.
            _write_shared_block(FORMAT_MAGIC, *streams)
            index = 0
            while True:
                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break
                nonce = secrets.token_bytes(NONCE_SIZE)
                ciphertext = aesgcm.encrypt(nonce, chunk, _aad(index, len(chunk)))
                record = struct.pack(">I", len(chunk)) + nonce + ciphertext
                _write_shared_block(record, *streams)
                index += 1

            # A zero-length record marks the end of the stream.
            _write_shared_block(struct.pack(">I", 0), *streams)

        for stream in streams:
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()

        key_path.parent.mkdir(parents=True, exist_ok=True)
        _write_private(key_path, KEY_MAGIC + key)
        created.append(key_path)
        return (*part_paths, key_path)
    except Exception:
        for stream in locals().get("streams", []):
            try:
                stream.close()
            except Exception:
                pass
        for path in created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def _xor_share_files(p1: Path, p2: Path, p3: Path, destination: BinaryIO) -> None:
    try:
        sizes = [p.stat().st_size for p in (p1, p2, p3)]
    except OSError as exc:
        raise TrisectError(f"Cannot inspect share files: {exc}") from exc
    if not (sizes[0] == sizes[1] == sizes[2]):
        raise TrisectError("The three share files have different sizes.")
    if sizes[0] == 0:
        raise TrisectError("Share files are empty.")

    with p1.open("rb") as f1, p2.open("rb") as f2, p3.open("rb") as f3:
        remaining = sizes[0]
        while remaining:
            amount = min(READ_SIZE, remaining)
            a, b, c = f1.read(amount), f2.read(amount), f3.read(amount)
            if not (len(a) == len(b) == len(c) == amount):
                raise TrisectError("A share file was truncated while being read.")
            destination.write(_xor_bytes(a, b, c))
            remaining -= amount


def _decrypt_payload(payload_path: Path, key: bytes, output_stream: BinaryIO) -> None:
    aesgcm = AESGCM(key)
    with payload_path.open("rb") as source:
        if _read_exact(source, len(FORMAT_MAGIC)) != FORMAT_MAGIC:
            raise TrisectError("Invalid share combination or unsupported file format.")

        index = 0
        while True:
            raw_length = _read_exact(source, 4)
            plaintext_length = struct.unpack(">I", raw_length)[0]
            if plaintext_length == 0:
                if source.read(1):
                    raise TrisectError("Unexpected trailing data after end marker.")
                break
            if plaintext_length > CHUNK_SIZE:
                raise TrisectError("Invalid chunk length in encrypted payload.")

            nonce = _read_exact(source, NONCE_SIZE)
            ciphertext = _read_exact(source, plaintext_length + TAG_SIZE)
            try:
                plaintext = aesgcm.decrypt(
                    nonce, ciphertext, _aad(index, plaintext_length)
                )
            except Exception as exc:
                raise TrisectError(
                    f"Authentication failed for chunk {index}. Shares or key may be incorrect."
                ) from exc
            output_stream.write(plaintext)
            index += 1


def join_files(
    part1: Path, part2: Path, part3: Path, key_path: Path, output_path: Path
) -> Path:
    """Reconstruct shares, authenticate/decrypt chunks, and create output safely."""
    key = _load_key(key_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        raise TrisectError(f"Refusing to overwrite existing output: {output_path}")

    payload_tmp = None
    output_tmp = None
    reserved_output = False
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".trisect-payload-", dir=output_path.parent, delete=False
        ) as temp_payload:
            payload_tmp = Path(temp_payload.name)
            _xor_share_files(part1, part2, part3, temp_payload)

        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".trisect-output-", dir=output_path.parent, delete=False
        ) as temp_output:
            output_tmp = Path(temp_output.name)
            try:
                os.chmod(output_tmp, 0o600)
            except OSError:
                pass
            _decrypt_payload(payload_tmp, key, temp_output)
            temp_output.flush()
            os.fsync(temp_output.fileno())

        # Reserve the destination atomically so an existing file is never replaced.
        fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        reserved_output = True
        os.replace(output_tmp, output_path)
        output_tmp = None
        reserved_output = False
        return output_path
    except FileExistsError as exc:
        raise TrisectError(f"Refusing to overwrite existing output: {output_path}") from exc
    finally:
        for temp_path in (payload_tmp, output_tmp):
            if temp_path:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
        if reserved_output:
            try:
                output_path.unlink(missing_ok=True)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trisect-cipher",
        description="Encrypt a file with AES-256-GCM and split it into three XOR shares.",
        epilog="Keep all three shares and the key file in separate secure locations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    split_parser = subparsers.add_parser("split", help="Encrypt and create three shares.")
    split_parser.add_argument("input", type=Path, help="Input file.")
    split_parser.add_argument("prefix", type=Path, help="Output prefix for the three shares.")
    split_parser.add_argument(
        "--key-out", type=Path, default=None,
        help="Key-file path (default: PREFIX_key.bin).",
    )

    join_parser = subparsers.add_parser("join", help="Reconstruct and decrypt a file.")
    join_parser.add_argument("part1", type=Path)
    join_parser.add_argument("part2", type=Path)
    join_parser.add_argument("part3", type=Path)
    join_parser.add_argument("key", type=Path, help="Path to the separate key file.")
    join_parser.add_argument("output", type=Path, help="Reconstructed output file.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "split":
            paths = split_file(args.input, args.prefix, args.key_out)
            print("[+] Encryption and 3-of-3 splitting completed.")
            for path in paths[:3]:
                print(f"[+] Share: {path}")
            print(f"[+] Key file: {paths[3]}")
            print("[!] Store each share and the key independently. Do not keep them together.")
        else:
            result = join_files(
                args.part1, args.part2, args.part3, args.key, args.output
            )
            print(f"[+] File successfully authenticated and restored: {result}")
        return 0
    except (TrisectError, OSError) as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
