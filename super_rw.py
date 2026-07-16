#!/usr/bin/env python3
"""Unpack, grow, mount, shrink, and repack Android dynamic-partition super images.

The tool is intentionally conservative around Virtual A/B snapshot COW data:
COW partitions are opaque payloads.  They are never treated as filesystems,
resized, fscked, or mounted.

Run this script under Linux (native Linux or WSL2), not Windows Python.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Sequence


SCRIPT_VERSION = "1.1.2"
MANIFEST_VERSION = 1
MANIFEST_NAME = "super_rw_manifest.json"

ANDROID_SPARSE_MAGIC = 0xED26FF3A
LP_GEOMETRY_MAGIC = 0x616C4467
LP_HEADER_MAGIC = 0x414C5030
LP_RESERVED_BYTES = 4096
LP_GEOMETRY_SIZE = 4096
LP_SECTOR_SIZE = 512
LP_GEOMETRY_STRUCT_SIZE = 52

LP_ATTR_READONLY = 1 << 0
LP_ATTR_SLOT_SUFFIXED = 1 << 1
LP_ATTR_UPDATED = 1 << 2
LP_ATTR_DISABLED = 1 << 3
LP_GROUP_SLOT_SUFFIXED = 1 << 0
LP_BLOCK_DEVICE_SLOT_SUFFIXED = 1 << 0

COW_MAGIC = 0x436F77634F572121
EXT4_MAGIC = 0xEF53
EROFS_MAGIC = 0xE0F5E1E2
F2FS_MAGIC = 0xF2F52010
SQUASHFS_MAGIC = 0x73717368


class SuperRwError(RuntimeError):
    pass


def info(message: str) -> None:
    print(f"[+] {message}", flush=True)


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr, flush=True)


def command_text(command: Sequence[object]) -> str:
    return shlex.join(str(item) for item in command)


def run(
    command: Sequence[object],
    *,
    capture: bool = False,
    ok_codes: Iterable[int] = (0,),
) -> subprocess.CompletedProcess[str]:
    cmd = [str(item) for item in command]
    info(f"$ {command_text(cmd)}")
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    result = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=env,
    )
    if result.returncode not in set(ok_codes):
        detail = ""
        if capture:
            detail = "\n" + (result.stdout or "") + (result.stderr or "")
        raise SuperRwError(
            f"Command failed with exit code {result.returncode}: "
            f"{command_text(cmd)}{detail}"
        )
    return result


def ensure_linux() -> None:
    if os.name != "posix" or not Path("/proc").exists():
        raise SuperRwError(
            "This operation must run under Linux or WSL2. Windows cannot loop-mount "
            "the extracted Linux filesystems writable."
        )


def require_tools(*names: str) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise SuperRwError(
            "Missing required tool(s) on PATH: " + ", ".join(missing)
        )


def parse_size(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?b?)?\s*", value, re.I)
    if not match:
        raise argparse.ArgumentTypeError(f"Invalid size: {value!r}")
    number = float(match.group(1))
    suffix = (match.group(2) or "").lower()
    powers = {
        "": 0,
        "b": 0,
        "k": 1,
        "kb": 1,
        "ki": 1,
        "kib": 1,
        "m": 2,
        "mb": 2,
        "mi": 2,
        "mib": 2,
        "g": 3,
        "gb": 3,
        "gi": 3,
        "gib": 3,
        "t": 4,
        "tb": 4,
        "ti": 4,
        "tib": 4,
    }
    if suffix not in powers:
        raise argparse.ArgumentTypeError(f"Invalid size suffix: {suffix!r}")
    result = int(number * (1024 ** powers[suffix]))
    if result < 0:
        raise argparse.ArgumentTypeError("Size cannot be negative")
    return result


def human_size(size: int) -> str:
    value = float(size)
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or suffix == "TiB":
            return f"{value:.1f} {suffix}" if suffix != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def round_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        raise SuperRwError(f"Invalid alignment: {alignment}")
    return (value + alignment - 1) // alignment * alignment


def lp_align_to(value: int, alignment: int, alignment_offset: int = 0) -> int:
    """Match liblp's AlignTo(base, alignment, alignment_offset)."""
    if not alignment:
        return value
    aligned = round_up(value, alignment) + alignment_offset
    if aligned >= alignment and aligned - alignment >= value:
        aligned -= alignment
    return aligned


def total_metadata_reserved(geometry: dict[str, int]) -> int:
    return LP_RESERVED_BYTES + 2 * (
        LP_GEOMETRY_SIZE
        + geometry["metadata_max_size"] * geometry["metadata_slot_count"]
    )


def lpmake_device_alignment(
    device: dict[str, Any], geometry: dict[str, int]
) -> tuple[int, int]:
    """Choose build-time alignment that reproduces first_logical_sector.

    Some live super metadata reports the kernel's current 512-byte alignment
    even though the metadata area was originally padded to a 1 MiB boundary.
    lpmake would otherwise shrink that reserved area. We use a stricter
    build-time alignment, then restore the exact reported table values after
    lpmake has safely placed all extents beyond the original boundary.
    """
    expected_first = device["first_logical_sector"] * LP_SECTOR_SIZE
    reserved = total_metadata_reserved(geometry)
    original_alignment = device["alignment"]
    original_offset = device["alignment_offset"]
    effective_alignment = original_alignment or geometry["logical_block_size"]
    if lp_align_to(reserved, effective_alignment, original_offset) == expected_first:
        return original_alignment, original_offset

    if expected_first < reserved:
        raise SuperRwError(
            f"Original first logical sector for {device['raw_name']} overlaps its "
            "metadata reservation"
        )
    if expected_first > 0xFFFFFFFF:
        raise SuperRwError(
            f"Cannot reproduce first logical sector for {device['raw_name']}: "
            f"required build alignment {expected_first} exceeds lpmake's 32-bit field"
        )
    if lp_align_to(reserved, expected_first, 0) != expected_first:
        raise SuperRwError(
            f"Cannot derive a safe lpmake alignment for {device['raw_name']}"
        )
    info(
        f"Using temporary lpmake alignment {expected_first} for "
        f"{device['raw_name']} to preserve first logical sector "
        f"{device['first_logical_sector']}; reported alignment "
        f"{original_alignment} will be restored afterward"
    )
    return expected_first, 0


def lpdump_report_command(
    raw_super: Path, metadata_slot_count: int, selected_slot: int
) -> list[object]:
    # Current AOSP SlotSuffixForSlotNumber supports only slots 0 and 1 and
    # aborts when `lpdump --all` reaches a third reserved metadata slot.
    if metadata_slot_count > 2:
        return ["lpdump", f"--slot={selected_slot}", raw_super]
    return ["lpdump", "--all", raw_super]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(8 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def fixed_string(value: bytes) -> str:
    return value.split(b"\0", 1)[0].decode("ascii", errors="strict")


def is_android_sparse(path: Path) -> bool:
    with path.open("rb") as stream:
        data = stream.read(4)
    return len(data) == 4 and struct.unpack("<I", data)[0] == ANDROID_SPARSE_MAGIC


def android_sparse_block_size(path: Path) -> int | None:
    with path.open("rb") as stream:
        header = stream.read(16)
    if len(header) < 16 or struct.unpack_from("<I", header, 0)[0] != ANDROID_SPARSE_MAGIC:
        return None
    block_size = struct.unpack_from("<I", header, 12)[0]
    if block_size < 1024 or block_size % 4:
        raise SuperRwError(f"Invalid Android sparse block size: {block_size}")
    return block_size


def _validate_geometry_blob(blob: bytes) -> dict[str, int]:
    if len(blob) < LP_GEOMETRY_STRUCT_SIZE:
        raise SuperRwError("Truncated LP geometry")
    magic, struct_size = struct.unpack_from("<II", blob, 0)
    if magic != LP_GEOMETRY_MAGIC:
        raise SuperRwError(f"Invalid LP geometry magic: 0x{magic:08x}")
    if struct_size != LP_GEOMETRY_STRUCT_SIZE:
        raise SuperRwError(f"Unsupported LP geometry size: {struct_size}")
    check = bytearray(blob[:struct_size])
    stored_checksum = bytes(check[8:40])
    check[8:40] = b"\0" * 32
    if hashlib.sha256(check).digest() != stored_checksum:
        raise SuperRwError("LP geometry checksum is invalid")
    metadata_max_size, slot_count, logical_block_size = struct.unpack_from(
        "<III", blob, 40
    )
    if metadata_max_size <= 0 or metadata_max_size % LP_SECTOR_SIZE:
        raise SuperRwError("Invalid LP metadata maximum size")
    if slot_count <= 0:
        raise SuperRwError("Invalid LP metadata slot count")
    if logical_block_size <= 0 or logical_block_size % LP_SECTOR_SIZE:
        raise SuperRwError("Invalid LP logical block size")
    return {
        "metadata_max_size": metadata_max_size,
        "metadata_slot_count": slot_count,
        "logical_block_size": logical_block_size,
    }


def read_geometry(stream: Any) -> dict[str, int]:
    errors: list[str] = []
    for offset, label in (
        (LP_RESERVED_BYTES, "primary"),
        (LP_RESERVED_BYTES + LP_GEOMETRY_SIZE, "backup"),
    ):
        stream.seek(offset)
        blob = stream.read(LP_GEOMETRY_SIZE)
        try:
            geometry = _validate_geometry_blob(blob)
            geometry["source_offset"] = offset
            return geometry
        except SuperRwError as exc:
            errors.append(f"{label}: {exc}")
    raise SuperRwError("Could not read valid LP geometry (" + "; ".join(errors) + ")")


def _table_descriptor(header: bytes, offset: int) -> dict[str, int]:
    table_offset, entries, entry_size = struct.unpack_from("<III", header, offset)
    return {"offset": table_offset, "num_entries": entries, "entry_size": entry_size}


def _validate_table_bounds(
    descriptor: dict[str, int], tables_size: int, expected_entry_size: int, label: str
) -> None:
    if descriptor["entry_size"] != expected_entry_size:
        raise SuperRwError(
            f"Unsupported {label} entry size {descriptor['entry_size']} "
            f"(expected {expected_entry_size})"
        )
    length = descriptor["num_entries"] * descriptor["entry_size"]
    if descriptor["offset"] > tables_size or length > tables_size - descriptor["offset"]:
        raise SuperRwError(f"Invalid {label} table bounds")


def parse_metadata_blob(blob: bytes) -> dict[str, Any]:
    if len(blob) < 128:
        raise SuperRwError("Truncated LP metadata header")
    magic, major, minor, header_size = struct.unpack_from("<IHHI", blob, 0)
    if magic != LP_HEADER_MAGIC:
        raise SuperRwError(f"Invalid LP metadata magic: 0x{magic:08x}")
    if header_size not in (128, 256):
        raise SuperRwError(f"Unsupported LP metadata header size: {header_size}")
    tables_size = struct.unpack_from("<I", blob, 44)[0]
    total = header_size + tables_size
    if total > len(blob):
        raise SuperRwError("Truncated LP metadata tables")

    header = bytes(blob[:header_size])
    header_check = bytearray(header)
    stored_header_checksum = bytes(header_check[12:44])
    header_check[12:44] = b"\0" * 32
    if hashlib.sha256(header_check).digest() != stored_header_checksum:
        raise SuperRwError("LP metadata header checksum is invalid")

    tables = bytes(blob[header_size:total])
    if hashlib.sha256(tables).digest() != bytes(header[48:80]):
        raise SuperRwError("LP metadata tables checksum is invalid")

    descriptors = {
        "partitions": _table_descriptor(header, 80),
        "extents": _table_descriptor(header, 92),
        "groups": _table_descriptor(header, 104),
        "block_devices": _table_descriptor(header, 116),
    }
    _validate_table_bounds(descriptors["partitions"], tables_size, 52, "partition")
    _validate_table_bounds(descriptors["extents"], tables_size, 24, "extent")
    _validate_table_bounds(descriptors["groups"], tables_size, 48, "group")
    _validate_table_bounds(descriptors["block_devices"], tables_size, 64, "block device")

    def entries(name: str) -> Iterable[tuple[int, bytes]]:
        descriptor = descriptors[name]
        for index in range(descriptor["num_entries"]):
            start = descriptor["offset"] + index * descriptor["entry_size"]
            end = start + descriptor["entry_size"]
            yield start, tables[start:end]

    partitions: list[dict[str, Any]] = []
    for _, entry in entries("partitions"):
        attrs, first_extent, extent_count, group_index = struct.unpack_from("<IIII", entry, 36)
        partitions.append(
            {
                "raw_name": fixed_string(entry[:36]),
                "attributes": attrs,
                "first_extent_index": first_extent,
                "num_extents": extent_count,
                "group_index": group_index,
            }
        )

    extents: list[dict[str, int]] = []
    for _, entry in entries("extents"):
        sectors, target_type, target_data, target_source = struct.unpack("<QIQI", entry)
        extents.append(
            {
                "num_sectors": sectors,
                "target_type": target_type,
                "target_data": target_data,
                "target_source": target_source,
            }
        )

    groups: list[dict[str, Any]] = []
    for _, entry in entries("groups"):
        flags, maximum_size = struct.unpack_from("<IQ", entry, 36)
        groups.append(
            {
                "raw_name": fixed_string(entry[:36]),
                "flags": flags,
                "maximum_size": maximum_size,
            }
        )

    block_devices: list[dict[str, Any]] = []
    for _, entry in entries("block_devices"):
        first_sector, alignment, alignment_offset, size = struct.unpack_from("<QIIQ", entry, 0)
        flags = struct.unpack_from("<I", entry, 60)[0]
        block_devices.append(
            {
                "raw_name": fixed_string(entry[24:60]),
                "first_logical_sector": first_sector,
                "alignment": alignment,
                "alignment_offset": alignment_offset,
                "size": size,
                "flags": flags,
            }
        )

    for partition in partitions:
        first = partition["first_extent_index"]
        count = partition["num_extents"]
        if first + count > len(extents):
            raise SuperRwError(f"Partition {partition['raw_name']} has invalid extents")
        if partition["group_index"] >= len(groups):
            raise SuperRwError(f"Partition {partition['raw_name']} has invalid group index")
        owned_extents = extents[first : first + count]
        for extent in owned_extents:
            if extent["target_type"] == 0 and extent["target_source"] >= len(block_devices):
                raise SuperRwError(
                    f"Partition {partition['raw_name']} has invalid block-device index"
                )
        partition["size"] = sum(item["num_sectors"] for item in owned_extents) * LP_SECTOR_SIZE
        partition["extents"] = owned_extents
        partition["group_raw"] = groups[partition["group_index"]]["raw_name"]

    flags = struct.unpack_from("<I", header, 128)[0] if header_size >= 132 else 0
    return {
        "major_version": major,
        "minor_version": minor,
        "header_size": header_size,
        "header_flags": flags,
        "tables_size": tables_size,
        "descriptors": descriptors,
        "partitions": partitions,
        "extents": extents,
        "groups": groups,
        "block_devices": block_devices,
    }


def metadata_offsets(geometry: dict[str, int], slot: int) -> tuple[int, int]:
    if slot < 0 or slot >= geometry["metadata_slot_count"]:
        raise SuperRwError(
            f"Metadata slot {slot} is outside 0..{geometry['metadata_slot_count'] - 1}"
        )
    start = LP_RESERVED_BYTES + LP_GEOMETRY_SIZE * 2
    maximum = geometry["metadata_max_size"]
    primary = start + maximum * slot
    backup = start + maximum * geometry["metadata_slot_count"] + maximum * slot
    return primary, backup


def read_metadata_slot(stream: Any, geometry: dict[str, int], slot: int) -> dict[str, Any]:
    errors: list[str] = []
    for offset, label in zip(metadata_offsets(geometry, slot), ("primary", "backup")):
        stream.seek(offset)
        blob = stream.read(geometry["metadata_max_size"])
        try:
            metadata = parse_metadata_blob(blob)
            metadata["source_offset"] = offset
            return metadata
        except SuperRwError as exc:
            errors.append(f"{label}: {exc}")
    raise SuperRwError(
        f"Could not read metadata slot {slot} (" + "; ".join(errors) + ")"
    )


def slot_suffix(slot: int) -> str:
    if slot < 0 or slot > 25:
        raise SuperRwError(f"Cannot create suffix for metadata slot {slot}")
    return "_" + chr(ord("a") + slot)


def apply_display_names(metadata: dict[str, Any], slot: int) -> None:
    suffix = slot_suffix(slot)
    group_names: dict[str, str] = {}
    for group in metadata["groups"]:
        group["name"] = group["raw_name"] + (
            suffix if group["flags"] & LP_GROUP_SLOT_SUFFIXED else ""
        )
        group_names[group["raw_name"]] = group["name"]
    for device in metadata["block_devices"]:
        device["name"] = device["raw_name"] + (
            suffix if device["flags"] & LP_BLOCK_DEVICE_SLOT_SUFFIXED else ""
        )
    for partition in metadata["partitions"]:
        partition["name"] = partition["raw_name"] + (
            suffix if partition["attributes"] & LP_ATTR_SLOT_SUFFIXED else ""
        )
        partition["group"] = group_names[partition["group_raw"]]


def metadata_fingerprint(metadata: dict[str, Any]) -> str:
    summary = {
        "version": [metadata["major_version"], metadata["minor_version"]],
        "header_flags": metadata["header_flags"],
        "partitions": [
            {
                "name": item["raw_name"],
                "attrs": item["attributes"],
                "group": item["group_raw"],
                "size": item["size"],
                "extents": item["extents"],
            }
            for item in metadata["partitions"]
        ],
        "groups": metadata["groups"],
        "block_devices": metadata["block_devices"],
    }
    encoded = json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def attribute_names(value: int) -> str:
    known = []
    for bit, name in (
        (LP_ATTR_READONLY, "readonly"),
        (LP_ATTR_SLOT_SUFFIXED, "slot-suffixed"),
        (LP_ATTR_UPDATED, "updated"),
        (LP_ATTR_DISABLED, "disabled"),
    ):
        if value & bit:
            known.append(name)
            value &= ~bit
    if value:
        known.append(f"unknown(0x{value:x})")
    return ",".join(known) if known else "none"


def classify_image(path: Path, raw_name: str, display_name: str) -> str:
    with path.open("rb") as stream:
        prefix = stream.read(8)
        stream.seek(1024)
        at_1024 = stream.read(64)

    cow_name = bool(
        re.search(r"(?:^|[-_.])cow(?:$|[-_.])", raw_name, re.I)
        or re.search(r"(?:^|[-_.])cow(?:$|[-_.])", display_name, re.I)
    )
    if cow_name or (len(prefix) >= 8 and struct.unpack("<Q", prefix)[0] == COW_MAGIC):
        return "android-cow"
    if len(at_1024) >= 58 and struct.unpack_from("<H", at_1024, 56)[0] == EXT4_MAGIC:
        return "ext4"
    if len(at_1024) >= 4:
        magic = struct.unpack_from("<I", at_1024, 0)[0]
        if magic == EROFS_MAGIC:
            return "erofs"
        if magic == F2FS_MAGIC:
            return "f2fs"
    if len(prefix) >= 4 and struct.unpack_from("<I", prefix, 0)[0] == SQUASHFS_MAGIC:
        return "squashfs"
    return "opaque"


def e2fsck(path: Path) -> None:
    result = run(["e2fsck", "-f", "-y", path], capture=True, ok_codes=range(256))
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    # e2fsck uses a bitmask. Bits 0 and 1 mean corrected/reboot-needed; an
    # offline image does not actually need a host reboot. Any higher bit is fatal.
    if result.returncode & ~3:
        raise SuperRwError(
            f"e2fsck failed for {path} with status {result.returncode}"
        )


def ext4_filesystem_size(path: Path) -> int:
    result = run(["dumpe2fs", "-h", path], capture=True)
    text = (result.stdout or "") + (result.stderr or "")
    count_match = re.search(r"^Block count:\s*(\d+)\s*$", text, re.M)
    size_match = re.search(r"^Block size:\s*(\d+)\s*$", text, re.M)
    if not count_match or not size_match:
        raise SuperRwError(f"Could not determine ext4 size for {path}")
    return int(count_match.group(1)) * int(size_match.group(1))


def ext4_features(path: Path) -> set[str]:
    result = run(["dumpe2fs", "-h", path], capture=True)
    text = (result.stdout or "") + (result.stderr or "")
    match = re.search(r"^Filesystem features:\s*(.*?)\s*$", text, re.M)
    if not match:
        raise SuperRwError(f"Could not determine ext4 features for {path}")
    return set(match.group(1).split())


def unshare_ext4_blocks(path: Path) -> bool:
    """Remove Android's shared_blocks RO_COMPAT feature for writable mounting."""
    if "shared_blocks" not in ext4_features(path):
        return False
    info(f"Unsharing Android shared blocks in {path.name} for writable mounting")
    result = run(
        ["e2fsck", "-f", "-y", "-E", "unshare_blocks", path],
        capture=True,
        ok_codes=range(256),
    )
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode & ~3:
        raise SuperRwError(
            f"Could not unshare ext4 blocks in {path}; e2fsck status "
            f"{result.returncode}. The image may need more temporary free space."
        )
    if "shared_blocks" in ext4_features(path):
        # Some distro e2fsprogs builds complete the duplicate-block scan but
        # leave the RO_COMPAT bit set when there were no actual shared blocks.
        # Since the unshare pass succeeded, clearing that stale bit is safe.
        warn(
            f"e2fsck left a stale shared_blocks feature bit on {path.name}; "
            "clearing it with debugfs"
        )
        run(["debugfs", "-w", "-R", "feature -shared_blocks", path])
        e2fsck(path)
    if "shared_blocks" in ext4_features(path):
        raise SuperRwError(f"Could not clear shared_blocks from {path}")
    return True


def grow_ext4(path: Path, grow_by: int, minimum_base_size: int = 0) -> None:
    e2fsck(path)
    old_size = path.stat().st_size
    new_size = round_up(max(old_size, minimum_base_size) + grow_by, 4096)
    info(f"Growing {path.name}: {human_size(old_size)} -> {human_size(new_size)}")
    with path.open("r+b") as stream:
        stream.truncate(new_size)
    run(["resize2fs", path])
    unshare_ext4_blocks(path)
    e2fsck(path)


def shrink_ext4(path: Path) -> int:
    e2fsck(path)
    run(["resize2fs", "-M", path])
    e2fsck(path)
    filesystem_size = ext4_filesystem_size(path)
    with path.open("r+b") as stream:
        stream.truncate(filesystem_size)
    e2fsck(path)
    return filesystem_size


def manifest_path(workspace: Path) -> Path:
    return workspace / MANIFEST_NAME


def save_manifest(workspace: Path, manifest: dict[str, Any]) -> None:
    path = manifest_path(workspace)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def load_manifest(workspace: Path) -> dict[str, Any]:
    path = manifest_path(workspace)
    if not path.is_file():
        raise SuperRwError(f"Manifest not found: {path}")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("manifest_version") != MANIFEST_VERSION:
        raise SuperRwError(
            f"Unsupported manifest version: {manifest.get('manifest_version')!r}"
        )
    return manifest


def partition_image(workspace: Path, partition: dict[str, Any]) -> Path:
    path = (workspace / partition["image"]).resolve()
    images_root = (workspace / "images").resolve()
    if path.parent != images_root:
        raise SuperRwError(f"Unsafe partition image path in manifest: {path}")
    return path


def _decode_findmnt(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value.strip()
    )


def loop_devices_for_image(path: Path) -> list[str]:
    if shutil.which("losetup") is None:
        return []
    result = run(["losetup", "-j", path.resolve()], capture=True, ok_codes=(0, 1))
    devices = []
    for line in (result.stdout or "").splitlines():
        match = re.match(r"^(/dev/loop\d+):", line)
        if match:
            devices.append(match.group(1))
    return devices


def findmnt_targets_for_source(source: str) -> list[Path]:
    if shutil.which("findmnt") is None:
        return []
    result = run(
        ["findmnt", "-r", "-n", "-S", source, "-o", "TARGET"],
        capture=True,
        ok_codes=(0, 1),
    )
    return [Path(_decode_findmnt(line)) for line in (result.stdout or "").splitlines() if line]


def exact_mountpoint(path: Path) -> bool:
    if shutil.which("findmnt") is None:
        return False
    result = run(
        ["findmnt", "-r", "-n", "--mountpoint", path, "-o", "TARGET"],
        capture=True,
        ok_codes=(0, 1),
    )
    wanted = str(path.resolve())
    return any(_decode_findmnt(line) == wanted for line in (result.stdout or "").splitlines())


def mounted_targets(workspace: Path, manifest: dict[str, Any]) -> list[Path]:
    targets: set[Path] = set()
    for partition in manifest["partitions"]:
        image = partition_image(workspace, partition)
        if not image.exists():
            continue
        for loop in loop_devices_for_image(image):
            targets.update(target.resolve() for target in findmnt_targets_for_source(loop))
        expected = (workspace / "mnt" / partition["name"]).resolve()
        if expected.exists() and exact_mountpoint(expected):
            targets.add(expected)
    return sorted(targets, key=lambda value: len(value.parts), reverse=True)


def unmount_workspace(workspace: Path, manifest: dict[str, Any]) -> None:
    require_tools("findmnt", "losetup", "umount")
    targets = mounted_targets(workspace, manifest)
    if not targets:
        info("No workspace images are mounted")
        return
    if os.geteuid() != 0:
        joined = ", ".join(str(item) for item in targets)
        raise SuperRwError(f"Mounted images require sudo/root to unmount: {joined}")
    for target in targets:
        info(f"Unmounting {target}")
        try:
            run(["umount", target])
        except SuperRwError as exc:
            raise SuperRwError(
                f"Could not unmount {target}. Close shells/files using it; "
                f"'fuser -vm {shlex.quote(str(target))}' can identify them.\n{exc}"
            ) from exc
    os.sync()


def mount_workspace(
    workspace: Path, manifest: dict[str, Any], selected: set[str] | None = None
) -> None:
    require_tools(
        "mount", "findmnt", "losetup", "e2fsck", "dumpe2fs", "debugfs"
    )
    if os.geteuid() != 0:
        raise SuperRwError("Mounting images requires sudo/root")
    mounted = 0
    failures: list[tuple[str, str]] = []
    for partition in manifest["partitions"]:
        if selected and partition["name"] not in selected and partition["raw_name"] not in selected:
            continue
        image = partition_image(workspace, partition)
        current_type = classify_image(image, partition["raw_name"], partition["name"])
        if current_type != "ext4":
            continue
        target = (workspace / "mnt" / partition["name"]).resolve()
        target.mkdir(parents=True, exist_ok=True)
        if exact_mountpoint(target):
            info(f"Already mounted: {target}")
            continue
        try:
            # Android image builders can deduplicate ext4 blocks and set the
            # shared_blocks RO_COMPAT feature. Linux correctly refuses to mount
            # such an image rw until e2fsck materializes the shared blocks.
            unshare_ext4_blocks(image)
            run(
                ["mount", "-t", "ext4", "-o", "loop,rw", image, target],
                capture=True,
            )
            info(f"Mounted {partition['name']} at {target}")
            mounted += 1
        except SuperRwError as exc:
            failures.append((partition["name"], str(exc)))
            warn(f"Could not mount {partition['name']}; continuing with the rest: {exc}")
    if selected:
        known = {item["name"] for item in manifest["partitions"]} | {
            item["raw_name"] for item in manifest["partitions"]
        }
        unknown = selected - known
        if unknown:
            warn("Unknown partition name(s): " + ", ".join(sorted(unknown)))
    if mounted == 0:
        info("No new ext4 images were mounted")
    if failures:
        failed_names = ", ".join(name for name, _ in failures)
        details = "; ".join(f"{name}: {reason}" for name, reason in failures)
        raise SuperRwError(
            f"Mount pass finished with {len(failures)} failure(s): {failed_names}. "
            f"Successfully mounted {mounted} new image(s). Details: {details}"
        )


def run_lpunpack(raw_super: Path, output_dir: Path, slot: int) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        run(["lpunpack", f"--slot={slot}", raw_super, output_dir])
    except SuperRwError as first_error:
        # Older downstream builds sometimes only accept the short -S spelling.
        for child in output_dir.iterdir():
            if child.is_file() or child.is_symlink():
                child.unlink()
        warn("lpunpack rejected --slot; retrying with -S")
        try:
            run(["lpunpack", "-S", str(slot), raw_super, output_dir])
        except SuperRwError:
            raise first_error


def command_unpack(args: argparse.Namespace) -> None:
    ensure_linux()
    require_tools("lpunpack")
    source = args.super_image.resolve()
    workspace = args.workspace.resolve()
    if not source.is_file():
        raise SuperRwError(f"Super image not found: {source}")
    if workspace.exists() and any(workspace.iterdir()):
        raise SuperRwError(f"Workspace must be empty: {workspace}")
    workspace.mkdir(parents=True, exist_ok=True)
    images_dir = workspace / "images"
    work_dir = workspace / "work"
    (workspace / "mnt").mkdir()
    images_dir.mkdir()
    work_dir.mkdir()

    source_sparse = is_android_sparse(source)
    raw_super = source
    converted = False
    if source_sparse:
        require_tools("simg2img")
        raw_super = work_dir / "source_super.raw.img"
        info("Input is Android sparse; converting it to raw for metadata parsing")
        run(["simg2img", source, raw_super])
        converted = True

    try:
        with raw_super.open("rb") as stream:
            geometry = read_geometry(stream)
            if args.slot >= geometry["metadata_slot_count"]:
                raise SuperRwError(
                    f"Requested slot {args.slot}, but image has only "
                    f"{geometry['metadata_slot_count']} metadata slot(s)"
                )
            selected_metadata = read_metadata_slot(stream, geometry, args.slot)
            apply_display_names(selected_metadata, args.slot)
            slot_digests: dict[str, str | None] = {}
            for slot in range(geometry["metadata_slot_count"]):
                try:
                    candidate = read_metadata_slot(stream, geometry, slot)
                    slot_digests[str(slot)] = metadata_fingerprint(candidate)
                except SuperRwError:
                    slot_digests[str(slot)] = None

        if len(selected_metadata["block_devices"]) != 1:
            raise SuperRwError(
                "This version supports a single physical super block device. "
                f"The image metadata references {len(selected_metadata['block_devices'])}."
            )

        run_lpunpack(raw_super, images_dir, args.slot)

        if shutil.which("lpdump"):
            try:
                result = run(
                    lpdump_report_command(
                        raw_super, geometry["metadata_slot_count"], args.slot
                    ),
                    capture=True,
                    ok_codes=(0,),
                )
                (workspace / "metadata_dump.txt").write_text(
                    result.stdout or "", encoding="utf-8"
                )
            except SuperRwError as exc:
                warn(f"Optional lpdump report failed; continuing: {exc}")

        manifest: dict[str, Any] = {
            "manifest_version": MANIFEST_VERSION,
            "script_version": SCRIPT_VERSION,
            "created_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "source_image": str(source),
            "source_was_sparse": source_sparse,
            "source_sparse_block_size": android_sparse_block_size(source),
            "selected_slot": args.slot,
            "grow_by": args.grow_by,
            "geometry": {
                key: geometry[key]
                for key in ("metadata_max_size", "metadata_slot_count", "logical_block_size")
            },
            "metadata": {
                key: selected_metadata[key]
                for key in ("major_version", "minor_version", "header_size", "header_flags")
            },
            "slot_fingerprints": slot_digests,
            "slot_layouts_differ": len(
                {value for value in slot_digests.values() if value is not None}
            )
            > 1,
            "slot_metadata_incomplete": any(
                value is None for value in slot_digests.values()
            ),
            "groups": [
                {
                    key: group[key]
                    for key in ("raw_name", "name", "flags", "maximum_size")
                }
                for group in selected_metadata["groups"]
            ],
            "block_devices": [
                {
                    key: device[key]
                    for key in (
                        "raw_name",
                        "name",
                        "first_logical_sector",
                        "alignment",
                        "alignment_offset",
                        "size",
                        "flags",
                    )
                }
                for device in selected_metadata["block_devices"]
            ],
            "partitions": [],
        }

        for partition in selected_metadata["partitions"]:
            expected = images_dir / f"{partition['name']}.img"
            if not expected.is_file() and partition["name"] != partition["raw_name"]:
                fallback = images_dir / f"{partition['raw_name']}.img"
                if fallback.is_file():
                    expected = fallback
            if not expected.is_file():
                raise SuperRwError(
                    f"lpunpack did not create an image for {partition['name']}: {expected}"
                )
            fs_type = classify_image(expected, partition["raw_name"], partition["name"])
            item = {
                "raw_name": partition["raw_name"],
                "name": partition["name"],
                "group_raw": partition["group_raw"],
                "group": partition["group"],
                "attributes": partition["attributes"],
                "original_partition_size": partition["size"],
                "original_image_size": expected.stat().st_size,
                "image": str(expected.relative_to(workspace)),
                "filesystem": fs_type,
                "expanded": False,
            }
            if fs_type == "android-cow":
                info(f"Preserving COW payload as opaque: {partition['name']}")
                item["original_sha256"] = sha256_file(expected)
            manifest["partitions"].append(item)

        save_manifest(workspace, manifest)

        if manifest["slot_layouts_differ"]:
            warn(
                "The source metadata slots differ (common in a live OTA/snapshot state). "
                "Repack will fail closed unless --mirror-selected-slot-across-ab is used "
                "explicitly."
            )
        if manifest["slot_metadata_incomplete"]:
            warn(
                "At least one source metadata slot was unreadable. Repack will fail closed "
                "unless --mirror-selected-slot-across-ab is used explicitly."
            )

        ext4_items = [item for item in manifest["partitions"] if item["filesystem"] == "ext4"]
        if not args.no_expand and ext4_items:
            require_tools("e2fsck", "resize2fs", "dumpe2fs", "debugfs")
            for item in ext4_items:
                image = partition_image(workspace, item)
                grow_ext4(image, args.grow_by)
                item["expanded"] = True
                item["expanded_image_size"] = image.stat().st_size
                save_manifest(workspace, manifest)
        elif not ext4_items:
            warn(
                "No ext4 partitions were found. EROFS/F2FS/SquashFS and unknown images "
                "were left untouched; EROFS cannot be mounted writable."
            )

        if args.mount:
            mount_workspace(workspace, manifest)

        info(f"Workspace ready: {workspace}")
        for item in manifest["partitions"]:
            info(
                f"{item['name']}: {item['filesystem']}, "
                f"attrs={attribute_names(item['attributes'])}, "
                f"logical={human_size(item['original_partition_size'])}"
            )
    finally:
        if converted and raw_super.exists() and not args.keep_raw:
            raw_super.unlink()


def _patch_table_by_name(
    tables: bytearray,
    descriptor: dict[str, int],
    name_offset: int,
    value_offset: int,
    value_format: str,
    expected: dict[str, int],
    label: str,
) -> None:
    found: set[str] = set()
    for index in range(descriptor["num_entries"]):
        start = descriptor["offset"] + index * descriptor["entry_size"]
        name = fixed_string(bytes(tables[start + name_offset : start + name_offset + 36]))
        if name not in expected:
            raise SuperRwError(f"Generated metadata has unexpected {label}: {name}")
        struct.pack_into(value_format, tables, start + value_offset, expected[name])
        found.add(name)
    missing = set(expected) - found
    if missing:
        raise SuperRwError(
            f"Generated metadata is missing {label}(s): {', '.join(sorted(missing))}"
        )


def patch_metadata_blob(blob: bytes, manifest: dict[str, Any]) -> bytes:
    parsed = parse_metadata_blob(blob)
    original = manifest["metadata"]
    if parsed["major_version"] != original["major_version"]:
        raise SuperRwError(
            f"lpmake emitted metadata major {parsed['major_version']}, expected "
            f"{original['major_version']}"
        )
    if parsed["header_size"] != original["header_size"]:
        raise SuperRwError(
            f"lpmake emitted header size {parsed['header_size']}, expected "
            f"{original['header_size']}. Use a current AOSP lpmake build."
        )

    mutable = bytearray(blob)
    header_size = parsed["header_size"]
    tables_size = parsed["tables_size"]
    header = bytearray(mutable[:header_size])
    tables = bytearray(mutable[header_size : header_size + tables_size])

    struct.pack_into("<H", header, 4, original["major_version"])
    struct.pack_into("<H", header, 6, original["minor_version"])
    if header_size >= 132:
        struct.pack_into("<I", header, 128, original["header_flags"])
    elif original["header_flags"]:
        raise SuperRwError("Original header flags do not fit in a v1.0/v1.1 header")

    partition_attrs = {
        item["raw_name"]: item["attributes"] for item in manifest["partitions"]
    }
    group_flags = {item["raw_name"]: item["flags"] for item in manifest["groups"]}
    group_maximums = {
        item["raw_name"]: item["maximum_size"] for item in manifest["groups"]
    }
    block_flags = {
        item["raw_name"]: item["flags"] for item in manifest["block_devices"]
    }
    block_first_sectors = {
        item["raw_name"]: item["first_logical_sector"]
        for item in manifest["block_devices"]
    }
    block_alignments = {
        item["raw_name"]: item["alignment"] for item in manifest["block_devices"]
    }
    block_alignment_offsets = {
        item["raw_name"]: item["alignment_offset"]
        for item in manifest["block_devices"]
    }
    block_sizes = {
        item["raw_name"]: item["size"] for item in manifest["block_devices"]
    }

    generated_devices = {
        item["raw_name"]: item for item in parsed["block_devices"]
    }
    for expected in manifest["block_devices"]:
        generated = generated_devices.get(expected["raw_name"])
        if not generated:
            raise SuperRwError(
                f"Generated metadata is missing block device {expected['raw_name']}"
            )
        if generated["first_logical_sector"] != expected["first_logical_sector"]:
            raise SuperRwError(
                f"lpmake placed {expected['raw_name']} first logical sector at "
                f"{generated['first_logical_sector']}, expected "
                f"{expected['first_logical_sector']}"
            )
        if generated["size"] != expected["size"]:
            raise SuperRwError(
                f"lpmake changed block-device size for {expected['raw_name']}"
            )

    _patch_table_by_name(
        tables,
        parsed["descriptors"]["partitions"],
        0,
        36,
        "<I",
        partition_attrs,
        "partition",
    )
    _patch_table_by_name(
        tables,
        parsed["descriptors"]["groups"],
        0,
        36,
        "<I",
        group_flags,
        "group",
    )
    _patch_table_by_name(
        tables,
        parsed["descriptors"]["groups"],
        0,
        40,
        "<Q",
        group_maximums,
        "group",
    )
    _patch_table_by_name(
        tables,
        parsed["descriptors"]["block_devices"],
        24,
        0,
        "<Q",
        block_first_sectors,
        "block device",
    )
    _patch_table_by_name(
        tables,
        parsed["descriptors"]["block_devices"],
        24,
        8,
        "<I",
        block_alignments,
        "block device",
    )
    _patch_table_by_name(
        tables,
        parsed["descriptors"]["block_devices"],
        24,
        12,
        "<I",
        block_alignment_offsets,
        "block device",
    )
    _patch_table_by_name(
        tables,
        parsed["descriptors"]["block_devices"],
        24,
        16,
        "<Q",
        block_sizes,
        "block device",
    )
    _patch_table_by_name(
        tables,
        parsed["descriptors"]["block_devices"],
        24,
        60,
        "<I",
        block_flags,
        "block device",
    )

    header[48:80] = hashlib.sha256(tables).digest()
    header[12:44] = b"\0" * 32
    header[12:44] = hashlib.sha256(header).digest()
    mutable[:header_size] = header
    mutable[header_size : header_size + tables_size] = tables
    # Validate our own result before returning it.
    parse_metadata_blob(bytes(mutable))
    return bytes(mutable)


def _literal_slot_name(name: str, source_suffix: str, target_suffix: str) -> str:
    cow_suffix = source_suffix + "-cow"
    if name.endswith(cow_suffix):
        return name[: -len(cow_suffix)] + target_suffix + "-cow"
    if name.endswith(source_suffix):
        return name[: -len(source_suffix)] + target_suffix
    return name


def _write_fixed_name(tables: bytearray, offset: int, name: str) -> None:
    encoded = name.encode("ascii")
    if len(encoded) >= 36:
        raise SuperRwError(f"LP name is too long after slot mirroring: {name}")
    tables[offset : offset + 36] = encoded + b"\0" * (36 - len(encoded))


def mirror_metadata_blob_slot(
    blob: bytes, source_suffix: str, target_suffix: str
) -> bytes:
    if source_suffix == target_suffix:
        return blob

    parsed = parse_metadata_blob(blob)
    mutable = bytearray(blob)
    header_size = parsed["header_size"]
    tables_size = parsed["tables_size"]
    header = bytearray(mutable[:header_size])
    tables = bytearray(mutable[header_size : header_size + tables_size])

    for table_name, name_offset in (
        ("partitions", 0),
        ("groups", 0),
        ("block_devices", 24),
    ):
        descriptor = parsed["descriptors"][table_name]
        for index in range(descriptor["num_entries"]):
            start = descriptor["offset"] + index * descriptor["entry_size"]
            name_start = start + name_offset
            old = fixed_string(bytes(tables[name_start : name_start + 36]))
            new = _literal_slot_name(old, source_suffix, target_suffix)
            if new != old:
                _write_fixed_name(tables, name_start, new)

    header[48:80] = hashlib.sha256(tables).digest()
    header[12:44] = b"\0" * 32
    header[12:44] = hashlib.sha256(header).digest()
    mutable[:header_size] = header
    mutable[header_size : header_size + tables_size] = tables
    parse_metadata_blob(bytes(mutable))
    return bytes(mutable)


def _source_slot_readable(manifest: dict[str, Any], slot: int) -> bool:
    fingerprints = manifest.get("slot_fingerprints")
    return isinstance(fingerprints, dict) and fingerprints.get(str(slot)) is not None


def patch_all_metadata(
    raw_super: Path,
    manifest: dict[str, Any],
    mirror_selected_slot_across_ab: bool = False,
) -> None:
    with raw_super.open("r+b") as stream:
        geometry = read_geometry(stream)
        wanted = manifest["geometry"]
        for key in ("metadata_max_size", "metadata_slot_count", "logical_block_size"):
            if geometry[key] != wanted[key]:
                raise SuperRwError(
                    f"Generated geometry {key}={geometry[key]}, expected {wanted[key]}"
                )
        selected_slot = manifest["selected_slot"]
        source_suffix = slot_suffix(selected_slot)
        for slot in range(geometry["metadata_slot_count"]):
            if (
                mirror_selected_slot_across_ab
                and slot >= 2
                and not _source_slot_readable(manifest, slot)
            ):
                empty = b"\0" * geometry["metadata_max_size"]
                for offset in metadata_offsets(geometry, slot):
                    stream.seek(offset)
                    stream.write(empty)
                continue

            for offset in metadata_offsets(geometry, slot):
                stream.seek(offset)
                blob = stream.read(geometry["metadata_max_size"])
                patched = patch_metadata_blob(blob, manifest)
                if mirror_selected_slot_across_ab and slot in (0, 1):
                    patched = mirror_metadata_blob_slot(
                        patched, source_suffix, slot_suffix(slot)
                    )
                stream.seek(offset)
                stream.write(patched)
        stream.flush()
        os.fsync(stream.fileno())


def _expected_raw_name(
    raw_name: str,
    manifest: dict[str, Any],
    slot: int,
    mirror_selected_slot_across_ab: bool,
) -> str:
    if not mirror_selected_slot_across_ab or slot not in (0, 1):
        return raw_name
    return _literal_slot_name(
        raw_name,
        slot_suffix(manifest["selected_slot"]),
        slot_suffix(slot),
    )


def verify_metadata(
    raw_super: Path,
    manifest: dict[str, Any],
    requested_sizes: dict[str, int],
    mirror_selected_slot_across_ab: bool = False,
) -> None:
    with raw_super.open("rb") as stream:
        geometry = read_geometry(stream)
        for slot in range(geometry["metadata_slot_count"]):
            if (
                mirror_selected_slot_across_ab
                and slot >= 2
                and not _source_slot_readable(manifest, slot)
            ):
                try:
                    read_metadata_slot(stream, geometry, slot)
                except SuperRwError:
                    continue
                raise SuperRwError(
                    f"Reserved metadata slot {slot} should remain unreadable"
                )

            metadata = read_metadata_slot(stream, geometry, slot)
            if metadata["major_version"] != manifest["metadata"]["major_version"]:
                raise SuperRwError("Repacked metadata major version mismatch")
            if metadata["minor_version"] != manifest["metadata"]["minor_version"]:
                raise SuperRwError("Repacked metadata minor version mismatch")
            if metadata["header_flags"] != manifest["metadata"]["header_flags"]:
                raise SuperRwError("Repacked metadata header flags mismatch")

            actual_parts = {item["raw_name"]: item for item in metadata["partitions"]}
            expected_parts = {
                _expected_raw_name(
                    item["raw_name"],
                    manifest,
                    slot,
                    mirror_selected_slot_across_ab,
                ): item
                for item in manifest["partitions"]
            }
            if set(actual_parts) != set(expected_parts):
                raise SuperRwError("Repacked partition name set differs from the manifest")
            for name, expected in expected_parts.items():
                actual = actual_parts[name]
                if actual["attributes"] != expected["attributes"]:
                    raise SuperRwError(f"Repacked attributes differ for {name}")
                expected_group = _expected_raw_name(
                    expected["group_raw"],
                    manifest,
                    slot,
                    mirror_selected_slot_across_ab,
                )
                if actual["group_raw"] != expected_group:
                    raise SuperRwError(f"Repacked group differs for {name}")
                expected_size = requested_sizes[expected["raw_name"]]
                if actual["size"] != expected_size:
                    raise SuperRwError(
                        f"Repacked size differs for {name}: {actual['size']} != "
                        f"{expected_size}"
                    )

            actual_groups = {item["raw_name"]: item for item in metadata["groups"]}
            for expected in manifest["groups"]:
                expected_name = _expected_raw_name(
                    expected["raw_name"],
                    manifest,
                    slot,
                    mirror_selected_slot_across_ab,
                )
                actual = actual_groups.get(expected_name)
                if not actual or actual["flags"] != expected["flags"]:
                    raise SuperRwError(f"Repacked flags differ for group {expected_name}")
                if actual["maximum_size"] != expected["maximum_size"]:
                    raise SuperRwError(
                        f"Repacked maximum differs for group {expected_name}"
                    )

            actual_devices = {
                item["raw_name"]: item for item in metadata["block_devices"]
            }
            for expected in manifest["block_devices"]:
                expected_name = _expected_raw_name(
                    expected["raw_name"],
                    manifest,
                    slot,
                    mirror_selected_slot_across_ab,
                )
                actual = actual_devices.get(expected_name)
                if not actual:
                    raise SuperRwError(
                        f"Repacked block device missing: {expected_name}"
                    )
                for key in (
                    "first_logical_sector",
                    "alignment",
                    "alignment_offset",
                    "size",
                    "flags",
                ):
                    if actual[key] != expected[key]:
                        raise SuperRwError(
                            f"Repacked block device {expected_name} {key} differs"
                        )


def compare_payload(expected: Path, actual: Path) -> None:
    expected_size = expected.stat().st_size
    actual_size = actual.stat().st_size
    if actual_size < expected_size:
        raise SuperRwError(f"Payload is truncated after repack: {actual.name}")
    with expected.open("rb") as left, actual.open("rb") as right:
        while True:
            left_chunk = left.read(8 * 1024 * 1024)
            if not left_chunk:
                break
            right_chunk = right.read(len(left_chunk))
            if left_chunk != right_chunk:
                raise SuperRwError(f"Payload bytes differ after repack: {actual.name}")
        while True:
            tail = right.read(8 * 1024 * 1024)
            if not tail:
                break
            if any(tail):
                raise SuperRwError(f"Non-zero padding after repack: {actual.name}")


def verify_payloads(raw_super: Path, workspace: Path, manifest: dict[str, Any]) -> None:
    verify_root = workspace / "work"
    verify_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="verify-", dir=verify_root) as temporary:
        output_dir = Path(temporary)
        run_lpunpack(raw_super, output_dir, manifest["selected_slot"])
        for partition in manifest["partitions"]:
            expected = partition_image(workspace, partition)
            actual = output_dir / f"{partition['name']}.img"
            if not actual.is_file() and partition["name"] != partition["raw_name"]:
                actual = output_dir / f"{partition['raw_name']}.img"
            if not actual.is_file():
                raise SuperRwError(f"Verification unpack omitted {partition['name']}")
            compare_payload(expected, actual)


def validate_slot_repack_mode(
    manifest: dict[str, Any], mirror_selected_slot_across_ab: bool
) -> None:
    slot_hazard = bool(
        manifest.get("slot_layouts_differ")
        or manifest.get("slot_metadata_incomplete")
    )
    if slot_hazard and not mirror_selected_slot_across_ab:
        raise SuperRwError(
            "Source LP metadata slots differ or are incomplete. Refusing to flatten the "
            "selected slot into every metadata copy because that can make the other boot "
            "slot unmountable. If both A and B should intentionally use the edited selected "
            "slot payloads, rerun with --mirror-selected-slot-across-ab."
        )

    if not mirror_selected_slot_across_ab:
        return

    slot_count = manifest["geometry"]["metadata_slot_count"]
    selected_slot = manifest["selected_slot"]
    if slot_count < 2 or selected_slot not in (0, 1):
        raise SuperRwError(
            "--mirror-selected-slot-across-ab requires metadata slots 0 and 1 and a "
            "selected source slot of 0 or 1"
        )
    fingerprints = manifest.get("slot_fingerprints")
    if not isinstance(fingerprints, dict):
        raise SuperRwError(
            "The workspace manifest predates per-slot fingerprints; unpack it again before "
            "using --mirror-selected-slot-across-ab"
        )
    readable_extra_slots = [
        slot
        for slot in range(2, slot_count)
        if fingerprints.get(str(slot)) is not None
    ]
    if readable_extra_slots:
        raise SuperRwError(
            "Safe A/B mirroring does not support additional readable metadata slot(s): "
            + ", ".join(str(slot) for slot in readable_extra_slots)
        )

    source_suffix = slot_suffix(selected_slot)
    has_slot_identity = any(
        item["attributes"] & LP_ATTR_SLOT_SUFFIXED
        or item["raw_name"].endswith(source_suffix)
        or item["raw_name"].endswith(source_suffix + "-cow")
        for item in manifest["partitions"]
    )
    if not has_slot_identity:
        raise SuperRwError(
            "The selected layout has neither slot-suffixed attributes nor literal slot "
            "suffixes, so safe A/B mirroring cannot infer the target names"
        )


def command_repack(args: argparse.Namespace) -> None:
    ensure_linux()
    require_tools("lpmake", "e2fsck", "resize2fs", "dumpe2fs")
    workspace = args.workspace.resolve()
    output = args.output.resolve()
    manifest = load_manifest(workspace)
    if output.exists() and not args.force:
        raise SuperRwError(f"Output already exists (use --force): {output}")
    validate_slot_repack_mode(manifest, args.mirror_selected_slot_across_ab)
    output.parent.mkdir(parents=True, exist_ok=True)

    unmount_workspace(workspace, manifest)
    if args.mirror_selected_slot_across_ab:
        warn(
            f"Mirroring selected slot {manifest['selected_slot']} payloads with distinct "
            "A names in metadata slot 0 and B names in metadata slot 1."
        )

    logical_block_size = manifest["geometry"]["logical_block_size"]
    requested_sizes: dict[str, int] = {}
    for partition in manifest["partitions"]:
        image = partition_image(workspace, partition)
        if not image.is_file():
            raise SuperRwError(f"Partition image is missing: {image}")
        current_type = classify_image(image, partition["raw_name"], partition["name"])
        original_type = partition["filesystem"]

        if original_type == "android-cow":
            if current_type != "android-cow":
                raise SuperRwError(f"COW payload no longer looks like COW: {image}")
            current_hash = sha256_file(image)
            if current_hash != partition.get("original_sha256") and not args.allow_cow_change:
                raise SuperRwError(
                    f"COW payload changed: {partition['name']}. It is kept opaque by design; "
                    "use --allow-cow-change only if that change was intentional."
                )
            if image.stat().st_size > partition["original_partition_size"]:
                raise SuperRwError(f"COW payload no longer fits: {partition['name']}")
            requested_sizes[partition["raw_name"]] = partition["original_partition_size"]
            info(f"Keeping COW partition unchanged: {partition['name']}")
            continue

        if current_type != original_type and not args.allow_filesystem_change:
            raise SuperRwError(
                f"{partition['name']} was {original_type} but is now {current_type}; "
                "use --allow-filesystem-change if this replacement was intentional."
            )

        if current_type == "ext4":
            old_size = image.stat().st_size
            new_size = shrink_ext4(image)
            info(
                f"Shrank {partition['name']}: {human_size(old_size)} -> "
                f"{human_size(new_size)}"
            )
            requested_sizes[partition["raw_name"]] = round_up(
                new_size, logical_block_size
            )
        else:
            image_size = image.stat().st_size
            original_size = partition["original_partition_size"]
            if image_size > original_size:
                raise SuperRwError(
                    f"Opaque {partition['name']} grew beyond its original logical size: "
                    f"{image_size} > {original_size}"
                )
            requested_sizes[partition["raw_name"]] = original_size

    raw_tmp = output.parent / f".{output.name}.super_rw.{os.getpid()}.raw.tmp"
    final_tmp = output.parent / f".{output.name}.super_rw.{os.getpid()}.tmp"
    for temporary in (raw_tmp, final_tmp):
        if temporary.exists():
            temporary.unlink()

    command: list[object] = [
        "lpmake",
        "--metadata-size",
        manifest["geometry"]["metadata_max_size"],
        "--metadata-slots",
        manifest["geometry"]["metadata_slot_count"],
        "--block-size",
        logical_block_size,
        "--super-name",
        manifest["block_devices"][0]["raw_name"],
        "--force-full-image",
    ]
    if manifest["metadata"]["minor_version"] >= 2:
        # This makes lpmake emit the expanded 256-byte header. The exact original
        # header flags are restored below, so this does not invent virtual-A/B.
        command.append("--virtual-ab")
    for device in manifest["block_devices"]:
        build_alignment, build_alignment_offset = lpmake_device_alignment(
            device, manifest["geometry"]
        )
        command.extend(
            [
                "--device",
                f"{device['raw_name']}:{device['size']}:"
                f"{build_alignment}:{build_alignment_offset}",
            ]
        )
    for group in manifest["groups"]:
        if group["raw_name"] != "default":
            command.extend(
                ["--group", f"{group['raw_name']}:{group['maximum_size']}"]
            )
    for partition in manifest["partitions"]:
        cli_attr = "readonly" if partition["attributes"] & LP_ATTR_READONLY else "none"
        size = requested_sizes[partition["raw_name"]]
        command.extend(
            [
                "--partition",
                f"{partition['raw_name']}:{cli_attr}:{size}:{partition['group_raw']}",
                "--image",
                f"{partition['raw_name']}={partition_image(workspace, partition)}",
            ]
        )
    command.extend(["--output", raw_tmp])

    try:
        run(command)
        patch_all_metadata(
            raw_tmp, manifest, args.mirror_selected_slot_across_ab
        )
        verify_metadata(
            raw_tmp,
            manifest,
            requested_sizes,
            args.mirror_selected_slot_across_ab,
        )
        info(
            "LP geometry, slot views, groups, attributes, flags, and metadata "
            "checksums verified"
        )

        if args.verify_payloads:
            verify_payloads(raw_tmp, workspace, manifest)
            info("All unpacked payload bytes verified")

        if shutil.which("lpdump"):
            try:
                result = run(
                    lpdump_report_command(
                        raw_tmp,
                        manifest["geometry"]["metadata_slot_count"],
                        manifest["selected_slot"],
                    ),
                    capture=True,
                )
                (workspace / "last_repack_lpdump.txt").write_text(
                    result.stdout or "", encoding="utf-8"
                )
            except SuperRwError as exc:
                warn(f"Optional lpdump report failed; continuing: {exc}")

        make_sparse = (
            args.sparse
            if args.sparse is not None
            else bool(manifest["source_was_sparse"])
        )
        if make_sparse:
            require_tools("img2simg")
            sparse_block_size = (
                manifest.get("source_sparse_block_size") or logical_block_size
            )
            run(["img2simg", raw_tmp, final_tmp, sparse_block_size])
            if not is_android_sparse(final_tmp):
                raise SuperRwError("img2simg did not produce an Android sparse image")
            if output.exists():
                output.unlink()
            os.replace(final_tmp, output)
        else:
            if output.exists():
                output.unlink()
            os.replace(raw_tmp, output)

        manifest["last_repack_utc"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
        manifest["last_repack_output"] = str(output)
        manifest["last_repack_sparse"] = make_sparse
        manifest["last_repack_mirror_selected_slot_across_ab"] = (
            args.mirror_selected_slot_across_ab
        )
        manifest["last_partition_sizes"] = requested_sizes
        save_manifest(workspace, manifest)
        info(
            f"Repacked {'sparse' if make_sparse else 'raw'} super image: {output} "
            f"({human_size(output.stat().st_size)})"
        )
    finally:
        for temporary in (raw_tmp, final_tmp):
            if temporary.exists():
                temporary.unlink()


def command_mount(args: argparse.Namespace) -> None:
    ensure_linux()
    workspace = args.workspace.resolve()
    manifest = load_manifest(workspace)
    selected = set(args.partitions) if args.partitions else None
    mount_workspace(workspace, manifest, selected)


def command_expand(args: argparse.Namespace) -> None:
    ensure_linux()
    require_tools("e2fsck", "resize2fs", "dumpe2fs", "debugfs")
    workspace = args.workspace.resolve()
    manifest = load_manifest(workspace)
    selected = set(args.partitions) if args.partitions else None

    # Growing a mounted backing file is avoidably risky. Reuse the same exact
    # loop-device discovery as repack and unmount first when necessary.
    unmount_workspace(workspace, manifest)

    known = {item["name"] for item in manifest["partitions"]} | {
        item["raw_name"] for item in manifest["partitions"]
    }
    if selected:
        unknown = selected - known
        if unknown:
            raise SuperRwError(
                "Unknown partition name(s): " + ", ".join(sorted(unknown))
            )

    expanded = 0
    failures: list[tuple[str, str]] = []
    for partition in manifest["partitions"]:
        if selected and partition["name"] not in selected and partition["raw_name"] not in selected:
            continue
        name = partition["name"]
        try:
            image = partition_image(workspace, partition)
            if not image.is_file():
                raise SuperRwError(f"Partition image is missing: {image}")
            current_type = classify_image(image, partition["raw_name"], name)
            if current_type != "ext4":
                info(f"Skipping non-ext4 partition: {name} ({current_type})")
                continue
            grow_ext4(
                image,
                args.grow_by,
                minimum_base_size=partition["original_partition_size"],
            )
            partition["expanded"] = True
            partition["expanded_image_size"] = image.stat().st_size
            expanded += 1
            save_manifest(workspace, manifest)
        except (SuperRwError, OSError) as exc:
            failures.append((name, str(exc)))
            warn(f"Could not expand {name}; continuing with the rest: {exc}")

    if not expanded:
        if failures:
            failed_names = ", ".join(name for name, _ in failures)
            details = "; ".join(f"{name}: {reason}" for name, reason in failures)
            raise SuperRwError(
                f"Expand pass finished with {len(failures)} failure(s): {failed_names}. "
                f"Successfully expanded {expanded} ext4 image(s). Details: {details}"
            )
        raise SuperRwError("No selected ext4 partition images were available to expand")

    manifest["last_expand_utc"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    manifest["last_expand_grow_by"] = args.grow_by
    save_manifest(workspace, manifest)
    info(f"Expanded {expanded} ext4 partition image(s)")
    if args.mount:
        try:
            mount_workspace(workspace, manifest, selected)
        except SuperRwError as exc:
            failures.append(("mount", str(exc)))
    if failures:
        failed_names = ", ".join(name for name, _ in failures)
        details = "; ".join(f"{name}: {reason}" for name, reason in failures)
        raise SuperRwError(
            f"Expand pass finished with {len(failures)} failure(s): {failed_names}. "
            f"Successfully expanded {expanded} ext4 image(s). Details: {details}"
        )


def command_unmount(args: argparse.Namespace) -> None:
    ensure_linux()
    workspace = args.workspace.resolve()
    manifest = load_manifest(workspace)
    unmount_workspace(workspace, manifest)


def command_status(args: argparse.Namespace) -> None:
    ensure_linux()
    workspace = args.workspace.resolve()
    manifest = load_manifest(workspace)
    targets = set(mounted_targets(workspace, manifest)) if shutil.which("findmnt") else set()
    print(f"Workspace: {workspace}")
    print(f"Source:    {manifest['source_image']}")
    print(f"Slot:      {manifest['selected_slot']}")
    print(f"Sparse:    {manifest['source_was_sparse']}")
    print("Partitions:")
    for item in manifest["partitions"]:
        image = partition_image(workspace, item)
        target = (workspace / "mnt" / item["name"]).resolve()
        state = "mounted" if target in targets else "unmounted"
        size = image.stat().st_size if image.exists() else -1
        print(
            f"  {item['name']:<28} {item['filesystem']:<12} "
            f"{human_size(size) if size >= 0 else 'MISSING':>12}  {state}  "
            f"attrs={attribute_names(item['attributes'])}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Safely unpack/repack Android super images while treating Virtual A/B "
            "COW partitions as opaque data."
        )
    )
    parser.add_argument("--version", action="version", version=SCRIPT_VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    unpack = subparsers.add_parser(
        "unpack", help="unpack a super image and grow ext4 images for writable editing"
    )
    unpack.add_argument("super_image", type=Path)
    unpack.add_argument("workspace", type=Path)
    unpack.add_argument("--slot", type=int, default=0, help="metadata slot to unpack (default: 0)")
    unpack.add_argument(
        "--grow-by",
        type=parse_size,
        default=parse_size("1GiB"),
        metavar="SIZE",
        help="temporary growth per ext4 image (default: 1GiB)",
    )
    unpack.add_argument("--no-expand", action="store_true", help="extract but do not grow ext4")
    unpack.add_argument("--mount", action="store_true", help="mount all ext4 images writable")
    unpack.add_argument(
        "--keep-raw",
        action="store_true",
        help="keep the temporary raw conversion of a sparse source",
    )
    unpack.set_defaults(func=command_unpack)

    repack = subparsers.add_parser(
        "repack", help="unmount, shrink ext4, and rebuild a super image"
    )
    repack.add_argument("workspace", type=Path)
    repack.add_argument("output", type=Path)
    output_format = repack.add_mutually_exclusive_group()
    output_format.add_argument(
        "--sparse", dest="sparse", action="store_true", help="emit Android sparse output"
    )
    output_format.add_argument(
        "--raw", dest="sparse", action="store_false", help="emit raw output"
    )
    repack.set_defaults(sparse=None)
    repack.add_argument(
        "--verify-payloads",
        action="store_true",
        help="unpack the rebuilt raw image and byte-check every payload (slow, extra disk I/O)",
    )
    repack.add_argument(
        "--allow-cow-change",
        action="store_true",
        help="permit a changed COW payload (normally rejected)",
    )
    repack.add_argument(
        "--allow-filesystem-change",
        action="store_true",
        help="permit replacing a partition with a different filesystem format",
    )
    repack.add_argument(
        "--mirror-selected-slot-across-ab",
        action="store_true",
        help=(
            "for a differing Virtual A/B source, deliberately expose the edited selected "
            "slot payloads as A names in metadata slot 0 and B names in metadata slot 1; "
            "without this option repack fails closed"
        ),
    )
    repack.add_argument("--force", action="store_true", help="replace an existing output file")
    repack.set_defaults(func=command_repack)

    expand = subparsers.add_parser(
        "expand", help="regrow shrunken ext4 images in an existing workspace"
    )
    expand.add_argument("workspace", type=Path)
    expand.add_argument(
        "partitions", nargs="*", help="optional partition names (default: all ext4)"
    )
    expand.add_argument(
        "--grow-by",
        type=parse_size,
        default=parse_size("1GiB"),
        metavar="SIZE",
        help="headroom above the original logical size (default: 1GiB)",
    )
    expand.add_argument(
        "--mount", action="store_true", help="mount expanded ext4 images writable"
    )
    expand.set_defaults(func=command_expand)

    mount = subparsers.add_parser("mount", help="mount extracted ext4 images writable")
    mount.add_argument("workspace", type=Path)
    mount.add_argument("partitions", nargs="*", help="optional partition names")
    mount.set_defaults(func=command_mount)

    unmount = subparsers.add_parser("unmount", help="unmount all images from a workspace")
    unmount.add_argument("workspace", type=Path)
    unmount.set_defaults(func=command_unmount)

    status = subparsers.add_parser("status", help="show workspace partitions and mount state")
    status.add_argument("workspace", type=Path)
    status.set_defaults(func=command_status)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
        return 0
    except KeyboardInterrupt:
        warn("Interrupted")
        return 130
    except (SuperRwError, OSError, json.JSONDecodeError) as exc:
        warn(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
