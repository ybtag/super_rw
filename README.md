# Android super image writable unpack/repack tool

`super_rw.py` is a Linux/WSL2 tool that:

1. Converts a sparse `super.img` to raw when necessary.
2. Reads the LP metadata directly and saves a JSON manifest.
3. Extracts every logical partition with `lpunpack`.
4. Grows ext4 partition images so they can be loop-mounted writable.
   Android ext4 images using the read-only `shared_blocks` feature are
   automatically materialized with `e2fsck -E unshare_blocks` first.
5. Treats Android Virtual A/B COW partitions as opaque data. It never runs
   filesystem tools against them and refuses to repack a changed COW by default.
6. On repack, finds and unmounts workspace images, shrinks ext4 to minimum size,
   rebuilds with `lpmake`, restores metadata attributes/flags that `lpmake` cannot
   express, recomputes LP SHA-256 checksums, and verifies the result.

## Requirements

Run under native Linux or WSL2. Do not run it with Windows Python.

Required commands:

- `lpunpack` and a current AOSP `lpmake`
- `simg2img` and `img2simg` for sparse input/output
- `e2fsck`, `resize2fs`, `dumpe2fs`, and `debugfs` from `e2fsprogs`
- `mount`, `umount`, `findmnt`, and `losetup` from `util-linux`
- `lpdump` is optional and is used only to save human-readable reports

On Ubuntu, the ordinary Linux pieces and sparse tools can usually be installed
with:

```bash
sudo apt update
sudo apt install python3 e2fsprogs util-linux android-sdk-libsparse-utils
```

Put compatible AOSP host builds of `lpmake`, `lpunpack`, and optionally `lpdump`
on `PATH`. Use tools from the same Android branch when possible.

## Basic use

Unpack and give each ext4 image 1 GiB of temporary free space:

```bash
python3 super_rw.py unpack super.img super-work
```

Unpack, expand, and mount ext4 images immediately (requires root):

```bash
sudo python3 super_rw.py unpack super.img super-work --mount
```

The mount points are created under `super-work/mnt/<partition>`. The extracted
images are under `super-work/images`.

Mount later, optionally selecting partitions:

```bash
sudo python3 super_rw.py mount super-work
sudo python3 super_rw.py mount super-work system_a vendor_a
```

Show status or unmount explicitly:

```bash
python3 super_rw.py status super-work
sudo python3 super_rw.py unmount super-work
```

Repack. This automatically unmounts any loop-mounted workspace images first and
defaults to the same raw/sparse format as the source:

```bash
sudo python3 super_rw.py repack super-work super-new.img
```

After repack, reopen the same workspace for another editing pass without
unpacking the original super again:

```bash
python3 super_rw.py expand super-work
sudo python3 super_rw.py mount super-work
```

Or expand selected partitions and mount them in one root invocation:

```bash
sudo python3 super_rw.py expand super-work system_a vendor_a --grow-by 2GiB --mount
```

`expand` grows ext4 from at least its original logical partition size and then
adds the requested headroom. COW, EROFS, F2FS, SquashFS, and unknown images are
skipped.

The expansion pass attempts every selected ext4 partition even if one fails.
It reports a combined nonzero result at the end, including the failed names and
the number successfully expanded. Successful images remain expanded and are
recorded in the workspace manifest.

The mount pass attempts every selected ext4 partition even if one fails. It
reports a combined nonzero result at the end, including the failed names and the
number successfully mounted.

Force a specific output format and perform the slower byte-for-byte extraction
check after rebuilding:

```bash
sudo python3 super_rw.py repack super-work super-new.img --sparse --verify-payloads
```

If the source Virtual A/B metadata slots differ or one slot is incomplete, the
script fails closed by default. To intentionally expose the edited selected-slot
payloads as `_a` names in metadata slot 0 and `_b` names in metadata slot 1:

```bash
sudo python3 super_rw.py repack super-work super-new.img --sparse \
  --mirror-selected-slot-across-ab --verify-payloads
```

Use `--force` to replace an existing output file.

## COW behavior

The script detects COW by logical-partition naming and by Android's official COW
magic. COW images keep their original logical partition size and are included in
the rebuilt super image without `e2fsck`, mounting, expansion, or shrinking. A
SHA-256 recorded at unpack time prevents accidental COW modification. The escape
hatch `--allow-cow-change` exists, but it should only be used when the caller
understands the snapshot format.

A dump taken during an active Virtual A/B update can have different LP metadata
in each slot. `lpmake` builds one layout and writes it to every metadata copy, so
an ordinary repack refuses to flatten a differing or incomplete source. The
explicit `--mirror-selected-slot-across-ab` mode uses the slot selected during
unpack (`--slot`, default `0`) as the payload set for both A and B while retaining
distinct slot-specific partition/group names and preserving unreadable reserved
metadata slots. This avoids silently mixing or flattening incompatible layouts.

Preserving a COW partition in `super` does not make an active snapshot portable by
itself. Snapshot state also lives under `/metadata`, and part of the COW can live
on `/data`. This tool preserves what is present in the supplied super image; it
does not merge or reconstruct an active OTA snapshot.

## Filesystem and verified-boot limits

- Only ext4 is grown, mounted writable, and shrunk. EROFS, F2FS, SquashFS, and
  unknown images remain opaque. EROFS is inherently read-only; converting it is a
  separate operation.
- Modifying an AVB-protected logical partition invalidates its existing hash tree
  or footer. This tool does not resign AVB metadata. Handle `vbmeta`/verity for the
  target device separately.
- Repack mutates the workspace's ext4 images into their minimized form before it
  calls `lpmake`. Run `super_rw.py expand super-work` to regrow them for another
  editing pass; the original super does not need to be unpacked again.
- The current script accepts a normal super image backed by one physical block
  device. Retrofit/split super sets that require multiple input image files are
  rejected instead of being packed incorrectly.

## Metadata preservation

The manifest records the selected source slot's:

- metadata version, maximum size, slot count, logical block size, and header flags;
- block-device size, first logical sector, alignment, alignment offset, and flags;
- group names, maximum sizes, and flags;
- partition names, groups, sizes, and all attribute bits.

The `lpmake` command initially supplies `readonly` where supported. The script then
restores the exact original attribute words—including `updated`, `disabled`, and
slot-suffixed bits—plus group/device flags and header flags in every primary and
backup metadata copy. It recalculates both header and tables SHA-256 checksums and
parses every copy again before publishing the output.

Some live images report 512-byte block-device alignment while retaining a first
logical sector padded to a historical 1 MiB boundary. For these images the script
uses a stricter temporary alignment while `lpmake` allocates extents, then restores
the reported alignment in the checksummed metadata. This preserves both the first
usable sector and the original block-device attributes. When a super reserves more
than two metadata slots, the optional `lpdump` report is limited to the selected
slot because common AOSP builds abort when `--all` reaches slot 2.

Relevant AOSP references:

- [Dynamic partition tools](https://android.googlesource.com/platform/system/extras/+/refs/heads/main/partition_tools/)
- [LP metadata format](https://android.googlesource.com/platform/system/core/+/refs/heads/main/fs_mgr/liblp/include/liblp/metadata_format.h)
- [Virtual A/B overview](https://source.android.com/docs/core/ota/virtual_ab)
