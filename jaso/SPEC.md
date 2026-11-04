# `.jaso` module format — format 1 ("beta 1")

Status: **beta**. Licensed under Apache-2.0 together with the rest of this repository.

> 中文摘要：`.jaso` 是语言中立的模块文件格式。本文定义 format 1（beta 1）的字节级布局、清单核心键、扩展段、
> 错误码表与 L1 运行期装载流程。beta 不是冻结版：任何不兼容修改都必须提升 `format` 号，并同步所有实现与一致性向量。
> 读取器只接受 `format = 1`；format 0 文件须先经打包工具一次性迁移。

Beta means: this is the first version that several independent implementations read and write and that ships with
conformance vectors (`jaso/vectors/`). Incompatible changes are still allowed during beta, but every such change
bumps `format` and updates all implementations and vectors together.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Layers

* **Core layer** (this document): file header, section directory, manifest, platform description, image index,
  native segments, exports, relocations, managed code, extension sections, signature. The core layer is
  language-neutral: no language's type system appears in it.
* **Extension layers** live inside `Ext` sections (§9), each under its own name. The Jasper layer owns the names
  `jasper.*` (§9.3). A core reader stores extension contents without interpreting them.

## 2. Conventions

* All integers are little-endian and unsigned unless stated otherwise.
* Offsets and lengths are byte counts relative to the start of the file unless stated otherwise.
* A reader MUST NOT trust any field: every offset/length computation is checked (no wrap-around), every
  out-of-range value, overlap, unknown enumerator or non-zero reserved field is a rejection, and a reader MUST NOT
  crash on any input.
* "Name" below means a non-empty ASCII string of the stated character set and maximum length; "NUL-padded"
  fields hold the name followed by zero bytes up to the field size, and every byte after the first zero MUST be zero.
* `PAGE = 4096`.
* Rejections are reported as error codes from §13. When several rules are violated, the reader reports the
  **first** violation in the order the checks are listed in §12.1 (this is what makes codes comparable across
  implementations).

## 3. File header (80 bytes, offset 0)

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | `magic` | `89 4A 41 53 4F 0D 0A 1A` (`\x89JASO\r\n\x1a`) |
| 8 | 2 | `format` | `1` |
| 10 | 2 | `kind` | `1` Native, `2` Managed, `3` Hybrid (§4) |
| 12 | 2 | `arch` | quick filter: `0` any (see below), `1` x86_64, `2` aarch64, `3` riscv64, `4` riscv32 |
| 14 | 1 | `stage` | `0` runtime, `1` boot, `2` build |
| 15 | 1 | reserved | 0 |
| 16 | 4 | `header_size` | 80 |
| 20 | 4 | `section_count` | 1 ..= 64 |
| 24 | 4 | `section_dir_offset` | ≥ 80; directory MUST lie inside the file |
| 28 | 4 | `file_len` | equals the actual file length |
| 32 | 4 | reserved | 0 (format 0 kept the image size here; it moved to the image index) |
| 36 | 4 | reserved | 0 |
| 40 | 32 | `digest` | SHA-256 of the whole file with these 32 bytes taken as zero |
| 72 | 8 | reserved | 0 |

`arch` rules:

* `arch ≠ 0`: every platform record (§6) that an image refers to MUST have this `isa`.
* `arch = 0` ("any"): no constraint; used by Managed files and by native files that carry images for several
  instruction sets. A Native or Hybrid file whose images all share one `isa` SHOULD set `arch` to it.

The digest proves the file is unmodified; it does not prove origin (that is the signature's job, §10).

## 4. Module kinds

| `kind` | Meaning | Images allowed | Extra requirement |
|---:|---|---|---|
| 1 | Native: machine code mapped into an address space | native only | — |
| 2 | Managed: a managed-runtime image (beta defines exactly one carrier: JVM class files) | managed only | — |
| 3 | Hybrid: native code plus its own Jasper binding | native only | exactly one `jasper.import` extension, critical (§9.3) |

Every image in a file MUST have the image kind the table allows (`image.kind` otherwise).

## 5. Section directory

`section_count` entries of 32 bytes each, starting at `section_dir_offset`:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | `kind` |
| 4 | 4 | `flags` |
| 8 | 4 | `file_offset` |
| 12 | 4 | `file_size` |
| 16 | 4 | `vaddr` |
| 20 | 4 | `mem_size` |
| 24 | 8 | reserved (0) |

Section kinds:

| `kind` | Name | Count per file | Belongs to | `flags` | `vaddr`/`mem_size` |
|---:|---|---|---|---|---|
| 1 | Manifest | exactly 1 | file | 0 | 0 |
| 2 | Segment | see §7 | one image | R=1 \| W=2 \| X=4 | used |
| 3 | Exports | ≤ 1 per image | one image | 0 | 0 |
| 4 | Relocs | ≤ 1 per native image | one image | 0 | 0 |
| 5 | Signature | ≤ 1 | file | 0 | 0 |
| 6 | Platform | exactly 1 | file | 0 | 0 |
| 7 | Images | exactly 1 | file | 0 | 0 |
| 8 | Ext | ≤ 32 | file | bit 0 = critical, other bits 0 | 0 |
| 9 | Code | exactly 1 per managed image | one image | 0 | 0 |

Rules (all `section.*` unless noted):

* `file_offset + file_size` MUST NOT overflow and MUST be ≤ `file_len`; a section with `file_size > 0` MUST start
  at or after offset 80 (`section.bounds`).
* Unknown `kind` → `section.unknown`. Too many of a kind → `section.duplicate`. A required kind absent →
  `section.missing`.
* "Belongs to one image" sections are assigned through the image index (§6.2); "file" sections MUST NOT fall inside
  any image's directory range (`image.index`).

## 6. Platform description and image index

### 6.1 Platform section (kind 6)

```
count     u32   1 ..= 16
reserved  u32   0
records   count × 64 bytes
```

The section size MUST be exactly `8 + 64 × count`. Each record:

| Offset | Size | Field | Values |
|---:|---:|---|---|
| 0 | 2 | `isa` | `0` none (managed), `1` x86_64, `2` aarch64, `3` riscv64, `4` riscv32 |
| 2 | 1 | `pointer_bytes` | `0` (managed only), `4`, `8`; MUST match `isa` (riscv32 → 4, other native → 8) |
| 3 | 1 | `float_abi` | `0` none (managed only), `1` soft, `2` hard |
| 4 | 2 | `target` | `1` jasper-os, `2` jvm, `3` host (a conventional host OS process) |
| 6 | 2 | reserved | 0 |
| 8 | 32 | `isa_ext` | NUL-padded; empty, or comma-separated tokens of `[a-z0-9_]`, each ≤ 15 bytes, no duplicates, e.g. `i,m,a,c` |
| 40 | 16 | `abi` | NUL-padded name `[a-z0-9._]`, 1 ..= 16 bytes, e.g. `c.v1`, `jvm.52` |
| 56 | 8 | reserved | 0 |

Consistency: `isa = 0` ⇔ `target = 2` (jvm) ⇔ `pointer_bytes = 0` ⇔ `float_abi = 0`. Violations of this
section's layout or value rules → `platform.malformed`; the header `arch` rule (§3) → `platform.arch`.
The manifest `core.abi` MUST equal the `abi` of every record that some image refers to (`platform.abi`).

### 6.2 Images section (kind 7)

```
count     u32   1 ..= 8
reserved  u32   0
entries   count × 32 bytes
```

The section size MUST be exactly `8 + 32 × count`. Each entry:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 2 | `image_kind` | `1` native, `2` managed |
| 2 | 2 | `platform` | index into the platform records (< `count` of §6.1) |
| 4 | 4 | `first_section` | first directory index of this image |
| 8 | 4 | `section_count` | ≥ 1; `[first_section, first_section + section_count)` inside the directory |
| 12 | 4 | `image_size` | native: page multiple, 1 page ..= 64 MiB; managed: 0 |
| 16 | 16 | reserved | 0 |

Rules (`image.index` unless noted): ranges of different entries MUST NOT overlap; every section of a
"belongs to one image" kind MUST be inside exactly one range and every section inside a range MUST be of such a
kind; the platform record's `isa = 0` iff `image_kind = 2`; `image_size` rule → `image.size`. Two entries MAY refer
to the same platform record only if they are identical apart from the section range — a reader rejects it otherwise
(`image.index`), because selection (§12.2) would be ambiguous.

Writers in beta produce exactly one image per file; readers MUST accept up to 8.

## 7. Native image contents

A native image has ≥ 1 Segment, ≤ 1 Exports, ≤ 1 Relocs and no Code (`image.index`).

### 7.1 Segment (kind 2)

`vaddr` and `mem_size` are relative to the image's load base. Rules: `flags` ⊆ {R,W,X} and R set (`image.segment`);
not both W and X (`image.wx`); `vaddr` page-aligned, `mem_size > 0`, `mem_size ≥ file_size`,
`vaddr + roundup(mem_size, PAGE) ≤ image_size` without overflow (`image.segment`); bytes beyond `file_size` are
zero-filled at load. Two segments of the same image MUST NOT share a page (`image.overlap`).

### 7.2 Exports (kind 3)

```
count    u32   ≤ 1024
entries  count × { name_offset u32, name_len u32, value u32, kind u32 }
names    bytes
```

`name_offset` is relative to the section start and MUST point at or after the entry array; names are 1 ..= 128
bytes of `[A-Za-z0-9_.$]`, unique within the table (`image.exports`). Native export `kind = 1` (C-convention
function): `value` is an image offset that MUST fall inside an X segment (`image.export_range`).

### 7.3 Relocs (kind 4)

```
count    u32
entries  count × { offset u32, kind u32, addend u64 }
```

The section size MUST be exactly `4 + 16 × count`. `kind = 1` writes 8 bytes `base + addend` (pointer width 8);
`kind = 2` writes 4 bytes (pointer width 4); the kind MUST match the image's platform `pointer_bytes`
(`image.reloc`). `offset` is aligned to the write width, the written bytes lie inside a non-X segment and
`addend < image_size` (`image.reloc_range`).

## 8. Managed image contents

A managed image has exactly one Code section, ≤ 1 Exports, and no Segment or Relocs (`image.index`).

* **Code** (kind 9): `format u32` (`1` = JVM class archive: a stored-only ZIP of `.class` files) · reserved u32 (0) ·
  payload (≥ 1 byte). Unknown `format` or non-zero reserved → `image.code`. The core reader does not inspect the
  payload; the managed runtime that loads it does.
* **Exports**: layout of §7.2 with export `kind = 2` (managed symbol) and `value = 0`; names are the
  runtime-qualified symbols (for JVM: `package.Class.member`) (`image.exports`).

## 9. Extension sections (kind 8)

### 9.1 Layout

```
version   u32    ≥ 1
name_len  u16    1 ..= 64
reserved  u16    0
name      name_len bytes   [a-z0-9_.-], contains at least one '.', e.g. jasper.import
padding   zero bytes up to the next multiple of 8 (relative to the section start)
content   the remaining bytes of the section (may be empty)
```

Directory `flags` bit 0 is the **critical** flag. Malformed layout → `extension.malformed`; two Ext sections with
the same `name` → `extension.duplicate`.

### 9.2 Handling

A reader knows a set of `(name, version)` pairs. For each Ext section:

* known name and version → stored for the layer that owns it;
* otherwise, critical = 0 → skipped (still covered by digest and signature);
* otherwise, critical = 1 → `extension.critical`.

### 9.3 Names reserved by the Jasper layer

| Name | Version | Critical | Beta status |
|---|---:|---|---|
| `jasper.import` | 1 | MUST be 1 | defined by the Jasper layer: typed export declarations; required in Hybrid files |
| `jasper.source` | 1 | MUST be 0 | defined by the Jasper layer: optional source text; no loader is required to use it |
| `jasper.types`, `jasper.gc`, `jasper.error`, `jasper.command` | — | — | reserved, no content defined in beta |

A conforming beta reader knows exactly `(jasper.import, 1)` and `(jasper.source, 1)` at the core layer; it checks the
critical flag above (`extension.malformed` if wrong) but not their contents: structural reading never looks inside
them. An L1 load checks `jasper.import` (§9.4, §12.2 step 6a). A Hybrid file without exactly one `jasper.import` →
`extension.required`. Non-Jasper namespaces (`ui.*`, `web.*`, `jasql.*`, …) are owned by their frameworks.

### 9.4 `jasper.import` version 1

The content declares the module's typed exports. It is covered by the digest and the signature like every other
section. It is UTF-8 text of at most 65536 bytes and at most 1024 effective lines. Each line has surrounding
whitespace removed; empty lines and lines starting with `#` are ignored. An effective line is one of:

```
package <dotted>                 at most one; the Jasper package of the module
type <ident>                     a type the module defines
cap <capability>                 a capability the binding's functions use
fn <symbol>(<params>): <type>    one exported function

params  := empty | param (',' param)*
param   := <ident> ':' <type>
type    := [ 'own ' | 'borrow ' ] <dotted> [ '<' type (',' type)* '>' ] [ '?' ]      nesting depth ≤ 8
dotted  := <ident> ('.' <ident>)*
ident   := [A-Za-z_][A-Za-z0-9_]*
symbol  := an export name (§7)
```

Spaces (U+0020 only) are allowed between tokens. `own` transfers ownership across the boundary, `borrow` lends for
the duration of the call, no keyword passes by value; `?` means nullable. Type names are checked for syntax only,
their meaning belongs to the Jasper layer. There is no pointer syntax, so raw pointers cannot appear in a binding.

Agreement with the core layer, independent of line order:

* the set of `fn` symbols equals `core.exports` minus the lifecycle exports `jaso_init`, `jaso_start`, `jaso_stop`;
* every `cap` is listed in `core.requires`: a binding never asks for more than the manifest;
* no two lines declare the same `fn`, `type` or `cap`.

Any violation → `extension.binding`.

## 10. Signature (kind 5)

Exactly 104 bytes: `scheme u32` (`1` = Ed25519, RFC 8032 strict verification) · reserved u32 (0) ·
`publisher_key[32]` · `signature[64]`. It MUST be the last 104 bytes of the file and every other section and the
directory MUST end at or before its start (`signature.section`).

The signed digest is SHA-256 over the whole file with the 32-byte header `digest` and the 64-byte `signature`
value taken as zero (the publisher key and scheme are covered). The signed message is the ASCII bytes
`jaso.signature.v1` followed by one zero byte, followed by that digest. Signature verification and the trust
decision belong to the loader (§12.2), not to structural parsing.

## 11. Manifest (kind 1)

UTF-8 text (`manifest.utf8`). One `key = value` per line; key and value are trimmed of surrounding whitespace;
blank lines and lines starting with `#` are ignored; any other line without `=` → `manifest.line`.
"Whitespace" throughout this section is the Unicode `White_Space` property (it includes U+0085, U+00A0, U+2003 and
U+3000, not only ASCII); the same definition applies to the comma-separated lists in manifest values.

| Key | Required | Single | Value |
|---|---|---|---|
| `core.name` | yes | yes | `[a-z0-9._-]`, 1 ..= 64 |
| `core.version` | yes | yes | `major.minor.patch`, decimal, each 1 ..= 9 digits |
| `core.abi` | yes | yes | `[a-z0-9._]`, 1 ..= 16; equals the platform `abi` (§6.1) |
| `core.stage` | yes | yes | `build`, `boot` or `runtime`; MUST equal header `stage` (`manifest.stage`) |
| `core.lifecycle` | no | yes | `plugin` (default) or `system` |
| `core.runtime` | no | yes | a version range (below) the host runtime MUST satisfy |
| `core.depends` | no | no | dependency list (below) |
| `core.host` | no | yes | host interface table name, `[a-z0-9._]`, 1 ..= 32 |
| `core.requires` | no | no | comma-separated capability names `[a-z0-9._]`, 1 ..= 64; ≤ 32 in total |
| `core.exports` | no | no | comma-separated export names (§7.2 charset); ≤ 256 in total |
| `core.description` | no | yes | free text |
| `core.publisher` | no | yes | `[a-z0-9._-]`, 1 ..= 64; MUST be present when the file is signed (checked by the loader) |

* An unknown `core.*` key → `manifest.key`; other keys MUST be `<namespace>.<key>` with namespace `[a-z0-9_-]`
  1 ..= 32 and key `[a-z0-9._-]` 1 ..= 64 (`manifest.key`), and are kept uninterpreted for their framework.
* A required key absent → `manifest.missing`; a single key repeated → `manifest.duplicate`; a bad value →
  `manifest.value`; a count limit exceeded → `manifest.limit`.
* **Exports must be declared**: every image's export table MUST correspond one-to-one with `core.exports`
  (no missing, no extra, no duplicate declarations) → `image.exports_mismatch`.

**Version range** (`core.runtime`, and after `@` in `core.depends`): one or more comparators separated by `,`;
a comparator is an operator `>=`, `>`, `<=`, `<` or `=` immediately followed by a version `major.minor[.patch]`
(missing patch = 0). The range is satisfied when all comparators are. At most 4 comparators per range.
Example: `core.runtime = >=0.1,<0.2`.

**Dependency list** (`core.depends`): entries `name` or `name@range`, where `name` follows `core.name`. Because a
range itself contains commas, the value is split on `,` and a piece that starts with `<`, `>` or `=` continues the
range of the previous entry; any other piece starts a new entry. Example:
`core.depends = jaso-log@>=1.0,<2.0, jaso-fmt` declares two dependencies. Names MUST be unique across all
`core.depends` lines; at most 32 entries.

## 12. Reading and loading

### 12.1 Structural read (static; no host context)

In this order, first failure wins:

1. header: length ≥ 80 (`format.truncated`), magic (`format.magic`), `format` (`version.unsupported`),
   `kind` (`format.kind`), `arch` (`format.arch`), `stage` (`format.stage`), reserved/`header_size`
   (`format.header`), `file_len` (`format.length`), digest (`format.digest`);
2. directory placement and count (`section.dir`), then each entry in index order (`section.*`, per-kind
   flags/vaddr rules: `section.dir`);
3. required sections present (`section.missing`);
4. Platform (§6.1), then Images (§6.2) including section assignment;
5. per image in index order: segments, overlap, exports, relocs or code (§7, §8);
6. manifest (§11), then `core.abi` against platforms (`platform.abi`), then export declarations;
7. extensions in directory order (§9), then the Hybrid requirement;
8. signature section layout (§10).

Order inside the steps (normative; the reference implementation follows it):

* step 2, per directory entry: `kind` (`section.unknown`) → reserved field and per-kind `flags`/`vaddr`/`mem_size`
  (`section.dir`) → bounds (`section.bounds`) → per-file count of that kind (`section.duplicate`). Per-image limits
  (≤ 1 Exports per image, …) are not checked here.
* step 3: Manifest, then Platform, then Images.
* step 4, per image entry in index order: `image_kind` value, reserved bytes, platform index, section range, and
  `isa = 0` ⇔ managed (all `image.index`) → kind allowed by the module kind (`image.kind`) → `image_size`
  (`image.size`); then, over all pairs of entries, range overlap and shared-platform equality (`image.index`); then
  section assignment in directory order (`image.index`); finally the header `arch` rule (`platform.arch`).
* step 5, per image: composition (§7 / §8 counts, `image.index`) → each Segment in directory order → page overlap
  → exports → relocs (native) or code then exports (managed).
* step 6: manifest lines in order (first bad line wins); after all lines, missing keys in the order `core.name`,
  `core.version`, `core.abi`, `core.stage`; then `manifest.stage`, `platform.abi`, `image.exports_mismatch`.
  `core.depends`, `core.requires` and `core.exports` limits are reported on the line that exceeds them.
  Within such a line every entry is still value-checked first (`manifest.value` wins over `manifest.limit`).
  `core.depends` uniqueness is checked for the first 32 entries of the manifest only: a line that exceeds the limit
  reports `manifest.limit` even if a name repeats among the entries past the 32nd, so the check stays linear in the
  manifest size.
* step 7, per Ext section in directory order: layout (`extension.malformed`) → same name as an earlier Ext
  (`extension.duplicate`) → critical flag of a known `(name, version)` (`extension.malformed`) or unknown critical
  (`extension.critical`); after all sections, the Hybrid requirement.

A `platform.mismatch` report for `isa_ext` names the first file token the host lacks as the actual value and `-`
as the expected value.

### 12.2 L1 runtime load

Loading is all-or-nothing: nothing is mapped, linked or called before every step before 7 succeeds, and a failure
leaves no trace except an audit record.

1. **Read** the structure (§12.1).
2. **Trust** (`trust.*`, `signature.invalid`): the loader's trust policy has a mode (enforce / development) and a
   table of trusted publishers `{name, namespace prefix, Ed25519 key}`. Unsigned → `trust.unsigned` in enforce mode
   (development mode admits it and MUST emit an audit record); missing `core.publisher` → `trust.publisher`;
   publisher not in the table → `trust.publisher`; key differs from the table → `trust.key`; `core.name` outside
   the publisher's namespace → `trust.namespace`; signature does not verify → `signature.invalid`.
   Kernel-mode loading accepts only `build`/`boot` stage files signed by an allow-listed publisher.
3. **Platform**: select the first image whose platform record matches the host: equal `isa`, `target`,
   `pointer_bytes`, `float_abi`, `abi`, and every `isa_ext` token present in the host's set. No match →
   `platform.mismatch`, reported with the first differing field of image 0 (`isa`, `isa_ext`, `target`,
   `abi`, `float_abi`, `pointer_bytes` — checked in this order) and its expected (host) and actual (file) value.
4. **Runtime**: `core.runtime` against the host runtime version → `dependency.runtime`.
5. **Dependencies**: each `core.depends` entry MUST be satisfied by an already-loaded, running (not stopped) module
   of that name whose version is in range → `dependency.unsatisfied` (L1 never downloads anything).
6. **Capabilities**: every `core.requires` name MUST be granted by the caller → `capability.denied`.
   Capabilities in the manifest are requests, never grants.
6a. **Binding**: a file carrying `jasper.import` (always a Hybrid file; optional on the others) MUST satisfy §9.4 →
   `extension.binding`.
7. **Link**: map segments with their permissions, apply relocations (native), or hand the Code payload to the
   managed runtime (managed).
8. **Discover** services from the manifest and the export table — never by reflection.
9. **init** then **start**: native modules with `core.host` export `jaso_init(host: *const Host) -> i32`; optional
   `jaso_start() -> i32` and `jaso_stop() -> i32`. Non-zero return → the load fails and the image is unmapped.
   The beta host interface table is `jaso.host.v1` (same C layout as before: `version u32 = 1`, `size u32`,
   `log`, `alloc`, `dealloc`; later functions are only appended). The native calling convention is `c.v1`.

**stop and unload in beta.** `stop` is defined and implemented: the loader calls `jaso_stop` (if exported) and
the module stops serving. A loader refuses to stop a module that a running module depends on. Unloading (L2) and hot replacement (L3) are not part of beta: an unload request for a
`plugin` module returns *deferred* and the module stays mapped; a `system` module refuses unload. A loader MUST
NOT report a deferred unload as done.

## 13. Error codes

Every implementation MUST report the same code for the same file under the same context. Codes are stable names;
the numbers are for compact binary transport. Codes marked *load* need host context (§14).

| Number | Code | Meaning |
|---:|---|---|
| 101 | `format.truncated` | shorter than the header |
| 102 | `format.magic` | wrong magic |
| 103 | `format.header` | `header_size` ≠ 80 or a reserved header field ≠ 0 |
| 104 | `format.length` | `file_len` ≠ actual length |
| 105 | `format.digest` | integrity digest mismatch |
| 106 | `format.kind` | unknown module kind |
| 107 | `format.arch` | unknown `arch` value |
| 108 | `format.stage` | unknown `stage` value |
| 201 | `version.unsupported` | `format` ≠ 1 |
| 301 | `section.dir` | directory out of file, bad count, or bad per-kind directory fields |
| 302 | `section.bounds` | section content outside the file |
| 303 | `section.unknown` | unknown section kind |
| 304 | `section.duplicate` | more sections of a kind than allowed |
| 305 | `section.missing` | a required section is absent |
| 401 | `manifest.utf8` | manifest is not UTF-8 |
| 402 | `manifest.line` | a line is not `key = value` |
| 403 | `manifest.key` | unknown `core.*` key or malformed extension key |
| 404 | `manifest.missing` | required key absent |
| 405 | `manifest.duplicate` | single-valued key repeated, or duplicate dependency name |
| 406 | `manifest.value` | malformed value |
| 407 | `manifest.limit` | count limit exceeded |
| 408 | `manifest.stage` | `core.stage` ≠ header `stage` |
| 501 | `platform.malformed` | Platform section layout or values invalid |
| 502 | `platform.arch` | header `arch` inconsistent with a referenced platform record |
| 503 | `platform.abi` | `core.abi` ≠ a referenced platform `abi` |
| 504 | `platform.mismatch` | *load*: no image matches the host platform |
| 601 | `image.index` | Images section invalid or sections not correctly assigned to images |
| 602 | `image.kind` | image kind not allowed by the module kind |
| 603 | `image.size` | bad `image_size` |
| 604 | `image.segment` | bad segment |
| 605 | `image.wx` | segment both writable and executable |
| 606 | `image.overlap` | two segments share a page |
| 607 | `image.exports` | malformed export table |
| 608 | `image.export_range` | native export outside an executable segment |
| 609 | `image.exports_mismatch` | export table ≠ `core.exports` |
| 610 | `image.reloc` | malformed relocation table or wrong relocation kind |
| 611 | `image.reloc_range` | relocation target out of range, misaligned or in an executable segment |
| 612 | `image.code` | malformed Code section |
| 701 | `signature.section` | malformed or misplaced signature section |
| 702 | `signature.invalid` | *load*: signature does not verify |
| 801 | `trust.unsigned` | *load*: unsigned file in enforce mode |
| 802 | `trust.publisher` | *load*: `core.publisher` missing or not trusted |
| 803 | `trust.key` | *load*: signing key differs from the trusted key |
| 804 | `trust.namespace` | *load*: module name outside the publisher's namespace |
| 901 | `capability.denied` | *load*: a required capability is not granted |
| 1001 | `dependency.unsatisfied` | *load*: a dependency is missing or out of range |
| 1002 | `dependency.runtime` | *load*: host runtime version outside `core.runtime` |
| 1101 | `extension.malformed` | malformed Ext section, or wrong critical flag on a reserved name |
| 1102 | `extension.critical` | unknown critical extension or unsupported version |
| 1103 | `extension.duplicate` | two Ext sections with the same name |
| 1104 | `extension.required` | Hybrid file without exactly one `jasper.import` |
| 1105 | `extension.binding` | *load*: `jasper.import` violates §9.4 |

## 14. Conformance vectors

`jaso/vectors/` holds files `<name>.jaso`, each with `<name>.expect` containing one line: `ok` or an error code
from §13. Vectors are regenerated by a script in the repository; every implementation runs all of them and MUST
produce the expected line. Static codes are checked by structural read (§12.1); *load* codes and `ok` are checked
by an L1 load (§12.2, steps 1–6a) in this fixed **conformance context**:

* host platform: `isa` x86_64, `isa_ext` empty, `target` jasper-os, `pointer_bytes` 8, `float_abi` hard,
  `abi` `c.v1`; for Managed files: `isa` none, `target` jvm, `abi` `jvm.52`;
* host runtime version `0.1.0`;
* trust mode enforce, one trusted publisher `jasper.dev`, namespace `jaso-`, with the public development key
  published next to the vectors (development-only; never trusted in production);
* already-loaded modules: `jaso-base` version `1.2.0`;
* granted capabilities: `log`, `alloc`;
* extensions known at the core layer: §9.3.

A trusted key that is not a valid curve point can never match a signing key, so its result is `trust.key`, the same
as a key that differs from the table.

## 15. Changes from format 0

* `format` 0 → 1; readers accept only 1. Format 0 files are migrated once by the packing tool.
* Header offset 32 (image size) is now reserved; image size lives in the image index.
* New sections: Platform (6), Images (7), Ext (8), Code (9); Managed and Hybrid kinds are defined.
* Exports and Relocs are per image.
* New manifest keys `core.stage` (required), `core.lifecycle`, `core.runtime`, `core.depends`.
* Signature domain string `jaso.signature.v0` → `jaso.signature.v1`.
* Calling convention `c.v0` → `c.v1`, host table `jaso.host.v0` → `jaso.host.v1`; lifecycle exports
  `jaso_start` / `jaso_stop` added.
* Stable error codes (§13) and conformance vectors (§14).
