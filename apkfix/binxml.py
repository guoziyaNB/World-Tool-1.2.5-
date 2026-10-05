#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read AndroidManifest.xml (compiled AXML, binary) out of a read-only APK and
report the decisive fields.

Read-only contract: the APK is opened with zipfile in 'r' mode and the target
entry is decompressed in memory.  Nothing is ever written back to the APK or to
its directory.

Attribute identification uses two independent sources and cross-checks them:
  1. the string pool entry referenced by the attribute's name index;
  2. the RES_XML_RESOURCE_MAP chunk: entry i holds the android.R.attr resource
     id of string-pool entry i, so resource_map[name_index] is the attribute's
     numeric id (0x0101xxxx) even when the name string was stripped.

Usage:  python binxml.py <apk-or-manifest>
        （apk：自动取其中 AndroidManifest.xml；xml：直接解析该二进制 XML）
"""

import json
import struct
import sys
import zipfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ENTRY = "AndroidManifest.xml"

RES_STRING_POOL = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NS = 0x0100
RES_XML_END_NS = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_RESOURCE_MAP = 0x0180

ANDROID_NS = "http://schemas.android.com/apk/res/android"

TYPE_NAMES = {
    0x00: "NULL",
    0x01: "REFERENCE",
    0x02: "ATTRIBUTE",
    0x03: "STRING",
    0x04: "FLOAT",
    0x05: "DIMENSION",
    0x06: "FRACTION",
    0x07: "DYNAMIC_REFERENCE",
    0x08: "DYNAMIC_ATTRIBUTE",
    0x10: "INT_DEC",
    0x11: "INT_HEX",
    0x12: "INT_BOOLEAN",
    0x1C: "INT_COLOR_ARGB8",
}

# AOSP framework attribute ids (android.R.attr), each name<->id pair independently
# corroborated by `aapt2 dump xmltree` from Android SDK build-tools 36.0.0
# (see 06_logs/aapt2_xmltree.txt).  The reference snippet axml.py in this project
# lists 0x01010270 as extractNativeLibs; that is wrong -- 0x01010270 is
# targetSdkVersion, extractNativeLibs is 0x010104ea.
ATTR_BY_ID = {
    0x01010000: "theme",
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010006: "permission",
    0x01010009: "protectionLevel",
    0x0101000E: "enabled",
    0x01010010: "exported",
    0x01010018: "authorities",
    0x0101001B: "grantUriPermissions",
    0x0101001E: "screenOrientation",
    0x01010024: "value",
    0x01010025: "resource",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x01010271: "maxSdkVersion",
    0x01010280: "allowBackup",
    0x010102D3: "hardwareAccelerated",
    0x010103AF: "supportsRtl",
    0x010104EA: "extractNativeLibs",
    0x010104EB: "fullBackupContent",
    0x01010505: "directBootAware",
    0x0101052C: "roundIcon",
    0x01010572: "compileSdkVersion",
    0x01010573: "compileSdkVersionCodename",
    0x0101057A: "appComponentFactory",
    0x0101063E: "dataExtractionRules",
}


def varint_utf16(buf, p):
    n = struct.unpack_from("<H", buf, p)[0]
    p += 2
    if n & 0x8000:
        n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", buf, p)[0]
        p += 2
    return n, p


def varint_utf8(buf, p):
    n = buf[p]
    p += 1
    if n & 0x80:
        n = ((n & 0x7F) << 8) | buf[p]
        p += 1
    return n, p


def decode_string_pool(buf, off):
    """Return (strings, meta) for a RES_STRING_POOL chunk at `off`."""
    typ, hdr_size, chunk_size = struct.unpack_from("<HHI", buf, off)
    assert typ == RES_STRING_POOL, hex(typ)
    count, style_count, flags, strings_start, styles_start = struct.unpack_from(
        "<IIIII", buf, off + 8
    )
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from("<%dI" % count, buf, off + hdr_size) if count else ()
    out = []
    for o in offsets:
        p = off + strings_start + o
        if utf8:
            _, p = varint_utf8(buf, p)  # length in UTF-16 code units
            nbytes, p = varint_utf8(buf, p)  # length in bytes
            s = buf[p : p + nbytes].decode("utf-8", "replace")
        else:
            n, p = varint_utf16(buf, p)  # length in UTF-16 code units
            s = buf[p : p + n * 2].decode("utf-16-le", "replace")
        out.append(s)
    meta = {
        "chunk_off": off,
        "header_size": hdr_size,
        "chunk_size": chunk_size,
        "string_count": count,
        "style_count": style_count,
        "flags": "0x%08x" % flags,
        "encoding": "UTF-8" if utf8 else "UTF-16LE",
        "utf8_flag_0x100": utf8,
        "strings_start": strings_start,
        "styles_start": styles_start,
    }
    return out, meta


def chunk_table(buf):
    """Walk the top-level RES_XML chunk and yield (type, header_size, size, off)."""
    typ, hdr_size, total = struct.unpack_from("<HHI", buf, 0)
    assert typ == RES_XML_TYPE, "not an AXML file: 0x%04x" % typ
    rows = []
    off = hdr_size
    while off + 8 <= total:
        rtyp, rhsz, rsz = struct.unpack_from("<HHI", buf, off)
        if rsz == 0:
            break
        rows.append((rtyp, rhsz, rsz, off))
        off += rsz
    return rows, hdr_size, total


def parse_axml(buf):
    rows, hdr_size, total = chunk_table(buf)
    strpool = []
    sp_meta = None
    resource_map = []
    rm_meta = None
    elements = []  # (depth, kind, dict)
    depth = 0

    for rtyp, rhsz, rsz, off in rows:
        if rtyp == RES_STRING_POOL:
            strpool, sp_meta = decode_string_pool(buf, off)
        elif rtyp == RES_XML_RESOURCE_MAP:
            n = (rsz - rhsz) // 4
            resource_map = list(struct.unpack_from("<%dI" % n, buf, off + rhsz))
            rm_meta = {"chunk_off": off, "count": n, "chunk_size": rsz}
        elif rtyp == RES_XML_START_NS:
            prefix_i, uri_i = struct.unpack_from("<ii", buf, off + 16)
            elements.append(
                (
                    depth,
                    "start-ns",
                    {"prefix": sp(strpool, prefix_i), "uri": sp(strpool, uri_i)},
                )
            )
        elif rtyp == RES_XML_END_NS:
            prefix_i, uri_i = struct.unpack_from("<ii", buf, off + 16)
            elements.append(
                (
                    depth,
                    "end-ns",
                    {"prefix": sp(strpool, prefix_i), "uri": sp(strpool, uri_i)},
                )
            )
        elif rtyp == RES_XML_START_ELEMENT:
            ns_i, name_i = struct.unpack_from("<ii", buf, off + 16)
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", buf, off + 24)
            attrs = []
            for i in range(attr_count):
                a = off + 16 + attr_start + i * attr_size
                a_ns, a_name, a_raw = struct.unpack_from("<iii", buf, a)
                v_size, v_res0, v_type, v_data = struct.unpack_from("<HBBI", buf, a + 12)
                attrs.append(
                    dict(
                        off=a,
                        ns=sp(strpool, a_ns),
                        name_index=a_name,
                        raw_index=a_raw,
                        name_from_pool=sp(strpool, a_name) if 0 <= a_name < len(strpool) else None,
                        res_id=resource_map[a_name]
                        if 0 <= a_name < len(resource_map)
                        else None,
                        value_type=v_type,
                        value_type_name=TYPE_NAMES.get(v_type, hex(v_type)),
                        data=v_data,
                        value=render_value(strpool, v_type, v_data, v_res0),
                    )
                )
            for at in attrs:
                at["name"], at["resolve_method"] = resolve_attr_name(at)
            elements.append(
                (
                    depth,
                    "start",
                    {"ns": sp(strpool, ns_i), "name": sp(strpool, name_i), "attrs": attrs},
                )
            )
            depth += 1
        elif rtyp == RES_XML_END_ELEMENT:
            ns_i, name_i = struct.unpack_from("<ii", buf, off + 16)
            depth = max(depth - 1, 0)
            elements.append(
                (depth, "end", {"ns": sp(strpool, ns_i), "name": sp(strpool, name_i)})
            )
        elif rtyp == RES_XML_CDATA:
            data_i = struct.unpack_from("<i", buf, off + 16)[0]
            elements.append((depth, "cdata", {"text": sp(strpool, data_i)}))
        else:
            elements.append((depth, "chunk", {"type": "0x%04x" % rtyp}))

    return {
        "header_size": hdr_size,
        "total_size": total,
        "chunks": rows,
        "strings": strpool,
        "string_pool_meta": sp_meta,
        "resource_map": resource_map,
        "resource_map_meta": rm_meta,
        "elements": elements,
    }


def sp(strpool, i):
    if 0 <= i < len(strpool):
        return strpool[i]
    return None


def resolve_attr_name(at):
    """Attribute name: prefer the string-pool hit, corroborate with resource id."""
    pool_name = at.get("name_from_pool")
    res_id = at.get("res_id")
    table_name = ATTR_BY_ID.get(res_id) if res_id else None
    if pool_name and table_name and pool_name == table_name:
        return pool_name, "string pool + resource id agree"
    if pool_name:
        return pool_name, "string pool"
    if table_name:
        return table_name, "resource id lookup"
    if res_id:
        return "0x%08x" % res_id, "resource id (unknown)"
    return "<unnamed>", "no name index"


def render_value(strpool, v_type, v_data, v_res0):
    if v_type == 0x03:
        return sp(strpool, v_data) if 0 <= v_data < len(strpool) else "<?%d>" % v_data
    if v_type == 0x12:
        return "true" if v_data != 0 else "false"
    if v_type == 0x01:
        return "@ref(0x%08x)" % v_data
    if v_type == 0x02:
        return "?attr(0x%08x)" % v_data
    if v_type == 0x11:
        return "0x%08x" % v_data
    if v_type == 0x10:
        return str(struct.unpack("<i", struct.pack("<I", v_data))[0])
    if v_type == 0x04:
        return repr(struct.unpack("<f", struct.pack("<I", v_data))[0])
    return "raw:0x%08x" % v_data


def find(elements, name):
    return [e for e in elements if e[1] == "start" and e[2]["name"] == name]


def attr_of(el, name):
    for at in el[2]["attrs"]:
        if at["name"] == name or at["name"].split(":")[-1] == name:
            return at
    return None


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    apk_path = sys.argv[1]
    print("### APK: %s" % apk_path)
    with zipfile.ZipFile(apk_path, "r") as z:
        info = z.getinfo(ENTRY)
        print(
            "### entry %s: compress_type=%d file_size=%d compress_size=%d crc=0x%08x"
            % (ENTRY, info.compress_type, info.file_size, info.compress_size, info.CRC)
        )
        buf = z.read(ENTRY)
        libs = [
            (i.filename, i.compress_type, i.file_size, i.compress_size)
            for i in z.infolist()
            if i.filename.startswith("lib/")
        ]
    print("### read %d bytes" % len(buf))

    doc = parse_axml(buf)

    print("\n== chunk header ==")
    print(
        "header_size=%d total_size=%d" % (doc["header_size"], doc["total_size"])
    )
    for rtyp, rhsz, rsz, off in doc["chunks"]:
        print("  off=%-6d type=0x%04x header=%-3d size=%d" % (off, rtyp, rhsz, rsz))

    print("\n== string pool ==")
    print(json.dumps(doc["string_pool_meta"], ensure_ascii=False))
    for i, s in enumerate(doc["strings"]):
        print("  [%3d] %r" % (i, s))

    print("\n== resource map ==")
    print(json.dumps(doc["resource_map_meta"], ensure_ascii=False))
    for i, rid in enumerate(doc["resource_map"]):
        print(
            "  [%3d] 0x%08x  pool=%r  table=%r"
            % (i, rid, sp(doc["strings"], i), ATTR_BY_ID.get(rid))
        )

    print("\n== XML tree ==")
    for depth, kind, payload in doc["elements"]:
        pad = "  " * depth
        if kind == "start":
            attrs = " ".join(
                '%s="%s"' % (a["name"], a["value"]) for a in payload["attrs"]
            )
            print("%s<%s %s>" % (pad, payload["name"], attrs))
        elif kind == "end":
            print("%s</%s>" % (pad, payload["name"]))
        elif kind in ("start-ns", "end-ns"):
            print("%s<%s prefix=%r uri=%r>" % (pad, kind, payload["prefix"], payload["uri"]))
        elif kind == "cdata":
            print("%s<![CDATA[%s]]>" % (pad, payload["text"]))
        else:
            print("%s<chunk %s>" % (pad, payload["type"]))

    print("\n== attribute name provenance (every attribute of every element) ==")
    for depth, kind, payload in doc["elements"]:
        if kind != "start":
            continue
        for a in payload["attrs"]:
            print(
                "  %s/%-22s idx=%-4d pool=%-22r res_id=%s -> %-22s via %s  type=%s(%s) data=0x%08x value=%r"
                % (
                    payload["name"],
                    a["name"],
                    a["name_index"],
                    a["name_from_pool"],
                    ("0x%08x" % a["res_id"]) if a["res_id"] else None,
                    a["name"],
                    resolve_attr_name(a)[1],
                    a["value_type_name"],
                    hex(a["value_type"]),
                    a["data"],
                    a["value"],
                )
            )

    print("\n== FIELDS ==")
    root = find(doc["elements"], "manifest")[0]
    out = {}
    pkg = attr_of(root, "package")
    out["package"] = pkg["value"] if pkg else "NOT DECLARED"
    print("package = %r" % out["package"])

    for key in ("versionName", "versionCode"):
        a = attr_of(root, key)
        out[key] = (a["value"], a["name"], a["value_type_name"], a["data"]) if a else None
        print("%s = %s" % (key, out[key]))

    for sdk in find(doc["elements"], "uses-sdk"):
        for key in ("minSdkVersion", "targetSdkVersion", "maxSdkVersion"):
            a = attr_of(sdk, key)
            out["uses-sdk." + key] = (
                (a["value"], a["name"], a["value_type_name"], a["data"]) if a else "NOT DECLARED"
            )
            print("uses-sdk.%s = %s" % (key, out["uses-sdk." + key]))

    for app in find(doc["elements"], "application"):
        for key in (
            "extractNativeLibs",
            "appComponentFactory",
            "requestLegacyExternalStorage",
            "name",
            "debuggable",
            "usesCleartextTraffic",
            "hasCode",
            "networkSecurityConfig",
            "largeHeap",
        ):
            a = attr_of(app, key)
            out["application." + key] = (
                (a["value"], a["name"], a["value_type_name"], a["data"]) if a else "NOT DECLARED"
            )
            print("application.%s = %s" % (key, out["application." + key]))

    print("\n== uses-permission ==")
    perms = []
    for el in find(doc["elements"], "uses-permission"):
        a = attr_of(el, "name")
        perms.append(a["value"] if a else "NOT DECLARED")
    out["uses-permission"] = perms
    for p in perms:
        print("  %s" % p)

    print("\n== native / library related declarations ==")
    native_related = []
    for depth, kind, payload in doc["elements"]:
        if kind != "start":
            continue
        nm = payload["name"]
        if nm in ("uses-native-library", "uses-library", "meta-data", "application"):
            row = {a["name"]: a["value"] for a in payload["attrs"]}
            if nm in ("uses-native-library", "uses-library") or any(
                "native" in (a["name"] or "").lower() for a in payload["attrs"]
            ):
                native_related.append((nm, row))
                print("  <%s %s>" % (nm, " ".join('%s="%s"' % kv for kv in row.items())))
    out["native-related"] = native_related

    print("\n== lib/ entries (physical packaging evidence) ==")
    for fn, ct, us, cs in libs:
        print(
            "  %-46s method=%d(%s) stored=%d packed=%d"
            % (fn, ct, "STORED" if ct == 0 else "DEFLATE", us, cs)
        )
    out["lib_entries"] = libs

    print("\n== decisive byte evidence for extractNativeLibs ==")
    app_el = find(doc["elements"], "application")[0]
    a = attr_of(app_el, "extractNativeLibs")
    if a:
        raw = buf[a["off"] : a["off"] + 20]
        print(
            "attribute record @ file offset 0x%04x (%d), 20 bytes:\n  %s"
            % (a["off"], a["off"], " ".join("%02x" % b for b in raw))
        )
        print(
            "  ns_idx=%d name_idx=%d raw_idx=%d  typed.size=%d res0=%d dataType=0x%02x data=0x%08x"
            % (
                struct.unpack_from("<i", raw, 0)[0],
                struct.unpack_from("<i", raw, 4)[0],
                struct.unpack_from("<i", raw, 8)[0],
                struct.unpack_from("<H", raw, 12)[0],
                raw[14],
                raw[15],
                struct.unpack_from("<I", raw, 16)[0],
            )
        )
        print(
            "  -> resource_map[name_idx=%d] = 0x%08x ; pool[name_idx] = %r ; BOOLEAN(%s)"
            % (
                a["name_index"],
                doc["resource_map"][a["name_index"]],
                doc["strings"][a["name_index"]],
                "true" if a["data"] != 0 else "false",
            )
        )

    print("\n== JSON ==")
    print(json.dumps(out, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
