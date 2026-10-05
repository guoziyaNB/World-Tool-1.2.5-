#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apkfix/probe.py —— APK / ZIP 包结构探测（纯标准库，只读）。

回答四个问题：
  1. 容器是否自洽：EOCD 定位、中央目录逐条解析是否精确填满、条目数是否一致
  2. 条目布局：STORED / DEFLATE 分布，STORED 条目数据偏移是否 4 字节对齐，.so 是否 4096 页对齐
  3. 签名形态：Signing Block 是否存在、含哪些 scheme（v2 / v3 / v3.1 / source-stamp / verity）
  4. 遗留物：是否还有 v1（META-INF/*.SF|*.RSA|MANIFEST.MF）签名条目

用法:
  python -m apkfix.probe <file.apk>            # 文本报告
  python -m apkfix.probe <file.apk> --json     # 机器可读
  python -m apkfix.probe <file.apk> --top 20   # 按未压缩体积列出前 N 大条目
"""
import hashlib
import json
import struct
import sys
import zipfile

EOCD = b"PK\x05\x06"
CD = b"PK\x01\x02"
LFH = b"PK\x03\x04"
SIGMAGIC = b"APK Sig Block 42"
V1_EXTS = (".SF", ".RSA", ".DSA", ".EC")
SIG_IDS = {0x7109871A: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1",
           0x2B09189E: "source-stamp", 0x42726577: "verity-padding"}


def find_eocd(buf):
    start = max(0, len(buf) - 22 - 65535)
    for i in range(len(buf) - 22, start - 1, -1):
        if buf[i:i + 4] == EOCD:
            if i + 22 + struct.unpack_from("<H", buf, i + 20)[0] == len(buf):
                return i
    return -1


def parse_cd(buf, cd_off, n_total):
    entries, p = [], cd_off
    for _ in range(n_total):
        if buf[p:p + 4] != CD:
            raise SystemExit("[!] 中央目录第 %d 条签名异常 @%d" % (len(entries), p))
        (sig, vm, vn, flags, method, mt, md, crc, csize, usize,
         nlen, elen, clen, dsk, iattr, eattr, lho) = struct.unpack_from("<IHHHHHHIIIHHHHHII", buf, p)
        entries.append({
            "name": buf[p + 46:p + 46 + nlen].decode("utf-8", "replace"),
            "flags": flags, "method": method, "csize": csize, "usize": usize,
            "lho": lho, "cd_extra": elen, "made_by": vm,
        })
        p += 46 + nlen + elen + clen
    return entries, p


def local_data_off(fh, entry):
    fh.seek(entry["lho"])
    hdr = fh.read(30)
    if hdr[:4] != LFH:
        raise SystemExit("[!] 本地头签名异常 @%d" % entry["lho"])
    nlen, elen = struct.unpack_from("<HH", hdr, 26)
    return entry["lho"] + 30 + nlen + elen


def signing_block(buf, cd_off):
    if cd_off < 32 or buf[cd_off - 16:cd_off] != SIGMAGIC:
        return None
    size2 = struct.unpack_from("<Q", buf, cd_off - 24)[0]
    start = cd_off - 8 - size2
    size1 = struct.unpack_from("<Q", buf, start)[0]
    pairs, pos, end = [], start + 8, cd_off - 24
    while pos < end:
        plen = struct.unpack_from("<Q", buf, pos)[0]
        pid = struct.unpack_from("<I", buf, pos + 8)[0]
        pairs.append({"id": pid, "scheme": SIG_IDS.get(pid, "unknown"), "value_len": plen - 4})
        pos += 8 + plen
    return {"offset": start, "size": size2 + 8, "size_head": size1, "size_tail": size2, "pairs": pairs}


def probe(path):
    buf = open(path, "rb").read()
    eocd = find_eocd(buf)
    if eocd < 0:
        raise SystemExit("[!] 找不到合法 EOCD —— 不是完整的 ZIP/APK")
    (_disk, _cdd, _nd, n_total, cd_size, cd_off, clen) = struct.unpack_from("<HHHHIIH", buf, eocd + 4)
    entries, end = parse_cd(buf, cd_off, n_total)
    with open(path, "rb") as fh:
        bad4 = badso = so_cnt = stored = 0
        for e in entries:
            if e["method"] != zipfile.ZIP_STORED:
                continue
            stored += 1
            off = local_data_off(fh, e)
            if off % 4:
                bad4 += 1
            if e["name"].endswith(".so"):
                so_cnt += 1
                if off % 4096:
                    badso += 1
    blk = signing_block(buf, cd_off)
    v1 = [e["name"] for e in entries
          if e["name"].startswith("META-INF/")
          and (e["name"].upper().endswith(V1_EXTS) or e["name"].upper().endswith("MANIFEST.MF"))]
    return {
        "file": path,
        "bytes": len(buf),
        "eocd_off": eocd,
        "comment_len": clen,
        "cd_off": cd_off,
        "cd_size": cd_size,
        "cd_entries_eocd": n_total,
        "cd_entries_parsed": len(entries),
        "cd_parse_exact": end == cd_off + cd_size,
        "entry_area_sha256": hashlib.sha256(buf[:blk["offset"] if blk else cd_off]).hexdigest(),
        "cd_sha256": hashlib.sha256(buf[cd_off:cd_off + cd_size]).hexdigest(),
        "stored": stored,
        "misaligned4": bad4,
        "so_entries": so_cnt,
        "so_misaligned_4096": badso,
        "signing_block": blk,
        "v1_leftovers": v1,
        "entries": entries,
    }


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0 if len(argv) > 1 else 2
    path = argv[1]
    as_json = "--json" in argv
    top = 0
    if "--top" in argv:
        top = int(argv[argv.index("--top") + 1])
    r = probe(path)
    if as_json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0
    print("文件            : %s" % r["file"])
    print("字节数          : %d" % r["bytes"])
    print("EOCD @%d  注释长 %d" % (r["eocd_off"], r["comment_len"]))
    print("中央目录        : off=%d size=%d 条目(EOCD)=%d 条目(解析)=%d 精确填满=%s"
          % (r["cd_off"], r["cd_size"], r["cd_entries_eocd"], r["cd_entries_parsed"], r["cd_parse_exact"]))
    print("条目区 sha256   : %s" % r["entry_area_sha256"][:32])
    print("中央目录 sha256 : %s" % r["cd_sha256"][:32])
    print("STORED 条目     : %d（未 4 字节对齐 %d）" % (r["stored"], r["misaligned4"]))
    print(".so 条目        : %d（未 4096 页对齐 %d）" % (r["so_entries"], r["so_misaligned_4096"]))
    if r["signing_block"]:
        b = r["signing_block"]
        print("Signing Block   : @%d size=%d 首尾 size 一致=%s"
              % (b["offset"], b["size"], b["size_head"] == b["size_tail"]))
        for p in b["pairs"]:
            print("  0x%08x  %-16s value_len=%d" % (p["id"], p["scheme"], p["value_len"]))
    else:
        print("Signing Block   : 无（v2+ 未签名）")
    print("v1 残留         : %s" % (r["v1_leftovers"] or "无"))
    if top:
        print("\n-- 未压缩体积前 %d 大条目 --" % top)
        for e in sorted(r["entries"], key=lambda x: -x["usize"])[:top]:
            print("  %10d  method=%d  %s" % (e["usize"], e["method"], e["name"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
