#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""APK Signing Block 结构探测 / 剥离 / zipalign 等价校验。

纯标准库实现，不依赖 apksigner，用于独立断言：
  info  <apk>                      打印 EOCD / CD / Signing Block 结构与条目对齐
  strip <in.apk> <out.apk>         剥离 Signing Block，得到「未签名等价体」
  cmp   <base.apk> <signed.apk>     断言签名产物相对基线「只插入未重排」
  assert-insert-only <base.apk> <signed.apk>   cmp 的同义命令（语义更直白）
License: MIT (see LICENSE).
"""
import hashlib
import struct
import sys
import zipfile

MAGIC = b"APK Sig Block 42"
V2_ID = 0x7109871A
V3_ID = 0xF05368C0
V31_ID = 0x1B93AD61
STAMP_ID = 0x2B09189E
VERITY_ID = 0x42726577
SIG_IDS = {V2_ID: "v2", V3_ID: "v3", V31_ID: "v3.1", STAMP_ID: "source-stamp", VERITY_ID: "verity-padding"}


def find_eocd(buf):
    """从尾部向前搜索 EOCD 签名 0x06054b50，排除位于注释内的伪签名。"""
    n = len(buf)
    start = max(0, n - 22 - 65535)
    for i in range(n - 22, start - 1, -1):
        if buf[i:i + 4] == b"PK\x05\x06":
            comment_len = struct.unpack_from("<H", buf, i + 20)[0]
            if i + 22 + comment_len == n:
                return i
    raise SystemExit("[!] 找不到合法的 EOCD")


def parse_eocd(buf):
    off = find_eocd(buf)
    (disk, cd_disk, cd_entries_disk, cd_entries, cd_size, cd_off, comment_len) = struct.unpack_from("<HHHHIIH", buf, off + 4)
    return {
        "eocd_off": off,
        "cd_off": cd_off,
        "cd_size": cd_size,
        "cd_entries": cd_entries,
        "comment_len": comment_len,
        "cd_off_field_off": off + 16,
        "is_zip64": cd_off == 0xFFFFFFFF,
    }


def find_sig_block(buf, eocd):
    """Signing Block 紧贴中央目录之前，std 布局：
    [size_of_block u64][id-value pairs][size_of_block u64][magic 16B] -> 紧接着就是 CD。
    因此 magic 占 [cd_off-16, cd_off)，尾部 size 占 [cd_off-24, cd_off-16)。
    返回 (block_start, 块总字节数, pairs)。"""
    cd_off = eocd["cd_off"]
    if cd_off < 32:
        return None
    if buf[cd_off - 16:cd_off] != MAGIC:
        return None
    size2 = struct.unpack_from("<Q", buf, cd_off - 24)[0]
    block_start = cd_off - 8 - size2  # size_of_block 的值 S 不含开头 8 字节
    if block_start < 0 or block_start + 8 + size2 != cd_off:
        raise SystemExit("[!] Signing Block size 字段越界")
    size1 = struct.unpack_from("<Q", buf, block_start)[0]
    if size1 != size2:
        raise SystemExit("[!] Signing Block 首尾 size 不一致: %d vs %d" % (size1, size2))
    pairs = []
    pos = block_start + 8
    end = cd_off - 24  # 尾部 size(8) + magic(16) 之前
    while pos < end:
        pair_len = struct.unpack_from("<Q", buf, pos)[0]
        pid = struct.unpack_from("<I", buf, pos + 8)[0]
        if pair_len < 4 or pos + 8 + pair_len > end:
            raise SystemExit("[!] id-value pair 长度溢出 @%d" % pos)
        pairs.append({"id": pid, "len": pair_len, "value_off": pos + 12, "value_len": pair_len - 4})
        pos += 8 + pair_len
    if pos != end:
        raise SystemExit("[!] id-value pairs 未精确填满 Signing Block")
    return {"block_start": block_start, "block_size": size2 + 8, "pairs": pairs, "cd_off": cd_off}


def sections(buf):
    eocd = parse_eocd(buf)
    blk = find_sig_block(buf, eocd)
    entry_end = blk["block_start"] if blk else eocd["cd_off"]
    return {
        "eocd": eocd,
        "block": blk,
        "sec1": (0, entry_end),
        "sec2": (eocd["cd_off"], eocd["cd_off"] + eocd["cd_size"]),
        "sec3": (eocd["eocd_off"], len(buf)),
    }


def local_data_offset(f, info):
    """真实 data offset 必须用『本地头』自己的 name_len/extra_len 计算：
    zipfile 暴露的 info.extra 是中央目录的 extra，长度常与本地头不同。"""
    f.seek(info.header_offset)
    hdr = f.read(30)
    if hdr[:4] != b"PK\x03\x04":
        raise SystemExit("[!] 本地头签名异常 @%d" % info.header_offset)
    name_len, extra_len = struct.unpack_from("<HH", hdr, 26)
    return info.header_offset + 30 + name_len + extra_len


def zipalign_check(path, page_align_so=True):
    """zipalign -c -p -v 4 的等价实现：所有 STORED 条目 data offset 必须 4 字节对齐，
    .so 文件额外要求 4096 字节页对齐（-p）。"""
    bad4, badso, stored, checked_so = [], [], 0, 0
    with open(path, "rb") as f, zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.compress_type != zipfile.ZIP_STORED:
                continue
            stored += 1
            data_off = local_data_offset(f, info)
            if data_off % 4:
                bad4.append((info.filename, data_off))
            if page_align_so and info.filename.endswith(".so"):
                checked_so += 1
                if data_off % 4096:
                    badso.append((info.filename, data_off))
    return {"stored": stored, "bad4": bad4, "so_checked": checked_so, "badso": badso}


def cmd_info(path):
    with open(path, "rb") as f:
        buf = f.read()
    s = sections(buf)
    e, blk = s["eocd"], s["block"]
    print("文件: %s" % path)
    print("字节数: %d" % len(buf))
    print("EOCD @%d  cd_off=%d  cd_size=%d  entries=%d  comment=%d  zip64=%s"
          % (e["eocd_off"], e["cd_off"], e["cd_size"], e["cd_entries"], e["comment_len"], e["is_zip64"]))
    if blk:
        print("Signing Block @%d  size=%d (含首尾 size+magic 共 32 字节开销)  隐式 size_of_block=%d"
              % (blk["block_start"], blk["block_size"], blk["block_size"] - 8))
        for p in blk["pairs"]:
            print("  id=0x%08x (%-13s) pair_len=%d value_len=%d"
                  % (p["id"], SIG_IDS.get(p["id"], "unknown"), p["len"], p["value_len"]))
    else:
        print("Signing Block: 不存在")
    print("section1 条目区 [0,%d)  sha256=%s" % (s["sec1"][1], hashlib.sha256(buf[:s["sec1"][1]]).hexdigest()))
    print("section2 中央目录 [%d,%d)  sha256=%s"
          % (s["sec2"][0], s["sec2"][1], hashlib.sha256(buf[s["sec2"][0]:s["sec2"][1]]).hexdigest()))
    print("section3 EOCD [%d,%d)  sha256=%s"
          % (s["sec3"][0], s["sec3"][1], hashlib.sha256(buf[s["sec3"][0]:s["sec3"][1]]).hexdigest()))
    with zipfile.ZipFile(path) as z:
        meta = [i.filename for i in z.infolist() if i.filename.upper().startswith("META-INF/")
                and i.filename.upper().endswith((".SF", ".RSA", ".DSA", ".EC", "MANIFEST.MF"))]
    print("v1 残留 JAR 签名文件: %s" % (meta if meta else "无"))
    z = zipalign_check(path)
    print("zipalign 等价检查: STORED 条目=%d  非 4 字节对齐=%d  .so 受检=%d  非 4096 对齐=%d"
          % (z["stored"], len(z["bad4"]), z["so_checked"], len(z["badso"])))
    for name, off in (z["bad4"] + z["badso"])[:5]:
        print("  未对齐: %s @%d" % (name, off))
    return 0


def cmd_strip(src, dst):
    with open(src, "rb") as f:
        buf = f.read()
    s = sections(buf)
    e, blk = s["eocd"], s["block"]
    if not blk:
        raise SystemExit("[!] %s 没有 Signing Block，无需剥离" % src)
    head = buf[:blk["block_start"]]
    tail = bytearray(buf[e["cd_off"]:])
    new_cd_off = blk["block_start"]
    old_cd_off = e["cd_off"]
    rel = e["cd_off_field_off"] - e["cd_off"]  # EOCD 内 cd_off 字段相对 EOCD 起点的偏移
    struct.pack_into("<I", tail, rel, new_cd_off)
    out = head + bytes(tail)
    with open(dst, "wb") as f:
        f.write(out)
    print("剥离 %s -> %s : 去掉 %d 字节 block，cd_off %d -> %d，输出 %d 字节"
          % (src, dst, blk["block_size"], old_cd_off, new_cd_off, len(out)))
    return 0


def cmd_cmp(signed_path, base_path):
    """严格断言：签名产物相对未签名基线只做了『插入』，没有重排/改写任何既有字节。

    四条不变量：
      I1 条目区共同前缀逐字节一致（既有条目字节零改动）
      I2 较长一侧多出的字节全部为 0x00（纯零填充，不承载语义）
      I3 中央目录逐字节一致（含全部条目的 local header offset，证明条目未被搬动）
      I4 EOCD 除 cd_off 字段外逐字节一致
    """
    with open(signed_path, "rb") as f:
        A = f.read()
    with open(base_path, "rb") as f:
        B = f.read()
    sa, sb = sections(A), sections(B)
    a_end, b_end = sa["sec1"][1], sb["sec1"][1]
    n = min(a_end, b_end)
    fails = []

    ok1 = A[:n] == B[:n]
    print("I1 条目区共同前缀 [0,%d) 逐字节一致 : %s" % (n, "PASS" if ok1 else "FAIL"))
    if not ok1:
        fails.append("I1")
        for i in range(n):
            if A[i] != B[i]:
                print("     首个差异 @%d  signed=0x%02x base=0x%02x" % (i, A[i], B[i]))
                break
    print("     signed 条目区=%d 字节 (sha256=%s)" % (a_end, hashlib.sha256(A[:a_end]).hexdigest()[:16]))
    print("     base   条目区=%d 字节 (sha256=%s)" % (b_end, hashlib.sha256(B[:b_end]).hexdigest()[:16]))

    gap = A[n:a_end] if a_end > b_end else B[n:b_end]
    ok2 = all(x == 0 for x in gap)
    print("I2 多出的 %d 字节填充全为 0x00 : %s" % (len(gap), "PASS" if ok2 else "FAIL"))
    if not ok2:
        fails.append("I2")

    ca = A[sa["sec2"][0]:sa["sec2"][1]]
    cb = B[sb["sec2"][0]:sb["sec2"][1]]
    ok3 = ca == cb
    print("I3 中央目录 %d 字节逐字节一致 : %s (sha256=%s)"
          % (len(ca), "PASS" if ok3 else "FAIL", hashlib.sha256(ca).hexdigest()[:16]))
    if not ok3:
        fails.append("I3")
        if len(ca) == len(cb):
            d = next(i for i in range(len(ca)) if ca[i] != cb[i])
            print("     首差异 @cd+%d" % d)

    ea = A[sa["sec3"][0]:sa["sec3"][1]]
    eb = B[sb["sec3"][0]:sb["sec3"][1]]
    ra = sa["eocd"]["cd_off_field_off"] - sa["sec3"][0]
    ok4 = len(ea) == len(eb) and all(ea[i] == eb[i] for i in range(len(ea)) if not (ra <= i < ra + 4))
    print("I4 EOCD 除 cd_off 字段外逐字节一致 : %s" % ("PASS" if ok4 else "FAIL"))
    print("     EOCD cd_off: signed=%d  base=%d" % (sa["eocd"]["cd_off"], sb["eocd"]["cd_off"]))
    if not ok4:
        fails.append("I4")

    with zipfile.ZipFile(signed_path) as z:
        n_signed = len(z.infolist())
    with zipfile.ZipFile(base_path) as z:
        n_base = len(z.infolist())
    print("     条目总数: signed=%d  base=%d  EOCD 记录数: signed=%d  base=%d"
          % (n_signed, n_base, sa["eocd"]["cd_entries"], sb["eocd"]["cd_entries"]))
    if n_signed != n_base:
        fails.append("条目数")

    if fails:
        raise SystemExit("[FAIL] 不变量未满足: %s —— 签名过程改写了既有字节" % ",".join(fails))
    print("[OK] 签名只做了插入：条目区前缀 + 中央目录 100%% 逐字节保真，未重排任何条目")
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "info":
        return cmd_info(argv[2])
    if cmd == "strip":
        return cmd_strip(argv[2], argv[3])
    if cmd in ("cmp", "assert-insert-only"):
        return cmd_cmp(argv[3], argv[2]) if cmd == "assert-insert-only" else cmd_cmp(argv[2], argv[3])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
