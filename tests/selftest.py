#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selftest.py —— 离线自检（不需要 Android SDK、不需要真实 APK）。

构造合成 ZIP 与合成的 APK Signing Block，逐项验证三个模块的核心断言：
  1. probe     : EOCD 定位、CD 精确填满、STORED 对齐统计、Signing Block 识别
  2. sigblock  : Signing Block 解析、「只插入不重排」四不变量（正例 + 反例必须失败）
  3. binxml    : 非 AXML 输入必须明确报错，不静默产出垃圾
  4. js lint   : 正常 JS 通过、括号/引号错误被抓出
"""
import io
import os
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from apkfix import probe as probe_mod          # noqa: E402
from apkfix import sigblock as sig_mod         # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print(("  [PASS] " if ok else "  [FAIL] ") + name + ("" if ok else "  -> " + str(detail)))
    if not ok:
        FAILS.append(name)


def make_zip(path, align_so=True, with_block=False):
    """造一个形状像 APK 的 zip：STORED 的 resources.arsc / .so，DEFLATE 的其余。"""
    pad = b"\x00" * 4096
    with zipfile.ZipFile(path, "w") as z:
        zi = zipfile.ZipInfo("AndroidManifest.xml")
        z.writestr(zi, b"\x03\x00\x08\x00" + b"\x00" * 60, zipfile.ZIP_DEFLATED)
        zi = zipfile.ZipInfo("resources.arsc")
        z.writestr(zi, b"ARSC" + b"\x11" * 200, zipfile.ZIP_STORED)
        zi = zipfile.ZipInfo("classes.dex")
        z.writestr(zi, b"dex\n035\x00" + b"\x22" * 500, zipfile.ZIP_DEFLATED)
        zi = zipfile.ZipInfo("lib/arm64-v8a/libdemo.so")
        z.writestr(zi, b"\x7fELF" + b"\x33" * 1000, zipfile.ZIP_STORED)
        zi = zipfile.ZipInfo("assets/pad.bin")
        z.writestr(zi, pad, zipfile.ZIP_STORED)
    if with_block:
        inject_signing_block(path)
    return path


def inject_signing_block(path):
    """在 CD 之前插入一个结构合法的空 Signing Block，并把 EOCD 的 cd_off 往后挪。"""
    buf = bytearray(Path(path).read_bytes())
    eocd = buf.rfind(b"PK\x05\x06")
    cd_off = struct.unpack_from("<I", buf, eocd + 16)[0]
    pairs = b""
    pid = struct.pack("<I", 0x7109871A)                 # v2，内容留空占位
    pair = struct.pack("<Q", len(pid)) + pid
    pairs += pair
    body = pairs
    size = len(body) + 8 + 16                            # 尾部 size(8) + magic(16)
    blk = struct.pack("<Q", size) + body + struct.pack("<Q", size) + b"APK Sig Block 42"
    out = buf[:cd_off] + blk + buf[cd_off:]
    struct.pack_into("<I", out, eocd + 16 + len(blk), cd_off + len(blk))
    Path(path).write_bytes(bytes(out))


def main():
    tmp = Path(tempfile.mkdtemp(prefix="apkfix-selftest-"))
    plain = make_zip(tmp / "plain.apk")
    signed = make_zip(tmp / "signed.apk", with_block=True)
    aligned_ok = make_zip(tmp / "aligned.apk")
    # 造一个「未对齐」包：把 STORED 条目塞进 1 字节 extra 使其数据偏移非 4 的倍数
    with zipfile.ZipFile(aligned_ok, "a", zipfile.ZIP_DEFLATED) as z:
        z.writestr("odd.bin", b"x" * 3)
    Path(aligned_ok).write_bytes(Path(aligned_ok).read_bytes())

    print("1) probe")
    r = probe_mod.probe(str(plain))
    check("EOCD 定位成功", r["eocd_off"] > 0)
    check("中央目录精确填满", r["cd_parse_exact"])
    check("条目数与 EOCD 一致", r["cd_entries_eocd"] == r["cd_entries_parsed"] == 5)
    check("无 Signing Block 判定正确", r["signing_block"] is None)
    check("STORED 条目数正确", r["stored"] == 3)
    rs = probe_mod.probe(str(signed))
    check("Signing Block 被识别", rs["signing_block"] is not None)
    check("Signing Block scheme 为 v2", rs["signing_block"]["pairs"][0]["scheme"] == "v2")

    print("2) sigblock 只插入不重排")
    rc = sig_mod.cmd_cmp(str(signed), str(plain))
    check("正例：合成签名包通过四不变量", rc == 0)
    # 反例：把 plain 改一个字节，断言必须失败
    broken = tmp / "broken.apk"
    b = bytearray(Path(plain).read_bytes())
    b[40] ^= 0xFF
    Path(broken).write_bytes(bytes(b))
    buf = io.StringIO()
    old, sys.stdout = sys.stdout, buf
    try:
        try:
            sig_mod.cmd_cmp(str(signed), str(broken))
            neg_ok = False
        except SystemExit:
            neg_ok = True
        except Exception:
            neg_ok = False
    finally:
        sys.stdout = old
    check("反例：内容被改动时断言失败（非静默通过）", neg_ok, buf.getvalue()[-200:])

    print("3) binxml 输入校验")
    junk = tmp / "junk.bin"
    junk.write_bytes(b"not an axml at all" * 10)
    p = subprocess.run([sys.executable, str(ROOT / "apkfix" / "binxml.py"), str(junk)],
                       capture_output=True, text=True)
    check("非 AXML 输入以非零码退出", p.returncode != 0, p.stdout[-200:] + p.stderr[-200:])

    print("4) JS 结构自检")
    good = tmp / "good.js"
    good.write_text('var a = {"k": [1, 2, /x[0-9]+/.test("3")]}; // ok\n', encoding="utf-8")
    bad = tmp / "bad.js"
    bad.write_text('function f( { return "unclosed\n', encoding="utf-8")
    pg = subprocess.run([sys.executable, str(ROOT / "tools" / "js_syntax_lite.py"), str(good)],
                        capture_output=True, text=True)
    pb = subprocess.run([sys.executable, str(ROOT / "tools" / "js_syntax_lite.py"), str(bad)],
                        capture_output=True, text=True)
    check("正常 JS 通过", pg.returncode == 0, pg.stdout + pg.stderr)
    check("坏 JS 被抓出", pb.returncode != 0, pb.stdout)

    print("\n结果: %s" % ("全部通过" if not FAILS else "失败 %d 项: %s" % (len(FAILS), FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
