"""js_syntax_lite.py —— 无 Node 环境下的 JS 结构自检（纯标准库）。

作用：给无法用 `node --check` 校验的单文件 JS（生成脚本、注入脚本、打包器产物）做结构体检。
检查项（状态机逐字符扫描）：
  1) 字符串字面量（' " `）是否正确闭合、有无未转义换行
  2) 行注释 // 与块注释 /* */ 是否正确闭合
  3) {} () [] 三类括号是否配平，且给出不匹配时所在行号
  4) 正则字面量按「前一个有意义字符」判定，避免把除法误当正则（保守处理）

它不是完整的 JS 解析器，但足以发现补丁引入的括号/引号类语法错误。
"""

import sys

PAIRS = {")": "(", "]": "[", "}": "{"}
OPEN = set("([{")
CLOSE = set(")]}")


def check(path):
    src = open(path, encoding="utf-8", errors="replace").read()
    line = 1
    i = 0
    n = len(src)
    stack = []
    errors = []
    prev_sig = ""  # 上一个有意义的字符（用于正则判定）

    while i < n:
        c = src[i]

        if c == "\n":
            line += 1
            i += 1
            continue

        # 行注释
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue

        # 块注释
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            start_line = line
            i += 2
            closed = False
            while i < n:
                if src[i] == "\n":
                    line += 1
                if src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    i += 2
                    closed = True
                    break
                i += 1
            if not closed:
                errors.append(f"L{start_line}: 块注释未闭合")
            continue

        # 字符串
        if c in "'\"`":
            quote = c
            start_line = line
            i += 1
            closed = False
            while i < n:
                ch = src[i]
                if ch == "\\":
                    i += 2
                    continue
                if ch == "\n":
                    if quote != "`":
                        errors.append(f"L{start_line}: {quote} 字符串内出现未转义换行")
                        break
                    line += 1
                if ch == quote:
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed and i >= n:
                errors.append(f"L{start_line}: {quote} 字符串未闭合（文件尾）")
            prev_sig = quote
            continue

        # 正则字面量（保守：仅在明确的“期望表达式”位置识别 /.../）
        if c == "/" and prev_sig in ("", "(", "[", "{", ",", ";", "=", ":", "!", "&", "|", "?", "+", "-", "*", "%", "<", ">", "~", "^"):
            start_line = line
            i += 1
            in_class = False
            closed = False
            while i < n:
                ch = src[i]
                if ch == "\\":
                    i += 2
                    continue
                if ch == "\n":
                    break
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                errors.append(f"L{start_line}: 正则字面量疑似未闭合")
            prev_sig = "/"
            continue

        if c in OPEN:
            stack.append((c, line))
            prev_sig = c
            i += 1
            continue

        if c in CLOSE:
            if not stack:
                errors.append(f"L{line}: 多余的 '{c}'（栈空）")
            else:
                op, ol = stack.pop()
                if op != PAIRS[c]:
                    errors.append(f"L{line}: '{c}' 与 L{ol} 的 '{op}' 不匹配")
            prev_sig = c
            i += 1
            continue

        if not c.isspace():
            prev_sig = c
        i += 1

    for op, ol in stack:
        errors.append(f"L{ol}: '{op}' 未闭合")

    return errors


if __name__ == "__main__":
    path = sys.argv[1]
    errs = check(path)
    if errs:
        print(f"[FAIL] {path} —— {len(errs)} 处结构问题：")
        for e in errs[:40]:
            print("  " + e)
        sys.exit(1)
    print(f"[PASS] {path} —— 括号/引号/注释结构自检通过")
