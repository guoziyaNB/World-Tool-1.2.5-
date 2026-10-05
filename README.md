# apk-repack-invariants

> APK 重打包、对齐与 v2/v3 签名的**结构不变量**工具集：让「重新签名」这件事可断言、可复现。
> 纯标准库实现，只读分析，不需要 Android SDK 就能跑自检。

[English](#english) · 中文主体

## 它解决什么问题

对已经存在的 APK 做「改内容 → 重新签名」时，最容易在三个地方悄悄改坏包，而
`apksigner verify` 只告诉你签名有效，不告诉你包被动过：

| 症状 | 后果 |
|---|---|
| 解压重压既有条目 | CRC/压缩流变化，增量更新与签名溯源失效 |
| `apksigner` 默认重排/重对齐条目 | 与基线布局不同，无法证明「只改了该改的」 |
| 对齐质量下降 | Android 15+ 上 `.so` 页对齐不达标，运行期额外解压/映射开销甚至失败 |

本仓提供**可执行的判据**：`sigblock.py` 用四条不变量证明签名产物相对基线
「只插入、未重排」，`probe.py` 报告容器自洽性与对齐质量，`binxml.py` 读二进制 manifest，
`js_syntax_lite.py` 在没有 Node 的环境里做 JS 结构体检。

## 快速开始

```bash
git clone <this-repo> && cd apk-repack-invariants
python tests/selftest.py            # 离线自检：合成 zip + 合成 Signing Block，无需 SDK
```

```bash
# 1) 探测包结构（容器自洽性 / 对齐 / 签名形态 / v1 残留）
python -m apkfix.probe app.apk
python -m apkfix.probe app.apk --json --top 10

# 2) 比较「基线」与「重新签名产物」：四不变量必须全 PASS
python -m apkfix.sigblock info app.apk
python -m apkfix.sigblock assert-insert-only app-unsigned.apk app-signed.apk

# 3) 读二进制 AndroidManifest.xml（package / versionName / targetSdk / 属性表）
python apkfix/binxml.py app.apk

# 4) 无 Node 环境的 JS 结构自检（括号 / 引号 / 注释 / 正则）
python tools/js_syntax_lite.py build/inject.js
```

签名流水线（Windows / PowerShell，需要 Android build-tools）：

```powershell
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
$env:WB_KS_PASS   = '<密钥库口令>'          # 口令走环境变量，不进命令行与仓库
pwsh -File scripts/sign_apk.ps1 -InApk app-unsigned.apk -OutApk app-signed.apk `
     -KeyStore keys/release.jks -Alias release
```

脚本会依次：判定输入是否已对齐（必要时 `zipalign -f -p 4`）→
`apksigner sign --alignment-preserved true`（v1 关 / v2+v3 开）→ 验签 →
**跑 `assert-insert-only` 四不变量** → 对产物 `zipalign -c -p -v 4` 复检。

## 四条不变量（`sigblock.py` 的判据）

签名相对基线必须是**纯插入**：

```
I1 条目区共同前缀逐字节一致          —— 既有条目一个字节都没改
I2 多出来的字节全为 0x00            —— 插入的是零填充，不承载语义
I3 中央目录逐字节一致                —— 含每个条目的 local header offset，条目未被搬动
I4 EOCD 除 cd_off 字段外逐字节一致   —— 只有该字段被顺移
```

任一不满足即非零退出。上例中 `assert-insert-only <base> <signed>` 的顺序不能反。

## 目录

```
apkfix/
  probe.py      容器自洽性 + 对齐质量 + 签名形态 + 条目台账（--json 可机读）
  sigblock.py   Signing Block 解析 / 剥离 / 「只插入不重排」四不变量断言
  binxml.py     二进制 AndroidManifest.xml（AXML）解析，字符串池 + 资源映射双源交叉校验
tools/
  js_syntax_lite.py   无 Node 环境下的 JS 结构自检（状态机扫描）
scripts/
  sign_apk.ps1  可移植签名流水线（自动定位 build-tools，口令走环境变量）
tests/
  selftest.py   离线自检：正例通过、反例（内容被改）必须失败
docs/
  APK重打包与动态插桩_工程不变量.md   背景笔记：重打包/对齐/签名/插桩载体的工程要点
```

## 设计取舍

- **只用标准库**：不绑定 `apksigner` 的实现细节，可在 CI、离线机、无 SDK 环境跑。
- **只读**：除 `sigblock strip` 显式要求外，不写任何输入文件。
- **断言优于报告**：关键路径是「不满足就非零退出」，便于挂进流水线当守门人。
- **反例必须失败**：`tests/selftest.py` 除了跑正例，还篡改内容验证断言会拒绝（避免守门人形同虚设）。

## 已知边界

- `probe`/`sigblock` 不解析 v2/v3 签名的**内容**（证书、摘要），只看结构；签名有效性交给 `apksigner verify`。
- ZIP64 与加密条目未做专门分支（真机 APK 通常不涉及）。
- `binxml.py` 面向 AXML（resource map 存在的二进制 XML），不处理普通 XML。

## 许可

MIT（见 `LICENSE`）。第三方工具与许可见 `NOTICE.md`。本仓不含任何第三方反编译产物或二进制。

---

## English

`apkfix` is a small, standard-library-only toolbox that makes **"re-sign an existing APK"**
verifiable: `probe.py` reports container self-consistency, entry alignment and signing-scheme
layout; `sigblock.py` parses the APK Signing Block and asserts four invariants proving the
signer **only inserted bytes** (entry-area prefix, zero padding, central directory, EOCD)
instead of re-packing or re-aligning existing entries; `binxml.py` decodes binary
`AndroidManifest.xml`; `tools/js_syntax_lite.py` lints JavaScript without Node.
`tests/selftest.py` builds synthetic fixtures and requires both positive and negative cases to
behave, so the assertions cannot silently pass. MIT licensed.
