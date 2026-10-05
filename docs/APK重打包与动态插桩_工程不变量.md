# APK 重打包与动态插桩 · 工程不变量笔记

从一次真实的 Android 插件研究（apktool 反编译 → 重打包 → 4K 对齐 → v2+v3 签名 →
动态插桩探针）里沉淀出来的**通用工程要点**。不含任何具体产品的绕过实现、授权数据或密钥。

## 1. 「不改内容的重打包」必须逐字节保真

用 ZIP 层重写 APK 时，最容易在三个地方悄悄改坏包：

| 不变量 | 为什么 |
|---|---|
| 未修改条目的「局部头 + 局部 extra + 压缩数据」原样搬运 | 解压重压会改 CRC 与压缩流，破坏签名溯源与增量更新 |
| `method / mt / md / flags / version_made_by / version_needed / iattr / eattr / central extra / comment` 全保留 | 任何一项变化都会被 `apksigner verify` 之外的校验工具发现 |
| 局部头的 `nlen/elen` 从**原文件局部头**重读，不信中央目录 | 两者不一致的包真实存在（工具会修好其一） |

自检脚本 `build/apk_sigblock.py` 会解析签名块、EOCD 与中央目录，断言
「条目区前缀逐字节一致、新增条目之后偏移不变」。

## 2. resources.arsc 与 4K 对齐

- `resources.arsc` 保持 **STORED**（不压缩），起始偏移按 4 字节对齐；
  观察到的真实包用「局部 extra 纯零填充 1–4 字节」实现对齐，
  而不是结构化 `0xD935` 字段（结构字段至少要 4 字节头）。
- Android 15 起 `zipalign -P 16` 对 `.so` 有额外要求；只做 `-p 4` 时，
  用 `zipalign -c -p -v 4` 复检即可。

## 3. 签名：只插入，不重排

`apksigner` 默认会重排/重对齐所有条目。要「原包 + 新签名」的最小改动效果，用
`--alignment-preserved true`，然后断言：条目区前缀哈希一致、插入区全 `0x00`、
中央目录哈希一致、EOCD 的 `cd_off` 差值等于插入长度。
`build/sign_apk.ps1` 是这条流水线的参考实现（v2+v3 双签，v1 关）。

## 4. 动态插桩载体的加载点

- 原生库依赖链（`DT_NEEDED`）是**最稳的加载入口**：把目标 `.so` 的第 N 项
  `DT_NEEDED` 在 `.dynstr` 里整体替换成载体名，长度对齐、不改偏移。
  「朴素 11 字节替换」会留下 `liblib…s` 这种半截字符串 —— 必须整槽重写。
- Java 侧 `appComponentFactory` / `Application` 替换是另一条路，但受
  `extractNativeLibs` 与 installer 校验影响更大。
- Android 从非 debuggable 应用的 `/lib` 只解压「`lib*.so` 命名」或名为 `gdbserver`
  的文件 —— 想塞非 `.so` 后缀的资源进 `/lib` 是行不通的（实测：装后只剩 6 个 `.so`）。

## 5. ART 内部接口的版本适配

跨 Android 12–16 探测方法调用入口时，不要在 `apiLevel` 上二选一，
而要**逐变体尝试 + 全不命中时记日志后返回**；`ClassLinker` / heap offset 一类
结构偏移必须同时用「符号探测」与「版本下界」双重条件，否则新版本上静默失效。
本机验证：无 node 时用 `tools/js_syntax_lite.py` 做括号/引号结构自检，
不要指望 `node --check` 一定存在。

## 6. 发布与合规

- 分析记录里通常会夹带：卡密、密钥、设备标识、私网 IP。**入库前一律脱敏**，
  口令改用环境变量注入，密钥库永不入库。
- 反编译源码属第三方版权，公开前先确认权利状态。

## 目录

```
apkfix/   probe.py（容器自洽/对齐/签名形态）、sigblock.py（签名块解析 + 只插入不重排断言）、binxml.py（二进制 manifest 解析）
scripts/  sign_apk.ps1（可移植签名流水线）
tests/    selftest.py（离线自检，正例+反例）
tools/    js_syntax_lite.py（无 Node 的 JS 结构自检）
docs/     本文件
```

## 许可

MIT（仅覆盖本仓自研脚本与文档）。第三方工具见 `NOTICE.md`。
