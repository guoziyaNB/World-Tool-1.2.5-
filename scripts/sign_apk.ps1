<#
.SYNOPSIS
  APK v2+v3 签名流水线：只插入、不重排（zipalign + apksigner + 结构断言）。

.DESCRIPTION
  apksigner 默认会重新对齐所有条目（改写本地头/CD 的 extra 字段），使「同一份内容
  重新签名」得到与基线不同布局的包。本脚本固定传 --alignment-preserved true，
  再用 apkfix/sigblock.py 的四条不变量断言签名确实只做了插入。

  契约:
    sign_apk.ps1 -InApk <未签名.apk> -OutApk <已签名.apk> -KeyStore <ks.jks> [-Alias a]

  环境变量（避免把口令写进命令行/仓库）:
    WB_KS_PASS   密钥库口令（必填，同时用作 key 口令）
    ANDROID_HOME Android SDK 根目录（用于自动定位 build-tools，可用 -BuildTools 覆盖）

  依赖: Android build-tools 的 apksigner / zipalign；本仓 apkfix/sigblock.py（纯 Python）。
  产物: <OutApk>，以及 <LogDir>/apksigner_verify_*.txt 等日志。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$InApk,
    [Parameter(Mandatory = $true, Position = 1)][string]$OutApk,
    [Parameter(Mandatory = $true)][string]$KeyStore,
    [string]$Alias = "release",
    [string]$StorePass = $env:WB_KS_PASS,
    [string]$KeyPass = $env:WB_KS_PASS,
    [string]$LogDir = ".\logs",
    [string]$BuildTools = "",
    [string]$Python = "",
    [switch]$SkipAlign
)

$ErrorActionPreference = 'Stop'
$LogDir = (New-Item -ItemType Directory -Force -Path $LogDir).FullName
$name = [System.IO.Path]::GetFileNameWithoutExtension($InApk)

# ---- 工具定位 ----------------------------------------------------------------
if (-not $BuildTools) {
    $sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { $env:ANDROID_SDK_ROOT }
    if (-not $sdk) { throw "未设置 ANDROID_HOME / ANDROID_SDK_ROOT，且未指定 -BuildTools" }
    $bt = Join-Path $sdk 'build-tools'
    if (-not (Test-Path $bt)) { throw "找不到 $bt" }
    $BuildTools = (Get-ChildItem $bt -Directory | Sort-Object { [version]($_.Name -replace '[^0-9.].*$','') } |
                   Select-Object -Last 1).FullName
}
$apksigner = Join-Path $BuildTools 'apksigner.bat'
$zipalign = Join-Path $BuildTools 'zipalign.exe'
foreach ($t in @($apksigner, $zipalign)) { if (-not (Test-Path -LiteralPath $t)) { throw "缺少工具: $t" } }
if (-not $Python) {
    $Python = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $Python) { throw "找不到 python，请用 -Python 指定" }
}
$Sigblock = Join-Path $PSScriptRoot '..\apkfix\sigblock.py'
if (-not (Test-Path -LiteralPath $Sigblock)) { throw "缺少 $Sigblock" }
if (-not $StorePass) { throw "未提供密钥库口令：设置环境变量 WB_KS_PASS 或用 -StorePass" }
if (-not (Test-Path -LiteralPath $InApk)) { throw "输入不存在: $InApk" }
$InApk = (Get-Item -LiteralPath $InApk).FullName
$OutApk = [System.IO.Path]::GetFullPath($OutApk)
if ($OutApk -eq $InApk) { throw "输入输出不能是同一个文件" }

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

# ---- 0 预对齐判定 -------------------------------------------------------------
Section '0 预对齐判定'
$base = $InApk
$probe = & $zipalign -c -p -v 4 $InApk 2>&1 | Out-String
$inAligned = ($LASTEXITCODE -eq 0)
Write-Host ("输入 zipalign -c -p 4: {0}" -f $(if ($inAligned) { '已对齐' } else { '未对齐' }))
if (-not $inAligned -and -not $SkipAlign) {
    $base = Join-Path ([System.IO.Path]::GetDirectoryName($OutApk)) ("_zipaligned_" + [System.IO.Path]::GetFileName($OutApk))
    & $zipalign -f -p 4 $InApk $base | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "zipalign 失败" }
    Write-Host "已对齐: $base"
}

# ---- 1 签名（v2+v3，保留既有对齐） --------------------------------------------
Section '1 apksigner sign (v1 关 / v2+v3 开 / 保留既有对齐)'
& $apksigner sign --alignment-preserved true --v1-signing-enabled false --v2-signing-enabled true `
    --v3-signing-enabled true --ks $KeyStore --ks-key-alias $Alias `
    --ks-pass "pass:$StorePass" --key-pass "pass:$KeyPass" --out $OutApk $base
if ($LASTEXITCODE -ne 0) { throw "apksigner sign 失败 (exit $LASTEXITCODE)" }

# ---- 2 验签 -------------------------------------------------------------------
Section '2 apksigner verify'
$verify = & $apksigner verify --verbose --print-certs $OutApk 2>&1 | Out-String
$verify | Set-Content -LiteralPath (Join-Path $LogDir "apksigner_verify_$name.txt") -Encoding utf8
if ($verify -notmatch 'Verifies') { throw "验签失败：`n$verify" }
Write-Host ($verify -split "`n" | Select-String 'Verified using|Signer #1 certificate DN' | Out-String)

# ---- 3 结构不变量：签名只做了插入 ---------------------------------------------
Section '3 结构断言（条目区 / 中央目录逐字节保真）'
& $Python $Sigblock assert-insert-only $base $OutApk
if ($LASTEXITCODE -ne 0) { throw "结构断言失败：签名过程改写了既有字节（详见上方 I1~I4）" }

# ---- 4 产出复检 ---------------------------------------------------------------
Section '4 产物 zipalign -c -p -v 4'
& $zipalign -c -p -v 4 $OutApk | Select-Object -Last 2
if ($LASTEXITCODE -ne 0) { throw "产物未通过 zipalign 校验" }

Write-Host "`n=== DONE ===" -ForegroundColor Green
Write-Host "输出: $OutApk"
Write-Host ("字节数: {0}" -f (Get-Item -LiteralPath $OutApk).Length)
Write-Host ("SHA256: {0}" -f (Get-FileHash -LiteralPath $OutApk -Algorithm SHA256).Hash)
