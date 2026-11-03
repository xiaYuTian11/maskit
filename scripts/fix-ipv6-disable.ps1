# 修复 TLS 握手随机挂死：解绑指定网卡的 IPv6（ms_tcpip6），强制该网卡走 IPv4。
#
# 根因（本机实测，2026-11-02）：
#   · 纯 IPv4 路径 20/20 全过（avg 0.68s / max 1.61s）
#   · 纯 IPv6 路径 20 次挂 6 次（TCP 0.2s 正常、TLS 0.6s↔15s 剧烈抖动）
#   · 降 IPv6 MTU 1400→1280 反而更差（16/20 → 14/20），故不是 PMTUD 可调项
#   · 抬 RFC6724 地址族优先级无效（Windows 排序不按该策略，且被 DNS 缓存掩盖）
#   结论：该网卡的 IPv6 链路对大包不可靠，唯一稳定解法是不从它发 IPv6。
#
# 影响面（本机核对）：
#   · 只解绑一个网卡的 ms_tcpip6 绑定，不改路由、不改 IPv4、不改 MTU、不禁用网卡；
#   · WLAN 的 IPv4 照常工作（外网访问不受影响）；
#   · Tailscale（fd7a:: ULA 走自己网卡）与 SVN 企业内网（无全球 IPv6）均不受影响。
#
# 用法（需管理员）：
#   .\scripts\fix-ipv6-disable.ps1                # 解绑（默认 WLAN）
#   .\scripts\fix-ipv6-disable.ps1 -Rollback      # 重新绑定
#   .\scripts\fix-ipv6-disable.ps1 -Verify        # 只测当前状态
param(
    [switch]$Rollback,
    [switch]$Verify,
    [string]$InterfaceAlias = 'WLAN',
    [int]$Probes = 20
)

$ErrorActionPreference = 'Stop'
$ComponentId = 'ms_tcpip6'

function Test-Handshake([string]$Tag, [int]$n) {
    # 并发探测：成功 0.6~2s，失败挂到 8s 超时；串行 n 次最坏 n×8s 用户得干等
    $py = @'
import socket, ssl, time, concurrent.futures, sys
host = "token.ciyuanroute.com"
probes = int(sys.argv[1])

def one(_):
    t0 = time.time()
    try:
        s = socket.create_connection((host, 443), timeout=8)
        ssl.create_default_context().wrap_socket(s, server_hostname=host).close()
        return time.time() - t0
    except Exception:
        return None

with concurrent.futures.ThreadPoolExecutor(max_workers=min(probes, 8)) as ex:
    res = list(ex.map(one, range(probes)))

ok = [r for r in res if r is not None]
avg = sum(ok) / max(len(ok), 1)
mx = max(ok) if ok else 0.0
print(f"ok={len(ok)}/{probes} fail={probes - len(ok)} avg={avg:.2f}s max={mx:.2f}s")
'@
    $tmp = Join-Path $env:TEMP ("maskit-v6probe-{0}.py" -f [guid]::NewGuid().ToString('N'))
    Set-Content -Path $tmp -Value $py -Encoding UTF8
    try {
        $out = (& python $tmp $n 2>&1 | Out-String).Trim()
        Write-Host ("{0}: {1}" -f $Tag, $out)
        if ($out -match 'fail=(\d+)') { return [int]$Matches[1] }
        return -1
    } finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
}

function Get-Binding([string]$alias) {
    $b = Get-NetAdapterBinding -Name $alias -ComponentID $ComponentId -ErrorAction Stop
    if ($b -is [array]) { $b = $b[0] }
    return $b
}

$b = Get-Binding $InterfaceAlias
Write-Host ("网卡 {0} 的 {1} 绑定当前 Enabled = {2}" -f $InterfaceAlias, $ComponentId, $b.Enabled)
Write-Host ''

if ($Verify) {
    [void](Test-Handshake '当前状态' $Probes)
    exit 0
}

if ($Rollback) {
    if ($b.Enabled) {
        Write-Host '已是绑定状态，无需回滚。'
        [void](Test-Handshake '当前状态' $Probes)
        exit 0
    }
    Write-Host ("重新绑定 {0} 的 {1}" -f $InterfaceAlias, $ComponentId)
    Enable-NetAdapterBinding -Name $InterfaceAlias -ComponentID $ComponentId
    $nb = Get-Binding $InterfaceAlias
    Write-Host ("绑定后 Enabled = {0}" -f $nb.Enabled)
    Write-Host ''
    [void](Test-Handshake '回滚后' $Probes)
    Write-Host '已回滚。'
    exit 0
}

if (-not $b.Enabled) {
    Write-Host '已是解绑状态，无需修改。'
    [void](Test-Handshake '当前状态' $Probes)
    exit 0
}

Write-Host ("解绑 {0} 的 {1}" -f $InterfaceAlias, $ComponentId)
Disable-NetAdapterBinding -Name $InterfaceAlias -ComponentID $ComponentId
$nb = Get-Binding $InterfaceAlias
Write-Host ("解绑后 Enabled = {0}" -f $nb.Enabled)
if ($nb.Enabled) {
    Write-Warning '解绑未生效。'
    exit 1
}
Write-Host ''

$fails = Test-Handshake '修改后' $Probes
Write-Host ''

# 全失败 = 问题不在这个网卡的 IPv6，立即回滚，不留坏状态
if ($fails -eq $Probes) {
    Write-Warning "全部 $Probes 次失败，解绑未带来改善，自动回滚。"
    Enable-NetAdapterBinding -Name $InterfaceAlias -ComponentID $ComponentId
    exit 1
}

Write-Host '完成。如需回滚： .\scripts\fix-ipv6-disable.ps1 -Rollback'
