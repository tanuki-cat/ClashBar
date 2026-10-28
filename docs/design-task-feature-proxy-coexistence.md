# ClashBar 与其他代理软件共存：通用兼容方案

## 文档信息

- 状态：待实施
- 适用范围：macOS，ClashBar 应用侧（不改 mihomo 核心）
- 前置基线：分支 `fix/tun-dns-adguard-compat`（已含 AdGuard 定点修复、DNS 缓存恢复、连通性探测）
- 关联改动：`AdGuardCompatibility`、`LocalCoreRuntimeConfig`、`NetworkReachabilityMonitor`、`AppViewModel+TunNetworkRecovery`

## 1. 目标

把「与其他网络代理软件冲突」从定点补丁升级为体系化能力，达到三个结果：

1. **不坏**：其他软件暴露在本机的服务端点不被 FakeIP 与 TUN 接管。
2. **能兜底**：无法避免的冲突被检测到，并给出可执行结论，而不是表现为「网络不可用」。
3. **不外溢**：默认配置尽可能少影响与本应用无关的流量。

## 2. 非目标

- 不实现「多个 TUN 同时抢占默认路由」的彻底解决——这由 macOS 决定，第三方应用无解。
- 不替代、不修改其他软件自身的设置（不写对方配置、不结束对方进程）。
- 不修改用户订阅源文件。所有改动只发生在运行时副本。

## 3. 问题分类与根因

冲突分四类，可解决程度不同：

| 层次 | 机制 | 可解决性 |
| --- | --- | --- |
| 路由网段 | 更具体的路由自动胜出 | 基本无冲突，仅需排除对方网段 |
| 本地服务端点 | 对方端点若是公网 IP，必然被 TUN 接管 | **可完全解决** |
| DNS 命名空间 | 全局唯一，53 端口劫持排他 | 可大部分解决 |
| 默认路由抢占 | 多个 Network Extension 竞争 | **不可解决**，只能检测 |

已确认的真实案例：

- AdGuard：`local.adguard.org` → 公网 `94.140.14.247`，被 FakeIP + TUN 接管，页面卡在 `Waiting for local.adguard.org`。
- Tailscale：`100.64/10` 比 TUN 的 `64/2` 更具体，路由层面自动存活；风险点在 DNS（`100.100.100.100` MagicDNS）。

**因此通用方案的核心是：把「写死的 AdGuard 例外」泛化为「从运行态推导的排除集」。**

## 4. 现状基线（可直接复用）

| 能力 | 位置 | 说明 |
| --- | --- | --- |
| 运行时配置合并 | `LocalCoreRuntimeConfig` | 解析源配置 → 生成运行时副本 → 私有目录 `state/runtime-configs`（0700/0600），拒绝符号链接；失败降级用原配置 |
| YAML 无损合并 | `AdGuardCompatibility` | 固定 Yams 6.1.0，处理锚点、别名、合并键、多文档、Unicode |
| 配置变更监听 | `NetworkReachabilityMonitor` | SCDynamicStore 监听 `Global/Service` 的 DNS/IPv4/IPv6 + NWPathMonitor |
| 变更后恢复 | `AppViewModel+TunNetworkRecovery` | 1s 防抖、10s 限频、可取消、远程目标隔离 |
| 连通性探针 | `TunConnectivityProbe` | 绕过系统代理，5s 超时 |
| 系统 DNS 清理 | `SystemProxyService.flushSystemDNSCache` + helper v3 | 固定命令白名单，1.5s 超时 |
| 用户提示 | `statusItemBanner` | 菜单栏横幅，用于共存告警 |
| 接口枚举参考 | `DeviceIPv4AddressResolver` | 已有 `getifaddrs` 遍历骨架 |

权限现状：项目无 entitlements 文件，**未启用 App Sandbox**。`getifaddrs`、`SCDynamicStore`、`systemextensionsctl` 均可直接调用，本方案**不需要新增特权操作**。

## 5. 总体架构

```
                       ┌─────────────────────────────┐
   系统运行态 ─────────▶│ CoexistenceDiscovery        │
   (接口/扩展/DNS)      │  非特权只读探测              │
                       └──────────────┬──────────────┘
                                      │ CoexistenceSnapshot
                                      ▼
   ┌──────────────────┐   ┌─────────────────────────────┐
   │ LocalEndpoint    │──▶│ ExclusionPlanner (纯函数)   │
   │ Catalog (内置库)  │   │  可单测，无系统依赖          │
   └──────────────────┘   └──────────────┬──────────────┘
                                         │ ExclusionPlan
                                         ▼
                       ┌─────────────────────────────┐
                       │ LocalCoreRuntimeConfig      │  ← 已有
                       │  YAML 合并 → 运行时副本      │
                       └──────────────┬──────────────┘
                                      ▼
                              mihomo -t / 启动 / 重载
```

设计原则：

1. **探测与决策分离**：`CoexistenceDiscovery` 只产事实，`ExclusionPlanner` 是纯函数，便于测试与复现。
2. **只读探测**：不调用任何修改系统状态的命令。
3. **优雅降级**：任一环节失败退回上一档行为，最差退回当前行为 + 告警，绝不阻断核心启动。
4. **单一出口**：所有排除项仍经 `LocalCoreRuntimeConfig` 合并，不新增第二条配置写入路径。

## 6. 模块设计

### 6.1 CoexistenceDiscovery

只读探测，产出不可变快照。

```swift
struct DetectedInterface: Equatable, Sendable {
    let name: String          // utun4 / ipsec0 / en0
    let family: AddressFamily // v4 / v6
    let address: String       // 点分或压缩 IPv6
    let prefixLength: Int
}

struct DetectedExtension: Equatable, Sendable {
    let bundleIdentifier: String   // io.tailscale.ipn.macsys.network-extension
    let displayName: String
    let isActive: Bool
}

struct ScopedResolver: Equatable, Sendable {
    let interfaceName: String?     // 可能为 nil（全局）
    let nameservers: [String]
    let searchDomains: [String]
}

struct CoexistenceSnapshot: Equatable, Sendable {
    let interfaces: [DetectedInterface]
    let extensions: [DetectedExtension]
    let resolvers: [ScopedResolver]
    let capturedAt: Date
}
```

采集方式：

- **接口与其网段**：`getifaddrs` + `ifa_netmask` 计算前缀长度；过滤 `lo*`、`awdl*`、`llw*`、`169.254/16`。
- **网络扩展**：解析 `/usr/bin/systemextensionsctl list` 的制表符输出，仅取 `network_extension` 段且 `[activated enabled]` 的行。解析失败**不视为错误**，返回空数组。
- **Scoped DNS**：读取 SCDynamicStore 的 `State:/Network/Service/*/DNS` 与 `Global/DNS`，关联到接口名。

约束：

- 单次探测目标 < 50ms，仅在「开启 TUN」与「网络配置变化（防抖后）」触发。
- 结果缓存，同一网络配置代次内不重复探测。
- 任何异常捕获后返回空快照，不向上抛。

### 6.2 LocalEndpointCatalog

内置的「已知本地端点」规则库，解决探测不到的场景（如对方软件运行时无扩展、端点域名与 IP 不固定）。

```swift
struct LocalEndpointRule: Sendable {
    let id: String                 // adguard / tailscale / zerotier
    let displayName: String
    let domains: [String]          // local.adguard.org
    let addresses: [String]        // 94.140.14.247/32
    let subnets: [String]          // 100.64.0.0/10（Tailscale）
    let activation: Activation     // .always / .whenInterfacePresent("utun")
}
```

首批条目：

| id | 域名 | 地址/网段 | 激活条件 |
| --- | --- | --- | --- |
| `adguard` | `local.adguard.org`、`injections.adguard.org` | `94.140.14.247/32` | 检测到 AdGuard 扩展或 `local.adguard.org` 可解析 |
| `tailscale` | `*.ts.net` | `100.64.0.0/10`、`100.100.100.100/32`、`fd7a:115c:a1e0::/48` | 存在 Tailscale 接口或扩展 |
| `zerotier` | — | 由接口地址推导 | 存在 `feth*` 接口 |

`Activation` 决定是否参与，避免「没装 AdGuard 也强行改配置」——这是当前定点修复的改进点。

### 6.3 ExclusionPlanner（纯函数）

```swift
struct ExclusionPlan: Equatable, Sendable {
    var routeExclusions: [String] = []      // tun.route-exclude-address
    var fakeIPFilters: [String] = []        // dns.fake-ip-filter
    var fakeIPFilterMode: String?           // 必要时改写
    var hostPins: [String: String] = [:]    // hosts
    var directRules: [String] = []          // rules 顶部
    var nameserverPolicy: [String: [String]] = [:]
    var sniffingSkips: [String] = []
}

static func plan(snapshot: CoexistenceSnapshot,
                 catalog: [LocalEndpointRule],
                 own: OwnTunInfo) -> ExclusionPlan
```

`OwnTunInfo` 来自运行时配置的 `tun.device`（如 `utun9`），用于**排除自身**，避免把自己写出范围。

安全规则（全部为硬性校验，不满足则该条丢弃并告警）：

1. 拒绝 `0.0.0.0/0`、`::/0`。
2. 拒绝覆盖本机物理接口网段（`en0` 的子网）。
3. 拒绝 `127.0.0.0/8`、`224.0.0.0/4`、`255.255.255.255/32` 作为排除项（无意义）。
4. 前缀长度必须合法且与地址族匹配。
5. 单类排除项上限 64 条，超出截断并告警。
6. 仅当对应接口/扩展**当前存在且 up** 时才加入动态排除。

### 6.4 并入运行时配置

在 `AdGuardCompatibility.applying(to:)` 之上抽象为统一合并器：

```swift
enum RuntimeOverlay {
    static func apply(source: String, plan: ExclusionPlan) throws -> String
}
```

合并语义（顺序即优先级）：

1. `tun.route-exclude-address`：plan 项**前置**，用户原有项保留。
2. `dns.fake-ip-filter`：按 `fake-ip-filter-mode` 分别处理（blacklist 前置域名；rule 前置 `DOMAIN,...,real-ip`；whitelist 按现有转换逻辑，plan 项优先，尾部保持 `MATCH,real-ip`）。
3. `hosts`：plan 的固定映射覆盖同名项。
4. `rules`：plan 的 DIRECT 规则**前置**，用户规则整段保留。
5. `dns.nameserver-policy`：合并 plan 的分域解析。
6. `sniffer.skip-domain`：plan 项前置。

保持既有保证：不改源文件、私有目录、原子写、降级。

### 6.5 DNS 分域

针对 Tailscale 这类「域名只在对方 DNS 里有答案」的情况：

- 从 `ScopedResolver.searchDomains` 与 catalog 的 `domains` 得到后缀集合。
- 写入 `dns.nameserver-policy`，指向对方接口上的 DNS（如 `100.100.100.100`）。
- 对应域名同时进 `fake-ip-filter`，保证拿到真实地址后走更具体的路由出去。

风险控制：仅当该 DNS 地址所在接口存在时才写入，避免对方关闭后查询挂死。

### 6.6 共存检测与诊断

**开启 TUN 前**：执行一次探测，若命中已知软件，写一条 info 日志并在 `statusItemBanner` 给出提示（不阻断，不弹模态框）。

**探针失败时**：执行三路对比，输出明确结论。

```swift
struct ConnectivityDiagnosis {
    let systemResolution: ProbeResult   // 系统解析
    let coreResolution: ProbeResult     // 核心 DNS
    let directConnect: ProbeResult      // 固定 IP 直连
    let verdict: Verdict
}

enum Verdict {
    case ok
    case nodeUnavailable            // 直连通、代理不通 → 节点问题
    case dnsInterception            // 系统解析与核心解析不一致
    case routeCapture(String)       // 命中其他 TUN 网段
    case unknown
}
```

对应文案区分「节点不可用」「DNS 被其他软件接管」「路由被 X 接管」，替换当前笼统的「连通性探测失败」。

### 6.7 保守默认值

作为独立开关（默认关闭，避免改变既有行为）：

- FakeIP 默认排除：`*.local`、`*.lan`、`169.254.0.0/16`、`127.0.0.0/8`。
- 可选：把 RFC1918 从 TUN 路由排除（`10/8`、`172.16/12`、`192.168/16`）。

> 说明：RFC1918 默认仍在 TUN 内（由 mihomo 规则判 DIRECT）。改为路由排除会降低 LAN 访问延迟，但会影响「需要代理访问内网」的用户，因此必须显式开启。

## 7. 数据流与时序

**开启 TUN：**

1. 权限校验（现有）
2. `CoexistenceDiscovery.snapshot()`
3. `ExclusionPlanner.plan(...)`
4. `RuntimeOverlay.apply(source:plan:)` → 运行时副本
5. 写入 `tun.enable = true`（沿用现有 PATCH 路径）
6. 若检测到共存软件 → info 日志 + 横幅
7. 进入现有恢复流程（DNS 清理 + 探针）

**网络配置变化：**

1. SCDynamicStore 回调（现有）
2. 防抖 1s / 限频 10s（现有）
3. 重新探测 → 若排除集**实际变化**才重写运行时副本并重启内核；无变化只做 DNS 清理
4. 探针失败 → 三路诊断

关键点：**排除集未变化时不重启内核**，避免网络抖动引发频繁重启。

## 8. 关键约束与安全

- 只读探测，不调用修改系统状态的命令。
- 不写入其他软件目录，不结束其他进程。
- 运行时副本保持 0700/0600，拒绝符号链接父目录（现有实现已覆盖）。
- 远程目标（`isRemoteTarget`）执行全部本机探测与系统操作，远程只做核心侧 PATCH。
- 解析失败、命令不存在、输出格式变化一律降级，不抛错到用户。

## 9. 失败降级与回滚

四档，逐级退让：

1. 完整方案：动态排除 + 内置库 + DNS 分域
2. 仅内置库（探测失败）
3. 仅安全默认值
4. 原始配置（合并失败）——现有行为，附警告日志

任一档都保证核心能启动。回滚方式：删除 `state/runtime-configs` 下副本即可，源配置从未被改动。

## 10. 影响面

| 模块 | 变更 |
| --- | --- |
| `Services/CoexistenceDiscovery.swift` | 新增 |
| `Services/LocalEndpointCatalog.swift` | 新增 |
| `Services/ExclusionPlanner.swift` | 新增（纯函数） |
| `Services/RuntimeOverlay.swift` | 新增，替换 `AdGuardCompatibility.applying` 的入口 |
| `Services/AdGuardCompatibility.swift` | 收敛为 catalog 的一条规则 |
| `Services/ConnectivityDiagnosis.swift` | 新增 |
| `ViewModels/AppViewModel+Tun.swift` | 开启前探测与提示 |
| `ViewModels/AppViewModel+TunNetworkRecovery.swift` | 排除集变化判定、诊断接管 |
| 本地化 | 新增诊断与提示文案 |

## 11. 测试与验证

单元测试（纯函数，无系统依赖）：

- Planner：自身 TUN 不被排除；物理网段不被排除；`0.0.0.0/0` 被拒绝；上限截断；接口消失后不产生动态项。
- Catalog：未安装软件的规则不激活。
- Overlay：三种 `fake-ip-filter-mode` 合并正确；用户规则整段保留；重复应用幂等。
- Diagnosis：四类 `Verdict` 的判定表。

集成验证：

- 真实订阅副本经合并后 `mihomo -t` 通过（沿用现有测试）。
- 真实环境对照：开启/关闭 AdGuard、Tailscale 各一遍，检查 `route -n get` 与 `dig @127.0.0.1 -p 7874`。

回归守则：不引入网络副作用，测试默认不调用真实系统命令（探测层注入替身）。

## 12. 验收标准

1. 开启 AdGuard + Tailscale 情况下开启 TUN，`local.adguard.org` 返回真实地址且页面不卡。
2. 关闭 Tailscale 后，`100.64/10` 不再出现在排除集中（下次探测自动收敛）。
3. 探针失败时日志能明确指出是哪一类问题，而不是「网络不可用」。
4. 合并失败时核心仍能启动，且日志有明确降级说明。
5. 现有 30 项测试全部保持通过。

## 13. 实施阶段

| 阶段 | 内容 | 依赖 |
| --- | --- | --- |
| P1 | `ExclusionPlanner` + `LocalEndpointCatalog` + `RuntimeOverlay` 重构，AdGuard 定点逻辑迁入 | 无 |
| P2 | `CoexistenceDiscovery` 接入 TUN 开启与配置变化 | P1 |
| P3 | `ConnectivityDiagnosis` 与文案 | P1 |
| P4 | DNS 分域（Tailscale）| P1、P2 |
| P5 | 保守默认值与设置开关 | P1 |

每阶段独立可交付、可回滚。P1+P2 完成后即覆盖主要场景。

## 14. 风险

| 风险 | 缓解 |
| --- | --- |
| `systemextensionsctl` 输出格式变化 | 防御式解析，失败返回空，不影响主流程 |
| 误排除用户想代理的网段 | 仅排除「当前存在的外部接口」；安全规则硬校验；可在设置中关闭动态排除 |
| 排除集频繁变化导致重启 | 仅在排除集实际变化时重启 |
| 分域 DNS 指向已消失的接口 | 写入前校验接口存在 |
| YAML 合并破坏复杂订阅 | 已有降级 + 真实订阅 `mihomo -t` 测试 |

## 15. 未解决的边界

- 两个 Network Extension 同时抢默认路由，优先级由系统决定，**不做也不能做**干预；本方案只保证「检测到并说清楚」。
- 对方软件若强制改写系统 DNS 且拒绝共存，唯一可靠形态是互斥使用；本方案提供明确提示，不自动结束对方进程。
- 未知软件的私有协议端点无法穷举，只能通过「已知库 + 动态接口推导」覆盖大多数。
