---
name: security-audit-lnd
description: lnd (Lightning Network Daemon) 定制化 AI 安全审计技能。基于 `gpBlockchain/ckb-test-skills` 的通用 security-audit 技能改造，针对 lnd 的协议（BOLT #1~#11）、密码学（secp256k1 / Brontide / Sphinx / MuSig2）、资金托管与状态机特性提供专业化审计流程。以 TODO 文档为中枢，分阶段渐进执行，支持跨会话持续推进。
---

# Skill: lnd 定制化安全审计 (Security-Audit for Lightning Network Daemon)

> 本技能基于通用 [security-audit SKILL](https://github.com/gpBlockchain/ckb-test-skills/blob/main/.claude/skills/security-audit/SKILL.md)
> 改造，**完整保留** 其 4 阶段流水线（侦察 → 审计 → 文档更新 → 报告）与 TODO
> 文档驱动模式，并针对 lnd 的协议、密码学与资金路径进行专业化定制。
>
> 审计目标仓库：[`lightningnetwork/lnd`](https://github.com/lightningnetwork/lnd)
> （Go 实现的 BOLT 兼容闪电网络节点）。

---

## 〇、与通用 SKILL 的关系

| 模块 | 通用 SKILL | lnd 定制 |
|------|-----------|----------|
| 核心工作流 | Phase 0 → 1 → 2 → 3 | ✅ 完全保留 |
| 项目类型 | 单一选择 | ➕ 改为 **6 项复合类型** 同时勾选 |
| 信任边界 | 自由描述 | ➕ 强制 **T0~T5 共 6 等级** 打标 |
| 审计维度 | 9 个通用维度 | ➕ 新增 **6 个 LN 专属维度** (DIM-LN-*) |
| Phase 1 选取规则 | P0/P1/P2/P3 | ➕ 加入 **lnd 加权规则**（资金路径优先） |
| Phase 1 攻击思维 | 通用 6 类 | ➕ 强制覆盖 **4 类 LN 特有攻击场景** |
| 报告 (Phase 3) | 7 节 | ➕ 追加 **3 节** (BOLT 合规 / 资金风险 / 历史 CVE) |
| 执行约束 | 8 条 | ➕ 追加 **4 条** lnd 专属约束 |

凡未在本技能中显式覆盖的规则，**均沿用通用 SKILL** 的定义。

---

## 一、项目类型重定位 (覆盖通用 Step 0.1)

在通用 SKILL 的 Phase 0.1 中，lnd **必须同时勾选** 以下复合类型（不再是单一项目类型）：

- ☑ **区块链节点**（与 btcd/bitcoind/Neutrino 交互的 L2 节点）
- ☑ **密码学库使用者**（`secp256k1`、ECDH、Schnorr/MuSig2、Sphinx 洋葱）
- ☑ **P2P 网络协议实现**（BOLT #1~#11、Brontide / Noise_XK 握手）
- ☑ **资金托管型守护进程**（持有热钱包私钥 + 通道状态 → 误操作可能导致资金永久损失）
- ☑ **gRPC / REST 后端服务**（macaroon 认证 + TLS）
- ☑ **状态机系统**（通道生命周期、HTLC 生命周期、链上仲裁）

➡ 这一定位会激活通用 SKILL 的 **全部 9 个维度**，并额外引入第三节的
**6 个 Lightning 专属维度**，合计 **15 个审计维度**。

---

## 二、Phase 0 (侦察建档) 的 lnd 定制步骤

### Step 0.1 — 技术栈与版本基线（lnd 固定项）

固定收集项（写入 TODO 文档的「项目概况」段）：

- Go 版本（`go.mod` 顶部 `go` 指令）
- 关键依赖与版本：
  - `github.com/btcsuite/btcd`
  - `github.com/btcsuite/btcwallet`
  - `github.com/btcsuite/btcd/btcec/v2`
  - `github.com/lightningnetwork/lnd/tor`
  - `github.com/lightninglabs/neutrino`（如启用）
- `lnrpc/*.proto` 中暴露的 RPC 子服务列表（决定攻击面边界）
- BOLT 规范版本对齐（BOLT 1 / 2 / 3 / 4 / 5 / 7 / 8 / 9 / 11）
- 是否启用：
  - Taproot Channels
  - MuSig2
  - SCB (Static Channel Backup)
  - Watchtower（`wtclient` / `watchtower/`）
  - `--no-macaroons`
  - Tor
  - Loop / Pool 集成
- 数据后端：`bbolt` vs `etcd` vs `postgres` vs `sqlite`（`kvdb/` 与 `sqldb/`）

### Step 0.2 — lnd 信任边界图谱（**必须建档**）

将信任边界明确划分为下列 **6 个等级**，**每个 RPC / 包都要打标签**：

| 等级 | 来源 | 典型攻击者 | lnd 中的位置 |
|------|------|------------|--------------|
| T0 | 本地操作员 / init 配置 | 内部威胁 | `config.go`, `lncfg/*`, `lnd.conf`, `sample-lnd.conf` |
| T1 | 已认证 macaroon RPC | 凭据泄露 / 越权 | `rpcserver.go`, `*rpcserver.go`, `rpcperms/` |
| T2 | 未认证 RPC (`WalletUnlocker`) | 未授权用户 | `walletunlocker/` |
| T3 | 已建立通道的远端节点 | 通道对手方 | `peer/`, `htlcswitch/`, `lnwire/` |
| T4 | 公网任意节点 (gossip / 握手) | 任意网络攻击者 | `brontide/`, `discovery/`, `lnpeer/` |
| T5 | 区块链数据 | 矿工 / 重组 / RBF | `chainntnfs/`, `lnwallet/btcwallet/`, `routing/` |

> **核心规则**：T3 / T4 / T5 输入必须假定为 **完全恶意**。
> Phase 1 中所有处理 T3 / T4 / T5 数据的函数自动获得 **P0** 优先级。

### Step 0.3 — 关键调用链快速建图（"7 条资金路径"）

**强制** 为以下 7 条「资金路径」建立完整调用链（CallChain），作为 Phase 1
审计的主轴：

1. **链上充值 → 通道开启**：`fundingmanager` → `lnwallet.LightningChannel` → 广播 funding tx
2. **HTLC 转发**：`htlcswitch.Switch.forward` → `link.handleDownstreamPkt` → `commitment_chain` 更新
3. **HTLC 结算**：`invoiceRegistry.NotifyExitHopHtlc` → preimage 释放 → `link.settle`
4. **通道关闭（合作）**：`chancloser` → 协商 fee → 共同签名
5. **通道关闭（强制 / 对手作弊）**：`contractcourt.ChannelArbitrator` → `BreachArbitrator` → `sweep` 资金回收
6. **节点重启 → 通道恢复**：`channeldb` 重放 + `chanbackup` 强制恢复
7. **守望塔 (Watchtower)**：`wtclient` 备份会话 → 远端 `watchtower` 触发司法交易

### Step 0.4 — lnd 测试盲区清单

`itest/` 集成测试覆盖广但耗时长；以下场景天然测试不足，**需重点静态审计**：

- 链重组（1/3/6 块深度）+ 通道状态机交互
- 对手方发送畸形 `lnwire` 消息序列
- macaroon caveat 边界绕过
- `kvdb` 切换后端时的事务原子性差异
- 钱包派生在异常路径（如 Aezeed birthday 错误）
- Watchtower session 在中途断网 / 重试时的一致性

### Step 0.5 — 初始 TODO 文档（lnd 扩展字段）

在通用 TODO 模板基础上，**「项目概况」段** 必须新增以下字段：

```
- BOLT 兼容版本: {1/2/3/4/5/7/8/9/11 各自的实现位置与版本}
- 启用的实验性特性: {Taproot Channels / AMP / MPP / Hodl Invoice / MuSig2 / Blinded Paths}
- 数据库后端: {bbolt | etcd | postgres | sqlite}
- macaroon 权限矩阵导出: {对应文件链接，如 lnrpc/*.yaml}
- 总通道相关代码行数 (lnwallet + htlcswitch + contractcourt + channeldb): {N}
- 6 等级信任边界打标完成率: {N/总包数}
- 7 条资金路径调用链建图完成率: {N/7}
```

---

## 三、新增 Lightning 专属审计维度

在通用 SKILL 的 9 个维度（INPUT / CRYPTO / AUTH / LOGIC / MEMORY / CONTRACT /
DEPS / SERDE / ERRINFO，外加可选的 SPEC 规范一致性）基础上，**新增以下 6 个
LN 专属维度**，并在 Phase 0.5 **强制启用**。

### DIM-LN-COMMIT: 通道承诺状态机

**适用**: `lnwallet/`, `channeldb/`

- ☐ commitment number 单调递增；revocation key 派生使用 `shachain` 正确点
- ☐ remote-revoked state 永远不会被签名 / 广播（防自我作弊保护）
- ☐ `dust limit` 与 `to_self_delay` 边界值（最小 / 最大）
- ☐ `pending_htlcs` 提交点切换的原子性 (TOCTOU)
- ☐ Taproot 通道下 MuSig2 nonce **不可重用**（重用 = 私钥泄露）
- ☐ FeeRate 飙升时本地承诺仍可上链（"anchor" 输出 + CPFP）

### DIM-LN-HTLC: HTLC 生命周期与转发安全

**适用**: `htlcswitch/`, `invoices/`, `record/`

- ☐ CLTV expiry delta 是否充足，能否被剥削发起 **拥塞攻击 / probing**
- ☐ HTLC 数量上限 (`max_accepted_htlcs` ≤ 483)
- ☐ preimage 释放 **必须先于** 上游 `settle`（防偷币）
- ☐ Hodl Invoice 超时是否在 expiry 之前主动 fail（防强制上链亏损）
- ☐ replay：同一 payment_hash 多次抵达不应被结算两次（持久化幂等）
- ☐ AMP / MPP 分片：所有分片到齐前不释放 preimage；分片 set_id 校验
- ☐ probing：错误码是否泄露内部节点拓扑 / 余额

### DIM-LN-ONION: Sphinx 洋葱路由

**适用**: `htlcswitch/hop`, `routing/route`

- ☐ HMAC 校验在解密前 / 后顺序正确（恒定时间）
- ☐ 共享密钥派生使用唯一 ephemeral pubkey；防 replay 通过 `replay_log`
- ☐ failure onion 加密层数 = 路径长度，**长度填充** 必须固定
- ☐ 错误 obfuscation 不泄露中间跳信息
- ☐ TLV onion payload 解析对未知偶 / 奇类型的处理符合 BOLT #1
- ☐ Blinded paths：introduction node 之后不泄露 next-hop

### DIM-LN-CHAIN: 链上仲裁与资金回收

**适用**: `contractcourt/`, `sweep/`, `chainntnfs/`

- ☐ Breach（对手广播旧 commit）→ `BreachArbitrator` 是否能在 `to_self_delay` 内回收
- ☐ Anchor / CPFP / RBF 费率计算上限 (`MaxFeeRate`)，防止把自己付到尘埃
- ☐ 区块重组场景下：已 `Resolved` 的合约不会被错误重新解析
- ☐ `nursery` UTXO 在 `csv_delay` 满足前不被广播
- ☐ HTLC second-level success / timeout tx 的费率与 deadline 匹配
- ☐ Pinning attack：mempool replacement 政策对 HTLC 回收的影响

### DIM-LN-WIRE: 线协议消息处理

**适用**: `lnwire/`, `peer/`, `brontide/`

- ☐ 所有 `Message.Decode` 对超长 / 截断 / 未定义 TLV 的处理
- ☐ `feature bits` 协商：必须特性未支持时立即断开
- ☐ Brontide (Noise_XK) 握手：actone / two / three 状态机仅按顺序推进
- ☐ Brontide 16KB 帧上限严格执行；消息计数器 (nonce) 防溢出
- ☐ 与 BOLT #1 兼容：未知偶数类型必须断开通道
- ☐ Gossip 消息：`channel_announcement` 4 个签名全部校验后再传播
- ☐ Gossip 速率限制（防止 DoS / gossip flood）—— `discovery/`

### DIM-LN-KEY: 密钥与种子管理

**适用**: `aezeed/`, `keychain/`, `macaroons/`, `lnencrypt/`, `walletunlocker/`

- ☐ Aezeed 通行码错误时不泄露差异（恒定时间比较）
- ☐ HD 派生路径与 BIP32 + lnd 扩展（KeyFamily）不冲突；keyloc 隔离
- ☐ 私钥导出 RPC (`WalletKit.DeriveKey` 等) 的 macaroon 权限严格
- ☐ Macaroon caveat first-party verifier 实现：无任何 caveat 类型可被静默忽略
- ☐ `admin.macaroon` 自动续期 / 吊销策略
- ☐ Static Channel Backup (SCB) 加密使用 ChaCha20-Poly1305；nonce 唯一
- ☐ 私钥内存零化（`btcec` / `lnencrypt` 用完即清）

---

## 四、Phase 1 审计选取规则的 lnd 化

通用 SKILL 的优先级规则之上，**加入 lnd 加权**（自上而下递减）：

```
1. 信任边界等级 T4 / T5 输入处理函数
2. 任何会持久化 commitment / revocation 状态的写路径
3. 任何会触发 OnchainBroadcast 的代码
4. 任何在 funding / settle / breach 路径上的密码学操作
5. macaroon caveat 校验路径
6. gossip 验签与转发
7. 其他通用 P0（输入验证、序列化）
```

每个审计项在通用「逆向攻击思维」之外，**强制覆盖以下 4 类 LN 攻击场景**：

- **重组攻击**：1 / 3 / 6 块深度重组的状态变化
- **恶意对手方**：发送任意 `lnwire` 消息序列（不仅是协议允许的）
- **慢节点 / 死锁**：对手方故意不响应 `RevokeAndAck` 时本地状态
- **资源耗尽**：填满 `max_accepted_htlcs` 后的内存 / CPU 行为

---

## 五、Phase 3 报告的 lnd 定制章节

在通用 7 节报告结构基础上 **追加** 以下 3 节：

- **第 8 节: BOLT 合规性矩阵** — 列出 BOLT 1~11 中每个 MUST / SHOULD 子句的
  实现位置 + 偏差说明（每条引用 BOLT 文档锚点）。
- **第 9 节: 资金风险敞口模型** — 列出每个发现影响的资金路径与最大损失估算
  （单位 sats / BTC 等级；区分 "通道余额" / "在途 HTLC" / "热钱包 UTXO"）。
- **第 10 节: 与 lnd 已公开 CVE 的对比** — 检查历史 CVE（如 CVE-2020-26896
  等）对应的回归测试 / 修复仍存在，且未被后续重构意外回退。

---

## 六、AI 执行约束（在通用 8 条基础上追加 4 条）

> 通用 8 条约束（深度优于广度、不臆断、需动态验证标注、最坏情况输入、
> TODO 单一真相、每次输出"做了什么 + 下次做什么"）**继续生效**。

追加 lnd 专属约束：

9.  **严禁臆造 BOLT 条款**：每条"协议要求"必须引用具体的 BOLT 文档锚点
   （例如 `BOLT #2 § "the receiving node:"` 列表第 N 项）。
10. **区分理论 vs 实际可利用**：链上攻击成本（fee bump、矿工合谋、mempool
   pinning）须显式估算，避免高估严重性。
11. **跨进程边界**：lnd ↔ btcd / bitcoind / Neutrino / SQL backend
   (postgres / sqlite) 的信任假设必须显式声明（不能默认 backend 可信；
   恶意 / bug backend 应作为威胁模型一部分）。
12. **数据库后端差异**：发现的问题应注明在哪些 backend（bbolt / etcd /
   postgres / sqlite）复现，因为事务语义不同（`kvdb/` 与 `sqldb/` 实现各异）。

---

## 七、初始 TODO 文档骨架（建议生成的第一版）

> Phase 0.5 完成后，应至少产出以下 P0 / P1 审计项作为 v1 TODO 文档的起点。
> 具体行号在 Phase 0 完成后补全。

```markdown
# lnd 安全审计 TODO

> 版本: v1 | 最后更新: YYYY-MM-DD | 状态: 进行中

## 项目概况
  - 语言: Go (version: TBD)
  - 类型: 区块链节点 / 密码学库使用者 / P2P 协议 / 资金托管守护进程 /
          gRPC 后端 / 状态机系统
  - BOLT 兼容版本: {…}
  - 启用的实验性特性: {…}
  - 数据库后端: {…}
  - macaroon 权限矩阵导出: {…}
  - 总通道相关代码行数 (lnwallet + htlcswitch + contractcourt + channeldb): {N}

## 审计进度
  - 总 TODO 项: 10 (初始)
  - ✅ 已完成: 0  | ❌ 发现问题: 0  | ⏳ 待审计: 10

---

## 第 1 章: DIM-LN-COMMIT 通道承诺状态机

- [ ] 🔴 **AUDIT-LN-COMMIT-001**: 验证 MuSig2 nonce 永不重用
  - **关联代码**: `lnwallet/channel.go::LightningChannel.SignNextCommitment`
  - **审计内容**:
    - SignNextCommitment 每次调用使用全新 nonce
    - 异常路径 (重试 / panic 恢复) 不会复用旧 nonce
    - nonce 持久化至 `channeldb` 前不被广播
  - **现有覆盖**: TBD（检查 `lnwallet/musig_session_test.go`）

## 第 2 章: DIM-LN-HTLC HTLC 生命周期与转发安全

- [ ] 🔴 **AUDIT-LN-HTLC-001**: HTLC settle → upstream propagate 顺序与持久化
  - **关联代码**: `htlcswitch/link.go`, `htlcswitch/switch.go`
  - **审计内容**:
    - preimage 持久化在向上游 settle 之前完成
    - 节点重启后 in-flight HTLC 不丢失 / 不重复结算

## 第 3 章: DIM-LN-CHAIN 链上仲裁与资金回收

- [ ] 🔴 **AUDIT-LN-CHAIN-001**: justice tx 在 `to_self_delay` 内可上链的费率上限
  - **关联代码**: `contractcourt/breacharbiter.go`
  - **审计内容**:
    - MaxFeeRate 上限合理；不会把 justice tx 自身付为 dust
    - 检测 breach 后到 sweep 入块的最大延迟在 `to_self_delay` 内

## 第 4 章: DIM-LN-ONION Sphinx 洋葱路由

- [ ] 🔴 **AUDIT-LN-ONION-001**: 解密前 HMAC 恒定时间校验
  - **关联代码**: `htlcswitch/hop/`, `routing/route/`
  - **审计内容**:
    - HMAC 比较使用 `hmac.Equal` / `subtle.ConstantTimeCompare`
    - 校验失败的错误路径不泄露失败位置

## 第 5 章: DIM-LN-WIRE 线协议消息处理

- [ ] 🔴 **AUDIT-LN-WIRE-001**: lnwire Message.Decode 畸形输入覆盖
  - **关联代码**: `lnwire/*.go`
  - **审计内容**:
    - 超长 / 截断 / 未定义 TLV 的处理（已有 fuzz 覆盖率检查）
    - 未知偶数类型按 BOLT #1 触发断开通道

## 第 6 章: DIM-LN-KEY 密钥与种子管理

- [ ] 🔴 **AUDIT-LN-KEY-001**: macaroon first-party caveat 校验器完整性
  - **关联代码**: `macaroons/service.go`, `macaroons/constraints.go`
  - **审计内容**:
    - 所有已定义 caveat 类型都有对应 verifier
    - 未识别 caveat 默认拒绝（fail-closed）

## 第 7 章: DIM-CRYPTO 密码学（通用维度，lnd 实例化）

- [ ] 🔴 **AUDIT-CRYPTO-001**: brontide actthree 前禁止应用层消息；nonce 溢出处理
  - **关联代码**: `brontide/noise.go`
  - **审计内容**:
    - 握手未完成前任何 `WriteMessage` 调用应失败
    - 消息计数器 (nonce) 接近 2^64 时主动断开 / 轮换

## 第 8 章: DIM-AUTH 认证与授权（通用维度，lnd 实例化）

- [ ] 🔴 **AUDIT-AUTH-001**: walletunlocker 解锁前的 RPC 暴露面
  - **关联代码**: `walletunlocker/`, `rpcserver.go`
  - **审计内容**:
    - 仅白名单方法可在解锁前调用
    - 解锁后未授权 RPC 不会因状态切换错误地保持开放

## 第 9 章: DIM-SERDE 序列化（通用维度，lnd 实例化）

- [ ] 🟠 **AUDIT-SERDE-001**: channeldb 旧版本 schema 读取的下溢 / 越界
  - **关联代码**: `channeldb/migration*/`
  - **审计内容**:
    - 迁移过程中字段长度校验
    - 不同 backend (bbolt/etcd/postgres/sqlite) 一致性

## 第 10 章: DIM-LOGIC 业务逻辑（通用维度，lnd 实例化）

- [ ] 🟠 **AUDIT-LOGIC-001**: kvdb 不同后端的事务回滚一致性
  - **关联代码**: `kvdb/`, `channeldb/`
  - **审计内容**:
    - postgres / sqlite / bbolt / etcd 的 `Update` 失败语义一致
    - 中间状态不会被部分提交

---

## 附录 A: 审计执行日志
| 日期 | 审计项 | 发现摘要 | 状态 |
|------|--------|----------|------|

## 附录 B: 新增项跟踪
| 日期 | 新增项 ID | 来源 | 描述 |
|------|-----------|------|------|

## 附录 C: 修复建议
| 审计项 | 严重级别 | 建议方案 | 修复状态 |
|--------|----------|----------|----------|
```

---

## 八、快速使用指南（给后续 AI 会话）

每次进入 lnd 仓库执行审计时：

1. **首轮**：执行 Phase 0（按本技能第二节的 5 个 Step），产出
   `SECURITY_AUDIT_TODO.md`（建议放在仓库外或 `/tmp` 下，避免污染源码树）。
2. **后续轮次**：
   - 读取最新 TODO 文档
   - 按本技能第四节的 lnd 加权规则选取 1~3 个 TODO 项
   - 对每项执行通用 SKILL Phase 1 的「A. 正向逻辑审查 / B. 逆向攻击思维 /
     C. 上下文关联审查」+ 本技能第四节强制的 4 类 LN 攻击场景
   - 按通用 SKILL Phase 2 更新 TODO 文档
3. **收尾轮**：当所有 P0/P1 完成或用户主动要求时，执行 Phase 3，按本技能第五
   节生成 7 + 3 = 10 节的完整报告。

> 提醒：本技能 **不修改 lnd 源码**，仅提供审计流程与维度。所有发现以审计报告
> 形式输出，由维护者决定是否落地为 PR / Issue。
