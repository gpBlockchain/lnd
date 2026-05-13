# lnd 安全审计报告 — 第二轮 (Round 2)

| 项 | 值 |
|---|---|
| 审计技能 | `.claude/skills/security-audit-lnd/SKILL.md` |
| 审计提交 SHA | `628f46a` (HEAD)（代码基线仍为 `18dfd54`，第二轮未做代码修改） |
| 审计日期 | 2026-05-13 |
| 上轮报告 | `audit-reports/2026-05-13-initial-audit.md` |
| 本轮聚焦 | 上轮 §11 列出的 4 个 P0 + 1 个 P1 TODO |

---

## 第 0 节: 阅读须知

- 本轮**仍是静态审计**，未跑 itest、未链上验证。
- 沿用第一轮的 6 等级信任边界与 15 维度框架（见 SKILL.md §三）。
- 本轮**新发现 1 个真实风险（依赖漏洞 R2-FIND-001）**，其余 4 项为 PASS（含 1 个设计性观察 O-05）。
- 本轮不修改任何源码；修复建议交由维护者评审后处理。

---

## 第 1 节: 本轮执行摘要

| ID | 维度 | 严重级 | 结论 |
|---|---|---|---|
| AUDIT-DEPS-001 | DEPS | 🔴 P0 | **FAIL — 发现 R2-FIND-001** (`google.golang.org/grpc v1.79.1` 受 GHSA `:path` 缺前导斜杠的授权绕过影响) |
| AUDIT-LN-HTLC-002 | DIM-LN-HTLC | 🔴 P0 | **PASS** — RevokeAndAck 缺失场景由 `pingTimeout=30s` + `MailboxDeliveryTimeout=60s` 兜底 |
| AUDIT-LN-HTLC-003 | DIM-LN-HTLC | 🔴 P0 | **PASS + 观察项 O-05** — 协议层 `max_accepted_htlcs ≤ 483` 严格生效；mailbox 内存层无显式 cap，但 1 分钟过期 + per-channel 隔离构成自然上限 |
| AUDIT-LN-CHAIN-002 | DIM-LN-CHAIN | 🔴 P0 | **PASS** — RBF compliant + `MaxFeeRate=1000 sat/vB` + budget 限速；pinning 风险在协议层尚不可彻底消除，但 lnd 的 anchor-CPFP 与 deadline-aware fee bumping 已对齐 v1.0 缓解方案 |
| AUDIT-LN-COMMIT-002 | DIM-LN-COMMIT | 🟠 P1 | **PASS** — MuSig2 session per-commit 重建；持久化分离 |

---

## 第 2 节: 详细发现

### R2-FIND-001 — google.golang.org/grpc 授权绕过 (🔴 P0/HIGH)

- **CVE/GHSA**: GitHub Advisory — "gRPC-Go has an authorization bypass via missing leading slash in `:path`"
- **受影响版本**: `< 1.79.3`
- **lnd 中的版本**: `google.golang.org/grpc v1.79.1` (`go.mod:61`)
- **修复版本**: `1.79.3` 或更新
- **触发条件**:
  - 攻击者直接构造一个 gRPC 请求，`:path` 伪头部省略前导斜杠（如发送 `lnrpc.Lightning/SendPayment` 而非 `/lnrpc.Lightning/SendPayment`）。
  - 在受漏洞影响版本中，gRPC-Go 内部的 path-based 授权拦截器对此匹配失败，但底层路由仍能定位到服务方法 — 导致**绕过基于 `FullMethod` 字符串的拦截器**。
- **对 lnd 的实际影响评估**:
  - lnd 的 macaroon 拦截器使用 `info.FullMethod`（`rpcperms/interceptor.go:646`、`L947`）做白名单与权限匹配。
  - 经过对 [`grpc-go` 源代码](https://github.com/grpc/grpc-go) 的调研，`FullMethod` 在内部由 gRPC 框架填充，**正常情况下** 始终带前导斜杠。
  - 该 GHSA 漏洞的实际利用面取决于 gRPC 框架内部对 `:path` 头与 `FullMethod` 派生的处理是否一致 — **无法仅通过 lnd 代码审计排除该路径**。
  - **结论**: 不能假定无影响；属于高优先级补丁。
- **修复建议**:
  - **首选**: 在 `go.mod` 中将 `google.golang.org/grpc` 升级到 `v1.79.3` 或更高（同时 `go.sum` 同步更新）。
  - **次选**（如版本升级被 ABI 约束阻塞）：在 lnd 自身 `rpcperms/interceptor.go` 的拦截器前置一条断言 `strings.HasPrefix(info.FullMethod, "/")`，否则直接 `codes.Unauthenticated` 拒绝。
  - 验证：执行 `go list -m -u all | grep grpc` 与 `go test ./rpcperms/...`。
- **建议提交方式**: 单独 PR，commit message 引用 GHSA 标识。
- **本报告不直接修改代码**：维护者复核后可创建独立 PR。

### AUDIT-LN-HTLC-002 — 对手不回 RevokeAndAck 的死锁 (PASS)

- **场景**: 对手节点收到我们的 `CommitSig` 后故意拖延或永远不发 `RevokeAndAck`。
- **防御链路**:
  1. `peer/brontide.go:67-71` — `pingTimeout = 30 * time.Second`：Ping/Pong 心跳 30 秒无响应即断开链路（`peer/brontide.go:816 TimeoutDuration: p.scaleTimeout(pingTimeout)`）。
  2. `htlcswitch/switch.go:45-47` — `DefaultMailboxDeliveryTimeout = time.Minute`：上游 HTLC 在 mailbox 中 1 分钟未投递成功即被 `FailAdd` 取消，防止上游被 hold。
  3. `htlcswitch/link.go:325` + `L4437 processRemoteRevokeAndAck` — 仅处理收到的 RAA，不阻塞发送侧；commitment chain 单调推进而不依赖对手 RAA。
  4. 断连后 channel reestablish (`htlcswitch/link.go:3921+`) 会重新协商 commit number，使我们能够要么重发，要么走 force-close 路径。
- **结论**: 死锁场景被 `pingTimeout(30s) + MailboxDeliveryTimeout(60s)` 双重兜底。**PASS**。
- **加固建议**（非必要）: 在 `link.go` 中增加显式的「peer 已 N 次 reestablish 失败 → 自动 force-close」的可配置阈值；当前依赖 `peer.scaleTimeout` 隐式处理。

### AUDIT-LN-HTLC-003 — max_accepted_htlcs 填满的 mailbox 行为 (PASS + O-05)

- **协议层硬上限**: `input/size.go:328`
  ```go
  MaxHTLCNumber = 966
  ```
  在 `lnwallet/reservation.go:992` 进一步限制 `MaxAcceptedHtlcs ≤ MaxHTLCNumber/2 = 483`（与 BOLT #2 spec 一致）。
- **运行时校验**: `lnwallet/channel.go:4052`
  ```go
  if numInFlight > constraints.MaxAcceptedHtlcs {
      return ErrMaxHTLCNumber
  }
  ```
  在每次 `validateUpdates` 时双侧校验，**拒绝额外的 UpdateAddHTLC 入站**。
- **mailbox 隔离层**: `htlcswitch/mailbox.go:580-623 AddPacket`
  - 每个对端 channel 都有独立 `memoryMailBox` 实例。
  - **无显式的队列长度上限**（无 `len(addPkts) >= N` 检查）。
  - 但每个 packet 有 `expiry: m.cfg.clock.Now().Add(m.cfg.expiry)`（默认 1 分钟），到期由 `FailAdd` 清理（`mailbox.go:684`）。
- **观察项 O-05**: mailbox 没有显式的最大长度限制。在以下极端情况：
  - 同一个攻击者控制 N 个上游通道，向同一目标 channel 的 mailbox 持续投递 packets。
  - 目标 channel 因下游对手方拒不响应而处于 stalled 状态。
  - 在 1 分钟过期前，addPkts 可堆积。
  - 单 packet 内存量级 ~几百字节，1 分钟内即使每秒 10000 个 packet 也只是 ~600MB 的内存压力 — 未达到 OOM 风险，但**可观测可放大**。
- **建议**: 在 `htlcswitch/mailbox.go::memoryMailBoxConfig` 中加入可配置的 `maxAddPkts`（默认 e.g. `MaxHTLCNumber * 10 = 9660`），并在 `AddPacket` 中 fast-fail。**非紧急加固**，不构成阻塞。
- **结论**: 协议层防御坚实；mailbox 仅在病态对手 + 极大量上游通道场景下可能成为放大点。**PASS**。

### AUDIT-LN-CHAIN-002 — Pinning 攻击与 anchor CPFP 实际可达 fee rate (PASS)

- **背景**: Pinning 攻击通过让对手锁定 mempool 中的低费 commitment tx，使受害方无法及时 RBF/CPFP 抢先广播 justice/HTLC sweep。
- **lnd 防御链路**:
  - `sweep/fee_bumper.go:482-543 createRBFCompliantTx` — 每次 RBF 都验证符合 BIP125 规则（更高 fee 且总费率覆盖被替换 tx）。
  - `sweep/fee_bumper.go:1162-1361 monitorRecord` — 监听新区块并按 deadline 重新计算 fee；deadline 越近，fee 单调上升至 `MaxFeeRate=1000 sat/vB`。
  - `sweep/fee_function.go:120-237 LinearFeeFunction` — 线性 fee 增长策略，保证在 deadline 之前最大化 fee 利用率。
  - `sweep/fee_bumper.go:680-720 handleMissingInputs` — 当输入被对手抢先花掉时（典型 pinning 结局），lnd 切换到 `TxUnknownSpend` 流程并触发 channel 强制关闭路径。
  - Anchor channel 的对称 anchor output（commitment 两端各 330 sat 锚点）允许任一方独立 CPFP — 不依赖对手合作。
- **当前协议层局限**:
  - BOLT/Bitcoin 协议本身对 mempool replacement 不完美（替代 transaction discovery 仍是 best-effort）。
  - lnd 已经达到 spec v1.0 提供的最强缓解：anchor + RBF + deadline-aware budgeting。
  - 进一步缓解依赖 v3 transaction relay (BIP 431) — 这是 Bitcoin Core 与 BOLT 仍在演进的方向。
- **结论**: **PASS**。lnd 在当前 BOLT spec 范围内已实施最佳缓解。该项标 PASS 不代表 pinning 风险消失，只代表「lnd 没有遗留可立刻修复的实现层缺陷」。
- **后续跟踪**: 关注 `lightning-onion` 与 BOLT 仓库的 v3-transaction 相关 PR；待 Bitcoin Core 默认启用 v3 后回归此项。

### AUDIT-LN-COMMIT-002 — panic-recovery 下 MuSig2 session 完整性 (PASS)

- **代码**: `lnwallet/musig_session.go` + `lnwallet/channel.go::SignNextCommitment`
- **关键属性**:
  - 每次 SignNextCommitment 通过 `musig2.GenerateNonces` 生成新 nonce（基于 `rand.Reader` + secret key 派生）。
  - Session 对象**未持久化到 channeldb**（仅持久化签名结果与 commit pointer）。
  - 进程崩溃 → 重启后调用 `LoadChannel` → state machine 从 commit chain 重建 → 重新发起新 MuSig2 session（新 nonce）。
- **风险评估**:
  - 不存在 nonce 重用风险：每次 session 用完即抛弃，崩溃后**强制**生成新 nonce。
  - 不存在 partial-sig 泄漏：partial-sig 仅在 commit-chain 完整存在的前提下 broadcast，且 partial-sig + 对端 partial-sig 才能拼出完整签名。
- **结论**: **PASS**。上轮报告 O-01 标注的「测试覆盖不足」仍有效，但代码层无缺陷。

---

## 第 3 节: 修复优先级建议

| ID | 类型 | 优先级 | 建议 |
|---|---|---|---|
| **R2-FIND-001** | 依赖升级 | **🔴 P0** | 升级 `google.golang.org/grpc` 到 `v1.79.3+` |
| O-05 | 加固 (DoS 防护) | 🟢 P3 | 在 `memoryMailBoxConfig` 加 `maxAddPkts` 选项 |

---

## 第 4 节: 上轮 TODO 清结表

| 上轮 TODO ID | 本轮状态 | 备注 |
|---|---|---|
| AUDIT-LN-HTLC-002 | ✅ 完成 — PASS | 见 §2 |
| AUDIT-LN-HTLC-003 | ✅ 完成 — PASS + O-05 | 见 §2 |
| AUDIT-LN-CHAIN-002 | ✅ 完成 — PASS | 见 §2 |
| AUDIT-LN-WIRE-002 (Blinded path fuzz) | ⏸ 推迟 | 非阻塞，留下轮 |
| AUDIT-DEPS-001 | ✅ 完成 — **FAIL/FIND** | 见 §2 R2-FIND-001 |
| AUDIT-LN-COMMIT-002 | ✅ 完成 — PASS | 见 §2 |
| AUDIT-SERDE-002 (cross-backend migration) | ⏸ 推迟 | 需运行时环境 |
| AUDIT-DOC-001 (kvdb backend doc) | ⏸ 推迟 | 文档任务 |

---

## 第 5 节: 下一轮 TODO

- [ ] 🔴 **R2-FOLLOWUP-001**: 验证 grpc 升级到 v1.79.3 不破坏现有 RPC 行为（`go test ./rpcperms/... ./lnrpc/...`）
- [ ] 🟠 **AUDIT-LN-WIRE-002**: 补全 Blinded Path / peer_storage TLV Fuzz（结转）
- [ ] 🟠 **AUDIT-LN-HTLC-004**: 在 mailbox 增加 `maxAddPkts` 后回归 DoS 场景（O-05 跟进）
- [ ] 🟢 **AUDIT-SERDE-002**: 跨 backend channeldb migration 矩阵（结转）
- [ ] 🟢 **AUDIT-DOC-001**: kvdb 后端事务语义文档化（结转）
- [ ] 🟢 **AUDIT-LN-CHAIN-003**: 跟踪 BIP 431 v3 transaction 相关 PR，回归 pinning 风险

---

## 第 6 节: 全部依赖项漏洞扫描结果

按 SKILL §六 严禁臆造，全部结果来自 `gh-advisory-database` 工具实际查询：

### 已扫描且 PASS

| 包 | 版本 | 结果 |
|---|---|---|
| `github.com/btcsuite/btcd` | 0.25.1 | ✅ 无漏洞 |
| `github.com/btcsuite/btcd/btcec/v2` | 2.3.6 | ✅ |
| `github.com/btcsuite/btcd/btcutil` | 1.1.6 | ✅ |
| `github.com/btcsuite/btcwallet` | 0.16.17 | ✅ |
| `github.com/decred/dcrd/dcrec/secp256k1/v4` | 4.4.0 | ✅ |
| `github.com/lightninglabs/neutrino` | 0.16.2 | ✅ |
| `github.com/lightningnetwork/lightning-onion` | 1.3.0 | ✅ |
| `github.com/jackc/pgx/v4` | 4.18.3 | ✅ |
| `github.com/grpc-ecosystem/grpc-gateway/v2` | 2.16.0 | ✅ |
| `github.com/gorilla/websocket` | 1.5.0 | ✅ |
| `golang.org/x/net` | 0.48.0 | ✅ |
| `golang.org/x/crypto` | 0.46.0 | ✅ |
| `github.com/miekg/dns` | 1.1.43 | ✅ |
| `github.com/prometheus/client_golang` | 1.11.1 | ✅ |
| `google.golang.org/protobuf` | 1.36.10 | ✅ |
| `github.com/urfave/cli` | 1.22.9 | ✅ |
| `github.com/klauspost/compress` | 1.17.9 | ✅ |
| `github.com/grpc-ecosystem/go-grpc-middleware` | 1.3.0 | ✅ |
| `golang.org/x/sync` | 0.19.0 | ✅ |

### FAIL

| 包 | 当前版本 | 漏洞 | 修复版本 |
|---|---|---|---|
| **`google.golang.org/grpc`** | **1.79.1** | **`:path` 缺前导斜杠导致授权绕过** | **1.79.3+** |

### 未扫描 (本轮范围外)

`go.mod` 还有约 50 个间接依赖未扫描；建议在下一轮使用 `go list -m -json all` 全量提取后批量送 `gh-advisory-database`。

---

## 第 7 节: 结论

第二轮审计 **发现 1 个真实安全风险（R2-FIND-001 — 依赖漏洞）**，其余 4 个 P0/P1 审计项 PASS。

**强烈建议**维护者尽快单独提 PR 将 `google.golang.org/grpc` 升级到 `v1.79.3` 或更高版本。该升级即使在最坏情况下（即 lnd 自身代码不直接受影响）也属于纵深防御的标准做法。

其他 4 项 PASS 表明：在 HTLC 死锁、HTLC 资源耗尽、pinning 攻击、MuSig2 panic recovery 等高风险方向上，lnd 的现有防御链路完整、与 BOLT spec v1.0 对齐。

— **End of Round 2 Report** —
