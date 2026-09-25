# Admission 运维

[English](./admission.md) | [中文](./admission.zh-CN.md)

Admission 用于保护一个 Antigravity 账号，避免多 agent Paseo 委派形成 prompt
突发。它是围绕官方内核 `session/prompt` 写入的持久、账号级 fence，不替代 Paseo
调度或官方 ACP session 生命周期。

## 平台支持与默认行为

Admission 支持 Linux，以及 macOS `arm64` 和 `x64` 主机。Admission 默认保持禁用；
只有需要账号级排队、共享席位、启动恢复与 runtime reaper 时，才把
`AGY_ACP_ADMISSION_ENABLED` 设为 `true` 或 `1`。不启用 Admission 只适合明确隔离的
单 agent。

其他操作系统不支持启用 Admission。它们会 fail closed，不会在缺少已配置队列保证时
写入官方内核 prompt。Claude 与 GPT-OSS 的仅限 Linux 官方内核兼容生命周期不属于
macOS Admission 支持。

## 何时启用

同一主机上，多个 Paseo agent 并发使用同一 Antigravity 账号时启用 Admission。
同一账号的所有 connector 进程必须使用相同的 `AGY_ACP_STATE_DIR` 与 policy。
不同账号必须使用不同的账号状态根。

## 准备全新的账号状态根

每个 Antigravity 账号都选择一个未使用的新状态根：

```bash
export AGY_ACP_STATE_DIR="$HOME/.local/state/paseo-agy-acp/account-name"
install -d -m 700 "$AGY_ACP_STATE_DIR"
npx -y --package=paseo-agy-acp@2.3.2 \
  agy-acp-prepare-state "$AGY_ACP_STATE_DIR"
export AGY_ACP_ADMISSION_ENABLED=true
```

预检只创建或验证账号状态根。它要求路径为绝对路径、由当前用户拥有，并具有
精确 `0700` 权限；已有目录权限过宽时会拒绝，而不是静默修改。启用 Admission
首次打开该状态根时，才会创建嵌套 ledger 目录，目录权限为 `0700`；其中的新
owner-only 状态文件使用 `0600` 权限。

内部嵌套 `official-kernel` ledger 位于 `$AGY_ACP_STATE_DIR/official-kernel`。
请配置账号状态根，不要直接配置嵌套目录。Admission state 属于宿主机本地且绑定平台：
不要在机器之间、Linux 与 macOS 之间或 macOS 与 Linux 之间复制正在使用或已有的
ledger。更换 policy 或平台时保留旧状态根。

## 检查 owner 与权限

在 Linux 上检查账号状态根：

```bash
stat -c '%U %a %n' "$AGY_ACP_STATE_DIR"
```

在 macOS 上使用：

```bash
stat -f '%Su %Lp %N' "$AGY_ACP_STATE_DIR"
```

路径必须为绝对路径，owner 必须与 connector 用户一致，mode 必须为 `700`。
确认它是目标账号状态根后，修复 owner 或 mode，并重新运行预检：

```bash
sudo chown "$(id -un)" "$AGY_ACP_STATE_DIR"
chmod 700 "$AGY_ACP_STATE_DIR"
npx -y --package=paseo-agy-acp@2.3.2 \
  agy-acp-prepare-state "$AGY_ACP_STATE_DIR"
```

确认账号与路径之前，不要递归修改 owner 或权限。

## 必需 runtime identity

启用状态下的 connector 需要：

- `AGY_ACP_ADMISSION_ENABLED=true` 或 `1`；
- 已准备好的绝对路径 `AGY_ACP_STATE_DIR`；
- Paseo 提供的有效 `PASEO_AGENT_ID`；
- 受支持的证据平台，以及 macOS 上与主机匹配且健康的 native artifact。

缺失或格式错误的启用配置会 fail closed。在 Paseo 提供 `PASEO_AGENT_ID` 之前，
provider Discovery 不会打开 Admission ledger，也不会加载 process evidence。
`--login` 不会初始化 Admission 或创建嵌套 ledger；官方 OAuth state 仍由官方
内核拥有。

## Policy 默认值

| 行为 | 默认值 | 环境变量覆盖 |
|---|---:|---|
| 共享 active turns | `8` | `AGY_ACP_ADMISSION_MAX_ACTIVE_TURNS`，integer >= 1 |
| 同时启动数 | `8` | `AGY_ACP_ADMISSION_MAX_CONCURRENT_STARTS`，integer >= 1 |
| 最小启动间隔 | `2000 ms` | `AGY_ACP_ADMISSION_MIN_START_INTERVAL_MS`，integer >= 2000 |
| 最大排队时间 | `1800000 ms` | `AGY_ACP_ADMISSION_QUEUE_TIMEOUT_MS`，integer 1-1800000 |
| Provider/model capacity cooldown | `30000 ms` | `AGY_ACP_ADMISSION_CAPACITY_COOLDOWN_MS`，integer >= 30000 |

这些是经过测试的运行默认值，不是 Google 并发上限声明。只有基于账号观察后才应提高
它们，并保留最小启动间隔。非法覆盖会让已启用的 connector 在可能 unfenced 运行前
停止。

## 运行行为

1. Prompt 在写入官方内核前申请账号席位。
2. Eligible 请求按 oldest-first 与 agent fairness 调度。
3. Start gate 执行同时启动数与间隔 policy。
4. Connector 执行一次受 fence 保护的 `session/prompt` 写入。
5. 完成、失败或取消时释放席位。

Idle session 不占席位。关闭 session 会取消尚未开始的排队工作。运行中的工作使用
connector 的正常取消路径。排队超时会在同一事务中删除请求及其受保护 payload。

可信 provider-capacity 故障只按配置 cooldown 暂停对应的 provider/model。
Authentication、permission、transport、timeout 与其他故障保持独立分类。

## 持久化与恢复

Policy、queued ownership、lease 与 recovery state 保存在宿主机本地且绑定平台的
嵌套 ledger 中，使同一主机上的独立 connector 进程共享一个账号池。Startup recovery
与 runtime reaper 使用同一个选定的 process-evidence adapter；只有验证 connector、
child、process group、descendant 与 PID reuse 证据后，才会回收本机容量。

Heartbeat 过期只表示怀疑。缺失、损坏、不可访问、不完整或不确定的证据属于
`unverifiable`，必须保留本机席位。不要通过删除或编辑状态目录强行启动。只有停止
该账号的全部 connector 后，才能备份或检查它。

## Native artifact 选择与源码构建回退

Darwin loader 根据实际 Node runtime 平台与架构选择，不猜测 Mac 型号。用以下命令
检查 runtime target：

```bash
node -p '`${process.platform}/${process.arch}`'
```

| Runtime target | 选中的 evidence 实现 |
|---|---|
| `darwin/arm64` | `prebuilds/darwin-arm64/darwin_process_evidence.node` |
| `darwin/x64` | `prebuilds/darwin-x64/darwin_process_evidence.node` |
| `linux/*` | Linux procfs evidence；不加载 Darwin prebuild |

因此，Rosetta 下的 x64 Node 进程需要审核过的 x64 prebuild。缺失、不可读、无效或
架构不匹配的 artifact 会产生可操作的启动错误。记录 expected platform、actual
platform、expected architecture、actual architecture 与尝试加载的 artifact 路径，
然后在受支持主机上重新安装同一固定版本。不要从其他架构复制 artifact。

源码构建回退用于安装 Xcode Command Line Tools 的源码 checkout，不是安装包的自动
修复方式：

```bash
npm run build:native
npm run test:native:source
```

源码构建写入 `build/Release/`，并与安装包 prebuild 消费测试分开验证。贡献者可用它
在本机复现 native process-evidence contract；操作者应重新安装与主机匹配的审核
package，而不是发布或复制本机构建的 artifact。

## 更换 policy

打开同一状态目录的进程必须与持久 policy 一致。冲突 policy 会 fail closed，不会形成
进程本地的分裂状态。

有意更换 policy 时：

1. 停止使用该账号的全部 connector；
2. 记录旧环境与状态路径；
3. 选择新的 owner-only `AGY_ACP_STATE_DIR`；
4. 为新目录运行 `agy-acp-prepare-state`；
5. 启动一个 connector 并验证简单 turn；
6. 恢复正常多 agent 委派。

新 policy 通过实际验证前，保留旧目录。把 provider environment 切回旧路径就是
rollback。

## 安全故障排查

检查持久状态前，停止受影响账号的新 dispatch。保留账号状态根，只收集脱敏错误、
runtime target、policy 值、owner 名称与进程状态。issue 中绝不能包含 prompt
payload、credential、OAuth state 或加密数据库内容。

### Connector 拒绝启动

检查配置路径、runtime target 与传入的 agent identity：

```bash
printf '%s\n' "$AGY_ACP_STATE_DIR"
node -p '`${process.platform}/${process.arch}`'
printf '%s\n' "$PASEO_AGENT_ID"
```

然后使用准备章节中的 Linux 或 macOS owner 检查命令。路径必须为绝对路径，owner
必须与 connector 用户一致，mode 必须为 `700`，所有数值 policy 必须符合 policy
表。

### Policy mismatch

停止使用该账号的全部 connector，并确认它们的 Admission environment 完全相同。
Policy mismatch 表示同一本地 ledger 使用了不同的规范化 policy。保留旧 ledger；
不要覆盖 fingerprint。有意迁移时，准备一个全新的账号状态根，启动一个 connector，
验证简单 turn，再恢复正常 dispatch。

### Platform mismatch 或不支持的操作系统

Platform mismatch 表示在 macOS 打开 Linux state，或在 Linux 打开 macOS state。
不支持的操作系统在显式启用 Admission 时也必须 fail closed。不要编辑持久化的
platform tag 或 evidence JSON。只有明确隔离的单 agent 才可在不支持平台上继续保持
unfenced；否则应在受支持主机上用全新本地账号状态根迁移。

### 损坏或无法验证的证据

损坏的持久证据或带 platform tag 的 JSON 损坏会在启动时 fail closed；保留 ledger
供诊断，不要手工替换记录。不可访问或不完整的实时进程证据属于 `unverifiable`：
保留本机席位，稍后重试观察。绝不能把 `ps` 输出、PID 是否存在或 timeout 当成
进程或 turn 已退出的证明。

### 工作持续排队

检查 active agent、queue timeout、配置席位、启动间隔、owner liveness 与最近的
provider-capacity 故障。在认证、配额、native evidence 与官方内核健康状态明确前，
不要提高限制。

### Recovery 状态

#### queued-owner 取消

如果 dispatch 前已证明 connector owner 消失，或其 PID 已被复用，startup recovery
或 runtime reaper 会把排队请求改为 `cancelled`，并删除受保护 payload。此时没有发生
业务 prompt 写入，请求也不占席位。

#### `recovery_required`

如果 delivery 或本地进程状态不确定，请求会保持可见的 `recovery_required`。
它不会被报告为 provider 成功、已知 provider 失败或已完成 turn。

#### 本机席位释放

只有 connector 与 child 已证明消失或其 PID 已证明复用，并且预期 process group
可验证为空时，才会释放本机席位。请求仍保持 `recovery_required`；本机资源协调不
声称已获知远端 provider 结果。

#### 永不重放保证

Delivery 不确定后，Admission 绝不重放原业务 prompt。`recovery_required` 没有
manual requeue 或第二次 delivery 路径。如果操作者有意重新开始，应提交新的用户请求；
不要编辑 SQLite 或复用内部 recovery state 作为重放机制。

## 安全边界

Admission state 可能包含加密的排队 prompt material 与进程身份证据。保持目录
owner-only，绝不能提交到仓库，也不能放入 npm package。Repository secret scan 与
package-content check 会拒绝 release tarball 中的数据库与运行状态 artifact。
