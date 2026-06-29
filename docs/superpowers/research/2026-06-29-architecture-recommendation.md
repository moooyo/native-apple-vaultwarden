# 推荐架构

本文档为 native Swift iOS+macOS 的 Vaultwarden-compatible client 给出**最终推荐架构**。结论：以 **VaultKit（security & AutoFill-first，总分 34/40）** 作为 base proposal，因为它在两项决定项目成败的硬约束上拿到满分——**AutoFill ~120MB memory safety & key isolation（5/5）** 与 **offline/sync robustness without push（5/5）**——这正是 self-hosted Vaultwarden + 纯 Swift crypto 场景下最难、最不可妥协的两条 locked decision；同时它的 **crypto-correctness（4/5）** 与 **evolvability（4/5）** 也领先。VaultKit 唯一被扣分的不是设计缺陷，而是工程量（M1 要点亮 ~13 个 target、test plan 只是声明未具化），这两点可以靠**嫁接（graft）**解决：

- 从 **Glasshouse（30/40，UI fidelity 满分 5/5）** 嫁接其 **per-platform 双 view tree（`UI-iOS` / `UI-mac` + 共享 `UIShared` @Observable VM）**，把 VaultKit 偏弱（被评 "UX 是断言而非设计"）的 UI 层换成 Glasshouse 已经设计好的具体屏幕与 Liquid Glass 用法，直接补齐 native-UX fidelity 这一维。
- 从 **Glasswarden（28/40，testability 满分 5/5、milestone fit 4/5）** 嫁接其 **务实的 M1 收敛节奏**（先共享一套 `UIShared` 跑通，Mac 专属打磨延后），用来对冲 VaultKit "13 target 一次性点亮" 的 M1 过重风险——做法是：M1 用 VaultKit 的安全骨架 + Glasswarden 式精简 UI 先 ship，M2 再展开 Glasshouse 的 Mac 三栏/inspector/MenuBarExtra 全套。

一句话 thesis：**安全骨架（CryptoCore / KeyVault / KeychainBridge / VaultReader）按 VaultKit 的 least-privilege 切分一次写死、一次审计；UI 按 Glasshouse 的 per-OS 双 tree 做到真正 native；M1 按 Glasswarden 的节奏先收敛再展开。** 安全是 base，UI fidelity 与交付节奏是 graft。

---

## 方案对比

| 方案 | Lens（视角） | 总分 | 关键优势 | 关键劣势 | 裁决 |
|---|---|---|---|---|---|
| **VaultKit**（base） | security & AutoFill-extension-first | **34** | AutoFill 隔离 best-in-class（extension 只链 `VaultReader`+`KeychainBridge`+`Models`+`DesignSystem`，单条目解密，UserKey 仅 SE-ECIES-wrap 跨进程）；no-push sync 与 self-hosted 现实完全吻合；crypto 字节级正确（PKCS#7-unpad-before-HMAC、HKDF enc/mac、type-2 vs RSA type-4） | M1 需点亮 ~13 个 target，DI/facade/DTO 脚手架前期重；test plan 只声明未具化；UX 路线正确但未设计成具体屏幕 | 安全主导、设计稳健，AutoFill 隔离与 no-push sync 双满分。主要风险是 M1 脚手架重量与测试计划缺细节，**采为 base** |
| **Glasshouse** | platform-native polish（每个 OS 最佳 Liquid Glass） | 30 | 每个 OS 真正 native：iOS TabView+floating `.glassProminent`+minimizing tab bar，macOS 三栏 split+`.inspector`+`MenuBarExtra`；glass 只上 chrome、敏感字段绝不上 clear glass、honor Reduce Transparency | 两套 SwiftUI view tree 让 UI build/QA 翻倍、易行为漂移；Argon2id >64MiB extension OOM 只有 "warn/cap" 未解决；crypto-v2/type-7 只能降级未架构化 | 在干净可测的 Core 上把 native 打磨拉满，但双 UI 成本与未解的 Argon2id OOM 是主要负担。**嫁接其双 UI tree 与具体屏幕设计** |
| **Glasswarden** | maximize code-sharing & delivery velocity | 28 | 单一共享 `VaultUI` 复用最大、M1 最快；testability 满分（UI-free 包 + protocol DI + actor-isolated sync）；crypto 字节级准确；自知之明地披露 tradeoff | 共享 VaultUI 直塞进 extension 与 ~120MB 预算正面冲突（缓解措施空泛、无强制 UI-slice 边界）；macOS 自承 Catalyst-ish，与 full parity 目标矛盾；monolithic VaultUI 是 M3 编译/合并瓶颈 | Core/test/sync 故事强，但 shared-VaultUI-in-extension 与 macOS parity gap 是真实负债。**嫁接其 M1 收敛节奏，但拒绝其 extension 链 UI 的做法** |

---

## 模块与 target 分解

整体分四层（依赖只能从上往下，UI/App 层不得反向被 Core 依赖）。安全敏感代码全部下沉到 **L0 Spine + L1 Security**，UI 与 Networking 永远不触碰 raw key bytes。

```
┌──────────────────────────────────────────────────────────────────────────┐
│ L4  App targets                                                            │
│     App-iOS · App-macOS · AutoFillExtension                               │
├──────────────────────────────────────────────────────────────────────────┤
│ L3  UI                                                                     │
│     UI-iOS · UI-mac   ←(共享)←  UIShared(@Observable VMs) · DesignSystem  │
├──────────────────────────────────────────────────────────────────────────┤
│ L2  App-side services (主 App 专属，extension 绝不链)                       │
│     Networking · SyncEngine · Generators · VaultRepository · AppShared    │
├──────────────────────────────────────────────────────────────────────────┤
│ L1  Security & data                                                        │
│     KeyVault · KeychainBridge · VaultStore · VaultReader · Fido2          │
├──────────────────────────────────────────────────────────────────────────┤
│ L0  Spine                                                                  │
│     CryptoCore · VaultModels                                               │
└──────────────────────────────────────────────────────────────────────────┘
```

**关键架构红线**：AutoFill extension 只允许链 `VaultReader + KeychainBridge + VaultModels + Fido2 + DesignSystem + AppShared`（外加它们的传递依赖 `CryptoCore`/`KeyVault`/`VaultStore`）。它**绝不**链 `Networking`、`SyncEngine`、`Generators`、`VaultRepository`、`UIShared`、`UI-iOS`、`UI-mac`。这是 VaultKit 拿满分的核心，也是对 Glasswarden 失分点（共享 UI 塞进 extension）的明确拒绝。

### L0 — Spine

| Target | Kind | 职责 | 依赖 |
|---|---|---|---|
| **CryptoCore** | SwiftPackage（无 UIKit/AppKit/SwiftUI/Foundation-networking） | 唯一持有 key bytes 的模块。EncString parser（type 0/1/2 sym、type 3-6 RSA、type 7 gated soft-fail）、KDF（PBKDF2 / Argon2id via 审计过的 libsodium 绑定）、HKDF-Expand 拉伸、AES-256-CBC + HMAC-SHA256、RSA-OAEP（Security `SecKey`）、PKCS#7、`SecureBytes` 归零缓冲 | — |
| **VaultModels** | SwiftPackage | Sendable 的 wire + domain Codable 模型：Cipher / Login / Card / Identity / SecureNote / SshKey / Fido2Credential / Folder / Collection / Organization / Send / Attachment / Profile / KdfConfig / SyncResponse DTO。casing 容错（VW camelCase vs official PascalCase） | CryptoCore |

### L1 — Security & data

| Target | Kind | 职责 | 依赖 |
|---|---|---|---|
| **KeyVault** | SwiftPackage（actor） | 内存中 key hierarchy 持有者。持 unwrapped UserKey(64B)、per-cipher/org/RSA 私钥；vend 短生命周期 decryptor；lock/超时时归零。**绝不持久化 key** | CryptoCore |
| **KeychainBridge** | SwiftPackage | SE P-256 keygen、UserKey 的 ECIES-wrap、biometry-gated shared-access-group Keychain I/O、`LAContext` 解锁。**跨进程 key 传输的唯一通道** | CryptoCore |
| **VaultStore** | SwiftPackage | GRDB+SQLCipher，App Group 容器。cipher/folder/collection 存为 encrypted blob + plaintext metadata + 本地搜索索引；`cipher_plaintext_header_size=32`、self-managed salt、WAL+`NSFileCoordinator`。DB key 取自 Keychain | CryptoCore, VaultModels |
| **VaultReader** | SwiftPackage | **extension 专用 least-privilege 读 facade**：query credential identities、解密**单个**选中 cipher/passkey、build `authenticatorData`。无 sync、无 network、无 bulk decrypt | CryptoCore, KeyVault, KeychainBridge, VaultStore, VaultModels |
| **Fido2** | SwiftPackage | 软件 WebAuthn authenticator：`authenticatorData` 构建、assertion/registration 签名、none-attestation CBOR、COSE alg 映射、P-256 keypair 生成 | CryptoCore, VaultModels |

### L2 — App-side services（主 App 专属）

| Target | Kind | 职责 | 依赖 |
|---|---|---|---|
| **Networking** | SwiftPackage | URLSession async/await client：prelogin、connect/token（password / refresh / 2FA challenge）、`/api/sync`、cipher/folder/collection CRUD、attachment v2、sends；custom server URL；Device-Type / Bitwarden-Client-* headers 注入 | VaultModels |
| **SyncEngine** | SwiftPackage（actor） | revision-token 增量 sync、conflict resolution（skip-write-when-server-newer + outbound 队列优先）、`ASCredentialIdentityStore` 重建、`BGAppRefreshTask`/`NSBackgroundActivityScheduler` 调度。soft-fail 未知 EncString | CryptoCore, KeyVault, VaultStore, VaultModels, Networking |
| **Generators** | SwiftPackage | password/passphrase/username 生成、passkey keypair（P-256）、TOTP（RFC 6238） | CryptoCore, VaultModels, Fido2 |
| **VaultRepository** | SwiftPackage | App-facing CRUD/unlock/lock 编排（store+sync+keyvault）；`AuthRepository`（login/2FA/refresh）；`ServiceContainer` + `Has<Service>` DI | KeyVault, KeychainBridge, VaultStore, VaultModels, Networking, SyncEngine |
| **AppShared** | SwiftPackage | 跨 target 胶水：App Group ID、Keychain access-group 常量、auto-lock 策略、device metadata（deviceType/identifier/name）、日志脱敏 | — |

### L3 — UI（嫁接 Glasshouse 的双 tree）

| Target | Kind | 职责 | 依赖 |
|---|---|---|---|
| **DesignSystem** | SwiftPackage | Liquid Glass tokens、`GlassScrim`、`ConcentricRectangle` 卡片、OTP 环、`SecureRevealView`（敏感字段绝不上 clear glass）、Reduce-Transparency/Increased-Contrast 感知的 opaque fallback（`.regular`→`.identity`） | VaultModels |
| **UIShared** | SwiftPackage | 双 App 共用的 `@Observable` view model + flow：`UnlockModel`、`VaultListModel`、`ItemDetailModel`、`GeneratorModel`、`SyncStatusModel`。仅逻辑，无 layout | VaultRepository, Generators, DesignSystem |
| **UI-iOS** | SwiftPackage | iOS 定制 SwiftUI：`TabView`、bottom `searchable`、`tabViewBottomAccessory`、floating `.glassProminent` "+"、swipe actions | UIShared |
| **UI-mac** | SwiftPackage | macOS 定制 SwiftUI：三栏 `NavigationSplitView`、`.inspector`、`.backgroundExtensionEffect()` hero、`ToolbarSpacer` 胶囊、`MenuBarExtra` scene | UIShared |

### L4 — App targets

| Target | Kind | 职责 | 依赖 |
|---|---|---|---|
| **App-iOS** | App target | 薄壳：`@main`、scene lifecycle、`BGAppRefreshTask` 注册、background/超时 auto-lock 观察者、entitlements（App Group / Keychain group / AutoFill / Passkeys） | UI-iOS, VaultRepository, AppShared |
| **App-macOS** | App target | 薄壳：`@main`、`MenuBarExtra` quick-unlock、`NSBackgroundActivityScheduler`、window/inspector 恢复、同套 entitlements | UI-mac, VaultRepository, AppShared |
| **AutoFillExtension** | Extension（`ASCredentialProviderViewController`，双平台） | password/OTP provider + 软件 WebAuthn。silent 路径 `cancelRequest(userInteractionRequired)`；biometric unlock UI；**只解密选中条目**；buffer 在 `completeRequest` 后释放 | **VaultReader, KeychainBridge, VaultModels, Fido2, DesignSystem, AppShared**（不链 L2/L3 任何重模块） |

---

## UI 策略（iOS vs macOS）

Baseline 锁定 **iOS 26.0 / macOS 26.0**，几乎无需 `#available` 分支；标准控件在 Xcode 26 SDK 下重编译即自动获得 Liquid Glass material。采用 **Glasshouse 的 per-OS 双 view tree** —— `UIShared` 持有所有 `@Observable` VM（逻辑只写一次），`UI-iOS`/`UI-mac` 仅做 layout/navigation，确保两套 tree 很薄、避免行为漂移。

**全局 glass 红线（locked decision）**：`.glassEffect()` 只用于真正自定义的 chrome；list rows 与 detail 主体保持 opaque（content layer）；`SecureRevealView` 把 password/TOTP/card number/passkey 渲染在 `.regular` material 或纯色 scrim 上，**绝不 clear glass**；所有自定义 glass 在 `accessibilityReduceTransparency` / `differentiateWithoutColor` / `reduceMotion` 下切到 `.identity`/opaque。

### iOS（`UI-iOS`）

- **导航模型**：`TabView`（Vault / Generator / Send / Settings），用 `Tab(role: .search)` + bottom `searchable`。
- **列表**：opaque `List` rows（content layer），条目用 `ConcentricRectangle` 卡片。
- **floating action**：右下 `.buttonStyle(.glassProminent)` 的 "+"，多个浮动按钮包进 `GlassEffectContainer` + `.glassEffectID`。
- **tab bar**：`.tabBarMinimizeBehavior(.onScrollDown)`，配 `.tabViewBottomAccessory` 放 unlock/sync 状态 pill；`.scrollEdgeEffectStyle` 让 rows 在 glass bar 下淡出仍可读。

### macOS（`UI-mac`）

- **导航模型**：三栏 `NavigationSplitView`（categories/folders 侧栏 | item list | detail）。
- **inspector**：`.inspector(isPresented:)` 放 metadata / password history。
- **detail hero**：`.backgroundExtensionEffect()`。
- **toolbar**：用 `ToolbarSpacer` 把工具栏拆成 glass 胶囊组。
- **MenuBarExtra**：独立 `MenuBarExtra` scene 做 quick unlock / search / copy，无需打开主窗口。

### M1 节奏（嫁接 Glasswarden 的收敛）

为对冲 VaultKit "双 UI tree 让 M1 过重" 的风险：**M1 先让 `UIShared` + `UI-iOS` 跑通全部核心屏幕**，macOS 在 M1 用最小可用三栏壳（复用 `UIShared` VM），把 `.inspector` 深度、`MenuBarExtra` 全功能、`ToolbarSpacer` 胶囊化、`backgroundExtensionEffect` 等 Mac 专属打磨**放到 M2**。这样 M1 交付一个打磨过的 iOS App + 一个可用的 macOS App，M2 再补齐 full native parity。

---

## 加密与密钥管理

### 内存中 key hierarchy（KeyVault actor，全程 `SecureBytes`）

```
MasterPassword + salt(prelogin-driven KDF)
        │  PBKDF2 或 Argon2id  →  MasterKey(32B)
        ▼
HKDF-Expand("enc")  +  HKDF-Expand("mac")  →  StretchedMasterKey(64B)
        │  解密 Key EncString（先 HMAC 常量时间校验，再解）
        ▼
UserKey(64B)  ──┬──→ per-cipher Cipher Key（PKCS#7 unpad 后才用作 HMAC key）
                ├──→ RSA-2048 私钥（type-4 EncString）→ org keys
                └──→ attachment keys
```

只有 UserKey 与按需派生的 material 常驻内存；lock/background/超时即归零。

### Unlock flow

1. `POST /identity/accounts/prelogin` 取服务器驱动的 KDF 参数（**永不硬编码**）。PBKDF2 salt = `trim+lowercase(email)` 原文；Argon2id salt = `SHA-256(trim+lowercase email)` 32B。
2. 派生 MasterKey → HKDF 拉伸 → 解密 token 响应里的 `Key`（protected user key）得 UserKey。
3. 服务器认证 hash = `B64(PBKDF2(MasterKey, salt=MasterPassword, iters=1))`，作为 OAuth `password` 字段发送（**不是** `masterPasswordHash` key）。
4. 本地离线校验 hash（PBKDF2 iters=2）持久化，供离线解锁验证。

### Secure Enclave + Keychain access group（biometric unlock）

- 一把 SE P-256 key（`.privateKeyUsage` + `.biometryCurrentSet`）对 UserKey 做 **ECIES-wrap**。
- 密文存入 **shared Keychain access group**，属性 `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`（更严：要求设备已设密码且不随备份迁移）。
- 主 App 与 extension 通过同一 access group 读取；解锁时用 `LAContext` / `kSecUseAuthenticationContext`，Face ID/Touch ID 直接返回 wrapped key，**无需 master password、明文 UserKey 绝不跨进程**。

### Extension 如何在 ~120MB 预算内解锁（VaultKit 的满分点）

- extension 只链 `VaultReader + KeychainBridge`，**不链** Networking/SyncEngine/Generators/UIShared —— link graph 最小，启动内存最低。
- silent 路径直接 `cancelRequest(.userInteractionRequired)`，进入 UI 才走 biometric → 经 `LAContext` 拿回 ECIES-wrapped UserKey → 解 wrap。
- **只解密当前选中的那一个 cipher/passkey**，绝不 bulk decrypt 整库；attachment 流式处理；`completeRequest` 后立即释放 buffer。
- **Argon2id 显式封顶**：AutoFill-critical 场景下 prelogin 若返回 `kdfMemory > 64MiB` 给出告警/降级提示——这是 Apple 不给保证数值的现实下，避免 silent OOM 的必要妥协（在文档与设置中向用户说明）。

---

## 同步引擎

### Actor model

`SyncEngine` 是 Swift 6 `actor`，独占所有可变 sync 状态：in-flight cursor、account-level revision、per-cipher `RevisionDate` map、outbound 写队列。data race 变成编译错误。UI 经 `@MainActor` `@Observable` repository 消费结果，actor 边界是唯一的 Sendable 跳点。

### 增量 revision-token sync

1. `GET /api/sync`（可选 `excludeDomains=true`）。
2. 比对 account-level revision + 每个 cipher 的 `RevisionDate`（ISO-8601）。
3. **只写更新比本地更新的服务器行**，本地更新的不被 clobber。
4. 解密在 MainActor 之外完成，upsert 进 VaultStore，再在后台队列重建 `ASCredentialIdentityStore`（先 `getState`，支持增量则 incremental save/remove，否则 replace）。

### No-push polling + background refresh

self-hosted **无 APNs**（VW `ConnectData` 不解析 `devicePushToken`，`pushTechnology=0`）。触发器：foreground 进入、活跃时定时、手动 pull-to-refresh、`BGAppRefreshTask`（iOS）、`NSBackgroundActivityScheduler`（macOS）。`/alive` 用作可达性探测。staleness/电量 tradeoff 明确接受。

### Conflict handling

- **outbound 队列优先**：本地 CRUD 先 flush 到服务器再拉取，减少 race。
- 写入时带 `lastKnownRevisionDate` 做乐观并发（服务器 stale 则 400）。
- 拉取时 skip-write-when-server-newer，避免覆盖本地新编辑。
- 基线策略为 last-write-wins + skip-write 保护；M3 可在此 actor 内升级为字段级 merge（不改结构）。

### Soft-fail 未知 EncString

EncString parser 对未知 type（如 type 7 CoseEncrypt0 / XChaCha20）**标记为 degraded 并跳过该字段/条目，绝不 crash sync**。这是应对 2026 协议分裂（official client 可能发 type-7）的安全阀；type-7 完整支持作为 opt-in 后续排期。

---

## 数据层与持久化

### 存储划分

| 介质 | 存什么 | 不存什么 |
|---|---|---|
| **GRDB+SQLCipher（App Group）** | 全部 cipher 字段（已是 E2E EncString，SQLCipher 是 defense-in-depth）+ 真正明文的 metadata（item type、时间戳、UUID、folder 归属、favorite/reprompt）+ 本地搜索索引 | **unwrapped UserKey 绝不落盘** |
| **Keychain** | SQLCipher DB 密码（随机值，**非** master password）、SE-ECIES-wrapped UserKey（biometry-gated, shared access group）、refresh_token、本地离线校验 hash | master password 明文、UserKey 明文 |
| **UserDefaults / App Group defaults** | 非敏感偏好：server URL、deviceIdentifier(UUID)、auto-lock 超时、上次 sync 时间、UI 偏好 | 任何 key material、任何 token |

### Schema sketch（plaintext-metadata vs encrypted-blob）

> 约定：`enc_` 前缀 = E2E EncString（密文）；其余列为明文 metadata，专供本地查询/排序/搜索（SQLCipher 在此之上再加一层 at-rest 加密）。

```
account(id PK, email, server_url, kdf_type, kdf_iters, kdf_mem, kdf_parallel,
        revision_date, security_stamp, enc_user_key, enc_private_key)

cipher(id PK, account_id FK, type INT,                 -- 1..5 明文用于过滤
       folder_id, organization_id,
       favorite INT, reprompt INT, edit INT, view_password INT,
       revision_date, creation_date, deleted_date, archived_date,  -- 明文用于增量/排序
       enc_name, enc_notes, enc_blob,                  -- enc_blob: login/card/identity/sshKey/secureNote 子对象序列化后的 EncString 集合
       enc_cipher_key,                                  -- 可选 per-cipher 64B key
       search_text)                                     -- 本地解密后构建的明文搜索索引（仅落 SQLCipher 加密库）

cipher_uri(id PK, cipher_id FK, enc_uri, match_type INT)   -- 供 AutoFill 域名匹配（match_type 明文）
fido2_credential(id PK, cipher_id FK, enc_blob, creation_date)  -- creation_date 明文 ISO-8601

folder(id PK, account_id FK, enc_name, revision_date)
collection(id PK, account_id FK, organization_id, enc_name)
organization(id PK, account_id FK, enc_org_key, name)
send(id PK, account_id FK, type INT, enc_name, enc_blob,
     deletion_date, expiration_date, disabled INT, max_access_count INT)
attachment(id PK, cipher_id FK, enc_key, enc_file_name, file_size, url)

sync_state(account_id PK, last_account_revision, last_full_sync_at)
outbox(id PK, op_type, entity_type, entity_id, payload_json, last_known_revision_date)  -- 离线写队列
```

明文 metadata 的取舍原则：**只把 AutoFill 域名匹配、本地搜索/排序、增量 sync 比对所必需的字段留作明文列**（type、各 date、match_type、folder/org 归属、flags、本地搜索索引）；其余一律 `enc_`。SQLCipher 用 `cipher_plaintext_header_size=32` + self-managed salt + WAL + `NSFileCoordinator`，保证 app+extension 跨进程访问不触发 `SQLITE_BUSY`/`0xDEAD10CC`。

---

## API 端点速查

> server base 分两段：**`/identity/*`** 走认证，**`/api/*`** 走 vault。官方 client 发 camelCase form 字段 + `Device-Type`/`Bitwarden-Client-Name`/`Bitwarden-Client-Version`(semver，VW `ClientVersion` guard 必需) headers；VW snake_case + uncased alias 对 camelCase 大小写不敏感匹配。master-pw-hash 走 OAuth `password` 字段。Decimal cipher type：1=Login,2=SecureNote,3=Card,4=Identity,5=SshKey。

| 端点 | Method | Path | 关键字段 | 备注 |
|---|---|---|---|---|
| prelogin | POST | `/identity/accounts/prelogin` | req `{email}`；resp VW camelCase `kdf/kdfIterations/kdfMemory/kdfParallelism` | **必须先调**，永不硬编码 KDF。PBKDF2 salt=trim+lower(email)；Argon2id salt=SHA-256(同上) |
| token (password) | POST | `/identity/connect/token` | form: `grant_type=password, client_id, scope='api offline_access', username=email, password=B64(server-auth hash), deviceType, deviceIdentifier(UUID), deviceName` | resp 含 `access_token`(RS256 JWT)/`refresh_token`/`Key`/`PrivateKey`/Kdf*。VW 忽略 `devicePushToken` |
| token (refresh) | POST | `/identity/connect/token` | form: `grant_type=refresh_token, refresh_token, client_id` + 同 Device 头 | 401/过期时用；refresh 失败需 full re-login |
| token 2FA retry | POST | `/identity/connect/token` | 重发 password form + `twoFactorToken, twoFactorProvider(int), twoFactorRemember(0|1)` | 首次无 2FA 返 400 `{TwoFactorProviders, TwoFactorProviders2}`。0 Authenticator,1 Email,3 YubiKey,7 WebAuthn,2/6 Duo |
| sync | GET | `/api/sync` | Bearer；可选 `excludeDomains=true` | resp `{profile, folders, collections, policies, ciphers, domains|null, sends, userDecryption:{masterPasswordUnlock}, object:'sync'}`。按 RevisionDate 增量 |
| cipher create | POST | `/api/ciphers` | `CipherRequestModel`：type,name,notes,folderId,organizationId,favorite,reprompt,key,fields,passwordHistory,login/card/identity/secureNote/sshKey,lastKnownRevisionDate | resp object=`cipherDetails`。org-owned 用 `POST /api/ciphers/create {cipher, collectionIds}` |
| cipher update | PUT | `/api/ciphers/{id}` | 同 `CipherRequestModel`；发 `lastKnownRevisionDate` 做乐观并发 | stale 则 400。partial：`POST/PUT /api/ciphers/{id}/partial {folderId, favorite}` |
| cipher delete | DELETE | `/api/ciphers/{id}` | 空 body | soft：`PUT .../delete`；restore：`PUT .../restore`；bulk/move 见 spec |
| folders CRUD | GET | `/api/folders` | create `POST {name}`；update `PUT/POST /{id} {name}`；delete `DELETE /{id}` | name 是 E2E EncString。删 folder 仅解绑其 ciphers（不删 cipher） |
| attachment v2 (step1) | POST | `/api/ciphers/{id}/attachment/v2` | req `{key(EncString), fileName(EncString), fileSize}` | resp `{attachmentId, url, fileUploadType:0(Direct), cipherResponse}`。**client 发 key/fileName/fileSize** |
| attachment v2 (step2) | POST | `/api/ciphers/{id}/attachment/{attachmentId}` | multipart `data`(AES-256-CBC+HMAC blob) | 上传到 step1 返回的 url |
| send create | POST | `/api/sends` | `SendData`：type(0 Text/1 File),name,key,deletionDate,disabled,text/file | 128-bit secret 在 URL fragment，永不发送。file send 走 `/api/sends/file/v2` 两步 |
| send access | POST | `/api/sends/access/{accessId}` | 可选 `{password:hash}`；**未认证端点** | password 仅鉴权 gate（hashed），**非** key material |
| config | GET | `/api/config` | 无需认证 | VW camelCase `{version, gitHash, server, environment, push:{pushTechnology:0}, featureStates}`；official PascalCase。**大小写容错解析** |
| alive / now / version | GET | `/alive` | 无需认证 | VW 专属健康路由（不在 `/api` 下）。`/alive` 做可达性探测 |
| device push reg | POST | `/api/devices/identifier/{identifier}/token` | `{pushToken}` | **VW self-host 无 APNs**，视作 no-op；改用 polling + BGAppRefreshTask |

---

## 里程碑映射

### M1 — 核心（先收敛）

**模块**：CryptoCore、VaultModels、KeyVault、KeychainBridge、VaultStore、VaultReader、Fido2、Networking、SyncEngine、VaultRepository、AppShared、DesignSystem、UIShared、UI-iOS、（最小三栏）UI-mac、App-iOS、App-macOS、AutoFillExtension。
**功能**：login/unlock（prelogin+KDF+2FA+refresh）、sync（增量 polling）、personal-vault CRUD（全部 5 种 item type）、TOTP、system AutoFill + passkey extension。

**建议 build order**：
1. `CryptoCore`（先用 golden-vector 把 EncString/KDF/HKDF/PKCS#7 字节级钉死）
2. `VaultModels`
3. `KeyVault` + `KeychainBridge`（unlock + SE-wrap 链路）
4. `VaultStore`（schema + SQLCipher 跨进程）
5. `Networking`（prelogin/token/sync 打通真实 VW）
6. `SyncEngine` + `VaultRepository`（端到端解锁→sync→解密→落库）
7. `VaultReader` + `Fido2` + `AutoFillExtension`（最小内存路径优先验证 120MB）
8. `DesignSystem` + `UIShared` + `UI-iOS` + App-iOS（打磨 iOS）
9. 最小 `UI-mac` + App-macOS（可用即可，深度打磨延后）

### M2 — 组织与生成器

**模块**：扩展 VaultModels/VaultStore/Networking 支持 organizations/collections/folders/attachments(v2 流式)；`Generators` 完整化（password+passkey）；展开 `UI-mac` 的 `.inspector` 深度、`MenuBarExtra` 全功能、`ToolbarSpacer` 胶囊、`backgroundExtensionEffect`，补齐 macOS full native parity；两端补 folder/collection/generator 屏幕。
**功能**：organizations/collections、attachments、folders、password+passkey generator、macOS 原生打磨。

### M3 — 高级特性

**模块**：`Sends`（已在 Networking/Models 预留）、emergency access、password health reports（作为 `Generators`/`Reports` 兄弟模块）、multi-account（`KeyVault` 升级为 multi-key）；conflict handling 可选升级为字段级 merge。**无 spine 重写**。
**功能**：Sends、emergency access、password health reports、multi-account switching。

---

## 主要风险与缓解

| 风险 | 缓解 |
|---|---|
| **AutoFill extension 内存 OOM（~120MB）**，尤其 Argon2id `kdfMemory > 64MiB` 会 silent 杀死 extension（Apple 无保证数值） | extension link graph 最小化（只链 `VaultReader`+`KeychainBridge`）；只解密选中条目、attachment 流式、completeRequest 后释放；prelogin 驱动的 KDF 参数封顶 + 对高内存库告警；**早期上真机测 extension 内存** |
| **纯 Swift crypto 字节级错误**（Argon2id salt=SHA-256(normalized email)、cipher-key PKCS#7-unpad-before-HMAC、type-2 vs type-4、MAC framing）→ silent decrypt 失败或跨 client 不兼容 | 建立 **golden-vector 回归语料**（对官方 client/VW fixture 生成的 EncString/KDF 向量逐条比对）+ 常量时间 MAC 测试 harness，纳入 CI；这是对 VaultKit "test plan 只声明未具化" 失分点的直接补救 |
| **未审计 Argon2id Swift 绑定**（供应链/正确性） | 选 **libsodium** 审计实现并 pin 版本；不自写 Argon2id |
| **2026 协议分裂**：official client 对 VW 发 type-7（CoseEncrypt0/XChaCha20）EncString，可能 strand 现有账户 | EncString parser **soft-fail + 标记 degraded + 清晰错误**；type-7 作为 opt-in 后续排期；架构上 type-dispatch 已留 seam |
| **macOS SE/Touch ID 在 Intel vs Apple Silicon 不一致**，biometric unlock 可能降级 | 早期硬件验证；提供 master-password fallback 路径；biometry 不可用时 graceful 退回 |
| **M1 脚手架过重**（~13 target 一次点亮，拖慢 first-unlock） | 按上面 build order 顺序点亮、每步可端到端验证；macOS UI 深度延到 M2（嫁接 Glasswarden 节奏） |
| **GRDB+SQLCipher over SPM 需 forked Package.swift；跨进程 WAL 损坏 App Group DB** | 早期固化 `cipher_plaintext_header_size=32`+self-managed salt+WAL+`NSFileCoordinator` 方案并做 app+extension 并发压测；pin 依赖版本 |
| **config/casing 分裂**（VW camelCase vs official PascalCase）导致解析 breakage | 大小写不敏感解析或按检测到的 server 分支；`VaultModels` 内集中容错 |

---

## 仍需确认

1. **userDecryption.masterPasswordUnlock 子结构**：新版 VW `GET /api/sync` 多了 `userDecryption.masterPasswordUnlock`（含 kdf 参数 + encrypted user key + email salt？）。需对当前 VW `db/models` 核实其确切 shape，再决定走它还是传统 `profile.key` 路径解 UserKey。
2. **UriMatchType 枚举值**：`UriMatchType.cs` fetch 时 404（文件被移/改名）。值 0-5（Domain/Host/StartsWith/Exact/RegularExpression/Never）由 brief+VW 用法佐证，但 AutoFill 匹配逻辑上线前需对当前 server 枚举路径再核实。
3. **/api/config 挂载路径 vs reverse-proxy**：确认 self-host reverse-proxy 下 official `/api/config` 与 VW 路径前缀；VW 另在 `/api` 外提供 `/alive,/now,/version`。需确认目标部署的反代规则以正确拼 base URL。
4. **产品命名**：locked decision 要求避开 "Bitwarden" 商标与任何 "...warden" 变体，仅可用 nominative "compatible with Bitwarden®"。三个候选名（Glasswarden/Glasshouse/VaultKit）中 **Glasswarden 含 "warden" 违规**、**VaultKit 与 Apple 风格命名易混且 "Kit" 后缀偏框架感**。**需用户给出/确认最终产品名**（建议方向：以 "Glass"/"Vault" 为词根但避开 warden 与 Apple "*Kit" 命名，如 Glasshouse 系）。
5. **Argon2id 内存上限的产品策略**：AutoFill 场景下对 `kdfMemory > 64MiB` 是"硬封顶 + 仅主 App 解锁"还是"告警 + 允许用户接受 extension 不可用"？这是 security-vs-usability 取舍，需用户拍板默认行为。
6. **离线写冲突的默认策略**：M1 采用 last-write-wins + skip-write 保护是否可接受，还是 M1 就需要字段级 merge（影响 `SyncEngine`/`outbox` 复杂度）。
