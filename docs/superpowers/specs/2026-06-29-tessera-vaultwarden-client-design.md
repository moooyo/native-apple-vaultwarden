# Tessera — Vaultwarden 兼容的原生 Apple 客户端 · 设计规格

> 状态：草案待评审（v1）｜ 日期：2026-06-29 ｜ 作者：moooyo + Claude
> 关联文档：
> - 研究简报（字节级 crypto / API / AutoFill / Liquid Glass 细节 + 对抗式核实修正）：[`docs/superpowers/research/2026-06-28-vaultwarden-client-research.md`](../research/2026-06-28-vaultwarden-client-research.md)
> - 架构推荐（评审团 3 方案打分 + 模块分解 + API 速查）：[`docs/superpowers/research/2026-06-29-architecture-recommendation.md`](../research/2026-06-29-architecture-recommendation.md)
>
> 本 spec 是上述两份文档 + 用户范围决策的**自洽收敛**。深层字节级常量与来源引用以研究简报为准，本文不重复抄录全部来源。

---

## 1. 概述与目标

**Tessera** 是一个用纯 Swift 实现、与 Bitwarden/Vaultwarden 协议**字节级兼容**的原生密码管理客户端，覆盖 iOS 与 macOS，提供系统级 AutoFill（密码 + passkey）扩展，采用 macOS 26/iOS 26 的 Liquid Glass 设计语言。本质是**重新实现 Bitwarden 的客户端密码学与同步协议**，并用现代 SwiftUI 在两个平台上原生呈现。

### Goals（目标）
- 与自托管 **Vaultwarden** 字节级兼容：能登录、端到端解密、增删改查、同步个人保险库。
- **全平台原生**：iOS 与 macOS 各自原生体验，共享一套业务逻辑与加密核心。
- **系统级 AutoFill + passkey**：作为软件 WebAuthn authenticator 提供密码/OTP/passkey 自动填充。
- **离线可用**：本地加密缓存，无网也能查看；联网增量同步。
- **完整对标官方功能**（终极目标，分里程碑交付）：保险库全条目类型、组织/集合、附件、文件夹、生成器、Sends、紧急访问、密码健康报告、多账户。
- **安全为先**：明文密钥最小驻留、跨进程零明文密钥、生物识别解锁、自动锁定。

### Non-Goals（非目标，显式排除）
- **不支持 Argon2id KDF**（用户显式决策）：仅支持 **PBKDF2** 账户。`prelogin` 返回 Argon2id 的账户将被清晰拒绝（见 §6.1）。代价：无法登录使用 Argon2id 的账户（含 Bitwarden/Vaultwarden 新账户默认）；用户已知悉并接受。
- **不正式支持 bitwarden.com / .eu 云**：仅以自托管 Vaultwarden 为官方测试目标（仍提供自定义服务器 URL 输入框，连云端属"尽力而为、不保证"）。规避 Bitwarden SDK License 的"兼容应用"灰区。
- **不链接 Bitwarden Rust SDK**（许可证不兼容，见 §13）：加密纯 Swift 自研。
- **不依赖推送通知**：自托管收不到 APNs，改用轮询 + 后台刷新。
- **不支持 Account crypto v2 / type-7（CoseEncrypt0/XChaCha20）的解密**（首期）：仅做 soft-fail 软失败，作为后续 opt-in。
- **不支持 Key Connector / SSO TDE 解锁路径**（首期）。
- **不向后兼容 iOS/macOS 26 以下系统**。

---

## 2. 锁定决策（Locked Decisions）

| # | 决策 | 取值 | 影响 |
|---|------|------|------|
| D1 | 服务器目标 | Vaultwarden 自托管（官方）；自定义 URL 支持；云端非官方目标 | 测试范围、规避 SDK License 灰区 |
| D2 | 最低系统 | iOS 26.0 / macOS 26.0 | 干净用 Liquid Glass，几乎无 `#available` 分支 |
| D3 | 范围 | 完整对标，分 M1/M2/M3 里程碑 | 见 §9 |
| D4 | AutoFill + passkey | v1（M1）即包含 | App Group 共享 + 扩展隔离架构 |
| D5 | 加密实现 | 纯 Swift（CryptoKit + CommonCrypto + Security `SecKey`） | 不链 Rust SDK；保住 MIT + App Store |
| D6 | KDF | **仅 PBKDF2-SHA256**；不支持 Argon2id | `CryptoCore` 去掉 libsodium/Argon2 依赖；AutoFill OOM 风险消失 |
| D7 | 离线存储 | GRDB + SQLCipher（App Group 容器） | 密文 blob + 明文 metadata 分离 |
| D8 | 密钥跨进程 | 仅传 SE-ECIES-wrap 后的 UserKey，生物识别门控 | 明文 UserKey 绝不跨进程、绝不落盘 |
| D9 | 同步 | 无推送 → 轮询 + `BGAppRefreshTask`/`NSBackgroundActivityScheduler` + revision-token 增量 | 接受 staleness 取舍 |
| D10 | UI | per-OS 双 view tree（`UI-iOS`/`UI-mac`）+ 共享 `UIShared` `@Observable` VM | native 保真 + 逻辑单写 |
| D11 | 产品名 | **Tessera**（避开 "...warden" 与 Apple "*Kit"） | 见 §13 |
| D12 | 冲突策略（M1） | last-write-wins + skip-write-when-server-newer + outbound 队列优先 | M3 可升级字段级 merge |

---

## 3. 平台与基线

- **部署目标**：iOS 26.0、macOS 26.0（统一构建用 Xcode 26 SDK，标准控件重编译即自动获得 Liquid Glass material）。
- **语言/并发**：Swift 6 严格并发；`@MainActor` 默认隔离 UI；sync/key 状态用 `actor`。
- **包管理**：Swift Package Manager（多 target 单仓）。
- **第三方依赖（最小化、全部 pin 版本）**：GRDB（+ SQLCipher）。加密原语优先用系统框架（CryptoKit / CommonCrypto / Security），避免引入加密第三方库。**不引入 Argon2 库**（D6）。

---

## 4. 架构总览

四层分层架构，依赖只能自上而下；安全敏感代码全部下沉 **L0 Spine + L1 Security**，UI 与 Networking 永不触碰 raw key bytes。

```
L4  App targets        App-iOS · App-macOS · AutoFillExtension
L3  UI                 UI-iOS · UI-mac  ←共享←  UIShared(@Observable) · DesignSystem
L2  App-side services  Networking · SyncEngine · Generators · VaultRepository · AppShared   (扩展绝不链)
L1  Security & data    KeyVault · KeychainBridge · VaultStore · VaultReader · Fido2
L0  Spine              CryptoCore · VaultModels
```

**AutoFill 隔离红线（架构成败关键）**：`AutoFillExtension` 只允许链
`VaultReader + KeychainBridge + VaultModels + Fido2 + DesignSystem + AppShared`
（及其传递依赖 `CryptoCore`/`KeyVault`/`VaultStore`）。**绝不**链 `Networking`/`SyncEngine`/`Generators`/`VaultRepository`/`UIShared`/`UI-iOS`/`UI-mac`。这保证扩展 link graph 最小、启动内存最低、守住 ~120MB 预算。

模块清单（职责/依赖见架构推荐文档 §模块与 target 分解，本 spec 不重复表格）。**相对架构推荐文档的唯一修订**：`CryptoCore` 的 KDF 只实现 **PBKDF2-SHA256**（移除 Argon2id），不引入 libsodium。

---

## 5. 组件设计

### 5.1 CryptoCore（L0 · 唯一持 key bytes）
- 无 UIKit/AppKit/SwiftUI/网络依赖；所有 key material 用 `SecureBytes`（锁定+归零缓冲）。
- **EncString 解析器**：解析 `type.iv|ct|mac` / `type.data` / `type.data|mac`。支持 type 0（已弃用，故意阻断解密）、type 2（`AesCbc256_HmacSha256`，当前对称）、type 3-6（RSA）。对 **未知/未实现 type（含 type 7）软失败**：标记 degraded、跳过该字段/条目，绝不 crash。
- **KDF（仅 PBKDF2）**：`MasterKey = PBKDF2-HMAC-SHA256(password, salt = email.trim().lowercased(), iterations)`，32 字节。salt 为规范化邮箱**原文直接用**（不做 SHA）。`iterations` 来自 prelogin（永不硬编码）；低于 5000 视为非法。
- **认证/本地哈希**：`B64(PBKDF2-SHA256(MasterKey, salt = password, iters))`，`iters=1` → 服务器认证哈希（走 OAuth `password` 字段），`iters=2` → 本地离线解锁校验哈希。
- **Stretched Master Key**：HKDF-Expand-SHA256(MasterKey, info `"enc"` 32B || info `"mac"` 32B) = 64B（`enc`+`mac`）。
- **对称加解密**：AES-256-CBC + encrypt-then-MAC（HMAC-SHA256 over `iv||ct`，**常量时间**比较，校验通过才解）。CommonCrypto `CCCrypt`。
- **PKCS#7**：对解密出的 per-cipher Cipher Key **先 unpad 再当 HMAC key**（高频兼容陷阱）。
- **RSA-2048-OAEP**：Security `SecKey`（`kSecKeyAlgorithmRSAEncryptionOAEPSHA1` = type-4，活跃；SHA256 = type-3）。私钥 PKCS8-DER 经 UserKey 包裹为 type-2。
- **正确性护栏**：建立 **golden-vector 回归语料**（对 Vaultwarden/官方 client fixture 生成的 EncString/KDF/HKDF/PKCS#7 向量逐条比对），纳入 CI（见 §10）。

### 5.2 KeyVault（L1 · actor）
- 内存中 key 层级唯一持有者：unwrapped `UserKey`(64B) + 按需派生的 per-cipher / org / RSA 私钥。
- vend **短生命周期 decryptor**给上层；调用方拿到的是解密结果而非裸 key。
- lock / 进入后台 / 超时 → 立即归零所有 key material。**绝不持久化 key**。

```
MasterPassword + prelogin salt
   │ PBKDF2 → MasterKey(32B)
   ├ PBKDF2(iters=1, salt=password) → 服务器认证哈希 → OAuth password 字段
   ├ PBKDF2(iters=2, salt=password) → 本地离线校验哈希（持久化）
   └ HKDF-Expand("enc"/"mac") → StretchedMasterKey(64B)
        └ 解 type-2 `Key` EncString（先验 HMAC）→ UserKey(64B)
             ├ per-cipher Cipher Key（type-2，PKCS#7 unpad 后作 HMAC key）
             ├ RSA-2048 私钥（type-2 包裹）→ org keys（type-4 RSA-OAEP）
             └ attachment keys（经 Cipher Key 包裹）
```

### 5.3 KeychainBridge（L1）
- 生成 Secure Enclave P-256 key（`.privateKeyUsage` + `.biometryCurrentSet`）。
- 对 `UserKey` 做 **ECIES-wrap**，密文存入 **共享 Keychain access group**，属性 `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`。
- 主 App 与扩展经同一 access group 读取；解锁用 `LAContext` + `kSecUseAuthenticationContext`，Face ID/Touch ID/Optic ID 成功才返回 wrapped key。**明文 UserKey 绝不跨进程**——这是唯一的跨进程 key 通道。
- ⚠️ 开放项：macOS Intel vs Apple Silicon 的 SE/Touch ID 一致性需早期硬件验证；提供主密码 fallback。

### 5.4 VaultStore（L1）
- GRDB + SQLCipher，库文件位于 **App Group 容器**。
- DB 密码 = Keychain 里的**随机值**（非主密码）；`config.prepareDatabase { try $0.usePassphrase(keyData) }`。
- 跨进程：`PRAGMA cipher_plaintext_header_size = 32` + self-managed salt + WAL + `NSFileCoordinator`，避免 `SQLITE_BUSY`/`0xDEAD10CC`。
- 存储划分见 §7.3 schema。**unwrapped UserKey 绝不落盘**。

### 5.5 Networking（L2）
- URLSession async/await。base URL 分 `/identity/*`（认证）与 `/api/*`（vault）；支持自定义服务器 URL 与反代前缀。
- 注入 headers：`Device-Type`、`Bitwarden-Client-Name`、`Bitwarden-Client-Version`（semver，VW `ClientVersion` guard 需要）、`Device-Identifier`(稳定 UUID)、`Device-Name`。
- 端点见 §7.4。大小写容错解析（VW camelCase vs official PascalCase）集中在 `VaultModels`。

### 5.6 SyncEngine（L2 · actor）
- 独占可变 sync 状态：in-flight cursor、account-level revision、per-cipher `RevisionDate` map、outbound 写队列。
- **增量**：`GET /api/sync`（可选 `excludeDomains`）→ 比对 account revision + 每个 cipher `RevisionDate`（ISO-8601）→ 只写比本地新的服务器行。
- **解密在 MainActor 之外**完成 → upsert 进 VaultStore → 后台队列重建 `ASCredentialIdentityStore`（先 `getState`，支持增量则 incremental，否则 replace）。
- **无推送**：触发器 = foreground 进入 / 活跃时定时 / pull-to-refresh / `BGAppRefreshTask`(iOS) / `NSBackgroundActivityScheduler`(macOS)；`/alive` 做可达性探测。
- **冲突（D12）**：outbound 队列优先 flush；写时带 `lastKnownRevisionDate` 乐观并发（stale→400）；拉取 skip-write-when-server-newer。

### 5.7 VaultReader + Fido2 + AutoFillExtension（L1/L4）
- **VaultReader**（扩展专用 least-privilege 只读 facade）：query credential identities、解密**单个**选中 cipher/passkey、build `authenticatorData`。无 sync/network/bulk-decrypt。
- **Fido2**（软件 WebAuthn authenticator）：构造 `authenticatorData`（32B SHA-256(rpId) + flags(UP/UV) + 4B signCount）、用存储的 P-256 私钥签 `(authenticatorData || clientDataHash)`、`none` attestation CBOR、COSE alg 映射、P-256 keypair 生成。
- **AutoFillExtension**（`ASCredentialProviderViewController`，双平台）：
  - silent 路径 `provideCredentialWithoutUserInteraction`：库锁定即 `cancelRequest(NSError(ASExtensionErrorDomain, userInteractionRequired=100))`，绝不阻塞等生物识别。
  - `prepareInterfaceToProvideCredential`：生物识别解锁 UI → 经 `LAContext` 取回 ECIES-wrapped UserKey → 解 wrap → 只解密选中条目。
  - passkey：`prepareInterface(forPasskeyRegistration:)` / passkey 列表与断言。
  - **内存**：只解密选中项、附件流式、`completeRequest` 后立即释放 buffer。因 D6（PBKDF2-only）扩展内即便主密码 fallback 也只跑轻量 PBKDF2，Argon2 OOM 风险已消除。
  - 能力声明：`com.apple.developer.authentication-services.autofill-credential-provider` 加到主 App + 扩展两 target；Info.plist `ASCredentialProviderExtensionCapabilities`（`ProvidesPasswords`/`ProvidesPasskeys`/`ProvidesOneTimeCodes` 等）。

### 5.8 Generators（L2）
- password / passphrase / username 生成；passkey keypair（P-256，复用 Fido2）；TOTP（RFC 6238）。

### 5.9 VaultRepository + DI（L2）
- App-facing CRUD / unlock / lock 编排（store + sync + keyvault）；`AuthRepository`（login / 2FA / refresh）。
- DI：`ServiceContainer` + `Has<Service>` 协议（镜像官方 iOS App 模式），便于 mock 测试。

### 5.10 UI 层（L3）
- **DesignSystem**：Liquid Glass tokens、`GlassScrim`、`ConcentricRectangle` 卡片、OTP 环、`SecureRevealView`、无障碍 opaque fallback（`accessibilityReduceTransparency`/`differentiateWithoutColor`/`reduceMotion` → `.regular`→`.identity`/纯色）。
- **UIShared**：双 App 共用的 `@Observable` VM（`UnlockModel`/`VaultListModel`/`ItemDetailModel`/`GeneratorModel`/`SyncStatusModel`），仅逻辑无 layout。
- **UI-iOS**：`TabView`（Vault/Generator/Send/Settings）+ bottom `searchable` + `tabBarMinimizeBehavior(.onScrollDown)` + `tabViewBottomAccessory`（unlock/sync 状态 pill）+ 右下 `.glassProminent` "+" 浮动（多按钮包 `GlassEffectContainer`+`.glassEffectID`）+ opaque List + `ConcentricRectangle` 卡片 + `.scrollEdgeEffectStyle`。
- **UI-mac**：三栏 `NavigationSplitView`（分类/folders | 列表 | 详情）+ `.inspector`（metadata/密码历史）+ 详情 hero `.backgroundExtensionEffect()` + `ToolbarSpacer` 玻璃胶囊 + `MenuBarExtra`（快速解锁/搜索/复制）。
- **全局 glass 红线**：`.glassEffect()` 只用于自定义 chrome；list rows/详情主体保持 opaque（content layer）；**密码/TOTP/卡号/passkey 绝不渲染在 clear glass**，用 `.regular` 或纯色 scrim。

---

## 6. 认证与解锁流程

### 6.1 登录
1. `POST /identity/accounts/prelogin {email}` → `{kdf, kdfIterations, ...}`。
   - **若 `kdf != 0`（即 Argon2id 等）→ 立即以清晰文案拒绝**（D6）："此账户使用 Argon2id KDF，Tessera 当前仅支持 PBKDF2 账户。" 提供帮助链接说明如何在 Vaultwarden/Bitwarden 后台改 KDF。**不进入派生流程**。
2. 派生 `MasterKey`（PBKDF2，salt=规范化邮箱，iters=prelogin 值）。
3. `POST /identity/connect/token`（form）：`grant_type=password, client_id, scope='api offline_access', username=email, password=B64(认证哈希 iters=1), deviceType, deviceIdentifier, deviceName`。
4. 成功 → 拿 `access_token`/`refresh_token`/`Key`/`PrivateKey` → HKDF 拉伸解 `Key` 得 `UserKey`。
5. 持久化本地离线校验哈希（iters=2）+ refresh_token（Keychain）；首次解锁后生成 SE key 并 ECIES-wrap UserKey 入共享 Keychain。

### 6.2 二因素
- 首次 token 无 2FA 返回 400 `{TwoFactorProviders2}` → 带 `twoFactorToken/twoFactorProvider(int)/twoFactorRemember` 重试。
- 支持：Authenticator(0)、Email(1)、YubiKey(3)、WebAuthn(7)、Duo(2/6)。WebAuthn/Duo 需 challenge/redirect 处理（M1 至少 Authenticator+Email；WebAuthn/Duo 可 M2）。

### 6.3 解锁与自动锁定
- **生物识别解锁**（主路径）：`LAContext` → 取回 SE-ECIES-wrapped UserKey → 解 wrap，无需重跑 KDF。
- **主密码解锁**（fallback）：用本地离线校验哈希（PBKDF2 iters=2）验证。
- **自动锁定**：超时 / 进入后台 → `KeyVault` 归零内存 key；可配置超时与"立即锁定"。

---

## 7. 数据模型与 API 参考

### 7.1 Cipher 类型（明文 type 整数）
`1=Login, 2=SecureNote, 3=Card, 4=Identity, 5=SshKey`。

### 7.2 EncString 类型
| type | 名称 | 处理 |
|---|---|---|
| 0 | AesCbc256_B64 | 故意阻断解密（防降级） |
| 2 | AesCbc256_HmacSha256_B64 | **当前对称格式**（3 段 `iv|ct|mac`） |
| 3/4 | Rsa2048_OAEP_SHA256/SHA1 | 非对称（type-4 活跃，org key 分发） |
| 5/6 | Rsa2048_OAEP_*_HmacSha256 | 非对称 + MAC |
| 7 | Cose_Encrypt0_B64 | **soft-fail**（首期不解，标 degraded） |

### 7.3 持久化 schema（草图）
约定：`enc_` 前缀 = E2E EncString 密文；其余为明文 metadata（专供本地查询/排序/搜索，SQLCipher 在其上再加 at-rest 层）。

```
account(id PK, email, server_url, kdf_type, kdf_iters,
        revision_date, security_stamp, enc_user_key, enc_private_key)
cipher(id PK, account_id FK, type INT, folder_id, organization_id,
       favorite INT, reprompt INT, edit INT, view_password INT,
       revision_date, creation_date, deleted_date,         -- 明文：增量/排序
       enc_name, enc_notes, enc_blob, enc_cipher_key, search_text)
cipher_uri(id PK, cipher_id FK, enc_uri, match_type INT)   -- match_type 明文供 AutoFill 匹配
fido2_credential(id PK, cipher_id FK, enc_blob, creation_date)
folder(id PK, account_id FK, enc_name, revision_date)
collection(id PK, account_id FK, organization_id, enc_name)
organization(id PK, account_id FK, enc_org_key, name)
send(id PK, account_id FK, type INT, enc_name, enc_blob, deletion_date, expiration_date, disabled INT, max_access_count INT)
attachment(id PK, cipher_id FK, enc_key, enc_file_name, file_size, url)
sync_state(account_id PK, last_account_revision, last_full_sync_at)
outbox(id PK, op_type, entity_type, entity_id, payload_json, last_known_revision_date)
```
- **Keychain**：DB 随机密码、SE-ECIES-wrapped UserKey、refresh_token、本地离线校验哈希。
- **UserDefaults（App Group）**：server URL、deviceIdentifier、auto-lock 超时、上次 sync、UI 偏好。**绝不存任何 key/token**。

### 7.4 API 端点速查（核心）
| 端点 | Method | Path | 备注 |
|---|---|---|---|
| prelogin | POST | `/identity/accounts/prelogin` | 先调；**kdf!=0 拒绝** |
| token (password/refresh/2FA) | POST | `/identity/connect/token` | OAuth form；master-pw-hash 走 `password` 字段 |
| sync | GET | `/api/sync` | `{profile,folders,collections,policies,ciphers,domains,sends}`；按 RevisionDate 增量 |
| cipher CRUD | POST/PUT/DELETE | `/api/ciphers[/{id}]` | `CipherRequestModel`；写带 `lastKnownRevisionDate`；org 用 `/api/ciphers/create` |
| folders | GET/POST/PUT/DELETE | `/api/folders[/{id}]` | name 是 EncString |
| attachment v2 | POST | `/api/ciphers/{id}/attachment/v2` → `/{attachmentId}` | 两步：client 发 `{key,fileName,fileSize}` → 上传密文 blob |
| sends | POST | `/api/sends`、`/api/sends/access/{id}` | 128-bit secret 在 URL fragment，永不发送 |
| config / alive | GET | `/api/config`、`/alive` | 大小写容错；`/alive` 探测可达性 |
| device token | POST | `/api/devices/identifier/{id}/token` | **VW 无 APNs，视作 no-op** |

> 完整请求/响应字段见架构推荐文档 §API 端点速查。

---

## 8. 安全模型（概要）

| 资产 | 在哪 | 保护 |
|---|---|---|
| 明文 UserKey / 派生 key | 仅 `KeyVault` actor 内存 | 锁屏/后台/超时归零；绝不落盘、绝不跨进程明文 |
| 跨进程 key 传输 | 共享 Keychain（SE-ECIES-wrapped） | 生物识别门控 + `WhenPasscodeSetThisDeviceOnly` + `.biometryCurrentSet`（生物特征变更即失效） |
| 保险库密文 | SQLCipher（App Group） | 字段已 E2E EncString + SQLCipher at-rest 纵深防御 |
| DB 密码 | Keychain | 随机值，非主密码 |
| refresh_token | Keychain | 不入 UserDefaults |
| 明文 metadata | SQLCipher 明文列 | 仅必要字段（type/日期/match_type/folder 归属/搜索索引）；URL/folder 名等仍 EncString 加密 |
| 扩展攻击面 | 最小 link graph | 不链网络/同步/UI；只解选中项 |

威胁取舍：接受"明文搜索索引落 SQLCipher 加密库"以支持本地搜索；接受 PBKDF2-only 的兼容性收窄换取实现简化与扩展内存安全；接受无推送带来的同步延迟。

---

## 9. 里程碑

### M1 — 核心（先收敛）
- **模块**：CryptoCore、VaultModels、KeyVault、KeychainBridge、VaultStore、VaultReader、Fido2、Networking、SyncEngine、VaultRepository、AppShared、DesignSystem、UIShared、UI-iOS、（最小三栏）UI-mac、App-iOS、App-macOS、AutoFillExtension。
- **功能**：login/unlock（prelogin + PBKDF2 + 2FA[Authenticator/Email] + refresh + 生物识别）、增量同步、个人保险库 CRUD（全部 5 种 item type）、TOTP、系统 AutoFill + passkey。
- **建议 build order**：
  1. CryptoCore（golden-vector 字节级钉死 EncString/PBKDF2/HKDF/PKCS#7）
  2. VaultModels
  3. KeyVault + KeychainBridge（unlock + SE-wrap 链路）
  4. VaultStore（schema + SQLCipher 跨进程）
  5. Networking（prelogin/token/sync 打通真实 Vaultwarden）
  6. SyncEngine + VaultRepository（端到端 解锁→sync→解密→落库）
  7. VaultReader + Fido2 + AutoFillExtension（最小内存路径优先验证 ~120MB）
  8. DesignSystem + UIShared + UI-iOS + App-iOS（打磨 iOS）
  9. 最小 UI-mac + App-macOS（可用即可，深度延后）

### M2 — 组织与生成器
- organizations/collections、attachments（v2 流式）、folders、password+passkey generator、WebAuthn/Duo 2FA；展开 macOS 原生深度（`.inspector`/`MenuBarExtra`/`ToolbarSpacer`/`backgroundExtensionEffect`）。

### M3 — 高级特性
- Sends、emergency access、密码健康报告（`Reports` 模块）、多账户（`KeyVault` 升级 multi-key）、可选字段级 merge 冲突。**无 spine 重写**。

---

## 10. 测试策略

- **Golden-vector 回归（最高优先）**：对 Vaultwarden/官方 client 生成的 EncString/PBKDF2/HKDF/PKCS#7/RSA-OAEP 向量逐条比对；常量时间 MAC 测试 harness。纳入 CI。
- **集成测试**：对真实 self-hosted Vaultwarden（docker）跑 login→sync→CRUD→AutoFill 端到端；覆盖 PBKDF2 账户、2FA、附件、org（M2）。
- **AutoFill 内存实测**：早期在真机测扩展内存峰值（守 ~120MB），含大库 + 附件场景。
- **无障碍**：Reduce Transparency / Increased Contrast / Reduce Motion 三态下自定义 glass 的 opaque fallback。
- **并发**：Swift 6 严格并发编译零警告；actor 边界 race 测试。

---

## 11. 风险与缓解

| 风险 | 缓解 |
|---|---|
| 纯 Swift crypto 字节级错误（salt/PKCS#7/MAC framing/type 混淆）→ silent decrypt 失败或跨 client 不兼容 | golden-vector CI（§10）；常量时间 MAC harness |
| 2026 协议分裂：官方 client 对 VW 发 type-7 EncString | EncString **soft-fail + degraded 标记 + 清晰错误**；type-dispatch 留 seam |
| AutoFill 扩展内存（~120MB，Apple 无保证数值） | 最小 link graph + 只解选中项 + 流式 + 即时释放；**PBKDF2-only 已消除 Argon2 OOM** |
| macOS SE/Touch ID（Intel vs Apple Silicon）不一致 | 早期硬件验证；主密码 fallback；graceful 退回 |
| GRDB+SQLCipher over SPM 需 forked Package.swift；跨进程 WAL 损坏 | 早期固化 `cipher_plaintext_header_size=32`+self-managed salt+WAL+`NSFileCoordinator` 并做 app+extension 并发压测；pin 版本 |
| VW camelCase vs official PascalCase 解析 breakage | 集中在 VaultModels 做大小写容错 |
| **Argon2id 账户登录失败（D6 接受的限制）** | `prelogin` kdf!=0 时清晰文案 + 改 KDF 指引；文档中标注限制 |
| M1 脚手架重（~13 target） | 按 build order 逐步点亮、每步端到端可验；macOS UI 深度延 M2 |

---

## 12. 待核实 / 开放项（实现期落地，不阻塞设计）

1. `GET /api/sync` 的 `userDecryption.masterPasswordUnlock` 子结构 → 对当前 VW `db/models` 核实，决定走它还是传统 `profile.key` 解 UserKey。
2. `UriMatchType` 枚举确切值（Domain/Host/StartsWith/Exact/Regex/Never）→ 对当前 server 源码核实（AutoFill 域名匹配上线前）。
3. 反代下 `/api/config` 路径前缀 vs VW `/alive,/now,/version` 的拼接规则。
4. 附件文件流的精确 HMAC framing（裸 AES-CBC blob + 独立 HMAC vs EncString 信封）→ 对 sdk attachment 代码核实。
5. Send 的精确 HKDF info-label 字符串 → 对 sdk-internal 核实。
6. macOS Catalyst vs 原生 AppKit 下 AutoFill 提供者注册与 `deviceType` 取值。
7. `ASPasskeyRegistrationCredential.attestationObject` 中第三方 `none` attestation 的精确 CBOR/COSE 编码与系统校验。

---

## 13. 命名与许可

- **产品名 Tessera**（古罗马"口令代币"，主题贴合；避开 Bitwarden 商标与任何 "...warden" 变体，避开 Apple 风格 "*Kit"）。仅可用提名式 "compatible with Bitwarden®"，不暗示背书。
- **许可**：仓库现为 **MIT**。因加密为纯 Swift 自研、**不嵌入** GPLv3/SDK-License 的 Rust SDK，MIT 与 App Store 分发均无冲突。Vaultwarden 自身 AGPL-3.0 仅约束服务端，不约束独立分发的客户端。
- 若未来考虑接入官方 SDK，则触发 GPL/SDK-License 冲突，**不予采用**（见 Non-Goals D5）。

---

## 14. 下一步

本 spec 通过评审后 → 进入 **writing-plans**：把 M1 拆成可独立执行、带验收标准的实现计划（按 §9 build order），优先 CryptoCore golden-vector + 端到端解锁/同步链路。
