# 原生 Apple（iOS + macOS）Vaultwarden/Bitwarden 兼容客户端 — 研究简报

> 日期：2026-06-28 ｜ 目标：设计一个与 Bitwarden/Vaultwarden 协议兼容的原生 Swift iOS + macOS 客户端（含 AutoFill / Passkey 扩展）。
> 本简报综合了 6 个研究域（API、crypto、autofill、liquidglass、swiftarch、priorart）及其对抗式核实（adversarial verification）结果。凡属训练截止后（iOS 27 / macOS 27 / 2026 年事件）且仅靠二手来源的内容，均以 ⚠️ 标注。

---

## 摘要

本项目的本质是**重新实现 Bitwarden 的客户端密码学与同步协议**，并用现代 SwiftUI（Liquid Glass）在 iOS + macOS 上呈现，同时提供系统级 AutoFill / Passkey 扩展。可行性高——协议是字节级可规格化的（security whitepaper + `bitwarden/sdk-internal` Rust 源码），且 Vaultwarden 提供 Bitwarden 兼容的 REST API。但有三大硬约束：**许可证**（GPL/AGPL/SDK License 三重夹击）、**AutoFill 扩展内存预算（~120 MB）**、以及 **2026 年正在发生的协议/SDK 版本分裂**正在破坏 Vaultwarden 兼容性。

**6 个最大要点：**

1. **不要链接官方 Rust SDK，自己用 Swift 重写 crypto。** 核实阶段**推翻**了"SDK 现在是纯 GPL-3.0、可自由复用"的说法：`sdk-internal` 实为**双许可（GPL-3.0 OR Bitwarden SDK License v2.0）**，且 SDK License 仍禁止开发"非 Bitwarden 兼容"应用——对一个 Vaultwarden-only 闭源客户端，**两个分支都不可用**。纯 Swift 重写是唯一能保留许可证与 App Store 选项的路径。

2. **KDF 与 salt 必须字节精确，且服务器驱动。** 永远先调 `POST /identity/accounts/prelogin` 取参数；PBKDF2 的 salt = `email.trim().lowercased()` 直接用（**不做 SHA**），而 Argon2id 的 salt = `SHA-256(email.trim().lowercased())` 的 32 字节原始摘要（核实**纠正**了原研究"Argon2 用未规范化邮箱"的错误——两条路径共享同一个规范化邮箱）。

3. **密钥层级清晰：StretchedMasterKey → UserKey(64B) → {per-cipher key, RSA 私钥, org keys}。** EncString 格式 `type.iv|ct|mac`；当前用 type 2（AES-256-CBC + HMAC-SHA256），非对称用 type 4（RSA-2048-OAEP-SHA1），新格式 type 7（CoseEncrypt0 / XChaCha20-Poly1305）⚠️ 正在 2026 年逐步推出（先对新注册账户）。

4. **AutoFill 扩展是软件 WebAuthn authenticator，且受 ~120 MB 内存上限钳制。** 这直接决定了 KDF 选择：Argon2id 内存 > 64 MiB 会让扩展静默崩溃。条件式 passkey 注册（conditional registration）实为 **iOS 18** 特性（核实**纠正**了"iOS 26 新增"的说法）；真正 iOS 26 新增的是 Signal/update API（`ASCredentialUpdater`）、账户创建流、Credential Exchange（CXF/CXP 导入导出）。

5. **Liquid Glass 第 1 代 API（iOS/macOS 26）已确认可用且权威；iOS 27 / macOS 27 "Golden Gate" 仅有少量经 Apple 文档确认的新增。** 标准控件重编译即自动获得材质；`UIDesignRequiresCompatibility` 退出开关在 iOS 27 SDK 下被系统**忽略**（已由 Apple 官方文档确认，非传言）。对密码这种安全 App，必须在 Reduce Transparency / Increased Contrast 下做不透明回退，且**绝不**把密码/OTP 渲染在 clear glass 上。

6. **不要依赖推送；为 2026 协议分裂做防御。** Vaultwarden 自托管/第三方构建几乎收不到 APNs 推送（需官方商店的 Firebase/APNs 配置 + Installation ID/Key），必须设计轮询 + 后台刷新 + revision-token 增量同步。EncString 解析器要对未知 type **软失败**（标记/跳过而非崩溃）。

---

## API 与同步协议

### 认证流程

1. **预登录（取 KDF 参数）** `POST /identity/accounts/prelogin`，body `{"email":"..."}`，返回 `{kdf, kdfIterations, kdfMemory, kdfParallelism}`。`kdf:0` = PBKDF2-SHA256（memory/parallelism 为 null），`kdf:1` = Argon2id。**必须先调用，不要硬编码默认值**。Vaultwarden 自托管返回相同结构；2025.2.0 以来客户端要求 KDF 配置存在。
   - 来源：<https://github.com/dani-garcia/vaultwarden/discussions/5730> ｜ <https://bitwarden.com/help/kdf-algorithms/>

2. **令牌（OAuth2 password grant）** `POST /identity/connect/token`（`application/x-www-form-urlencoded`）：
   - `grant_type=password`, `client_id`, `scope=api offline_access`, `username`, `password=<base64(server-auth master-password-hash)>`, `deviceType`(int), `deviceIdentifier`(稳定 UUID), `deviceName`, `devicePushToken`。
   - ⚠️ **字段名核实**：master-password-hash 在 password-grant 请求里走的是 OAuth `password` 表单字段，**不是**字面叫 `masterPasswordHash` 的字段（`masterPasswordHash` JSON 字段名用于注册/改密/security-stamp 等其他端点）。
   - 返回 `access_token`(RS256 JWT)、`refresh_token`、`expires_in`、`Key`（protected user key）、`PrivateKey`（RSA）。
   - 来源：<https://contributing.bitwarden.com/architecture/deep-dives/authentication/> ｜ <https://docs.cozy.io/en/cozy-stack/bitwarden/>

3. **刷新令牌** `grant_type=refresh_token`。

**DeviceType（Apple 相关枚举）**：iOS=1, MacOsDesktop=7, SafariBrowser=17, SafariExtension=20, MacOsCLI=24。
来源：<https://github.com/bitwarden/server/blob/main/src/Core/Enums/DeviceType.cs>

### 2FA

收到 `400` 时服务器返回 `TwoFactorProviders2` map；客户端带 `twoFactorToken`、`twoFactorProvider`(int)、`twoFactorRemember` 重试令牌请求。

**TwoFactorProviderType 枚举**：Authenticator=0, Email=1, Duo=2, YubiKey=3, U2f=4（已弃用）, Remember=5, OrganizationDuo=6, WebAuthn=7, RecoveryCode=8。Vaultwarden 支持 Authenticator、Email、FIDO2 WebAuthn、YubiKey、Duo。WebAuthn(7) 与 Duo 需要 challenge/redirect 处理。
来源：<https://github.com/bitwarden/server/blob/master/src/Core/Models/TwoFactorProvider.cs> ｜ <https://www.mintlify.com/bitwarden/clients/api/auth/two-factor>

### 同步形态

`GET /api/sync`（Bearer token）返回 `{Profile, Folders, Ciphers, Collections, Domains, Sends}`。`Profile` 含 `key`(protected user key)、`privateKey`、`organizations`(含各 org 的加密 key)。CRUD：`/api/ciphers[/{id}]`、`/api/folders`。
**增量同步**：以 revision-token 驱动；存储并比较每个 cipher 的 `RevisionDate` 及账户级 revision，避免覆盖更新的服务器数据。日期用 ISO-8601。

### 附件（attachments）

**两步 v2 流程**，每个附件有独立 key：

1. 客户端在**请求体**里 POST 加密后的 attachment key + 加密 filename + fileSize 到 `POST /ciphers/{id}/attachment/v2`（`AttachmentRequestModel`: `Key, FileName, FileSize, AdminRequest, LastKnownRevisionDate`）。
2. 服务器**响应**（`AttachmentUploadDataResponseModel`）返回 `attachmentId, url, fileUploadType, cipherResponse`（org/admin 请求为 `cipherMiniResponse`）。**响应不携带 key/filename/size 作为新数据**——`cipherResponse` 只是回显已更新的 cipher。
3. 客户端把 AES-256-CBC+HMAC 加密的 blob 上传到返回的 `url`。

> ⚠️ **核实纠正了原研究的方向性错误**：原说 v2 响应返回 key/fileName/fileSize，实际是客户端在请求体里**发送**这些。另原研究把 "2023.5" 当作 v1→v2 切换点也是误判——v2 直传端点早在 server PR #1229（约 2021）就已上线；v2023.5.0 的失败是无关的 Node 18 multipart 编码回归。

加密层级（whitepaper）：**Cipher Key** 加密附件的 filename/size 并加密 **Attachment Key**；**Attachment Key** 加密文件 blob（AES-256-CBC + HMAC-SHA256）。
来源：<https://bitwarden.com/help/bitwarden-security-white-paper/> ｜ <https://raw.githubusercontent.com/bitwarden/server/main/src/Api/Vault/Controllers/CiphersController.cs> ｜ <https://github.com/bitwarden/server/pull/1229>

### Vaultwarden 分歧与陷阱

- **推送通知**：需要 bitwarden.com/host 的 Installation ID+Key，经 Bitwarden 的 Azure Notification Hub / `push.bitwarden.com` 中继（EU: `PUSH_RELAY_URI=https://api.bitwarden.eu`）。**仅对官方商店构建（带真实 Firebase/APNs 配置）的应用生效**；自建/第三方客户端基本收不到推送，必须回退到轮询/手动同步。
  来源：<https://github.com/dani-garcia/vaultwarden/wiki/Enabling-Mobile-Client-push-notification>
- **功能缺口**：「Login with passkey」（无密码账户解密）和完整 public/org API 未（完全）实现。
- ⚠️ **2026 活跃协议分裂**：官方客户端 v2026.4.0+ 发出新 EncString 格式，而 Vaultwarden 1.36 仍服务 2025.12 schema，产生 `EncString(InvalidTypeSymm)` 失败。Android 先坏（约 2026 春），随后 Chrome/Edge、Firefox；web vault v2026.4.1 仍正常。
- ⚠️ **「type 60」误诊已被核实纠正**：vaultwarden 维护者 BlackDex 指出 Vaultwarden 不做任何 SDK/加密工作，`InvalidTypeSymm`/"got type 60" 是**客户端 SDK 解析损坏或明文数据**（常由第三方工具如 n8n 写入未加密字段所致）——"60" 是非 EncString 字符串首字节（ASCII `<` = 0x3C = 60）的十进制。这**不是**新格式/旧服务器不匹配的症状。但防御建议仍成立：对未知 EncString type 前缀软失败。
  来源：<https://github.com/dani-garcia/vaultwarden/discussions/7334> ｜ <https://github.com/dani-garcia/vaultwarden/discussions/7177>

**设计含义**：固定并声明一个测试过的客户端/SDK 协议版本；对 bitwarden.com 与当前 Vaultwarden **两者**都做集成测试（它们可能差几周）；服务器返回更新的 EncString 格式时给出清晰错误而非崩溃。

---

## 加密架构

### 密钥层级（key hierarchy）总述

```
Master Password ──(KDF: PBKDF2-SHA256 或 Argon2id; salt 见下)──> Master Key (32B)
   │
   ├─(PBKDF2 iters=1, salt=password)──> Server Auth Hash  ──> 发给服务器（OAuth password 字段）
   ├─(PBKDF2 iters=2, salt=password)──> Local Unlock Hash ──> 本地离线解锁验证
   │
   └─(HKDF-Expand-SHA256, info "enc"||"mac")──> Stretched Master Key = Aes256CbcHmacKey(32B enc + 32B mac)
          │
          └─(AES-256-CBC + 验证 HMAC, 解 type-2 EncString)──> User Key (64B = 32B AES + 32B HMAC)  ← 根数据密钥
                 │
                 ├──> per-cipher Cipher Key (64B, cipher.key 字段, type-2 包裹)  ──> 解该 item 各字段
                 ├──> RSA-2048 私钥 (PKCS8-DER, type-2 包裹)  ──> 解 org keys / emergency / TDE
                 │       └──> Org Symmetric Key (经 type-4 = RSA-OAEP-SHA1 用成员公钥包裹)  ──> 解 org items
                 └──> Attachment Key (经 Cipher Key 包裹)  ──> 解附件文件 blob
```

### KDF（必须字节精确，否则哈希/解密静默失败）

**PBKDF2（kdf:0）** — 已核实**确认**：
- `Master Key = PBKDF2-HMAC-SHA256(password, salt = email.trim().to_lowercase().as_bytes(), iterations)`，输出 **32 字节**。
- salt 是**裁剪+小写后直接用，不做 SHA-256**（这是与 Argon2id 路径的关键区别，也是最常被搞错的地方）。
- 默认 iterations = 600,000；`PBKDF2_MIN_ITERATIONS = 5000`（低于此报 `InsufficientKdfParameters`）；代码中无硬上限。
- 数字 KDF id（`PBKDF2_SHA256 = 0`, `Argon2id = 1`）定义在 server 的 `KdfType.cs`，是 wire 编码；SDK 的 Rust `Kdf` enum 本身按 camelCase 变体名序列化。
- 来源：<https://raw.githubusercontent.com/bitwarden/sdk-internal/main/crates/bitwarden-crypto/src/keys/kdf.rs> ｜ <https://raw.githubusercontent.com/bitwarden/sdk-internal/main/crates/bitwarden-crypto/src/util.rs> ｜ <https://raw.githubusercontent.com/bitwarden/server/main/src/Core/Enums/KdfType.cs>

**Argon2id（kdf:1）** — 已核实，含**重要纠正**：
- `Master Key = Argon2id(password, salt = SHA-256(normalized_email) 的 32 字节原始摘要, memory, iterations, parallelism)`，输出 32 字节。
- ❗ **纠正**：`normalized_email = email.trim().to_lowercase()`——邮箱**先规范化（裁剪+小写）再做 SHA-256**，**不是**对原始邮箱字符串做 SHA-256。两条 KDF 分支共享 `derive_kdf_key`，由 `derive()` 统一传入 `email.trim().to_lowercase().as_bytes()`。用原始未规范化邮箱会算出不兼容的 key 而破坏跨客户端兼容。
- 参数：`Argon2::new(Algorithm::Argon2id, Version::V0x13, params)`；`Params::new(memory.get()*1024, iterations, parallelism, Some(32))`（memory 单位 MiB→KiB）。
- 默认：memory 32 MiB、iterations 6、parallelism 4。下限：`ARGON2ID_MIN_MEMORY = 16 MiB`、`MIN_ITERATIONS = 2`、`MIN_PARALLELISM = 1`；无上限。
- ⚠️ **默认值来源有分歧**：help/kdf-algorithms 写 32 MiB/6/4，而 whitepaper 上下文提到 64 MiB/3/4——**务必读 prelogin 响应**，不要硬编码。
- 来源：<https://sdk-api-docs.bitwarden.com/src/bitwarden_crypto/keys/kdf.rs.html>

**认证/本地哈希** — 已核实**确认**：
- `derive_master_key_hash(password, purpose)` = `B64(pbkdf2(payload = MasterKey, salt = password, rounds = purpose))`，`HashPurpose` 的判别值**就是迭代次数**：`ServerAuthorization = 1`（发服务器），`LocalAuthorization = 2`（本地离线验证）。
- 服务器收到后再用随机 salt + 600,000 iters 重新哈希存储。
- 来源：<https://raw.githubusercontent.com/bitwarden/sdk-internal/main/crates/bitwarden-crypto/src/keys/master_key.rs>

**Stretched Master Key** — 已核实**确认**：
- `stretch_key(masterKey: [u8;32]) -> Aes256CbcHmacKey { enc: hkdf_expand(key, "enc"), mac: hkdf_expand(key, "mac") }`。
- HKDF-**Expand**（无 extract 步；PRK = 32B master key 直接当 PRK）+ SHA-256，每段 32 字节输出，info 为字面 ASCII `"enc"` / `"mac"`，拼成 64 字节。
- 来源：<https://raw.githubusercontent.com/bitwarden/sdk-internal/main/crates/bitwarden-crypto/src/keys/utils.rs>

### EncString / CipherString 线格式

格式 `type.b64iv|b64ct|b64mac`（对称）或 `type.b64data` / `type.b64data|b64mac`（RSA）。IV=16B，MAC=32B，全部标准 base64。解析：先按 `.` 分出整数 type，再按 `|` 分段。

| type | 名称 | 说明 |
|------|------|------|
| 0 | `AesCbc256_B64` | 2 段 `iv\|data`，**无 MAC，已弃用，解密被故意阻断**（防降级） |
| 1 | `AesCbc128_HmacSha256_B64` | 已从现行代码移除 |
| 2 | `AesCbc256_HmacSha256_B64` | 3 段 `iv\|ct\|mac`，**当前对称格式**（3 段是正常的，2026 某 bug 报告称非正常是错的） |
| 3 | `Rsa2048_OaepSha256_B64` | 1 段，非对称 |
| 4 | `Rsa2048_OaepSha1_B64` | 1 段，**当前活跃的非对称包裹格式**（org key 分发） |
| 5 | `Rsa2048_OaepSha256_HmacSha256_B64` | 2 段 |
| 6 | `Rsa2048_OaepSha1_HmacSha256_B64` | 2 段 |
| 7 | `Cose_Encrypt0_B64` / CoseEncrypt0 | 1 段（原始 COSE_Encrypt0 字节，XChaCha20-Poly1305 AEAD）⚠️ v2，逐步推出中 |

> ⚠️ **注意 type-4 不是对称类型**（核实纠正）：现行对称类型是 0 和 2；type 4 是**非对称** RSA EncString。原研究多处把 type 4 与对称混淆。

来源：<https://raw.githubusercontent.com/bitwarden/clients/main/libs/common/src/platform/enums/encryption-type.enum.ts> ｜ <https://raw.githubusercontent.com/bitwarden/sdk-internal/main/crates/bitwarden-crypto/src/enc_string/symmetric.rs>

### 各类对象加密

- **User Key**：64 字节 AES-256-CBC + HMAC-SHA256 key（32B enc + 32B mac），作为 type-2 EncString 由 stretched master key 解出（解前先验 HMAC）。`decrypt_user_key` 对 type-7 路径返回 `CryptoError::OperationNotSupported(UnsupportedOperationError::DecryptionNotImplementedForKey)`，目前只支持 type 0 与 type 2。
- **Per-item**：AES-256-CBC + encrypt-then-MAC（HMAC-SHA256，对 `IV||ciphertext`，验证后再解，常量时间比较）。每个 cipher 有可选 64B `cipher.key`（type-2 包裹）；存在时该 item 各字段（name、login.username/password、notes、fido2Credentials.* 等）用 cipher key 加密，缺省时直接用 User/Org key。
- **附件**：见上文 API 节。
- **RSA 密钥对**：RSA-2048；私钥 PKCS8-DER 经 User Key 包裹为 type-2 EncString；公钥 SPKI-DER 明文。`RsaOaepSha1` = type 4，用于包裹 org 对称 key、emergency access、trusted-device。
- **Send**：随机 128-bit secret key 经 HKDF-SHA256 expand（name/salt `"send"`，info `"send"`）成 64B AES-256-CBC+HMAC key。128-bit seed 是访问 URL fragment（`#/send/<id>/<key>`）里的 base64url 值，**从不发服务器**。Send 上的密码仅作认证门（哈希后发，**非密钥材料**）。访问 `POST /api/sends/access/{id}`。
- **Passkey / FIDO2**：存于 `login.fido2Credentials[]`，**每个字段都是加密 EncString**（除 `creationDate` 明文 ISO-8601）。结构（serde camelCase）：`credentialId, keyType, keyAlgorithm, keyCurve, keyValue, rpId, userHandle?, userName?, counter, rpName?, userDisplayName?, discoverable, creationDate`。解密后约定：`keyType="public-key"`, `keyAlgorithm="ECDSA"`, `keyCurve="P-256"`, `keyValue=base64url PKCS8 DER 的 P-256 私钥`, `counter` 通常 "0"。

### MAC 验证陷阱（高频且难调）

- 每个 cipher 可携带 per-item 64B Cipher Key（`key` 字段，本身是用 user/org key 加密的 EncString）。存在时 item 字段用 **cipher key** 而非 user key 做 MAC。
- ❗ 第三方实现的 MAC 失败常源于**未对解密后的 cipher key 做 PKCS#7 unpadding** 就拿去当 HMAC key。务必：解密 cipher key → PKCS#7 unpad → 才用作 HMAC key。
- type 2：HMAC-SHA256 over `(iv || ciphertext)` 用 32B mac 半段；MAC 不匹配则**解密前**拒绝；常量时间比较防 timing oracle。
- 来源：<https://community.bitwarden.com/t/mac-validaton-when-cipher-key-exists/73043>

### 已移除/可忽略

- **遗留 type-0 user key（pre-2017）**：服务端已于 2025-06-24（server 2025.6.2）移除；新客户端无需为登录支持，SDK 也阻断 type-0 解密。
- **Key Connector / TDE（SSO 信任设备）**：替代解锁路径（绕过 master-key 派生但到达同一 User Key），master-password-only 客户端初期可忽略。

### Account crypto v2（type 7） ⚠️ 经核实，状态已更新

- type 7 = `Cose_Encrypt0_B64`，单 base64 段的原始 COSE_Encrypt0 字节（XChaCha20-Poly1305 AEAD），是加密的首选变体；签名机制存在：`keys/signed_public_key.rs` + `signing/` 模块（`SignatureAlgorithm::Ed25519` 默认）。
- ❗ **核实纠正"rollout 时间线未找到"**：实际**可查**——server v2026.5.0（2026-05-29，PM-27278）给 `RegisterFinishRequestModel` 加了 `AccountKeysRequestModel` 以支持 v2，应用于**新账户注册**并扩展到更多注册方式（JIT password signups）。即 v2 正在推出（新账户优先），既有账户迁移进行中。
- **结论**：Swift 客户端先做 type-2 对称 + RSA 非对称（type 4），把 type 7 当 opt-in 特性门控，待账户迁移再实现。
- 来源：<https://github.com/bitwarden/server/releases/tag/v2026.5.0> ｜ <https://contributing.bitwarden.com/architecture/cryptography/crypto-guide/>

---

## AutoFill 与 Passkey 扩展

### 扩展生命周期（已核实**确认**，极精确）

主类继承 `ASCredentialProviderViewController`（`UIViewController`/`NSViewController` 子类；iOS 12.0+ / iPadOS 12.0+ / Mac Catalyst 14.0+ / macOS 11.0+ / visionOS 1.0+，所有方法同可用性）。系统驱动：

- `provideCredentialWithoutUserInteraction(for: any ASCredentialRequest)` — 静默路径，**不可显示 UI**（VC 未呈现）。若库锁定无法静默返回，必须调 `extensionContext.cancelRequest(withError:)`，`NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userInteractionRequired.rawValue)`（raw value 100）。系统随后丢弃视图并重新调用 VC，转 `prepareInterfaceToProvideCredential(for:)` 显示解锁 UI。**不要在静默路径阻塞等待生物识别。**
- `prepareInterfaceToProvideCredential(for: any ASCredentialRequest)` — 显示解锁/选择 UI。
- `prepareCredentialList(for: [ASCredentialServiceIdentifier])` — 选择器。
- `prepareCredentialList(for:requestParameters: ASPasskeyCredentialRequestParameters)` — passkey/password 列表变体。
- `prepareInterface(forPasskeyRegistration: any ASCredentialRequest)` — passkey 创建。
- `prepareOneTimeCodeCredentialList(for:)` — OTP。
- `prepareInterfaceForExtensionConfiguration()` — 从设置打开。

完成（`ASCredentialProviderExtensionContext`，completionHandler 均为可选 `((Bool)->Void)?`）：`completeRequest(withSelectedCredential:completionHandler:)`、`completeAssertionRequest(using:completionHandler:)`、`completeRegistrationRequest(using:completionHandler:)`、`completeOneTimeCodeRequest(using:completionHandler:)`；`cancelRequest(withError:)`（继承自 `NSExtensionContext`）。

> 单参数 `ASPasswordCredentialIdentity` 重载的 `provideCredentialWithoutUserInteraction(for:)` 与 `prepareInterfaceToProvideCredential(for:)` 已**弃用**，用 `any ASCredentialRequest` 重载。

来源：<https://developer.apple.com/documentation/AuthenticationServices/ASCredentialProviderViewController> ｜ <https://developer.apple.com/tutorials/data/documentation/authenticationservices/asextensionerror/code/userinteractionrequired.json>

### 能力声明（已核实，含版本纠正）

- 实体权限 `com.apple.developer.authentication-services.autofill-credential-provider = true` 加到**主 App 与扩展两个 target**（在 Xcode 启用 "AutoFill Credential Provider" capability）。
- 扩展 Info.plist：`NSExtension > NSExtensionPointIdentifier = com.apple.authentication-services-credential-provider-ui`（`NSExtensionPrincipalClass` 指向你的 VC 子类），`NSExtension > NSExtensionAttributes > ASCredentialProviderExtensionCapabilities` 字典（全 Boolean）。
- ❗ **版本纠正**：并非全部 6 个键都是 iOS 17/macOS 14。字典本身 + `ProvidesPasswords` + `ProvidesPasskeys` + `ShowsConfigurationUI` 是 **iOS 17.0 / macOS 14.0**；而 `ProvidesOneTimeCodes`、`ProvidesTextToInsert`、`SupportsConditionalPasskeyRegistration` 是 **iOS 18.0 / macOS 15.0 / visionOS 2.0**。
- 26+ 加 `SupportsCredentialExchange = YES` 和 `SupportedCredentialExchangeVersions = ["1.0"]`。
- 来源：<https://developer.apple.com/tutorials/data/documentation/BundleResources/Information-Property-List/NSExtension/NSExtensionAttributes/ASCredentialProviderExtensionCapabilities.json>

### 凭据身份存储（QuickType 栏）

每次同步后把身份写入 `ASCredentialIdentityStore.shared`（**不存密码**，仅站点+用户名元数据，存于 App 容器，卸载自动清除）：

- `ASPasswordCredentialIdentity`（`serviceIdentifier, user, recordIdentifier=你的 vault item id, rank`）。
- `ASPasskeyCredentialIdentity(relyingPartyIdentifier:userName:credentialID:userHandle:recordIdentifier:)`。
- `ASOneTimeCodeCredentialIdentity`（OTP）。
- 先 `getState(_:)` 检查 `.isEnabled`；若 `state.supportsIncrementalUpdates` 用 `saveCredentialIdentities`/`removeCredentialIdentities` 做增量，否则 `replaceCredentialIdentities` 全量替换。
- **从主 App（内存更充裕）在后台队列执行**，每次 `/api/sync` 后重建。
- 来源：<https://developer.apple.com/documentation/authenticationservices/ascredentialidentitystore/savecredentialidentities(_:completion:)-1bbx6>

### Passkey：扩展即软件 WebAuthn authenticator

- `ASPasskeyCredentialRequest` 暴露 `clientDataHash: Data`（系统**预哈希**，非原始 challenge）、`userVerificationPreference`、`supportedAlgorithms`（COSE alg id，如 -7 ES256）。
- 列表/条件断言用 `ASPasskeyCredentialRequestParameters`：`relyingPartyIdentifier, clientDataHash, userVerificationPreference, allowedCredentials: [Data], extensionInput`。
- **断言**：构造 `authenticatorData`（32B `SHA-256(rpId)` + flags 字节含 UP/UV + 4B signCount），用存储的私钥签 `(authenticatorData || clientDataHash)`，返回 `ASPasskeyAssertionCredential(userHandle:relyingParty:signature:clientDataHash:authenticatorData:credentialID:)` → `completeAssertionRequest(using:)`。
- **注册**：生成密钥对，构造 CBOR `attestationObject`（密码管理器用 `none` attestation），返回 `ASPasskeyRegistrationCredential(relyingParty:clientDataHash:credentialID:attestationObject:)` → `completeRegistrationRequest(using:)`。
- 两类均 iOS 17.0+ / macOS 14.0+，有 `extensionOutput` 变体（PRF/largeBlob）。
- 来源：<https://developer.apple.com/documentation/authenticationservices/aspasskeyassertioncredential>

### 扩展内解锁（unlock-in-extension）

- 经 **App Group** 容器共享加密 vault DB；把解包 user key 的密钥存到**共享 Keychain access group**（`kSecAttrAccessGroup`），App 与扩展都能读。
- 访问控制：`SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error)`，设为 `kSecAttrAccessControl`。`.biometryCurrentSet` 在生物识别集合变化时使密钥失效（比 `.biometryAny` 更安全）。
- 读取：建 `LAContext`，经 `kSecUseAuthenticationContext` 传入 `SecItemCopyMatching` 查询——系统弹 Face ID/Touch ID/Optic ID，成功才返回密钥，用户无需输入主密码。
- **把密钥藏在生物识别后**（而非仅用 `evaluatePolicy` 验证生物识别，后者可被绕过）。
- 来源：<https://developer.apple.com/documentation/LocalAuthentication/accessing-keychain-items-with-face-id-or-touch-id>

### 硬约束：~120 MB 内存预算

- 多个密码管理器报告 iOS AutoFill 扩展上限约 **120 MB**（含代码、库、UI、DB、解密临时空间）。
- **Argon2id 内存直接竞争此预算**：KeePass 系要求 Argon2 内存 < ~32 MB 才安全，Bitwarden 在 Argon2id 内存 > 64 MB 时警告。超限会 "Not enough memory" 或静默终止（sheet 消失）。
- 设计：在扩展里**只解密选中项**（非整库）、流式处理附件、`completeRequest` 后立即释放解密缓冲、对 AutoFill-关键库的高内存 Argon2id 给出警告/上限（建议 PBKDF2 或低内存 Argon2）。⚠️ Apple 不公开保证数字，应在目标 OS 上实测。
- 来源：<https://keepassium.com/articles/autofill-memory-limits/> ｜ <https://github.com/bitwarden/mobile/issues/2389>

### macOS 差异

- 同一 `ASCredentialProviderViewController` API（passwords macOS 11+，passkeys macOS 14+）。
- 启用路径：System Settings > General > AutoFill & Passwords。无软键盘 QuickType 栏（行内字段自动完成）；窗口式 UI（AppKit/Catalyst）；**无法用 MDM 强制启用第三方提供者**。系统 UI 锚定用 `ASPresentationAnchor`（macOS 上为 `NSWindow`）。
- iOS 26/macOS 26 允许同时选最多 3 个凭据管理器，可按字段切换提供者。

### iOS/macOS 26 vs 27 关键差异（已核实，含重大版本纠正）

**iOS 26 / macOS 26（2026）真正新增：**
- **Credential Exchange（CXF/CXP）**：`ASCredentialExportManager(presentationAnchor:)` / `ASCredentialImportManager`，加密的 app-to-app 导入导出（FIDO CXF 格式）。导出 `requestExport(for:)` → `exportCredentials(_:)`；导入声明 `NSUserActivityTypes` 含 `ASCredentialExchangeActivityType`，系统以含 `ASCredentialImportToken`(UUID) 的 NSUserActivity 启动，`importCredentials(token:)`。SwiftUI 环境 `\.credentialExportManager`/`\.credentialImportManager`。数据模型映射 `ASImportableItem` / `ASImportableCredential`（enum：`basicAuthentication, passkey, totp, note, creditCard, address, apiKey, customFields, ...`）。
- **`ASCredentialUpdater`**（iOS 26.0/macOS 26.0）Signal/update API：`reportPublicKeyCredentialUpdate(relyingPartyIdentifier:userHandle:newName:)`、`reportAllAcceptedPublicKeyCredentials(relyingPartyIdentifier:userHandle:acceptedCredentialIDs:)`、`reportUnusedPasswordCredential(domain:username:)`。Web 镜像 `PublicKeyCredential.signalCurrentUserDetails()`/`signalAllAcceptedCredentials()`（**Safari 26**，非 Safari 19）。
- **`ASAuthorizationAccountCreationProvider`**：账户创建流，`createPlatformPublicKeyCredentialRegistrationRequest(acceptedContactIdentifiers:shouldRequestName:relyingPartyIdentifier:challenge:userID:)`。
- well-known URL `/.well-known/passkey-endpoints`（复数，无 `.json` 扩展名），返回可选 `enroll`/`manage` 键。

> ❗ **重大版本纠正**：**自动 passkey 升级 / 条件式注册**（`RequestStyle.conditional`、`SupportsConditionalPasskeyRegistration` 能力键、`prepareInterface(forPasskeyRegistration:)`）实为 **iOS 18.0 / macOS 15.0**（WWDC24）特性，**不是 iOS 26 新增**。原研究把它错误归入 iOS 26。客户端应针对 **iOS 18** 做条件式注册，**iOS 26** 做 Signal/account-creation。

**iOS 27 / macOS 27（WWDC 2026） ⚠️ 后截止、依赖二手来源：**
- iOS 26 ("Liquid Glass" 版本) 的 AutoFill 行为变化已**确认**：(a) 多字段 OTP autofill 在 iOS 26.0.1–26.3 回归——整串验证码粘进单个 `UITextField` 而非分散到各位字段，仅在首字段设 `textContentType=.oneTimeCode` 不足以恢复（vs iOS 15–18），需手动分发；(b) 部分用户见 passkey AutoFill 默认到 "Scan a QR Code"。这些 sheet 由 iOS AutoFill 渲染，凭据管理器无法控制其外观。
- **无任何 Liquid-Glass 专属的 credential-provider API**——系统自动重绘 picker/keyboard。注意：App 内标准组件的自动重绘需用 **Xcode 26 SDK** 构建（`UIDesignRequiresCompatibility` 可退出）；但你的**自定义**扩展 UI 不会被自动重绘，需手动适配。
- 来源：<https://developer.apple.com/forums/thread/807907> ｜ <https://developer.apple.com/videos/play/wwdc2025/279/> ｜ <https://developer.apple.com/documentation/authenticationservices/ascredentialupdater>

**设计含义**：所有 26+ 特性用 `#available(iOS 26, macOS 26, *)` 门控，保持 iOS 17/macOS 14 基线完全可用（条件式注册门控到 iOS 18）。

---

## Liquid Glass 设计语言

### 核心原则（iOS/macOS 26，已确认且权威）

- **两层系统**：半透明"功能层"（控件/导航）浮于"内容层"之上，反射/折射环境、投影、"lensing"。**玻璃只用于 chrome**（工具栏、标签栏、侧栏、浮动按钮、搜索），**绝不用在正文内容后面**。
- 两个变体：`regular`（模糊 + 调亮度保证文字可读）、`clear`（更透明，用于富媒体背景）。
- 三原则：Hierarchy、Harmony、Consistency。**不要**玻璃叠玻璃；**不要**把玻璃放内容层；色彩/tint 要克制。
- **标准 SwiftUI/UIKit/AppKit 控件重编译即自动获得材质**（需用新 Xcode/SDK 构建，仅升部署目标不够）。
- 来源：<https://developer.apple.com/documentation/TechnologyOverviews/liquid-glass> ｜ <https://developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass>

### 确认可用的第 1 代 SwiftUI API（iOS/macOS 26.0+）

| API | 用途 |
|-----|------|
| `.glassEffect(_ glass: Glass = .regular, in shape: some Shape = DefaultGlassEffectShape())` | 给**自定义**视图加材质（默认 Capsule 形状）。标准控件已自带，勿重复加 |
| `Glass` 变体：`.regular` / `.clear` / `.identity` + `.tint(Color?)` + `.interactive(Bool)` | 可组合：`.glassEffect(.regular.tint(.blue).interactive())`。`.identity` = 无效果 |
| `GlassEffectContainer(spacing:)` | 分组玻璃形状使其混合/变形并高效渲染 |
| `.glassEffectID(_:in: Namespace.ID)` | 配 `@Namespace` 做过渡时形状互相动画 |
| `.glassEffectUnion(id:namespace:)` | 把多视图几何合并成**一个**玻璃形状（须同形状+变体） |
| `.buttonStyle(.glass)` / `.glassProminent` | 玻璃按钮（浮动 "+" 加项按钮用 `.glassProminent`） |
| `.backgroundExtensionEffect()` | 把内容镜像+模糊延伸到侧栏/inspector 下（详情列 hero）。"谨慎使用"，通常单个实例 |
| `.scrollEdgeEffectStyle(_:for:)` | 控制内容在浮动玻璃栏下淡入/模糊（`.automatic`/`.hard`/`.soft`） |
| `.tabBarMinimizeBehavior(_:)` | 滚动时最小化标签栏（`.onScrollDown` 已确认） |
| `.tabViewBottomAccessory(content:)` | 标签栏上方放置视图（标签栏最小化时内联折叠） |
| `ToolbarSpacer(.fixed/.flexible, placement:)` | 把工具栏项分成独立玻璃胶囊 |
| `ConcentricRectangle` / `Shape.rect(corners:isUniform:)`（UIKit `UICornerConfiguration`） | 同心圆角（卡片行、sheet、浮动按钮） |
| `searchable(text:placement:prompt:)` / `Tab(role: .search)` / `searchToolbarBehavior(_:)` | 搜索（iPhone 底部、iPad/Mac 顶部尾随） |

来源：<https://developer.apple.com/documentation/swiftui/view/glasseffect(_:in:)> ｜ <https://developer.apple.com/documentation/swiftui/glasseffectcontainer> ｜ <https://developer.apple.com/documentation/swiftui/view/backgroundextensioneffect()>

### iOS 27 / macOS 27 "Golden Gate" ⚠️ 后截止，分两类

**经 Apple 官方文档确认（不再是传言）：**
- `UIDesignRequiresCompatibility` 退出开关：Apple 官方文档明确"系统在你为 iOS/iPadOS/Mac Catalyst/macOS/tvOS 27+ 构建时**忽略此键**"——即 iOS 27 SDK 下 Liquid Glass 采用**实质强制**。键未被删除，只是被忽略。
  来源：<https://developer.apple.com/documentation/bundleresources/information-property-list/uidesignrequirescompatibility>
- 以下 SwiftUI 符号经 Apple docs JSON 可用性徽章确认为 **iOS 27.0 beta** 新增：`visibilityPriority(_:)`(ToolbarContent)、`ToolbarOverflowMenu`、`ToolbarItemPlacement.topBarPinnedTrailing`、`toolbarMinimizeBehavior(_:for:)` + `ToolbarMinimizeBehavior.onScrollDown`、`TabRole.prominent`（`Tab(role: .prominent)`）、`reorderable()`(DynamicViewContent/ForEach)、`swipeActionsContainer()`（使 swipeActions 可用于 List 之外，**须显式加此修饰符**）、`alert(_:item:actions:)` 与 `confirmationDialog(_:item:titleVisibility:actions:)` 的 item-binding 重载。

**经 Apple 文档纠正/否定的传言：**
- ❗ `appearsActive` **不是** iOS 27 新增——它早在 **iOS 18.0 / macOS 10.15** 就有。
- ❗ reorder 容器修饰符是 `reorderContainer(for:isEnabled:move:)`（及 `in:`/`itemID:` 重载），**不是** `reorderContainer(for:)`；`move:` 闭包（返回 `ReorderDifference`）必需。
- ⚠️ `@State` 变 macro + `@Observable` 惰性初始化（据称回溯部署到 iOS 17/macOS 14）：社区多源支持但未对到 Apple 官方可用性徽章，低置信。

**用户可见变化（仅二手 WWDC 2026 报道）⚠️：**
- 全系统**渐变透明度滑块**（clear/ultraclear → opaque/fully tinted），取代 iOS 26 的二元控制，回应可读性投诉；默认外观改变、background diffusion 改善（暗边 + 更亮镜面高光增强深度/对比）。
- macOS 27 "Golden Gate"：System Settings > Appearance 下全局滑块、更紧/统一的窗口圆角（甚至应用于第三方 App）、统一工具栏、边到边（非浮动）侧栏。注："Golden Gate" 是 macOS 27 的**公开营销名**（加州地名惯例），**内部代号**是 "Honeycrisp"→"Fizz"。
- ⚠️ **无确认的 iOS 27 专属 Liquid Glass 修饰符**；相关 API（`.glassEffect()` 等）就是既有 iOS 26 API，iOS 27 带来精炼的设计 token + 用户强度滑块。自定义 `.glassEffect` 表面应重新审计以尊重新用户透明度偏好（如读 `accessibilityReduceTransparency` 把 `.regular` 切 `.identity`）。
- 来源：<https://www.macrumors.com/2026/06/08/apple-announces-liquid-glass-improvements/> ｜ <https://www.macrumors.com/2026/06/09/macos-golden-gate-liquid-glass/> ｜ <https://developer.apple.com/documentation/macos-release-notes/macos-27-release-notes>

### 无障碍（对安全 App 至关重要）

- 标准组件在 Reduce Transparency / Increased Contrast / Reduce Motion 下自动适配；**自定义玻璃必须实测这三项并提供不透明回退**（读 `@Environment` 的 reduce-transparency / differentiate-without-color / reduce-motion）。
- **绝不**把可复制的密码、OTP 或敏感字段渲染在 clear glass 且背景繁忙处——用 `.regular` 变体或实心 scrim 保证可读。
- 来源：<https://developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass>

### list/detail 模式

- **macOS 三栏**：`NavigationSplitView { 分类侧栏 } content: { 项列表 } detail: { 详情 + inspector }`。侧栏作为玻璃浮于内容上；`.inspector(isPresented:)` 看密码详情/元数据；详情列 hero 用 `.backgroundExtensionEffect()`。提供 `MenuBarExtra` 做快速解锁/搜索（依赖标准 chrome 自动获得材质）。macOS 27 ⚠️ 据报统一工具栏 + 边到边侧栏。
- **iOS**：用 `List`、`TabView`、`searchable`、浮动 `.glassProminent` "+" 按钮（多浮动按钮包进 `GlassEffectContainer` + `.glassEffectID`）。列表行保持不透明（内容层），用 `ConcentricRectangle` 做卡片圆角，`.scrollEdgeEffectStyle` 让行在玻璃栏下可读地淡出。

**核心设计含义**：**不要手搓玻璃**——用标准控件 + 重编译让系统自动应用并适配无障碍；`.glassEffect()` 只留给真正自定义表面。

---

## Swift 架构与安全存储

### 包结构

平台无关的 **Core Swift Package**（models、crypto、API、sync、repositories），被薄 iOS/macOS App target + 一个 AutoFill 扩展共用；App Group + 共享 Keychain access group 桥接。镜像官方分层：

- Core（无 UIKit/AppKit/SwiftUI）：Models、DataStores、KeychainRepository、Services（如 CipherService）、Repositories（VaultRepository、AuthRepository），全部进 ServiceContainer + `Has<Service>` 协议 DI。
- 平台代码用协议或 `#if os()` 门控。
- Targets：app(iOS)、app(macOS)、AutoFillExtension，加本地 Networking package。
- 来源：<https://contributing.bitwarden.com/architecture/mobile-clients/ios/>

### Crypto 栈（CryptoKit 缺口 + 补齐）

CryptoKit/swift-crypto 覆盖：`AES.GCM`、`ChaChaPoly`、HKDF、HMAC、SHA256/384/512、`SymmetricKey`、P256/384/521、Curve25519、`SecureEnclave.P256`。**不覆盖** Bitwarden 需要的 4 个原语，补齐如下：

| 缺口 | 补齐方案 |
|------|---------|
| AES-256-CBC | CommonCrypto `CCCrypt`（或 CryptoSwift） |
| PBKDF2 | CommonCrypto `CCKeyDerivationPBKDF` |
| Argon2id | 经审计的 Swift 绑定（Argon2Swift / swift-argon2 / libsodium）；v0x13，salt = 原始 SHA-256(规范化邮箱) 32B |
| RSA-2048-OAEP | Security `SecKeyCreateDecryptedData` + `kSecKeyAlgorithmRSAEncryptionOAEPSHA1/SHA256`（或 swift-crypto `_RSA`） |
| HKDF / HMAC / SHA / P-256 | 直接用 CryptoKit |
| （type 7）XChaCha20-Poly1305 / COSE | 后续，门控 |

集中到一个 crypto 模块，精确匹配 Bitwarden 的 EncString 类型与 KDF 常量。用 `SecureBytes`/锁定缓冲模式清零密钥材料（对应 SDK 的 `Pin<Box<>>`）。
来源：<https://developer.apple.com/documentation/cryptokit> ｜ <https://www.andyibanez.com/posts/cryptokit-not-enough/>

### Rust SDK vs 纯 Swift 决策 — ❗ 关键，核实**推翻**了原结论

- 原研究："`sdk-internal` 现为纯 GPL-3.0，UniFFI Swift 复用合法可行（仅 GPL 缠累）。" **被核实推翻为 REFUTED。**
- **实情**：`sdk-internal` 是**双许可（GPL-3.0 OR Bitwarden SDK License v2.0，日期 2025-10-07）**，`bitwarden_license/` 目录下仅 SDK License。SDK License **仍含** "You may not use this SDK to develop applications for use with software other than Bitwarden (including non-compatible implementations of Bitwarden)"，且 "Compatible Application" 定义为连接 **Bitwarden 服务器产品**——所以面向 Vaultwarden 的客户端处于灰区甚至禁区。
- **对闭源 App Store 客户端，两个分支都不可用**：GPL-3.0 与闭源 App Store 分发冲突；SDK License 禁止非 Bitwarden/非兼容（Vaultwarden-only）使用。
- 此外 SDK 是 ~102 MB 压缩的预编译 xcframework（BitwardenFFI，多架构切片），UniFFI 构建复杂、类型不透明。passkey 支持在 `bitwarden-fido` crate（**非** "bitwarden-fido2"，包裹 Bitwarden 的 passkey-rs fork）。
- **决策**：**纯 Swift 重写**（包裹 CommonCrypto/Security/argon2），保留许可证与 App Store 选项。代价是自己正确实现 EncString、密钥层级、KDF、passkey/FIDO2。
- 来源：<https://raw.githubusercontent.com/bitwarden/sdk-internal/main/LICENSE> ｜ <https://raw.githubusercontent.com/bitwarden/sdk-internal/main/LICENSE_SDK.txt> ｜ <https://raw.githubusercontent.com/bitwarden/sdk-swift/main/Package.swift>

### Keychain / Secure Enclave 解锁

- Secure Enclave 只存 EC P-256 key（`kSecAttrTokenIDSecureEnclave`, `kSecAttrKeyTypeECSECPrimeRandom`）；`SecAccessControlCreateWithFlags(kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet])`。
- SE 不能直接存对称 user key，所以**把 user key 用 SE 公钥 ECIES 加密**，密文存 Keychain（`kSecAttrAccessGroup` = App Group 共享组 + `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`）。
- App 与扩展经 App Group 实体权限 + 同一 Keychain access group 共享；`LAContext` 生物识别解锁。
- 自动锁定：超时/进入后台时清除内存中的 user key。
- ⚠️ macOS Secure Enclave + Touch ID 在 Apple Silicon vs Intel 上的一致性与 Intel 回退需确认（开放问题）。
- 来源：<https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave>

### 离线缓存（已核实，含纠正）

- 用 **GRDB + SQLCipher**（SwiftData 无 SQLCipher 路径；Core Data 技术上可经自定义 `NSIncrementalStore`/encrypted-core-data，但该路线 2014 年起停维护，故 GRDB 是正选）。
- 加密：`config.prepareDatabase { db in try db.usePassphrase(keyData) }`（接受 String 或 Data，GRDB 不保留口令）。**DB key 用 Keychain 里的随机值（非主密码）**；解包的 user key 只留内存，绝不入库。
- GRDB **7.10.0**（2026-02-15）让 SQLCipher-over-SPM "可行但仍不容易"：当前须 fork GRDB 改 `Package.swift`；SPM 会下载未用依赖（CocoaPods 更顺）。
- ❗ **纠正 "SQLCipher 保护的明文元数据" 例子**：Bitwarden 把几乎所有敏感字段都加密为 EncString——**包括 item names、notes、custom fields、URIs/URLs、folder NAMES**，这些**已是 E2E 加密**，SQLCipher 不"保护"它们。SQLCipher 的真正价值是 (a) 对已加密 blob 的纵深防御，(b) 保护真正明文的元数据：item type、created/updated/deleted 时间戳、cipher/user/org UUID、folder **成员关系**（非 folder 名）、favorite、reprompt flag，以及客户端本地构建的明文搜索索引。
- 共享 App Group 容器的 SQLCipher 还需设 `PRAGMA cipher_plaintext_header_size = 32`（并自管 salt），用 WAL/NSFileCoordinator/挂起处理避免 `SQLITE_BUSY` 与 `0xDEAD10CC`。
- 来源：<https://forums.swift.org/t/grdb-v7-10-0-android-linux-windows-and-sqlcipher-spm/84754> ｜ <https://bitwarden.com/help/vault-data/>

### 并发 + 状态（已核实**确认**）

- Swift 6 严格并发：sync 引擎与共享可变缓存（in-flight 请求、sync cursor）建模为 **actor**（数据竞争变编译错误）；UI 可观察模型 `@MainActor`。注：Swift 6.2/Xcode 26 下 MainActor 成新 App target 的**默认隔离**，故 `@MainActor` 常隐式。actor + Sendable 只消除低层**数据**竞争，不防高层逻辑/重入竞争。
- 网络：URLSession async/await 薄 package。后台同步：`BGAppRefreshTask`(iOS) / `NSBackgroundActivityScheduler`(macOS)。
- UI：`@Observable`（Observation，iOS 17+）视图模型藏在 repository 协议后，从容器（手搓或 Factory）解析；测试用 mock repository。2026 默认栈 = MVVM/MVVM-C + DI + SwiftUI `@Observable` + Swift 6 严格并发。
- 来源：<https://www.donnywals.com/exploring-concurrency-changes-in-swift-6-2/> ｜ <https://github.com/hmlongco/Factory>

---

## 先例与许可

### 官方应用

- **iOS**：`bitwarden/ios`（~99% Swift, GPL-3.0），Swift/SwiftUI 重写，取代退役的 Xamarin/MAUI `bitwarden/mobile`；含 Password Manager + Authenticator，最低 iOS 15.0；经 BitwardenSdk Swift 模块（`bitwarden/sdk-swift`，SPM，UniFFI 生成）消费 Rust SDK。架构 = BitwardenShared/BitwardenKit 分 Core/UI（Module/Coordinator/Processor/State），DI 经 ServiceContainer + `Has<Service>`；targets 含 AutoFill/Share/Action/Notification 扩展 + watchOS。`bitwarden/clients` monorepo 含 web/browser/desktop/cli 但**不含**移动 App。（已核实**确认**。）
- **macOS**：**无官方原生 App**——桌面是 Electron + Angular（`@angular/core 21.x`, `electron 41.x`，加 Rust `desktop_native` 做生物识别等）。
- 来源：<https://contributing.bitwarden.com/architecture/mobile-clients/ios/> ｜ <https://github.com/bitwarden/clients>

### 第三方/原生 Apple 先例（稀少）

- **Swiftwarden**（github.com/jesse231/Swiftwarden）：原生 macOS SwiftUI，**恰 89 stars，0 release/tag，无 LICENSE 文件**（默认即保留所有权利），最后提交 2025-02，WIP。支持 logins、org 密码解密、TouchID、官方+自托管。**用 Swift 重写 crypto**（bundled CryptoSwift.xcframework；`Encryption.swift` 手搓 PBKDF2-SHA256、HKDF-Expand、AES-CBC、HMAC-SHA256 + `SwCrypt.swift`），**不用** Rust SDK。❗ 核实纠正：README 显示 identity/card/secure-note 项类型**已实现**（原研究说缺失是过时的）；仍缺的是其他 KDF 方法、设置页、多账户。
- **Keyguard**（github.com/AChep/keyguard-app）：**source-available 仅供个人使用，LICENSE = "All Rights Reserved"，非开源**；Kotlin/Compose Multiplatform on JVM，"Android first"，发 Android/Linux/Windows/macOS(JVM) 构建，**无 iOS、无原生 Apple(Swift) 实现**。
- **净结论**：几乎无可复用的原生 Apple Swift 代码库；唯一 Swift 参考实现（Swiftwarden）是 WIP 且无许可证。
- 来源：<https://github.com/jesse231/Swiftwarden> ｜ <https://raw.githubusercontent.com/AChep/keyguard-app/master/LICENSE>

### Vaultwarden 本身

AGPL-3.0，"近乎完整" 的 Bitwarden API 重实现。支持个人库、Sends、附件、org/collections/groups/policies/event logs/admin reset/Directory Connector、2FA、emergency access。最大运营缺口 = **推送**（见 API 节）。
来源：<https://www.opensourcealternatives.to/item/vaultwarden>

### 许可证含义（关键约束）

- **Vaultwarden = AGPL-3.0；Bitwarden SDK/clients = GPL-3.0（+ SDK License 双许可）。**
- 你可以作为版权持有人把**自己的** GPL/AGPL 代码上 App Store（Signal/Bitwarden/Element 即如此，因版权持有人授予所需许可）。但**把第三方 GPLv3 SDK 链进闭源 App Store 二进制是有问题的**（FSF 立场；2010 GNU Go 被下架）。
- **最安全路径**：用你掌控的许可证自己写 Swift crypto/API，不嵌入 GPLv3 `sdk-internal`，除非把整个 App GPL 化并接受 App Store 冲突。
- **商标**：`bitwarden/server` TRADEMARK_GUIDELINES.md 禁止在产品/App/域名/公司名中用 "Bitwarden" 标记或"明显变体/谐音"。提名式 "compatible with Bitwarden®"（不暗示背书）允许。**选中性名字，避开 "...warden" 变体**（Vaultwarden 即因此从 bitwarden_rs 改名）。
- 来源：<https://github.com/bitwarden/server/blob/main/TRADEMARK_GUIDELINES.md> ｜ <https://appfair.org/blog/gpl-and-the-app-stores/>

---

## 核实修正

> 这一节汇总核实阶段**推翻（REFUTED）/部分正确（PARTIALLY-CORRECT）/不确定（UNCERTAIN）**的声明及其修正版。**实施前务必以此为准。**

| # | 域 | 原声明 | 裁定 | 修正 |
|---|----|--------|------|------|
| 1 | swiftarch | `sdk-internal` 现为纯 GPL-3.0，UniFFI Swift 复用合法可行 | **REFUTED** | 实为**双许可（GPL-3.0 OR Bitwarden SDK License v2.0）**；SDK License 仍禁止非 Bitwarden/非兼容用途，"Compatible Application" 须连 Bitwarden 服务器。**闭源 App Store 客户端两个分支都不可用**。→ 纯 Swift 重写。 |
| 2 | api（占位） | claim="c", detail="d"（模板占位符） | **UNCERTAIN** | 无可核实内容——API 域的 research 字段未填入真实内容（是测试占位）。**该域研究需重做**，本简报 API 节内容来自其他域的交叉引用与核实链。 |
| 3 | crypto | Argon2id salt = SHA-256(原始邮箱字符串) | **PARTIALLY-CORRECT** | salt = SHA-256(**email.trim().to_lowercase()**) 32B；邮箱**先规范化再 SHA**，与 PBKDF2 共享规范化路径。用原始邮箱会破坏兼容。 |
| 4 | crypto | type 4 是对称类型 / 多处把 type 4 当对称 | **PARTIALLY-CORRECT** | type 4 = `Rsa2048_OaepSha1_B64` 是**非对称**；现行对称是 0 与 2。 |
| 5 | crypto | account crypto v2（type 7）"rollout 时间线未找到" | **PARTIALLY-CORRECT** | 时间线**可查**：server v2026.5.0（2026-05-29）加 `AccountKeysRequestModel` 支持 v2，先用于新账户注册并扩展到更多注册方式。`decrypt_user_key` 对 type-7 返回 `OperationNotSupported(DecryptionNotImplementedForKey)`（含包裹错误）。 |
| 6 | crypto | 认证哈希在请求里叫 `masterPasswordHash` 字段 | （确认 + 字段名注脚）| 派生确认无误；但 password-grant 请求走 OAuth **`password`** 表单字段，`masterPasswordHash` JSON 名用于注册/改密等其他端点。 |
| 7 | autofill | 条件式 passkey 注册（conditional registration）是 iOS 26 新增 | **PARTIALLY-CORRECT** | 实为 **iOS 18.0 / macOS 15.0（WWDC24）**。iOS 26 真正新增的是 `ASCredentialUpdater`(Signal API)、`ASAuthorizationAccountCreationProvider`、well-known `/.well-known/passkey-endpoints`（复数无扩展名）。Web Signal API 是 **Safari 26** 非 Safari 19。 |
| 8 | autofill | `ASCredentialProviderExtensionCapabilities` 六键皆 iOS 17/macOS 14 | **PARTIALLY-CORRECT** | 字典 + `ProvidesPasswords`/`ProvidesPasskeys`/`ShowsConfigurationUI` 是 iOS 17/macOS 14；`ProvidesOneTimeCodes`/`ProvidesTextToInsert`/`SupportsConditionalPasskeyRegistration` 是 **iOS 18/macOS 15/visionOS 2**。 |
| 9 | liquidglass | WWDC26 社区列出的 iOS 27 SwiftUI API（dev.to）| **PARTIALLY-CORRECT** | 多数确为 iOS 27.0 beta 真实 API；但 `appearsActive` 实为 **iOS 18**（非 27）；reorder 修饰符是 `reorderContainer(for:isEnabled:move:)`（`move:` 必需），非 `reorderContainer(for:)`；`swipeActionsContainer()` 须显式加才能在 List 外用 swipeActions。 |
| 10 | liquidglass | macOS 27 "Golden Gate" 是**代号** | **PARTIALLY-CORRECT** | "Golden Gate" 是**公开营销名**（加州地名惯例）；**内部代号**是 "Honeycrisp"→"Fizz"。设计细节（折射/对比改善、透明度滑块、统一工具栏、边到边侧栏）已确认。 |
| 11 | priorart | 附件 v2 响应返回 key/fileName/fileSize；v1→v2 切换在 2023.5 | **PARTIALLY-CORRECT** | 客户端在**请求体**发送这些；响应返回 `attachmentId/url/fileUploadType/cipherResponse`。v2 直传约 2021（PR #1229）；2023.5 失败是无关 Node 18 回归。 |
| 12 | priorart | Vaultwarden "type 60" = 新格式/旧服务器不匹配 | **PARTIALLY-CORRECT** | 实为**客户端 SDK 解析损坏/明文数据**（"60"=ASCII `<` 的十进制）；Vaultwarden 不做加密工作。防御建议（对未知 type 软失败）仍成立。 |
| 13 | priorart | Swiftwarden 缺 identity/card/secure-note 类型 | **PARTIALLY-CORRECT** | 这三类**已实现**；实际缺：其他 KDF 方法、设置页、多账户。Keyguard 有 macOS(JVM) 构建（"无 Apple 构建"略不准），但无 iOS/原生 Swift。 |
| 14 | swiftarch | "SwiftData/Core Data 无 SQLCipher 路径"；SQLCipher 保护 URL/folder 名 | **PARTIALLY-CORRECT** | Core Data 技术上可经 `NSIncrementalStore`（但停维护）；SwiftData 确无路径。URL/folder 名**已 E2E 加密**，SQLCipher 实际保护的是 item type/时间戳/UUID/folder 成员关系/favorite/本地搜索索引。 |
| 15 | swiftarch | reuse-vs-reimplement: crate 名 "bitwarden-fido2" | **PARTIALLY-CORRECT** | crate 名是 `bitwarden-fido`（无 "2"）；许可证是混合（GPL OSS + 商业），非纯 GPL；BitwardenFFI.xcframework ~102 MB 压缩。 |

**已确认（CONFIRMED，无需修正，列出以增信心）：** PBKDF2 主密钥派生与 salt（#crypto）、认证/本地哈希派生（#crypto）、stretched master key HKDF（#crypto）、扩展生命周期与 `userInteractionRequired`（#autofill）、iOS 26 Liquid Glass 行为变化（#autofill/#liquidglass）、`UIDesignRequiresCompatibility` 在 27 被忽略（#liquidglass，Apple 官方）、iOS 27 透明度滑块（#liquidglass，二手但多源一致）、官方 iOS App 架构（#priorart）、Swift 6 并发栈（#swiftarch）。

---

## 设计取舍与建议

1. **首先定 crypto 策略 = 纯 Swift 重写**（不链 GPLv3/SDK-License 的 Rust SDK），以保住许可证与 App Store 选项。建一个 EncString 抽象：解析 `type.iv|data|mac`，按整数 type 分派，对未知 type **软失败**。
2. **KDF 服务器驱动**：始终先调 `/identity/accounts/prelogin`，用返回的 `Kdf/KdfIterations/KdfMemory/KdfParallelism` + 规范化邮箱 salt；**永不假设默认值**。PBKDF2 salt 直接用规范化邮箱，Argon2id salt = SHA-256(规范化邮箱)。
3. **两个哈希分清**：server hash = `B64(PBKDF2(MasterKey, salt=password, iters=1))` 发服务器；local hash = iters=2 持久化做离线解锁验证。
4. **MAC 严谨**：常量时间比较；对含 `key` 字段的 cipher，解密 cipher key 后 **PKCS#7 unpad** 再当 HMAC key；写回归测试。建模两层解密（item 字段在 cipher key 下，org item 在 org key 下）。
5. **包结构**：UIKit/AppKit-free 的 Core Swift Package，iOS/macOS App + AutoFill 扩展共用；App Group 容器（加密 vault DB）+ 共享 Keychain access group（生物识别门控的解包 key，藏 SE P-256 后）。
6. **AutoFill 内存工程**：扩展只解密选中项、流式附件、`completeRequest` 后立即释放；对 AutoFill-关键库的高内存 Argon2id（>64 MB）给警告/上限。静默路径立即 `cancelRequest(userInteractionRequired)`，生物识别解锁放 `prepareInterfaceToProvideCredential`。
7. **Passkey 全客户端实现**：构造 `authenticatorData`、签 `authenticatorData||clientDataHash`、返回 assertion/registration（`none` attestation）；尊重 `userVerificationPreference` 与 `allowedCredentials`。
8. **不要依赖推送**：假设自托管/第三方收不到 APNs，设计轮询 + 后台刷新 + revision-token 增量同步，清晰报错而非崩溃。
9. **Liquid Glass 用标准控件**：重编译自动获得材质 + 无障碍适配；`.glassEffect()` 只留自定义表面，玻璃只在功能层。安全字段绝不上 clear glass，必测 Reduce Transparency/Increased Contrast/Reduce Motion。
10. **平台/版本门控**：26+ 特性 `#available(iOS 26, macOS 26, *)`；条件式 passkey 注册门控到 iOS 18；iOS 27-only API 先对 developer.apple.com 验证符号再写，保留 26 路径。计划 `UIScene` 生命周期、`UIScreen.main`、`actionSheet`→`confirmationDialog` 的迁移。
11. **离线缓存 GRDB + SQLCipher**（App Group 容器，`cipher_plaintext_header_size=32` + 自管 salt + WAL 共享处理）；解包 user key 只留内存。
12. **命名/品牌**：中性名，**不**用 Bitwarden 商标或 "...warden" 变体，限于提名式 "compatible with Bitwarden®"。若开源，AGPL/GPL 与生态一致，但要刻意处理你授予自己的 App Store 版权持有人许可。
13. **数据层**：结构化 vault 数据入 SQLite/GRDB，secrets 入 Keychain，settings 入 UserDefaults；用 actor 化 sync 引擎 + `@Observable` repositories。

---

## 待澄清问题

**需向用户确认的产品/范围决策：**

1. **目标服务器**：仅 Vaultwarden，还是也要兼容 bitwarden.com？后者会触发 SDK License 的"Compatible Application"灰区，且需对两端做集成测试（它们可能差几周）。
2. **开源 vs 闭源**：决定许可证策略（纯 Swift 重写在两种下都安全；若闭源则**绝不**能碰 Rust SDK）。
3. **最低 OS 基线**：iOS 17（passkey 基线）/iOS 18（条件式注册）/iOS 26（CXF、Signal API）哪个作为下限？影响特性门控与可用 API。
4. **范围**：是否一期就要 organizations/collections、Sends、附件、emergency access、TDE/Key Connector？建议初期 master-password-only + 个人库 + AutoFill。
5. **多账户**：是否需要多账户切换（Swiftwarden 缺此项）？

**需技术核实（实施时落地）：**

6. ⚠️ Argon2id 默认值分歧（32 MiB/6/4 vs 64 MiB/3/4）——以真实 prelogin 响应 + SDK 源码为准，不硬编码。
7. ⚠️ type 7 CoseEncrypt0 的精确字节布局/AAD/key-id 放置，及生产账户 2025-2026 的自动迁移情况——读当前 sdk-internal 源码确认（master-key→user-key type-7 路径仍 "not implemented"）。
8. ⚠️ 附件文件流的精确 HMAC framing（是裸 AES-CBC blob + 独立 HMAC，还是 EncString 信封）——对 sdk bitwarden-vault attachment 代码确认。
9. ⚠️ Send 的精确 HKDF info-label 字符串——从 sdk-internal 确认而非 help 文档。
10. ⚠️ macOS Secure Enclave + Touch ID 在 Apple Silicon vs Intel 的一致性与 Intel 回退方案；Catalyst vs 原生 macOS 能否对等注册 AutoFill 提供者，及发送的 deviceType（7 MacOsDesktop vs Catalyst 特定值）。
11. ⚠️ iOS 27/macOS 27 是否有超出 iOS 26 集合的 AutoFill/CXF API——待 Apple 发布 27 文档（当前 "27" 目标视为"继承 26 行为"）。
12. ⚠️ AutoFill 扩展在 iOS 26/27 的精确内存上限——社区一致约 120 MB，但 Apple 不公开保证，需在目标 OS 实测。
13. ⚠️ `ASPasskeyRegistrationCredential.attestationObject` 中第三方提供者的精确 attestation 格式（`none` 是否总被接受，及系统校验的 CBOR/COSE 编码）。
14. **API 域研究重做**：JSON 中 api 域的 research 字段是未填占位符（claim="c" 等），本简报 API 节内容来自其他域交叉引用，建议补做一轮针对 endpoint/字段名的专项研究。
