# Tessera App/ — Xcode 验证清单（VERIFY-IN-XCODE）

## 为什么有这份清单

`App/` 目录（仅 Xcode 可构建，依赖 iOS 26 / macOS 26 SDK 与 Liquid Glass API）**无法在 CLT（Command Line Tools）host 上编译**，因此这些 API 调用的精确签名/枚举成员/初始化器在 CI/CLI 扫描阶段无法被编译器验证。本清单把四块逐区审计合并成一份可执行项，等到 Xcode（完整 SDK）被 `xcode-select` 选中后逐项核对。

**一行构建路径：** `xcodegen generate` → `open` 生成的工程 → 构建 `Tessera-iOS` / `Tessera-macOS` scheme → 按编译器报错逐项修正下表。

> 排序约定：每个区域内按 certainty 排序，**uncertain 在前，likely 居中，confirmed 在后**。所有 `file:line` 引用保留原始值。

---

## 一、iOS UI（`App/iOS/UI/*.swift`）

- [ ] **`.searchable(text:placement:prompt:)`（placement `.toolbar`）** — 底部搜索框绑定 `searchText`，placement: `.toolbar`，prompt "Search vault"（MainTabView.swift:84）。校验: 在 Xcode 确认 `SearchFieldPlacement` 是否存在 `.toolbar` case；很多代码用的是 `.automatic` / `.navigationBarDrawer`。若不符: 若 `.toolbar` 无效则用 `.automatic`（配合 `Tab(role: .search)` 会自动路由到 iPhone 底部搜索框）。
- [ ] **`.scrollEdgeEffectStyle(_:for:)`** — 应用 `.soft` 边缘效果 `for: .all`，使行内容在浮动玻璃栏下淡出（VaultListView.swift:74）。校验: 在 Xcode 确认该 modifier 及 `for:` 参数类型；确认该 edge 类型上存在 `.all` 成员。若不符: 若 `for:` 是 `VerticalEdge.Set` 则用 `[.top, .bottom]`；style cases 为 `.automatic` / `.hard` / `.soft`。
- [ ] **`ConcentricRectangleCard`（DesignSystem 包装器）** — 行圆角的自定义卡片包装器；命名借用但**不是**原始 `ConcentricRectangle` shape（VaultListView.swift:43）。校验: 打开 DesignSystem 确认该包装器内部用的是 `ConcentricRectangle`（iOS 26）还是 `RoundedRectangle`。若不符: 超出本次扫描范围；若它使用 `ConcentricRectangle`，需在 Xcode 单独验证该 shape。
- [ ] **`Tab(_:systemImage:value:content:)`** — 为 Vault/Generator/Send/Settings 提供基于 value 的带标签 tab（selection TabView）（MainTabView.swift:51, 57, 63, 69）。校验: 在 Xcode 确认 title+systemImage+value 的 Tab init 重载存在（iOS 18+）。若不符: 若重载不同，改用 `Tab(value:) { content } .tabItem` 或 label 闭包形式。
- [ ] **`.glassEffectID(_:in:)`** — 在 `GlassEffectContainer` 内的 `@Namespace` 中标记浮动 + 按钮（"add-item"），用于 blend/morph 过渡（MainTabView.swift:139）。校验: 构建 iOS 26 target；在 Xcode Quick Help 检查 `View.glassEffectID(_:in:)`，确认 `Namespace.ID` 参数。若不符: 删除该 modifier，依赖 `GlassEffectContainer` 自动合并（仅丢失 morph）。
- [ ] **`GlassEffectContainer(spacing:)`** — 包裹浮动 + 按钮，使未来的浮动按钮合并为单个玻璃形状（MainTabView.swift:132）。校验: 在 Xcode Quick Help 确认 iOS 26 上 `GlassEffectContainer` 的 `init(spacing:)` 签名。若不符: spacing 为 CGFloat；如签名不同则用默认 spacing 的 `GlassEffectContainer { }`。
- [ ] **`.buttonStyle(.glassProminent)`** — 浮动 + add-item 主按钮样式（自定义 chrome）（MainTabView.swift:138）。校验: 在 Xcode 输入 `.glassProminent`，确认其在 iOS 26 上解析到 `PrimitiveButtonStyle`。若不符: 回退 `.borderedProminent`。
- [ ] **`.buttonStyle(.glass)`** — detail/copy 行内小型复制按钮（doc.on.doc）样式（ItemDetailView.swift:113, 152）。校验: 在 Xcode 自动补全确认 iOS 26 上 `ButtonStyle` 的 `.glass`。若不符: 回退 `.bordered`。
- [ ] **`.tabViewBottomAccessory(content:)`** — 在 tab bar 上方放置 SyncStatusPill；tab bar 最小化时内联折叠（MainTabView.swift:94）。校验: 在 Xcode 确认 iOS 26 上 `View.tabViewBottomAccessory` 的 trailing-closure 签名。若不符: 按 brief 文档原样使用；如名称不同检查 `tabViewBottomAccessory` 重载。
- [ ] **`.tabBarMinimizeBehavior(.onScrollDown)`** — 下滑时最小化 tab bar（MainTabView.swift:93）。校验: 在 Xcode 确认该 modifier 及 `TabBarMinimizeBehavior.onScrollDown` case。若不符: 用 `.automatic`；注意 iOS 27 新增了类似的 `toolbarMinimizeBehavior`（独立 API）。
- [ ] **`Tab(value:role:content:)` role: `.search`** — 专用搜索 tab，在 iPhone 上路由到底部 searchable 字段（MainTabView.swift:77）。校验: 在 Xcode 确认 iOS 26 上 Tab init 带 `role: TabRole.search`（TabRole 于 iOS 18 引入）。若不符: 确保基于 value 的 init 与 selection 类型匹配。
- [ ] **`List .swipeActions(edge:allowsFullSwipe:)`** — vault 行上的 trailing 删除（full-swipe）与 leading 复制用户名操作（List 内）（VaultListView.swift:51, 58）。校验: `swipeActions` 自 iOS 15 起；确认在 iOS 26 上编译通过（List 内无需 `swipeActionsContainer`）。若不符: List 内正确；iOS 27 仅在 List 外才需要 `swipeActionsContainer()`。
- [ ] **`UIPasteboard.setItems(_:options:)` `[.expirationDate]`** — 以 `UIPasteboard.OptionsKey.expirationDate` 复制值，使复制的密文自动过期（Clipboard.swift:16, 18）。校验: 在 Xcode 确认 `setItems(_:options:)` 与 `.expirationDate` key（iOS 10+），值为 Date。若不符: 早于 cutoff，正确；确保 items 数组为 `[[String: Any]]`。

---

## 二、macOS UI（`App/macOS/UI/*.swift`）

- [ ] **`ConcentricRectangle`（原始 SwiftUI shape）** — **未**直接使用；代码调用自定义 `ConcentricRectangleCard` 包装器（定义于 Sources/DesignSystem，超出本范围）（MacItemDetailView.swift:164，间接）。校验: 打开 `Sources/DesignSystem/ConcentricRectangleCard.swift` 看其内部是否使用原始 `ConcentricRectangle`（macOS 26 shape）。若不符: brief 确认 `ConcentricRectangle` 在 26 上可用；扫描文件仅用包装器，需单独验证包装器实现。
- [ ] **`ToolbarSpacer(.fixed)` / `ToolbarSpacer(.flexible)`** — 放在 `.toolbar` 内的 `ToolbarItemGroup` 之间，把操作分隔成独立的玻璃 capsule（MacMainView.swift:95, MacItemDetailView.swift:64）。校验: 在 Xcode 确认此处 `ToolbarSpacer` init 仅接受 `SpacerSizing` 位置参数；确认其在 `ToolbarContent` 中可组合。若不符: brief 显示 `ToolbarSpacer(.fixed/.flexible, placement:)`；代码省略了 placement（可能是可选/有默认值）——可接受，但要确认无 placement 的 init 存在。
- [ ] **`backgroundExtensionEffect()`** — 应用于 detail hero HStack，使其 tinted 背景在 sidebar/inspector 列下镜像+模糊（MacItemDetailView.swift:106）。校验: 在 View 上用 Xcode 自动补全；在 Quick Help 检查可用性 badge macOS 26.0+。若不符: 与 brief line 288 完全一致，无参形式；如缺失则删除该 modifier（纯装饰）。
- [ ] **`.buttonStyle(.glass)`** — detail view 中 TOTP 复制按钮与用户名/网站复制按钮的玻璃样式（MacItemDetailView.swift:142, 204）。校验: 在 Xcode 输入 `.buttonStyle(.glass)`，确认 macOS 26 上 `.glass` 静态成员解析。若不符: brief line 287 确认 `.glass`/`.glassProminent`；回退 `.bordered`。
- [ ] **`NavigationSplitView(columnVisibility:)` 三列 sidebar/content/detail** — 三列 shell：MacSidebarView | MacItemListView | detail，带 columnVisibility 绑定（MacMainView.swift:56-75）。校验: 前 26 API（macOS 13+），正常编译；确认 3-trailing-closure 形式。若不符: 自 macOS 13 起稳定，无需变更。
- [ ] **`navigationSplitViewColumnWidth(min:ideal:max:)`** — 设置 sidebar/content 列宽约束（MacMainView.swift:58, 63）。校验: macOS 13+ API；Xcode 自动补全确认 3 参重载。若不符: 稳定，无需变更。
- [ ] **`inspector(isPresented:)`** — 切换尾部 inspector 面板（metadata/password history），绑定 showInspector（MacItemDetailView.swift:71）。校验: macOS 14+/iOS 17+ API；在 Quick Help 验证可用性 badge。若不符: 自 macOS 14 起稳定，无需变更。
- [ ] **`inspectorColumnWidth(min:ideal:max:)`** — 设置 inspector 列宽范围（240/280/360）（MacItemDetailView.swift:73）。校验: macOS 14+/iOS 17+；在 Xcode 确认 3 参重载。若不符: 自 macOS 14 起稳定，无需变更。
- [ ] **`searchable(text:placement:prompt:)`（`.toolbar` placement）** — vault 搜索框放在 toolbar，驱动 debounced 的 `listModel.search`（MacMainView.swift:76）。校验: brief line 294 确认；验证 macOS 上 `.toolbar` SearchFieldPlacement 有效。若不符: 稳定；macOS 上 `.toolbar`/`.automatic` 均有效。
- [ ] **`ContentUnavailableView(_:systemImage:description:)`** — 无选中/无项目的空状态占位（MacMainView.swift:72, MacItemListView.swift:28）。校验: macOS 14+/iOS 17+；确认 string+systemImage+description init。若不符: 自 macOS 14 起稳定，无需变更。
- [ ] **`NSPasteboard.general` / `clearContents` / `setString(_:forType:.string)` / `string(forType:)`** — macOS 密文复制/清除接缝；clear-if-still-equal 自动清除辅助（MacClipboard.swift:13-24）。校验: 长期存在的 AppKit API，任何 macOS 均可编译，无 badge 顾虑。若不符: 稳定，无需变更。
- [ ] **`onChange(of:)` 双参数 (old, new) 闭包** — 通过 iOS17+ 双参签名响应 searchText / model.state 变化（MacMainView.swift:77, MacLoginView.swift:70, MacUnlockView.swift:63）。校验: macOS 14+/iOS 17+ 双参重载；确认不是已弃用的单参版本。若不符: 自 macOS 14 起稳定，无需变更。
- [ ] **`safeAreaInset(edge: .bottom)`** — 在 sidebar List 底部固定 sync-status footer（MacSidebarView.swift:26）。校验: macOS 13+/iOS 15+，稳定，无 badge 顾虑。若不符: 稳定，无需变更。
- [ ] **`TextField(_:text:axis: .vertical)` + `lineLimit(_:Range)`** — 多行增长的备注字段，3...8 行范围（MacItemEditView.swift:87-88）。校验: macOS 13+/iOS 16+ axis init 与 Range lineLimit；确认重载。若不符: 自 macOS 13 起稳定，无需变更。
- [ ] **`MenuBarExtra` / `menuBarExtraStyle`** — 此处仅定义 MenuBarExtra 的 content View；scene+style 按文件头说明位于 App target（MenuBarContent.swift，未找到 scene）。校验: 在 App target 搜索 `MenuBarExtra { }` / `.menuBarExtraStyle(.window)`，不在扫描范围内。若不符: MenuBarExtra 为 macOS 13+，`.window` 样式 macOS 13+；在 App target 文件中验证。
- [ ] **`foregroundStyle` / `textSelection(.enabled)` / `formStyle(.grouped)` / `LabeledContent`** — detail/inspector/settings 中的标准样式、可选文本、grouped form、labeled 行（MacItemDetailView.swift:96, 196, 238, 219; MacSettingsView.swift:33, 78）。校验: 均为 macOS 13+/14+ API，稳定，无 badge 顾虑。若不符: 稳定，无需变更。

---

## 三、AutoFill 扩展（`App/AutoFill/*.swift`，AuthenticationServices）

- [ ] **`ASCredentialRequest.type == .passkeyAssertion`** — 依据 request 的 type 属性在 password vs passkey 路径间分支（CredentialProviderViewController.swift:67）。校验: 在 Xcode 确认 `ASCredentialRequest` 有 `.type` 返回 `ASCredentialRequestType`、且存在 `.passkeyAssertion` case。若不符: 若不存在，通过 downcast `as? ASPasskeyCredentialRequest` 分支（line 78 已做）。
- [ ] **`ASCredentialRequest.credentialIdentity.recordIdentifier`** — 从 credentialIdentity 读取 recordIdentifier 以查找本地项（CredentialProviderViewController.swift:51, 66）。校验: 在 Xcode 确认 `credentialIdentity` 属性与 `ASCredentialIdentity.recordIdentifier`（optional String）。若不符: recordIdentifier 在 `ASCredentialIdentity` 协议上；验证 request 是否暴露 `credentialIdentity`。
- [ ] **`ASPasskeyCredentialRequest.credentialIdentity`（downcast 到 `ASPasskeyCredentialIdentity`）** — 把 `request.credentialIdentity` downcast 为 `ASPasskeyCredentialIdentity` 以取 rpId/userHandle/credentialID（CredentialProviderViewController.swift:113, 165）。校验: 在 Xcode 确认 `ASPasskeyCredentialRequest.credentialIdentity` 返回可转为 `ASPasskeyCredentialIdentity` 的类型。若不符: 若 request 直接暴露类型化的 passkey 字段，则直接读取而非强转。
- [ ] **`ASCredentialRequest.type == .passkeyAssertion` + `ASPasskey*` 请求/标识/注册/断言凭据（整套）** — passkey+password provider：锁定时以 `.userInteractionRequired` 失败；构建 AS passkey assertion/registration 凭据（CredentialProviderViewController.swift:35, 44, 65, 78, 101, 111-145, 164-188）。校验: 在 Xcode 确认 `ASPasskeyRegistrationCredential(relyingParty:clientDataHash:credentialID:attestationObject:)` 与 `ASPasskeyAssertionCredential` 的 init labels（iOS 17+）。若不符: init label/顺序可能不同；逐个在 Xcode 文档中验证 AS* 初始化器签名。
- [ ] **`ASPasskeyRegistrationCredential(relyingParty:clientDataHash:credentialID:attestationObject:)`** — Fido2 attestation 后构建注册凭据（CredentialProviderViewController.swift:139-144）。校验: brief line 224 列出这 4 个 labels；iOS 26 可能新增 `extensionOutput` 参数，在 Xcode 确认。若不符: 若 init 新增参数，补齐它们或改用 SDK 暴露的指定初始化器。
- [ ] **`prepareCredentialList(for:requestParameters: ASPasskeyCredentialRequestParameters)`** — passkey+password 列表变体；把 requestParameters 传入 SwiftUI 列表（CredentialProviderViewController.swift:101-103）。校验: brief line 189（iOS 17+/macOS 14+）；在 Xcode 确认参数 label `requestParameters`。若不符: 正确；确认部署目标无需 `@available` 门控。
- [ ] **`ASCredentialProviderViewController`（subclass）** — principal class 子类化它；iOS 上为 UIViewController / macOS 上为 NSViewController（CredentialProviderViewController.swift:35；HostingSupport.swift:19, 43）。校验: brief line 184：iOS 12+/macOS 11+。在 Xcode 打开，自动补全类成员。若不符: 用法正确；基类稳定且早于 cutoff。
- [ ] **`provideCredentialWithoutUserInteraction(for: ASCredentialRequest)`** — 静默快路径；锁定时以 `.userInteractionRequired` 取消，绝不提示生物识别（CredentialProviderViewController.swift:44）。校验: brief line 186 确认该 any-`ASCredentialRequest` 重载；检查 override 在 Xcode 编译通过。若不符: 单参 `ASPasswordCredentialIdentity` 重载已弃用（brief 196）；此形式正确。
- [ ] **`prepareInterfaceToProvideCredential(for: ASCredentialRequest)`** — 驱动生物识别解锁后提供密码或 passkey assertion（CredentialProviderViewController.swift:65）。校验: brief line 187；在 Xcode 确认 override 签名。若不符: 正确；避免弃用的 `ASPasswordCredentialIdentity` 单参变体。
- [ ] **`prepareCredentialList(for: [ASCredentialServiceIdentifier])`** — 密码选择器入口，针对 service identifiers（CredentialProviderViewController.swift:96）。校验: brief line 188，标准 override。若不符: 按文档原样使用。
- [ ] **`prepareInterface(forPasskeyRegistration: ASCredentialRequest)`** — 把 request 转为 `ASPasskeyCredentialRequest`，经 Fido2 注册，完成注册（CredentialProviderViewController.swift:111）。校验: brief line 190；在 Xcode 确认 override + downcast。若不符: 按用法正确。
- [ ] **`prepareInterfaceForExtensionConfiguration()`** — 显示 SwiftUI ConfigurationView；调用 `completeExtensionConfigurationRequest()`（CredentialProviderViewController.swift:155）。校验: 标准 config override，在 Xcode 确认。若不符: 按用法正确。
- [ ] **`ASPasskeyCredentialRequest.clientDataHash`** — 系统预哈希值，传给 Fido2 register 及 assertion/registration 凭据（CredentialProviderViewController.swift:128, 142, 174, 180）。校验: brief line 221：`clientDataHash: Data`（预哈希）；在 Xcode 确认该属性。若不符: 正确；它是预哈希值，不是原始 challenge。
- [ ] **`ASPasskeyCredentialIdentity`（relyingPartyIdentifier, userHandle, credentialID）** — 为 register 与 assert 读取 relyingPartyIdentifier、userHandle、credentialID（CredentialProviderViewController.swift:124-128, 135-136, 170-182）。校验: brief line 213 列出 init 成员；在 Xcode 确认属性名。若不符: 成员名与文档初始化器匹配；验证精确大小写。
- [ ] **`ASPasswordCredential(user:password:)`** — 构建提供的密码凭据（CredentialProviderViewController.swift:53, 83, 211）。校验: 长期存在的初始化器，在 Xcode 确认。若不符: 按用法正确。
- [ ] **`ASPasskeyAssertionCredential(userHandle:relyingParty:signature:clientDataHash:authenticatorData:credentialID:)`** — 构建返回给系统的 assertion 凭据（CredentialProviderViewController.swift:176-183）。校验: brief line 223 列出该初始化器精确顺序；在 Xcode 确认 labels/顺序。若不符: 与文档 init 匹配；验证 iOS 26 SDK 无额外必填参数（如 `extensionOutput`）。
- [ ] **`extensionContext.completeRequest(withSelectedCredential:)`** — 完成密码请求（省略 completionHandler，它是可选的）（CredentialProviderViewController.swift:229）。校验: brief line 194：completionHandler 为可选 `((Bool) -> Void)?`，在 Xcode 确认。若不符: 正确；trailing completionHandler 可省略。
- [ ] **`extensionContext.completeAssertionRequest(using:)`** — 完成 passkey assertion（CredentialProviderViewController.swift:234）。校验: brief line 194；在 Xcode 确认 `ASCredentialProviderExtensionContext` 上的该方法。若不符: 按用法正确。
- [ ] **`extensionContext.completeRegistrationRequest(using:)`** — 完成 passkey 注册（CredentialProviderViewController.swift:239）。校验: brief line 194；在 Xcode 确认该方法。若不符: 按用法正确。
- [ ] **`extensionContext.completeExtensionConfigurationRequest()`** — dismiss 配置 UI（CredentialProviderViewController.swift:157）。校验: 标准 context 方法，在 Xcode 确认。若不符: 按用法正确。
- [ ] **`ASExtensionError.userInteractionRequired` / `ASExtensionErrorDomain` / `.Code`** — `cancel()` 构建 `NSError(domain: ASExtensionErrorDomain, code: code.rawValue)`；配合 `.userInteractionRequired`/`.failed`/`.userCanceled`/`.credentialIdentityNotFound`（CredentialProviderViewController.swift:47, 242-244）。校验: brief line 186：raw value 100，精确 cancelRequest 模式；在 Xcode 确认枚举 cases。若不符: 模式与文档化的 `cancelRequest(withError:)` 配方匹配。
- [ ] **`UIHostingController` / `NSHostingController` + `ASCredentialProviderViewController` 作为 UI/NSViewController** — 平台条件 typealias `UIHostingControllerCompat`；经 `addChild` + Auto Layout 约束嵌入 SwiftUI（HostingSupport.swift:15, 19-33, 39, 43-55）。校验: 早于 cutoff 的 UIKit/AppKit hosting API；确认两平台 child VC 生命周期编译通过。若不符: 所有成员（addChild、NSLayoutConstraint、removeFromParent）稳定，非 Liquid Glass。
- [ ] **`buttonStyle(.borderedProminent)` / `.borderless` / `Button(role: .cancel)`（非 Liquid Glass）** — 极简 SwiftUI 表面仅用经典样式；本范围内无 `.glass`/`.glassProminent`/glassEffect/GlassEffectContainer（ExtensionViews.swift:33, 35, 84, 112; foregroundStyle 23, 29, 66, 103）。校验: 均为前 iOS-26 API；已确认 App/AutoFill 无 Liquid Glass API，它们位于范围外的 UI-* 包。若不符: 正确；标准控件重新编译后自动采用玻璃，无需显式 glass 调用。
- [ ] **AutoFill plist `NSExtension` + `ASCredentialProviderExtensionCapabilities`；`autofill-credential-provider` 权益；App Groups + `keychain-access-groups`** — 提供 Passwords/Passkeys/OneTimeCodes/ConfigUI 为 true；跨 app+extension 共享 `group.dev.moooyo.tessera` + `$(AppIdentifierPrefix)...shared` keychain group（Info-AutoFill.plist:23-43; Tessera-AutoFill.entitlements; Tessera-iOS/macOS.entitlements）。校验: 在 Xcode capabilities pane 确认 AutoFill 已开启；principal class `$(PRODUCT_MODULE_NAME).CredentialProviderViewController` 可解析。若不符: keys 正确；保持三个 target 的 App Group + keychain group 完全一致。

---

## 四、App 生命周期与工程配置（`App/Shared`、`App/*/App`、DesignSystem、plist、entitlements、project.yml）

- [ ] **信号量桥接的 async DB-passphrase 引导（`Task.detached` + `DispatchSemaphore.wait`）** — `loadOrCreatePassphrase` 派生 `Task.detached`，await keychain actor，经 `semaphore.wait()` 阻塞 `@MainActor` init（AppEnvironment.swift:272-293，makeStore:256）。校验: 用 `SWIFT_STRICT_CONCURRENCY=complete`（project.yml）构建；因 init 为 `@MainActor`，测试主 actor 死锁。若不符: 用 `semaphore.wait()` 阻塞主线程有优先级反转/死锁风险；改用同步 Keychain `SecItem` 读取，而非 detached+await。**（本清单最高风险项）**
- [ ] **`ConcentricRectangle(corners:isUniform:)`** — 不透明卡片 shape：`ConcentricRectangle(corners: .concentric(minimum: .fixed(r)), isUniform: true)`（ConcentricRectangleCard.swift:51；被 VaultListView.swift:43、MacItemDetailView.swift:164 消费）。校验: 在 Xcode 确认 `ConcentricRectangle` init `corners:isUniform:` 与 `.concentric(minimum:)`/`.fixed()` 辅助。若不符: 若 init 不同，用 `ConcentricRectangle(corner: .fixed(r))` 或 `RoundedRectangle(cornerRadius:)`。
- [ ] **`.scrollEdgeEffectStyle(_:for:)`** — 调用为 `.scrollEdgeEffectStyle(.soft, for: .all)`，使行在浮动玻璃栏下淡出（VaultListView.swift:74）。校验: 在 Xcode 确认 style case `.soft` 与 edge selector `.all`（`ScrollEdgeEffectStyle` + edge set）。若不符: 若 `.soft`/`.all` 名称不同，改用正确的 style 枚举 case + edge set。
- [ ] **`.tabViewBottomAccessory { }`** — 在 tab bar 下方承载 SyncStatusPill（MainTabView.swift:94-96）。校验: 在 Xcode 确认 TabView 上 `tabViewBottomAccessory(content:)` 的精确 label。若不符: brief 列为 confirmed；如名称不同检查 `tabViewBottomAccessory` 重载。
- [ ] **`Tab(_:systemImage:value:)` / `Tab(value:role: .search)`** — 新的基于 value 的 Tab DSL 加上路由到底部 searchable 字段的 `.search` role tab（MainTabView.swift:51-81）。校验: 在 Xcode 确认 Tab init 重载与 `TabRole.search`（iOS 18+/26）。若不符: 若不可用，回退到 `TabView { view.tabItem{}.tag() }` 并在搜索 tab 上用 searchable。
- [ ] **`ToolbarSpacer(_:)`** — 经 `.flexible` 与 `.fixed` 把 toolbar 操作分隔成独立玻璃 capsule（MacMainView.swift:95; MacItemDetailView.swift:64）。校验: 在 Xcode 确认 `ToolbarSpacer` 与 sizing cases `.flexible`/`.fixed`。若不符: brief 确认 ToolbarSpacer；如 sizing 枚举名不同则调整 case。
- [ ] **`ASCredentialProviderViewController` + `ASCredentialRequest`/`.passkeyAssertion` + `ASPasskey*` 请求/标识/注册/断言凭据** — passkey+password provider：锁定时以 `.userInteractionRequired` 失败；构建 AS passkey assertion/registration 凭据（CredentialProviderViewController.swift:35, 44, 65, 78, 101, 111-145, 164-188）。校验: 在 Xcode 确认 `ASPasskeyRegistrationCredential(relyingParty:clientDataHash:credentialID:attestationObject:)` 与 `ASPasskeyAssertionCredential` init labels（iOS 17+）。若不符: init label/顺序可能不同；逐个验证 AS* 初始化器签名。
- [ ] **xcodegen `project.yml` schema（本地 package path、deps、deploymentTarget、extension embed）** — `packages.Tessera.path: .`；apps 经 `target:...; embed: true` 嵌入 TesseraAutoFill；deploymentTarget 26.0；Swift 6.2；strict concurrency complete；AutoFill 为 120MB 上限省略 Networking/SyncEngine/UI（project.yml:21-30, 53, 95-96, 145-146, 154-214）。校验: 运行 `xcodegen generate` 后构建；确认 extension 嵌入 app PlugIns 且 package products 解析。若不符: 若 embed 被拒，在 app target 下的依赖上设 `embed: true`；确认 `path: .` 解析到根 Package.swift。
- [ ] **`.glassEffect(_:in:)` / `Glass`（`.regular`/`.clear`/`.identity`）** — 经 DesignSystem 包装器实现自定义表面玻璃，被 App 视图消费；`Glass.identity` 是 reduce-transparency 回退（GlassResolution.swift:70-76, GlassHelpers.swift:40, GlassScrim.swift:42）。校验: Xcode 自动补全 `View.glassEffect(_:in:)`；确认 `Glass` 有 `.regular`/`.clear`/`.identity` 静态成员。若不符: 若 `.identity` 不存在，有条件地省略 `.glassEffect`；brief 确认 glassEffect 在 iOS/macOS 26 上可用。
- [ ] **`GlassEffectContainer(spacing:)`** — 包裹浮动 + 按钮，使未来浮动按钮作为单一玻璃形状 morph（MainTabView.swift:132）。校验: Xcode：`GlassEffectContainer(spacing:)` init 带 trailing ViewBuilder。若不符: 文档化的 iOS 26 API；如 init 不同则用默认 spacing 的 `GlassEffectContainer { }`。
- [ ] **`.glassEffectID(_:in:)`** — 在 `@Namespace` 中标识 add 按钮以实现玻璃 morph 过渡（MainTabView.swift:139）。校验: Xcode：验证 View 上的 `glassEffectID(_:in: Namespace.ID)`。若不符: iOS 26 已确认；如缺失则删除该 modifier（仅丢失 morph）。
- [ ] **`.buttonStyle(.glass)` / `.buttonStyle(.glassProminent)`** — `.glassProminent` 用于浮动 + 按钮；`.glass` 用于 detail view 中的复制/reveal 按钮（MainTabView.swift:138; ItemDetailView.swift:113, 152; MacItemDetailView.swift:142, 204; SecureRevealView.swift:86, 96）。校验: Xcode：确认 ButtonStyle 静态成员 `.glass` 与 `.glassProminent`。若不符: iOS/macOS 26 已确认；回退 `.bordered` / `.borderedProminent`。
- [ ] **`.backgroundExtensionEffect()`** — 把 detail hero tint/blur 延伸到相邻 sidebar/inspector 列下（MacItemDetailView.swift:106）。校验: Xcode：确认 `View.backgroundExtensionEffect()` 无参签名。若不符: macOS 26 已确认；如签名不同则删除（仅装饰）。
- [ ] **`.tabBarMinimizeBehavior(_:)`** — 调用为 `.tabBarMinimizeBehavior(.onScrollDown)` 滚动时最小化 tab bar（MainTabView.swift:93）。校验: Xcode：确认 `TabBarMinimizeBehavior.onScrollDown`。若不符: iOS 26 已确认；如 case 不同用 `.automatic`。
- [ ] **`.searchable(text:placement:prompt:)`（`.toolbar` placement）** — vault 搜索绑定 searchText，`SearchFieldPlacement.toolbar`（MainTabView.swift:84; MacMainView.swift:76）。校验: Xcode：确认 `SearchFieldPlacement.toolbar` case。若不符: searchable 长期存在；如 `.toolbar` 无效用 `.automatic` / `.navigationBarDrawer`。
- [ ] **`.inspector(isPresented:)` + `.inspectorColumnWidth(min:ideal:max:)`** — 尾部 metadata/password-history inspector 面板与尺寸列（MacItemDetailView.swift:71-73）。校验: Xcode：两者均 macOS 14+ 发布；确认签名编译。若不符: 自 macOS 14 起稳定，无预期回退。
- [ ] **`MenuBarExtra { }` + `.menuBarExtraStyle(.window)`** — 用于快速 unlock/search/copy 的第二个 Scene；window 样式（TesseraMacApp.swift:48-51）。校验: Xcode：`MenuBarExtra` Scene + `MenuBarExtraStyle.window`（macOS 13+）。若不符: 稳定，无回退。
- [ ] **`NavigationSplitView(columnVisibility:)` + `.navigationSplitViewColumnWidth(min:ideal:max:)`** — 三列 sidebar/list/detail 带尺寸列；visibility 绑定 `NavigationSplitViewVisibility`（MacMainView.swift:56-63）。校验: Xcode：macOS 13 发布；确认重载。若不符: 稳定，无回退。
- [ ] **`@Environment(\.scenePhase)` + `.onChange(of:)` 双参闭包** — 观察 scenePhase 自动锁定；用 `onChange(of:) { _, newPhase in }` 双值闭包（TesseraApp.swift:33, 52; TesseraMacApp.swift:25, 37）。校验: Xcode：确认双参 onChange（iOS 17+）与 macOS Scene 上的 scenePhase。若不符: 双参 onChange 为 iOS 17+，在此部署目标可用。
- [ ] **`BGTaskScheduler.register` / `BGAppRefreshTaskRequest` / `BGAppRefreshTask` + Info.plist `BGTaskSchedulerPermittedIdentifiers`** — 在 App.init `register(forTaskWithIdentifier:using:nil)`；submit `BGAppRefreshTaskRequest`；id `dev.moooyo.tessera.sync` 与 plist 匹配；UIBackgroundModes fetch+processing（AppEnvironment.swift:174-198; TesseraApp.swift:38, 69-71; Info-iOS.plist:50-58）。校验: Xcode：在设备上 build+run；验证 identifier 匹配且 register 在 launch 完成前运行。若不符: 按写法正确；确保 register 留在 App.init（确实如此）。
- [ ] **`NSBackgroundActivityScheduler`（schedule/qualityOfService/interval/repeats）** — macOS 周期性 ~30min 同步；`schedule { completion in ... completion(.finished) }`（AppEnvironment.swift:64, 214-227; TesseraMacApp.swift:34）。校验: Xcode：稳定的 Foundation API；确认 `NSBackgroundActivityScheduler.Result.finished`。若不符: 长期存在的 API，无回退。

---

## 五、高风险（先核对这几个）

以下为所有区域中 certainty 为 **uncertain** 的项，建议在 Xcode 选中后**优先**核对：

- [ ] **信号量桥接的 async DB-passphrase 引导（`Task.detached` + `DispatchSemaphore.wait`）** — AppEnvironment.swift:272-293（makeStore:256）。`@MainActor` init 中 `semaphore.wait()` 阻塞主线程，strict concurrency 下有死锁/优先级反转风险。**最高风险**：改用同步 Keychain `SecItem` 读取。
- [ ] **`ConcentricRectangle(corners:isUniform:)`** — ConcentricRectangleCard.swift:51（被 VaultListView.swift:43、MacItemDetailView.swift:164 消费）。init 签名 `corners:isUniform:` 与 `.concentric(minimum:)`/`.fixed()` 辅助需在 Xcode 确认；不符则回退 `RoundedRectangle(cornerRadius:)`。
- [ ] **`.searchable(text:placement:prompt:)`（placement `.toolbar`）** — MainTabView.swift:84。`SearchFieldPlacement.toolbar` 在 iOS 上是否存在待确认；不符则用 `.automatic`。
- [ ] **`.scrollEdgeEffectStyle(_:for:)`** — VaultListView.swift:74。`for:` 参数类型与 `.all` / `.soft` 成员需确认；不符则 `for:` 用 `[.top, .bottom]`。
- [ ] **`ConcentricRectangleCard`（DesignSystem 包装器）** — VaultListView.swift:43。需打开 DesignSystem 确认内部是 `ConcentricRectangle`（iOS 26）还是 `RoundedRectangle`。
- [ ] **`ConcentricRectangle`（macOS 侧，原始 shape，间接）** — MacItemDetailView.swift:164。仅经 `ConcentricRectangleCard` 包装器使用；需单独验证包装器实现是否用原始 macOS 26 shape。

---

> 注：12 个库 package 已通过 838 项检查，**不在**本清单范围内；本文件仅针对 `App/`（Xcode-only）源码。
