# OpenVault 界面交接 · 2026-11-20

**下一步是真机验收。** 这次调整的是 iPhone、iPad、Mac 和 AutoFill 的 SwiftUI 界面，没有更改保险库格式、加密、同步或认证协议。[设计核对报告](../liquid-glass-audit.md)包含改动前后的具体差异、实测对比度、五张脱敏截图和界面测试命令。

## 从哪里继续

以 GitHub `moooyo/native-apple-vaultwarden` 的 `origin/main` 为准。本次改动以 `e4b8337` 为基线，UI 实现与回归测试在 `7092a49`。交接时，原开发目录的本地 `main` 仍在更早的提交且有未提交工作，不要直接在那里切分支、拉取合并或重置。需要另开会话时，可以从仓库根目录创建干净工作树：

```sh
git fetch --prune origin
git worktree add -b codex/liquid-glass-device-qa ../openvault-device-qa origin/main
cd ../openvault-device-qa
```

## 不要回退的行为

- 玻璃留给导航和操作；密码、卡号、验证码始终用不透明底色。旧的染色 API 仅为源码兼容保留，不要把玻璃透明度滑杆接回来。材质和高对比度按钮在 [DesignSystem](../../Sources/DesignSystem)。
- iPhone 的设置在保险库齿轮中；从其他标签点搜索应直接聚焦，关闭后返回原标签。iPad 和 Mac 浏览时三栏、工具页两栏。Mac 搜索保留 `⌘K`。
- AutoFill 的“取消”不随候选列表滚走。显示和朗读网站时只取域名；填充仍使用原始候选对象。不要把网址中的用户信息、路径或令牌放回辅助标签。

## 验证边界

| 已验证 | 尚未由这次验证证明 |
| --- | --- |
| `swift run DesignSystemTests`：42/42；`swift run UISharedTests`：104/104。 | 这不是所有仓库测试或 App Store 发布验收。 |
| 11 月 20 日合并前使用 Xcode 27.3 重跑 `Tessera-iOS`（generic iOS device）和 `Tessera-macOS`（arm64）的 Release 无签名构建；两份产物都嵌入了各自平台的 AutoFill 扩展。 | 构建成功不能证明签名、共享 Keychain、App Group 或真实生物识别可用。 |
| [独立界面测试](../../Tests/Interface/project.yml)使用内存样例，iPhone 3 项、iPad 1 项通过；Mac 用演示数据检查了搜索、编辑、主题和同步操作。 | 辅助功能树检查不等于实际听过 VoiceOver；测试宿主也不是系统的 AutoFill 选择器。 |

仓库保留了测试工程规格和截图。生成的 Xcode 工程、`.app`、`build/` 下的本机预览不随 Git 分发；从干净检出运行 `xcodegen generate` 可重建生产工程，不需要旧会话的演示二进制。

## 下次会话的验收顺序

1. 按 [App 构建与签名说明](../../App/README.md)配置开发团队、App Group、Keychain 共享组和 AutoFill capability。只用专门的测试账户与测试保险库。
2. 在已签名设备上验证 Face ID / Touch ID 的成功、取消、不可用三条路径；关闭生物识别后，主窗口和 Mac 菜单栏都应保留主密码入口。
3. 从系统 AutoFill 选择器完成密码、一次性验证码和通行密钥填充。用两个同名测试账户检查域名区分，滚动长列表后取消，确认请求不会继续。
4. 打开 VoiceOver，实际听一次导航、显示/隐藏密码和复制反馈；再用浅色、深色、增强对比度、减少透明度及减弱动态复核。记录平台、系统版本和复现步骤，不记录真实凭据。
