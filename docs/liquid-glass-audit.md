# OpenVault：Liquid Glass 设计核对

2026-11-19，范围为 iPhone、iPad、Mac 应用和 AutoFill 的 SwiftUI 界面。本次检查的基线是 OpenVault `e4b8337`，不是早期 Tessera 原型。

**结论：原设计部分符合。** 系统标签栏、搜索角色以及不透明的保险库列表值得保留；问题主要来自覆盖系统导航的自绘材质、模拟玻璃的验证码卡，以及不能跟随系统的外观。Apple 的[技术概览](https://developer.apple.com/documentation/technologyoverviews/liquid-glass)、[采用指南](https://developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass)和 [HIG 材质指南](https://developer.apple.com/design/human-interface-guidelines/materials#Liquid-Glass)强调区分内容与操作，不要求每个界面都使用玻璃。普通内容也可以使用标准材质；**秘密字段始终使用实色**是 OpenVault 自己的选择。

| 区域 | 原有问题 | 现在的设计 |
| --- | --- | --- |
| 保险库与验证码 | Mac 验证码卡手绘高光、光晕和投影；普通字段按钮也有独立玻璃外观。 | 密码、卡号和 OTP 使用不透明系统底色。复制和显示是有名称的行内按钮；验证码保持等宽、倒计时仍更新。 |
| iPhone | 设置同时占用标签栏及保险库入口，紧凑布局拥挤。 | 四个业务标签加一个系统搜索入口；设置用保险库工具栏的齿轮进入，新建用加号。搜索直接聚焦到保险库查询。 |
| iPad 与 Mac | 手绘的选中状态；Mac 在系统侧栏上叠玻璃，列表还有没有实际行为的前进、后退箭头。 | 用 `NavigationSplitView` 和系统列表处理选择。浏览时显示侧栏、列表与详情；工具页只留侧栏与工具。排序、编辑和搜索随系统工具栏布局。 |
| 外观与动效 | 应用内滑杆可让普通界面使用清透玻璃；Mac 窗口固定深色。 | 移除滑杆，保留跟随系统、浅色和深色主题。自定义浮动反馈默认用常规玻璃，开启减少透明度或增强对比度时改用实色；减弱动态效果不会停止验证码计时。 |
| 主要按钮 | 深色且增强对比度时，解锁、复制验证码的白字落在浅蓝底上。 | 普通外观保留系统显著按钮；增强对比度时仍用系统按钮，但明确区分前景和填充。 |
| AutoFill | 长列表中取消操作会滚出视野；同名账号不易通过读屏区分。 | iPhone/iPad 使用原生取消工具项，Mac 将取消固定在滚动区域外。候选项可读出账号、域名和类型，不显示或播报网址里的用户信息、路径或查询参数。 |
| App 图标 | 单层 PNG 将高光烘焙进图像。 | 保留盾牌与钥匙孔，改为[分层图标](../App/Shared/OpenVault.icon/icon.json)。系统负责遮罩与不同外观的合成，见 [Apple 的 Icon Composer 指南](https://developer.apple.com/documentation/xcode/creating-your-app-icon-using-icon-composer)。 |

## 原生截图

均为实际 SwiftUI 界面，使用独立测试宿主与内存演示数据，不包含真实保险库凭据。

- [iPhone：保险库与独立搜索入口](assets/liquid-glass/iphone-vault.png)
- [iPhone：辅助大字号、深色、增强对比度下的解锁操作](assets/liquid-glass/iphone-unlock.png)
- [iPad：深色、增强对比度下的验证码工作区](assets/liquid-glass/ipad-codes.png)
- [Mac：浅色保险库、系统侧栏与窗口工具栏](assets/liquid-glass/mac-vault.png)
- [Mac：深色验证码详情与剩余秒数](assets/liquid-glass/mac-codes.png)（左上紫色标记是系统窗口共享提示）。

## 回归验证

- `swift run DesignSystemTests`：42 项通过。覆盖减少透明度、增强对比度的四种组合，验证正文始终不透明，浮动反馈只在合适时使用玻璃。
- `swift run UISharedTests`：104 项通过，覆盖登录、解锁、搜索、设置、生成器及条目详情的视图模型行为。
- Xcode 27.3：iOS、macOS 两个生产 scheme 均通过无签名构建，包含各自的 AutoFill 扩展。Icon Composer 已导出默认、深色、清透及着色版本，产物的主图标均指向 `OpenVault`。
- iPhone 18 Pro 跑通了标签与搜索、主密码面板、滚动后取消 AutoFill 三项测试；深色、辅助大字号和增强对比度下再次通过。iPad Pro 13 英寸实测从侧栏进入验证码及生成器。Mac 用虚构账户实际检查了切换主题、`⌘K` 搜索和编辑面板。
- 按 [Apple 的无障碍对比度指导](https://developer.apple.com/design/human-interface-guidelines/accessibility)，取原始模拟器截图，对字形实心区域和相邻按钮底色做 sRGB 相对亮度比较。深色且增强对比度时，iPhone 解锁从 **2.18:1** 提高到 **21:1**，iPad 复制验证码从 **2.15:1** 提高到 **21:1**。切换为浅色并保持增强对比度，两处也测得 **21:1**。这些数值只描述所测按钮，不是整屏评分。
- iOS 界面测试使用[单独的测试工程](../Tests/Interface/project.yml)，不在生产 App 中添加测试账户或免登录入口。在仓库根目录运行以下命令，分别选择 iPhone 和 iPad 模拟器：

```sh
xcodegen generate --spec Tests/Interface/project.yml
xcodebuild -project Tests/Interface/InterfaceChecks.xcodeproj -scheme InterfaceChecks \
  -destination 'platform=iOS Simulator,name=iPhone 18 Pro,OS=27.3' -parallel-testing-enabled NO test
xcodebuild -project Tests/Interface/InterfaceChecks.xcodeproj -scheme InterfaceChecks \
  -destination 'platform=iOS Simulator,name=iPad Pro 13-inch (M5),OS=27.3' -parallel-testing-enabled NO test
```

界面测试检查实际点击、键盘与读屏标签，不等同于人工听过 VoiceOver。签名真机上的 Face ID、Touch ID 及从系统密码选择器完成填充，仍需单独验收。
