// Xcode-only target. Not part of the SPM build.
//
// HostingSupport — platform-conditional SwiftUI hosting for the extension principal class.
//
// `ASCredentialProviderViewController` is a `UIViewController` on iOS and an `NSViewController`
// on macOS, so embedding a SwiftUI view differs by platform. These shims keep the principal
// class platform-agnostic.

import SwiftUI

#if os(iOS)
import UIKit

/// iOS hosting controller alias.
typealias UIHostingControllerCompat = UIHostingController

extension CredentialProviderViewController {
    /// Add a hosting controller as a pinned child filling the extension's view.
    func addChildController(_ child: UIViewController) {
        // Remove any previously embedded child (the lifecycle methods can be called in sequence).
        children.forEach { $0.willMove(toParent: nil); $0.view.removeFromSuperview(); $0.removeFromParent() }

        addChild(child)
        child.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(child.view)
        NSLayoutConstraint.activate([
            child.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            child.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            child.view.topAnchor.constraint(equalTo: view.topAnchor),
            child.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        child.didMove(toParent: self)
    }
}
#elseif os(macOS)
import AppKit

/// macOS hosting controller alias.
typealias UIHostingControllerCompat = NSHostingController

extension CredentialProviderViewController {
    /// Add a hosting controller as a pinned child filling the extension's view.
    func addChildController(_ child: NSViewController) {
        children.forEach { $0.view.removeFromSuperview(); $0.removeFromParent() }

        addChild(child)
        child.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(child.view)
        NSLayoutConstraint.activate([
            child.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            child.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            child.view.topAnchor.constraint(equalTo: view.topAnchor),
            child.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }
}
#endif
