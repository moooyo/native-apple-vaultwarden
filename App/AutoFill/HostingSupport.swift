// Xcode-only target. Not part of the SPM build.
//
import UIKit

extension CredentialProviderViewController {
    func configurePickerPresentation() {
        preferredContentSize = CGSize(width: 460, height: 420)
        sheetPresentationController?.detents = [.medium(), .large()]
        sheetPresentationController?.prefersGrabberVisible = true
    }

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
