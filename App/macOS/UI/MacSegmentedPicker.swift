import AppKit
import SwiftUI

struct MacSegmentedPicker<Option: Hashable>: NSViewRepresentable {
    let label: String
    let options: [Option]
    @Binding var selection: Option
    let title: (Option) -> String
    @Environment(\.isEnabled) private var isEnabled

    init(_ label: String, options: [Option], selection: Binding<Option>, title: @escaping (Option) -> String) {
        self.label = label
        self.options = options
        _selection = selection
        self.title = title
    }

    func makeCoordinator() -> Coordinator { Coordinator(picker: self) }

    func makeNSView(context: Context) -> NSSegmentedControl {
        let control = NSSegmentedControl()
        control.trackingMode = .selectOne
        control.segmentDistribution = .fillEqually
        control.target = context.coordinator
        control.action = #selector(Coordinator.selectSegment(_:))
        return control
    }

    func updateNSView(_ control: NSSegmentedControl, context: Context) {
        context.coordinator.picker = self
        if control.segmentCount != options.count { control.segmentCount = options.count }
        for (index, option) in options.enumerated() {
            let text = title(option)
            if control.label(forSegment: index) != text { control.setLabel(text, forSegment: index) }
        }
        control.selectedSegment = options.firstIndex(of: selection) ?? -1
        control.isEnabled = isEnabled
        control.setAccessibilityLabel(label)
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: NSSegmentedControl, context: Context) -> CGSize? {
        let intrinsic = nsView.intrinsicContentSize
        return CGSize(width: proposal.width.flatMap { $0.isFinite ? $0 : nil } ?? intrinsic.width, height: intrinsic.height)
    }

    @MainActor
    final class Coordinator: NSObject {
        var picker: MacSegmentedPicker

        init(picker: MacSegmentedPicker) { self.picker = picker }

        @objc func selectSegment(_ control: NSSegmentedControl) {
            guard picker.options.indices.contains(control.selectedSegment) else { return }
            picker.selection = picker.options[control.selectedSegment]
        }
    }
}
