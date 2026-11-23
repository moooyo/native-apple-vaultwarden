import AppKit
import SwiftUI

struct MacMasterPasswordField: NSViewRepresentable {
    @Binding var text: String
    let prompt: String
    var isRevealed = false
    @Binding var isFocused: Bool
    let accessibilityIdentifier: String
    let onSubmit: () -> Void
    @Environment(\.isEnabled) private var isEnabled

    init(text: Binding<String>, prompt: String, isRevealed: Bool = false, isFocused: Binding<Bool>,
         accessibilityIdentifier: String, onSubmit: @escaping () -> Void) {
        _text = text
        self.prompt = prompt
        self.isRevealed = isRevealed
        _isFocused = isFocused
        self.accessibilityIdentifier = accessibilityIdentifier
        self.onSubmit = onSubmit
    }

    func makeCoordinator() -> Coordinator { Coordinator(owner: self) }

    func makeNSView(context: Context) -> Host {
        let host = Host()
        host.coordinator = context.coordinator
        context.coordinator.update(owner: self, host: host)
        return host
    }

    func updateNSView(_ host: Host, context: Context) {
        context.coordinator.update(owner: self, host: host)
    }

    static func dismantleNSView(_ host: Host, coordinator: Coordinator) {
        host.coordinator = nil
        host.removeField()
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView host: Host, context: Context) -> CGSize? {
        guard let field = host.field else { return nil }
        return CGSize(width: proposal.width.flatMap { $0.isFinite ? $0 : nil } ?? field.intrinsicContentSize.width,
                      height: field.intrinsicContentSize.height)
    }

    final class Host: NSView {
        fileprivate var field: NSTextField?
        fileprivate weak var coordinator: Coordinator?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            coordinator?.updateFocus()
        }

        fileprivate func removeField() {
            guard let field else { return }
            let editor = field.currentEditor()
            field.delegate = nil
            field.abortEditing()
            editor?.string = ""
            field.stringValue = ""
            field.removeFromSuperview()
            self.field = nil
        }

        fileprivate func install(_ field: NSTextField) {
            removeField()
            field.frame = bounds
            field.autoresizingMask = [.width, .height]
            addSubview(field)
            self.field = field
        }
    }

    @MainActor
    final class Coordinator: NSObject, NSTextFieldDelegate {
        private var owner: MacMasterPasswordField
        private weak var host: Host?
        private var selectionToRestore: NSRange?
        private var focusUpdate: Task<Void, Never>?

        init(owner: MacMasterPasswordField) { self.owner = owner }

        fileprivate func update(owner: MacMasterPasswordField, host: Host) {
            self.owner = owner
            self.host = host
            if host.field == nil || owner.isRevealed == (host.field is NSSecureTextField) {
                selectionToRestore = host.field?.currentEditor()?.selectedRange
                host.install(makeField(revealed: owner.isRevealed))
            }
            guard let field = host.field else { return }
            field.isEnabled = owner.isEnabled
            if field.placeholderString != owner.prompt {
                field.placeholderString = owner.prompt
                field.setAccessibilityLabel(owner.prompt)
            }
            field.setAccessibilityIdentifier(owner.accessibilityIdentifier)
            if !field.stringValue.utf8.elementsEqual(owner.text.utf8) { field.stringValue = owner.text }
            updateFocus()
        }

        fileprivate func updateFocus() {
            focusUpdate?.cancel()
            focusUpdate = Task { [weak self] in
                guard !Task.isCancelled, let self, let field = host?.field, let window = field.window else { return }
                if owner.isFocused, field.isEnabled {
                    if field.currentEditor() == nil { window.makeFirstResponder(field) }
                    if let selection = selectionToRestore, let editor = field.currentEditor(),
                       NSMaxRange(selection) <= owner.text.utf16.count {
                        editor.selectedRange = selection
                    }
                } else if field.currentEditor() != nil {
                    window.makeFirstResponder(nil)
                }
                selectionToRestore = nil
            }
        }

        private func makeField(revealed: Bool) -> NSTextField {
            let field = revealed ? NSTextField() : NSSecureTextField()
            let prepareEditor: (NSText) -> Void = { [weak self, weak field] editor in
                configureMasterPasswordEditor(editor)
                self?.reportFocus(for: field)
            }
            let cell: NSTextFieldCell = revealed
                ? MasterPasswordVisibleCell(prepareEditor: prepareEditor)
                : MasterPasswordSecureCell(prepareEditor: prepareEditor)
            cell.usesSingleLineMode = true
            cell.isScrollable = true
            cell.allowedInputSourceLocales = [NSAllRomanInputSourcesLocaleIdentifier]
            field.cell = cell
            field.isBezeled = false
            field.isBordered = false
            field.drawsBackground = false
            field.isEditable = true
            field.isSelectable = true
            field.focusRingType = .none
            field.font = .systemFont(ofSize: 15)
            field.textColor = .labelColor
            field.contentType = .password
            field.allowsWritingTools = false
            field.isAutomaticTextCompletionEnabled = false
            field.allowsCharacterPickerTouchBarItem = false
            field.delegate = self
            return field
        }

        private func reportFocus(for field: NSTextField?) {
            Task { [weak self, weak field] in
                guard let self, let field, field === host?.field, field.isEnabled else { return }
                let focused = field.currentEditor() != nil
                if owner.isFocused != focused { owner.isFocused = focused }
            }
        }

        func controlTextDidEndEditing(_ notification: Notification) {
            reportFocus(for: notification.object as? NSTextField)
        }

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSTextField, field === host?.field else { return }
            owner.text = field.stringValue
        }

        func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
            guard control === host?.field, commandSelector == #selector(NSResponder.insertNewline(_:)),
                  control.isEnabled, !textView.hasMarkedText() else { return false }
            owner.onSubmit()
            return true
        }
    }
}

private final class MasterPasswordSecureCell: NSSecureTextFieldCell {
    private let prepareEditor: (NSText) -> Void

    init(prepareEditor: @escaping (NSText) -> Void) {
        self.prepareEditor = prepareEditor
        super.init(textCell: "")
        echosBullets = true
    }

    @available(*, unavailable)
    required init(coder: NSCoder) { fatalError() }

    override func setUpFieldEditorAttributes(_ textObject: NSText) -> NSText {
        let editor = super.setUpFieldEditorAttributes(textObject)
        prepareEditor(editor)
        return editor
    }
}

private final class MasterPasswordVisibleCell: NSTextFieldCell {
    private let prepareEditor: (NSText) -> Void
    private let editor = NSTextView()

    init(prepareEditor: @escaping (NSText) -> Void) {
        self.prepareEditor = prepareEditor
        super.init(textCell: "")
        editor.isFieldEditor = true
    }

    @available(*, unavailable)
    required init(coder: NSCoder) { fatalError() }

    override func fieldEditor(for controlView: NSView) -> NSTextView? { editor }

    override func setUpFieldEditorAttributes(_ textObject: NSText) -> NSText {
        let editor = super.setUpFieldEditorAttributes(textObject)
        prepareEditor(editor)
        return editor
    }
}

@MainActor private func configureMasterPasswordEditor(_ text: NSText) {
    guard let editor = text as? NSTextView else { return }
    editor.allowsUndo = false
    editor.isContinuousSpellCheckingEnabled = false
    editor.isGrammarCheckingEnabled = false
    editor.isAutomaticSpellingCorrectionEnabled = false
    editor.isAutomaticTextReplacementEnabled = false
    editor.isAutomaticQuoteSubstitutionEnabled = false
    editor.isAutomaticDashSubstitutionEnabled = false
    editor.isAutomaticLinkDetectionEnabled = false
    editor.isAutomaticDataDetectionEnabled = false
    editor.smartInsertDeleteEnabled = false
    editor.isAutomaticTextCompletionEnabled = false
    editor.inlinePredictionType = .no
    editor.mathExpressionCompletionType = .no
    editor.writingToolsBehavior = .none
}
