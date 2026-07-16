// Xcode-only target (UI-iOS / UI-mac). Not part of the SPM build.
//
// MacItemEditView — create / edit any of Bitwarden's five `PlaintextCipher` item types.
// Presented as a sheet from `MacMainView`/`MacItemDetailView`; calls the
// `VaultService` CRUD directly and hands the saved id back via `onSaved`.

import SwiftUI
import UIShared
import DesignSystem
import VaultRepository
import VaultModels

@available(macOS 26.0, *)
struct MacItemEditView: View {
    private let vault: VaultService
    private let existing: PlaintextCipher?
    private let onSaved: (String) -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var type: Int
    @State private var name: String
    @State private var loginDraft: LoginDraft
    @State private var cardDraft: CardDraft
    @State private var identityDraft: IdentityDraft
    @State private var sshKeyDraft: SshKeyDraft
    @State private var notes: String
    @State private var favorite: Bool
    @State private var revealPassword = false
    @State private var revealCardNumber = false
    @State private var revealCardCode = false
    @State private var revealSSN = false
    @State private var revealPassportNumber = false
    @State private var revealLicenseNumber = false
    @State private var revealPrivateKey = false
    @State private var isSaving = false
    @State private var errorMessage: String?

    init(vault: VaultService, existing: PlaintextCipher? = nil, onSaved: @escaping (String) -> Void) {
        self.vault = vault
        self.existing = existing
        self.onSaved = onSaved
        _type = State(initialValue: existing?.type ?? CipherType.login.rawValue)
        _name = State(initialValue: existing?.name ?? "")
        _loginDraft = State(initialValue: LoginDraft(existing?.login))
        _cardDraft = State(initialValue: CardDraft(existing?.card))
        _identityDraft = State(initialValue: IdentityDraft(existing?.identity))
        _sshKeyDraft = State(initialValue: SshKeyDraft(existing?.sshKey))
        _notes = State(initialValue: existing?.notes ?? "")
        _favorite = State(initialValue: existing?.favorite ?? false)
    }

    private var selectedType: CipherType { CipherType(rawValue: type) }
    private var canSave: Bool {
        guard case .unknown = selectedType else {
            return !name.trimmingCharacters(in: .whitespaces).isEmpty && !isSaving
        }
        return false
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    Picker("Type", selection: $type) {
                        Text("Login").tag(CipherType.login.rawValue)
                        Text("Secure Note").tag(CipherType.secureNote.rawValue)
                        Text("Card").tag(CipherType.card.rawValue)
                        Text("Identity").tag(CipherType.identity.rawValue)
                        Text("SSH Key").tag(CipherType.sshKey.rawValue)
                    }
                    .disabled(existing != nil)
                    TextField("Name", text: $name)
                    Toggle("Favorite", isOn: $favorite)
                    if existing != nil {
                        Text("An existing item's type cannot be changed because its encrypted payload is type-specific.")
                            .font(Typography.caption)
                            .foregroundStyle(Palette.secondaryText)
                    }
                }

                typeSpecificFields

                Section("Notes") {
                    TextField("Notes", text: $notes, axis: .vertical)
                        .lineLimit(3...8)
                }

                if let errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(Palette.danger)
                        .font(Typography.rowSubtitle)
                }
            }
            .formStyle(.grouped)

            Divider()

            HStack {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                if isSaving {
                    ProgressView().controlSize(.small)
                } else {
                    Button("Save") { save() }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                        .disabled(!canSave)
                }
            }
            .padding(Spacing.lg)
        }
        .frame(width: 560, height: 700)
    }

    @ViewBuilder
    private var typeSpecificFields: some View {
        switch selectedType {
        case .login:
            Section("Login") {
                TextField("Username", text: $loginDraft.username)
                SecretEntryField(title: "Password", text: $loginDraft.password,
                                 isRevealed: $revealPassword)
                TextField("Authenticator key (TOTP)", text: $loginDraft.totp)
                TextField("Website (URI)", text: $loginDraft.uri)
            }

        case .secureNote:
            EmptyView()

        case .card:
            Section("Card") {
                TextField("Cardholder name", text: $cardDraft.cardholderName)
                TextField("Brand", text: $cardDraft.brand)
                SecretEntryField(title: "Card number", text: $cardDraft.number,
                                 isRevealed: $revealCardNumber)
                HStack {
                    TextField("Exp. month", text: $cardDraft.expMonth)
                    TextField("Exp. year", text: $cardDraft.expYear)
                }
                SecretEntryField(title: "Security code (CVV)", text: $cardDraft.code,
                                 isRevealed: $revealCardCode)
            }

        case .identity:
            Section("Name") {
                TextField("Title", text: $identityDraft.title)
                TextField("First name", text: $identityDraft.firstName)
                TextField("Middle name", text: $identityDraft.middleName)
                TextField("Last name", text: $identityDraft.lastName)
            }
            Section("Contact") {
                TextField("Username", text: $identityDraft.username)
                TextField("Company", text: $identityDraft.company)
                TextField("Email", text: $identityDraft.email)
                TextField("Phone", text: $identityDraft.phone)
            }
            Section("Address") {
                TextField("Address line 1", text: $identityDraft.address1)
                TextField("Address line 2", text: $identityDraft.address2)
                TextField("Address line 3", text: $identityDraft.address3)
                TextField("City", text: $identityDraft.city)
                TextField("State / Province", text: $identityDraft.state)
                TextField("Postal code", text: $identityDraft.postalCode)
                TextField("Country", text: $identityDraft.country)
            }
            Section("Identification") {
                SecretEntryField(title: "Social Security number", text: $identityDraft.ssn,
                                 isRevealed: $revealSSN)
                SecretEntryField(title: "Passport number", text: $identityDraft.passportNumber,
                                 isRevealed: $revealPassportNumber)
                SecretEntryField(title: "License number", text: $identityDraft.licenseNumber,
                                 isRevealed: $revealLicenseNumber)
            }

        case .sshKey:
            Section("SSH Key") {
                SecretEntryField(title: "Private key", text: $sshKeyDraft.privateKey,
                                 isRevealed: $revealPrivateKey, multiline: true)
                TextField("Public key", text: $sshKeyDraft.publicKey, axis: .vertical)
                    .lineLimit(2...6)
                    .font(Typography.secretValue)
                TextField("Fingerprint", text: $sshKeyDraft.keyFingerprint)
                    .font(Typography.secretValue)
            }

        case .unknown:
            Section {
                Text("This item type is not editable in this version.")
                    .foregroundStyle(Palette.secondaryText)
            }
        }
    }

    private func save() {
        isSaving = true
        errorMessage = nil
        let cipher = buildCipher()
        Task {
            do {
                if let id = existing?.id {
                    try await vault.updateCipher(id: id, cipher)
                    onSaved(id)
                } else {
                    let newID = try await vault.createCipher(cipher)
                    onSaved(newID)
                }
                dismiss()
            } catch {
                errorMessage = "Could not save the item. Please try again."
            }
            isSaving = false
        }
    }

    private func buildCipher() -> PlaintextCipher {
        let login = selectedType == .login
            ? loginDraft.value(preserving: existing?.login)
            : existing?.login
        let card = selectedType == .card ? cardDraft.value : existing?.card
        let identity = selectedType == .identity ? identityDraft.value : existing?.identity
        let secureNote = selectedType == .secureNote
            ? (existing?.secureNote ?? PlaintextCipher.SecureNote())
            : existing?.secureNote
        let sshKey = selectedType == .sshKey ? sshKeyDraft.value : existing?.sshKey
        return PlaintextCipher(
            id: existing?.id,
            type: type,
            name: name.trimmingCharacters(in: .whitespaces),
            notes: notes.nilIfEmpty,
            folderID: existing?.folderID,
            organizationID: existing?.organizationID,
            protectedCipherKey: existing?.protectedCipherKey,
            favorite: favorite,
            reprompt: existing?.reprompt ?? 0,
            login: login,
            card: card,
            identity: identity,
            secureNote: secureNote,
            sshKey: sshKey,
            fields: existing?.fields ?? []
        )
    }
}

@available(macOS 26.0, *)
private struct SecretEntryField: View {
    let title: String
    @Binding var text: String
    @Binding var isRevealed: Bool
    var multiline = false

    var body: some View {
        HStack(alignment: multiline ? .top : .center) {
            Group {
                if isRevealed {
                    if multiline {
                        TextField(title, text: $text, axis: .vertical)
                            .lineLimit(3...10)
                    } else {
                        TextField(title, text: $text)
                    }
                } else {
                    SecureField(title, text: $text)
                }
            }
            .font(isRevealed ? Typography.secretValue : Typography.rowTitle)
            .privacySensitive()

            Button {
                isRevealed.toggle()
            } label: {
                Image(systemName: isRevealed ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(isRevealed ? "Hide \(title)" : "Reveal \(title)")
        }
    }
}

private struct LoginDraft {
    var username: String
    var password: String
    var totp: String
    var uri: String

    init(_ login: PlaintextCipher.Login?) {
        username = login?.username ?? ""
        password = login?.password ?? ""
        totp = login?.totp ?? ""
        uri = login?.uris.first?.uri ?? ""
    }

    func value(preserving existing: PlaintextCipher.Login?) -> PlaintextCipher.Login {
        var uris = existing?.uris ?? []
        if let primaryURI = uri.nilIfEmpty {
            if uris.isEmpty {
                uris.append(PlaintextCipher.Uri(uri: primaryURI))
            } else {
                uris[0].uri = primaryURI
            }
        } else if !uris.isEmpty {
            uris.removeFirst()
        }
        let passwordValue = password.nilIfEmpty
        let passwordRevisionDate: Date?
        if passwordValue == existing?.password {
            passwordRevisionDate = existing?.passwordRevisionDate
        } else {
            passwordRevisionDate = passwordValue == nil ? nil : Date()
        }
        return PlaintextCipher.Login(
            username: username.nilIfEmpty,
            password: passwordValue,
            totp: totp.nilIfEmpty,
            uris: uris,
            fido2Credentials: existing?.fido2Credentials ?? [],
            passwordRevisionDate: passwordRevisionDate
        )
    }
}

private struct CardDraft {
    var cardholderName: String
    var brand: String
    var number: String
    var expMonth: String
    var expYear: String
    var code: String

    init(_ card: PlaintextCipher.Card?) {
        cardholderName = card?.cardholderName ?? ""
        brand = card?.brand ?? ""
        number = card?.number ?? ""
        expMonth = card?.expMonth ?? ""
        expYear = card?.expYear ?? ""
        code = card?.code ?? ""
    }

    var value: PlaintextCipher.Card {
        PlaintextCipher.Card(
            cardholderName: cardholderName.nilIfEmpty,
            brand: brand.nilIfEmpty,
            number: number.nilIfEmpty,
            expMonth: expMonth.nilIfEmpty,
            expYear: expYear.nilIfEmpty,
            code: code.nilIfEmpty
        )
    }
}

private struct IdentityDraft {
    var title: String
    var firstName: String
    var middleName: String
    var lastName: String
    var address1: String
    var address2: String
    var address3: String
    var city: String
    var state: String
    var postalCode: String
    var country: String
    var company: String
    var email: String
    var phone: String
    var ssn: String
    var username: String
    var passportNumber: String
    var licenseNumber: String

    init(_ identity: PlaintextCipher.Identity?) {
        title = identity?.title ?? ""
        firstName = identity?.firstName ?? ""
        middleName = identity?.middleName ?? ""
        lastName = identity?.lastName ?? ""
        address1 = identity?.address1 ?? ""
        address2 = identity?.address2 ?? ""
        address3 = identity?.address3 ?? ""
        city = identity?.city ?? ""
        state = identity?.state ?? ""
        postalCode = identity?.postalCode ?? ""
        country = identity?.country ?? ""
        company = identity?.company ?? ""
        email = identity?.email ?? ""
        phone = identity?.phone ?? ""
        ssn = identity?.ssn ?? ""
        username = identity?.username ?? ""
        passportNumber = identity?.passportNumber ?? ""
        licenseNumber = identity?.licenseNumber ?? ""
    }

    var value: PlaintextCipher.Identity {
        PlaintextCipher.Identity(
            title: title.nilIfEmpty,
            firstName: firstName.nilIfEmpty,
            middleName: middleName.nilIfEmpty,
            lastName: lastName.nilIfEmpty,
            address1: address1.nilIfEmpty,
            address2: address2.nilIfEmpty,
            address3: address3.nilIfEmpty,
            city: city.nilIfEmpty,
            state: state.nilIfEmpty,
            postalCode: postalCode.nilIfEmpty,
            country: country.nilIfEmpty,
            company: company.nilIfEmpty,
            email: email.nilIfEmpty,
            phone: phone.nilIfEmpty,
            ssn: ssn.nilIfEmpty,
            username: username.nilIfEmpty,
            passportNumber: passportNumber.nilIfEmpty,
            licenseNumber: licenseNumber.nilIfEmpty
        )
    }
}

private struct SshKeyDraft {
    var privateKey: String
    var publicKey: String
    var keyFingerprint: String

    init(_ sshKey: PlaintextCipher.SshKey?) {
        privateKey = sshKey?.privateKey ?? ""
        publicKey = sshKey?.publicKey ?? ""
        keyFingerprint = sshKey?.keyFingerprint ?? ""
    }

    var value: PlaintextCipher.SshKey {
        PlaintextCipher.SshKey(
            privateKey: privateKey.nilIfEmpty,
            publicKey: publicKey.nilIfEmpty,
            keyFingerprint: keyFingerprint.nilIfEmpty
        )
    }
}

private extension String {
    var nilIfEmpty: String? {
        trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : self
    }
}
