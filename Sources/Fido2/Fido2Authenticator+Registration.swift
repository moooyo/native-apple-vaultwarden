import Foundation

extension Fido2Authenticator {
    /// WebAuthn registration with `fmt = "none"` (self/none attestation).
    ///
    /// Generates a fresh P-256 credential key, builds attested credential data
    /// (`aaguid(16) || credIdLen(2, big-endian) || credentialId || cosePublicKey`),
    /// embeds it in authenticatorData with the AT flag set, and wraps it in the
    /// attestationObject CBOR map `{"fmt":"none", "attStmt":{}, "authData":<bytes>}`.
    ///
    /// Returns the attestationObject and the generated credential key (whose private
    /// key the caller persists in `fido2Credentials.keyValue` via `exportPKCS8()`).
    public static func register(rpId: String,
                                clientDataHash: Data,
                                credentialId: Data,
                                userVerified: Bool,
                                aaguid: Data = Data(repeating: 0, count: 16)) throws
        -> (attestationObject: Data, credentialKey: CredentialKey) {
        let key = CredentialKey()
        let cose = try COSEKey.encode(publicKeyX963: key.publicKeyX963)

        var acd = Data()
        acd.append(aaguid)
        let len = UInt16(credentialId.count).bigEndian
        acd.append(contentsOf: withUnsafeBytes(of: len) { Array($0) })
        acd.append(credentialId)
        acd.append(cose)

        var flags: AuthenticatorFlags = [.userPresent, .attestedData]
        if userVerified { flags.insert(.userVerified) }
        let authData = authenticatorData(rpId: rpId, flags: flags, signCount: 0,
                                         attestedCredentialData: acd)

        let attObj = CBOR.map([
            (.text("fmt"), .text("none")),
            (.text("attStmt"), .map([])),
            (.text("authData"), .bytes(authData)),
        ]).encoded()

        return (attObj, key)
    }
}
