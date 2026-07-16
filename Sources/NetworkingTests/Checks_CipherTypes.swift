import Foundation
import CryptoCore
import Networking

func checkCompleteCipherRequestEncoding(_ r: inout TestRunner) {
    let key = try! SymmetricCryptoKey(combined: Data((0..<64).map(UInt8.init)))
    func enc(_ value: String) -> EncString {
        try! SymmetricCrypto.encrypt(Data(value.utf8), using: key)
    }

    let privateKey = enc("private")
    let publicKey = enc("public")
    let fingerprint = enc("fingerprint")
    let request = CipherRequest(
        type: 5,
        name: enc("SSH"),
        sshKey: CipherSshKeyRequest(privateKey: privateKey, publicKey: publicKey,
                                    keyFingerprint: fingerprint),
        fields: [CipherFieldRequest(type: 3, name: enc("field"),
                                    value: enc("value"), linkedId: 42)]
    )

    do {
        let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(request))
        guard let root = object as? [String: Any],
              let ssh = root["sshKey"] as? [String: Any],
              let fields = root["fields"] as? [[String: Any]],
              let field = fields.first else {
            r.expectTrue(false, "complete CipherRequest JSON shape")
            return
        }
        r.expect(ssh["privateKey"] as? String, privateKey.stringValue,
                 "CipherRequest encodes SSH private key wire string")
        r.expect(ssh["publicKey"] as? String, publicKey.stringValue,
                 "CipherRequest encodes SSH public key wire string")
        r.expect(ssh["keyFingerprint"] as? String, fingerprint.stringValue,
                 "CipherRequest encodes SSH fingerprint wire string")
        r.expect((field["linkedId"] as? NSNumber)?.intValue, 42,
                 "CipherRequest encodes custom-field linkedId")
    } catch {
        r.expectTrue(false, "complete CipherRequest encoding threw: \(error)")
    }
}
