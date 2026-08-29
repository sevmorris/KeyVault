import Foundation

actor GPGService {
    private let shell = ShellService()

    private func gpgPath() throws -> String {
        try GPGLocator.resolve()
    }

    func loadKeys() async throws -> [EncryptionKey] {
        let gpg = try gpgPath()

        let pubResult = try await shell.run(gpg, arguments: ["--list-keys", "--with-colons", "--with-fingerprint"])
        let secResult = try await shell.run(gpg, arguments: ["--list-secret-keys", "--with-colons"])

        let secretKeyIDs = parseSecretKeyIDs(from: secResult.stdout)
        return parseKeys(from: pubResult.stdout, secretKeyIDs: secretKeyIDs)
    }

    private func parseSecretKeyIDs(from output: String) -> Set<String> {
        var ids = Set<String>()
        for line in output.components(separatedBy: "\n") {
            let fields = line.components(separatedBy: ":")
            guard fields.count > 4, fields[0] == "sec" else { continue }
            ids.insert(fields[4])
        }
        return ids
    }

    private func parseKeys(from output: String, secretKeyIDs: Set<String>) -> [EncryptionKey] {
        var keys: [EncryptionKey] = []
        var currentKeyID: String?
        var currentAlgorithm: String?
        var currentFingerprint: String?
        var currentName: String?
        var currentCreated: Date?
        var currentExpiry: Date?

        func flushKey() {
            guard let keyID = currentKeyID else { return }
            let hasPrivate = secretKeyIDs.contains(keyID)
            let key = EncryptionKey(
                id: UUID(stableIdentity: "gpg:\(keyID)"),
                type: .gpg,
                name: currentName ?? keyID,
                fingerprint: currentFingerprint,
                keyID: keyID,
                algorithm: currentAlgorithm,
                createdDate: currentCreated,
                expiryDate: currentExpiry,
                hasPrivateKey: hasPrivate
            )
            keys.append(key)
        }

        for line in output.components(separatedBy: "\n") {
            let fields = line.components(separatedBy: ":")
            guard fields.count > 1 else { continue }
            let recordType = fields[0]

            switch recordType {
            case "pub":
                flushKey()
                currentKeyID = fields.count > 4 ? fields[4] : nil
                currentAlgorithm = gpgAlgorithmName(fields.count > 3 ? fields[3] : "")
                currentFingerprint = nil
                currentName = nil
                currentCreated = unixTimestampToDate(fields.count > 5 ? fields[5] : "")
                currentExpiry = unixTimestampToDate(fields.count > 6 ? fields[6] : "")
            case "fpr":
                if currentFingerprint == nil {
                    currentFingerprint = fields.count > 9 ? fields[9] : nil
                }
            case "uid":
                if currentName == nil {
                    currentName = fields.count > 9 ? fields[9] : nil
                }
            default:
                break
            }
        }
        flushKey()
        return keys
    }

    private func gpgAlgorithmName(_ pubkeyAlgoID: String) -> String {
        switch pubkeyAlgoID {
        case "1": return "RSA"
        case "17": return "DSA"
        case "18": return "ECDH"
        case "19": return "ECDSA"
        case "22": return "EdDSA"
        default: return pubkeyAlgoID.isEmpty ? "Unknown" : pubkeyAlgoID
        }
    }

    private func unixTimestampToDate(_ string: String) -> Date? {
        guard let ts = TimeInterval(string), ts > 0 else { return nil }
        return Date(timeIntervalSince1970: ts)
    }

    /// The key-shape parameters for an algorithm.
    ///
    /// Previously every algorithm was emitted as `Key-Length: 4096`, which was
    /// only ever right for RSA. DSA silently accepted it and gave you 3072
    /// anyway — so the key you got was never the key you asked for — and ECDSA
    /// failed outright with "Unknown elliptic curve", meaning that option had
    /// never once produced a key.
    private static func shapeParameters(for algorithm: String) throws -> String {
        switch algorithm.uppercased() {
        case "RSA":
            return """
            Key-Type: RSA
            Key-Length: 4096
            Subkey-Type: RSA
            Subkey-Length: 4096
            """
        case "DSA":
            // 3072 is GnuPG's ceiling for DSA. DSA cannot encrypt, so the
            // encryption subkey is Elgamal — the conventional pairing.
            return """
            Key-Type: DSA
            Key-Length: 3072
            Subkey-Type: ELG-E
            Subkey-Length: 3072
            """
        case "ECDSA":
            // Elliptic curves are named, not measured. ECDH for the subkey,
            // because ECDSA signs and does not encrypt.
            return """
            Key-Type: ECDSA
            Key-Curve: nistp256
            Subkey-Type: ECDH
            Subkey-Curve: nistp256
            """
        default:
            throw KeyError.keygenFailed("Unsupported GPG algorithm: \(algorithm)")
        }
    }

    /// Generate a key pair.
    ///
    /// An empty `passphrase` means an unprotected private key, and the caller
    /// is expected to have said so out loud. It used to be the only option:
    /// `%no-protection` was hardcoded, so every key KeyVault generated sat in
    /// `~/.gnupg` usable by anything that could read the file, and nothing in
    /// the UI mentioned it.
    func generate(
        name: String,
        email: String,
        algorithm: String,
        expiry: String,
        passphrase: String
    ) async throws {
        let gpg = try gpgPath()
        // The parameter block must begin with Key-Type — gpg rejects one that
        // opens with Passphrase — so protection is appended, not prepended.
        let protection = passphrase.isEmpty ? "%no-protection" : "Passphrase: \(passphrase)"
        let batchInput = """
        \(try Self.shapeParameters(for: algorithm))
        Name-Real: \(name)
        Name-Email: \(email)
        Expire-Date: \(expiry)
        \(protection)
        %commit
        """
        guard let data = batchInput.data(using: .utf8) else {
            throw KeyError.keygenFailed("Failed to encode batch input")
        }
        let result = try await shell.runWithStdin(
            gpg,
            // loopback so a passphrase supplied here is used directly rather
            // than gpg-agent trying to raise a pinentry against a tty a GUI
            // app does not have.
            arguments: ["--batch", "--pinentry-mode", "loopback", "--full-generate-key"],
            stdinData: data
        )
        guard result.status == 0 else {
            throw KeyError.keygenFailed(result.stderr.isEmpty ? result.stdout : result.stderr)
        }
    }

    func exportPublicKey(_ keyID: String) async throws -> String {
        let gpg = try gpgPath()
        let result = try await shell.run(gpg, arguments: ["--export", "--armor", keyID])
        guard result.status == 0, !result.stdout.isEmpty else {
            throw KeyError.exportFailed(result.stderr)
        }
        return result.stdout
    }

    func importKey(from path: String) async throws {
        let gpg = try gpgPath()
        let result = try await shell.run(gpg, arguments: ["--import", path])
        guard result.status == 0 else {
            throw KeyError.importFailed(result.stderr.isEmpty ? result.stdout : result.stderr)
        }
    }

    /// Remove a key from the keyring.
    ///
    /// Addressed by fingerprint rather than key id, because gpg refuses a
    /// batch-mode deletion given anything shorter:
    ///
    ///     gpg: can't do this in batch mode
    ///     gpg: (unless you specify the key by fingerprint)
    ///
    /// Without --batch it asks for confirmation on a tty this app does not
    /// have, so passing the key id could never delete anything — every GPG
    /// deletion failed with that message, and reported it as an export
    /// failure into the bargain.
    func deleteKey(fingerprint: String, includeSecret: Bool) async throws {
        let gpg = try gpgPath()
        let option = includeSecret ? "--delete-secret-and-public-key" : "--delete-key"
        let result = try await shell.run(gpg, arguments: ["--batch", "--yes", option, fingerprint])
        guard result.status == 0 else {
            throw KeyError.deleteFailed(result.stderr.isEmpty ? result.stdout : result.stderr)
        }
    }
}
