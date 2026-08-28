import Foundation

actor GPGService {
    private let shell = ShellService()
    private static let gpgPaths = ["/usr/local/bin/gpg", "/opt/homebrew/bin/gpg", "/usr/bin/gpg"]

    private func gpgPath() throws -> String {
        for path in Self.gpgPaths {
            if FileManager.default.fileExists(atPath: path) { return path }
        }
        throw KeyError.toolNotFound("gpg")
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

    func generate(name: String, email: String, algorithm: String, expiry: String) async throws {
        let gpg = try gpgPath()
        let batchInput = """
        %no-protection
        Key-Type: \(algorithm)
        Key-Length: 4096
        Subkey-Type: \(algorithm)
        Subkey-Length: 4096
        Name-Real: \(name)
        Name-Email: \(email)
        Expire-Date: \(expiry)
        %commit
        """
        guard let data = batchInput.data(using: .utf8) else {
            throw KeyError.keygenFailed("Failed to encode batch input")
        }
        let result = try await shell.runWithStdin(gpg, arguments: ["--batch", "--full-generate-key"], stdinData: data)
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

    func deleteKey(_ keyID: String, includeSecret: Bool) async throws {
        let gpg = try gpgPath()
        if includeSecret {
            let secResult = try await shell.run(gpg, arguments: ["--batch", "--yes", "--delete-secret-and-public-key", keyID])
            guard secResult.status == 0 else {
                throw KeyError.exportFailed(secResult.stderr)
            }
        } else {
            let pubResult = try await shell.run(gpg, arguments: ["--batch", "--yes", "--delete-key", keyID])
            guard pubResult.status == 0 else {
                throw KeyError.exportFailed(pubResult.stderr)
            }
        }
    }
}
