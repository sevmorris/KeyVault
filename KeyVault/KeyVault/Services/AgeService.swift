import Foundation

actor AgeService {
    private let shell = ShellService()
    private static let agekeygenPaths = ["/usr/local/bin/age-keygen", "/opt/homebrew/bin/age-keygen"]

    private func agekeygenPath() -> String? {
        Self.agekeygenPaths.first { FileManager.default.fileExists(atPath: $0) }
    }

    func loadKeys(from paths: [String]) async throws -> [EncryptionKey] {
        var keys: [EncryptionKey] = []
        for rawPath in paths {
            let expandedPath = (rawPath as NSString).expandingTildeInPath
            guard let content = try? String(contentsOfFile: expandedPath, encoding: .utf8) else { continue }
            keys += parseKeyFile(content: content, path: expandedPath)
        }
        return keys
    }

    private func parseKeyFile(content: String, path: String) -> [EncryptionKey] {
        var keys: [EncryptionKey] = []
        var pendingPublicKey: String?
        var pendingCreated: Date?

        for line in content.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if trimmed.hasPrefix("# created: ") {
                let dateStr = String(trimmed.dropFirst("# created: ".count))
                pendingCreated = ISO8601DateFormatter().date(from: dateStr)
            } else if trimmed.hasPrefix("# public key: ") {
                pendingPublicKey = String(trimmed.dropFirst("# public key: ".count))
            } else if trimmed.hasPrefix("AGE-SECRET-KEY-") {
                // Private key line found — create the entry now
                let pubKey = pendingPublicKey ?? ""
                let displayName = pubKey.isEmpty ? "Age Key" : String(pubKey.prefix(20)) + "..."
                let key = EncryptionKey(
                    type: .age,
                    name: displayName,
                    publicKey: pubKey.isEmpty ? nil : pubKey,
                    path: path,
                    createdDate: pendingCreated,
                    hasPrivateKey: true
                )
                keys.append(key)
                pendingPublicKey = nil
                pendingCreated = nil
            }
        }
        return keys
    }

    func generate(outputPath: String) async throws {
        guard let ageKeygen = agekeygenPath() else {
            throw KeyError.toolNotFound("age-keygen")
        }
        let expandedPath = (outputPath as NSString).expandingTildeInPath
        let result = try await shell.run(ageKeygen, arguments: ["-o", expandedPath])
        guard result.status == 0 else {
            throw KeyError.keygenFailed(result.stderr.isEmpty ? result.stdout : result.stderr)
        }
    }

    func publicKeyText(for key: EncryptionKey) throws -> String {
        guard let pubKey = key.publicKey, !pubKey.isEmpty else {
            throw KeyError.exportFailed("No public key available for this Age key")
        }
        return pubKey
    }
}
