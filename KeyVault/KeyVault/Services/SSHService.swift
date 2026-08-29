import Foundation

actor SSHService {
    private let shell = ShellService()
    private static let sshKeygenPath = "/usr/bin/ssh-keygen"
    private static let sshDir = NSHomeDirectory() + "/.ssh"

    func loadKeys() async throws -> [EncryptionKey] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: Self.sshDir) else { return [] }

        let contents = (try? fm.contentsOfDirectory(atPath: Self.sshDir)) ?? []
        let pubFiles = contents.filter { $0.hasSuffix(".pub") }

        var keys: [EncryptionKey] = []
        for pubFile in pubFiles {
            let pubPath = Self.sshDir + "/" + pubFile
            let privateName = String(pubFile.dropLast(4)) // remove .pub
            let privatePath = Self.sshDir + "/" + privateName

            let result = try await shell.run(
                Self.sshKeygenPath,
                arguments: ["-l", "-E", "sha256", "-f", pubPath]
            )

            guard result.status == 0 else { continue }

            // Output format: "2048 SHA256:xxxx comment (RSA)"
            let output = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            let parts = output.split(separator: " ", maxSplits: 3)

            var fingerprint: String?
            var algorithm: String?

            if parts.count >= 2 {
                fingerprint = String(parts[1])
            }
            if parts.count >= 4 {
                let last = String(parts[3])
                algorithm = last.trimmingCharacters(in: CharacterSet(charactersIn: "()"))
            }

            let pubKeyText = (try? String(contentsOfFile: pubPath, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
            let hasPrivate = fm.fileExists(atPath: privatePath)

            let key = EncryptionKey(
                id: UUID(stableIdentity: "ssh:\(privatePath)"),
                type: .ssh,
                name: privateName,
                fingerprint: fingerprint,
                publicKey: pubKeyText,
                algorithm: algorithm,
                path: privatePath,
                hasPrivateKey: hasPrivate
            )
            keys.append(key)
        }

        return keys.sorted { $0.name < $1.name }
    }

    func generate(
        algorithm: String,
        bits: Int?,
        comment: String,
        path: String,
        passphrase: String
    ) async throws {
        var args = ["-t", algorithm]
        if let bits = bits {
            args += ["-b", "\(bits)"]
        }
        args += ["-C", comment, "-f", path, "-N", passphrase]

        let result = try await shell.run(Self.sshKeygenPath, arguments: args)
        guard result.status == 0 else {
            throw KeyError.keygenFailed(result.stderr.isEmpty ? result.stdout : result.stderr)
        }
    }

}
