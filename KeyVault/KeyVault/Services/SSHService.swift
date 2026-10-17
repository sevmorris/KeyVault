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

    /// Generate a key pair at `path`.
    ///
    /// The passphrase never goes on the command line. It used to, as
    /// `-N <passphrase>`, and a process's arguments are public: `ps` shows
    /// them to every account on this Mac for as long as ssh-keygen runs.
    /// ssh-keygen has no option to read a new passphrase from a file or from
    /// stdin, but it will ask an askpass program for one when
    /// SSH_ASKPASS_REQUIRE is "force" — OpenSSH 8.4 and later, older than any
    /// macOS this app runs on. See `Askpass`.
    func generate(
        algorithm: String,
        bits: Int?,
        comment: String,
        path: String,
        passphrase: String
    ) async throws {
        let fm = FileManager.default
        // Refused here rather than left to ssh-keygen, which asks "Overwrite
        // (y/n)?" on a stdin this app does not have. It also means anything at
        // `path` once ssh-keygen has run is something this call made, which
        // is what lets the check below remove it.
        for existing in [path, path + ".pub"] where fm.fileExists(atPath: existing) {
            throw KeyError.keygenFailed(
                "\(existing) already exists. Choose another path, or move that key out of the way first."
            )
        }

        var args = ["-t", algorithm]
        if let bits = bits {
            args += ["-b", "\(bits)"]
        }
        args += ["-C", comment, "-f", path]

        let result: (stdout: String, stderr: String, status: Int32)
        if passphrase.isEmpty {
            // An empty -N is the one passphrase that is safe to show.
            result = try await shell.run(Self.sshKeygenPath, arguments: args + ["-N", ""])
        } else {
            let askpass = try Askpass(passphrase: passphrase)
            defer { askpass.remove() }
            result = try await shell.run(
                Self.sshKeygenPath,
                arguments: args,
                environment: [
                    "SSH_ASKPASS": askpass.script.path,
                    "SSH_ASKPASS_REQUIRE": "force"
                ]
            )
        }
        guard result.status == 0 else {
            throw KeyError.keygenFailed(result.stderr.isEmpty ? result.stdout : result.stderr)
        }

        // An askpass that fails to answer reads to ssh-keygen as an empty
        // passphrase, and it then writes the key unprotected without a word.
        // So check: a key that opens with no passphrase is not protected, and
        // one that was asked to be is removed rather than left on disk looking
        // as though it were. `-P ""` asks nothing when it is wrong; it fails.
        if !passphrase.isEmpty {
            let probe = try await shell.run(Self.sshKeygenPath, arguments: ["-y", "-P", "", "-f", path])
            if probe.status == 0 {
                try? fm.removeItem(atPath: path)
                try? fm.removeItem(atPath: path + ".pub")
                throw KeyError.keygenFailed(
                    "ssh-keygen did not take the passphrase, so the key it wrote was "
                    + "unprotected. It has been deleted rather than kept."
                )
            }
        }
    }

    /// The askpass program ssh-keygen runs for the passphrase: a script that
    /// prints a file. Both live in a 0700 directory, the file at 0600, and the
    /// directory is removed once ssh-keygen is done — the same trade the vault
    /// export makes for gpg, a passphrase briefly on disk where only this
    /// account can reach it, over one on display to every account.
    ///
    /// ssh-keygen asks twice, for the passphrase and to confirm it, and the
    /// script gives the same answer both times.
    private struct Askpass {
        let directory: URL
        let script: URL

        init(passphrase: String) throws {
            let fm = FileManager.default
            directory = fm.temporaryDirectory
                .appendingPathComponent("keyvault-askpass-\(UUID().uuidString)", isDirectory: true)
            try fm.createDirectory(at: directory, withIntermediateDirectories: false,
                                   attributes: [.posixPermissions: 0o700])
            script = directory.appendingPathComponent("askpass")
            do {
                let secret = directory.appendingPathComponent("passphrase")
                try Data(passphrase.utf8).write(to: secret)
                try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: secret.path)

                // The path goes into the script single-quoted. macOS does not
                // hand out a temporary directory with a quote in it, but one
                // that did would break the script, so it is refused instead.
                guard !secret.path.contains("'") else {
                    throw KeyError.keygenFailed("The temporary folder's path cannot be used: \(secret.path)")
                }
                try Data("#!/bin/sh\nexec /bin/cat '\(secret.path)'\n".utf8).write(to: script)
                try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
            } catch {
                try? fm.removeItem(at: directory)
                throw error
            }
        }

        func remove() {
            try? FileManager.default.removeItem(at: directory)
        }
    }
}
