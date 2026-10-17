import XCTest
@testable import KeyVault

/// `SSHService.generate` hands ssh-keygen its passphrase through askpass rather
/// than on the command line. These run the real ssh-keygen, because what
/// matters is whether the key it writes is protected, and only ssh-keygen can
/// say.
final class SSHServiceGenerateTests: XCTestCase {

    private func scratchDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("keyvault-ssh-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        return dir
    }

    /// Whether ssh-keygen can read the private key with this passphrase. An
    /// empty one asks whether the key is protected at all.
    private func opens(_ path: String, with passphrase: String) async throws -> Bool {
        let result = try await ShellService().run(
            "/usr/bin/ssh-keygen", arguments: ["-y", "-P", passphrase, "-f", path]
        )
        return result.status == 0
    }

    func testAPassphraseProtectsTheKey() async throws {
        let dir = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("id_ed25519").path

        try await SSHService().generate(algorithm: "ed25519", bits: nil, comment: "test",
                                        path: path, passphrase: "correct horse battery")

        let opensWithIt = try await opens(path, with: "correct horse battery")
        let opensWithout = try await opens(path, with: "")
        XCTAssertTrue(opensWithIt)
        XCTAssertFalse(opensWithout)
        XCTAssertTrue(FileManager.default.fileExists(atPath: path + ".pub"))
    }

    func testNoPassphraseWritesAnOpenKey() async throws {
        let dir = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("id_ed25519").path

        try await SSHService().generate(algorithm: "ed25519", bits: nil, comment: "test",
                                        path: path, passphrase: "")

        let opensWithout = try await opens(path, with: "")
        XCTAssertTrue(opensWithout)
    }

    /// The askpass directory goes once ssh-keygen is done with it.
    func testLeavesNoAskpassBehind() async throws {
        let dir = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("id_ed25519").path
        // Compared with what was there before, so one left by an earlier run
        // that crashed does not fail this one.
        func askpassDirectories() throws -> Set<String> {
            try Set(FileManager.default
                .contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)
                .filter { $0.hasPrefix("keyvault-askpass-") })
        }
        let before = try askpassDirectories()

        try await SSHService().generate(algorithm: "ed25519", bits: nil, comment: "test",
                                        path: path, passphrase: "correct horse battery")

        XCTAssertEqual(try askpassDirectories(), before)
    }

    /// A key already at the path is left alone, not overwritten or deleted.
    func testRefusesAPathThatIsTaken() async throws {
        let dir = try scratchDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("id_ed25519").path
        try Data("keep me".utf8).write(to: URL(fileURLWithPath: path))

        do {
            try await SSHService().generate(algorithm: "ed25519", bits: nil, comment: "test",
                                            path: path, passphrase: "correct horse battery")
            XCTFail("generate wrote over an existing key")
        } catch {}

        XCTAssertEqual(try String(contentsOfFile: path, encoding: .utf8), "keep me")
    }
}
