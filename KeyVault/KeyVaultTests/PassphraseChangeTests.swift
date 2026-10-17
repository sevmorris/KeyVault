import CryptoKit
import XCTest
@testable import KeyVault

/// A passphrase change, run against a Keychain held in memory and a file
/// store in a scratch folder — never the real ones — and interrupted at every
/// write it makes. Whatever step it dies at, `recover` at the next launch must
/// leave a vault that one passphrase or the other opens completely, with
/// nothing staged or pending left behind.
final class PassphraseChangeTests: XCTestCase {

    /// The process dying: every write from here on is refused, and the ones
    /// that cannot throw quietly do nothing.
    private struct Crash: Error {}

    private final class MemoryBackend: RekeyBackend {
        var salt: Data
        var verifier: Data
        var pending: (salt: Data, verifier: Data)?
        var items: [UUID: Data] = [:]
        var staged: [UUID: Data] = [:]

        /// Die on this write, counting from 1.
        var crashAt: Int?
        /// The salt update lands, and then reports failure anyway.
        var saltLandsThenThrows = false
        private(set) var writes = 0
        private var dead = false

        init(salt: Data, verifier: Data) {
            self.salt = salt
            self.verifier = verifier
        }

        /// A fresh launch on the same storage.
        func relaunch() {
            dead = false
            crashAt = nil
            saltLandsThenThrows = false
        }

        private func write() throws {
            if dead { throw Crash() }
            writes += 1
            if let crashAt, writes >= crashAt {
                dead = true
                throw Crash()
            }
        }

        private func quietWrite() -> Bool { (try? write()) != nil }

        func vaultBlobs() -> (salt: Data, verifier: Data)? { (salt, verifier) }
        func pendingBlobs() -> (salt: Data, verifier: Data)? { pending }
        func writePending(salt: Data, verifier: Data) throws {
            try write()
            pending = (salt, verifier)
        }
        func deletePending() { if quietWrite() { pending = nil } }
        func updateSalt(_ salt: Data) throws {
            try write()
            self.salt = salt
            if saltLandsThenThrows { throw Crash() }
        }
        func updateVerifier(_ verifier: Data) throws {
            try write()
            self.verifier = verifier
        }
        func secretIDs() -> [UUID] { items.keys.sorted { $0.uuidString < $1.uuidString } }
        func payload(for id: UUID) -> Data? { items[id] }
        func stage(_ payload: Data, for id: UUID) throws {
            try write()
            staged[id] = payload
        }
        func stagedIDs() -> [UUID] { staged.keys.sorted { $0.uuidString < $1.uuidString } }
        func stagedPayload(for id: UUID) -> Data? { staged[id] }
        func promoteStaged(for id: UUID) throws {
            guard let payload = staged[id] else { return }
            try write()
            if items[id] != nil { items[id] = payload }
            staged[id] = nil
        }
        func discardStaged(for id: UUID) { if quietWrite() { staged[id] = nil } }
    }

    private static let oldPassphrase = "old passphrase"
    private static let newPassphrase = "new passphrase, longer"
    private static let oldSalt = Data(repeating: 0x11, count: 32)
    private static let newSalt = Data(repeating: 0x22, count: 32)
    // Derived once: at 600,000 rounds each derivation is a noticeable pause.
    private static let oldKey = try! VaultCrypto.derive(passphrase: oldPassphrase, salt: oldSalt)
    private static let newKey = try! VaultCrypto.derive(passphrase: newPassphrase, salt: newSalt)

    private var folder: URL!
    private var secrets: [UUID: String] = [:]
    private var plaintextID = UUID()
    private var fileContents: [UUID: Data] = [:]

    override func setUpWithError() throws {
        folder = FileManager.default.temporaryDirectory
            .appending(path: "PassphraseChangeTests-\(UUID().uuidString)", directoryHint: .isDirectory)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: folder)
    }

    /// A vault under the old passphrase: two version 2 secrets, one version 1,
    /// one still in plain text, and two files.
    private func makeVault() throws -> (MemoryBackend, FileStore) {
        let backend = MemoryBackend(salt: Self.oldSalt,
                                    verifier: try VaultCrypto.makeVerifier(using: Self.oldKey))
        secrets = [:]
        for text in ["first secret", "second secret"] {
            let id = UUID()
            secrets[id] = text
            backend.items[id] = try VaultCrypto.encrypt(text, for: id, using: Self.oldKey)
        }
        let legacyID = UUID()
        secrets[legacyID] = "legacy secret"
        backend.items[legacyID] = VaultCrypto.magicV1
            + (try AES.GCM.seal(Data("legacy secret".utf8), using: Self.oldKey).combined!)
        plaintextID = UUID()
        backend.items[plaintextID] = Data("never encrypted".utf8)

        let store = FileStore(directory: folder.appending(path: "Files"), keying: .fixed(Self.oldKey))
        fileContents = [:]
        for (name, bytes) in [("a.pdf", Data(repeating: 1, count: 3000)), ("b.csv", Data("x,y".utf8))] {
            let key = EncryptionKey(type: .file, name: name, fileName: name, hasPrivateKey: false)
            try store.save(key, contents: bytes)
            fileContents[key.id] = bytes
        }
        return (backend, store)
    }

    @discardableResult
    private func change(_ backend: MemoryBackend, _ store: FileStore) throws -> PassphraseChange.Result {
        try PassphraseChange.change(from: Self.oldPassphrase, to: Self.newPassphrase,
                                        backend: backend, files: store.rekeying,
                                        newSalt: Self.newSalt)
    }

    /// The vault opens completely under exactly one of the two passphrases,
    /// and nothing of the change is left lying around. Returns which.
    @discardableResult
    private func assertWhole(_ backend: MemoryBackend, _ store: FileStore,
                             file: StaticString = #filePath, line: UInt = #line) throws -> Bool {
        let isNew = backend.salt == Self.newSalt
        let key = isNew ? Self.newKey : Self.oldKey
        XCTAssertTrue(VaultCrypto.verifier(backend.verifier, accepts: key),
                      "the verifier does not match the salt", file: file, line: line)
        for (id, text) in secrets {
            XCTAssertEqual(try VaultCrypto.decrypt(XCTUnwrap(backend.items[id]), for: id, using: key), text,
                           file: file, line: line)
        }
        XCTAssertEqual(backend.items[plaintextID], Data("never encrypted".utf8), file: file, line: line)

        let reader = FileStore(directory: store.directory, keying: .fixed(key))
        let listing = reader.loadAll()
        XCTAssertEqual(listing.unreadable, [], file: file, line: line)
        XCTAssertEqual(Set(listing.files.map(\.id)), Set(fileContents.keys), file: file, line: line)
        for (id, bytes) in fileContents {
            XCTAssertEqual(try reader.loadContents(for: id), bytes, file: file, line: line)
        }

        XCTAssertNil(backend.pending, "a pending record was left", file: file, line: line)
        XCTAssertTrue(backend.staged.isEmpty, "staged secrets were left", file: file, line: line)
        XCTAssertTrue(store.rekeying.stagedIDs().isEmpty, "staged files were left", file: file, line: line)
        return isNew
    }

    func testAChangeReEncryptsEverything() throws {
        let (backend, store) = try makeVault()
        let result = try change(backend, store)
        XCTAssertTrue(result.finished)
        XCTAssertTrue(try assertWhole(backend, store))
        // Everything re-keyed is now version 2, the version 1 item included.
        for id in secrets.keys {
            XCTAssertFalse(VaultCrypto.isVersion1(try XCTUnwrap(backend.items[id])))
        }
    }

    func testTheWrongCurrentPassphraseChangesNothing() throws {
        let (backend, store) = try makeVault()
        XCTAssertThrowsError(try PassphraseChange.change(from: "not it", to: Self.newPassphrase,
                                                         backend: backend, files: store.rekeying))
        XCTAssertEqual(backend.writes, 0)
        XCTAssertFalse(try assertWhole(backend, store))
    }

    /// A secret the current passphrase does not open stops the change before
    /// the salt moves, and takes its staged copies with it.
    func testAnUnreadableSecretStopsTheChange() throws {
        let (backend, store) = try makeVault()
        let stranger = UUID()
        backend.items[stranger] = try VaultCrypto.encrypt("other vault", for: stranger,
                                                          using: SymmetricKey(size: .bits256))
        XCTAssertThrowsError(try change(backend, store))
        backend.items[stranger] = nil
        XCTAssertFalse(try assertWhole(backend, store))
    }

    func testAnUnreadableFileStopsTheChange() throws {
        let (backend, store) = try makeVault()
        let strangerStore = FileStore(directory: store.directory, keying: .fixed(SymmetricKey(size: .bits256)))
        let stranger = EncryptionKey(type: .file, name: "other", fileName: "other", hasPrivateKey: false)
        try strangerStore.save(stranger, contents: Data("x".utf8))
        XCTAssertThrowsError(try change(backend, store))
        try strangerStore.delete(id: stranger.id)
        XCTAssertFalse(try assertWhole(backend, store))
    }

    /// The heart of it: die at every write in turn, relaunch, recover.
    func testAnInterruptionAtAnyWriteRecoversToOneWholeVault() throws {
        let (probe, probeStore) = try makeVault()
        try change(probe, probeStore)
        let total = probe.writes
        XCTAssertGreaterThan(total, 6)

        var sawOld = false, sawNew = false
        for crashAt in 1...total {
            try? FileManager.default.removeItem(at: folder)
            let (backend, store) = try makeVault()
            backend.crashAt = crashAt
            // Before the commit point a crash throws; after it, the change
            // reports itself unfinished instead. Either way, never finished.
            let result = try? change(backend, store)
            XCTAssertNotEqual(result?.finished, true, "write \(crashAt) of \(total)")
            let committed = result != nil

            backend.relaunch()
            let outcome = PassphraseChange.recover(backend: backend, files: store.rekeying)
            let isNew = try assertWhole(backend, store)
            XCTAssertEqual(isNew, committed, "write \(crashAt): returned \(String(describing: result))")
            // Before the pending record exists there is nothing to roll back,
            // only staged copies to discard.
            let expected: Set<PassphraseChange.Outcome> = isNew ? [.completed] : [.nothingToDo, .rolledBack]
            XCTAssertTrue(expected.contains(outcome), "write \(crashAt): \(outcome)")
            if isNew { sawNew = true } else { sawOld = true }
        }
        // Both sides of the commit point were exercised.
        XCTAssertTrue(sawOld)
        XCTAssertTrue(sawNew)
    }

    /// The salt update lands but reports failure. Rolling back then would
    /// discard the only copies under the key the salt now derives.
    func testASaltWriteThatLandsAndThenFailsIsCompleted() throws {
        let (backend, store) = try makeVault()
        backend.saltLandsThenThrows = true
        XCTAssertTrue(try change(backend, store).finished)
        XCTAssertTrue(try assertWhole(backend, store))
    }

    /// Staged copies with no pending record are from a change that died
    /// before committing to anything, and are simply removed.
    func testLeftoversWithoutAPendingRecordAreDiscarded() throws {
        let (backend, store) = try makeVault()
        let id = try XCTUnwrap(secrets.keys.first)
        backend.staged[id] = Data("stale".utf8)
        try FileManager.default.copyItem(
            at: store.directory.appending(path: "\(fileContents.keys.first!.uuidString).kvfile"),
            to: store.directory.appending(path: "\(fileContents.keys.first!.uuidString).kvfile.next"))
        XCTAssertEqual(PassphraseChange.recover(backend: backend, files: store.rekeying), .nothingToDo)
        XCTAssertFalse(try assertWhole(backend, store))
    }

    func testNothingInterruptedIsNothingToDo() throws {
        let (backend, store) = try makeVault()
        XCTAssertEqual(PassphraseChange.recover(backend: backend, files: store.rekeying), .nothingToDo)
        XCTAssertEqual(backend.writes, 0)
    }
}
