import CryptoKit
import XCTest
@testable import KeyVault

/// The `.kvfile` format, end to end, in a store built on a scratch folder with
/// a key of its own. Never `FileStore.standard`: that folder is the real
/// vault's, and its key is the real passphrase's.
final class FileStoreTests: XCTestCase {

    private var folder: URL!
    private var store: FileStore!
    private let key = SymmetricKey(size: .bits256)

    override func setUpWithError() throws {
        folder = FileManager.default.temporaryDirectory
            .appending(path: "FileStoreTests-\(UUID().uuidString)", directoryHint: .isDirectory)
        store = FileStore(directory: folder.appending(path: "Files"), keying: .fixed(key))
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: folder)
    }

    private func item(_ name: String = "Recovery kit", id: UUID = UUID()) -> EncryptionKey {
        EncryptionKey(id: id, type: .file, name: name, notes: "keep safe",
                      fileName: "kit.pdf", hasPrivateKey: false)
    }

    private func path(_ id: UUID) -> URL {
        store.directory.appending(path: "\(id.uuidString).kvfile")
    }

    func testAMissingFolderIsAnEmptyStore() {
        let listing = store.loadAll()
        XCTAssertTrue(listing.files.isEmpty)
        XCTAssertTrue(listing.unreadable.isEmpty)
    }

    func testASavedFileListsAndReadsBack() throws {
        let original = item()
        let contents = Data((0..<10_000).map { UInt8(truncatingIfNeeded: $0) })
        try store.save(original, contents: contents)

        let listing = store.loadAll()
        XCTAssertEqual(listing.unreadable, [])
        let listed = try XCTUnwrap(listing.files.first)
        XCTAssertEqual(listed.id, original.id)
        XCTAssertEqual(listed.type, .file)
        XCTAssertEqual(listed.name, "Recovery kit")
        XCTAssertEqual(listed.notes, "keep safe")
        XCTAssertEqual(listed.fileName, "kit.pdf")
        XCTAssertEqual(listed.fileSize, contents.count)
        XCTAssertEqual(try store.loadContents(for: original.id), contents)
    }

    /// Nothing about a stored file is legible on disk, not even its name.
    func testNothingIsStoredInTheClear() throws {
        let original = item("Bank recovery codes")
        try store.save(original, contents: Data("1234-5678".utf8))
        let raw = try Data(contentsOf: path(original.id))
        XCTAssertNil(raw.range(of: Data("Bank".utf8)))
        XCTAssertNil(raw.range(of: Data("1234-5678".utf8)))
        XCTAssertTrue(raw.starts(with: Data("KVFILE1\0".utf8)))
    }

    func testOnlyTheOwnerCanReachTheStore() throws {
        let original = item()
        try store.save(original, contents: Data("x".utf8))
        let fm = FileManager.default
        let folderMode = try fm.attributesOfItem(atPath: store.directory.path)[.posixPermissions] as? Int
        let fileMode = try fm.attributesOfItem(atPath: path(original.id).path)[.posixPermissions] as? Int
        XCTAssertEqual(folderMode, 0o700)
        XCTAssertEqual(fileMode, 0o600)
    }

    /// Under another key a file is reported, by name, rather than left out:
    /// the backup is built from this listing.
    func testAFileUnderAnotherKeyIsReportedUnreadable() throws {
        let original = item()
        try store.save(original, contents: Data("x".utf8))
        let stranger = FileStore(directory: store.directory, keying: .fixed(SymmetricKey(size: .bits256)))
        let listing = stranger.loadAll()
        XCTAssertTrue(listing.files.isEmpty)
        XCTAssertEqual(listing.unreadable.count, 1)
        XCTAssertTrue(listing.unreadable[0].hasPrefix("\(original.id.uuidString).kvfile"))
    }

    /// A copy renamed to another item's id is not that item.
    func testAFileRenamedToAnotherIDIsDamaged() throws {
        let original = item()
        try store.save(original, contents: Data("x".utf8))
        let impostor = UUID()
        try FileManager.default.copyItem(at: path(original.id), to: path(impostor))
        XCTAssertThrowsError(try store.loadContents(for: impostor)) { error in
            guard case FileStore.StoreError.damaged = error else {
                return XCTFail("expected damaged, got \(error)")
            }
        }
        XCTAssertEqual(store.loadAll().unreadable.count, 1)
    }

    func testATruncatedFileDoesNotOpen() throws {
        let original = item()
        try store.save(original, contents: Data(repeating: 7, count: 4096))
        let raw = try Data(contentsOf: path(original.id))
        try raw.prefix(raw.count - 100).write(to: path(original.id))
        XCTAssertThrowsError(try store.loadContents(for: original.id))
    }

    func testSomethingElseEntirelyIsUnrecognised() throws {
        let id = UUID()
        try FileManager.default.createDirectory(at: store.directory, withIntermediateDirectories: true)
        try Data(repeating: 0x41, count: 64).write(to: path(id))
        XCTAssertThrowsError(try store.loadContents(for: id)) { error in
            guard case FileStore.StoreError.unrecognised = error else {
                return XCTFail("expected unrecognised, got \(error)")
            }
        }
    }

    /// Staging files, Finder duplicates and anything not named for an id are
    /// not items.
    func testOnlyNamesTheStoreWritesAreItems() throws {
        let original = item()
        try store.save(original, contents: Data("x".utf8))
        let raw = try Data(contentsOf: path(original.id))
        for stray in [".\(original.id.uuidString).\(UUID().uuidString).partial",
                      "\(original.id.uuidString) copy.kvfile",
                      "notes.txt"] {
            try raw.write(to: store.directory.appending(path: stray))
        }
        let listing = store.loadAll()
        XCTAssertEqual(listing.files.map(\.id), [original.id])
        XCTAssertEqual(listing.unreadable, [])
    }

    func testTooLargeIsRefused() {
        XCTAssertThrowsError(try store.save(item(), contents: Data(count: FileStore.maxFileSize + 1))) { error in
            guard case FileStore.StoreError.tooLarge = error else {
                return XCTFail("expected tooLarge, got \(error)")
            }
        }
    }

    func testUpdateChangesTheNameAndKeepsTheContents() throws {
        var original = item()
        try store.save(original, contents: Data("contents".utf8))
        original.name = "Renamed"
        original.notes = nil
        try store.update(original)
        let listed = try XCTUnwrap(store.loadAll().files.first)
        XCTAssertEqual(listed.name, "Renamed")
        XCTAssertNil(listed.notes)
        XCTAssertEqual(try store.loadContents(for: original.id), Data("contents".utf8))
    }

    func testDeletingWhatIsAlreadyGoneSucceeds() throws {
        let original = item()
        try store.save(original, contents: Data("x".utf8))
        try store.delete(id: original.id)
        XCTAssertFalse(store.exists(id: original.id))
        XCTAssertNoThrow(try store.delete(id: original.id))
    }
}
