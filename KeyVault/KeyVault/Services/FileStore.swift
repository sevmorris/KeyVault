import Foundation

/// Encrypted storage for whole files KeyVault holds outright — a password
/// manager's CSV export, a service-account key, a recovery kit.
///
/// On disk, not in the Keychain beside notes. The login keychain is one
/// database every app on this Mac reads and writes, built for secrets measured
/// in bytes; filling it with files measured in megabytes would make them every
/// app's problem. Nor was the Keychain what protected anything here to begin
/// with — SecretStore opens every item's ACL to any application, on purpose —
/// so the protection is VaultCrypto's key, and a key works the same on a file.
///
/// Each item is one file named by its id, and self-describing the way
/// SecretStore's Keychain items are: the name, notes and original filename
/// travel inside it, so there is no index to lose and the folder *is* the
/// store. It goes one better than a note, whose name is a Keychain attribute
/// any process can read: nothing about a stored file is readable without the
/// vault key, not even what it is called.
///
/// Layout, written in one piece:
///
///     magic       "KVFILE1\0"                   8 bytes
///     id          the item's UUID               16 bytes
///     headerSize  UInt32, big-endian            4 bytes
///     header      sealed JSON: name, notes…     headerSize bytes
///     body        sealed file contents          the rest
///
/// Header and body are sealed separately so the list can be drawn from headers
/// alone, a few hundred bytes each however large the file. Each is sealed
/// against the magic, the id and which half it is, so a body moved into
/// another file, or swapped with a header, fails to open.
///
/// Stored only under a master passphrase. SecretStore falls back to plain
/// storage without one, because the app has to keep working before one is set;
/// an encrypted file store that fell back to plain storage would be a folder.
struct FileStore {
    /// The app's store. Anything else — a test — builds its own on a directory
    /// of its choosing, rather than this one being reassignable.
    static let standard = FileStore(
        directory: URL.applicationSupportDirectory
            .appending(path: "KeyVault/Files", directoryHint: .isDirectory)
    )

    let directory: URL

    /// Large enough for anything that belongs here — an export, a scan, a
    /// recovery kit — and small enough that the backup stays something you can
    /// move: every stored file travels inside the one encrypted archive, which
    /// is built and encrypted in memory.
    static let maxFileSize = 25_000_000

    private static let magic = Data("KVFILE1\0".utf8)
    private static let fileExtension = "kvfile"
    /// magic + id + headerSize.
    private static let prefixSize = 8 + 16 + 4
    /// A header is a name and some notes. One claiming to be larger than this
    /// is damage, and is refused before it is read rather than after.
    private static let maxHeaderSize = 1 << 20

    private struct Header: Codable {
        var name: String
        var fileName: String
        var fileSize: Int
        var notes: String?
        var createdDate: Date?
    }

    enum StoreError: LocalizedError {
        case needsPassphrase
        case notAFile
        case tooLarge(Int)
        case unrecognised
        case damaged
        case verificationFailed

        var errorDescription: String? {
            switch self {
            case .needsPassphrase:
                return "Files are stored only under a master passphrase. Set one in Settings first."
            case .notAFile:
                return "KeyVault stores single files. To keep a folder or a package, compress it "
                    + "first — Finder's Compress makes a .zip."
            case .tooLarge(let size):
                return "This file is \(size.formatted(.byteCount(style: .file))). KeyVault stores "
                    + "files up to \(FileStore.maxFileSize.formatted(.byteCount(style: .file))), "
                    + "because every one travels inside the encrypted backup."
            case .unrecognised:
                return "This is not a file KeyVault wrote, or a newer version of KeyVault wrote it."
            case .damaged:
                return "This stored file is damaged: it is not laid out the way KeyVault writes one."
            case .verificationFailed:
                return "The file was written but did not read back the same, so it was not kept."
            }
        }
    }

    // MARK: - Read

    /// Everything stored, read from the headers alone.
    ///
    /// A file that will not open is reported in `unreadable` rather than left
    /// out. This listing is also what the backup is built from, and a file
    /// missing from it quietly would be missing from the backup the same way.
    func loadAll() -> (files: [EncryptionKey], unreadable: [String]) {
        let fm = FileManager.default
        // No folder is the ordinary state of a vault that has never stored a
        // file. A folder that exists and cannot be listed is not, and must not
        // read as an empty one.
        guard fm.fileExists(atPath: directory.path) else { return ([], []) }
        let names: [String]
        do {
            names = try fm.contentsOfDirectory(atPath: directory.path)
        } catch {
            return ([], ["\(directory.path): \(error.localizedDescription)"])
        }

        var files: [EncryptionKey] = []
        var unreadable: [String] = []
        // Only names this store writes. The staging file an interrupted save
        // leaves behind is not an item, and neither is a Finder duplicate of
        // one: its original is still here under the real name.
        for name in names.sorted() where name.hasSuffix("." + Self.fileExtension) {
            let stem = String(name.dropLast(Self.fileExtension.count + 1))
            guard let id = UUID(uuidString: stem) else { continue }
            do {
                files.append(try loadItem(id: id))
            } catch {
                unreadable.append("\(name): \(error.localizedDescription)")
            }
        }
        files.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        return (files, unreadable)
    }

    /// The file itself, decrypted, and checked against the size its header
    /// recorded.
    func loadContents(for id: UUID) throws -> Data {
        try open(Data(contentsOf: url(for: id)), id: id).contents
    }

    func exists(id: UUID) -> Bool {
        FileManager.default.fileExists(atPath: url(for: id).path)
    }

    /// What can be known about a file before reading it — that it is one, and
    /// small enough — so a folder or a film dropped here by mistake costs an
    /// error message rather than a gigabyte of memory. Returns its size.
    @discardableResult
    static func checkStorable(_ url: URL) throws -> Int {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard values.isRegularFile == true else { throw StoreError.notAFile }
        let size = values.fileSize ?? 0
        guard size <= maxFileSize else { throw StoreError.tooLarge(size) }
        return size
    }

    /// Read a file someone has chosen to store. `save` checks the size again
    /// on what was actually read, in case the file grew in between.
    static func contentsForStoring(_ url: URL) throws -> Data {
        try checkStorable(url)
        return try Data(contentsOf: url)
    }

    // MARK: - Write

    /// Add a file, or replace the one stored under the same id.
    ///
    /// Written to a staging file beside its destination, read back, and only
    /// then renamed over it. A rename within one folder is atomic, so the item
    /// is always the old file or the new one and never half of either. The
    /// read-back is the rule SecretStore's sweep learned the hard way: a write
    /// that reports success is not evidence that the thing is there.
    func save(_ key: EncryptionKey, contents: Data) throws {
        guard VaultCrypto.isConfigured else { throw StoreError.needsPassphrase }
        guard contents.count <= Self.maxFileSize else { throw StoreError.tooLarge(contents.count) }

        let header = Header(
            name: key.name,
            fileName: key.fileName ?? key.name,
            fileSize: contents.count,
            notes: key.notes,
            createdDate: key.createdDate ?? Date()
        )
        let blob = try seal(header, contents: contents, id: key.id)

        let fm = FileManager.default
        // Owner-only. What is inside is ciphertext, but nobody else on this Mac
        // has any business listing what the vault holds, or how much of it.
        try fm.createDirectory(at: directory, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        let destination = url(for: key.id)
        let staging = directory.appending(path: ".\(key.id.uuidString).\(UUID().uuidString).partial")
        defer { try? fm.removeItem(at: staging) }

        try blob.write(to: staging, options: .withoutOverwriting)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: staging.path)

        guard try open(Data(contentsOf: staging), id: key.id).contents == contents else {
            throw StoreError.verificationFailed
        }
        guard rename(staging.path, destination.path) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    /// Change what the list shows — the name, the notes — and nothing else.
    /// Rewritten whole rather than patched in place: one write path, with the
    /// same read-back as any other save.
    func update(_ key: EncryptionKey) throws {
        try save(key, contents: loadContents(for: key.id))
    }

    /// Already gone counts as done, as it does for SecretStore.
    func delete(id: UUID) throws {
        do {
            try FileManager.default.removeItem(at: url(for: id))
        } catch let error as CocoaError where error.code == .fileNoSuchFile {
            return
        }
    }

    // MARK: - Format

    private func url(for id: UUID) -> URL {
        directory.appending(path: "\(id.uuidString).\(Self.fileExtension)")
    }

    private func loadItem(id: UUID) throws -> EncryptionKey {
        let header = try readHeader(id: id)
        return EncryptionKey(
            id: id,
            type: .file,
            name: header.name,
            notes: header.notes,
            createdDate: header.createdDate,
            fileName: header.fileName,
            fileSize: header.fileSize,
            hasPrivateKey: false
        )
    }

    /// The prefix and the sealed header, and not a byte past them.
    private func readHeader(id: UUID) throws -> Header {
        let handle = try FileHandle(forReadingFrom: url(for: id))
        defer { try? handle.close() }
        let headerSize = try Self.checkPrefix(handle.read(upToCount: Self.prefixSize) ?? Data(), id: id)
        let sealed = try handle.read(upToCount: headerSize) ?? Data()
        guard sealed.count == headerSize else { throw StoreError.damaged }
        return try Self.openHeader(sealed, id: id)
    }

    private func open(_ blob: Data, id: UUID) throws -> (header: Header, contents: Data) {
        let headerSize = try Self.checkPrefix(blob.prefix(Self.prefixSize), id: id)
        guard blob.count >= Self.prefixSize + headerSize else { throw StoreError.damaged }
        let header = try Self.openHeader(Data(blob.dropFirst(Self.prefixSize).prefix(headerSize)), id: id)
        let contents = try VaultCrypto.open(Data(blob.dropFirst(Self.prefixSize + headerSize)),
                                            authenticating: Self.context(id, "body"))
        // Belt and braces: the id already ties the body to this file, and this
        // ties it to the header it was written with.
        guard contents.count == header.fileSize else { throw StoreError.damaged }
        return (header, contents)
    }

    private func seal(_ header: Header, contents: Data, id: UUID) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let sealedHeader = try VaultCrypto.seal(encoder.encode(header),
                                                authenticating: Self.context(id, "header"))
        let sealedBody = try VaultCrypto.seal(contents, authenticating: Self.context(id, "body"))
        let size = UInt32(sealedHeader.count)
        let sizeBytes = Data([24, 16, 8, 0].map { UInt8(truncatingIfNeeded: size >> $0) })
        return Self.magic + id.bytes + sizeBytes + sealedHeader + sealedBody
    }

    /// Checks the fixed prefix and returns the header's size. The id in it has
    /// to be the one the file is named for: a copy renamed to look like
    /// another item is not that item.
    private static func checkPrefix(_ prefix: Data, id: UUID) throws -> Int {
        guard prefix.count == prefixSize, prefix.prefix(magic.count) == magic else {
            throw StoreError.unrecognised
        }
        guard UUID(bytes: prefix.dropFirst(magic.count).prefix(16)) == id else {
            throw StoreError.damaged
        }
        let size = prefix.suffix(4).reduce(0) { $0 << 8 | Int($1) }
        guard size > 0, size <= maxHeaderSize else { throw StoreError.damaged }
        return size
    }

    private static func openHeader(_ sealed: Data, id: UUID) throws -> Header {
        let json = try VaultCrypto.open(sealed, authenticating: context(id, "header"))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(Header.self, from: json)
        } catch {
            throw StoreError.damaged
        }
    }

    /// What each half is sealed against: which format, which item, which half.
    private static func context(_ id: UUID, _ part: String) -> Data {
        magic + id.bytes + Data(part.utf8)
    }
}

private extension UUID {
    var bytes: Data { withUnsafeBytes(of: uuid) { Data($0) } }

    init?(bytes: Data) {
        guard bytes.count == 16 else { return nil }
        self = bytes.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
    }
}
