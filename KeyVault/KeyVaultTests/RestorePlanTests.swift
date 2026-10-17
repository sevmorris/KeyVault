import XCTest
@testable import KeyVault

/// The rules a restore follows, through `VaultExportService.plan`, which
/// decides every write without making one. `restore` itself writes to the
/// real Keychain and file store, so it is not called here.
final class RestorePlanTests: XCTestCase {

    private func archive(_ items: [VaultArchive.Item]) -> VaultArchive {
        VaultArchive(exportedAt: Date(timeIntervalSince1970: 0), items: items)
    }

    private func note(_ id: UUID = UUID(), category: String? = nil) -> VaultArchive.Item {
        VaultArchive.Item(id: id, type: KeyType.note.rawValue, name: "Note", category: category,
                          secret: "secret")
    }

    private func file(_ id: UUID = UUID(), base64: String) -> VaultArchive.Item {
        VaultArchive.Item(id: id, type: KeyType.file.rawValue, name: "Kit", secret: base64,
                          fileName: "kit.pdf")
    }

    private func plan(_ archive: VaultArchive,
                      existing: [EncryptionKey] = [],
                      canStoreFiles: Bool = true,
                      existingFiles: Set<UUID> = []) throws -> VaultExportService.RestorePlan {
        try VaultExportService.plan(archive,
                                    existing: Dictionary(uniqueKeysWithValues: existing.map { ($0.id, $0) }),
                                    canStoreFiles: canStoreFiles,
                                    fileExists: existingFiles.contains)
    }

    func testNewItemsAreAddedAndKnownOnesUpdated() throws {
        let known = UUID()
        let result = try plan(archive([note(known), note()]),
                              existing: [EncryptionKey(id: known, type: .note, name: "Old")])
        XCTAssertEqual(result.added, 1)
        XCTAssertEqual(result.updated, 1)
        XCTAssertEqual(result.writes.count, 2)
        guard case .secret(let key, let secret, let isUpdate) = result.writes[0] else {
            return XCTFail("expected a secret write")
        }
        XCTAssertEqual(key.id, known)
        XCTAssertEqual(key.name, "Note")
        XCTAssertEqual(secret, "secret")
        XCTAssertTrue(isUpdate)
    }

    func testTypesThisBuildDoesNotStoreAreSkippedAndCounted() throws {
        let ssh = VaultArchive.Item(id: UUID(), type: KeyType.ssh.rawValue, name: "id", secret: "x")
        let unknown = VaultArchive.Item(id: UUID(), type: "Passkey", name: "p", secret: "x")
        let result = try plan(archive([ssh, unknown, note()]))
        XCTAssertEqual(result.skipped, 2)
        XCTAssertEqual(result.added, 1)
        XCTAssertEqual(result.writes.count, 1)
    }

    /// An archive from before categories were exported must not un-file the
    /// notes it restores over.
    func testAnAbsentCategoryKeepsTheStoredOne() throws {
        let id = UUID()
        let result = try plan(archive([note(id)]),
                              existing: [EncryptionKey(id: id, type: .note, name: "n", category: "Bank")])
        guard case .secret(let key, _, _) = result.writes[0] else { return XCTFail() }
        XCTAssertEqual(key.category, "Bank")
    }

    func testAPresentCategoryWins() throws {
        let id = UUID()
        let result = try plan(archive([note(id, category: "Home")]),
                              existing: [EncryptionKey(id: id, type: .note, name: "n", category: "Bank")])
        guard case .secret(let key, _, _) = result.writes[0] else { return XCTFail() }
        XCTAssertEqual(key.category, "Home")
    }

    func testFilesDecodeAndWrappedBase64IsForgiven() throws {
        let contents = Data((0..<200).map { UInt8($0) })
        var wrapped = contents.base64EncodedString(options: .lineLength64Characters)
        wrapped += "\n  "
        let existing = UUID()
        let result = try plan(archive([file(base64: wrapped), file(existing, base64: "AA==")]),
                              existingFiles: [existing])
        XCTAssertEqual(result.added, 1)
        XCTAssertEqual(result.updated, 1)
        guard case .file(let key, let data) = result.writes[0] else { return XCTFail() }
        XCTAssertEqual(data, contents)
        XCTAssertEqual(key.type, .file)
        XCTAssertEqual(key.fileName, "kit.pdf")
    }

    /// Refused before anything is written, even the items ahead of it.
    func testDamagedBase64StopsTheWholeRestore() {
        XCTAssertThrowsError(try plan(archive([note(), file(base64: "not base64!")])))
    }

    func testFilesNeedAPassphraseBeforeAnythingIsWritten() {
        XCTAssertThrowsError(try plan(archive([note(), file(base64: "AA==")]), canStoreFiles: false))
        // Without files there is nothing to refuse.
        XCTAssertNoThrow(try plan(archive([note()]), canStoreFiles: false))
    }

    // MARK: - Decoding

    private func json(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object)
    }

    func testAnArchiveWithItsReadmeTrimmedStillDecodes() throws {
        let decoded = try VaultExportService.decodeArchive(json([
            "exportedAt": "2026-01-01T00:00:00Z",
            "items": [["id": UUID().uuidString, "type": "Note", "name": "n", "secret": "s"]],
        ]))
        XCTAssertEqual(decoded.formatVersion, VaultArchive.currentFormatVersion)
        XCTAssertEqual(decoded.items.count, 1)
    }

    func testANewerFormatIsRefused() throws {
        XCTAssertThrowsError(try VaultExportService.decodeArchive(json([
            "formatVersion": VaultArchive.currentFormatVersion + 1,
            "exportedAt": "2026-01-01T00:00:00Z",
            "items": [],
        ])))
    }

    func testAnArchiveWithoutItemsIsRefused() throws {
        XCTAssertThrowsError(try VaultExportService.decodeArchive(json(["exportedAt": "2026-01-01T00:00:00Z"])))
    }

    /// What an export writes, a restore reads back field for field.
    func testAnExportedArchiveRoundTrips() throws {
        let item = VaultArchive.Item(id: UUID(), type: "API Key", name: "Stripe", service: "stripe.com",
                                     category: nil, notes: "live", createdDate: Date(timeIntervalSince1970: 1_700_000_000),
                                     secret: "sk_live_x")
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoded = try VaultExportService.decodeArchive(encoder.encode(archive([item])))
        let back = try XCTUnwrap(decoded.items.first)
        XCTAssertEqual(back.id, item.id)
        XCTAssertEqual(back.service, "stripe.com")
        XCTAssertEqual(back.notes, "live")
        XCTAssertEqual(back.createdDate, item.createdDate)
        XCTAssertEqual(back.secret, "sk_live_x")
    }
}
