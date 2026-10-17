import XCTest
@testable import KeyVault

/// gpg's `--with-colons` output, parsed without running gpg. The listings are
/// trimmed copies of real ones, in the record order gpg writes.
final class GPGParserTests: XCTestCase {

    private let publicListing = """
        tru::1:1700000000:0:3:1:5
        pub:u:255:22:AAAA1111BBBB2222:1700000000:1800000000::u:::scESC:::::ed25519:::0:
        fpr:::::::::0123456789ABCDEF0123456789ABCDEFAAAA1111BBBB2222:
        uid:u::::1700000000::HASH1::Seven Morris (Work\\x3a signing) <seven@example.com>::::::::::0:
        uid:u::::1700000000::HASH2::Second UID <other@example.com>::::::::::0:
        sub:u:255:18:CCCC3333DDDD4444:1700000000::::::e:::::cv25519::
        fpr:::::::::FFFFEEEEDDDDCCCCBBBBAAAA99998888CCCC3333DDDD4444:
        pub:-:3072:1:EEEE5555FFFF6666:1600000000:::-:::scESC::::::23::0:
        fpr:::::::::11112222333344445555666677778888EEEE5555FFFF6666:
        uid:-::::1600000000::HASH3::Caf\\xc3\\xa9 Owner <cafe@example.com>::::::::::0:
        """

    private let secretListing = """
        sec:u:255:22:AAAA1111BBBB2222:1700000000:1800000000::u:::scESC:::+:::ed25519::0:
        fpr:::::::::0123456789ABCDEF0123456789ABCDEFAAAA1111BBBB2222:
        ssb:u:255:18:CCCC3333DDDD4444:1700000000::::::e:::+::cv25519::
        """

    private var keys: [EncryptionKey] {
        GPGService.parseKeys(from: publicListing,
                             secretKeyIDs: GPGService.parseSecretKeyIDs(from: secretListing))
    }

    func testEachPrimaryKeyIsOneEntry() {
        XCTAssertEqual(keys.map(\.keyID), ["AAAA1111BBBB2222", "EEEE5555FFFF6666"])
        XCTAssertTrue(keys.allSatisfy { $0.type == .gpg })
    }

    /// The primary key's fingerprint, not the subkey's that follows it.
    func testTheFingerprintIsThePrimaryKeys() {
        XCTAssertEqual(keys[0].fingerprint, "0123456789ABCDEF0123456789ABCDEFAAAA1111BBBB2222")
    }

    func testTheFirstUserIDNamesTheKeyWithEscapesUndone() {
        XCTAssertEqual(keys[0].name, "Seven Morris (Work: signing) <seven@example.com>")
        XCTAssertEqual(keys[1].name, "Café Owner <cafe@example.com>")
    }

    func testAlgorithmsAndDates() {
        XCTAssertEqual(keys[0].algorithm, "EdDSA")
        XCTAssertEqual(keys[1].algorithm, "RSA")
        XCTAssertEqual(keys[0].createdDate, Date(timeIntervalSince1970: 1_700_000_000))
        XCTAssertEqual(keys[0].expiryDate, Date(timeIntervalSince1970: 1_800_000_000))
        XCTAssertNil(keys[1].expiryDate)
    }

    func testOnlyKeysWithASecretArePrivate() {
        XCTAssertTrue(keys[0].hasPrivateKey)
        XCTAssertFalse(keys[1].hasPrivateKey)
    }

    /// The id comes from the key id, so a key keeps its selection across
    /// reloads.
    func testIDsAreStable() {
        XCTAssertEqual(keys.map(\.id), keys.map(\.id))
        XCTAssertEqual(keys[0].id, UUID(stableIdentity: "gpg:AAAA1111BBBB2222"))
    }

    func testAnEmptyKeyringIsEmpty() {
        XCTAssertTrue(GPGService.parseKeys(from: "", secretKeyIDs: []).isEmpty)
    }

    func testUnescapingLeavesOrdinaryTextAlone() {
        XCTAssertEqual(GPGService.unescapeColonField("plain"), "plain")
        XCTAssertEqual(GPGService.unescapeColonField("a\\x5cb"), "a\\b")
        // Not an escape: left as written.
        XCTAssertEqual(GPGService.unescapeColonField("odd\\xZZ"), "odd\\xZZ")
    }
}
