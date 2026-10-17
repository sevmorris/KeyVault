import XCTest
@testable import KeyVault

/// The matching rule behind the search field. Pure, so it is tested without a
/// view model, which would read the Keychain to build itself.
final class SearchTests: XCTestCase {

    private let note = EncryptionKey(type: .note, name: "Router admin",
                                     service: "Eero", category: "Home Network",
                                     notes: "Second floor café")

    private func matches(_ query: String) -> Bool {
        KeyVaultViewModel.key(note, matches: query)
    }

    func testAnEmptyQueryMatchesEverything() {
        XCTAssertTrue(matches(""))
        XCTAssertTrue(matches("   "))
    }

    func testEachSearchedFieldMatches() {
        XCTAssertTrue(matches("router"))
        XCTAssertTrue(matches("eero"))
        XCTAssertTrue(matches("network"))
        XCTAssertTrue(matches("floor"))
    }

    func testCaseAndDiacriticsAreIgnored() {
        XCTAssertTrue(matches("ROUTER"))
        XCTAssertTrue(matches("cafe"))
    }

    func testSurroundingSpacesAreIgnored() {
        XCTAssertTrue(matches("  router "))
    }

    func testNothingElseMatches() {
        XCTAssertFalse(matches("bank"))
    }

    /// Fields that are not searched — a key's fingerprint, here — do not
    /// match, and a key with no optional fields at all is still searchable by
    /// name.
    func testOnlyTheNamedFieldsAreSearched() {
        let key = EncryptionKey(type: .ssh, name: "id_ed25519", fingerprint: "SHA256:abc")
        XCTAssertTrue(KeyVaultViewModel.key(key, matches: "ed25519"))
        XCTAssertFalse(KeyVaultViewModel.key(key, matches: "SHA256"))
    }
}
