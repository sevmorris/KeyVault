import XCTest
@testable import KeyVault

final class KeyTypeTests: XCTestCase {

    /// The raw values are written into every stored item, so renaming one
    /// would orphan whatever was saved under the old name.
    func testRawValuesAreWhatStoredItemsCarry() {
        XCTAssertEqual(KeyType.allCases.map(\.rawValue),
                       ["SSH", "GPG", "Age", "API Key", "Note", "File"])
    }

    /// Notes, API keys and files are KeyVault's own: what the backup carries
    /// and what locking the vault clears. SSH, GPG and Age are only indexed.
    func testStoredTypesAreTheOnesKeyVaultOwns() {
        XCTAssertEqual(Set(KeyType.allCases.filter(\.isStored)), [.note, .api, .file])
        XCTAssertEqual(Set(KeyType.allCases.filter { !$0.isStored }), [.ssh, .gpg, .age])
    }
}
