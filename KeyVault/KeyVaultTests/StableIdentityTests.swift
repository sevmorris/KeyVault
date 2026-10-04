import XCTest
@testable import KeyVault

/// SSH, GPG and Age rows are rebuilt on every reload; their ids have to come
/// out the same each time, or the selection empties on every refresh.
final class StableIdentityTests: XCTestCase {

    func testTheSameInputGivesTheSameID() {
        XCTAssertEqual(UUID(stableIdentity: "/Users/someone/.ssh/id_ed25519"),
                       UUID(stableIdentity: "/Users/someone/.ssh/id_ed25519"))
    }

    func testDifferentInputsGiveDifferentIDs() {
        XCTAssertNotEqual(UUID(stableIdentity: "/Users/someone/.ssh/id_ed25519"),
                          UUID(stableIdentity: "/Users/someone/.ssh/id_rsa"))
    }

    /// Version 8, the RFC 9562 slot for custom derivations, and the RFC
    /// variant, so it is a well-formed UUID rather than sixteen random bytes.
    func testItIsAWellFormedVersion8UUID() {
        let bytes = UUID(stableIdentity: "ABCDEF0123456789").uuid
        XCTAssertEqual(bytes.6 >> 4, 8)
        XCTAssertEqual(bytes.8 >> 6, 0b10)
    }
}
