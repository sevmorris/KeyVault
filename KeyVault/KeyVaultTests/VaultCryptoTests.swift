import CryptoKit
import XCTest
@testable import KeyVault

/// VaultCrypto's format, through the entry points that take a key. Nothing
/// here may reach `configure`, `unlock` or `isConfigured`: they read and
/// rewrite the vault's salt in the real login Keychain, and `configure`
/// replacing it would make every stored secret unreadable.
final class VaultCryptoTests: XCTestCase {

    private let key = SymmetricKey(size: .bits256)
    private let otherKey = SymmetricKey(size: .bits256)

    /// Pinned to an answer computed outside KeyVault (Python's
    /// hashlib.pbkdf2_hmac, SHA-256, 600,000 rounds). If this fails, the same
    /// passphrase now derives a different key, and every existing vault has
    /// stopped opening.
    func testDerivationMatchesAKnownAnswer() throws {
        let salt = Data(1...32)
        let derived = try VaultCrypto.derive(passphrase: "correct horse battery staple", salt: salt)
        let hex = derived.withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }
        XCTAssertEqual(hex, "b915fe8618c779195a061f4aceae83671cdab2d999eae300ddb2dad92b9f56f5")
    }

    func testTextRoundTrips() throws {
        let sealed = try VaultCrypto.encrypt("hunter2 — ünïcödé", using: key)
        XCTAssertEqual(try VaultCrypto.decrypt(sealed, using: key), "hunter2 — ünïcödé")
    }

    func testCiphertextIsMarkedAndPlaintextIsNot() throws {
        let sealed = try VaultCrypto.encrypt("x", using: key)
        XCTAssertTrue(sealed.starts(with: VaultCrypto.magic))
        XCTAssertTrue(VaultCrypto.isEncrypted(sealed))
        // What a vault written before encryption holds, and must keep reading.
        XCTAssertFalse(VaultCrypto.isEncrypted(Data("plain old note".utf8)))
        // The marker alone, with nothing after it, is not ciphertext either.
        XCTAssertFalse(VaultCrypto.isEncrypted(VaultCrypto.magic))
    }

    func testTheSameTextSealsDifferentlyEachTime() throws {
        XCTAssertNotEqual(try VaultCrypto.encrypt("same", using: key),
                          try VaultCrypto.encrypt("same", using: key))
    }

    func testAnotherKeyIsReportedAsTheWrongPassphrase() throws {
        let sealed = try VaultCrypto.encrypt("secret", using: key)
        XCTAssertThrowsError(try VaultCrypto.decrypt(sealed, using: otherKey)) { error in
            guard case VaultCrypto.CryptoError.wrongPassphrase = error else {
                return XCTFail("expected wrongPassphrase, got \(error)")
            }
        }
    }

    func testATamperedByteDoesNotOpen() throws {
        var sealed = try VaultCrypto.encrypt("secret", using: key)
        sealed[sealed.count - 1] ^= 0x01
        XCTAssertThrowsError(try VaultCrypto.decrypt(sealed, using: key))
    }

    func testPlaintextIsNotDecrypted() {
        XCTAssertThrowsError(try VaultCrypto.decrypt(Data("plain".utf8), using: key)) { error in
            guard case VaultCrypto.CryptoError.malformed = error else {
                return XCTFail("expected malformed, got \(error)")
            }
        }
    }

    func testSealedBytesOpenOnlyWithTheirContext() throws {
        let sealed = try VaultCrypto.seal(Data([0, 1, 2, 255]), authenticating: Data("a".utf8), using: key)
        XCTAssertEqual(try VaultCrypto.open(sealed, authenticating: Data("a".utf8), using: key),
                       Data([0, 1, 2, 255]))
        XCTAssertThrowsError(try VaultCrypto.open(sealed, authenticating: Data("b".utf8), using: key)) { error in
            guard case VaultCrypto.CryptoError.authenticationFailed = error else {
                return XCTFail("expected authenticationFailed, got \(error)")
            }
        }
        XCTAssertThrowsError(try VaultCrypto.open(sealed, authenticating: Data("a".utf8), using: otherKey))
    }

    func testTheVerifierAcceptsOnlyItsKey() throws {
        let verifier = try VaultCrypto.makeVerifier(using: key)
        XCTAssertTrue(VaultCrypto.verifier(verifier, accepts: key))
        XCTAssertFalse(VaultCrypto.verifier(verifier, accepts: otherKey))
        XCTAssertFalse(VaultCrypto.verifier(Data("junk".utf8), accepts: key))
    }

    /// The session entry points refuse while locked, rather than sealing
    /// under some default. A hosted test run never unlocks the vault.
    func testTheSessionKeyIsRequiredWhileLocked() {
        XCTAssertFalse(VaultCrypto.isUnlocked)
        XCTAssertThrowsError(try VaultCrypto.encrypt("x")) { error in
            guard case VaultCrypto.CryptoError.locked = error else {
                return XCTFail("expected locked, got \(error)")
            }
        }
    }
}
