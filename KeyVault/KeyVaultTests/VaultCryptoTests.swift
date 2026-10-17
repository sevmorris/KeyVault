import CryptoKit
import Security
import XCTest
@testable import KeyVault

/// VaultCrypto's format, through the entry points that take a key. Nothing
/// here may reach `configure`, `unlock`, `setup` or `isConfigured`: they read
/// and rewrite the vault's salt in the real login Keychain, and `configure`
/// replacing it would make every stored secret unreadable.
final class VaultCryptoTests: XCTestCase {

    private let key = SymmetricKey(size: .bits256)
    private let otherKey = SymmetricKey(size: .bits256)
    private let id = UUID()

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

    /// "café" typed as one code point or as "e" plus a combining accent
    /// derives the same key once composed — the answer here was computed from
    /// the composed form outside KeyVault.
    func testBothFormsOfAnAccentDeriveTheSameKeyOnceComposed() throws {
        let composed = "caf\u{E9}", decomposed = "cafe\u{301}"
        XCTAssertNotEqual(Array(composed.utf8), Array(decomposed.utf8))
        for form in [composed, decomposed] {
            let key = try VaultCrypto.derive(passphrase: VaultCrypto.normalized(form), salt: Data(count: 32))
            let hex = key.withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }
            XCTAssertEqual(hex, "d9ec0f3f1d43d4c77071aa14b579009fa4dbc78cd067d6845858f59491213044")
        }
    }

    /// A passphrase set before normalisation is still tried as typed.
    func testCandidatesKeepTheTypedFormWhenItDiffers() {
        XCTAssertEqual(VaultCrypto.candidates(for: "plain ascii"), ["plain ascii"])
        XCTAssertEqual(VaultCrypto.candidates(for: "cafe\u{301}").map { Array($0.unicodeScalars) },
                       [Array("caf\u{E9}".unicodeScalars), Array("cafe\u{301}".unicodeScalars)])
    }

    func testTextRoundTrips() throws {
        let sealed = try VaultCrypto.encrypt("hunter2 — ünïcödé", for: id, using: key)
        XCTAssertEqual(try VaultCrypto.decrypt(sealed, for: id, using: key), "hunter2 — ünïcödé")
    }

    func testCiphertextIsMarkedAndPlaintextIsNot() throws {
        let sealed = try VaultCrypto.encrypt("x", for: id, using: key)
        XCTAssertTrue(sealed.starts(with: VaultCrypto.magicV2))
        XCTAssertTrue(VaultCrypto.isEncrypted(sealed))
        // What a vault written before encryption holds, and must keep reading.
        XCTAssertFalse(VaultCrypto.isEncrypted(Data("plain old note".utf8)))
        // The marker alone, with nothing after it, is not ciphertext either.
        XCTAssertFalse(VaultCrypto.isEncrypted(VaultCrypto.magicV1))
        XCTAssertFalse(VaultCrypto.isEncrypted(VaultCrypto.magicV2))
    }

    func testTheSameTextSealsDifferentlyEachTime() throws {
        XCTAssertNotEqual(try VaultCrypto.encrypt("same", for: id, using: key),
                          try VaultCrypto.encrypt("same", for: id, using: key))
    }

    func testAnotherKeyIsReportedAsTheWrongPassphrase() throws {
        let sealed = try VaultCrypto.encrypt("secret", for: id, using: key)
        XCTAssertThrowsError(try VaultCrypto.decrypt(sealed, for: id, using: otherKey)) { error in
            guard case VaultCrypto.CryptoError.wrongPassphrase = error else {
                return XCTFail("expected wrongPassphrase, got \(error)")
            }
        }
    }

    func testATamperedByteDoesNotOpen() throws {
        var sealed = try VaultCrypto.encrypt("secret", for: id, using: key)
        sealed[sealed.count - 1] ^= 0x01
        XCTAssertThrowsError(try VaultCrypto.decrypt(sealed, for: id, using: key))
    }

    func testPlaintextIsNotDecrypted() {
        XCTAssertThrowsError(try VaultCrypto.decrypt(Data("plain".utf8), for: id, using: key)) { error in
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

    /// A payload copied over another item's does not open there. Version 1
    /// had no way to notice.
    func testAPayloadOpensOnlyUnderItsOwnItem() throws {
        let sealed = try VaultCrypto.encrypt("secret", for: id, using: key)
        XCTAssertThrowsError(try VaultCrypto.decrypt(sealed, for: UUID(), using: key))
    }

    /// What every vault encrypted before version 2 holds: the marker, then an
    /// AES-GCM box sealed with no authenticated data. It must keep opening,
    /// under any id, since it was never bound to one.
    func testVersion1StillOpens() throws {
        let box = try AES.GCM.seal(Data("legacy".utf8), using: key)
        let v1 = VaultCrypto.magicV1 + box.combined!
        XCTAssertTrue(VaultCrypto.isEncrypted(v1))
        XCTAssertTrue(VaultCrypto.isVersion1(v1))
        XCTAssertEqual(try VaultCrypto.decrypt(v1, for: id, using: key), "legacy")
        XCTAssertEqual(try VaultCrypto.decrypt(v1, for: UUID(), using: key), "legacy")
        XCTAssertThrowsError(try VaultCrypto.decrypt(v1, for: id, using: otherKey))
    }

    func testVersion2IsNotVersion1() throws {
        XCTAssertFalse(VaultCrypto.isVersion1(try VaultCrypto.encrypt("x", for: id, using: key)))
    }

    /// A version 2 marker on a version 1 box, or the reverse, does not open:
    /// the marker is not something to strip and retry around.
    func testTheMarkerCannotBeSwapped() throws {
        let v2 = try VaultCrypto.encrypt("x", for: id, using: key)
        let relabelled = VaultCrypto.magicV1 + v2.dropFirst(VaultCrypto.magicV2.count)
        XCTAssertThrowsError(try VaultCrypto.decrypt(relabelled, for: id, using: key))
    }

    func testTheVerifierAcceptsOnlyItsKey() throws {
        let verifier = try VaultCrypto.makeVerifier(using: key)
        XCTAssertTrue(VaultCrypto.verifier(verifier, accepts: key))
        XCTAssertFalse(VaultCrypto.verifier(verifier, accepts: otherKey))
        XCTAssertFalse(VaultCrypto.verifier(Data("junk".utf8), accepts: key))
    }

    /// Only a salt that is not there means there is no vault. A login keychain
    /// that is locked, a prompt refused, or any other failed read must not
    /// read as one, or the app offers first-time setup over the real vault.
    func testOnlyAMissingSaltMeansNoVault() {
        XCTAssertEqual(VaultCrypto.classify(saltRead: errSecItemNotFound, data: nil), .notSet)
        XCTAssertEqual(VaultCrypto.classify(saltRead: errSecSuccess, data: Data(count: 32)), .set)
        for status in [errSecAuthFailed, errSecInteractionNotAllowed, errSecUserCanceled,
                       errSecNotAvailable, errSecNoSuchKeychain] {
            XCTAssertEqual(VaultCrypto.classify(saltRead: status, data: nil), .unreadable(status))
        }
        XCTAssertEqual(VaultCrypto.classify(saltRead: errSecSuccess, data: nil), .unreadable(errSecDecode))
    }

    /// The session entry points refuse while locked, rather than sealing
    /// under some default. A hosted test run never unlocks the vault.
    func testTheSessionKeyIsRequiredWhileLocked() {
        XCTAssertFalse(VaultCrypto.isUnlocked)
        XCTAssertThrowsError(try VaultCrypto.encrypt("x", for: id)) { error in
            guard case VaultCrypto.CryptoError.locked = error else {
                return XCTFail("expected locked, got \(error)")
            }
        }
    }
}
