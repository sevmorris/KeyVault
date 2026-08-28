import Foundation

/// The exported form of everything `SecretStore` owns.
///
/// Deliberately a plain, self-describing JSON document rather than anything
/// clever. This file is the vault's exit: its whole purpose is to be readable
/// by something that is not KeyVault, years from now, by someone who no longer
/// has KeyVault and possibly no longer has a Mac. Every decision here is in
/// service of that — the field names say what they mean, and `readme` carries
/// the decryption command inside the payload so the instructions cannot be
/// separated from the thing they describe.
struct VaultArchive: Codable {
    /// Bumped only for a breaking change to the shape. An importer that does
    /// not recognise the version refuses rather than guesses, because guessing
    /// at the structure of irreplaceable data is how it gets mangled.
    static let currentFormatVersion = 1

    /// Instructions embedded in the payload, so a stranger finding the file
    /// knows what to do with it without any external documentation.
    static let readmeText = """
        This is a KeyVault export. Decrypt it with:
          gpg --decrypt keyvault-export.asc > vault.json
        It is OpenPGP symmetric (AES-256), so any GnuPG on any platform will \
        read it — KeyVault is not required. Inside is this JSON document; each \
        item's "secret" field is the stored value in plain text.
        """

    var formatVersion: Int = currentFormatVersion
    var readme: String = readmeText
    var exportedAt: Date
    var items: [Item]

    struct Item: Codable {
        var id: UUID
        /// `KeyType` raw value — "Note" or "API Key".
        var type: String
        var name: String
        var service: String?
        var notes: String?
        var createdDate: Date?
        /// The secret itself, in the clear. The file's confidentiality comes
        /// entirely from the encryption around it, which is the property that
        /// makes the archive portable.
        var secret: String
    }
}
