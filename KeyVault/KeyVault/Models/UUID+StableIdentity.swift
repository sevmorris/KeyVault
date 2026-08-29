import CryptoKit
import Foundation

extension UUID {
    /// A UUID derived from a string, so the same input always yields the same id.
    ///
    /// SSH, GPG and Age entries are not stored by KeyVault — they are a view
    /// onto files and a keyring that other tools own — so they are rebuilt from
    /// scratch on every reload. Minting a fresh random `UUID` each time meant
    /// each rebuild produced rows that were, to SwiftUI, entirely new: the id
    /// held in `selectedKeyID` matched nothing any more, so the selection
    /// silently emptied and the detail pane went blank on every refresh,
    /// including the automatic one after generating a key.
    ///
    /// Deriving the id from something the entry actually owns — its file path,
    /// its key id — makes the row the same row across reloads.
    init(stableIdentity identity: String) {
        var bytes = Array(SHA256.hash(data: Data(identity.utf8)).prefix(16))
        // Stamp the version and variant fields so this is a well-formed UUID
        // and not merely sixteen bytes in the shape of one. Version 8 is the
        // slot RFC 9562 reserves for custom derivations exactly like this.
        bytes[6] = (bytes[6] & 0x0F) | 0x80
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        self.init(uuid: (
            bytes[0],  bytes[1],  bytes[2],  bytes[3],
            bytes[4],  bytes[5],  bytes[6],  bytes[7],
            bytes[8],  bytes[9],  bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }
}
