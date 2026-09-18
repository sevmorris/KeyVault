import Foundation

struct EncryptionKey: Identifiable, Codable {
    let id: UUID
    var type: KeyType
    var name: String
    var fingerprint: String?
    var publicKey: String?
    var keyID: String?
    var algorithm: String?
    var path: String?
    var service: String?
    /// Free-text grouping for notes. nil reads as uncategorised.
    var category: String?
    var notes: String?
    var createdDate: Date?
    var expiryDate: Date?
    /// For a stored file: the name it had on disk, which Save a Copy offers
    /// back, and its size in bytes.
    var fileName: String?
    var fileSize: Int?
    var hasPrivateKey: Bool

    init(
        id: UUID = UUID(),
        type: KeyType,
        name: String,
        fingerprint: String? = nil,
        publicKey: String? = nil,
        keyID: String? = nil,
        algorithm: String? = nil,
        path: String? = nil,
        service: String? = nil,
        category: String? = nil,
        notes: String? = nil,
        createdDate: Date? = nil,
        expiryDate: Date? = nil,
        fileName: String? = nil,
        fileSize: Int? = nil,
        hasPrivateKey: Bool = false
    ) {
        self.id = id
        self.type = type
        self.name = name
        self.fingerprint = fingerprint
        self.publicKey = publicKey
        self.keyID = keyID
        self.algorithm = algorithm
        self.path = path
        self.service = service
        self.category = category
        self.notes = notes
        self.createdDate = createdDate
        self.expiryDate = expiryDate
        self.fileName = fileName
        self.fileSize = fileSize
        self.hasPrivateKey = hasPrivateKey
    }
}
