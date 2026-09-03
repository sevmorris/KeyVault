import Foundation

struct AppSettings: Codable {
    var ageKeyPaths: [String]

    /// Minutes of inactivity before the vault shuts itself; 0 for never.
    ///
    /// Optional, and it has to stay that way. The synthesised `Decodable`
    /// conformance does not apply a property's default value when the key is
    /// missing, so adding this as a plain `Int` would have made every settings
    /// blob written before today fail to decode — and `load()` answers a
    /// decode failure with a fresh `AppSettings`, quietly discarding the Age
    /// paths the user had configured. An Optional decodes as nil instead.
    var autoLockMinutes: Int?

    /// Optional for the same reason as `autoLockMinutes` above: a missing key
    /// must decode, not throw.
    var secretDisplayStyle: String?

    /// The default lives here rather than in the stored value, so a vault that
    /// has never opened Settings still locks itself.
    static let defaultAutoLockMinutes = 15

    var idleLockMinutes: Int {
        get { autoLockMinutes ?? Self.defaultAutoLockMinutes }
        set { autoLockMinutes = newValue }
    }

    var screenStyle: PhosphorStyle {
        get { PhosphorStyle(rawValue: secretDisplayStyle ?? "") ?? .green }
        set { secretDisplayStyle = newValue.rawValue }
    }

    init(ageKeyPaths: [String] = ["~/.config/sops/age/keys.txt", "~/.age/keys.txt"],
         autoLockMinutes: Int? = nil,
         secretDisplayStyle: String? = nil) {
        self.ageKeyPaths = ageKeyPaths
        self.autoLockMinutes = autoLockMinutes
        self.secretDisplayStyle = secretDisplayStyle
    }

    static func load() -> AppSettings {
        guard let data = UserDefaults.standard.data(forKey: "AppSettings"),
              let settings = try? JSONDecoder().decode(AppSettings.self, from: data) else {
            return AppSettings()
        }
        return settings
    }

    func save() {
        guard let data = try? JSONEncoder().encode(self) else { return }
        UserDefaults.standard.set(data, forKey: "AppSettings")
    }
}
