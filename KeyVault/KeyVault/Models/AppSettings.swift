import Foundation

struct AppSettings: Codable {
    var ageKeyPaths: [String]

    init(ageKeyPaths: [String] = ["~/.config/sops/age/keys.txt", "~/.age/keys.txt"]) {
        self.ageKeyPaths = ageKeyPaths
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
