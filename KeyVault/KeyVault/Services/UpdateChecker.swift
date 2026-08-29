import AppKit
import os.log

private let updateLog = Logger(subsystem: "io.github.sevmorris.KeyVault", category: "UpdateChecker")

struct AvailableUpdate: Sendable {
    let version: String
    let downloadURL: URL
    let releaseURL: URL
}

actor UpdateChecker {
    static let shared = UpdateChecker()

    enum Result {
        case upToDate(version: String)
        case available(version: String, downloadURL: URL, releaseURL: URL)
        case error(String)
    }

    private struct Release: Decodable {
        let tagName: String
        let htmlUrl: String
        let assets: [Asset]

        struct Asset: Decodable {
            let name: String
            let browserDownloadUrl: String
            enum CodingKeys: String, CodingKey {
                case name
                case browserDownloadUrl = "browser_download_url"
            }
        }

        enum CodingKeys: String, CodingKey {
            case tagName = "tag_name"
            case htmlUrl = "html_url"
            case assets
        }
    }

    private let apiURL = URL(string: "https://api.github.com/repos/sevmorris/KeyVault/releases/latest")!

    private let urlSession: URLSession = {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 5
        config.timeoutIntervalForResource = 10
        return URLSession(configuration: config)
    }()

    func check() async -> Result {
        do {
            let currentVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0"

            var request = URLRequest(url: apiURL, cachePolicy: .reloadIgnoringLocalCacheData)
            request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")

            let (data, response) = try await urlSession.data(for: request)

            guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                return .error("Could not reach GitHub. Check your internet connection.")
            }

            let release = try JSONDecoder().decode(Release.self, from: data)
            let remoteVersion = release.tagName.trimmingCharacters(in: CharacterSet(charactersIn: "v"))

            let releaseURL = URL(string: release.htmlUrl)
                ?? URL(string: "https://github.com/sevmorris/KeyVault/releases")!
            let downloadURL = release.assets.first(where: { $0.name.hasSuffix(".dmg") })
                .flatMap { URL(string: $0.browserDownloadUrl) }
                ?? releaseURL

            if remoteVersion.compare(currentVersion, options: .numeric) == .orderedDescending {
                return .available(version: remoteVersion, downloadURL: downloadURL, releaseURL: releaseURL)
            } else {
                return .upToDate(version: currentVersion)
            }
        } catch {
            updateLog.error("UpdateChecker: \(error.localizedDescription, privacy: .public)")
            return .error(error.localizedDescription)
        }
    }
}

/// Show an update dialog. When `silent` is true (launch check), only shows UI if an update
/// is available.
@MainActor @discardableResult
func checkForUpdates(silent: Bool = false) async -> AvailableUpdate? {
    let result = await UpdateChecker.shared.check()

    switch result {
    case .upToDate(let version):
        guard !silent else { return nil }
        let alert = NSAlert()
        alert.messageText = "You're up to date"
        alert.informativeText = "KeyVault \(version) is the latest version."
        alert.addButton(withTitle: "OK")
        alert.runModal()
        return nil

    case .available(let version, let downloadURL, let releaseURL):
        let update = AvailableUpdate(version: version, downloadURL: downloadURL, releaseURL: releaseURL)
        let alert = NSAlert()
        alert.messageText = "Update Available"
        alert.informativeText = "KeyVault \(version) is available."
        alert.addButton(withTitle: "Download")
        alert.addButton(withTitle: "Release Notes")
        alert.addButton(withTitle: "Not Now")
        let response = alert.runModal()
        if response == .alertFirstButtonReturn {
            NSWorkspace.shared.open(downloadURL)
        } else if response == .alertSecondButtonReturn {
            NSWorkspace.shared.open(releaseURL)
        }
        return update

    case .error(let message):
        guard !silent else { return nil }
        let alert = NSAlert()
        alert.messageText = "Update Check Failed"
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
        return nil
    }
}
