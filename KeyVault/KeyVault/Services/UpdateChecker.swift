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
        /// Newer than this build, but it needs a newer macOS than this Mac has.
        case needsNewerMacOS(version: String, minimum: String, installed: String)
        case error(String)
    }

    private struct Release: Decodable {
        let tagName: String
        let htmlUrl: String
        let assets: [Asset]
        /// The release notes, which carry the minimum-macos marker.
        let body: String?

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
            case body
        }
    }

    private let apiURL = URL(string: "https://api.github.com/repos/sevmorris/KeyVault/releases/latest")!

    private let urlSession: URLSession = {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 5
        config.timeoutIntervalForResource = 10
        return URLSession(configuration: config)
    }()

    /// The macOS a release says it needs. release.sh ends every release's notes
    /// with `<!-- minimum-macos: 15.0 -->`, read from the built app's
    /// LSMinimumSystemVersion; GitHub does not render the comment. nil when there
    /// is no marker: a release from before it existed, which runs on every macOS
    /// this build does.
    nonisolated static func minimumMacOS(inReleaseNotes notes: String?) -> OperatingSystemVersion? {
        guard let notes,
              let start = notes.range(of: "<!-- minimum-macos:"),
              let end = notes[start.upperBound...].range(of: "-->") else { return nil }
        return macOSVersion(String(notes[start.upperBound..<end.lowerBound]))
    }

    /// "15", "15.0" or "15.2.1" as a version; nil for anything else.
    nonisolated static func macOSVersion(_ string: String) -> OperatingSystemVersion? {
        let fields = string.trimmingCharacters(in: .whitespaces)
            .split(separator: ".", omittingEmptySubsequences: false)
        let numbers = fields.compactMap { Int($0) }
        guard (1...3).contains(fields.count), numbers.count == fields.count else { return nil }
        return OperatingSystemVersion(majorVersion: numbers[0],
                                      minorVersion: numbers.count > 1 ? numbers[1] : 0,
                                      patchVersion: numbers.count > 2 ? numbers[2] : 0)
    }

    /// True when a Mac running `os` meets `minimum`.
    nonisolated static func runs(on os: OperatingSystemVersion, given minimum: OperatingSystemVersion) -> Bool {
        (os.majorVersion, os.minorVersion, os.patchVersion)
            >= (minimum.majorVersion, minimum.minorVersion, minimum.patchVersion)
    }

    /// "15.0", or "15.2.1" when there is a patch number.
    nonisolated static func describe(_ version: OperatingSystemVersion) -> String {
        let base = "\(version.majorVersion).\(version.minorVersion)"
        return version.patchVersion > 0 ? "\(base).\(version.patchVersion)" : base
    }

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

            // These strings come out of a JSON document. The transport is
            // trusted, but the contents are still data, and NSWorkspace.open
            // will act on file:// or any custom scheme just as readily as on
            // a web address. Only https gets through.
            func httpsURL(_ string: String) -> URL? {
                guard let url = URL(string: string),
                      url.scheme?.lowercased() == "https" else { return nil }
                return url
            }
            let releasesFallback = URL(string: "https://github.com/sevmorris/KeyVault/releases")!
            let releaseURL = httpsURL(release.htmlUrl) ?? releasesFallback
            let downloadURL = release.assets.first(where: { $0.name.hasSuffix(".dmg") })
                .flatMap { httpsURL($0.browserDownloadUrl) }
                ?? releaseURL

            if remoteVersion.compare(currentVersion, options: .numeric) == .orderedDescending {
                // A release this Mac cannot run is not an update for it: its DMG
                // would replace a working app with one that will not open.
                if let minimum = Self.minimumMacOS(inReleaseNotes: release.body),
                   !Self.runs(on: ProcessInfo.processInfo.operatingSystemVersion, given: minimum) {
                    return .needsNewerMacOS(version: remoteVersion, minimum: Self.describe(minimum),
                                            installed: currentVersion)
                }
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

    case .needsNewerMacOS(let version, let minimum, let installed):
        // Nothing this Mac can install, so the check at launch says nothing,
        // and there is no version to record as dismissed.
        guard !silent else { return nil }
        let alert = NSAlert()
        alert.messageText = "KeyVault \(version) needs macOS \(minimum)"
        alert.informativeText = "This Mac has macOS \(UpdateChecker.describe(ProcessInfo.processInfo.operatingSystemVersion)), "
            + "so KeyVault \(installed) is the newest version it can run."
        alert.addButton(withTitle: "OK")
        alert.runModal()
        return nil

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
