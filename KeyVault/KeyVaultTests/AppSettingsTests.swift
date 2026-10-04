import XCTest
@testable import KeyVault

/// AppSettings reads and writes `UserDefaults.app`, which in a test run is a
/// scratch suite in the temporary folder. Each test clears its key on the
/// way in and out, so none depends on another's leftovers.
final class AppSettingsTests: XCTestCase {

    private let key = "AppSettings"

    override func setUp() {
        super.setUp()
        UserDefaults.app.removeObject(forKey: key)
    }

    override func tearDown() {
        UserDefaults.app.removeObject(forKey: key)
        super.tearDown()
    }

    /// What every other test here relies on: hosting tests, the app's store
    /// is the scratch suite, never the developer's real settings.
    func testATestRunNeverReachesTheRealDefaults() {
        XCTAssertTrue(AppLauncher.isHostingTests)
        XCTAssertFalse(UserDefaults.app === UserDefaults.standard)
    }

    func testNothingSavedLoadsTheDefaults() {
        let settings = AppSettings.load()
        XCTAssertEqual(settings.ageKeyPaths, AppSettings().ageKeyPaths)
        XCTAssertEqual(settings.idleLockMinutes, AppSettings.defaultAutoLockMinutes)
    }

    func testSavedSettingsLoadBack() {
        AppSettings(ageKeyPaths: ["/tmp/age/keys.txt"], autoLockMinutes: 5).save()
        let loaded = AppSettings.load()
        XCTAssertEqual(loaded.ageKeyPaths, ["/tmp/age/keys.txt"])
        XCTAssertEqual(loaded.idleLockMinutes, 5)
    }

    /// 0 means never, and has to survive the round trip rather than fall back
    /// to the default.
    func testZeroMinutesStaysNever() {
        AppSettings(autoLockMinutes: 0).save()
        XCTAssertEqual(AppSettings.load().idleLockMinutes, 0)
    }

    /// Settings saved before auto-lock existed carry no autoLockMinutes. That
    /// is why it is Optional: as a plain Int the old blob would fail to decode,
    /// and load() would replace the user's Age paths with the defaults.
    func testSettingsSavedBeforeAutoLockStillLoad() throws {
        UserDefaults.app.set(Data(#"{"ageKeyPaths":["/a/keys.txt"]}"#.utf8), forKey: key)
        let loaded = AppSettings.load()
        XCTAssertEqual(loaded.ageKeyPaths, ["/a/keys.txt"])
        XCTAssertNil(loaded.autoLockMinutes)
        XCTAssertEqual(loaded.idleLockMinutes, AppSettings.defaultAutoLockMinutes)
    }
}
