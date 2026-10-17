import XCTest
@testable import KeyVault

/// Runs /bin/sh and /bin/cat, which every Mac has, so the pipe handling and
/// the time limit are exercised without the tools KeyVault really drives.
final class ShellServiceTests: XCTestCase {

    func testOutputAndStatusComeBack() async throws {
        let result = try await ShellService().run("/bin/sh", arguments: ["-c", "echo out; echo err >&2; exit 3"])
        XCTAssertEqual(result.stdout, "out\n")
        XCTAssertEqual(result.stderr, "err\n")
        XCTAssertEqual(result.status, 3)
    }

    /// More than a pipe holds, both ways: the case that used to deadlock.
    func testLargeInputAndOutputDoNotDeadlock() async throws {
        let payload = Data(repeating: UInt8(ascii: "x"), count: 1_000_000)
        let result = try await ShellService().runWithStdin("/bin/cat", arguments: [], stdinData: payload)
        XCTAssertEqual(result.stdout.utf8.count, payload.count)
    }

    func testAToolThatHangsIsStopped() async throws {
        let start = Date()
        do {
            _ = try await ShellService().run("/bin/sleep", arguments: ["30"], timeout: 1)
            XCTFail("expected a timeout")
        } catch is ShellService.TimedOut {
            XCTAssertLessThan(Date().timeIntervalSince(start), 10)
        }
    }

    /// One that ignores SIGTERM is killed.
    func testAToolThatIgnoresTerminationIsKilled() async throws {
        let start = Date()
        do {
            _ = try await ShellService().run("/bin/sh", arguments: ["-c", "trap '' TERM; sleep 30"], timeout: 1)
            XCTFail("expected a timeout")
        } catch is ShellService.TimedOut {
            XCTAssertLessThan(Date().timeIntervalSince(start), 10)
        }
    }

    func testAMissingToolIsReported() async {
        do {
            _ = try await ShellService().run("/nonexistent/tool", arguments: [])
            XCTFail("expected toolNotFound")
        } catch KeyError.toolNotFound {
        } catch {
            XCTFail("unexpected \(error)")
        }
    }
}
