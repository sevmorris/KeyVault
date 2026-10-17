import Foundation

/// Runs a system tool and collects what it wrote.
///
/// Both output pipes are drained on their own queues *while* the child runs,
/// rather than read from `terminationHandler` once it has exited. Reading
/// after exit deadlocks, and not rarely: a macOS pipe holds 64 KB, so a child
/// that fills stdout blocks waiting for a reader that will not run until the
/// child it is blocking has terminated. Neither side moves again. An export of
/// ~30 notes was enough to reach that, and the symptom was the worst kind —
/// the backup never finished and never reported a failure either.
///
/// stdin is written on a queue of its own for the same reason: a payload
/// larger than the pipe buffer cannot be handed over in one blocking write
/// while the child is itself blocked writing output nobody is reading.
actor ShellService {
    /// Accumulates the child's output. A reference type with its own lock, so
    /// the reader queues can fill it concurrently without a data race.
    private final class Output: @unchecked Sendable {
        private let lock = NSLock()
        private var out = Data()
        private var err = Data()

        private var didTimeOut = false

        func appendOut(_ data: Data) { lock.lock(); out += data; lock.unlock() }
        func markTimedOut() { lock.lock(); didTimeOut = true; lock.unlock() }
        var timedOut: Bool { lock.lock(); defer { lock.unlock() }; return didTimeOut }
        func appendErr(_ data: Data) { lock.lock(); err += data; lock.unlock() }

        var strings: (stdout: String, stderr: String) {
            lock.lock()
            defer { lock.unlock() }
            return (String(data: out, encoding: .utf8) ?? "",
                    String(data: err, encoding: .utf8) ?? "")
        }
    }

    /// Writing to a pipe whose reader has already exited raises SIGPIPE, and
    /// the default disposition for SIGPIPE is to kill the process — so a tool
    /// that quits early, gpg on a passphrase it will not accept for instance,
    /// took the whole app down while stdin was still being handed over.
    /// Ignoring it turns that into a plain EPIPE the write below discards.
    /// Evaluated once, on first use, before any child exists.
    private static let ignoreSIGPIPE: Void = {
        signal(SIGPIPE, SIG_IGN)
    }()

    /// How long a tool may run before it is stopped. Every tool this app runs
    /// answers in a second or two; the ones that do not are waiting for
    /// something that will never come — gpg for a pinentry on a tty a GUI app
    /// does not have, or for a gpg-agent that has wedged — and without a limit
    /// the list stayed on "Loading keys…" for the life of the app, and a
    /// backup simply never finished.
    static let defaultTimeout: TimeInterval = 60

    struct TimedOut: LocalizedError {
        let tool: String
        let seconds: TimeInterval
        var errorDescription: String? {
            "\((tool as NSString).lastPathComponent) did not finish within \(Int(seconds)) seconds "
                + "and was stopped."
        }
    }

    /// `environment` is added to the app's own, not put in place of it: a
    /// child given only what the caller named would lose HOME and PATH.
    func run(
        _ executable: String,
        arguments: [String],
        environment: [String: String] = [:],
        timeout: TimeInterval = defaultTimeout
    ) async throws -> (stdout: String, stderr: String, status: Int32) {
        try await execute(executable, arguments: arguments, stdinData: nil,
                          environment: environment, timeout: timeout)
    }

    func runWithStdin(
        _ executable: String,
        arguments: [String],
        stdinData: Data,
        environment: [String: String] = [:],
        timeout: TimeInterval = defaultTimeout
    ) async throws -> (stdout: String, stderr: String, status: Int32) {
        try await execute(executable, arguments: arguments, stdinData: stdinData,
                          environment: environment, timeout: timeout)
    }

    private func execute(
        _ executable: String,
        arguments: [String],
        stdinData: Data?,
        environment: [String: String],
        timeout: TimeInterval
    ) async throws -> (stdout: String, stderr: String, status: Int32) {
        _ = Self.ignoreSIGPIPE

        guard FileManager.default.fileExists(atPath: executable) else {
            throw KeyError.toolNotFound(executable)
        }

        return try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            if !environment.isEmpty {
                process.environment = ProcessInfo.processInfo.environment
                    .merging(environment) { _, added in added }
            }

            let stdoutPipe = Pipe()
            let stderrPipe = Pipe()
            process.standardOutput = stdoutPipe
            process.standardError = stderrPipe

            let stdinPipe: Pipe? = stdinData == nil ? nil : Pipe()
            if let stdinPipe { process.standardInput = stdinPipe }

            let io = DispatchQueue(
                label: "io.github.sevmorris.KeyVault.shell",
                attributes: .concurrent
            )
            let group = DispatchGroup()
            let output = Output()

            group.enter()
            io.async {
                output.appendOut(stdoutPipe.fileHandleForReading.readDataToEndOfFile())
                group.leave()
            }
            group.enter()
            io.async {
                output.appendErr(stderrPipe.fileHandleForReading.readDataToEndOfFile())
                group.leave()
            }

            // Resume only once both readers have seen EOF, so nothing the tool
            // wrote is dropped just because it exited promptly after writing.
            process.terminationHandler = { proc in
                let status = proc.terminationStatus
                // A tool stopped for taking too long is not waited on for EOF.
                // Something it started can still hold the pipes open — a shell
                // killed outright leaves its own child behind — and waiting
                // for that would be the hang the time limit is there to end.
                // The readers finish on their own whenever the pipes close.
                if output.timedOut {
                    continuation.resume(throwing: TimedOut(tool: executable, seconds: timeout))
                    return
                }
                group.notify(queue: io) {
                    let (out, err) = output.strings
                    continuation.resume(returning: (stdout: out, stderr: err, status: status))
                }
            }

            do {
                try process.run()
                // SIGTERM first, so gpg can tidy up after itself; SIGKILL if
                // it is still there a few seconds later. Either way the child
                // exits, its pipes close, and the termination handler above
                // resumes with the timeout rather than hanging. A child that
                // has already finished is not signalled: `isRunning` is false.
                let pid = process.processIdentifier
                io.asyncAfter(deadline: .now() + timeout) {
                    guard process.isRunning else { return }
                    output.markTimedOut()
                    process.terminate()
                    io.asyncAfter(deadline: .now() + 3) {
                        if process.isRunning { kill(pid, SIGKILL) }
                    }
                }
                if let stdinPipe, let stdinData {
                    group.enter()
                    io.async {
                        let handle = stdinPipe.fileHandleForWriting
                        // The throwing form on purpose: the older write(_:)
                        // raises an Objective-C exception on a broken pipe,
                        // which Swift cannot catch, so a tool exiting early
                        // (a wrong passphrase, say) took the app down with it.
                        try? handle.write(contentsOf: stdinData)
                        try? handle.close()
                        group.leave()
                    }
                }
            } catch {
                // The child never started, so nothing will ever close these.
                // Close them here or the readers block for the life of the app.
                try? stdoutPipe.fileHandleForWriting.close()
                try? stderrPipe.fileHandleForWriting.close()
                continuation.resume(throwing: error)
            }
        }
    }
}
